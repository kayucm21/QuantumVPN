"""Operator-only routing target catalogue; it never probes or publishes rules.

Known/imported entries and measurement evidence live outside the signed policy.
Search reads at most one bounded page, not the complete catalogue into HTML.
"""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

MAX_IMPORT_BYTES = 1024 * 1024
MAX_IMPORT_ENTRIES = 20_000
MAX_CATALOG_ENTRIES = 100_000
MAX_CATALOG_SOURCES = 64
MAX_SEED_BYTES = 4 * 1024 * 1024
MAX_PAGE_SIZE = 50
_POLICY_KEYS = ("direct_domains", "proxy_domains", "block_domains", "direct_cidrs", "proxy_cidrs")
_MANAGED_SOURCES = ("policy", "draft", "manual", "scan", "dns")
_REPLACED_SOURCES = ("policy", "draft", "manual")
_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]")
_NONPUBLIC_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
))
_NONPUBLIC_V6 = tuple(ipaddress.ip_network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
))


class CatalogCapacityError(ValueError):
    """A bounded catalogue is full, not a failed routing/scan operation."""


def schema(db):
    """Create catalogue-only tables. Caller owns the transaction/commit."""
    db.execute("""create table if not exists routing_target_catalog (
        target text primary key, kind text not null check(kind in ('domain','ip','cidr')),
        status text not null default 'unchecked', latency_ms integer,
        checked_at integer not null default 0, addresses text not null default '',
        created_at integer not null
    )""")
    db.execute("""create table if not exists routing_target_catalog_sources (
        target text not null, source text not null, primary key(target,source),
        foreign key(target) references routing_target_catalog(target) on delete cascade
    )""")
    db.execute("create index if not exists routing_target_catalog_kind_target on routing_target_catalog(kind,target)")
    db.execute("create index if not exists routing_target_catalog_source on routing_target_catalog_sources(source,target)")
    db.execute("create table if not exists routing_target_catalog_state (key text primary key,value text not null)")


@contextmanager
def _atomic(db):
    # A top-level RELEASE would commit the caller's work. Keep an outer
    # transaction even when the caller has not performed its first write yet.
    if not db.in_transaction:
        db.execute("begin")
    db.execute("savepoint routing_catalog_update")
    try:
        yield
    except Exception:
        db.execute("rollback to routing_catalog_update")
        db.execute("release routing_catalog_update")
        raise
    else:
        db.execute("release routing_catalog_update")


def _public_address(address):
    return bool(address.is_global and not address.is_multicast and not address.is_reserved
                and not address.is_unspecified and not address.is_loopback and not address.is_link_local)


def _public_network(network):
    # Endpoint checks alone miss private ranges inside broad public-looking CIDRs.
    if not _public_address(network.network_address) or not _public_address(network.broadcast_address):
        return False
    excluded = _NONPUBLIC_V4 if network.version == 4 else _NONPUBLIC_V6
    if network.version == 6 and not network.subnet_of(ipaddress.ip_network("2000::/3")):
        return False
    return not any(network.overlaps(blocked) for blocked in excluded)


def _normal_entry(value):
    if not isinstance(value, str):
        raise ValueError("Цель должна быть доменом, публичным IP или CIDR.")
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or any(character.isspace() for character in value):
        raise ValueError("Некорректная цель каталога.")
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ValueError("Укажите CIDR без URL или параметров.") from error
        if not _public_network(network):
            raise ValueError("Каталог принимает только публичные IP/CIDR.")
        if network.prefixlen == network.max_prefixlen:
            return {"target": str(network.network_address), "kind": "ip", "selectable": True}
        return {"target": network.with_prefixlen, "kind": "cidr", "selectable": False}
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Keep the same concrete ASCII domain contract as the scan/policy parser.
        # IDN names must be supplied in explicit punycode, not silently remapped.
        if not _DOMAIN.fullmatch(value):
            raise ValueError("Укажите конкретный домен без URL, wildcard или regex (IDN — punycode).")
        if value.endswith((".local", ".localhost", ".invalid", ".test", ".onion", ".internal", ".lan", ".home.arpa")):
            raise ValueError("Для каталога нужны публичные домены, не локальные или служебные зоны.")
        return {"target": value, "kind": "domain", "selectable": True}
    if not _public_address(address):
        raise ValueError("Каталог принимает только публичные IP/CIDR.")
    return {"target": str(address), "kind": "ip", "selectable": True}


def normalize_entries(raw):
    """Validate the whole import before a write; canonicalise and deduplicate."""
    if not isinstance(raw, str) or len(raw) > MAX_IMPORT_BYTES or len(raw.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("Импорт каталога: не более 1 МБ текста.")
    result, seen = [], set()
    input_count = 0
    for value in re.split(r"[,;\r\n]+", raw):
        if not value.strip():
            continue
        input_count += 1
        if input_count > MAX_IMPORT_ENTRIES:
            raise ValueError("Импорт каталога: не более 20 000 строк за один запуск.")
        entry = _normal_entry(value)
        if entry["target"] not in seen:
            seen.add(entry["target"])
            result.append(entry)
    if not result:
        raise ValueError("Добавьте хотя бы один домен, публичный IP или CIDR.")
    return result


def _source(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value):
        raise ValueError("Некорректный идентификатор источника каталога.")
    return value


def _store(db, entries, source, now):
    source_rows = db.execute("select distinct source from routing_target_catalog_sources").fetchall()
    if source not in {row[0] for row in source_rows} and len(source_rows) >= MAX_CATALOG_SOURCES:
        raise CatalogCapacityError("Каталог ограничен 64 источниками.")
    keys = [entry["target"] for entry in entries]
    existing = set()
    for offset in range(0, len(keys), 800):
        chunk = keys[offset:offset + 800]
        existing.update(row[0] for row in db.execute(
            "select target from routing_target_catalog where target in (" + ",".join("?" for _ in chunk) + ")", chunk))
    total = db.execute("select count(*) from routing_target_catalog").fetchone()[0]
    added = len(keys) - len(existing)
    if total + added > MAX_CATALOG_ENTRIES:
        raise CatalogCapacityError("Каталог ограничен 100 000 уникальными целями.")
    db.executemany("insert or ignore into routing_target_catalog(target,kind,created_at) values (?,?,?)",
                   ((entry["target"], entry["kind"], now) for entry in entries))
    db.executemany("insert or ignore into routing_target_catalog_sources(target,source) values (?,?)",
                   ((entry["target"], source) for entry in entries))
    return {"accepted": len(keys), "added": added, "existing": len(existing), "total": total + added}


def import_entries(db, raw, source="import"):
    """Add explicit imported data only; never delete sources or change routing."""
    entries, source = normalize_entries(raw), _source(source)
    if source in _MANAGED_SOURCES or source == "seed" or source.startswith("seed:"):
        raise ValueError("Этот источник каталога управляется панелью.")
    with _atomic(db):
        return _store(db, entries, source, int(time.time()))


def install_seed(db, path):
    """Install a pinned, local data asset once per digest; no remote fetching.

    Service categories identify provenance only. They are never converted into
    direct/proxy/block routing advice, and unchecked entries have no latency.
    """
    with Path(path).open("rb") as file:
        raw = file.read(MAX_SEED_BYTES + 1)
    if len(raw) > MAX_SEED_BYTES:
        raise ValueError("Файл начального каталога: не более 4 МБ.")
    fingerprint = hashlib.sha256(raw).hexdigest()
    previous = db.execute("select value from routing_target_catalog_state where key='seed_fingerprint'").fetchone()
    if previous and previous[0] == fingerprint:
        stored_count = db.execute("select value from routing_target_catalog_state where key='seed_entries'").fetchone()
        return {"changed": False, "total": db.execute("select count(*) from routing_target_catalog").fetchone()[0],
                "entries": int(stored_count[0]) if stored_count and stored_count[0].isdigit() else 0}
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError("Некорректный JSON начального каталога.") from error
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ValueError("Неизвестная схема начального каталога.")
    metadata, source_records = [], value.get("sources")
    if not isinstance(source_records, list) or not 1 <= len(source_records) <= 32:
        raise ValueError("Начальный каталог должен содержать описание источника.")
    for record in source_records:
        if not isinstance(record, dict):
            raise ValueError("Некорректный источник начального каталога.")
        source_id = _source(record.get("id"))
        revision, license_name, url = record.get("revision"), record.get("license"), record.get("url")
        if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)
                or not isinstance(license_name, str) or not 1 <= len(license_name) <= 80
                or not isinstance(url, str) or not url.startswith("https://") or len(url) > 1024):
            raise ValueError("Начальному каталогу нужны закреплённая ревизия, лицензия и HTTPS-источник.")
        try:
            parsed_url = urlsplit(url)
            if (parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password
                    or parsed_url.port not in (None, 443) or any(ord(character) < 32 for character in url)):
                raise ValueError("Некорректный HTTPS-источник начального каталога.")
        except ValueError as error:
            raise ValueError("Некорректный HTTPS-источник начального каталога.") from error
        metadata.append({"id": source_id, "revision": revision, "license": license_name, "url": url})
    records = value.get("entries")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_CATALOG_ENTRIES:
        raise ValueError("Начальный каталог: от 1 до 100 000 целей.")
    groups = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Некорректная цель начального каталога.")
        entry = _normal_entry(record.get("target"))
        if record.get("kind") != entry["kind"]:
            raise ValueError("Тип цели начального каталога не совпадает с адресом.")
        category = record.get("category", "known")
        if not isinstance(category, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", category):
            raise ValueError("Некорректная категория начального каталога.")
        source = "seed:" + category
        groups.setdefault(source, {})[entry["target"]] = entry
    if len(groups) > MAX_CATALOG_SOURCES - len(_MANAGED_SOURCES) - 1:
        raise ValueError("Слишком много категорий в начальном каталоге.")
    entries_count = len({target for entries in groups.values() for target in entries})
    with _atomic(db):
        db.execute("delete from routing_target_catalog_sources where source like 'seed:%'")
        db.execute("delete from routing_target_catalog where not exists (select 1 from routing_target_catalog_sources s where s.target=routing_target_catalog.target)")
        for source, entries in groups.items():
            _store(db, list(entries.values()), source, int(time.time()))
        db.execute("insert or replace into routing_target_catalog_state(key,value) values ('seed_fingerprint',?)", (fingerprint,))
        db.execute("insert or replace into routing_target_catalog_state(key,value) values ('seed_metadata',?)",
                   (json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),))
        db.execute("insert or replace into routing_target_catalog_state(key,value) values ('seed_entries',?)", (str(entries_count),))
        return {"changed": True, "total": db.execute("select count(*) from routing_target_catalog").fetchone()[0],
                "entries": entries_count}


def _safe_entries(values):
    result, seen = [], set()
    if not isinstance(values, list):
        return result
    for value in values[:MAX_IMPORT_ENTRIES]:
        try:
            entry = _normal_entry(value)
        except (ValueError, TypeError):
            # Existing policies may intentionally contain private direct routes.
            # They remain active, but are not exposed as public probe targets.
            continue
        if entry["target"] not in seen:
            result.append(entry)
            seen.add(entry["target"])
    return result


def _json(value, fallback):
    try:
        return json.loads(value) if isinstance(value, str) else fallback
    except (ValueError, TypeError):
        return fallback


def sync_policy(db, s, payload):
    """Synchronise known active/draft/manual/evidence entries only when changed.

    This optional write must be called separately from page(), with the caller's
    commit. Imported entries and earlier discovered public scan/DNS targets
    survive a policy edit or subsequent batch. No endpoint is contacted.
    A capacity failure rolls back only this optional catalogue update, not the
    caller's successful scan/settings writes. The warning's skipped count is
    the number of new unique targets that were not added; import/seed continue
    to reject capacity failures rather than silently accepting a partial list.
    """
    relevant = {key: s.get("routing_" + key, "") for key in _POLICY_KEYS}
    relevant.update({key: s.get(key, "") for key in ("routing_draft_payload", "routing_scan_targets", "routing_last_scan")})
    relevant["payload_rules"] = payload.get("rules", {}) if isinstance(payload, dict) else {}
    fingerprint = hashlib.sha256(json.dumps(relevant, sort_keys=True, ensure_ascii=False,
                                              separators=(",", ":")).encode()).hexdigest()
    previous = db.execute("select value from routing_target_catalog_state where key='policy_fingerprint'").fetchone()
    if previous and previous[0] == fingerprint:
        return {"changed": False, "total": db.execute("select count(*) from routing_target_catalog").fetchone()[0]}
    groups = {source: [] for source in _MANAGED_SOURCES}
    for key in _POLICY_KEYS:
        groups["policy"].extend(_safe_entries(re.split(r"[,;\r\n]+", str(s.get("routing_" + key, "")))))
    draft = _json(s.get("routing_draft_payload"), {})
    payload_source = "draft" if isinstance(draft, dict) and draft else "policy"
    if isinstance(payload, dict) and isinstance(payload.get("rules"), dict):
        for key in _POLICY_KEYS:
            groups[payload_source].extend(_safe_entries(payload["rules"].get(key, [])))
    if isinstance(draft, dict) and isinstance(draft.get("rules"), dict):
        for key in _POLICY_KEYS:
            groups["draft"].extend(_safe_entries(draft["rules"].get(key, [])))
    groups["manual"] = _safe_entries(re.split(r"[,;\r\n]+", str(s.get("routing_scan_targets", "")))[:24])
    evidence = []
    scan = _json(s.get("routing_last_scan"), [])
    for finding in scan[:24] if isinstance(scan, list) else []:
        if not isinstance(finding, dict):
            continue
        entries = _safe_entries([finding.get("target")])
        if not entries or entries[0]["kind"] == "cidr":
            continue
        entry = entries[0]
        groups["scan"].append(entry)
        addresses = []
        samples = finding.get("addresses")
        for sample in samples[:3] if isinstance(samples, list) else []:
            if not isinstance(sample, dict):
                continue
            public = _safe_entries([sample.get("address")])
            if not public or public[0]["kind"] != "ip":
                continue
            address = public[0]["target"]
            if address not in addresses:
                addresses.append(address)
                groups["dns"].extend(public)
            latency = sample.get("latency_ms")
            if type(latency) is int and 0 < latency <= 60_000:
                evidence.append((address, "ok", latency, finding.get("checked_at", 0), address))
        status = finding.get("status", "unchecked")
        if status not in ("ok", "timeout", "unresolved", "budget", "unchecked"):
            status = "unchecked"
        latency = finding.get("latency_ms")
        latency = latency if status == "ok" and addresses and type(latency) is int and 0 < latency <= 60_000 else None
        if status == "ok" and latency is None:
            status = "unchecked"
        evidence.append((entry["target"], status, latency, finding.get("checked_at", 0), "\n".join(addresses)))
    try:
        with _atomic(db):
            db.execute("delete from routing_target_catalog_sources where source in (" + ",".join("?" for _ in _REPLACED_SOURCES) + ")", _REPLACED_SOURCES)
            db.execute("delete from routing_target_catalog where not exists (select 1 from routing_target_catalog_sources s where s.target=routing_target_catalog.target)")
            now = int(time.time())
            for source, entries in groups.items():
                unique = {entry["target"]: entry for entry in entries}
                _store(db, list(unique.values()), source, now)
            for target, status, latency, checked_at, addresses in evidence:
                checked_at = checked_at if type(checked_at) is int and 0 <= checked_at <= now + 60 else 0
                db.execute("update routing_target_catalog set status=?,latency_ms=?,checked_at=?,addresses=? where target=? and checked_at<=?",
                           (status, latency, checked_at, addresses, target, checked_at))
            db.execute("insert or replace into routing_target_catalog_state(key,value) values ('policy_fingerprint',?)", (fingerprint,))
            return {"changed": True, "total": db.execute("select count(*) from routing_target_catalog").fetchone()[0]}
    except CatalogCapacityError as error:
        # _atomic has restored the complete catalogue, including its last
        # fingerprint. Do not acknowledge a sync that did not happen: a later
        # retry after capacity becomes available must still import these goals.
        targets = list({entry["target"] for entries in groups.values() for entry in entries})
        existing = set()
        for offset in range(0, len(targets), 800):
            chunk = targets[offset:offset + 800]
            existing.update(row[0] for row in db.execute(
                "select target from routing_target_catalog where target in (" + ",".join("?" for _ in chunk) + ")", chunk))
        return {"changed": False, "total": db.execute("select count(*) from routing_target_catalog").fetchone()[0],
                "skipped": len(targets) - len(existing),
                "warning": {"code": "catalog_capacity", "message": str(error)}}


def page(db, query="", kind="", offset=0, limit=50):
    """Read a stable, deduplicated page. No schema writes, DNS or probes.

    ipv4/ipv6 are filters over existing concrete IP rows, not an invitation to
    expand CIDRs. Canonical IP text makes a colon a reliable family marker;
    filtering happens in SQLite before the bounded page is materialised.
    """
    if not isinstance(query, str) or len(query) > 160 or any(ord(character) < 32 for character in query):
        raise ValueError("Поиск каталога: до 160 символов без управляющих знаков.")
    if kind not in ("", "domain", "ip", "ipv4", "ipv6", "cidr"):
        raise ValueError("Неизвестный тип цели каталога.")
    try:
        offset, limit = int(offset), int(limit)
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("Некорректная страница каталога.") from error
    if offset < 0 or offset > MAX_CATALOG_ENTRIES or not 1 <= limit <= MAX_PAGE_SIZE:
        raise ValueError("Страница каталога: до 50 целей.")
    query = query.strip().lower()
    try:
        query = str(ipaddress.ip_address(query))
    except ValueError:
        pass
    clauses, parameters = [], []
    if query:
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        clauses.append("(c.target like ? escape '\\' or c.addresses like ? escape '\\')")
        parameters.extend((pattern, pattern))
    if kind in ("ipv4", "ipv6"):
        clauses.append("c.kind='ip' and instr(c.target,':')" + ("=0" if kind == "ipv4" else ">0"))
    elif kind:
        clauses.append("c.kind=?")
        parameters.append(kind)
    where = " where " + " and ".join(clauses) if clauses else ""
    total = db.execute("select count(*) from routing_target_catalog").fetchone()[0]
    matched = db.execute("select count(*) from routing_target_catalog c" + where, parameters).fetchone()[0]
    rows = db.execute("select c.target,c.kind,c.status,c.latency_ms,c.checked_at,c.addresses from routing_target_catalog c"
                      + where + " order by c.target collate binary limit ? offset ?", (*parameters, limit, offset)).fetchall()
    keys = [row[0] for row in rows]
    sources = {key: [] for key in keys}
    if keys:
        for target, source in db.execute("select target,source from routing_target_catalog_sources where target in ("
                                         + ",".join("?" for _ in keys) + ") order by source", keys):
            sources[target].append(source)
    return {"total": total, "matched": matched, "offset": offset, "limit": limit, "query": query, "kind": kind,
            "items": [{"target": target, "kind": row_kind, "sources": sources[target], "selectable": row_kind != "cidr",
                       "ip_version": (6 if ":" in target else 4) if row_kind in ("ip", "cidr") else None,
                       "status": status, "latency_ms": latency, "checked_at": checked_at,
                       "addresses": addresses.splitlines() if addresses else []}
                      for target, row_kind, status, latency, checked_at, addresses in rows]}


def workload_workers(load_per_cpu=None, mem_available_ratio=None):
    """Reduce probe concurrency with VDS pressure; never shorten the catalogue."""
    values = []
    for value in (load_per_cpu, mem_available_ratio):
        if value is None:
            values.append(None)
        elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("Некорректный замер нагрузки VDS.")
        else:
            values.append(float(value))
    load, available = values
    if available is not None and available > 1:
        raise ValueError("Доля доступной RAM должна быть от 0 до 1.")
    if (load is not None and load >= 2.5) or (available is not None and available < .08):
        raise ValueError("VDS перегружен. Проверка целей отложена; каталог и поиск доступны.")
    if (load is not None and load >= 1.5) or (available is not None and available < .15):
        return 1
    if (load is not None and load >= 1.0) or (available is not None and available < .25):
        return 2
    if load is None or available is None or load >= .65 or available < .4:
        return 4
    return 8
