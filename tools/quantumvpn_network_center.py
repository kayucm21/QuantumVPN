"""Read-only routing laboratory and the operator's consolidated Network view.

The HTTP owner supplies validated APK payloads and CSRF tokens. Publication,
staging, confirmation and rollback deliberately remain in the existing routing
handlers. Server evidence is an allowlisted snapshot of Xray's configuration,
never a dump of inbounds, users, endpoints, transport settings or credentials.
"""
from __future__ import annotations

import hashlib
import heapq
import html
import ipaddress
import json
import re
import time
from pathlib import Path

try:
    from quantumvpn_control_quality import ADS_SUFFIXES, explain_route
except ImportError:
    from tools.quantumvpn_control_quality import ADS_SUFFIXES, explain_route


MAX_XRAY_BYTES = 4 * 1024 * 1024
MAX_XRAY_RULES = 2000
MAX_RULE_VALUES = 2048
MAX_CONFLICTS = 200
NETWORK_VIEWS = ("overview", "nodes", "dns", "routes", "ai", "mtproto")
POLICY_SOURCES = {"production": "Опубликованная", "draft": "Черновик", "staging": "Тестовый канал"}
DIRECTION_LABELS = {"block": "Блокировка", "direct": "Напрямую", "proxy": "Через VPN"}
XRAY_DOCS = "https://xtls.github.io/en/config/routing.html"


def _public_address(address) -> bool:
    return bool(address.is_global and not address.is_multicast and not address.is_unspecified
                and not address.is_loopback and not address.is_link_local and not address.is_reserved)


def _domain(value: str) -> str:
    try:
        value = value.lower().rstrip(".").encode("idna").decode("ascii")
    except (UnicodeError, AttributeError) as exc:
        raise ValueError("Некорректный домен") from exc
    if (not re.fullmatch(r"(?=.{1,253}$)[a-z0-9.-]+", value)
            or any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
                   for part in value.split("."))):
        raise ValueError("Некорректный домен")
    return value


def normalize_lab_target(raw: str) -> dict:
    """Accept one IDNA host or public numeric IP, without performing DNS/I/O."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 1024:
        raise ValueError("Введите один домен или публичный IP, не более 1024 символов")
    value = raw.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if any(char.isspace() or ord(char) < 32 for char in value) or any(char in value for char in "/@?#*\\"):
        raise ValueError("Введите домен или IP без URL, порта, wildcard и учётных данных")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError("Некорректный IP-адрес")
        host = _domain(value)
        if ("." not in host or host in {"localhost", "localhost.localdomain"}
                or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa"))):
            raise ValueError("Для лаборатории разрешены публичные домены")
        return {"kind": "domain", "target": host}
    if not _public_address(address):
        raise ValueError("Для лаборатории разрешены только публичные IP-адреса")
    return {"kind": "ip", "target": str(address)}


def _suffix(target: str, suffix: str) -> bool:
    return target == suffix or target.endswith("." + suffix)


def _policy_rules(payload: dict) -> dict:
    rules = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}
    return {key: rules.get(key, []) if isinstance(rules.get(key, []), list) else []
            for key in ("block_domains", "direct_domains", "proxy_domains", "direct_cidrs", "proxy_cidrs")}


def signed_policy_conflicts(payload: dict, limit: int = MAX_CONFLICTS) -> dict:
    """Find overlapping managed lists; never rewrite, reorder or publish them.

    Domains use APK suffix semantics, so a parent suffix conflicts with a rule
    for any descendant. CIDRs conflict on intersection, not just equality.
    The cap bounds the report size; a capped report does not claim completeness.
    """
    limit = max(1, min(MAX_CONFLICTS, int(limit)))
    rules = _policy_rules(payload)
    rows, seen = [], set()

    def add(kind, target, first, second, winner):
        identity = (kind, first["list"], first["rule"], second["list"], second["rule"])
        if identity not in seen:
            seen.add(identity)
            rows.append({"kind": kind, "target": target, "first": first, "second": second,
                         "winner": winner, "reason": "Более ранняя группа правил APK перекрывает позднюю"})
        return len(rows) > limit

    groups = [(direction, direction + "_domains") for direction in ("block", "direct", "proxy")]
    for left_index, (winner, left_key) in enumerate(groups):
        left_values = {str(value): index for index, value in enumerate(rules[left_key])}
        for _, right_key in groups[left_index + 1:]:
            right_values = {str(value): index for index, value in enumerate(rules[right_key])}
            # Walk ancestors instead of comparing every pair of suffixes.
            for source_key, values, opposite_key, opposite in (
                    (left_key, left_values, right_key, right_values),
                    (right_key, right_values, left_key, left_values)):
                for value, source_index in values.items():
                    labels = value.split(".")
                    for index in range(len(labels)):
                        ancestor = ".".join(labels[index:])
                        if ancestor not in opposite:
                            continue
                        first = {"list": source_key, "rule": value, "index": source_index}
                        second = {"list": opposite_key, "rule": ancestor, "index": opposite[ancestor]}
                        if source_key != left_key:
                            first, second = second, first
                        if add("domain", value, first, second, winner):
                            return {"items": rows[:limit], "truncated": True, "limit": limit}

    intervals = []
    for side, key in enumerate(("direct_cidrs", "proxy_cidrs")):
        listed = set()
        for index, value in enumerate(rules[key]):
            # Duplicate text contributes the same report identity. Keep its
            # first index, as the former pairwise traversal did, so repeated
            # entries cannot turn one real conflict into a quadratic scan.
            label = str(value)
            if label in listed:
                continue
            listed.add(label)
            try:
                network = ipaddress.ip_network(value, strict=False)
            except (TypeError, ValueError):
                continue
            intervals.append((network.version, int(network.network_address), int(network.broadcast_address),
                              side, index, label, network))
    # Sorted interval sweep: expired ranges cannot overlap any following one.
    # Each opposite active range necessarily intersects the current interval,
    # so work is O(n log n + reported pairs), not direct_count * proxy_count.
    # CIDRs of one family are laminar; the narrower subnet is their overlap.
    active, expiry, family = ({}, {}), ([], []), None
    for version, start, end, side, index, label, network in sorted(intervals):
        if family != version:
            active, expiry, family = ({}, {}), ([], []), version
        for other_side in (0, 1):
            while expiry[other_side] and expiry[other_side][0][0] < start:
                _, expired_index = heapq.heappop(expiry[other_side])
                active[other_side].pop(expired_index, None)
        for other_index, (other_label, other_network) in active[1 - side].items():
            current = {"list": "direct_cidrs" if side == 0 else "proxy_cidrs", "rule": label, "index": index}
            other = {"list": "proxy_cidrs" if side == 0 else "direct_cidrs", "rule": other_label, "index": other_index}
            first, second = (current, other) if side == 0 else (other, current)
            intersection = network if network.prefixlen >= other_network.prefixlen else other_network
            if add("cidr", str(intersection), first, second, "direct"):
                return {"items": rows[:limit], "truncated": True, "limit": limit}
        active[side][index] = (label, network)
        heapq.heappush(expiry[side], (end, index))
    return {"items": rows, "truncated": False, "limit": limit}


def _managed_matches(payload: dict, target: dict) -> list[dict]:
    matches, rules = [], _policy_rules(payload)
    if target["kind"] == "domain":
        for direction in ("block", "direct", "proxy"):
            key = direction + "_domains"
            for index, value in enumerate(rules[key]):
                if isinstance(value, str) and _suffix(target["target"], value):
                    matches.append({"list": key, "index": index, "rule": value, "direction": direction})
        if payload.get("adblock", {}).get("enabled"):
            adblock_index = sum(item["direction"] == "block" for item in matches)
            for index, value in enumerate(ADS_SUFFIXES):
                if _suffix(target["target"], value):
                    matches.insert(adblock_index, {"list": "apk_adblock", "index": index, "rule": value, "direction": "block"})
                    adblock_index += 1
    else:
        address = ipaddress.ip_address(target["target"])
        for direction in ("direct", "proxy"):
            key = direction + "_cidrs"
            for index, value in enumerate(rules[key]):
                try:
                    matched = address in ipaddress.ip_network(value, strict=False)
                except (TypeError, ValueError):
                    matched = False
                if matched:
                    matches.append({"list": key, "index": index, "rule": value, "direction": direction})
    return matches


def _safe_label(value, limit=96) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(char) < 32 for char in value):
        return ""
    if any(char in value for char in "@/?#\\") or "://" in value:
        return ""
    return value


def _safe_xray_value(value, kind: str) -> str:
    if not isinstance(value, str) or len(value) > 512 or any(ord(char) < 32 for char in value):
        return "unsupported:[не проверяется]"
    if value.startswith("ext:"):
        return "ext:[внешний список]"
    if value.startswith("regexp:"):
        return "regexp:[не проверяется]"
    if kind == "ip":
        if re.fullmatch(r"!?geoip:[a-zA-Z0-9_@!.-]+", value):
            return value
        if value.startswith("!"):
            return "inverse:[не проверяется]"
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return "unsupported:[не проверяется]"
    if value.startswith("geosite:"):
        return value if re.fullmatch(r"geosite:[a-zA-Z0-9_@!.-]+", value) else "unsupported:[не проверяется]"
    if value.startswith(("domain:", "full:")):
        prefix, host = value.split(":", 1)
        try:
            return prefix + ":" + _domain(host)
        except ValueError:
            return "unsupported:[не проверяется]"
    if value.startswith(("keyword:", "dotless:")):
        prefix, value = value.split(":", 1)
        if re.fullmatch(r"[a-zA-Z0-9._-]+", value):
            return prefix + ":" + value.lower()
        return "unsupported:[не проверяется]"
    # Xray's unprefixed domain form is a substring, unlike APK suffixes.
    return value.lower() if re.fullmatch(r"[a-zA-Z0-9._-]+", value) else "unsupported:[не проверяется]"


def _safe_port_expression(value) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    value = str(value)
    if len(value) > 1024 or not re.fullmatch(r"[0-9,-]+", value):
        return ""
    for part in value.split(","):
        bounds = part.split("-")
        if (len(bounds) not in {1, 2} or any(not item or not 1 <= int(item) <= 65535 for item in bounds)
                or len(bounds) == 2 and int(bounds[0]) > int(bounds[1])):
            return ""
    return value


def sanitize_xray_config(config: dict) -> dict:
    """Copy only address conditions, rule order and outbound identifiers.

    Missing session conditions are represented by their field names only.
    User emails, source addresses, headers, URLs, UUIDs, private keys and all
    inbound/outbound settings are excluded. The supplied object is not changed.
    """
    if not isinstance(config, dict):
        raise ValueError("Конфигурация Xray должна быть JSON-объектом")
    routing = config.get("routing") if isinstance(config.get("routing"), dict) else {}
    raw_rules = routing.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("Некорректный список правил Xray")
    strategy = routing.get("domainStrategy", "AsIs")
    if not isinstance(strategy, str) or strategy not in {"AsIs", "IPIfNonMatch", "IPOnDemand"}:
        strategy = "unknown"
    outbounds = []
    raw_outbounds = config.get("outbounds", [])
    if isinstance(raw_outbounds, list):
        for index, item in enumerate(raw_outbounds[:100]):
            if isinstance(item, dict):
                outbounds.append({"index": index, "tag": _safe_label(item.get("tag")) or f"outbound #{index + 1}",
                                  "protocol": _safe_label(item.get("protocol"), 32) or "unknown"})
    rules = []
    address_fields = {"domain", "ip", "type", "outboundTag", "balancerTag", "ruleTag", "webhook"}
    for index, raw in enumerate(raw_rules[:MAX_XRAY_RULES]):
        if not isinstance(raw, dict):
            rules.append({"index": index, "domains": [], "ips": [], "context_fields": ["invalid_rule"],
                          "outbound": "", "balancer": "", "incomplete": True})
            continue
        row = {"index": index, "domains": [], "ips": [], "context_fields": [], "incomplete": False,
               "outbound": _safe_label(raw.get("outboundTag")), "balancer": _safe_label(raw.get("balancerTag")),
               "inbound_tags": [], "network": "", "port": ""}
        for raw_key, clean_key in (("domain", "domains"), ("ip", "ips")):
            values = raw.get(raw_key, [])
            if not isinstance(values, list):
                row["incomplete"] = True
            else:
                row[clean_key] = [_safe_xray_value(value, raw_key) for value in values[:MAX_RULE_VALUES]]
                row["incomplete"] |= len(values) > MAX_RULE_VALUES
        inbound_tags = raw.get("inboundTag", [])
        if isinstance(inbound_tags, list):
            row["inbound_tags"] = [label for value in inbound_tags[:MAX_RULE_VALUES] if (label := _safe_label(value))]
            row["incomplete"] |= len(row["inbound_tags"]) != len(inbound_tags)
        elif inbound_tags:
            row["incomplete"] = True
        network = raw.get("network", "")
        if (isinstance(network, str) and network and len(network) <= 1024
                and all(part in {"tcp", "udp"} for part in network.split(","))):
            row["network"] = ",".join(sorted(set(network.split(","))))
        row["port"] = _safe_port_expression(raw.get("port"))
        for key, value in raw.items():
            if key in address_fields or value in (None, [], {}, ""):
                continue
            if key == "network" and row["network"] == "tcp,udp":
                continue  # Covers every Xray transport, so no traffic context is needed.
            if key == "port" and str(value) == "1-65535":
                continue
            row["context_fields"].append(key if key in {
                "port", "sourcePort", "localPort", "network", "source", "sourceIP", "localIP",
                "user", "vlessRoute", "inboundTag", "protocol", "attrs", "process"} else "other_condition")
        if raw.get("type", "field") != "field":
            row["context_fields"].append("unsupported_rule_type")
        if not any(raw.get(key) not in (None, [], {}, "") for key in raw if key not in address_fields):
            if not row["domains"] and not row["ips"]:
                row["context_fields"].append("no_effective_conditions")
        rules.append(row)
    return {"available": True, "scope": "live-server-xray", "domain_strategy": strategy, "rules": rules,
            "outbounds": outbounds, "truncated": len(raw_rules) > MAX_XRAY_RULES,
            "default_outbound_known": bool(isinstance(raw_outbounds, list) and raw_outbounds
                                           and isinstance(raw_outbounds[0], dict)),
            "rule_count": len(raw_rules), "sanitized": True,
            "note": "Снимок файла Xray; загрузка этого файла работающим процессом не подтверждена."}


def read_xray_snapshot(path: str | Path) -> dict:
    """Read one server-configured path, never one supplied by an HTTP request."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_XRAY_BYTES + 1)
        if len(raw) > MAX_XRAY_BYTES:
            raise ValueError("Слишком большой снимок Xray")
        result = sanitize_xray_config(json.loads(raw.decode("utf-8")))
        result.update(sha256=hashlib.sha256(raw).hexdigest(), checked_at=int(time.time()))
        return result
    except (OSError, UnicodeError, ValueError, TypeError):
        return {"available": False, "scope": "live-server-xray", "sanitized": True,
                "reason": "Снимок серверной конфигурации Xray недоступен или некорректен"}


def _domain_condition(values: list[str], target: dict) -> tuple[str, list[str], str]:
    if not values:
        return "yes", [], ""
    if target["kind"] != "domain":
        return "no", [], ""
    unresolved = []
    for value in values:
        if value.startswith(("geosite:", "ext:", "regexp:", "unsupported:")):
            unresolved.append(value)
            continue
        if value.startswith("domain:"):
            matched = _suffix(target["target"], value[7:])
        elif value.startswith("full:"):
            matched = target["target"] == value[5:]
        elif value.startswith("keyword:"):
            matched = value[8:] in target["target"]
        elif value.startswith("dotless:"):
            matched = "." not in target["target"] and value[8:] in target["target"]
        else:
            matched = value in target["target"]
        if matched:
            return "yes", [], value
    return ("unknown", unresolved, "") if unresolved else ("no", [], "")


def _ip_condition(values: list[str], target: dict, resolve_ip: bool) -> tuple[str, list[str], str]:
    if not values:
        return "yes", [], ""
    if target["kind"] != "ip":
        return ("unknown", ["DNS-адреса не получены"], "") if resolve_ip else ("no", [], "")
    address, unresolved = ipaddress.ip_address(target["target"]), []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            unresolved.append(value)
            continue
        if address in network:
            return "yes", [], value
    return ("unknown", unresolved, "") if unresolved else ("no", [], "")


def _validate_traffic_context(context: dict | None) -> dict:
    if context is None:
        return {}
    if not isinstance(context, dict) or set(context) - {"inbound_tag", "network", "port"}:
        raise ValueError("Серверный сценарий допускает только inbound, транспорт и порт")
    result = {}
    if "inbound_tag" in context:
        if not _safe_label(context["inbound_tag"]):
            raise ValueError("Некорректная метка inbound в серверном сценарии")
        result["inbound_tag"] = context["inbound_tag"]
    if "network" in context:
        if context["network"] not in {"tcp", "udp"}:
            raise ValueError("Некорректный транспорт серверного сценария")
        result["network"] = context["network"]
    if "port" in context:
        if isinstance(context["port"], bool) or not isinstance(context["port"], int) or not 1 <= context["port"] <= 65535:
            raise ValueError("Некорректный порт серверного сценария")
        result["port"] = context["port"]
    return result


def _traffic_conditions(rule: dict, context: dict) -> tuple[list[str], list[str]]:
    states, unresolved = [], []
    for field in rule.get("context_fields", []):
        if field == "inboundTag" and rule.get("inbound_tags") and "inbound_tag" in context:
            states.append("yes" if context["inbound_tag"] in rule["inbound_tags"] else "no")
        elif field == "network" and rule.get("network") and "network" in context:
            states.append("yes" if context["network"] in rule["network"].split(",") else "no")
        elif field == "port" and rule.get("port") and "port" in context:
            matched = False
            for part in rule["port"].split(","):
                bounds = [int(value) for value in part.split("-")]
                matched |= bounds[0] <= context["port"] <= bounds[-1]
            states.append("yes" if matched else "no")
        else:
            states.append("unknown")
            unresolved.append(field)
    return states, unresolved


def _evaluate_xray_rule(rule: dict, target: dict, resolve_ip: bool, traffic_context: dict) -> dict:
    domain_state, domain_unknown, domain_match = _domain_condition(rule.get("domains", []), target)
    ip_state, ip_unknown, ip_match = _ip_condition(rule.get("ips", []), target, resolve_ip)
    context_states, context_unknown = _traffic_conditions(rule, traffic_context)
    states = [domain_state, ip_state] + context_states
    # All populated fields are ANDed. A known mismatch defeats missing context.
    if "no" in states and not rule.get("incomplete"):
        state = "no"
    elif ("unknown" in states
          or rule.get("incomplete") or not (rule.get("outbound") or rule.get("balancer"))):
        state = "unknown"
    else:
        state = "yes"
    return {"index": rule["index"], "state": state, "matched": domain_match or ip_match,
            "outbound": rule.get("outbound", ""), "balancer": rule.get("balancer", ""),
            "unresolved": domain_unknown + ip_unknown + context_unknown
                          + (["неполный снимок правила"] if rule.get("incomplete") else [])}


def explain_xray_route(snapshot: dict | None, target: str | dict, traffic_context: dict | None = None) -> dict:
    """Follow Xray's first effective rule with honest unknown membership/context.

    IPIfNonMatch has a domain-only first pass and a DNS-dependent second pass.
    AsIs does not resolve domains. IPOnDemand can encounter an unknown IP rule
    before a later domain match. No live DNS, geodata or session is fabricated.
    See Xray's routing documentation for order, AND fields and default outbound.
    """
    target = normalize_lab_target(target) if isinstance(target, str) else target
    traffic_context = _validate_traffic_context(traffic_context)
    base = {"scope": "live-server-xray", "matched_rule": None, "trace": [], "possible_rules": [],
            "certainty": "unknown", "direction": "Не определено", "source_docs": XRAY_DOCS}
    if traffic_context:
        base["traffic_context"] = traffic_context
        base["scenario_label"] = ("Серверный сценарий VLESS/TCP 443, не личная сессия"
                                  if traffic_context == {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
                                  else "Серверный сценарий с заданными параметрами, не личная сессия")
    if not snapshot or not snapshot.get("available") or not snapshot.get("sanitized"):
        return {**base, "reason": "Нет проверенного снимка серверных правил Xray"}
    base["evidence_note"] = snapshot.get("note", "Проверены правила снимка; реальная сессия не проверялась.")
    strategy = snapshot.get("domain_strategy", "AsIs")
    if strategy not in {"AsIs", "IPIfNonMatch", "IPOnDemand"}:
        return {**base, "reason": "Неизвестная стратегия разрешения доменов Xray"}
    trace, possible = [], []
    passes = [strategy == "IPOnDemand"]
    if target["kind"] == "domain" and strategy == "IPIfNonMatch":
        passes.append(True)
    for pass_index, resolve in enumerate(passes):
        for rule in snapshot.get("rules", []):
            row = _evaluate_xray_rule(rule, target, resolve, traffic_context)
            row["pass"] = pass_index + 1
            trace.append(row)
            if row["state"] == "unknown":
                possible.append(row)
            elif row["state"] == "yes":
                if possible:
                    return {**base, "trace": trace, "possible_rules": possible, "provisional_rule": row,
                            "reason": "Более раннее правило зависит от списков или параметров соединения; точный победитель не установлен"}
                destination = row["outbound"] or ("балансировщик " + row["balancer"])
                return {**base, "certainty": "known", "direction": destination, "matched_rule": row, "trace": trace,
                        "reason": "Первое совпавшее правило по заданному адресу; параметры реальной сессии не проверялись"}
        # An unknown first-pass rule may match; do not claim a DNS second pass.
        if possible:
            return {**base, "trace": trace, "possible_rules": possible,
                    "reason": "Совпадение зависит от geosite/geoip, DNS или параметров соединения"}
    if snapshot.get("truncated"):
        return {**base, "trace": trace, "reason": "Снимок правил неполный; маршрут по умолчанию не подтверждён"}
    outbounds = snapshot.get("outbounds", [])
    if not outbounds:
        return {**base, "trace": trace, "reason": "В снимке отсутствует исходящий маршрут по умолчанию"}
    if not snapshot.get("default_outbound_known", True) or outbounds[0].get("index", 0) != 0:
        return {**base, "trace": trace, "reason": "Первый outbound снимка некорректен; маршрут по умолчанию не подтверждён"}
    return {**base, "certainty": "known", "direction": outbounds[0]["tag"], "trace": trace,
            "reason": "Правила для заданного адреса не совпали; Xray использует первый outbound"}


def route_laboratory(payload: dict, target: str, xray_snapshot: dict | None = None,
                     policy_source: str = "production", traffic_context: dict | None = None) -> dict:
    """Compare separate APK/server scopes without resolving or modifying either."""
    if policy_source not in POLICY_SOURCES:
        raise ValueError("Неизвестный источник политики APK")
    parsed = normalize_lab_target(target)
    signed = explain_route(payload, parsed["target"])
    known = signed["direction"] not in {"Профиль устройства", "Зависит от RU-списка APK"}
    signed.update(scope="signed-apk-policy", source=policy_source, certainty="known" if known else "unknown",
                  matching_rules=_managed_matches(payload, parsed))
    return {**parsed, "checked_at": int(time.time()), "signed": signed,
            "server": explain_xray_route(xray_snapshot, parsed, traffic_context), "conflicts": signed_policy_conflicts(payload),
            "note": "Лаборатория читает правила. DNS-запросы, подключения и изменения конфигурации не выполняются."}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def render_lab_result(result: dict | None) -> str:
    if not result:
        return "<div class=network-empty>Введите адрес: увидите совпавшее правило и ограничения проверки.</div>"
    cards = []
    for key, title in (("signed", "Политика APK"), ("server", "Сервер Xray")):
        report = result.get(key, {})
        known = report.get("certainty") == "known"
        matched = report.get("matched_rule")
        rule = f"Правило #{_int(matched.get('index')) + 1}: {matched.get('matched') or 'условия адреса'}" if matched else report.get("matched", "Нет точного совпадения")
        if key == "signed":
            rule = f"{POLICY_SOURCES.get(report.get('source'), 'Политика')} · r{report.get('revision', '—')} · {rule}"
        unknown = report.get("possible_rules", [])
        details = "".join(f"<li>#{_int(item.get('index')) + 1}: {_esc(', '.join(item.get('unresolved', [])) or 'неизвестные условия')}</li>" for item in unknown[:8])
        evidence = f"<p>{_esc(report['scenario_label'])}</p>" if report.get("scenario_label") else ""
        evidence += f"<p>{_esc(report['evidence_note'])}</p>" if report.get("evidence_note") else ""
        cards.append(f"<article class=network-verdict><span class='network-badge {'known' if known else 'unknown'}'>{_esc(title)} · {'определено' if known else 'нужны данные'}</span><strong>{_esc(report.get('direction', 'Не определено'))}</strong><p>{_esc(rule)}</p><small>{_esc(report.get('reason', ''))}</small>{evidence}{'<ul>' + details + '</ul>' if details else ''}</article>")
    return f"<div class=network-result><div class=network-target>{_esc(result.get('target', ''))}</div><div class=network-verdict-grid>{''.join(cards)}</div></div>"


def render_conflicts(report: dict) -> str:
    rows = "".join(f"<tr><td><code>{_esc(row['target'])}</code></td><td>{_esc(row['first']['list'])}<br><small>{_esc(row['first']['rule'])}</small></td><td>{_esc(row['second']['list'])}<br><small>{_esc(row['second']['rule'])}</small></td><td>{_esc(DIRECTION_LABELS.get(row['winner'], row['winner']))}</td></tr>" for row in report.get("items", [])[:30])
    if not rows:
        return "<p class=network-empty>Пересечений между управляемыми списками block, direct и proxy не найдено.</p>"
    suffix = "<p class=network-hint>Показана часть пересечений. Уточните широкие правила перед публикацией.</p>" if report.get("truncated") or len(report["items"]) > 30 else ""
    return f"<div class=network-table><table><thead><tr><th>Область</th><th>Раньше</th><th>Позже</th><th>Приоритет</th></tr></thead><tbody>{rows}</tbody></table></div>{suffix}"


NETWORK_CSS = """
.network-center{--nc-bg:#06111e;--nc-line:#193749;--nc-text:#d9ecf5;--nc-muted:#829eaf;--nc-blue:#30cefa;color:var(--nc-text)}
.network-center h2{margin:0 0 10px;font-size:17px}.network-center p{line-height:1.45}.network-nav{display:flex;flex-wrap:wrap;gap:5px;padding:7px;margin:0 0 14px;border:1px solid var(--nc-line);border-radius:11px;background:#071523}.network-nav a{padding:9px 14px;border-radius:7px;color:#97b5c6;text-decoration:none;font-size:12px;font-weight:700}.network-nav a:hover,.network-nav a[aria-current=page]{background:#10384b;color:#62dfff}
.network-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:3px 0 15px}.network-heading p{margin:4px 0 0;color:var(--nc-muted);font-size:12px}.network-kicker{color:var(--nc-blue);font-size:10px;font-weight:800;letter-spacing:.12em}.network-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(270px,.75fr);gap:12px}.network-card{padding:16px;border:1px solid var(--nc-line);border-radius:11px;background:linear-gradient(130deg,#091b29,#06131f);margin:0 0 12px}.network-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}.network-metric{padding:13px;border:1px solid var(--nc-line);border-radius:9px;background:#071725}.network-metric span,.network-metric small{display:block;color:var(--nc-muted);font-size:11px}.network-metric b{display:block;font-size:20px;margin:5px 0;color:#e3f6ff}.network-hint,.network-empty{color:var(--nc-muted);font-size:12px;line-height:1.5}.network-empty{padding:10px 0}.network-center label{display:block;font-size:12px;color:#a7c3d1;margin:10px 0}.network-center input:not([type=checkbox]),.network-center select,.network-center textarea{width:100%;margin-top:5px;box-sizing:border-box;min-height:38px;border:1px solid #27495d;border-radius:7px;background:#06131f;color:#dcedf7;padding:9px;font-size:12px}.network-center textarea{min-height:65px;resize:vertical;font:12px/1.45 Consolas,monospace}.network-center fieldset{border:0;padding:0;margin:0;min-width:0}.network-fields{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.network-switches{display:flex;flex-wrap:wrap;gap:14px}.network-switches label{display:flex;gap:7px;align-items:center}.network-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.network-center button,.network-center .button{min-height:36px;padding:8px 12px;font-size:12px;border-radius:7px}.network-lab-input{display:grid;grid-template-columns:minmax(160px,1fr) 150px;gap:12px}.network-lab-input label{margin-top:0}.network-result{border-top:1px solid var(--nc-line);margin-top:14px;padding-top:12px}.network-target{font:13px Consolas,monospace;margin-bottom:10px;color:#c0edff}.network-verdict-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}.network-verdict{border:1px solid #203f52;border-radius:8px;padding:11px;min-width:0}.network-verdict strong{display:block;font-size:15px;margin:9px 0}.network-verdict p,.network-verdict small,.network-verdict li{font-size:11px;color:#90adbf;overflow-wrap:anywhere}.network-verdict ul{padding-left:17px}.network-badge{display:inline-block;font-size:10px;border-radius:5px;padding:4px 7px;background:#113044;color:#8dc9e3}.network-badge.known{color:#64edbd;background:#0b352f}.network-badge.unknown{color:#edca79;background:#362e1c}.network-table{overflow-x:auto}.network-center table{width:100%;border-collapse:collapse;font-size:12px}.network-center td,.network-center th{padding:8px;border-bottom:1px solid #163447;text-align:left}.network-center th{font-size:10px;color:#789bae;text-transform:uppercase}.network-center td small{color:var(--nc-muted)}.network-node-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.network-node{border:1px solid #1c3b4d;border-radius:8px;padding:12px}.network-node b{font-size:13px}.network-node p{font-size:11px;color:var(--nc-muted);overflow-wrap:anywhere}.network-rule-title{display:flex;justify-content:space-between;gap:10px;align-items:center}.network-rule-title span{font-size:10px;color:var(--nc-muted)}.network-history{margin-top:12px}.network-history summary{cursor:pointer;font-size:12px;font-weight:700;color:#9ac4d8}.network-history table{margin-top:10px}.network-center a.network-link{color:#6cd8fa;text-decoration:none;font-size:12px}.network-center a.network-link:hover{text-decoration:underline}
@media(max-width:1050px){.network-grid{grid-template-columns:1fr}}@media(max-width:680px){.network-verdict-grid,.network-fields,.network-node-list,.network-lab-input{grid-template-columns:1fr}.network-metrics{grid-template-columns:1fr 1fr}.network-nav a{padding:8px 9px}.network-heading{align-items:flex-start;flex-direction:column}.network-card{padding:13px}}
"""


def _csrf(csrf: str, view: str = "routes", policy_source: str | None = None) -> str:
    source_field = ""
    if policy_source is not None:
        policy_source = policy_source if policy_source in POLICY_SOURCES else "production"
        source_field = f'<input type=hidden name=policy_source value={policy_source}>'
    return f'<input type=hidden name=csrf value="{_esc(csrf)}"><input type=hidden name=return_tab value=network><input type=hidden name=return_view value={"dns" if view == "dns" else "routes"}>{source_field}'


def _policy_form(s: dict, payload: dict, csrf: str, can_write: bool, dns_only=False,
                 policy_source: str = "production") -> str:
    rules, dns = _policy_rules(payload), payload.get("dns", {})
    hidden, inputs = [], []
    for key, title in (("proxy_domains", "Через VPN · домены"), ("proxy_cidrs", "Через VPN · IP / CIDR"),
                       ("direct_domains", "Напрямую · домены"), ("direct_cidrs", "Напрямую · IP / CIDR"),
                       ("block_domains", "Блокировка · домены")):
        value = "\n".join(str(item) for item in rules[key])
        if dns_only:
            hidden.append(f'<input type=hidden name=routing_{key} value="{_esc(value)}">')
        else:
            inputs.append(f'<label>{_esc(title)}<textarea rows=2 name=routing_{key}>{_esc(value)}</textarea></label>')
    profiles = "".join(f'<option value={name} {"selected" if payload.get("profile", "balanced") == name else ""}>{label}</option>' for name, label in (("balanced", "Сбалансированный"), ("proxy_all", "Все через VPN"), ("whitelist", "Белый список")))
    modes = "".join(f'<option value={name} {"selected" if dns.get("mode", "vpn_only") == name else ""}>{label}</option>' for name, label in (("vpn_only", "Только в VPN"), ("system", "Системный")))
    rollout = max(1, min(100, _int(s.get("routing_staging_rollout_percent"), 10)))
    return f'''<form class=network-policy method=post action=/operator/routing>{_csrf(csrf, "dns" if dns_only else "routes", policy_source)}{''.join(hidden)}
      <fieldset {"disabled" if not can_write else ""}><div class=network-switches>
      <label><input type=checkbox name=routing_enabled {"checked" if payload.get("enabled", True) else ""}> Управляемые правила</label>
      <label><input type=checkbox name=routing_adblock_enabled {"checked" if payload.get("adblock", {}).get("enabled") else ""}> Блокировка рекламы</label></div>
      {"<div class=network-fields>" + ''.join(inputs) + "</div>" if inputs else ""}
      <div class=network-fields><label>Профиль APK<select name=routing_profile>{profiles}</select></label><label>DNS<select name=routing_dns_mode>{modes}</select></label>
      <label>DNS-over-HTTPS<input type=url maxlength=512 name=routing_dns_resolver value="{_esc(dns.get('resolver', ''))}" placeholder="https://dns.adguard-dns.com/dns-query"></label>
      <label>Тестовый канал, %<input type=number min=1 max=100 name=routing_staging_rollout_percent value={rollout}></label></div>
      <p class=network-hint>Сохранение создаёт черновик. Публикация проходит через просмотр изменений и отдельное подтверждение.</p>
      <div class=network-actions><button class=secondary name=action value=save>Сохранить черновик</button><button class=secondary name=action value=stage>Тестовый канал</button><button name=action value=publish>Предпросмотр публикации</button></div></fieldset></form>'''


def _history(rows: list[dict], csrf: str, can_write: bool, policy_source: str = "production",
             view: str = "routes") -> str:
    rendered = []
    for item in rows[:12]:
        rollback = "—"
        if item.get("state") == "production" and can_write:
            rollback = f'<form method=post action=/operator/routing>{_csrf(csrf, view, policy_source)}<input type=hidden name=revision value={_int(item.get("revision"))}><button class=secondary name=action value=rollback>Просмотреть откат</button></form>'
        rendered.append(f'<tr><td>r{_int(item.get("revision"))}</td><td>{_esc(item.get("actor", "—"))}</td><td>{_esc(item.get("state", "—"))}</td><td>{_esc(item.get("note", "")[:160])}</td><td>{rollback}</td></tr>')
    body = "".join(rendered) or "<tr><td colspan=5>История появится после публикации.</td></tr>"
    return f'<details class="network-card network-history"><summary>Ревизии и безопасный откат</summary><p class=network-hint>Откат проходит предпросмотр и создаёт новую ревизию. Предыдущие версии остаются в журнале.</p><div class=network-table><table><thead><tr><th>Ревизия</th><th>Оператор</th><th>Канал</th><th>Заметка</th><th></th></tr></thead><tbody>{body}</tbody></table></div></details>'


def render_network_hub(s: dict, csrf: str, *, payload: dict, lab_result: dict | None = None,
                       xray_snapshot: dict | None = None, nodes: list[dict] | None = None,
                       history: list[dict] | None = None, active: str = "overview", can_write: bool = True,
                       panel_html: dict[str, str] | None = None, policy_source: str = "production") -> str:
    """Return a standalone Aurora fragment with no outer/nested parent form.

    GET links use tab=network&network_view=<NETWORK_VIEWS>. The laboratory POST
    is /operator/network/lab with route_target, policy_source and csrf. All APK
    writes reuse /operator/routing. panel_html may contain trusted existing
    rendered nodes/AI/MTProto, journal controls, or a catalog scanner/dialog
    fragment supplied by the HTTP owner. Catalog forms must carry their own
    CSRF, selected policy_source and return_view, and obey the supplied role.
    The host must render catalog/scan IDs only once. Never pass raw
    configuration or user-generated HTML in this mapping.
    """
    active = active if active in NETWORK_VIEWS else "overview"
    policy_source = policy_source if policy_source in POLICY_SOURCES else "production"
    panel_html = panel_html or {}
    source_label = POLICY_SOURCES.get(policy_source, "Политика")
    # A source switch must be explicit. Otherwise moving from a saved routes
    # draft to DNS would load the published lists into hidden fields, and the
    # next DNS save would unintentionally replace the draft's pending rules.
    local_url = lambda view: f"/operator?tab=network&amp;network_view={view}&amp;policy_source={policy_source}"
    nav = "".join(f'<a href="{local_url(name)}" {"aria-current=page" if active == name else ""}>{label}</a>' for name, label in (("overview", "Обзор"), ("nodes", "Ноды"), ("dns", "DNS"), ("routes", "Маршруты"), ("ai", "AI"), ("mtproto", "Telegram")))
    rules, node_rows = _policy_rules(payload), nodes or []
    conflicts = signed_policy_conflicts(payload)
    staging = s.get("routing_staging_enabled") == "1"
    server_state = "Снимок доступен" if xray_snapshot and xray_snapshot.get("available") else "Нет снимка"
    metrics = f'<div class=network-metrics><div class=network-metric><span>Политика APK</span><b>r{_int(payload.get("revision"))}</b><small>{_esc(source_label)} · {sum(len(values) for values in rules.values())} правил</small></div><div class=network-metric><span>Тестовый канал</span><b>{"r" + str(_int(s.get("routing_staging_revision"))) if staging else "Выключен"}</b><small>{str(max(1, min(100, _int(s.get("routing_staging_rollout_percent"), 10)))) + "% устройств" if staging else "Ожидает публикации"}</small></div><div class=network-metric><span>Xray · сервер</span><b>{_int(xray_snapshot.get("rule_count")) if xray_snapshot and xray_snapshot.get("available") else "—"}</b><small>{server_state}</small></div></div>'
    options = "".join(f'<option value={name} {"selected" if policy_source == name else ""}>{label}</option>' for name, label in POLICY_SOURCES.items())
    lab = f'''<section class=network-card><h2>Лаборатория маршрутов</h2><p class=network-hint>Домен или публичный IPv4 / IPv6 → первое правило и возможные пересечения. APK и сервер проверяются отдельно.</p>
      <form method=post action=/operator/network/lab>{_csrf(csrf)}<fieldset {"disabled" if not can_write else ""}><div class=network-lab-input><label>Адрес<input name=route_target maxlength=1024 required value="{_esc((lab_result or {}).get('target', ''))}" placeholder="youtube.com или 8.8.8.8"></label><label>Политика APK<select name=policy_source>{options}</select></label></div><button class=secondary>Объяснить маршрут</button></fieldset></form>{render_lab_result(lab_result)}</section>'''
    if active in {"overview", "routes", "dns"} and panel_html.get("catalog"):
        # The known-target catalog and scanner are the existing bounded UI,
        # not a second network crawler. Append after the laboratory's closing
        # form so imports, scans and reviewed results never nest in a policy
        # or lab form. A viewer can browse/search without enabling writes.
        lab += '<section class="network-card network-catalog-tools"><div class=network-rule-title><h2>Каталог и проверка целей</h2><span>IPv4 · IPv6 · домены</span></div>'
        lab += '<p class=network-hint>Все известные цели из подключённых списков, правил и импортов — без повторов. Поиск по доменам, поддоменам, IP и CIDR; это не список всех адресов Интернета.</p>'
        lab += '<button type=button class=secondary data-catalog-open>Найти и сканировать цели</button>'
        lab += '<p class=network-hint>Измеряются только выбранные публичные адреса. TCP/443 с VDS — не пинг телефона. Добавление создаёт черновик; публикация подтверждается отдельно.</p>'
        lab += panel_html["catalog"] + '</section>'
    conflict_card = f'<section class=network-card><div class=network-rule-title><h2>Конфликты правил</h2><span>{len(conflicts["items"])}{ "+" if conflicts["truncated"] else ""}</span></div>{render_conflicts(conflicts)}</section>'
    return_view = "dns" if active == "dns" else "routes"
    journal = panel_html.get("journal", "") + _history(history or [], csrf, can_write, policy_source, return_view)
    staged_controls = ""
    if staging and can_write:
        staged_controls = f'<div class=network-actions><form method=post action=/operator/routing>{_csrf(csrf, return_view, policy_source)}<button name=action value=promote>Просмотреть публикацию тестового канала</button></form><form method=post action=/operator/routing>{_csrf(csrf, return_view, policy_source)}<button class=secondary name=action value=discard_stage>Снять тестовый канал</button></form></div>'
    workflow = f'<section class=network-card><h2>Применение и откат</h2><p class=network-hint>Черновик → тестовый канал → просмотр изменений → подтверждение. Каждая публикация подписывается Ed25519 и сохраняется в журнале.</p>{staged_controls}<a class=network-link href="{local_url("routes")}">Открыть редактор правил →</a></section>'
    if active == "overview":
        body = metrics + f'<div class=network-grid><div>{lab}{conflict_card}</div><div>{workflow}<section class=network-card><h2>DNS внутри VPN</h2><p>{_esc(payload.get("dns", {}).get("resolver") or "Не выбран")}</p><p class=network-hint>Режим: {_esc(payload.get("dns", {}).get("mode", "vpn_only"))}</p><a class=network-link href="{local_url("dns")}">Настроить DNS →</a></section></div></div>' + journal
    elif active == "routes":
        body = metrics + f'<div class=network-grid><section class=network-card><h2>Правила подписанной политики</h2>{_policy_form(s, payload, csrf, can_write, policy_source=policy_source)}</section><div>{lab}{conflict_card}{workflow}</div></div>' + journal
    elif active == "dns":
        body = f'<div class=network-grid><section class=network-card><h2>DNS и профиль APK</h2><p class=network-hint>Настройки применяются в активном VPN-туннеле через подписанную политику.</p>{_policy_form(s, payload, csrf, can_write, dns_only=True, policy_source=policy_source)}</section><div>{lab}{workflow}</div></div>' + journal
    elif active == "nodes":
        cards = "".join(f'<article class=network-node><b>{_esc(item.get("label", item.get("name", "Нода")))}</b><p>{_esc(item.get("host", "Адрес не указан"))}</p><span class=network-badge>{"Включена" if item.get("enabled") else "Отключена"}</span></article>' for item in node_rows[:80])
        fallback = f'<section class=network-card><h2>Ноды и доступность</h2><div class=network-node-list>{cards or "<p class=network-empty>Снимок нод пока недоступен.</p>"}</div><p class=network-hint>Включение в базе и доступность подключения проверяются раздельно.</p><a class=network-link href="/operator?tab=latency">Открыть измерения и управление нодами →</a></section>'
        body = panel_html.get("nodes", fallback)
    elif active == "ai":
        body = panel_html.get("ai", f'<section class=network-card><h2>AI · анализ сети</h2><p>Последний статус: {_esc(s.get("ai_last_status", "Нет данных")[:96])}</p><p class=network-hint>Предложения модели требуют просмотра оператором перед применением правил.</p><a class=network-link href="/operator?tab=ai">Открыть настройки и историю анализа →</a></section>')
    else:
        body = panel_html.get("mtproto", '<section class=network-card><h2>MTProto</h2><p class=network-empty>В переданном снимке нет подтверждённой конфигурации MTProto.</p><a class=network-link href="/operator?tab=service">Открыть сервисы и протоколы →</a></section>')
    return f'<style>{NETWORK_CSS}</style><section class=network-center data-network-view={active}><header class=network-heading><div><div class=network-kicker>NETWORK CENTER</div><p>Ноды, DNS, маршруты и сетевые инструменты в одном месте.</p></div><span class=network-badge>{_esc(source_label)} · r{_int(payload.get("revision"))}</span></header><nav class=network-nav aria-label="Разделы сети">{nav}</nav>{body}</section>'
