"""Evidence-backed operator controls; no shell, native config or client secrets.

All writes use the caller's SQLite transaction and must be committed by the
HTTP handler. Passkey handlers must commit consumed challenges even when a
ceremony is rejected. WebAuthn crypto belongs exclusively to Duo py_webauthn.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import math
import re
import secrets
import sqlite3
import time
from collections import defaultdict
from urllib.parse import urlsplit

SCOPES = {
    "routing": {
        "routing_enabled", "routing_profile", "routing_adblock_enabled", "routing_dns_mode",
        "routing_dns_resolver", "routing_direct_domains", "routing_proxy_domains",
        "routing_block_domains", "routing_direct_cidrs", "routing_proxy_cidrs",
    },
    "nodes": {
        "nodes_recommended", "nodes_forbidden", "node_map_config", "load_balancer_enabled",
        "load_balancer_strategy", "load_balancer_max_latency_ms", "latency_optimization_enabled",
        "latency_max_ms", "latency_probe_interval", "latency_probe_targets", "auto_quarantine_enabled", "auto_quarantine_failures",
        "auto_quarantine_recovery_checks", "auto_quarantine_ttl_minutes",
    },
    "release": {"rollout_percent", "update_rollout_paused", "public_download_enabled", "release_guard_enabled"},
}
BOOL_KEYS = {
    "routing_enabled", "routing_adblock_enabled", "load_balancer_enabled", "latency_optimization_enabled",
    "auto_quarantine_enabled", "update_rollout_paused", "public_download_enabled", "release_guard_enabled",
}
INT_KEYS = {
    "rollout_percent": (1, 100), "load_balancer_max_latency_ms": (20, 5000), "latency_max_ms": (20, 5000),
    "auto_quarantine_failures": (2, 10), "auto_quarantine_recovery_checks": (1, 10),
    "auto_quarantine_ttl_minutes": (5, 1440),
    "latency_probe_interval": (15, 300),
}
CHOICES = {
    "routing_profile": {"balanced", "whitelist", "proxy_all"},
    "routing_dns_mode": {"vpn_only", "system"},
    "load_balancer_strategy": {"latency_health", "stable"},
}
PREVIEW_TTL = 600
PASSKEY_TTL = 120
MAX_PASSKEYS = 10
MIN_QUALITY_GROUP = 3


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(value) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _now(now=None) -> int:
    return int(time.time() if now is None else now)


def _rows(db, sql, args=()) -> list[dict]:
    cur = db.execute(sql, args)
    keys = [column[0] for column in cur.description]
    return [dict(zip(keys, row)) for row in cur.fetchall()]


def migrate(db):
    """Call once at DB bootstrap, outside a live HTTP write transaction."""
    schema = """
        create table if not exists control_previews (
            id text primary key, digest text not null, scope text not null, actor text not null,
            created_at integer not null, expires_at integer not null, base_json text not null,
            candidate_json text not null, guards_json text not null, state text not null default 'pending'
        );
        create table if not exists control_config_snapshots (
            id integer primary key autoincrement, scope text not null, actor text not null,
            created_at integer not null, before_json text not null, after_json text not null
        );
        create table if not exists control_passkey_users (
            username text primary key, user_handle blob not null unique
        );
        create table if not exists control_passkeys (
            credential_id text primary key, username text not null, user_handle blob not null,
            public_key blob not null, sign_count integer not null, label text not null,
            created_at integer not null, last_used_at integer not null default 0,
            revoked_at integer not null default 0
        );
        create index if not exists control_passkeys_user on control_passkeys(username,revoked_at);
        create table if not exists control_passkey_challenges (
            id text primary key, purpose text not null, username text not null, binding_hash text not null,
            challenge blob not null, created_at integer not null, expires_at integer not null,
            consumed_at integer not null default 0
        );
        create index if not exists control_passkey_expiry on control_passkey_challenges(expires_at);
    """
    for statement in schema.split(";"):
        if statement.strip():
            db.execute(statement)


def _require_role(role, scope):
    if role not in {"operator", "owner"} or (scope == "release" and role != "owner"):
        raise PermissionError("Недостаточно прав для изменения этого раздела")


def _domain(value):
    try:
        value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, AttributeError) as exc:
        raise ValueError("Некорректный домен") from exc
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Некорректный домен")
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in value.split(".")):
        raise ValueError("Некорректный домен")
    return value


def _list(value, cidr=False):
    parts = [part.strip() for part in re.split(r"[,;\s]+", value) if part.strip()]
    if len(parts) > 2000:
        raise ValueError("Не более 2000 правил в каждом списке")
    result = []
    for item in parts:
        normalized = str(ipaddress.ip_network(item, strict=False)) if cidr else _domain(item)
        if normalized not in result:
            result.append(normalized)
    return ",".join(result)


def validate_values(scope, values):
    if scope not in SCOPES or not isinstance(values, dict) or set(values) - SCOPES[scope]:
        raise ValueError("Разрешены только типизированные настройки выбранного раздела")
    out = {}
    for key, raw in values.items():
        if not isinstance(raw, (str, int, bool)) or len(str(raw)) > 200_000:
            raise ValueError("Некорректное значение настройки")
        value = str(raw).strip()
        if key in BOOL_KEYS:
            if value not in {"0", "1"}:
                raise ValueError("Переключатель должен быть 0 или 1")
        elif key in INT_KEYS:
            lo, hi = INT_KEYS[key]
            if not re.fullmatch(r"[0-9]+", value) or not lo <= int(value) <= hi:
                raise ValueError("Число вне допустимых границ")
            value = str(int(value))
        elif key in CHOICES:
            if value not in CHOICES[key]:
                raise ValueError("Неизвестный вариант настройки")
        elif key.endswith("_domains"):
            value = _list(value)
        elif key.endswith("_cidrs"):
            value = _list(value, cidr=True)
        elif key == "routing_dns_resolver":
            if value:
                parsed = urlsplit(value)
                if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                        or parsed.fragment or len(value) > 512 or parsed.port not in {None, 443}):
                    raise ValueError("DNS-over-HTTPS: только HTTPS URL без секретов")
                _domain(parsed.hostname)
                try:
                    if not ipaddress.ip_address(parsed.hostname).is_global:
                        raise ValueError("Локальный DNS URL запрещён")
                except ValueError as exc:
                    if "Локальный" in str(exc):
                        raise
                if any(part in parsed.hostname.lower() for part in ("localhost", ".local")):
                    raise ValueError("Локальный DNS URL запрещён")
        elif key == "latency_probe_targets":
            targets = [target.strip() for target in value.split(",") if target.strip()]
            if not 1 <= len(targets) <= 24 or len(value) > 5000:
                raise ValueError("От 1 до 24 TCP-целей")
            for target in targets:
                parsed = urlsplit("https://" + target)
                if (not parsed.hostname or not parsed.port or parsed.username or parsed.password
                        or parsed.path or parsed.query or parsed.fragment):
                    raise ValueError("TCP-цель должна содержать только host:port")
                try:
                    address = ipaddress.ip_address(parsed.hostname)
                except ValueError:
                    _domain(parsed.hostname)
                else:
                    if not address.is_global:
                        raise ValueError("TCP-цель должна быть публичной")
            value = ",".join(targets)
        elif key == "node_map_config":
            lines = [line.strip() for line in value.splitlines() if line.strip()]
            if len(lines) > 24 or len(value) > 5000:
                raise ValueError("Не более 24 нод")
            for line in lines:
                parts = [part.strip() for part in line.split("|")]
                if len(parts) != 5 or not parts[0] or len(parts[0]) > 64 or len(parts[4]) > 96:
                    raise ValueError("Нода: название | host:port | широта | долгота | место")
                url = urlsplit("https://" + parts[1])
                if not url.hostname or not url.port or url.username or url.password or url.path or url.query or url.fragment:
                    raise ValueError("Адрес ноды должен содержать только host:port")
                if not 1 <= url.port <= 65535:
                    raise ValueError("Некорректный порт")
                try:
                    address = ipaddress.ip_address(url.hostname)
                    if not address.is_global:
                        raise ValueError("Нода должна иметь публичный адрес")
                except ValueError as exc:
                    if "публичный" in str(exc):
                        raise
                    _domain(url.hostname)
                lat, lon = float(parts[2]), float(parts[3])
                if not math.isfinite(lat) or not math.isfinite(lon) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
                    raise ValueError("Некорректные координаты ноды")
            value = "\n".join(lines)
        else:  # Operator-facing labels; never executable commands or URIs.
            if len(value) > 1000 or any(ord(c) < 32 and c not in "\n\t" for c in value):
                raise ValueError("Некорректный список нод")
        out[key] = value
    return out


def _live(db):
    return dict(db.execute("select key,value from settings"))


def _guard_values(current):
    return {key: str(current.get(key, "")) for key in ("config_revision", "routing_revision", "app_version", "app_version_code")}


def preview_settings(db, current, candidate, actor, scope, role="operator", now=None):
    _require_role(role, scope)
    values = validate_values(scope, candidate)
    if not values:
        raise ValueError("Нет изменений для просмотра")
    if not actor or len(actor) > 64:
        raise ValueError("Некорректная учётная запись")
    moment = _now(now)
    actual = _live(db)
    if any(str(actual.get(key, "")) != str(current.get(key, "")) for key in SCOPES[scope]) or _guard_values(actual) != _guard_values(current):
        raise ValueError("Настройки изменились. Обновите страницу и повторите просмотр")
    before = {key: str(actual.get(key, "")) for key in sorted(SCOPES[scope])}
    after = {**before, **values}
    diffs = [{"key": key, "before": before[key], "after": after[key]} for key in sorted(values) if before[key] != after[key]]
    if not diffs:
        raise ValueError("Настройки уже совпадают")
    guards = _guard_values(actual)
    identity = secrets.token_urlsafe(24)
    digest = _hash({"id": identity, "scope": scope, "before": before, "after": after, "guards": guards})
    db.execute("insert into control_previews values (?,?,?,?,?,?,?,?,?,'pending')",
               (identity, digest, scope, actor, moment, moment + PREVIEW_TTL, _json(before), _json(after), _json(guards)))
    db.execute("delete from control_previews where expires_at<?", (moment - 86400,))
    return {"preview_id": identity, "digest": digest, "scope": scope, "diff": diffs,
            "expires_at": moment + PREVIEW_TTL, "impact": {
                "routing": "Изменится подписанная политика APK. Активный профиль обновится по обычному циклу клиента; IP и ключи подписки не меняются.",
                "nodes": "Изменятся рекомендации и проверки панели. Это не переносит текущие VPN-сессии и не гарантирует пинг.",
                "release": "Изменится доступность дальнейшей выдачи обновления или публичной загрузки. Уже установленные приложения не удаляются.",
            }[scope]}


def apply_preview(db, preview_id, digest, current, actor, role, apply_callback, now=None):
    """CAS + typed caller callback + prior snapshot, all within one savepoint.

    apply_callback(db, typed_values, scope) must use existing typed settings
    handlers, raise on failure and never commit. Routing revision publication
    remains the operator module's responsibility, not this helper's.
    """
    if not callable(apply_callback):
        raise ValueError("Для применения нужен типизированный обработчик")
    moment = _now(now)
    if not db.in_transaction:
        db.execute("begin immediate")
    db.execute("savepoint control_apply")
    try:
        rows = _rows(db, "select * from control_previews where id=?", (str(preview_id),))
        if not rows:
            raise ValueError("Предпросмотр не найден")
        row = rows[0]
        _require_role(role, row["scope"])
        if row["actor"] != actor or row["state"] != "pending" or row["expires_at"] < moment or not hmac.compare_digest(row["digest"], str(digest)):
            raise ValueError("Предпросмотр устарел или уже применён")
        before, after, guards = (json.loads(row[key]) for key in ("base_json", "candidate_json", "guards_json"))
        actual = _live(db)
        if ({key: str(actual.get(key, "")) for key in before} != before or _guard_values(actual) != guards
                or {key: str(current.get(key, "")) for key in before} != before):
            raise ValueError("Обнаружены новые изменения. Старый предпросмотр не применён")
        values = validate_values(row["scope"], {key: value for key, value in after.items() if before[key] != value})
        changed = db.execute("update control_previews set state='applying' where id=? and state='pending'", (preview_id,)).rowcount
        if changed != 1:
            raise ValueError("Предпросмотр уже используется")
        apply_callback(db, values, row["scope"])
        actual_after = _live(db)
        if any(str(actual_after.get(key, "")) != value for key, value in values.items()):
            raise ValueError("Обработчик не сохранил проверенные настройки")
        stored_after = {key: str(actual_after.get(key, "")) for key in before}
        cur = db.execute("insert into control_config_snapshots(scope,actor,created_at,before_json,after_json) values (?,?,?,?,?)",
                         (row["scope"], actor, moment, _json(before), _json(stored_after)))
        db.execute("update control_previews set state='applied' where id=?", (preview_id,))
        db.execute("release savepoint control_apply")
        return {"snapshot_id": cur.lastrowid, "scope": row["scope"], "values": values}
    except Exception:
        db.execute("rollback to savepoint control_apply")
        db.execute("release savepoint control_apply")
        raise


def rollback_preview(db, snapshot_id, current, actor, role, now=None):
    rows = _rows(db, "select * from control_config_snapshots where id=?", (int(snapshot_id),))
    if not rows:
        raise ValueError("Снимок не найден")
    row = rows[0]
    _require_role(role, row["scope"])
    before, after = json.loads(row["before_json"]), json.loads(row["after_json"])
    if any(str(current.get(key, "")) != value for key, value in after.items()):
        raise ValueError("После снимка были новые изменения. Автоматический откат запрещён")
    # Only keys actually changed by the old operation are rolled back; an empty
    # value in an unrelated pre-existing setting is not sent through validators.
    candidate = {key: ("0" if value == "" and key in {"update_rollout_paused", "release_guard_enabled"} else value)
                 for key, value in before.items() if after[key] != value}
    return preview_settings(db, current, candidate,
                            actor, row["scope"], role, now)


def config_history(db, limit=20):
    return _rows(db, "select id,scope,actor,created_at,before_json,after_json from control_config_snapshots order by id desc limit ?",
                 (max(1, min(100, int(limit))),))


def _percentile(values, percentile):
    # Current APK report schema uses zero for "not measured"; never draw a
    # perfect-looking 0 ms latency from a missing measurement.
    values = sorted(float(value) for value in values if value is not None and float(value) > 0 and math.isfinite(float(value)))
    return round(values[min(len(values) - 1, max(0, math.ceil(len(values) * percentile) - 1))], 1) if values else None


def client_quality(db, now=None):
    """Authenticated voluntary reports, never a server-probe latency substitute."""
    moment = _now(now)
    try:
        reports = _rows(db, "select device,ts,node_key,protocol,network,app_version,connect_ms,ping_ms,disconnects,success from community_quality where ts>=? and ts<=? order by ts desc,id desc limit 10000",
                        (moment - 86400, moment + 60))
    except sqlite3.OperationalError:
        return {"available": False, "devices": 0, "samples": 0, "groups": [], "reports": []}
    latest = {}
    for row in reports:
        latest.setdefault(row["device"], row)
    groups = defaultdict(list)
    for row in latest.values():
        groups[(row["node_key"], row["protocol"], row["network"], row["app_version"])].append(row)
    aggregates = []
    for (node, protocol, network, version), items in groups.items():
        # Tiny cohorts could otherwise identify an individual's connection.
        if len(items) < MIN_QUALITY_GROUP:
            continue
        aggregates.append({"node": node, "protocol": protocol, "network": network, "version": version,
                           "devices": len(items), "success_percent": round(100 * sum(bool(x["success"]) for x in items) / len(items), 1),
                           "connect_p50_ms": _percentile([x["connect_ms"] for x in items], .5),
                           "connect_p95_ms": _percentile([x["connect_ms"] for x in items], .95),
                           "ping_p50_ms": _percentile([x["ping_ms"] for x in items], .5),
                           "disconnects": sum(int(x["disconnects"] or 0) for x in items)})
    return {"available": bool(reports), "devices": len(latest), "samples": len(reports),
            "groups": sorted(aggregates, key=lambda row: (-row["devices"], row["node"])), "reports": reports}


def delivery_funnel(db, version_code, now=None):
    moment = _now(now)
    stages = {name: set() for name in ("notification_received", "download_complete", "install_handoff", "app_started")}
    try:
        reports = _rows(db, "select device,ts,version_code,stage from community_delivery where version_code=? and ts>=? and ts<=? order by ts desc,id desc limit 20000",
                        (int(version_code), moment - 30 * 86400, moment + 60))
    except sqlite3.OperationalError:
        reports = []
    for row in reports:
        if row["stage"] in stages:
            stages[row["stage"]].add(row["device"])
    return {"version_code": int(version_code), "available": bool(reports), "stages": {key: len(value) for key, value in stages.items()},
            "reports": reports, "note": "Установка подтверждается только первым запуском новой версии. Передача APK установщику — не подтверждение установки."}


def release_guard_decision(quality, funnel, app_version, now=None):
    """Proposal only; require broad, recent authenticated new-version evidence."""
    moment = _now(now)
    started = {row["device"] for row in funnel.get("reports", []) if row["stage"] == "app_started" and moment - 3600 <= row["ts"] <= moment + 60}
    latest = {}
    for row in sorted(quality.get("reports", []), key=lambda row: row["ts"], reverse=True):
        if row["device"] in started and row["app_version"] == app_version and moment - 3600 <= row["ts"] <= moment + 60:
            latest.setdefault(row["device"], row)
    bad = sum(not bool(row["success"]) or int(row["disconnects"] or 0) >= 3 for row in latest.values())
    total = len(latest)
    percent = round(100 * bad / total, 1) if total else None
    pause = total >= 20 and bad >= 5 and percent >= 30
    return {"pause_recommended": pause, "devices": total, "bad_devices": bad, "bad_percent": percent,
            "reason": "У новой версии много подтверждённых клиентских проблем" if pause else
                      "Недостаточно новых запусков с диагностикой для безопасного решения" if total < 20 else "Порог остановки раздачи не достигнут",
            "min_devices": 20, "threshold_percent": 30, "window_seconds": 3600}


def pause_rollout(db, current, actor, role, now=None):
    """An owner-approved typed flag, not a version rollback or forced logout."""
    _require_role(role, "release")
    actual = _live(db)
    if _guard_values(actual) != _guard_values(current):
        raise ValueError("Релиз уже изменился. Повторите проверку")
    decision = release_guard_decision(client_quality(db, now), delivery_funnel(db, actual.get("app_version_code", 0), now), actual.get("app_version", ""), now)
    if not decision["pause_recommended"]:
        raise ValueError(decision["reason"])
    db.execute("insert into settings(key,value) values ('update_rollout_paused','1') on conflict(key) do update set value='1'")
    return decision


def dashboard_snapshot(db, settings, now=None):
    quality = client_quality(db, now)
    funnel = delivery_funnel(db, settings.get("app_version_code", 0), now)
    decision = release_guard_decision(quality, funnel, settings.get("app_version", ""), now)
    # Reports contain pseudonymous IDs and are for guard evaluation only, not UI.
    return {"quality": {key: value for key, value in quality.items() if key != "reports"},
            "delivery": {key: value for key, value in funnel.items() if key != "reports"}, "guard": decision,
            "version": settings.get("app_version", ""), "paused": settings.get("update_rollout_paused") == "1"}


def render_dashboard(snapshot):
    esc = lambda value: html.escape(str(value), quote=True)
    quality, delivery, guard = (snapshot[key] for key in ("quality", "delivery", "guard"))
    rows = "".join("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in (
        row["node"] or "Не сообщена", row["protocol"], row["network"], row["version"], row["devices"],
        str(row["success_percent"]) + "%", row["connect_p95_ms"] if row["connect_p95_ms"] is not None else "—",
        row["ping_p50_ms"] if row["ping_p50_ms"] is not None else "—", row["disconnects"])) + "</tr>" for row in quality["groups"])
    rows = rows or "<tr><td colspan=9>Нет достаточной добровольной выборки: минимум 3 устройства в группе. Серверный TCP ping не подставляется вместо измерений APK.</td></tr>"
    labels = {"notification_received": "Уведомление получено", "download_complete": "APK скачан", "install_handoff": "Передан установщику", "app_started": "Новая версия запущена"}
    tiles = "".join(f"<div class=stat>{esc(label)}<b>{delivery['stages'][key] if delivery['available'] else '—'}</b></div>" for key, label in labels.items())
    return f"""<section class='card control-next'><div class=section-head><h2>Качество на устройствах</h2><span class=pill>24 часа · добровольно</span></div>
      <p class=muted>{quality['devices']} устройств · {quality['samples']} отчётов. Без URL, истории посещений, IP пользователя и ключей подписки.</p>
      <div style='overflow:auto;max-height:280px'><table><thead><tr><th>Нода</th><th>Протокол</th><th>Сеть</th><th>APK</th><th>Устройств</th><th>Подключения OK</th><th>P95 подключения, мс</th><th>P50 ping, мс</th><th>Обрывы</th></tr></thead><tbody>{rows}</tbody></table></div></section>
      <section class='card control-next'><div class=section-head><h2>Доставка {esc(snapshot['version'])}</h2><span class='pill {'warn' if snapshot['paused'] else 'ok'}'>{'Раздача приостановлена' if snapshot['paused'] else 'Раздача активна'}</span></div><div class=reference-kpis>{tiles}</div>
      <p class=muted>{esc(delivery['note'])} Отсутствие отчёта не означает, что установка не состоялась.</p>
      <p class={'warn' if guard['pause_recommended'] else 'muted'}>{esc(guard['reason'])} · выборка {guard['devices']} устройств, проблемных {guard['bad_devices']}.</p></section>"""


def render_preview(preview, csrf=""):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f"<tr><td>{esc(row['key'])}</td><td><pre>{esc(row['before']) or '—'}</pre></td><td><pre>{esc(row['after']) or '—'}</pre></td></tr>" for row in preview["diff"])
    return f"""<section class=card><h2>Проверка изменений</h2><p>{esc(preview['impact'])}</p><div style='max-height:360px;overflow:auto'><table><thead><tr><th>Поле</th><th>Сейчас</th><th>После</th></tr></thead><tbody>{rows}</tbody></table></div>
      <form method=post action=/operator/control/apply><input type=hidden name=preview_id value='{esc(preview['preview_id'])}'><input type=hidden name=digest value='{esc(preview['digest'])}'><input type=hidden name=csrf value='{esc(csrf)}'><button>Подтвердить изменения</button><a href=/operator?tab=quality>Отмена</a></form>
      <p class=muted>Предпросмотр действителен 10 минут. Если другой оператор изменил настройки, применение будет отклонено.</p></section>"""


def render_support(threads, selected_id=None, can_write=True, csrf=""):
    """Use community.operator_threads; diagnostic values are already allowlisted."""
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for thread in threads[:100]:
        identity = int(thread["id"])
        messages = []
        for message in thread.get("messages", [])[-100:]:
            diagnosis = message.get("diagnostic") or message.get("diagnostic_json") or {}
            if isinstance(diagnosis, str):
                try:
                    diagnosis = json.loads(diagnosis)
                except ValueError:
                    diagnosis = {}
            diag_html = f"<details><summary>Диагностика по согласию</summary><pre>{esc(_json(diagnosis))}</pre></details>" if diagnosis else ""
            sender = "Пользователь" if message.get("sender") == "user" else "Поддержка"
            messages.append(f"<article class=card><strong>{sender}</strong><p style='white-space:pre-wrap'>{esc(message.get('body',''))}</p>{diag_html}</article>")
        reply = f"""<form method=post action=/operator/community/reply><input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=thread_id value={identity}><input type=hidden name=request_id value='{secrets.token_urlsafe(18)}'><label>Ответ пользователю<textarea name=body maxlength=4000 required></textarea></label><button>Отправить ответ в APK</button></form>
          <form method=post action=/operator/community/state><input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=thread_id value={identity}><button name=state value={'open' if thread.get('state') == 'closed' else 'closed'}>{'Открыть снова' if thread.get('state') == 'closed' else 'Закрыть обращение'}</button></form>""" if can_write else ""
        cards.append(f"<details class=card {'open' if selected_id and identity == int(selected_id) else ''}><summary>#{identity} · {esc(thread.get('subject',''))} · {esc(thread.get('state','open'))}</summary>{''.join(messages) or '<p class=muted>Сообщений пока нет</p>'}{reply}</details>")
    return "<section class=control-support><h2>Поддержка в приложении</h2><p class=muted>Ответы приходят в обращение и единую ленту APK. Диагностика прикрепляется только по согласию пользователя.</p>" + ("".join(cards) or "<p class=muted>Новых обращений пока нет</p>") + "</section>"


def public_origin(public_base):
    parsed = urlsplit(public_base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("Passkey требует настроенный публичный HTTPS origin")
    hostname = _domain(parsed.hostname)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Для passkey нужен домен, не IP")
    if hostname == "localhost" or hostname.endswith(".local"):
        raise ValueError("Требуется публичный домен")
    port = parsed.port
    return "https://" + hostname + (f":{port}" if port and port != 443 else ""), hostname


def csrf_token(secret, session_binding):
    if not isinstance(secret, bytes) or len(secret) < 32 or not session_binding:
        raise ValueError("Нужен защищённый session secret и binding")
    return hmac.new(secret, ("control-next-csrf:" + session_binding).encode(), hashlib.sha256).hexdigest()


def secure_json_request(headers, public_base, expected_csrf=None):
    try:
        origin, _ = public_origin(public_base)
    except ValueError:
        return False
    if (headers.get("Origin", "") != origin or headers.get("X-QV-Request", "") != "1"
            or not headers.get("Content-Type", "").lower().startswith("application/json")
            or headers.get("Sec-Fetch-Site", "same-origin") not in {"same-origin", "none"}):
        return False
    return expected_csrf is None or hmac.compare_digest(str(expected_csrf), str(headers.get("X-QV-CSRF", "")))


def passkey_available():
    try:
        import webauthn
        from webauthn.helpers.structs import UserVerificationRequirement
        return all(callable(getattr(webauthn, name, None)) for name in (
            "generate_registration_options", "verify_registration_response", "generate_authentication_options", "verify_authentication_response"))
    except (ImportError, AttributeError):
        return False


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value, max_bytes=4096):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) > (max_bytes * 4 // 3 + 4):
        raise ValueError("Некорректный WebAuthn идентификатор")
    data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if not data or len(data) > max_bytes or _b64(data) != value:
        raise ValueError("Некорректный WebAuthn идентификатор")
    return data


def _response(credential):
    if not isinstance(credential, dict) or len(_json(credential).encode()) > 65536 or not isinstance(credential.get("response"), dict):
        raise ValueError("Некорректный WebAuthn ответ")
    # Enforce top-level same-origin ceremonies in addition to the library's
    # cryptographic challenge/origin/RP-ID checks. Never trust this parse alone.
    try:
        client = json.loads(_unb64(credential["response"].get("clientDataJSON"), 8192))
        if client.get("crossOrigin") is True or client.get("topOrigin"):
            raise ValueError("Cross-origin passkey запрещён")
    except (KeyError, TypeError, UnicodeError) as exc:
        raise ValueError("Некорректные данные браузера") from exc
    return credential


class WebAuthnManager:
    """Library-backed ceremonies. HTTP layer owns RBAC, rate-limit, IP policy.

    Registration/revocation require an existing cookie session and fresh
    password + enabled TOTP verification. Binding is its unpredictable nonce.
    Authentication uses an independent random signed HttpOnly pre-auth cookie.
    Always call secure_json_request first; never accept the binding from JSON.
    """
    def __init__(self, public_base):
        self.origin, self.rp_id = public_origin(public_base)

    def _lib(self):
        if not passkey_available():
            raise RuntimeError("Passkey недоступен: требуется Python 3.10+ и пакет webauthn из requirements-control-next.txt")
        import webauthn
        return webauthn

    @staticmethod
    def _admin(db, username):
        rows = _rows(db, "select username,role,enabled from admin_users where username=?", (str(username),))
        if not rows or not rows[0]["enabled"] or rows[0]["role"] not in {"owner", "operator", "viewer"}:
            raise PermissionError("Учётная запись недоступна")
        return rows[0]

    def _begin(self, db, purpose, username, binding, now):
        if not isinstance(binding, str) or not 32 <= len(binding) <= 1024:
            raise PermissionError("Нужна защищённая браузерная сессия")
        identity, challenge = secrets.token_urlsafe(24), secrets.token_bytes(32)
        binding_hash = hashlib.sha256(binding.encode()).hexdigest()
        # A second browser or a hostile login attempt must not invalidate an
        # already-running ceremony in another legitimate browser session.
        db.execute("delete from control_passkey_challenges where expires_at<? or (username=? and purpose=? and binding_hash=?)",
                   (now, username, purpose, binding_hash))
        if db.execute("select count(*) from control_passkey_challenges where username=? and purpose=? and consumed_at=0 and expires_at>=?",
                      (username, purpose, now)).fetchone()[0] >= 8:
            raise PermissionError("Слишком много незавершённых passkey запросов. Подождите две минуты")
        db.execute("insert into control_passkey_challenges values (?,?,?,?,?,?,?,0)",
                   (identity, purpose, username, binding_hash, challenge, now, now + PASSKEY_TTL))
        return identity, challenge

    def _take(self, db, identity, purpose, binding, now):
        rows = _rows(db, "select * from control_passkey_challenges where id=?", (str(identity),))
        if not rows or not isinstance(binding, str):
            raise PermissionError("Passkey запрос истёк")
        row = rows[0]
        if (row["purpose"] != purpose or row["expires_at"] < now or row["consumed_at"]
                or not hmac.compare_digest(row["binding_hash"], hashlib.sha256(binding.encode()).hexdigest())):
            raise PermissionError("Passkey запрос истёк или уже использован")
        changed = db.execute("update control_passkey_challenges set consumed_at=? where id=? and consumed_at=0", (now, identity)).rowcount
        if changed != 1:
            raise PermissionError("Passkey запрос уже использован")
        return row

    def begin_registration(self, db, username, binding, reauthenticated=False, now=None):
        lib, moment = self._lib(), _now(now)
        self._admin(db, username)
        if not reauthenticated:
            raise PermissionError("Повторно подтвердите пароль и 2FA перед добавлением passkey")
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement, PublicKeyCredentialDescriptor, AttestationConveyancePreference
        credentials = _rows(db, "select credential_id from control_passkeys where username=? and revoked_at=0", (username,))
        if len(credentials) >= MAX_PASSKEYS:
            raise ValueError("Не более 10 активных passkey для аккаунта")
        handles = _rows(db, "select user_handle from control_passkey_users where username=?", (username,))
        handle = bytes(handles[0]["user_handle"]) if handles else secrets.token_bytes(32)
        if not handles:
            db.execute("insert into control_passkey_users values (?,?)", (username, handle))
        identity, challenge = self._begin(db, "register", username, binding, moment)
        options = lib.generate_registration_options(rp_id=self.rp_id, rp_name="Quantum Control", user_id=handle,
            user_name=username, user_display_name=username, challenge=challenge, timeout=PASSKEY_TTL * 1000,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=_unb64(row["credential_id"])) for row in credentials])
        return {"ceremony_id": identity, "options": json.loads(lib.options_to_json(options))}

    def finish_registration(self, db, username, binding, ceremony_id, credential, label="Мой passkey", now=None):
        lib, moment = self._lib(), _now(now)
        self._admin(db, username)
        row = self._take(db, ceremony_id, "register", binding, moment)
        if row["username"] != username:
            raise PermissionError("Passkey не принадлежит этой сессии")
        if db.execute("select count(*) from control_passkeys where username=? and revoked_at=0", (username,)).fetchone()[0] >= MAX_PASSKEYS:
            raise ValueError("Достигнут лимит passkey")
        try:
            verified = lib.verify_registration_response(credential=_response(credential), expected_challenge=bytes(row["challenge"]),
                expected_rp_id=self.rp_id, expected_origin=self.origin, require_user_verification=True)
        except Exception as exc:
            raise ValueError("Passkey не прошёл проверку браузера, подписи или присутствия пользователя") from exc
        handle = db.execute("select user_handle from control_passkey_users where username=?", (username,)).fetchone()[0]
        label = " ".join(str(label).split())[:64] or "Мой passkey"
        try:
            db.execute("insert into control_passkeys(credential_id,username,user_handle,public_key,sign_count,label,created_at) values (?,?,?,?,?,?,?)",
                       (_b64(verified.credential_id), username, handle, verified.credential_public_key, verified.sign_count, label, moment))
        except sqlite3.IntegrityError as exc:
            raise ValueError("Passkey уже зарегистрирован") from exc
        return {"registered": True, "label": label}

    def begin_authentication(self, db, username, binding, now=None):
        lib, moment = self._lib(), _now(now)
        self._admin(db, username)
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
        credentials = _rows(db, "select credential_id from control_passkeys where username=? and revoked_at=0", (username,))
        if not credentials:
            raise PermissionError("Passkey вход недоступен; используйте пароль и 2FA")
        identity, challenge = self._begin(db, "authenticate", username, binding, moment)
        options = lib.generate_authentication_options(rp_id=self.rp_id, challenge=challenge, timeout=PASSKEY_TTL * 1000,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=_unb64(row["credential_id"])) for row in credentials])
        return {"ceremony_id": identity, "options": json.loads(lib.options_to_json(options))}

    def finish_authentication(self, db, binding, ceremony_id, credential, now=None):
        lib, moment = self._lib(), _now(now)
        challenge = self._take(db, ceremony_id, "authenticate", binding, moment)
        admin = self._admin(db, challenge["username"])
        response = _response(credential)
        identity = _b64(_unb64(response.get("id")))
        rows = _rows(db, "select * from control_passkeys where credential_id=? and username=? and revoked_at=0", (identity, admin["username"]))
        if not rows:
            raise PermissionError("Passkey не принадлежит этой учётной записи")
        row = rows[0]
        handle = response["response"].get("userHandle")
        if handle is not None and not hmac.compare_digest(_unb64(handle), bytes(row["user_handle"])):
            raise PermissionError("Passkey user handle не совпадает")
        try:
            verified = lib.verify_authentication_response(credential=response, expected_challenge=bytes(challenge["challenge"]),
                expected_rp_id=self.rp_id, expected_origin=self.origin, credential_public_key=bytes(row["public_key"]),
                credential_current_sign_count=row["sign_count"], require_user_verification=True)
        except Exception as exc:
            raise ValueError("Passkey не прошёл проверку подписи, origin или присутствия пользователя") from exc
        changed = db.execute("update control_passkeys set sign_count=?,last_used_at=? where credential_id=? and sign_count=? and revoked_at=0",
                             (verified.new_sign_count, moment, identity, row["sign_count"])).rowcount
        if changed != 1:
            raise PermissionError("Passkey изменился во время входа")
        # HTTP layer signs the ordinary session with this freshly reloaded role,
        # applies the normal IP allowlist and never trusts a JSON-supplied role.
        return {"username": admin["username"], "role": admin["role"]}


def passkey_list(db, username):
    return _rows(db, "select credential_id,label,created_at,last_used_at from control_passkeys where username=? and revoked_at=0 order by created_at desc limit 10", (username,))


def render_passkeys(credentials, username, csrf):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f"<li>{esc(row['label'])}<form class=passkey-revoke data-credential='{esc(row['credential_id'])}' data-csrf='{esc(csrf)}'><label>Пароль для удаления<input type=password name=password autocomplete=current-password required></label><label>Код 2FA<input name=totp autocomplete=one-time-code inputmode=numeric></label><button type=submit class=secondary>Удалить свой passkey</button></form></li>" for row in credentials)
    return f"""<section class=card><h2>Мои passkey</h2><p class=muted>Подтверждение средствами устройства или аппаратным ключом. Пароль и включённая 2FA остаются резервным способом входа. Добавить ключ можно только после повторного подтверждения.</p>
      <ul>{rows or '<li>Passkey ещё не добавлены</li>'}</ul><form><input type=hidden name=username value='{esc(username)}'><label>Название ключа<input name=label maxlength=64 placeholder='Мой телефон или ключ'></label><label>Текущий пароль<input type=password name=password autocomplete=current-password></label><label>Код 2FA (если включён)<input name=totp autocomplete=one-time-code inputmode=numeric></label><button type=button data-passkey=register data-csrf='{esc(csrf)}' {'disabled' if not passkey_available() or not username else ''}>Добавить passkey</button></form><p class='muted passkey-status'>{'Готово к добавлению ключа' if passkey_available() else 'Официальная библиотека WebAuthn недоступна. Вход паролем не затронут.'}</p></section>"""


def render_guard_form(settings, csrf):
    esc = lambda value: html.escape(str(value), quote=True)
    return f"""<form class=card method=post action=/operator/control/preview><input type=hidden name=scope value=release><input type=hidden name=csrf value='{esc(csrf)}'><h2>Контроль раздачи обновлений</h2>
      <label>Охват, %<input name=rollout_percent type=number min=1 max=100 value='{esc(settings.get('rollout_percent','100'))}'></label>
      <label><input type=checkbox name=update_rollout_paused {'checked' if settings.get('update_rollout_paused') == '1' else ''}> Приостановить дальнейшую выдачу APK</label>
      <label><input type=checkbox name=release_guard_enabled {'checked' if settings.get('release_guard_enabled') == '1' else ''}> Автоматически приостанавливать по клиентским проблемам</label>
      <label><input type=checkbox name=public_download_enabled {'checked' if settings.get('public_download_enabled') == '1' else ''}> Публичная кнопка скачивания</label>
      <p class=muted>Автостоп: минимум 20 разных устройств с первым запуском новой версии и отчётом качества за час; минимум 5 проблемных и доля от 30%. Уже установленные приложения и время публикации не меняются.</p><button>Посмотреть изменения</button></form>"""


def render_history(snapshots, csrf):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f"<tr><td>#{int(row['id'])}</td><td>{esc(row['scope'])}</td><td>{esc(row['actor'])}</td><td><form method=post action=/operator/control/rollback><input type=hidden name=snapshot_id value={int(row['id'])}><input type=hidden name=csrf value='{esc(csrf)}'><button class=secondary>Посмотреть откат</button></form></td></tr>" for row in snapshots)
    return f"<details class=card><summary>Предыдущие конфигурации</summary><p class=muted>Откат всегда сначала показывается. Если настройки менялись позже, автоматический возврат запрещён.</p><table><thead><tr><th>Снимок</th><th>Раздел</th><th>Автор</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan=4>Пока нет подтверждённых изменений</td></tr>'}</tbody></table></details>"


def revoke_passkey(db, username, credential_id, reauthenticated=False, now=None):
    if not reauthenticated:
        raise PermissionError("Повторно подтвердите пароль и 2FA")
    _unb64(credential_id)
    if db.execute("update control_passkeys set revoked_at=? where username=? and credential_id=? and revoked_at=0",
                  (_now(now), username, credential_id)).rowcount != 1:
        raise ValueError("Passkey не найден")
    return {"revoked": True}


def passkey_script():
    """Inline browser adapter; root buttons provide data-passkey and data-csrf.

    Registration passes password/TOTP from the visible confirmation form to
    the root begin endpoint only. They are never retained after the request.
    """
    return r'''<script>(function(){
      const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
      const encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
      const options=(o,kind)=>{o.challenge=decode(o.challenge);if(o.user)o.user.id=decode(o.user.id);for(const k of ['excludeCredentials','allowCredentials'])if(o[k])o[k]=o[k].map(c=>({...c,id:decode(c.id)}));return o;};
      const serialize=c=>{const r=c.response,o={id:c.id,rawId:encode(c.rawId),type:c.type,response:{clientDataJSON:encode(r.clientDataJSON)},clientExtensionResults:c.getClientExtensionResults()};for(const k of ['attestationObject','authenticatorData','signature','userHandle'])if(r[k])o.response[k]=encode(r[k]);if(r.getTransports)o.response.transports=r.getTransports();return o;};
      document.querySelectorAll('[data-passkey]').forEach(button=>button.addEventListener('click',async()=>{
        const status=button.closest('section')?.querySelector('.passkey-status')||document.getElementById('passkey-status');const say=t=>{if(status)status.textContent=t;};
        if(!window.isSecureContext||!navigator.credentials||!window.PublicKeyCredential){say('Браузер не поддерживает passkey. Используйте пароль и 2FA.');return;}
        button.disabled=true;
        const kind=button.dataset.passkey,form=button.closest('form'),username=form?.querySelector('[name=username]')?.value||button.dataset.username||'';
        const request=async(path,body)=>{const response=await fetch('/operator/passkey/'+path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-QV-Request':'1','X-QV-CSRF':button.dataset.csrf||''},body:JSON.stringify(body)});const value=await response.json();if(!response.ok)throw Error(value.message||'Passkey запрос отклонён');return value;};
        try{let payload={username};if(kind==='register'){payload.password=form?.querySelector('[name=password]')?.value||'';payload.totp=form?.querySelector('[name=totp]')?.value||'';}
          const begin=await request(kind+'/begin',payload);delete payload.password;delete payload.totp;
          const credential=await navigator.credentials[kind==='register'?'create':'get']({publicKey:options(begin.options,kind)});
          const result=await request(kind+'/finish',{ceremony_id:begin.ceremony_id,credential:serialize(credential),label:form?.querySelector('[name=label]')?.value||'Мой passkey'});
          say(kind==='register'?'Passkey добавлен. Пароль и 2FA остаются доступны.':'Вход подтверждён');if(kind==='authenticate')location.assign('/operator');else location.reload();
        }catch(error){say(error.name==='NotAllowedError'?'Подтверждение отменено или время истекло.':error.message||'Не удалось подтвердить passkey.');}finally{button.disabled=false;}
      }));
      document.querySelectorAll('.passkey-revoke').forEach(form=>form.addEventListener('submit',async event=>{
        event.preventDefault();const button=form.querySelector('button'),status=form.closest('section')?.querySelector('.passkey-status')||document.getElementById('passkey-status');button.disabled=true;
        try{const response=await fetch('/operator/passkey/revoke',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-QV-Request':'1','X-QV-CSRF':form.dataset.csrf},body:JSON.stringify({credential_id:form.dataset.credential,password:form.querySelector('[name=password]').value,totp:form.querySelector('[name=totp]').value})});const result=await response.json();if(!response.ok)throw Error(result.message||'Удаление не подтверждено');location.reload();}catch(error){if(status)status.textContent=error.message;}finally{button.disabled=false;}
      }));
    })();</script>'''
