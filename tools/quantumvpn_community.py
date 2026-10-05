"""Private client support, durable inbox, and opt-in quality/delivery reports.

HTTP handlers own admission and authorization: credentials may ONLY be issued
after the existing managed-subscription upstream has admitted the raw HWID.
Never call issue_device_credential from an arbitrary public bootstrap handler.
All client read/write functions require the identity returned by authenticate_client.
This module never fetches URLs, stores subscription material, or executes model output.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time

TOKEN_HEADER = "X-Quantum-Client-Token"
MAX_REQUEST_BYTES = 20_480
MAX_DIAGNOSTIC_BYTES = 8_192
MAX_FEED_PAGE = 50
_IDENTITY = re.compile(r"^[0-9a-f]{16}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,96}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{40,96}$")
_REDACTIONS = (
    re.compile(r"(?i)\b(?:https?://|vless://|vmess://|trojan://|ss://|hysteria2?://|tuic://|wireguard://)\S+"),
    re.compile(r"(?i)\b(?:authorization|token|password|secret|private_?key|subscription|access_code)[\"']?\s*[=:]\s*[\"']?[^\s,;]+"),
    re.compile(r"(?i)\b(?:пароль|токен|секрет|приватный\s+ключ)\s*[:=]?\s+[^\s,;]+"),
    re.compile(r"(?i)\bbearer\s+\S+"),
    re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    re.compile(r"\b\d{7,12}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{43,}={0,2}(?![A-Za-z0-9+/=_-])"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"),
)


class CommunityError(ValueError):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


def migrate(db: sqlite3.Connection) -> None:
    """Idempotent startup migration; caller commits with its other migrations."""
    statements = (
        "create table if not exists community_credentials (token_hash text primary key, device text not null, created_at integer not null, expires_at integer not null)",
        "create index if not exists idx_community_credentials_device on community_credentials(device, expires_at)",
        "create table if not exists community_threads (id integer primary key autoincrement, device text not null, subject text not null, state text not null default 'open', created_at integer not null, updated_at integer not null, request_id text not null, unique(device,request_id))",
        "create index if not exists idx_community_threads_device on community_threads(device, updated_at)",
        "create table if not exists community_messages (id integer primary key autoincrement, thread_id integer not null, sender text not null, body text not null, diagnostic_json text not null default '{}', request_id text not null, created_at integer not null, unique(thread_id,sender,request_id))",
        "create table if not exists community_events (id integer primary key autoincrement, device text not null default '', kind text not null, title text not null, body text not null, created_at integer not null, dedupe_key text not null unique)",
        "create index if not exists idx_community_events_device on community_events(device,id)",
        "create table if not exists community_reads (device text primary key, event_id integer not null default 0)",
        "create table if not exists community_quality (id integer primary key autoincrement, device text not null, event_id text not null, ts integer not null, node_key text not null, protocol text not null, network text not null, app_version text not null, connect_ms integer not null, ping_ms integer not null, disconnects integer not null, success integer not null, unique(device,event_id))",
        "create index if not exists idx_community_quality_ts on community_quality(ts)",
        "create table if not exists community_delivery (id integer primary key autoincrement, device text not null, event_id text not null, ts integer not null, version_code integer not null, stage text not null, unique(device,event_id))",
        "create index if not exists idx_community_delivery_ts on community_delivery(ts)",
    )
    for statement in statements:
        db.execute(statement)


def _rows(cursor) -> list[dict]:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, tuple(row))) for row in cursor.fetchall()]


def _identity(device: str) -> str:
    if not isinstance(device, str) or not _IDENTITY.fullmatch(device):
        raise CommunityError("client_authentication_required", 401)
    return device


def _request_id(value) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise CommunityError("invalid_request_id")
    return value


def _bounded_int(value, minimum: int, maximum: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CommunityError("invalid_" + field)
    return value


def redact_text(value, limit: int = 4_000) -> str:
    if not isinstance(value, str):
        raise CommunityError("invalid_text")
    if len(value) > limit * 2:
        raise CommunityError("text_too_long")
    text = "".join(ch for ch in value if ord(ch) >= 32 or ch in "\n\t").strip()
    for pattern in _REDACTIONS:
        text = pattern.sub("[скрыто]", text)
    return text[:limit]


def issue_device_credential(db, admitted_raw_hwid: str, now: int | None = None) -> str:
    """Trusted admission hook; raw HWID never enters support/metrics tables."""
    if not isinstance(admitted_raw_hwid, str) or not admitted_raw_hwid.strip() or len(admitted_raw_hwid) > 512:
        raise CommunityError("invalid_admitted_device", 403)
    now = int(time.time()) if now is None else now
    device = hashlib.sha256(admitted_raw_hwid.encode()).hexdigest()[:16]
    token = secrets.token_urlsafe(32)
    db.execute("delete from community_credentials where expires_at<=?", (now,))
    db.execute("insert into community_credentials values (?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), device, now, now + 90 * 86_400))
    # Several concurrent accepted subscription refreshes must not revoke the
    # credential retained by another process instantly. Keep the newest four.
    db.execute("delete from community_credentials where device=? and token_hash not in (select token_hash from community_credentials where device=? order by created_at desc,rowid desc limit 4)", (device, device))
    return token


def authenticate_client(db, raw_hwid: str, token: str, now: int | None = None) -> str:
    if not isinstance(raw_hwid, str) or not raw_hwid or len(raw_hwid) > 512 or not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise CommunityError("client_authentication_required", 401)
    now = int(time.time()) if now is None else now
    device = hashlib.sha256(raw_hwid.encode()).hexdigest()[:16]
    row = db.execute("select device,expires_at from community_credentials where token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not row or row[1] <= now or not secrets.compare_digest(str(row[0]), device):
        raise CommunityError("client_authentication_required", 401)
    return device


def _diagnostic(payload: dict) -> str:
    source = payload.get("diagnostic")
    if source is None:
        return "{}"
    if payload.get("diagnostic_consent") is not True:
        raise CommunityError("diagnostic_consent_required")
    if not isinstance(source, dict):
        raise CommunityError("invalid_diagnostic")
    # Explicit compact allowlist: never persist raw profile/config, routing,
    # subscriptions, browsing history, hardware ID, interface addresses.
    accepted = {}
    for field, limit in (("app_version", 32), ("android_version", 32), ("last_error", 600), ("summary", 2_000), ("logs", 4_000)):
        if field in source:
            accepted[field] = redact_text(source[field], limit)
    raw = json.dumps(accepted, ensure_ascii=False)
    if len(raw.encode()) > MAX_DIAGNOSTIC_BYTES:
        raise CommunityError("diagnostic_too_large")
    return raw


def _thread(db, device: str, thread_id: int) -> dict:
    _identity(device)
    _bounded_int(thread_id, 1, 2**63 - 1, "thread_id")
    rows = _rows(db.execute("select * from community_threads where id=? and device=?", (thread_id, device)))
    if not rows:
        raise CommunityError("thread_not_found", 404)
    thread = rows[0]
    thread.pop("device", None)
    thread.pop("request_id", None)
    thread["messages"] = _rows(db.execute("select id,sender,body,created_at,diagnostic_json!='{}' as has_diagnostic from community_messages where thread_id=? order by id desc limit 30", (thread_id,)))
    thread["messages"].reverse()
    return thread


def list_threads(db, device: str) -> dict:
    _identity(device)
    return {"threads": _rows(db.execute("select id,subject,state,created_at,updated_at from community_threads where device=? order by updated_at desc,id desc limit 50", (device,)))}


def get_thread(db, device: str, thread_id: int) -> dict:
    return {"thread": _thread(db, device, thread_id)}


def create_thread(db, device: str, payload: dict, now: int | None = None) -> dict:
    _identity(device)
    request_id = _request_id(payload.get("request_id"))
    prior = db.execute("select id from community_threads where device=? and request_id=?", (device, request_id)).fetchone()
    if prior:
        return get_thread(db, device, prior[0])
    subject, body = redact_text(payload.get("subject", ""), 120), redact_text(payload.get("body", ""))
    if not subject or not body:
        raise CommunityError("subject_and_message_required")
    diagnostic = _diagnostic(payload)
    now = int(time.time()) if now is None else now
    open_count = db.execute("select count(*) from community_threads where device=? and state='open'", (device,)).fetchone()[0]
    daily = db.execute("select count(*) from community_threads where device=? and created_at>?", (device, now - 86_400)).fetchone()[0]
    if open_count >= 5 or daily >= 10:
        raise CommunityError("support_limit_reached", 429)
    cursor = db.execute("insert into community_threads(device,subject,created_at,updated_at,request_id) values (?,?,?,?,?)", (device, subject, now, now, request_id))
    db.execute("insert into community_messages(thread_id,sender,body,diagnostic_json,request_id,created_at) values (?,'user',?,?,?,?)", (cursor.lastrowid, body, diagnostic, request_id, now))
    return get_thread(db, device, cursor.lastrowid)


def add_message(db, device: str, thread_id: int, payload: dict, now: int | None = None) -> dict:
    thread = _thread(db, device, thread_id)
    if thread["state"] != "open":
        raise CommunityError("thread_closed", 409)
    request_id = _request_id(payload.get("request_id"))
    if db.execute("select 1 from community_messages where thread_id=? and sender='user' and request_id=?", (thread_id, request_id)).fetchone():
        return get_thread(db, device, thread_id)
    body = redact_text(payload.get("body", ""))
    if not body:
        raise CommunityError("message_required")
    diagnostic = _diagnostic(payload)
    now = int(time.time()) if now is None else now
    daily = db.execute("select count(*) from community_messages m join community_threads t on t.id=m.thread_id where t.device=? and m.sender='user' and m.created_at>?", (device, now - 86_400)).fetchone()[0]
    total = db.execute("select count(*) from community_messages where thread_id=?", (thread_id,)).fetchone()[0]
    if daily >= 50 or total >= 500:
        raise CommunityError("support_limit_reached", 429)
    db.execute("insert into community_messages(thread_id,sender,body,diagnostic_json,request_id,created_at) values (?,'user',?,?,?,?)", (thread_id, body, diagnostic, request_id, now))
    db.execute("update community_threads set updated_at=? where id=?", (now, thread_id))
    return get_thread(db, device, thread_id)


def append_event(db, kind: str, title: str, body: str, dedupe_key: str, device: str = "", now: int | None = None) -> int:
    if kind not in {"release", "maintenance", "recovery", "support_reply", "announcement"}:
        raise CommunityError("invalid_event_kind")
    if device:
        _identity(device)
    if not isinstance(dedupe_key, str) or not 1 <= len(dedupe_key) <= 160:
        raise CommunityError("invalid_event_key")
    now = int(time.time()) if now is None else now
    db.execute("insert or ignore into community_events(device,kind,title,body,created_at,dedupe_key) values (?,?,?,?,?,?)", (device, kind, redact_text(title, 160), redact_text(body, 1_200), now, dedupe_key))
    return int(db.execute("select id from community_events where dedupe_key=?", (dedupe_key,)).fetchone()[0])


def inbox(db, device: str, after: int = 0, limit: int = 30) -> dict:
    _identity(device)
    _bounded_int(after, 0, 2**63 - 1, "cursor")
    _bounded_int(limit, 1, MAX_FEED_PAGE, "limit")
    entries = _rows(db.execute("select id,kind,title,body,created_at,dedupe_key as key from community_events where (device='' or device=?) and id>? order by id limit ?", (device, after, limit + 1)))
    more = len(entries) > limit
    entries = entries[:limit]
    row = db.execute("select event_id from community_reads where device=?", (device,)).fetchone()
    read_through = int(row[0]) if row else 0
    unread = db.execute("select count(*) from community_events where (device='' or device=?) and id>?", (device, read_through)).fetchone()[0]
    return {"events": entries, "cursor": entries[-1]["id"] if entries else after, "has_more": more, "read_through": read_through, "unread": unread}


def mark_read(db, device: str, event_id: int) -> dict:
    _identity(device)
    _bounded_int(event_id, 0, 2**63 - 1, "event_id")
    visible = db.execute("select coalesce(max(id),0) from community_events where (device='' or device=?) and id<=?", (device, event_id)).fetchone()[0]
    db.execute("insert into community_reads values (?,?) on conflict(device) do update set event_id=max(community_reads.event_id,excluded.event_id)", (device, visible))
    return {"ok": True, "read_through": visible}


def operator_threads(db) -> dict:
    threads = _rows(db.execute("select id,device,subject,state,created_at,updated_at from community_threads order by state='open' desc,updated_at desc limit 100"))
    for thread in threads:
        thread["messages"] = _rows(db.execute("select id,sender,body,created_at,diagnostic_json from community_messages where thread_id=? order by id desc limit 30", (thread["id"],)))
        thread["messages"].reverse()
    return {"threads": threads}


def operator_reply(db, thread_id: int, body: str, request_id: str, now: int | None = None) -> dict:
    _bounded_int(thread_id, 1, 2**63 - 1, "thread_id")
    request_id = _request_id(request_id)
    body = redact_text(body)
    if not body:
        raise CommunityError("message_required")
    row = db.execute("select device from community_threads where id=?", (thread_id,)).fetchone()
    if not row:
        raise CommunityError("thread_not_found", 404)
    now = int(time.time()) if now is None else now
    db.execute("insert or ignore into community_messages(thread_id,sender,body,request_id,created_at) values (?,'operator',?,?,?)", (thread_id, body, request_id, now))
    db.execute("update community_threads set updated_at=? where id=?", (now, thread_id))
    append_event(db, "support_reply", "Ответ поддержки", body[:1_200], f"support:{thread_id}:{request_id}", device=row[0], now=now)
    return {"ok": True, "thread_id": thread_id}


def set_thread_state(db, thread_id: int, state: str) -> dict:
    _bounded_int(thread_id, 1, 2**63 - 1, "thread_id")
    if state not in {"open", "closed"}:
        raise CommunityError("invalid_thread_state")
    cursor = db.execute("update community_threads set state=?,updated_at=? where id=?", (state, int(time.time()), thread_id))
    if cursor.rowcount != 1:
        raise CommunityError("thread_not_found", 404)
    return {"ok": True}


def record_quality(db, device: str, payload: dict, now: int | None = None) -> dict:
    _identity(device)
    if payload.get("consent") is not True:
        raise CommunityError("quality_consent_required")
    event_id = _request_id(payload.get("event_id"))
    node = str(payload.get("node_key", ""))
    # A managed opaque node ID, NOT an IP, host, URL, or profile string.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", node):
        raise CommunityError("invalid_node_key")
    protocol = payload.get("protocol", "unknown")
    network = payload.get("network", "unknown")
    if protocol not in {"vless", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "amneziawg", "shadowsocks", "unknown"} or network not in {"wifi", "mobile", "ethernet", "unknown"}:
        raise CommunityError("invalid_quality_category")
    version = str(payload.get("app_version", ""))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", version):
        raise CommunityError("invalid_app_version")
    connect_ms = _bounded_int(payload.get("connect_ms", 0), 0, 300_000, "connect_ms")
    ping_ms = _bounded_int(payload.get("ping_ms", 0), 0, 60_000, "ping_ms")
    disconnects = _bounded_int(payload.get("disconnects", 0), 0, 1_000, "disconnects")
    if not isinstance(payload.get("success"), bool):
        raise CommunityError("invalid_success")
    now = int(time.time()) if now is None else now
    duplicate = db.execute("select 1 from community_quality where device=? and event_id=?", (device, event_id)).fetchone()
    if not duplicate and db.execute("select count(*) from community_quality where device=? and ts>?", (device, now - 3_600)).fetchone()[0] >= 24:
        raise CommunityError("quality_limit_reached", 429)
    db.execute("insert or ignore into community_quality(device,event_id,ts,node_key,protocol,network,app_version,connect_ms,ping_ms,disconnects,success) values (?,?,?,?,?,?,?,?,?,?,?)", (device, event_id, now, node, protocol, network, version, connect_ms, ping_ms, disconnects, int(payload["success"])))
    return {"ok": True, "duplicate": bool(duplicate)}


def record_delivery(db, device: str, payload: dict, now: int | None = None) -> dict:
    _identity(device)
    event_id = _request_id(payload.get("event_id"))
    stage = payload.get("stage")
    # All stages are client-reported evidence, not cryptographic attestation.
    # Installation handoff MUST NOT be reported as a successful installation.
    aliases = {"seen": "notification_received", "downloaded": "download_complete", "handoff": "install_handoff", "first_launch": "app_started"}
    stage = aliases.get(stage, stage)
    if stage not in {"notification_received", "download_complete", "install_handoff", "app_started"}:
        raise CommunityError("invalid_delivery_stage")
    version = _bounded_int(payload.get("version_code"), 1, 2_147_483_647, "version_code")
    now = int(time.time()) if now is None else now
    duplicate = db.execute("select 1 from community_delivery where device=? and event_id=?", (device, event_id)).fetchone()
    if not duplicate and db.execute("select count(*) from community_delivery where device=? and ts>?", (device, now - 3_600)).fetchone()[0] >= 40:
        raise CommunityError("delivery_limit_reached", 429)
    db.execute("insert or ignore into community_delivery(device,event_id,ts,version_code,stage) values (?,?,?,?,?)", (device, event_id, now, version, stage))
    return {"ok": True, "duplicate": bool(duplicate)}


def quality_snapshot(db, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    reports = _rows(db.execute("select device,ts,node_key,protocol,network,app_version,connect_ms,ping_ms,disconnects,success from community_quality where ts>? order by ts desc,id desc limit 2000", (now - 86_400,)))
    return {"reports": reports, "consent_required": True, "contains_browsing_history": False}


def delivery_snapshot(db, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    reports = _rows(db.execute("select device,ts,version_code,stage from community_delivery where ts>? order by ts desc,id desc limit 5000", (now - 7 * 86_400,)))
    stages = {stage: len({(row["device"], row["version_code"]) for row in reports if row["stage"] == stage}) for stage in ("notification_received", "download_complete", "install_handoff", "app_started")}
    return {"reports": reports, "stages": stages, "evidence": "authenticated_client_report", "handoff_is_installation": False}


def cleanup(db, now: int | None = None) -> None:
    """Call from existing maintenance worker, never per policy poll."""
    now = int(time.time()) if now is None else now
    db.execute("delete from community_credentials where expires_at<=?", (now,))
    db.execute("delete from community_quality where ts<?", (now - 30 * 86_400,))
    db.execute("delete from community_delivery where ts<?", (now - 90 * 86_400,))
    db.execute("delete from community_events where created_at<?", (now - 90 * 86_400,))
    # Preserve open conversations; closed conversations have a bounded lifetime.
    db.execute("delete from community_messages where thread_id in (select id from community_threads where state='closed' and updated_at<?)", (now - 180 * 86_400,))
    db.execute("delete from community_threads where state='closed' and updated_at<?", (now - 180 * 86_400,))
