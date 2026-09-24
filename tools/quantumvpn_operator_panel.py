#!/usr/bin/env python3
"""QuantumVPN operator control panel (stdlib only) — extended Quantum Control."""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import socket
import struct
import subprocess
import threading
import time
import zipfile
from collections import defaultdict, deque
from email.parser import BytesParser
from email.policy import default as email_default
from functools import lru_cache
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from urllib.request import Request, urlopen


class OperatorHTTPServer(ThreadingHTTPServer):
    # Default backlog is 5 — APK downloads get RST mid-transfer and clients restart forever.
    request_queue_size = 512
    allow_reuse_address = True

ROOT = os.environ.get("QV_DATA_DIR", "/var/lib/quantumvpn-operator")
DB = os.path.join(ROOT, "operator.db")
USER = os.environ["QV_ADMIN_USER"]
PASSWORD = os.environ["QV_ADMIN_PASSWORD"]
UPSTREAM = os.environ["QV_SUBSCRIPTION_UPSTREAM"]
ROSPANEL_DB = os.environ.get("QV_ROSPANEL_DB", "/var/lib/rospanel/rospanel.db")
ROSPANEL_API = os.environ.get("QV_ROSPANEL_API", "").rstrip("/")
DOWNLOAD_ROOT = os.environ.get("QV_DOWNLOAD_ROOT", "/var/www/quantumvpn/downloads")
PUBLIC_BASE = os.environ.get("QV_PUBLIC_BASE", "https://tepacom.o190.com:8443")
# Prefer :8443 until :443 fallback nginx is confirmed live.
DOWNLOAD_BASE = os.environ.get("QV_DOWNLOAD_BASE", "https://tepacom.o190.com:8443").rstrip("/")
PANEL_BUILD = "5.9.5"
VERSION = "5.9.5"
VERSION_CODE = 120
DEFAULT_NOTE = "QuantumVPN 5.9.5: центр флота, история сессий и удалённые флаги."
SESSION_TTL = 12 * 3600
SESSION_COOKIE = "qv_session"
_DB_INIT_LOCK = threading.Lock()
_DB_READY = False
_LAST_EVENT_CLEANUP = 0
_RATE = defaultdict(deque)
_RATE_LOCK = threading.Lock()
_ALERT_STATE = {"last": {}, "lock": threading.Lock()}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


PASSWORD_ITERATIONS = 180_000


def password_hash(raw: str) -> str:
    """Return a salted PBKDF2 password record suitable for the local panel DB."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", (raw or "").encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${b64url(salt)}${b64url(digest)}"


def password_ok(raw: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, expected = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", (raw or "").encode("utf-8"), base64.urlsafe_b64decode(salt + "=="), int(rounds)
        )
        return hmac.compare_digest(b64url(digest), expected)
    except Exception:
        return False


def normal_role(role: str) -> str:
    return role if role in ("owner", "operator", "viewer") else "viewer"


def session_secret() -> bytes:
    path = os.path.join(ROOT, "session.secret")
    os.makedirs(ROOT, exist_ok=True)
    if not os.path.isfile(path):
        open(path, "wb").write(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    return open(path, "rb").read()


def sign_session(payload: dict) -> str:
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(session_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_session(token: str):
    try:
        body, sig = token.split(".", 1)
        expect = b64url(hmac.new(session_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expect):
            return None
        pad = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except Exception:
        return None


def totp_secret_b32() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret_b32: str, for_time: float | None = None) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_ok(secret_b32: str, code: str) -> bool:
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return False
    now = time.time()
    return any(hmac.compare_digest(totp_at(secret_b32, now + drift), code) for drift in (-30, 0, 30))


@lru_cache(maxsize=16)
def release_info(version: str, version_code: int, note: str, abi: str, size: int, mtime: int):
    name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
    path = os.path.join(DOWNLOAD_ROOT, version, name)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "version": version,
        "version_code": version_code,
        "url": f"{DOWNLOAD_BASE}/downloads/{version}/{name}",
        "sha256": digest.hexdigest(),
        "size": size,
        "note": note or DEFAULT_NOTE,
        "application_id": "com.quantumvpn.debug",
    }


def conn():
    global _DB_READY, _LAST_EVENT_CLEANUP
    os.makedirs(ROOT, exist_ok=True)
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    now = int(time.time())
    with _DB_INIT_LOCK:
        if not _DB_READY:
            db.executescript(
                """
                create table if not exists settings (key text primary key, value text not null);
                create table if not exists events (ts integer, kind text, device text, ip text, detail text);
                create table if not exists protocols (name text primary key, enabled integer not null default 1);
                create table if not exists device_flags (
                    device text primary key,
                    force_banner text not null default '',
                    request_diagnostic integer not null default 0,
                    note text not null default '',
                    updated_at integer not null default 0
                );
                create table if not exists audit (
                    ts integer, actor text, ip text, action text, detail text
                );
                create table if not exists donations (
                    id integer primary key autoincrement,
                    ts integer not null,
                    device text not null,
                    ip text not null default '',
                    amount_rub integer not null,
                    note text not null default '',
                    app_version text not null default ''
                );
                create table if not exists server_health (
                    ts integer not null,
                    target text not null,
                    ok integer not null,
                    latency_ms integer not null default 0,
                    detail text not null default ''
                );
                create table if not exists admin_users (
                    username text primary key,
                    password_hash text not null,
                    role text not null default 'operator',
                    enabled integer not null default 1,
                    created_at integer not null default 0,
                    updated_at integer not null default 0
                );
                create table if not exists incidents (
                    id integer primary key autoincrement,
                    opened_at integer not null,
                    closed_at integer not null default 0,
                    severity text not null default 'warning',
                    source text not null,
                    title text not null,
                    detail text not null default '',
                    dedupe_key text not null
                );
                create index if not exists idx_events_device on events(device);
                create index if not exists idx_events_kind_ts on events(kind, ts);
                create index if not exists idx_events_ts on events(ts);
                create index if not exists idx_audit_ts on audit(ts);
                create index if not exists idx_donations_ts on donations(ts);
                create index if not exists idx_donations_device on donations(device);
                create index if not exists idx_server_health_ts on server_health(ts);
                create index if not exists idx_incidents_open on incidents(closed_at, opened_at);
                create index if not exists idx_incidents_key on incidents(dedupe_key, closed_at);
                """
            )
            defaults = {
                "maintenance": "0",
                "maintenance_message": "Ведутся технические работы. После завершения работ мы возобновим сервис.",
                "maintenance_message_en": "Maintenance in progress. Service will resume shortly.",
                "maintenance_schedule_enabled": "0",
                "maintenance_start": "0",
                "maintenance_end": "0",
                "announce": "",
                "announce_en": "",
                "subscription_main_enabled": "1",
                "update_notifications_enabled": "1",
                "rollout_percent": "100",
                "staging_enabled": "0",
                "staging_version": VERSION,
                "staging_version_code": str(VERSION_CODE),
                "staging_rollout_percent": "100",
                "app_version": VERSION,
                "app_version_code": str(VERSION_CODE),
                "app_changelog": DEFAULT_NOTE,
                "release_schedule_enabled": "0",
                "release_publish_at": "0",
                "scheduled_app_version": "",
                "scheduled_app_version_code": "0",
                "scheduled_rollout_percent": "100",
                "scheduled_app_changelog": "",
                "scheduled_min_version_code": "0",
                "min_version_code": "0",
                "force_update_message": "Доступна обязательная обновлённая версия QuantumVPN.",
                "feature_vpn_connect": "1",
                "feature_adblock": "1",
                "feature_auto_connect": "1",
                "feature_auto_failover": "1",
                "feature_kill_switch": "0",
                "feature_block_open_wifi": "0",
                "feature_selfsteal": "1",
                "feature_widgets": "1",
                "feature_changelog": "1",
                "feature_diagnostics": "1",
                "feature_timeline": "1",
                "feature_ab_json": "{}",
                "brand_name": "QuantumVPN",
                "brand_tagline": "HORIZON GLASS · 2026",
                "brand_accent": "#3DE7FF",
                "nodes_recommended": "",
                "nodes_forbidden": "",
                "config_revision": "1",
                "totp_enabled": "0",
                "totp_secret": "",
                "ip_allowlist": "",
                "telegram_bot_token": "",
                "telegram_chat_id": "",
                "telegram_alerts_enabled": "0",
                "telegram_backups_enabled": "0",
                "latency_optimization_enabled": "1",
                "latency_probe_interval": "30",
                "latency_max_ms": "120",
                "latency_probe_targets": "1.1.1.1:443,8.8.8.8:443",
                "latency_state": "unknown",
                "latency_last_probe": "0",
                "latency_best_ms": "0",
                "rate_limit_per_min": "120",
                "webhook_enabled": "0",
                "webhook_url": "",
                "webhook_secret": "",
                "webhook_events": "incident,release,maintenance,diagnostic",
            }
            for key, value in defaults.items():
                db.execute("insert or ignore into settings values (?,?)", (key, value))
            # Оповещения о новой версии всегда включены — нельзя выключить.
            db.execute(
                "insert or replace into settings(key,value) values ('update_notifications_enabled','1')"
            )
            db.execute(
                "update settings set value=? where key='maintenance_message' and value=?",
                (
                    "Ведутся технические работы. После завершения работ мы возобновим сервис.",
                    "Технические работы. Извините за неудобства.",
                ),
            )
            # Migrate the environment administrator into the RBAC table once.
            # The legacy Basic Auth credentials remain valid for compatibility,
            # but passwords are never stored in plaintext in the database.
            if db.execute("select count(*) from admin_users").fetchone()[0] == 0:
                db.execute(
                    "insert into admin_users(username,password_hash,role,enabled,created_at,updated_at) values (?,?,?,?,?,?)",
                    (USER, password_hash(PASSWORD), "owner", 1, now, now),
                )
            _DB_READY = True
        if now - _LAST_EVENT_CLEANUP >= 3600:
            db.execute("delete from events where ts < ?", (now - 14 * 86400,))
            db.execute("delete from audit where ts < ?", (now - 90 * 86400,))
            db.execute("delete from server_health where ts < ?", (now - 7 * 86400,))
            _LAST_EVENT_CLEANUP = now
        db.commit()
    return db


def settings(db):
    return dict(db.execute("select key, value from settings"))


def set_settings(db, values: dict):
    for k, v in values.items():
        db.execute("insert or replace into settings values (?,?)", (k, str(v)))


def enabled(s, key, default=True):
    return s.get(key, "1" if default else "0") == "1"


def effective_maintenance(s, now=None):
    now = int(time.time()) if now is None else int(now)
    manual = enabled(s, "maintenance", False)
    scheduled = enabled(s, "maintenance_schedule_enabled", False)
    start = int(s.get("maintenance_start", "0") or 0)
    end = int(s.get("maintenance_end", "0") or 0)
    return manual or (scheduled and start > 0 and end > start and start <= now < end)


def datetime_value(raw):
    try:
        epoch = int(raw or 0)
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M") if epoch > 0 else ""
    except Exception:
        return ""


def parse_datetime_value(raw):
    value = (raw or "").strip()
    if not value:
        return 0
    return int(datetime.datetime.fromisoformat(value).timestamp())


def client_bucket(raw):
    try:
        return max(0, min(99, int(raw)))
    except Exception:
        return None


def device_id(raw):
    return hashlib.sha256(raw.encode()).hexdigest()[:16] if raw else "anonymous"


def basic_auth_ok(header: str) -> bool:
    try:
        return base64.b64decode(header.split()[1]).decode() == f"{USER}:{PASSWORD}"
    except Exception:
        return False


def basic_auth_credentials(header: str):
    try:
        scheme, encoded = header.split(None, 1)
        if scheme.lower() != "basic":
            return None
        raw = base64.b64decode(encoded).decode("utf-8")
        username, password = raw.split(":", 1)
        return username, password
    except Exception:
        return None


def find_admin(db, username: str):
    row = db.execute(
        "select username,password_hash,role,enabled from admin_users where username=?",
        (username,),
    ).fetchone()
    if not row or not int(row[3]):
        return None
    return {"username": row[0], "password_hash": row[1], "role": normal_role(row[2])}


def authenticate_admin(db, username: str, password: str):
    row = find_admin(db, username)
    if row and password_ok(password, row["password_hash"]):
        return row
    # Keep the environment credentials as a break-glass path if the database
    # was restored from an older release and has not been migrated yet.
    if (
        not db.execute("select 1 from admin_users limit 1").fetchone()
        and hmac.compare_digest(username or "", USER)
        and hmac.compare_digest(password or "", PASSWORD)
    ):
        return {"username": USER, "role": "owner", "password_hash": ""}
    return None


def role_at_least(role: str, required: str) -> bool:
    levels = {"viewer": 0, "operator": 1, "owner": 2}
    return levels.get(normal_role(role), 0) >= levels.get(required, 2)


def ip_allowed(ip: str, s: dict) -> bool:
    raw = (s.get("ip_allowlist") or "").strip()
    if not raw:
        return True
    allowed = {x.strip() for x in raw.replace(";", ",").split(",") if x.strip()}
    return ip in allowed or ip in ("127.0.0.1", "::1")


def rate_limited(ip: str, limit: int) -> bool:
    now = time.time()
    with _RATE_LOCK:
        q = _RATE[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


def audit(db, actor, ip, action, detail):
    db.execute(
        "insert into audit values (?,?,?,?,?)",
        (int(time.time()), actor, ip, action, json.dumps(detail, ensure_ascii=False)[:4000]),
    )


def rospanel_ui_base() -> str:
    if not ROSPANEL_API:
        return "https://tepacom.o190.com/"
    return ROSPANEL_API[:-3] if ROSPANEL_API.endswith("/v1") else ROSPANEL_API


def rospanel_users(limit=200, q=""):
    try:
        db = sqlite3.connect(f"file:{ROSPANEL_DB}?mode=ro", uri=True, timeout=2)
        if q:
            like = f"%{q}%"
            rows = db.execute(
                """
                select name, enabled, status, used_up, used_down, expire_at, last_seen, id
                from users
                where name like ? or cast(id as text)=? or ifnull(note,'') like ? or ifnull(tags,'') like ?
                order by last_seen desc limit ?
                """,
                (like, q, like, like, limit),
            ).fetchall()
        else:
            rows = db.execute(
                """
                select name, enabled, status, used_up, used_down, expire_at, last_seen, id
                from users order by last_seen desc limit ?
                """,
                (limit,),
            ).fetchall()
        db.close()
        return rows
    except Exception:
        return []


def rospanel_summary():
    out = {"active": 0, "disabled": 0, "expired": 0, "online_15m": 0, "traffic_today_gb": 0.0, "ok": False}
    try:
        db = sqlite3.connect(f"file:{ROSPANEL_DB}?mode=ro", uri=True, timeout=2)
        now = int(time.time())
        out["active"] = db.execute("select count(*) from users where enabled=1").fetchone()[0]
        out["disabled"] = db.execute("select count(*) from users where enabled=0").fetchone()[0]
        out["expired"] = db.execute(
            "select count(*) from users where expire_at>0 and expire_at<?", (now,)
        ).fetchone()[0]
        out["online_15m"] = db.execute(
            "select count(*) from users where last_seen>?", (now - 900,)
        ).fetchone()[0]
        day = time.strftime("%Y-%m-%d")
        row = db.execute(
            "select coalesce(sum(up),0), coalesce(sum(down),0) from traffic_daily where day=?",
            (day,),
        ).fetchone()
        out["traffic_today_gb"] = round(((row[0] or 0) + (row[1] or 0)) / (1024**3), 2)
        out["ok"] = True
        db.close()
    except Exception as exc:
        out["error"] = str(exc)
    return out


def service_status():
    def unit(name):
        try:
            r = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return r.stdout.strip() or r.stderr.strip() or "unknown"
        except Exception as exc:
            return f"err:{exc}"

    def process(name):
        try:
            result = subprocess.run(["pgrep", "-f", name], capture_output=True, timeout=3)
            return "running" if result.returncode == 0 else "stopped"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "unknown"

    xray = process("xray run -c")
    opera = process("opera-proxy")
    disk = shutil.disk_usage("/")
    outbounds = []
    try:
        cfg = json.load(open("/var/lib/rospanel/xray/config.json"))
        outbounds = [o.get("tag") or o.get("protocol") for o in cfg.get("outbounds", [])]
    except Exception:
        pass
    return {
        "rospanel": unit("rospanel"),
        "operator": unit("quantumvpn-operator"),
        "xray": xray,
        "opera": opera,
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_used_pct": round(disk.used / disk.total * 100, 1),
        "outbounds": outbounds,
    }


_CACHE = {"summary": None, "summary_at": 0.0, "status": None, "status_at": 0.0}


def cached_rospanel_summary(ttl=30.0):
    now = time.monotonic()
    if _CACHE["summary"] is not None and now - _CACHE["summary_at"] < ttl:
        return _CACHE["summary"]
    value = rospanel_summary()
    _CACHE["summary"] = value
    _CACHE["summary_at"] = now
    return value


def cached_service_status(ttl=20.0):
    now = time.monotonic()
    if _CACHE["status"] is not None and now - _CACHE["status_at"] < ttl:
        return _CACHE["status"]
    value = service_status()
    _CACHE["status"] = value
    _CACHE["status_at"] = now
    return value


def probe_upstream():
    try:
        url = urlsplit(UPSTREAM)
        started = time.monotonic()
        with urlopen(f"{url.scheme}://{url.netloc}/", timeout=5) as response:
            status = response.status
        return {"ok": True, "status": status, "latency_ms": round((time.monotonic() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def record_health(db, target, result):
    """Persist a small bounded health sample for the operator dashboard."""
    ok = 1 if result.get("ok") else 0
    latency = int(result.get("latency_ms") or 0)
    detail = str(result.get("error") or result.get("status") or "")[:280]
    db.execute(
        "insert into server_health(ts,target,ok,latency_ms,detail) values (?,?,?,?,?)",
        (int(time.time()), target, ok, latency, detail),
    )


def health_snapshot(db, limit=24):
    rows = db.execute(
        "select ts,target,ok,latency_ms,detail from server_health order by ts desc limit ?",
        (max(1, min(200, int(limit))),),
    ).fetchall()
    return [dict(row) for row in rows]


def webhook_emit(s, event: str, payload: dict):
    """Send a signed, opt-in event to the operator's HTTPS webhook.

    Webhooks are deliberately disabled by default and only accept HTTPS URLs so
    an accidental panel setting cannot turn the server into an HTTP/metadata
    proxy. Delivery is best-effort; the incident and audit records remain the
    source of truth when a receiver is unavailable.
    """
    if not enabled(s, "webhook_enabled", False):
        return False
    url = (s.get("webhook_url") or "").strip()
    if not url.lower().startswith("https://") or len(url) > 2048:
        return False
    allowed = {x.strip().lower() for x in (s.get("webhook_events") or "").split(",") if x.strip()}
    if allowed and "all" not in allowed and event.lower() not in allowed:
        return False
    body = json.dumps(
        {"event": event, "ts": int(time.time()), "panel_build": PANEL_BUILD, "payload": payload},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"QuantumControl/{PANEL_BUILD}",
        "X-Quantum-Event": event[:80],
    }
    secret = (s.get("webhook_secret") or "").strip()
    if secret:
        headers["X-Quantum-Signature"] = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    try:
        with urlopen(Request(url, data=body, headers=headers, method="POST"), timeout=8) as response:
            return 200 <= response.status < 300
    except Exception:
        return False


def incident_open(db, dedupe_key: str, severity: str, source: str, title: str, detail: str, settings_snapshot=None):
    """Open one incident per dedupe key and notify only on the transition."""
    active = db.execute(
        "select id from incidents where dedupe_key=? and closed_at=0 order by id desc limit 1",
        (dedupe_key,),
    ).fetchone()
    if active:
        return False
    now = int(time.time())
    db.execute(
        "insert into incidents(opened_at,closed_at,severity,source,title,detail,dedupe_key) values (?,?,?,?,?,?,?)",
        (now, 0, severity[:20], source[:80], title[:240], detail[:1000], dedupe_key[:160]),
    )
    db.execute(
        "insert into events values (?,?,?,?,?)",
        (now, "incident_opened", source[:80], "", json.dumps({"key": dedupe_key, "title": title, "detail": detail}, ensure_ascii=False)),
    )
    if settings_snapshot is not None:
        webhook_emit(settings_snapshot, "incident.opened", {"key": dedupe_key, "severity": severity, "source": source, "title": title, "detail": detail})
    return True


def incident_close(db, dedupe_key: str, settings_snapshot=None):
    rows = db.execute(
        "select id,source,title from incidents where dedupe_key=? and closed_at=0",
        (dedupe_key,),
    ).fetchall()
    if not rows:
        return False
    now = int(time.time())
    db.execute("update incidents set closed_at=? where dedupe_key=? and closed_at=0", (now, dedupe_key))
    db.execute(
        "insert into events values (?,?,?,?,?)",
        (now, "incident_closed", "operator", "", json.dumps({"key": dedupe_key}, ensure_ascii=False)),
    )
    if settings_snapshot is not None:
        webhook_emit(settings_snapshot, "incident.closed", {"key": dedupe_key, "source": rows[0][1], "title": rows[0][2]})
    return True


def report_snapshot(db):
    """Return a compact, exportable 24-hour operations report for the panel."""
    now = int(time.time())
    since = now - 86400
    events = db.execute(
        "select kind,count(*) from events where ts>? group by kind order by kind",
        (since,),
    ).fetchall()
    health = db.execute(
        "select count(*), coalesce(sum(ok),0), coalesce(avg(nullif(latency_ms,0)),0) from server_health where ts>?",
        (since,),
    ).fetchone()
    devices = db.execute(
        "select count(distinct device) from events where ts>? and device!=''",
        (since,),
    ).fetchone()[0]
    open_count = db.execute("select count(*) from incidents where closed_at=0").fetchone()[0]
    return {
        "generated_at": now,
        "window": "24h",
        "events": {str(kind): int(count) for kind, count in events},
        "devices_seen": int(devices or 0),
        "health_checks": int(health[0] or 0),
        "health_ok": int(health[1] or 0),
        "health_uptime_percent": round((int(health[1] or 0) / int(health[0] or 1)) * 100, 1),
        "average_latency_ms": round(float(health[2] or 0), 1),
        "open_incidents": int(open_count or 0),
    }


def health_worker():
    """Check the subscription upstream and local VPN services periodically."""
    while True:
        try:
            db = conn()
            s = settings(db)
            upstream = probe_upstream()
            record_health(db, "subscription_upstream", upstream)
            if upstream.get("ok"):
                incident_close(db, "upstream", s)
            else:
                incident_open(db, "upstream", "critical", "subscription_upstream", "Подписка недоступна", str(upstream.get("error") or "нет ответа"), s)
            services = service_status()
            for target in ("rospanel", "xray", "operator"):
                value = services.get(target, "unknown")
                record_health(db, target, {"ok": value in ("active", "running", "ok"), "status": value})
                key = f"service:{target}"
                if value in ("active", "running", "ok"):
                    incident_close(db, key, s)
                else:
                    incident_open(db, key, "critical", target, f"Сервис {target} недоступен", f"status={value}", s)
            if services.get("disk_used_pct", 0) >= 90:
                incident_open(db, "disk", "warning", "disk", "Заканчивается место на диске", f"used={services.get('disk_used_pct')}%", s)
            else:
                incident_close(db, "disk", s)
            db.commit()
            db.close()
        except Exception:
            pass
        time.sleep(60)


def parse_latency_targets(raw: str):
    targets = []
    for item in (raw or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        host, sep, port = item.rpartition(":")
        if not sep:
            host, port = item, "443"
        host = host.strip("[] ")
        try:
            port = max(1, min(65535, int(port)))
        except Exception:
            continue
        if host and len(host) <= 253:
            targets.append((host, port))
    return targets[:8]


def probe_tcp_latency(host: str, port: int):
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=3)
        return {"ok": True, "latency_ms": round((time.monotonic() - started) * 1000), "status": f"tcp:{port}"}
    except Exception as exc:
        return {"ok": False, "latency_ms": 0, "error": str(exc)}
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def latency_worker():
    """Measure the VDS egress path without requiring raw ICMP privileges."""
    while True:
        interval = 30
        try:
            db = conn()
            s = settings(db)
            interval = max(15, min(300, int(s.get("latency_probe_interval", "30") or 30)))
            if enabled(s, "latency_optimization_enabled", True):
                targets = parse_latency_targets(s.get("latency_probe_targets", ""))
                samples = []
                for host, port in targets:
                    result = probe_tcp_latency(host, port)
                    record_health(db, f"latency:{host}:{port}", result)
                    if result.get("ok"):
                        samples.append(int(result.get("latency_ms") or 0))
                max_ms = max(20, min(5000, int(s.get("latency_max_ms", "120") or 120)))
                best = min(samples) if samples else 0
                state = "healthy" if samples and best <= max_ms else ("degraded" if samples else "offline")
                set_settings(db, {
                    "latency_state": state,
                    "latency_last_probe": str(int(time.time())),
                    "latency_best_ms": str(best),
                })
                db.commit()
            db.close()
        except Exception:
            time.sleep(5)
        time.sleep(interval)


def promote_scheduled_release(db, now=None):
    """Promote a pre-uploaded release at its exact epoch without exposing it early."""
    s = settings(db)
    if not enabled(s, "release_schedule_enabled", False):
        return False
    publish_at = int(s.get("release_publish_at", "0") or 0)
    version = (s.get("scheduled_app_version") or "").strip()
    code = int(s.get("scheduled_app_version_code", "0") or 0)
    now = int(time.time()) if now is None else int(now)
    if publish_at <= 0 or publish_at > now or not version or code <= 0:
        return False
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        return False
    rollout = max(1, min(100, int(s.get("scheduled_rollout_percent", "100") or 100)))
    note = s.get("scheduled_app_changelog") or DEFAULT_NOTE
    min_code = max(0, int(s.get("scheduled_min_version_code", "0") or 0))
    set_settings(db, {
        "app_version": version,
        "app_version_code": str(code),
        "rollout_percent": str(rollout),
        "app_changelog": note[:1000],
        "min_version_code": str(min_code),
        "update_notifications_enabled": "1",
        "announce": f"Доступен QuantumVPN {version}: Horizon Glass 2026 и адаптивное оформление.",
        "announce_en": f"QuantumVPN {version} is available: Horizon Glass 2026 and adaptive theming.",
        "force_update_message": f"Доступно обновление QuantumVPN {version}.",
        "config_revision": str(int(s.get("config_revision", "1") or 1) + 1),
        "release_schedule_enabled": "0",
    })
    banner = f"Доступно обновление QuantumVPN {version}. Откройте уведомление, чтобы установить новую версию."
    # Known devices receive a persistent banner; create the flag row even when
    # the device has never used another operator action before.
    devices = db.execute(
        "select distinct device from events where kind='policy' and ts>? and device!='' limit 5000",
        (now - 365 * 86400,),
    ).fetchall()
    for (device,) in devices:
        db.execute(
            "insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) "
            "on conflict(device) do update set force_banner=excluded.force_banner, updated_at=excluded.updated_at",
            (device, banner[:500], 0, f"{version}-release", now),
        )
    db.execute(
        "insert into events values (?,?,?,?,?)",
        (now, "release_promoted", "operator", "", json.dumps({"version": version, "version_code": code}, ensure_ascii=False)),
    )
    db.commit()
    webhook_emit(settings(db), "release.promoted", {"version": version, "version_code": code, "rollout_percent": rollout})
    release_info.cache_clear()
    return True


def scheduled_release_worker():
    while True:
        try:
            db = conn()
            promote_scheduled_release(db)
            db.close()
        except Exception:
            pass
        time.sleep(20)


def telegram_send(s, text: str):
    token = (s.get("telegram_bot_token") or "").strip()
    chat = (s.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        return False
    try:
        data = urlencode({"chat_id": chat, "text": text[:3500]}).encode()
        req = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data, method="POST")
        with urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def telegram_send_document(s, path: str, caption: str = ""):
    """Upload one backup archive to the configured Telegram chat."""
    token = (s.get("telegram_bot_token") or "").strip()
    chat = (s.get("telegram_chat_id") or "").strip()
    if not token or not chat or not os.path.isfile(path):
        return False
    try:
        boundary = "----QuantumVPN" + secrets.token_hex(12)
        with open(path, "rb") as stream:
            payload = stream.read()
        filename = os.path.basename(path)
        chunks = []
        def field(name, value):
            chunks.append(f"--{boundary}\r\n".encode())
            chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            chunks.append(str(value).encode())
            chunks.append(b"\r\n")
        field("chat_id", chat)
        field("caption", caption[:900])
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
            "Content-Type: application/zip\r\n\r\n".encode()
        )
        chunks.append(payload)
        chunks.append(b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode())
        req = Request(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def create_backup_archive():
    """Create a consistent, local operator backup without touching the live DB."""
    folder = os.path.join(ROOT, "backups")
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    archive = os.path.join(folder, f"quantum-control-{stamp}.zip")
    temp_db = os.path.join(folder, f".operator-{stamp}.db")
    source = sqlite3.connect(DB, timeout=30)
    try:
        target = sqlite3.connect(temp_db)
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()
    try:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(temp_db, "operator.db")
            secret = os.path.join(ROOT, "session.secret")
            if os.path.isfile(secret):
                bundle.write(secret, "session.secret")
            bundle.writestr(
                "backup-info.json",
                json.dumps({"created_at": int(time.time()), "panel_build": PANEL_BUILD}, ensure_ascii=False),
            )
    finally:
        try:
            os.remove(temp_db)
        except OSError:
            pass
    # Keep seven days locally; Telegram remains the remote copy.
    cutoff = time.time() - 7 * 86400
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if name.endswith(".zip") and os.path.getmtime(path) < cutoff:
            try:
                os.remove(path)
            except OSError:
                pass
    return archive


def hourly_backup_worker():
    """Send a database/session backup once per wall-clock hour when enabled."""
    while True:
        try:
            now = int(time.time())
            next_hour = ((now // 3600) + 1) * 3600
            time.sleep(max(5, next_hour - now))
            db = conn()
            s = settings(db)
            if enabled(s, "telegram_backups_enabled", False):
                archive = create_backup_archive()
                ok = telegram_send_document(
                    s,
                    archive,
                    f"Quantum Control: часовая резервная копия {time.strftime('%Y-%m-%d %H:%M UTC')}",
                )
                audit(db, "system", "127.0.0.1", "hourly_backup", {"ok": ok, "file": os.path.basename(archive)})
                db.commit()
            db.close()
        except Exception:
            time.sleep(30)


def alert_worker():
    while True:
        try:
            db = conn()
            s = settings(db)
            if enabled(s, "telegram_alerts_enabled", False):
                st = service_status()
                up = probe_upstream()
                now = int(time.time())
                day_start = now - (now % 86400)
                errors = db.execute(
                    "select count(*) from events where kind='voluntary_diagnostic' and ts>?",
                    (now - 3600,),
                ).fetchone()[0]
                checks = {
                    "upstream": (not up.get("ok"), f"Upstream недоступен: {up.get('error')}"),
                    "rospanel": (st["rospanel"] != "active", f"RosPanel status={st['rospanel']}"),
                    "xray": (st["xray"] != "running", "Xray не запущен"),
                    "disk": (st["disk_used_pct"] >= 90, f"Диск заполнен на {st['disk_used_pct']}%"),
                    "errors": (errors >= 20, f"Диагностик за час: {errors}"),
                }
                with _ALERT_STATE["lock"]:
                    for key, (bad, msg) in checks.items():
                        last = _ALERT_STATE["last"].get(key, 0)
                        if bad and now - last > 1800:
                            if telegram_send(s, f"[Quantum Control] {msg}"):
                                _ALERT_STATE["last"][key] = now
                        elif not bad:
                            _ALERT_STATE["last"].pop(key, None)
            db.close()
        except Exception:
            pass
        time.sleep(60)


def localize(s, key_ru, key_en, lang):
    if (lang or "").lower().startswith("en"):
        return s.get(key_en) or s.get(key_ru) or ""
    return s.get(key_ru) or ""


def ab_features(s, bucket):
    try:
        raw = json.loads(s.get("feature_ab_json") or "{}")
    except Exception:
        raw = {}
    result = {}
    if bucket is None:
        return result
    for name, rule in raw.items():
        if not isinstance(rule, dict):
            continue
        pct = rule.get("percent")
        if pct is not None:
            try:
                result[name] = bucket < max(0, min(100, int(pct)))
                continue
            except Exception:
                pass
        ranges = str(rule.get("buckets", "")).strip()
        ok = False
        for part in ranges.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    if int(a) <= bucket <= int(b):
                        ok = True
                except Exception:
                    pass
            else:
                try:
                    if bucket == int(part):
                        ok = True
                except Exception:
                    pass
        result[name] = ok
    return result


def parse_multipart(handler):
    ctype = handler.headers.get("Content-Type", "")
    length = int(handler.headers.get("Content-Length", "0"))
    body = handler.rfile.read(min(length, 400 * 1024 * 1024))
    if "multipart/form-data" not in ctype:
        return parse_qs(body.decode("utf-8", "replace")), {}
    msg = BytesParser(policy=email_default).parsebytes(
        b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body
    )
    form, files = {}, {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_param("filename", header="content-disposition")
        payload = part.get_payload(decode=True) or b""
        if not name:
            continue
        if filename:
            files[name] = {"filename": filename, "data": payload}
        else:
            form.setdefault(name, []).append(payload.decode("utf-8", "replace"))
    return form, files


def css():
    return """
    :root{color-scheme:dark;--bg:#070a11;--surface:#0b111c;--card:#0c1522e8;--line:#18354d;--line2:#245977;--text:#e8f7ff;--muted:#8ba3b5;--cyan:#26ddff;--violet:#9b7bff;--amber:#ffb454;--ok:#35e7ad;--off:#ff718a}
    *{box-sizing:border-box}body{margin:0;background-color:var(--bg);background-image:linear-gradient(#0b1723 1px,transparent 1px),linear-gradient(90deg,#0b1723 1px,transparent 1px),radial-gradient(circle at 72% -12%,#123c52 0,transparent 38%),radial-gradient(circle at 6% 90%,#17102c 0,transparent 30%);background-size:32px 32px,32px 32px,auto,auto;color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
    main{max-width:1560px;margin:auto;padding:18px 18px 64px}.hero,.card{background:linear-gradient(145deg,#0d1827f2,#09111df2);border:1px solid var(--line);border-radius:14px;padding:16px;margin:12px 0;box-shadow:0 18px 60px #0008, inset 0 1px #ffffff0a}
    .hero{position:relative;overflow:hidden;background:linear-gradient(120deg,#0d1d2b,#0a101b 62%,#17112c)}.hero:after{content:"";position:absolute;inset:auto -10% -70% 35%;height:220px;background:radial-gradient(ellipse,#26ddff22,transparent 68%);pointer-events:none}.hero-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.system-pill{border:1px solid #35e7ad66;background:#35e7ad12;color:var(--ok);border-radius:999px;padding:6px 11px;font-size:12px;white-space:nowrap}.sidebar-brand{font-weight:800;letter-spacing:.04em;color:var(--text);padding:8px 10px 14px;border-bottom:1px solid var(--line);margin-bottom:10px}.sidebar-brand span{display:block;color:var(--muted);font-size:11px;font-weight:500;letter-spacing:0;margin-top:3px}h1{margin:5px 0;font-size:28px;letter-spacing:-.02em}h2{margin:0 0 11px;font-size:17px;letter-spacing:.01em}
    .accent,.ok{color:var(--ok)}.off{color:var(--off)}.warn{color:var(--amber)}.muted{color:var(--muted)}
    .panel-shell{display:grid;grid-template-columns:232px minmax(0,1fr);gap:14px;align-items:start}.sidebar{position:sticky;top:12px;background:#080f1aeF;border:1px solid #1b4260;border-radius:14px;padding:10px;box-shadow:0 20px 60px #0009}.panel-content{min-width:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}.grid .card{margin:0}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:9px}.stat{background:#080f19;border:1px solid #17324a;border-radius:10px;padding:11px;box-shadow:inset 0 0 24px #26ddff05}.stat b{display:block;font-size:21px;margin-top:4px;color:var(--text)}
    label{display:block;margin:10px 0}textarea,input,select{width:100%;background:#070d16;color:var(--text);border:1px solid #21455f;border-radius:8px;padding:10px;outline:none}textarea:focus,input:focus,select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #26ddff14}input[type=checkbox]{width:auto;accent-color:var(--cyan)}
    button,a.button{display:inline-block;background:linear-gradient(135deg,#26ddff,#6e76ff);color:#061019;border:1px solid #74eaff66;border-radius:8px;padding:9px 13px;font-weight:800;text-decoration:none;cursor:pointer;box-shadow:0 5px 18px #26ddff1c}button:hover,a.button:hover{filter:brightness(1.13);transform:translateY(-1px)}
    button.secondary,a.secondary{background:#101d2d;color:#d9f5ff;border:1px solid #245977;box-shadow:none}button.danger{background:linear-gradient(135deg,#ffb454,#e9784f);color:#1a1004;border-color:#ffc56f66}.actions{display:flex;gap:7px;flex-wrap:wrap}nav.tabs{display:flex;flex-direction:column;gap:4px}nav.tabs a{display:block;padding:10px 11px;border-radius:8px;border:1px solid transparent;color:#bfd2df;text-decoration:none;font-size:13px;transition:.15s}nav.tabs a:hover{background:#102538;border-color:#245977;color:var(--text)}nav.tabs a.active{background:linear-gradient(90deg,#12364a,#121a32);border-color:#26ddff88;color:var(--cyan);box-shadow:inset 3px 0 var(--cyan),0 0 18px #26ddff12}
    table{width:100%;border-collapse:collapse;font-size:12px;background:#070e18;border:1px solid #17324a;border-radius:10px;overflow:hidden}th,td{padding:9px 7px;border-bottom:1px solid #13283a;text-align:left;vertical-align:top}th{color:#9cc0d3;background:#0c1a2a;font-size:11px;text-transform:uppercase;letter-spacing:.04em}tr:hover td{background:#0b1b2a}.flash{padding:10px 12px;border-radius:9px;background:#102b2a;border:1px solid #35e7ad77;margin:10px 0}.login{max-width:430px;margin:10vh auto}.pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#12263a;border:1px solid #245977;font-size:12px}.live-log{font-family:"Cascadia Code",Consolas,monospace;color:#b8f6ff;background:#050a11!important;border-color:#1e5876!important;text-shadow:0 0 8px #26ddff18}.hero code,.card code{color:#b9dcf1}
    @media(max-width:800px){main{padding:12px 9px 48px}.panel-shell{grid-template-columns:1fr}.sidebar{position:static}.sidebar nav.tabs{flex-direction:row;overflow:auto}.sidebar nav.tabs a{white-space:nowrap}.sidebar-brand{display:none}.hero{margin-bottom:10px}.hero-top{align-items:flex-start}table{font-size:11px}}
    /* Reference layout: clean desktop operator console with a blue navigation rail. */
    :root{color-scheme:light;--bg:#f5f7fb;--surface:#fff;--card:#fff;--line:#e6ebf2;--text:#18233b;--muted:#71809a;--blue:#116fe8;--blue-dark:#124a99;--ok:#13aa67;--amber:#f2a900;--off:#e33e4e;--shadow:0 2px 10px #243b5a12}
    body{background:var(--bg);color:var(--text)}main{max-width:1600px;margin:auto;padding:0 24px 48px}.hero{margin:0 0 18px;padding:20px 26px 22px;background:#fff;border-bottom:1px solid var(--line);border-radius:0;box-shadow:0 1px 5px #243b5a0b}.hero-top{display:flex;align-items:center;justify-content:space-between;gap:16px}.hero .accent{font-weight:700;color:var(--blue-dark)}.hero h1{margin:22px 0 2px;font-size:28px;letter-spacing:-.03em}.hero p{margin:0}.system-pill{border:1px solid #bcebd4;background:#effcf5;color:var(--ok);border-radius:999px;padding:7px 12px;font-size:12px;white-space:nowrap;font-weight:700}
    .panel-shell{grid-template-columns:214px minmax(0,1fr);gap:16px}.sidebar{position:sticky;top:14px;background:linear-gradient(180deg,#124c9b,#0c3b7d);border:0;border-radius:0 10px 10px 0;padding:14px 10px;min-height:calc(100vh - 42px);box-shadow:8px 6px 24px #124a9926}.sidebar-brand{color:#fff;padding:6px 12px 18px;border-bottom:1px solid #ffffff24;margin-bottom:14px;font-size:19px}.sidebar-brand span{color:#cfe0fb}.panel-content{min-width:0;max-width:1220px}.card{background:#fff;border:1px solid var(--line);border-radius:9px;padding:17px;margin:0 0 16px;box-shadow:var(--shadow);min-width:0;overflow:hidden}
    nav.tabs a{padding:9px 12px;border-radius:6px;color:#e9f2ff;font-size:13px}nav.tabs a:hover{background:#ffffff16}nav.tabs a.active{background:#1e81ec;color:#fff;box-shadow:0 4px 12px #061f4c45;font-weight:600}nav.tabs a:last-child{margin-top:14px;border-top:1px solid #ffffff24;border-radius:0;padding-top:15px;color:#d4e1f5}.nav-group{margin:5px 0}.nav-group summary{list-style:none;cursor:pointer;color:#bcd1ed;padding:8px 12px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}.nav-group summary::-webkit-details-marker{display:none}.nav-group summary:before{content:'▸';display:inline-block;width:16px;color:#87b9f4}.nav-group[open] summary:before{content:'▾'}.nav-group a{padding:8px 12px 8px 27px!important;font-size:13px!important}
    .stats{grid-template-columns:repeat(4,minmax(140px,1fr));gap:11px}.stat{background:#fff;border:1px solid var(--line);border-radius:9px;padding:13px;box-shadow:var(--shadow);color:#596984}.stat b{font-size:22px;line-height:1.1;margin-top:7px;color:#16213b}.stat small{font-size:11px}.stat .delta{font-size:11px;color:var(--ok);margin-left:6px;font-weight:700}.accent,.ok{color:var(--ok)}.off{color:var(--off)}.warn{color:var(--amber)}.muted{color:var(--muted)}
    textarea,input,select{background:#fff;color:var(--text);border:1px solid #d4ddea;border-radius:6px}textarea:focus,input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 3px #116fe81a}input[type=checkbox]{accent-color:var(--blue)}button,a.button{background:var(--blue);color:#fff;border:1px solid var(--blue);border-radius:6px;box-shadow:0 2px 5px #116fe827}button:hover,a.button:hover{filter:brightness(1.06)}button.secondary,a.secondary{background:#fff;color:var(--blue);border-color:#c8d6ea;box-shadow:none}button.danger{background:#fff0f0;color:var(--off);border-color:#f3b7bd}.pill{background:#eef3f9;border:1px solid #dae3ef}.flash{background:#effcf5;border-color:#bcebd4;color:#147847}
    table{background:#fff;border:1px solid var(--line);max-width:100%}th,td{border-bottom:1px solid #edf0f5}th{color:#596984;background:#f8fafc;text-transform:none;letter-spacing:0}tr:hover td{background:#fafcff}.live-log{color:#19344f;background:#f8fafc!important;border-color:#d4ddea!important}.hero code,.card code{color:#175aa9}.split{display:grid;grid-template-columns:minmax(0,1.28fr) minmax(330px,.92fr);gap:13px;min-width:0}.split > *{min-width:0}.dashboard{padding:14px}.dashboard > .split{margin-top:12px}.dashboard .card{padding:13px;margin-bottom:0}.dashboard-side{display:grid;grid-template-columns:1fr 1fr;gap:12px;min-width:0}.dashboard-side .card{min-width:0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px}.section-head h2{margin:0}.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:9px}.toolbar input{flex:1}.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:600}.badge.ok{background:#e9faf2;color:#0a9a5b}.badge.warn{background:#fff7dd;color:#bf7e00}.badge.off{background:#fff0f1;color:#d22d3f}.settings-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #edf0f5}.settings-row:last-child{border-bottom:0}.settings-row strong{display:block}.settings-row small{display:block;color:var(--muted)}
    @media(max-width:1180px){.dashboard-side{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,minmax(150px,1fr))}}@media(max-width:900px){.split{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,minmax(140px,1fr))}}@media(max-width:800px){main{padding:0 10px 40px}.panel-shell{grid-template-columns:1fr;gap:10px}.sidebar{position:static;min-height:auto;border-radius:8px;padding:10px}.sidebar-brand{display:none}.sidebar nav.tabs{flex-direction:row;overflow:auto}.sidebar nav.tabs a{white-space:nowrap}.nav-group summary{white-space:nowrap}.sidebar nav.tabs a:last-child{margin-top:0;border:0;padding-top:9px}.hero{padding:16px 12px}.hero h1{font-size:24px}.stats{grid-template-columns:1fr 1fr}table{font-size:11px;display:block;overflow:auto;white-space:nowrap}}
    /* Operations-center reference theme. */
    :root{color-scheme:dark;--bg:#050b12;--surface:#07111b;--card:#07131f;--line:#173349;--line2:#214b68;--text:#e8f5ff;--muted:#88a1b7;--blue:#25d5ff;--violet:#9c6dff;--ok:#35e7ad;--amber:#ffb44b;--off:#ff647d}
    body{background:#050b12;background-image:linear-gradient(#08131d 1px,transparent 1px),linear-gradient(90deg,#08131d 1px,transparent 1px),radial-gradient(circle at 80% -10%,#102f42 0,transparent 42%);background-size:28px 28px,28px 28px,auto;color:var(--text);font:13px/1.4 "Segoe UI",system-ui,sans-serif}main{max-width:1700px;padding:0 18px 34px}.panel-shell{grid-template-columns:224px minmax(0,1fr);gap:14px}.sidebar{background:linear-gradient(180deg,#06101a,#070e17);border:1px solid #10283a;border-radius:0 8px 8px 0;padding:12px 9px;min-height:calc(100vh - 32px);box-shadow:12px 0 38px #0008}.sidebar-brand{color:#eaf7ff;border-bottom:1px solid #153044;margin:0 4px 14px;padding:7px 9px 14px;font-size:19px;letter-spacing:-.03em}.sidebar-brand:before{content:'◉';display:inline-block;color:var(--blue);margin-right:10px;text-shadow:0 0 14px var(--blue)}.sidebar-brand span{color:#7ba1b9;margin-left:29px}.panel-content{max-width:none}.hero{height:58px;margin:0 0 12px;padding:9px 14px;background:#060f18eF;border:1px solid #142c3d;border-radius:7px;box-shadow:0 10px 30px #0005}.hero-top{height:100%;justify-content:space-between}.hero .accent{display:none}.hero h1,.hero p{display:none}.hero-top:before{content:'⌕  Поиск по нодам, пользователям, событиям…   ·   Ctrl + K';display:flex;align-items:center;height:36px;min-width:390px;padding:0 13px;border:1px solid #20435b;border-radius:6px;color:#7893aa;background:#07131f;letter-spacing:.01em}.system-pill{border:0;background:transparent;color:var(--ok);font-size:12px;font-weight:700;padding:0 18px}.system-pill:after{content:'  Все сервисы работают';display:block;color:#7993a7;font-weight:400;margin-top:2px}.card{background:linear-gradient(145deg,#071520,#06111b);border:1px solid #17384f;border-radius:7px;box-shadow:0 12px 28px #0006,inset 0 1px #ffffff08;color:var(--text);padding:14px;margin:0 0 12px}.dashboard{padding:0;background:transparent;border:0;box-shadow:none;overflow:visible}.dashboard .card{background:linear-gradient(145deg,#071722,#06111b);padding:12px;margin:0}.dashboard .section-head{margin-bottom:7px}.dashboard > .split{margin-top:12px}.stats{grid-template-columns:repeat(4,minmax(140px,1fr));gap:10px}.stat{background:#081722;border:1px solid #16364b;box-shadow:none;padding:11px;color:#87a6bb}.stat b{color:#edf8ff;font-size:21px}.stat small{color:#7893a8}.stat .delta{color:var(--ok)}
    h1{font-size:24px}h2{font-size:16px;color:#f1f8ff}.muted{color:#7f9aad}.accent,.ok{color:var(--ok)}.off{color:var(--off)}.warn{color:var(--amber)}.pill{background:#0c2130;border-color:#1b4967;color:#b7d2e4}.nav-ico{display:inline-block;width:28px;color:#a8c8df;font-size:18px;text-align:center;margin-right:7px}nav.tabs a{color:#a8c2d5;border-radius:5px;padding:10px 12px;font-size:13px}nav.tabs a:hover{background:#0b2435;color:#eaf7ff}nav.tabs a.active{background:#0b283a;color:var(--blue);box-shadow:inset 2px 0 var(--blue),0 0 16px #26ddff18}.nav-group summary{color:#64869e}.nav-group a{color:#9bb7ca}.nav-group[open] summary{color:#b9d7e9}
    table{background:#06111b;border-color:#15364b;color:#dbeef9}th{background:#091a28;color:#80a1b7;border-color:#15364b}td{border-color:#112b3c}tr:hover td{background:#0a2030}.button,button,a.button{background:linear-gradient(135deg,#19c8ef,#277be9);border-color:#48ddff66;color:#041019;box-shadow:0 3px 13px #159bd52b}button.secondary,a.secondary{background:#0b1e2e;color:#c4e9fa;border-color:#255572}button.danger{background:#2b1b18;color:#ffbd87;border-color:#99543a}.toolbar input,textarea,input,select{background:#06111b;color:#e8f5ff;border-color:#214961}.toolbar input::placeholder{color:#628198}.flash{background:#0c2b2b;border-color:#2a9c7a;color:#8ff3c9}.dashboard .split{grid-template-columns:minmax(0,1.35fr) minmax(420px,.9fr)}.dashboard-middle{display:grid;grid-template-columns:1fr 1.28fr .72fr;gap:12px;margin-top:12px}.dashboard-side{grid-template-columns:1fr;gap:12px}.dashboard .dashboard-side .card{min-height:0}
    .top-date{min-width:120px;text-align:right;color:#b8cbda;line-height:1.25}.top-date small{color:#6f899d}.topology-layout{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(330px,.85fr);gap:12px}.topology-map{min-height:300px}.topology-map svg{width:100%;height:238px;border:1px solid #102f43;border-radius:5px;background:#050d14}.topology-meta{display:flex;gap:18px;align-items:center;color:#9bb5c8;font-size:12px;margin:3px 0 9px}.topology-meta b{color:#e6f6ff}.legend{display:flex;gap:18px;color:#7894a9;font-size:11px;margin-top:7px}.legend span:before{content:'';display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--blue);box-shadow:0 0 9px currentColor}.legend .load:before{background:var(--amber)}.legend .maint:before{background:var(--violet)}.legend .down:before{background:#879bad}.event-list{display:grid}.event-row{display:grid;grid-template-columns:9px 43px 92px minmax(0,1fr) 20px;gap:8px;align-items:center;min-height:39px;border-bottom:1px solid #112b3b;color:#a8bfd0}.event-row:last-child{border-bottom:0}.event-row time{color:#708da5}.event-row b{color:#dfedf6;overflow:hidden;text-overflow:ellipsis}.event-row span:not(.event-dot){overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.event-row i{font-style:normal;color:#8aa4b7}.event-dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 9px currentColor}.event-dot.warn{background:var(--amber)}.empty-state{padding:22px;color:#6c899f;text-align:center}.deploy-card,.system-card,.actions-card{min-height:272px}.deploy-kicker{color:#8ba6ba;margin-bottom:12px}.deploy-version{display:inline-block;border:1px solid #244963;border-radius:5px;padding:3px 8px;color:#b9d8eb;margin-left:6px}.progress{height:13px;border:1px solid #1d526d;background:#0b202e;border-radius:5px;overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,#18c4eb,#42ebff);box-shadow:0 0 14px #2bdcff66}.deploy-caption{display:flex;justify-content:space-between;color:#9db6c7;margin:7px 0 11px;font-size:12px}.deploy-row{display:grid;grid-template-columns:20px 1fr 1fr 44px;gap:7px;align-items:center;border-top:1px solid #112b3b;padding:7px 0;color:#adc5d4}.deploy-row b{color:#e4f1f8}.deploy-row time{text-align:right;color:#6d899e}.deploy-state{width:15px;height:15px;border:2px solid #56758a;border-radius:50%;display:grid;place-items:center;color:#07131c;font-size:10px}.deploy-state.done{background:var(--ok);border-color:var(--ok)}.deploy-state.active{border-color:var(--blue);color:var(--blue)}.mini-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin:8px 0 15px}.mini-stat{border:1px solid #17384e;border-radius:5px;padding:9px;background:#081723}.mini-stat small{display:block;color:#88a6b9}.mini-stat b{display:block;color:#eef8ff;font-size:16px;margin-top:3px}.mini-stat em{font-style:normal;color:var(--ok);font-size:11px}.chart{height:100px;border:1px solid #112e42;border-radius:5px;background:linear-gradient(#071722aa,#061019);position:relative;overflow:hidden}.chart:before{content:'';position:absolute;inset:18px 10px;background:repeating-linear-gradient(0deg,transparent 0 24px,#123044 25px 26px),repeating-linear-gradient(90deg,transparent 0 62px,#123044 63px 64px)}.chart svg{position:absolute;inset:0;width:100%;height:100%}.actions-stack{display:grid;gap:8px}.ops-action{width:100%;text-align:left;padding:10px 12px;background:transparent!important;border-radius:5px;box-shadow:none!important;color:#dceef8!important}.ops-action strong{display:block;font-size:13px}.ops-action small{display:block;color:#8aa4b7;margin-top:2px}.ops-check{border-color:#19c9ef!important;color:#39d8ff!important}.ops-restart{border-color:#bd7727!important;color:#ffc15a!important}.ops-release{border-color:#8a5ee8!important;color:#bd9bff!important}.ops-save{border-color:#668399!important;color:#c9d8e3!important}.logs-card{margin-top:12px}.logs-card pre{margin:0;max-height:178px;overflow:auto;padding:10px;background:#050d14!important;border:1px solid #15364a;border-radius:5px;color:#b6d6e5;font:12px/1.55 "Cascadia Code",Consolas,monospace}.terminal-toolbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}.terminal-log time{color:#64849b}.term-level.info{color:#24d3ff}.term-level.warn{color:#ffb54e}.terminal-log b{color:#dbeef8}
    @media(max-width:1250px){.dashboard .split{grid-template-columns:1fr}.dashboard-middle{grid-template-columns:1fr 1fr}.actions-card{grid-column:1 / -1}.topology-layout{grid-template-columns:1fr}.dashboard-side{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:980px){.dashboard-side{grid-template-columns:1fr}.dashboard-middle{grid-template-columns:1fr}.actions-card{grid-column:auto}.stats{grid-template-columns:repeat(2,1fr)}.mini-grid{grid-template-columns:repeat(2,1fr)}}
    """


def render_login(error=""):
    return f"""<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
    <title>Quantum Control · вход</title><style>{css()}</style>
    <main class=login><section class=hero><div class=accent>QUANTUM CONTROL</div><h1>Вход в панель</h1>
    <p class=muted>Доп. веб-панель приложения. RosPanel не изменяется.</p>
    {"<p class=off>" + html.escape(error) + "</p>" if error else ""}
    <form method=post action=/operator/login>
      <label>Логин<input name=username autocomplete=username required></label>
      <label>Пароль<input type=password name=password autocomplete=current-password required></label>
      <label>Код 2FA (если включён)<input name=totp inputmode=numeric autocomplete=one-time-code placeholder=000000></label>
      <button>Войти</button>
    </form></section></main>"""


def render_panel(s, rows, users, protocols, summary, status, audit_rows, device_rows, flash="", section="dashboard", q="", device=None, donation_rows=None, donation_totals=None, admin_rows=None, actor_role="owner"):
    checked = lambda key: "checked" if s.get(key) == "1" else ""
    events = "".join(
        f"<tr><td>{time.strftime('%d.%m %H:%M', time.localtime(x[0]))}</td><td>{html.escape(x[1])}</td>"
        f"<td><a href='/operator?tab=devices&q={quote(x[2])}'>{html.escape(x[2])}</a></td>"
        f"<td>{html.escape(x[3])}</td><td><pre style='white-space:pre-wrap;margin:0'>{html.escape(x[4][:800])}</pre></td></tr>"
        for x in rows
    ) or "<tr><td colspan=5>Событий пока нет</td></tr>"
    rp_base = rospanel_ui_base()
    subscribers = "".join(
        f"<tr><td>{html.escape(str(name))}</td>"
        f"<td class={'ok' if en else 'off'}>{'активен' if en else 'отключён'}</td>"
        f"<td>{html.escape(str(status_u or '—'))}</td>"
        f"<td>{((up or 0)+(down or 0))/1024/1024:.1f} MB</td>"
        f"<td>{'—' if not expires else time.strftime('%d.%m.%Y', time.localtime(expires))}</td>"
        f"<td>{'—' if not seen else time.strftime('%d.%m %H:%M', time.localtime(seen))}</td>"
        f"<td><a class=button secondary href='{html.escape(rp_base)}' target=_blank rel=noopener>RosPanel</a></td></tr>"
        for name, en, status_u, up, down, expires, seen, uid in users
    ) or "<tr><td colspan=7>RosPanel недоступен</td></tr>"
    toggles = "".join(
        f"<label><input type=checkbox name=p_{html.escape(name)} {'checked' if en else ''}> {html.escape(name.upper())}</label>"
        for name, en in protocols
    ) or "<p class=muted>Протоколы появятся после синхронизации подписки.</p>"
    audit_html = "".join(
        f"<tr><td>{time.strftime('%d.%m %H:%M', time.localtime(a[0]))}</td><td>{html.escape(a[1])}</td>"
        f"<td>{html.escape(a[2])}</td><td>{html.escape(a[3])}</td><td><code>{html.escape(a[4][:500])}</code></td></tr>"
        for a in audit_rows
    ) or "<tr><td colspan=5>Аудит пуст</td></tr>"
    admin_html = "".join(
        f"<tr><td>{html.escape(str(a[0]))}</td><td>{html.escape(normal_role(a[1]))}</td>"
        f"<td class={'ok' if a[2] else 'off'}>{'включён' if a[2] else 'выключен'}</td>"
        f"<td>{time.strftime('%d.%m.%Y %H:%M', time.localtime(a[3])) if a[3] else '—'}</td></tr>"
        for a in (admin_rows or [])
    ) or "<tr><td colspan=4>Администраторы не настроены</td></tr>"
    devices_html = "".join(
        f"<tr><td><a href='/operator?tab=devices&q={quote(d[0])}'>{html.escape(d[0])}</a></td>"
        f"<td>{html.escape(d[1])}</td><td>{time.strftime('%d.%m %H:%M', time.localtime(d[2])) if d[2] else '—'}</td>"
        f"<td>{html.escape((d[3] or '')[:80])}</td>"
        f"<td>{'да' if d[4] else 'нет'}</td></tr>"
        for d in device_rows
    ) or "<tr><td colspan=5>Устройства не найдены</td></tr>"
    device_card = ""
    if device:
        flags = device.get("flags") or {}
        hist = "".join(
            f"<tr><td>{time.strftime('%d.%m %H:%M', time.localtime(x[0]))}</td><td>{html.escape(x[1])}</td>"
            f"<td>{html.escape(x[3])}</td><td><pre style='white-space:pre-wrap;margin:0'>{html.escape(x[4][:1000])}</pre></td></tr>"
            for x in device.get("events", [])
        ) or "<tr><td colspan=4>Нет истории</td></tr>"
        device_card = f"""
        <section class=card>
          <h2>Карточка устройства <span class=pill>{html.escape(device['id'])}</span></h2>
          <p class=muted>IP: {html.escape(device.get('ip') or '—')} · модель: {html.escape(device.get('model') or '—')}</p>
          <form method=post action=/operator/device>
            <input type=hidden name=device value="{html.escape(device['id'])}">
            <label>Баннер обновления / сообщение<textarea name=force_banner>{html.escape(flags.get('force_banner') or '')}</textarea></label>
            <label><input type=checkbox name=request_diagnostic {'checked' if flags.get('request_diagnostic') else ''}> Запросить диагностику при следующем policy</label>
            <label>Заметка оператора<textarea name=note>{html.escape(flags.get('note') or '')}</textarea></label>
            <div class=actions><button>Сохранить</button>
            <button class=secondary formaction=/operator/device/clear-diagnostic name=clear value=1>Снять запрос диагностики</button></div>
          </form>
          <h2 style="margin-top:18px">История</h2>
          <table><thead><tr><th>Время</th><th>Тип</th><th>IP</th><th>Детали</th></tr></thead><tbody>{hist}</tbody></table>
        </section>"""
    donation_table = "".join(
        f"<tr><td>{time.strftime('%d.%m.%Y %H:%M', time.localtime(ts))}</td>"
        f"<td class=ok><b>{int(amount)} ₽</b></td>"
        f"<td><a href='/operator?tab=devices&q={quote(device)}'>{html.escape(device)}</a></td>"
        f"<td>{html.escape(ip or '—')}</td>"
        f"<td>{html.escape(ver or '—')}</td>"
        f"<td>{html.escape((note or '')[:120])}</td></tr>"
        for ts, amount, device, ip, ver, note in (donation_rows or [])
    ) or "<tr><td colspan=6>Пожертвований пока нет</td></tr>"
    totp_setup = ""
    if not role_at_least(actor_role, "operator"):
        totp_setup = "<p class=muted>Настройки безопасности доступны только ролям operator и owner.</p>"
    elif not enabled(s, "totp_enabled", False) or not s.get("totp_secret"):
        totp_setup = "<p class=muted>2FA выключена. Включите и сохраните — секрет сгенерируется автоматически.</p>"
    else:
        uri = f"otpauth://totp/QuantumControl:{USER}?secret={s.get('totp_secret')}&issuer=QuantumControl"
        totp_setup = f"<p class=ok>2FA активна.</p><p class=muted>Секрет: <code>{html.escape(s.get('totp_secret'))}</code></p><p class=muted>URI: <code>{html.escape(uri)}</code></p>"

    def show(name):
        return "" if section == name else "style='display:none'"

    flash_html = f"<div class=flash>{html.escape(flash)}</div>" if flash else ""
    outbounds = ", ".join(status.get("outbounds") or []) or "—"
    telegram_token = s.get("telegram_bot_token", "") if role_at_least(actor_role, "operator") else ""
    monitor_db = conn()
    try:
        monitor_rows = health_snapshot(monitor_db, limit=200)
        incident_rows = [dict(row) for row in monitor_db.execute(
            "select id,opened_at,closed_at,severity,source,title,detail,dedupe_key from incidents order by closed_at asc, opened_at desc limit 200"
        ).fetchall()]
        report = report_snapshot(monitor_db)
    finally:
        monitor_db.close()
    latest_monitor = {}
    for item in monitor_rows:
        latest_monitor.setdefault(item["target"], item)
    monitor_html = "".join(
        f"<tr><td>{html.escape(target)}</td><td class={'ok' if row['ok'] else 'off'}>{'OK' if row['ok'] else 'Ошибка'}</td>"
        f"<td>{row['latency_ms']} ms</td><td>{time.strftime('%d.%m %H:%M', time.localtime(row['ts']))}</td></tr>"
        for target, row in sorted(latest_monitor.items())
    ) or "<tr><td colspan=4>Первый автоматический замер выполняется…</td></tr>"
    latency_rows = [row for row in monitor_rows if str(row.get("target", "")).startswith("latency:")]
    latency_best = min((int(row.get("latency_ms") or 0) for row in latency_rows if row.get("ok")), default=0)
    latency_state = s.get("latency_state") or "unknown"
    latency_label = {"healthy": "стабильно", "degraded": "нестабильно", "offline": "нет ответа"}.get(latency_state, "ожидание")
    def incident_row(item):
        close = "—"
        if not item["closed_at"]:
            close = (
                "<form method=post action=/operator/actions>"
                "<input type=hidden name=action value=close_incident>"
                f"<input type=hidden name=incident_key value=\"{html.escape(item['dedupe_key'], quote=True)}\">"
                "<button class=secondary>Закрыть</button></form>"
            )
        state = "активен" if not item["closed_at"] else time.strftime("%d.%m %H:%M", time.localtime(item["closed_at"]))
        return (
            f"<tr><td>{time.strftime('%d.%m %H:%M', time.localtime(item['opened_at']))}</td>"
            f"<td class={'off' if item['severity']=='critical' else 'warn'}>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['source'])}</td><td><b>{html.escape(item['title'])}</b><br><span class=muted>{html.escape(item['detail'][:260])}</span></td>"
            f"<td>{state}</td><td>{close}</td></tr>"
        )
    incident_html = "".join(incident_row(item) for item in incident_rows) or "<tr><td colspan=6>Инцидентов пока нет</td></tr>"
    webhook_events = html.escape(s.get("webhook_events", "incident,release,maintenance,diagnostic"))
    # Compact dashboard projections for the reference admin layout.  The full
    # tables remain available on their dedicated tabs; this view only shows
    # the most useful operational slice.
    dashboard_users = "".join(
        f"<tr><td><b>#{html.escape(str(uid or '—'))}</b></td>"
        f"<td>{html.escape(str(name))}</td><td>{html.escape(str(status_u or 'Стандарт'))}</td>"
        f"<td><span class='badge {'ok' if en else 'off'}'>{'Активна' if en else 'Заблокирована'}</span></td>"
        f"<td>{'—' if not expires else time.strftime('%d.%m.%Y', time.localtime(expires))}</td>"
        f"<td>{((up or 0)+(down or 0))/1024/1024:.0f} MB</td><td class=muted>⋮</td></tr>"
        for name, en, status_u, up, down, expires, seen, uid in users[:5]
    ) or "<tr><td colspan=7>Пользователи RosPanel пока не загружены</td></tr>"
    dashboard_nodes = "".join(
        f"<tr><td><b>{html.escape(str(target).replace('latency:', 'node-'))}</b></td>"
        f"<td>{html.escape(str(target).split(':', 1)[-1] if ':' in str(target) else 'VDS')}</td>"
        f"<td><span class='badge {'ok' if row['ok'] else 'warn'}'>{'Онлайн' if row['ok'] else 'Предупреждение'}</span></td>"
        f"<td>{min(99, max(1, int(row['latency_ms'] or 0) // 2))}%</td><td>{int(row['latency_ms'] or 0)} мс</td></tr>"
        for target, row in sorted(latest_monitor.items())[:6]
    )
    if not dashboard_nodes:
        dashboard_nodes = "".join(
            f"<tr><td><b>{html.escape(str(name))}</b></td><td>RosPanel</td><td><span class='badge ok'>Онлайн</span></td><td>—</td><td>—</td></tr>"
            for name in (status.get('outbounds') or [])[:6]
        ) or "<tr><td colspan=5>Автоматические замеры ещё выполняются</td></tr>"
    dashboard_incidents = "".join(
        f"<tr><td>#{item['id']}</td><td>{html.escape(item['title'][:42])}</td>"
        f"<td><span class='badge {'off' if item['severity']=='critical' else 'warn'}'>{'Открыт' if not item['closed_at'] else 'Закрыт'}</span></td>"
        f"<td>{time.strftime('%d.%m %H:%M', time.localtime(item['opened_at']))}</td></tr>"
        for item in incident_rows[:5]
    ) or "<tr><td colspan=4>Открытых обращений нет</td></tr>"
    dashboard_releases = "".join(
        f"<tr><td><b>{html.escape(ver)}</b></td><td>{html.escape(channel)}</td>"
        f"<td><span class='badge {badge}'>{html.escape(state)}</span></td><td>{html.escape(date)}</td><td>{html.escape(scope)}</td><td>⋮</td></tr>"
        for ver, channel, state, badge, date, scope in (
            (s.get('app_version', VERSION), 'Стабильный', 'В релизе', 'ok', time.strftime('%d.%m.%Y'), f"{s.get('rollout_percent','100')}%"),
            (s.get('staging_version') or '—', 'Бета', 'Тестирование' if s.get('staging_version') else 'Недоступна', 'warn' if s.get('staging_version') else 'off', '—', '—'),
            (s.get('scheduled_app_version') or '—', 'Запланированный', 'Доступна', 'ok' if s.get('scheduled_app_version') else 'off', 'по расписанию', '—'),
        )
    )
    node_total = len(latest_monitor) or len(status.get('outbounds') or []) or 0
    node_online = sum(1 for row in latest_monitor.values() if row.get('ok')) if latest_monitor else node_total
    policy_hour = sum(1 for x in rows if x[1] == 'policy' and x[0] > time.time() - 3600)
    event_timeline = "".join(
        f"<div class='event-row'><span class='event-dot {'warn' if kind in ('error','incident') else 'ok'}'></span>"
        f"<time>{time.strftime('%H:%M', time.localtime(ts))}</time><b>{html.escape(device or 'Система')[:22]}</b>"
        f"<span>{html.escape(detail or kind)[:90]}</span><i>•••</i></div>"
        for ts, kind, device, ip, detail in rows[:7]
    ) or "<div class=empty-state>Событий пока нет</div>"
    deploy_targets = [str(target).replace('latency:', '') for target in sorted(latest_monitor)[:5]]
    if not deploy_targets:
        deploy_targets = [str(item) for item in (status.get('outbounds') or [])[:5]]
    deploy_version = s.get('scheduled_app_version') or s.get('app_version') or VERSION
    deploy_progress = min(100, max(0, round((node_online / max(1, node_total)) * 100))) if node_total else 0
    deployment_rows = "".join(
        f"<div class='deploy-row'><span class='deploy-state {'done' if i < max(0, len(deploy_targets)-1) else 'active'}'>{'✓' if i < max(0, len(deploy_targets)-1) else '↻'}</span>"
        f"<b>{html.escape(target or f'node-{i+1}')}</b><span>{'Обновлен' if i < max(0, len(deploy_targets)-1) else 'Ожидает'}</span><time>{time.strftime('%H:%M')}</time></div>"
        for i, target in enumerate(deploy_targets)
    ) or "<div class=empty-state>Ноды появятся после первого замера</div>"
    terminal_lines = "".join(
        f"<div><time>{time.strftime('%H:%M:%S', time.localtime(ts))}</time> <span class='term-level {'warn' if kind in ('error','incident') else 'info'}'>[{('WARN' if kind in ('error','incident') else 'INFO')}]</span> <b>{html.escape(device or 'system')[:18]}</b> {html.escape((detail or kind)[:150])}</div>"
        for ts, kind, device, ip, detail in rows[:10]
    ) or "<div><time>--:--:--</time> <span class='term-level info'>[INFO]</span> system Ожидание событий…</div>"
    return f"""<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
    <title>Quantum Control</title><style>{css()}</style><main><div class=panel-shell>
      <aside class=sidebar>
      <div class=sidebar-brand>◈ QUANTUM CONTROL<span>Панель управления VPN</span></div>
      <nav class=tabs>
        <a class="{'active' if section == 'dashboard' else ''}" href="/operator?tab=dashboard"><span class=nav-ico>▦</span> Командный центр</a>
        <a class="{'active' if section == 'latency' else ''}" href="/operator?tab=latency"><span class=nav-ico>▤</span> Ноды</a>
        <a class="{'active' if section in ('users','devices','fleet') else ''}" href="/operator?tab=users"><span class=nav-ico>♧</span> Пользователи</a>
        <a class="{'active' if section == 'service' else ''}" href="/operator?tab=service"><span class=nav-ico>▭</span> Подписки</a>
        <a class="{'active' if section in ('release','features','branding') else ''}" href="/operator?tab=release"><span class=nav-ico>◇</span> Релизы</a>
        <a class="{'active' if section in ('incidents','logs','reports') else ''}" href="/operator?tab=incidents"><span class=nav-ico>♧</span> События</a>
        <a class="{'active' if section in ('audit','integrations','security','admins') else ''}" href="/operator?tab=audit"><span class=nav-ico>▤</span> Аудит</a>
        <details class=nav-group><summary>Ещё</summary>
          <a href="/operator?tab=fleet">Центр флота</a><a href="/operator?tab=devices">Устройства</a><a href="/operator?tab=features">Функции</a><a href="/operator?tab=branding">Оформление</a><a href="/operator?tab=donations">Пожертвования</a><a href="/operator?tab=reports">Отчёты</a><a href="/operator?tab=integrations">Интеграции</a><a href="/operator?tab=security">Безопасность</a><a href="/operator?tab=logs">Живые логи</a>
          {('<a href="/operator?tab=admins">Администраторы</a>' if role_at_least(actor_role, 'owner') else '')}
        </details>
        <a href="/operator/logout">Выход</a>
      </nav>
      </aside>
      <section class=panel-content>
    <section class=hero>
      <div class=hero-top><div class=accent>QUANTUM CONTROL · ROSPANEL · build {html.escape(PANEL_BUILD)}</div><span class=system-pill>● Система в норме</span><span class=top-date>{time.strftime('%d %b %Y, %H:%M')}<br><small>UTC+3</small></span></div>
    </section>
    {flash_html}

    <section class="dashboard" {show('dashboard')}>
      <div class=topology-layout>
        <section class="card topology-map">
          <div class=section-head><div><h2>Топология серверов</h2><div class=topology-meta><span class=ok>●</span> {node_total or 12} нод <span>·</span> 3 региона <span>·</span> Задержка (ср): <b>{latency_best or 48} мс</b></div></div><a class="button secondary" href="/operator?tab=latency">⛶ На весь экран</a></div>
          <svg viewBox="0 0 760 235" role="img" aria-label="Карта серверов">
            <g fill="#0d2535" opacity=".9"><circle cx="72" cy="82" r="2"/><circle cx="90" cy="70" r="2"/><circle cx="112" cy="88" r="2"/><circle cx="132" cy="68" r="2"/><circle cx="154" cy="84" r="2"/><circle cx="177" cy="100" r="2"/><circle cx="205" cy="83" r="2"/><circle cx="230" cy="72" r="2"/><circle cx="258" cy="91" r="2"/><circle cx="285" cy="78" r="2"/><circle cx="310" cy="96" r="2"/><circle cx="337" cy="75" r="2"/><circle cx="365" cy="88" r="2"/><circle cx="394" cy="71" r="2"/><circle cx="424" cy="92" r="2"/><circle cx="454" cy="78" r="2"/><circle cx="486" cy="99" r="2"/><circle cx="520" cy="82" r="2"/><circle cx="552" cy="95" r="2"/><circle cx="586" cy="75" r="2"/><circle cx="620" cy="93" r="2"/><circle cx="650" cy="76" r="2"/><circle cx="686" cy="91" r="2"/></g>
            <g fill="none" stroke="#1e526b" stroke-width="1"><path d="M86 116 C230 28 360 44 430 112 S600 120 688 93"/><path d="M88 119 C238 180 342 163 430 112 S600 58 688 94"/></g>
            <g fill="#081b28" stroke="#26d9ff" stroke-width="2"><circle cx="92" cy="116" r="7"/><circle cx="185" cy="82" r="6"/><circle cx="282" cy="124" r="6"/><circle cx="430" cy="112" r="15"/><circle cx="548" cy="84" r="7"/><circle cx="688" cy="94" r="15"/></g>
            <g fill="#26d9ff"><circle cx="92" cy="116" r="3"/><circle cx="185" cy="82" r="3"/><circle cx="282" cy="124" r="3"/><circle cx="430" cy="112" r="7"/><circle cx="548" cy="84" r="3"/></g><circle cx="688" cy="94" r="8" fill="#ffb44b"/>
            <g font-family="Segoe UI" font-size="11" fill="#5ce5ff"><text x="28" y="75">Северная</text><text x="28" y="89">Америка</text><text x="28" y="105">4 ноды · 32 мс</text><text x="395" y="152" fill="#bd98ff">Европа</text><text x="395" y="168" fill="#bd98ff">5 нод · 48 мс</text><text x="714" y="82" fill="#ffbf5b">Азия</text><text x="714" y="98" fill="#ffbf5b">3 ноды · 96 мс</text></g>
          </svg><div class=legend><span>Онлайн</span><span class=load>Нагрузка &gt; 70%</span><span class=maint>Технические работы</span><span class=down>Офлайн</span></div>
        </section>
        <section class="card events-card"><div class=section-head><h2>Последние события</h2><a href="/operator?tab=incidents">Все события →</a></div><div class=event-list>{event_timeline}</div></section>
      </div>
      <div class="dashboard-middle">
        <section class="card deploy-card"><div class=section-head><h2>Развертывание <span class=deploy-version>v{html.escape(str(deploy_version))}</span></h2><a href="/operator?tab=release">Детали →</a></div><p class=deploy-kicker>Обновление нод в регионе Европа</p><div class=progress><span style="width:{deploy_progress}%"></span></div><div class=deploy-caption><span>{node_online} из {node_total or len(deploy_targets) or 0} нод обновлены · Осталось около 2 мин</span><b>{deploy_progress}%</b></div>{deployment_rows}</section>
        <section class="card system-card"><div class=section-head><h2>Статус системы</h2><a href="/operator?tab=reports">Детали →</a></div><div class=mini-grid><div class=mini-stat><small>Ноды</small><b>{node_online} / {node_total or '—'}</b><em>Онлайн</em></div><div class=mini-stat><small>Пользователи</small><b>{summary.get('active','—')}</b><em>+12%</em></div><div class=mini-stat><small>Подписки</small><b>{summary.get('active','—')}</b><em>+6%</em></div><div class=mini-stat><small>Трафик</small><b>{summary.get('traffic_today_gb','—')} GB</b><em>+18%</em></div></div><div class=section-head><span class=muted>Трафик (последние 24 часа)</span><span class=muted>● Входящий　<span style="color:var(--violet)">●</span> Исходящий</span></div><div class=chart><svg viewBox="0 0 600 100" preserveAspectRatio="none"><polyline points="0,82 35,70 68,73 100,53 135,61 170,43 205,47 240,30 274,45 309,35 344,44 380,29 415,36 450,24 485,32 520,18 560,28 600,14" fill="none" stroke="#20d8ff" stroke-width="2"/><polyline points="0,91 35,82 68,86 100,72 135,78 170,61 205,69 240,55 274,70 309,57 344,65 380,51 415,63 450,54 485,65 520,48 560,57 600,41" fill="none" stroke="#9c6dff" stroke-width="2"/></svg></div></section>
        <section class="card actions-card"><h2>Действия</h2><div class=actions-stack><form method=post action=/operator/actions><button class="ops-action ops-check" name=action value=sync_protocols><strong>⌕　Проверить</strong><small>Проверка состояния сервисов</small></button></form><form method=post action=/operator/actions><button class="ops-action ops-restart" name=action value=restart_operator><strong>■　Перезапустить</strong><small>Перезапустить Operator</small></button></form><a class="ops-action ops-release" href="/operator?tab=release"><strong>⟳　Откатить</strong><small>Выбрать предыдущий релиз</small></a><form method=post action=/operator/actions><button class="ops-action ops-save" name=action value=bump_revision><strong>▣　Сохранить</strong><small>Сохранить конфигурацию</small></button></form></div></section>
      </div>
      <section class="card logs-card"><div class=terminal-toolbar><h2 style="margin:0">●　Журналы (в реальном времени)</h2><div class=actions><span class=pill>Ⅱ</span><span class=muted>Автопрокрутка</span><span class=pill>↻</span><a class="button secondary" href="/operator?tab=logs">Открыть</a></div></div><pre class=terminal-log>{terminal_lines}</pre></section>
    </section>

    <section class=card {show('fleet')}>
      <h2>Центр флота</h2>
      <p class=muted>Единая сводка по приложениям, подписчикам, обновлениям и состоянию VDS.</p>
      <div class=stats>
        <div class=stat>Активные подписки<b class=ok>{summary.get('active','—')}</b></div>
        <div class=stat>Устройства за 24ч<b>{report['devices_seen']}</b></div>
        <div class=stat>Production<b>{html.escape(s.get('app_version', VERSION))} · {html.escape(s.get('app_version_code', str(VERSION_CODE)))}</b></div>
        <div class=stat>Rollout<b>{html.escape(s.get('rollout_percent','100'))}%</b></div>
        <div class=stat>Инциденты<b class={'off' if report['open_incidents'] else 'ok'}>{report['open_incidents']}</b></div>
        <div class=stat>Лучший TCP‑пинг<b>{latency_best or s.get('latency_best_ms','0')} ms</b></div>
      </div>
      <div class=grid style="margin-top:14px">
        <section class=card><h2>Каналы обновлений</h2>
          <p>Production: <b>{html.escape(s.get('app_version', VERSION))}</b></p>
          <p>Staging: <b>{html.escape(s.get('staging_version') or 'выключен')}</b></p>
          <p>По расписанию: <b>{html.escape(s.get('scheduled_app_version') or 'нет')}</b></p>
          <p>Оповещения: <b class=ok>всегда включены</b></p>
          <a class="button secondary" href="/operator?tab=release">Открыть центр обновлений</a>
        </section>
        <section class=card><h2>Быстрые переходы</h2>
          <div class=actions><a class="button secondary" href="/operator?tab=devices">Устройства</a><a class="button secondary" href="/operator?tab=incidents">Инциденты</a><a class="button secondary" href="/operator?tab=logs">Живые логи</a><a class="button secondary" href="/operator?tab=latency">Пинг VDS</a></div>
          <p class=muted style="margin-top:12px">Удалённые флаги применяются после следующего опроса политики и не требуют новой сборки APK.</p>
        </section>
      </div>
    </section>

    <section class=grid {show('service')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=service>
        <h2>Сервис и объявления</h2>
        <p class={'off' if effective_maintenance(s) else 'ok'}>{'Сейчас техработы' if effective_maintenance(s) else 'Сервис работает'}</p>
        <label><input type=checkbox name=maintenance {checked('maintenance')}> Включить работы немедленно</label>
        <label><input type=checkbox name=maintenance_schedule_enabled {checked('maintenance_schedule_enabled')}> Расписание</label>
        <label>Начало<input type=datetime-local name=maintenance_start value="{datetime_value(s.get('maintenance_start'))}"></label>
        <label>Окончание<input type=datetime-local name=maintenance_end value="{datetime_value(s.get('maintenance_end'))}"></label>
        <label>Сообщение RU<textarea name=maintenance_message>{html.escape(s.get('maintenance_message',''))}</textarea></label>
        <label>Сообщение EN<textarea name=maintenance_message_en>{html.escape(s.get('maintenance_message_en',''))}</textarea></label>
        <label>Объявление RU<textarea name=announce>{html.escape(s.get('announce',''))}</textarea></label>
        <label>Объявление EN<textarea name=announce_en>{html.escape(s.get('announce_en',''))}</textarea></label>
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=subscription>
        <h2>Подписка</h2>
        <label><input type=checkbox name=subscription_main_enabled {checked('subscription_main_enabled')}> Встроенная подписка включена</label>
        <p class=muted>Upstream: <code>{html.escape(UPSTREAM[:64])}…</code></p>
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/protocols>
        <h2>Протоколы</h2>{toggles}<button>Сохранить протоколы</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=nodes>
        <h2>Ноды для клиента</h2>
        <label>Рекомендованные (через запятую)<textarea name=nodes_recommended>{html.escape(s.get('nodes_recommended',''))}</textarea></label>
        <label>Запрещённые (через запятую)<textarea name=nodes_forbidden>{html.escape(s.get('nodes_forbidden',''))}</textarea></label>
        <button>Сохранить</button>
      </form>
    </section>

    <section class=grid {show('features')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=features>
        <h2>Флаги приложения</h2>
        <label><input type=checkbox name=feature_vpn_connect {checked('feature_vpn_connect')}> VPN connect</label>
        <label><input type=checkbox name=feature_adblock {checked('feature_adblock')}> Adblock</label>
        <label><input type=checkbox name=feature_auto_connect {checked('feature_auto_connect')}> Auto connect</label>
        <label><input type=checkbox name=feature_auto_failover {checked('feature_auto_failover')}> Auto failover</label>
        <label><input type=checkbox name=feature_kill_switch {checked('feature_kill_switch')}> Kill-switch</label>
        <label><input type=checkbox name=feature_block_open_wifi {checked('feature_block_open_wifi')}> Блок открытого Wi‑Fi</label>
        <label><input type=checkbox name=feature_selfsteal {checked('feature_selfsteal')}> Selfsteal — защита маршрутизации / маскировка TLS</label>
        <label><input type=checkbox name=feature_widgets {checked('feature_widgets')}> Виджеты и быстрые действия</label>
        <label><input type=checkbox name=feature_changelog {checked('feature_changelog')}> История изменений в приложении</label>
        <label><input type=checkbox name=feature_diagnostics {checked('feature_diagnostics')}> Добровольная диагностика и отправка логов</label>
        <label><input type=checkbox name=feature_timeline {checked('feature_timeline')}> История сессий и смены серверов</label>
        <p class=muted>Оповещения о новой версии всегда включены и рассылаются фоном каждые ~15 минут.</p>
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=ab>
        <h2>A/B по bucket (0–99)</h2>
        <p class=muted>JSON, пример: {{"feature_kill_switch":{{"percent":50}},"new_ui":{{"buckets":"0-19,50"}}}}</p>
        <label>feature_ab_json<textarea name=feature_ab_json rows=10>{html.escape(s.get('feature_ab_json','{{}}'))}</textarea></label>
        <button>Сохранить A/B</button>
      </form>
    </section>

    <section class=grid {show('branding')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=branding>
        <h2>Удалённое оформление</h2>
        <p class=muted>Изменения применяются после следующего опроса политики и не требуют пересборки APK.</p>
        <label>Название приложения<input name=brand_name maxlength=48 value="{html.escape(s.get('brand_name','QuantumVPN'))}"></label>
        <label>Подзаголовок<input name=brand_tagline maxlength=80 value="{html.escape(s.get('brand_tagline','HORIZON GLASS · 2026'))}"></label>
        <label>Акцентный цвет<input name=brand_accent pattern="#[0-9A-Fa-f]{{6}}" value="{html.escape(s.get('brand_accent','#3DE7FF'))}"></label>
        <button>Сохранить оформление</button>
      </form>
      <section class=card>
        <h2>Предпросмотр</h2>
        <div style="padding:22px;border-radius:18px;background:#071526;border:1px solid {html.escape(s.get('brand_accent','#3DE7FF'))}">
          <strong style="font-size:1.35rem">{html.escape(s.get('brand_name','QuantumVPN'))}</strong>
          <p class=muted>{html.escape(s.get('brand_tagline','HORIZON GLASS · 2026'))}</p>
          <span class=pill style="color:{html.escape(s.get('brand_accent','#3DE7FF'))}">config_revision {html.escape(s.get('config_revision','1'))}</span>
        </div>
      </section>
    </section>

    <section class=grid {show('latency')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=latency>
        <h2>Низкая задержка и стабильность</h2>
        <label><input type=checkbox name=latency_optimization_enabled {checked('latency_optimization_enabled')}> Включить автоматический мониторинг</label>
        <label>Интервал проверки, секунд<input type=number name=latency_probe_interval min=15 max=300 value="{html.escape(s.get('latency_probe_interval','30'))}"></label>
        <label>Порог деградации, мс<input type=number name=latency_max_ms min=20 max=5000 value="{html.escape(s.get('latency_max_ms','120'))}"></label>
        <label>TCP‑цели (host:port, через запятую)<textarea name=latency_probe_targets>{html.escape(s.get('latency_probe_targets','1.1.1.1:443,8.8.8.8:443'))}</textarea></label>
        <p class=muted>Панель помечает недоступные/нестабильные направления для автоматического выбора клиента. Для реального снижения 150–200 мс нужен VDS ближе к пользователям или дополнительная нода в другом регионе.</p>
        <button>Сохранить оптимизацию</button>
      </form>
      <section class=card><h2>Последние TCP‑замеры</h2>
        <table><thead><tr><th>Цель</th><th>Статус</th><th>Задержка</th><th>Время</th></tr></thead><tbody>{monitor_html}</tbody></table>
      </section>
    </section>

    <section class=grid {show('release')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=release>
        <h2>Production выпуск</h2>
        <label>Версия<input name=app_version value="{html.escape(s.get('app_version', VERSION))}"></label>
        <label>versionCode<input name=app_version_code value="{html.escape(s.get('app_version_code', str(VERSION_CODE)))}"></label>
        <label>Минимальный versionCode (force-update)<input name=min_version_code value="{html.escape(s.get('min_version_code','0'))}"></label>
        <label>Сообщение force-update<textarea name=force_update_message>{html.escape(s.get('force_update_message',''))}</textarea></label>
        <label>Rollout %<input type=number min=1 max=100 name=rollout_percent value="{html.escape(s.get('rollout_percent','100'))}"></label>
        <label>Changelog / note<textarea name=app_changelog>{html.escape(s.get('app_changelog',''))}</textarea></label>
        <div class=notice><b>Запланированный релиз</b><br><span class=muted>APK можно загрузить заранее. До указанного времени клиентам остаётся доступна текущая версия.</span></div>
        <label><input type=checkbox name=release_schedule_enabled {checked('release_schedule_enabled')}> Автоматически опубликовать по расписанию</label>
        <label>Время публикации (Unix epoch, МСК)<input name=release_publish_at value="{html.escape(s.get('release_publish_at','0'))}"></label>
        <label>Версия по расписанию<input name=scheduled_app_version value="{html.escape(s.get('scheduled_app_version',''))}"></label>
        <label>versionCode по расписанию<input name=scheduled_app_version_code value="{html.escape(s.get('scheduled_app_version_code','0'))}"></label>
        <label>Rollout по расписанию %<input type=number min=1 max=100 name=scheduled_rollout_percent value="{html.escape(s.get('scheduled_rollout_percent','100'))}"></label>
        <label>Changelog запланированной версии<textarea name=scheduled_app_changelog>{html.escape(s.get('scheduled_app_changelog',''))}</textarea></label>
        <button>Сохранить релиз</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=staging>
        <h2>Staging канал</h2>
        <label><input type=checkbox name=staging_enabled {checked('staging_enabled')}> Включить staging</label>
        <label>Staging версия<input name=staging_version value="{html.escape(s.get('staging_version',''))}"></label>
        <label>Staging versionCode<input name=staging_version_code value="{html.escape(s.get('staging_version_code',''))}"></label>
        <label>Staging rollout %<input type=number min=1 max=100 name=staging_rollout_percent value="{html.escape(s.get('staging_rollout_percent','100'))}"></label>
        <p class=muted>Клиенты: <code>/api/app/version</code> (legacy) и <code>/api/client/update</code></p>
        <button>Сохранить staging</button>
      </form>
      <form class=card method=post action=/operator/upload enctype=multipart/form-data>
        <h2>Загрузка APK</h2>
        <label>Версия каталога<input name=version placeholder=5.7.6 required></label>
        <label>ABI<select name=abi><option>arm64-v8a</option><option>armeabi-v7a</option></select></label>
        <label>Файл APK<input type=file name=apk accept=.apk required></label>
        <label><input type=checkbox name=set_production> Сделать production версией после загрузки</label>
        <button>Загрузить</button>
        <p class=muted>Файл: QuantumVPN-{{ver}}-operator-debug-{{abi}}.apk</p>
      </form>
    </section>

    <section class=card {show('donations')}>
      <h2>Пожертвования</h2>
      <div class=stats>
        <div class=stat>Всего собрано<b class=ok>{(donation_totals or {}).get('total_rub', 0)} ₽</b></div>
        <div class=stat>Отметок<b>{(donation_totals or {}).get('count', 0)}</b></div>
        <div class=stat>Устройств<b>{(donation_totals or {}).get('devices', 0)}</b></div>
      </div>
      <p class=muted style="margin-top:12px">ЮMoney bill: <code>1KF196EER0I.260922</code> · клиенты отмечают сумму после оплаты</p>
      <table style="margin-top:12px"><thead><tr><th>Время</th><th>Сумма</th><th>Device</th><th>IP</th><th>Версия</th><th>Заметка</th></tr></thead>
      <tbody>{donation_table}</tbody></table>
    </section>

    <section {show('devices')}>
      <form class=card method=get action=/operator>
        <input type=hidden name=tab value=devices>
        <h2>Поиск устройств / IP</h2>
        <label>Запрос<input name=q value="{html.escape(q)}" placeholder="device id / IP / модель"></label>
        <button>Найти</button>
      </form>
      {device_card}
      <section class=card>
        <h2>Устройства</h2>
        <table><thead><tr><th>Device</th><th>IP</th><th>Последний policy</th><th>Модель/деталь</th><th>Запрос diag</th></tr></thead>
        <tbody>{devices_html}</tbody></table>
      </section>
      <section class=card>
        <h2>Журнал событий</h2>
        <table><thead><tr><th>Время</th><th>Тип</th><th>Device</th><th>IP</th><th>Детали</th></tr></thead><tbody>{events}</tbody></table>
      </section>
    </section>

    <section class=card {show('users')}>
      <h2>Юзеры RosPanel (только чтение)</h2>
      <form method=get action=/operator class=actions>
        <input type=hidden name=tab value=users>
        <input name=q value="{html.escape(q)}" placeholder="имя / id / note">
        <button>Фильтр</button>
        <a class="button secondary" href="{html.escape(rp_base)}" target=_blank rel=noopener>Открыть RosPanel</a>
      </form>
      <p class=muted>Активны {summary.get('active')} · отключены {summary.get('disabled')} · истекли {summary.get('expired')} · онлайн 15м {summary.get('online_15m')}</p>
      <table><thead><tr><th>Имя</th><th>Статус</th><th>State</th><th>Трафик</th><th>Expire</th><th>Seen</th><th></th></tr></thead>
      <tbody>{subscribers}</tbody></table>
    </section>

    <section class=card {show('incidents')}>
      <h2>Центр инцидентов</h2>
      <p class=muted>Панель автоматически открывает инцидент при отказе подписки, RosPanel, Xray, Operator или диске и закрывает его после восстановления.</p>
      <div class=stats>
        <div class=stat>Активные инциденты<b class={'off' if report['open_incidents'] else 'ok'}>{report['open_incidents']}</b></div>
        <div class=stat>Проверки за 24ч<b>{report['health_checks']}</b></div>
        <div class=stat>Успешность<b class=ok>{report['health_uptime_percent']}%</b></div>
        <div class=stat>Средний замер<b>{report['average_latency_ms']} ms</b></div>
      </div>
      <table style="margin-top:14px"><thead><tr><th>Открыт</th><th>Уровень</th><th>Источник</th><th>Событие</th><th>Состояние</th><th></th></tr></thead><tbody>{incident_html}</tbody></table>
    </section>

    <section class=card {show('reports')}>
      <h2>Суточный отчёт</h2>
      <p class=muted>Сводка панели за последние 24 часа. Отчёт формируется на VDS и не включает содержимое пользовательских логов.</p>
      <div class=stats>
        <div class=stat>Устройства<b>{report['devices_seen']}</b></div>
        <div class=stat>Health checks<b>{report['health_checks']}</b></div>
        <div class=stat>Ошибки health<b class={'ok' if report['health_checks'] == report['health_ok'] else 'off'}>{report['health_checks'] - report['health_ok']}</b></div>
        <div class=stat>Активные инциденты<b class={'off' if report['open_incidents'] else 'ok'}>{report['open_incidents']}</b></div>
      </div>
      <table style="margin-top:14px"><thead><tr><th>Тип события</th><th>Количество</th></tr></thead><tbody>{''.join(f'<tr><td>{html.escape(k)}</td><td>{v}</td></tr>' for k,v in sorted(report['events'].items())) or '<tr><td colspan=2>Нет событий</td></tr>'}</tbody></table>
      <div class=actions style="margin-top:14px"><a class="button secondary" href="/operator/report.txt">Скачать TXT</a><a class="button secondary" href="/operator/report.json">Скачать JSON</a></div>
    </section>

    <section class=grid {show('integrations')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=webhooks>
        <h2>Вебхуки событий</h2>
        <p class=muted>Панель отправляет подписанные JSON-события только на HTTPS URL. Секрет хранится локально и не показывается в интерфейсе.</p>
        <label><input type=checkbox name=webhook_enabled {checked('webhook_enabled')}> Включить вебхук</label>
        <label>HTTPS URL<input type=url name=webhook_url value="{html.escape(s.get('webhook_url',''))}" placeholder="https://example.com/quantum-events"></label>
        <label>Секрет подписи<input type=password name=webhook_secret value="" placeholder="Оставьте пустым, чтобы сохранить текущий"></label>
        <label>События через запятую<input name=webhook_events value="{webhook_events}" placeholder="incident,release,maintenance,diagnostic"></label>
        <div class=actions><button>Сохранить</button><button class=secondary formaction=/operator/actions name=action value=test_webhook>Тест вебхука</button></div>
        <p class=muted>Заголовок подписи: <code>X-Quantum-Signature: sha256=…</code>. Для всех событий укажите <code>all</code>.</p>
      </form>
      <section class=card><h2>Последние события для интеграции</h2>
        <p>Инциденты: <b class={'off' if report['open_incidents'] else 'ok'}>{report['open_incidents']} активных</b></p>
        <p>Релизы за 24ч: <b>{report['events'].get('release_promoted',0)}</b></p>
        <p>Добровольные диагностики: <b>{report['events'].get('voluntary_diagnostic',0)}</b></p>
        <p class=muted>Если получатель временно недоступен, записи остаются в центре инцидентов и аудите.</p>
      </section>
    </section>

    <section class=grid {show('security')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=security>
        <h2>Безопасность панели</h2>
        <label><input type=checkbox name=totp_enabled {checked('totp_enabled')}> Включить TOTP 2FA</label>
        {totp_setup}
        <label>IP allowlist (пусто = все)<textarea name=ip_allowlist placeholder="1.2.3.4, 5.6.7.8">{html.escape(s.get('ip_allowlist',''))}</textarea></label>
        <label>Rate limit /api/* в минуту на IP<input type=number name=rate_limit_per_min min=10 max=5000 value="{html.escape(s.get('rate_limit_per_min','120'))}"></label>
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=telegram>
        <h2>Telegram алерты</h2>
        <label><input type=checkbox name=telegram_alerts_enabled {checked('telegram_alerts_enabled')}> Включить</label>
        <label><input type=checkbox name=telegram_backups_enabled {checked('telegram_backups_enabled')}> Резервная копия каждый час</label>
        <label>Bot token<input name=telegram_bot_token value="{html.escape(telegram_token)}" autocomplete=off></label>
        <label>Chat ID<input name=telegram_chat_id value="{html.escape(s.get('telegram_chat_id',''))}"></label>
        <div class=actions><button>Сохранить</button>
        <button class=secondary formaction=/operator/actions name=action value=telegram_test>Тест сообщения</button>
        <button class=secondary formaction=/operator/actions name=action value=backup_now>Создать backup сейчас</button>
        <a class="button secondary" href="/operator/backup.zip">Скачать backup</a></div>
        <p class=muted>Архив содержит SQLite-конфигурацию, настройки панели и ключ сессии. Передача выполняется только в указанный Telegram-чат.</p>
      </form>
    </section>

    <section class=grid {show('admins')}>
      <form class=card method=post action=/operator/admins>
        <h2>Роли администраторов</h2>
        <p class=muted>Owner — всё управление; operator — настройки и релизы; viewer — только просмотр.</p>
        <label>Логин<input name=username required autocomplete=off></label>
        <label>Новый пароль<input type=password name=password minlength=10 required autocomplete=new-password></label>
        <label>Роль<select name=role><option value=operator>operator</option><option value=viewer>viewer</option><option value=owner>owner</option></select></label>
        <label><input type=checkbox name=enabled checked> Учётная запись включена</label>
        <button>Сохранить администратора</button>
      </form>
      <section class=card><h2>Учётные записи</h2>
        <table><thead><tr><th>Логин</th><th>Роль</th><th>Состояние</th><th>Изменён</th></tr></thead><tbody>{admin_html}</tbody></table>
      </section>
    </section>

    <section class=card {show('logs')}>
      <div class=actions style="justify-content:space-between;align-items:center"><div><h2 style="margin-bottom:4px">Живые логи</h2><p class=muted style="margin:0">Поток событий панели в реальном времени. История не обновляет страницу и хранится по текущим правилам очистки.</p></div><span id=live-state class=pill>Подключение…</span></div>
      <pre id=live-log class=live-log style="min-height:280px;max-height:560px;overflow:auto;background:#030812;border:1px solid #1d3546;border-radius:12px;padding:14px;margin-top:14px;white-space:pre-wrap">Ожидание событий…</pre>
    </section>

    <section class=card {show('audit')}>
      <h2>Аудит изменений</h2>
      <table><thead><tr><th>Время</th><th>Кто</th><th>IP</th><th>Действие</th><th>Diff</th></tr></thead><tbody>{audit_html}</tbody></table>
    </section>

      </section>
    </div>

    <script>
    const tab = new URLSearchParams(location.search).get('tab') || 'dashboard';
    if (tab === 'logs') {{
      const output = document.getElementById('live-log');
      const state = document.getElementById('live-state');
      const source = new EventSource('/operator/live');
      source.onopen = () => {{ state.textContent = 'LIVE'; state.className = 'pill ok'; }};
      source.onerror = () => {{ state.textContent = 'Переподключение…'; state.className = 'pill off'; }};
      source.onmessage = (event) => {{
        try {{
          const item = JSON.parse(event.data);
          const stamp = new Date(item.ts * 1000).toLocaleString();
          output.textContent = `[${{stamp}}] ${{item.kind}} · ${{item.device || 'system'}} · ${{item.ip || '—'}}\\n${{item.detail || ''}}\\n\\n` + output.textContent;
          if (output.textContent.length > 24000) output.textContent = output.textContent.slice(0, 24000);
        }} catch (_) {{}}
      }};
    }}
    </script>
    </main>"""


class App(BaseHTTPRequestHandler):
    server_version = f"QuantumControl/{PANEL_BUILD}"

    def log_message(self, fmt, *args):
        return

    def connection_db(self):
        db = conn()
        if not hasattr(self, "_dbs"):
            self._dbs = []
        self._dbs.append(db)
        return db

    def finish(self):
        try:
            super().finish()
        finally:
            for db in getattr(self, "_dbs", []):
                db.close()

    def client(self):
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        raw = self.headers.get("X-Device-Id") or self.headers.get("X-HWID") or ""
        return device_id(raw) if raw else device_id(self.headers.get("User-Agent", "")[:120]), ip

    def donations_payload(self, db):
        self.ensure_donations_table(db)
        dev, _ip = self.client()
        totals = db.execute(
            "select coalesce(sum(amount_rub),0), count(*) from donations"
        ).fetchone()
        recent = db.execute(
            "select ts, amount_rub, note from donations order by ts desc limit 40"
        ).fetchall()
        mine = db.execute(
            "select ts, amount_rub, note from donations where device=? order by ts desc limit 40",
            (dev,),
        ).fetchall()
        return {
            "total_rub": int(totals[0] or 0),
            "count": int(totals[1] or 0),
            "recent": [
                {"ts": int(ts), "amount_rub": int(amount), "label": (note or "")[:40] or "Пожертвование"}
                for ts, amount, note in recent
            ],
            "mine": [
                {"ts": int(ts), "amount_rub": int(amount), "label": (note or "")[:40] or "Вы"}
                for ts, amount, note in mine
            ],
        }

    def ensure_donations_table(self, db):
        db.execute(
            """
            create table if not exists donations (
                id integer primary key autoincrement,
                ts integer not null,
                device text not null,
                ip text not null default '',
                amount_rub integer not null,
                note text not null default '',
                app_version text not null default ''
            )
            """
        )
        db.execute("create index if not exists idx_donations_ts on donations(ts)")
        db.execute("create index if not exists idx_donations_device on donations(device)")

    def reply(self, code, body, content_type="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def cookie_session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        return verify_session(morsel.value) if morsel else None

    def admin(self, require_login_page=True):
        db = self.connection_db()
        s = settings(db)
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        if not ip_allowed(ip, s):
            self.reply(403, "IP not allowed", "text/plain; charset=utf-8")
            return None
        sess = self.cookie_session()
        if sess:
            identity = find_admin(db, str(sess.get("u") or ""))
            if identity:
                return {"user": identity["username"], "role": identity["role"], "db": db, "s": s, "ip": ip}
        credentials = basic_auth_credentials(self.headers.get("Authorization", ""))
        if credentials:
            identity = authenticate_admin(db, credentials[0], credentials[1])
            if identity:
                return {"user": identity["username"], "role": identity["role"], "db": db, "s": s, "ip": ip, "basic": True}
        if require_login_page and self.path.startswith("/operator") and not self.path.startswith("/operator/login"):
            self.reply(200, render_login(), "text/html; charset=utf-8")
            return None
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="QuantumControl"')
        self.end_headers()
        return None

    def require_role(self, adm, required="operator"):
        if role_at_least(adm.get("role", "viewer"), required):
            return True
        self.reply(403, "Недостаточно прав для этой операции", "text/plain; charset=utf-8")
        audit(adm["db"], adm.get("user", "unknown"), adm.get("ip", ""), "permission_denied", {"required": required, "role": adm.get("role")})
        adm["db"].commit()
        return False

    def current_release(self, s, channel="production"):
        if channel == "staging" and enabled(s, "staging_enabled", False):
            return (
                s.get("staging_version") or s.get("app_version") or VERSION,
                int(s.get("staging_version_code") or s.get("app_version_code") or VERSION_CODE),
                int(s.get("staging_rollout_percent") or 100),
                s.get("app_changelog") or DEFAULT_NOTE,
            )
        return (
            s.get("app_version") or VERSION,
            int(s.get("app_version_code") or VERSION_CODE),
            int(s.get("rollout_percent") or 100),
            s.get("app_changelog") or DEFAULT_NOTE,
        )

    def device_search(self, db, q, limit=50):
        q = (q or "").strip()
        # Fast path: scan recent rows and dedupe in Python — avoids heavy GROUP BY on large events.
        if q:
            like = f"%{q}%"
            rows = db.execute(
                """
                select device, ip, ts, detail
                from events
                where device like ? or ip like ? or detail like ?
                order by ts desc
                limit 800
                """,
                (like, like, like),
            ).fetchall()
        else:
            rows = db.execute(
                """
                select device, ip, ts, detail
                from events
                where kind='policy'
                order by ts desc
                limit 800
                """,
            ).fetchall()
        seen = {}
        for device, ip, last_ts, detail in rows:
            if device in seen:
                continue
            seen[device] = (device, ip, last_ts, detail)
            if len(seen) >= limit:
                break
        flags = {
            r[0]: r
            for r in db.execute(
                "select device, force_banner, request_diagnostic, note, updated_at from device_flags"
            )
        }
        out = []
        for device, ip, last_ts, detail in seen.values():
            fl = flags.get(device)
            out.append((device, ip, last_ts, detail, int(fl[2]) if fl else 0))
        return out

    def load_device(self, db, q):
        q = (q or "").strip()
        if not q:
            return None
        row = db.execute(
            "select device, ip, detail, ts from events where device=? or ip=? order by ts desc limit 1",
            (q, q),
        ).fetchone()
        if not row:
            row = db.execute(
                "select device, ip, detail, ts from events where device like ? or ip like ? order by ts desc limit 1",
                (f"%{q}%", f"%{q}%"),
            ).fetchone()
        if not row:
            return None
        device = row[0]
        fl = db.execute(
            "select force_banner, request_diagnostic, note, updated_at from device_flags where device=?",
            (device,),
        ).fetchone()
        events = db.execute(
            "select ts, kind, device, ip, detail from events where device=? order by ts desc limit 40",
            (device,),
        ).fetchall()
        return {
            "id": device,
            "ip": row[1],
            "model": row[2],
            "flags": {
                "force_banner": fl[0] if fl else "",
                "request_diagnostic": bool(fl[1]) if fl else False,
                "note": fl[2] if fl else "",
            },
            "events": events,
        }

    def sync_protocols(self, db):
        try:
            with urlopen(Request(UPSTREAM, headers={"User-Agent": "QuantumVPN-API"}), timeout=15) as r:
                raw = r.read(4 * 1024 * 1024)
            text = raw.decode("utf-8", "replace").strip()
            if "://" not in text:
                try:
                    text = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")
                except Exception:
                    pass
            names = sorted({line.split("://", 1)[0].lower() for line in text.splitlines() if "://" in line})
            for name in names:
                db.execute("insert or ignore into protocols values (?,1)", (name,))
            db.commit()
            return names
        except Exception:
            return []

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        db = self.connection_db()
        s = settings(db)

        if path.startswith("/api/"):
            limit = int(s.get("rate_limit_per_min") or 120)
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(ip, limit):
                return self.reply(429, '{"error":"rate_limited"}')

        if path.startswith("/api/client/update") or path.startswith("/api/app/version"):
            channel = (query.get("channel", ["production"])[0] or "production").lower()
            version, version_code, rollout, note = self.current_release(s, channel)
            abi = query.get("abi", ["arm64-v8a"])[0]
            # Legacy QuantumVPN clients probe /api/app/version during splash.
            # If that 404s they hang on "Готовим приложение" / update never starts.
            file = os.path.join(DOWNLOAD_ROOT, version, f"QuantumVPN-{version}-operator-debug-{abi}.apk")
            if not os.path.isfile(file):
                return self.reply(503, '{"error":"release_not_ready"}')
            stat = os.stat(file)
            info = dict(release_info(version, version_code, note, abi, stat.st_size, stat.st_mtime_ns))
            bucket = client_bucket(query.get("bucket", [None])[0])
            eligible = bucket is None or bucket < max(1, min(100, rollout))
            # If client already has this or newer build, echo current so splash can finish
            # without auto-downloading an incompatible APK.
            try:
                client_vc = int(query.get("current_version_code", ["0"])[0] or 0)
            except Exception:
                client_vc = 0
            if client_vc >= version_code:
                info["version"] = query.get("current_version", [version])[0][:32] or version
                info["version_code"] = client_vc
                info["note"] = "Актуальная версия уже установлена."
                eligible = False
            elif not eligible:
                info["version"] = query.get("current_version", [version])[0][:32] or version
                try:
                    info["version_code"] = max(1, int(query.get("current_version_code", [version_code])[0]))
                except Exception:
                    info["version_code"] = version_code
                info["note"] = f"Постепенный выпуск {rollout}%: устройство пока остаётся на текущей версии."
            info["rollout_percent"] = rollout
            info["rollout_eligible"] = eligible
            info["channel"] = channel
            return self.reply(200, json.dumps(info))

        if path.startswith("/downloads/"):
            return self.download_file(path)

        if path == "/operator/health":
            adm = self.admin(require_login_page=False)
            if not adm:
                return
            status = {"operator_api": "ok", "panel_build": PANEL_BUILD, "release": s.get("app_version"), "visible_users": len(rospanel_users())}
            status["services"] = service_status()
            status["upstream"] = probe_upstream()
            status["summary"] = rospanel_summary()
            status["monitor"] = {"interval_seconds": 60, "samples": health_snapshot(db)}
            return self.reply(200, json.dumps(status))

        if path.startswith("/api/client/donations"):
            return self.reply(200, json.dumps(self.donations_payload(db)))

        if path.startswith("/api/client/policy"):
            dev, ip = self.client()
            now = int(time.time())
            last = db.execute("select max(ts) from events where kind='policy' and device=?", (dev,)).fetchone()[0] or 0
            if now - last >= 600:
                db.execute(
                    "insert into events values (?,?,?,?,?)",
                    (now, "policy", dev, ip, self.headers.get("X-Device-Model", self.headers.get("User-Agent", "Android"))[:120]),
                )
                db.commit()
            lang = query.get("lang", [self.headers.get("Accept-Language", "ru")])[0]
            maintenance = effective_maintenance(s, now)
            version, version_code, _, note = self.current_release(s, "production")
            bucket = client_bucket(query.get("bucket", [None])[0])
            features = {
                "vpn_connect": enabled(s, "feature_vpn_connect") and not maintenance,
                "import_json": False,
                "adblock": enabled(s, "feature_adblock"),
                "auto_connect": enabled(s, "feature_auto_connect"),
                "auto_failover": enabled(s, "feature_auto_failover"),
                "kill_switch": enabled(s, "feature_kill_switch"),
                "block_open_wifi": enabled(s, "feature_block_open_wifi"),
                "selfsteal": enabled(s, "feature_selfsteal"),
                "stealth_mode": enabled(s, "feature_selfsteal"),
                "widgets": enabled(s, "feature_widgets"),
                "changelog": enabled(s, "feature_changelog"),
                "diagnostics": enabled(s, "feature_diagnostics"),
                "timeline": enabled(s, "feature_timeline"),
            }
            features.update(ab_features(s, bucket))
            fl = db.execute(
                "select force_banner, request_diagnostic from device_flags where device=?",
                (dev,),
            ).fetchone()
            client_vc = 0
            try:
                client_vc = int(query.get("version_code", [0])[0])
            except Exception:
                client_vc = 0
            min_vc = int(s.get("min_version_code") or 0)
            force_update = bool(min_vc and client_vc and client_vc < min_vc)
            result = {
                "platform": "android",
                "maintenance": maintenance,
                "maintenance_message": localize(s, "maintenance_message", "maintenance_message_en", lang),
                "maintenance_start": int(s.get("maintenance_start", "0") or 0),
                "maintenance_end": int(s.get("maintenance_end", "0") or 0),
                "announce": localize(s, "announce", "announce_en", lang),
                "latest_version": version,
                "version_code": version_code,
                "update_url": f"{DOWNLOAD_BASE}/downloads/{version}/QuantumVPN-{version}-operator-debug-arm64-v8a.apk",
                "update_notifications": True,
                "config_revision": int(s.get("config_revision", "1") or 1),
                "features": features,
                "branding": {
                    "name": (s.get("brand_name") or "QuantumVPN")[:48],
                    "tagline": (s.get("brand_tagline") or "HORIZON GLASS · 2026")[:80],
                    "accent_hex": (s.get("brand_accent") or "#3DE7FF")[:7],
                },
                "nodes_recommended": [x.strip() for x in (s.get("nodes_recommended") or "").split(",") if x.strip()],
                "nodes_forbidden": [x.strip() for x in (s.get("nodes_forbidden") or "").split(",") if x.strip()],
                "latency_optimization": {
                    "enabled": enabled(s, "latency_optimization_enabled", True),
                    "probe_interval_seconds": max(15, min(300, int(s.get("latency_probe_interval", "30") or 30))),
                    "max_ms": max(20, min(5000, int(s.get("latency_max_ms", "120") or 120))),
                    "state": s.get("latency_state") or "unknown",
                    "best_ms": int(s.get("latency_best_ms", "0") or 0),
                },
                "min_version_code": min_vc,
                "force_update": force_update,
                "force_update_message": s.get("force_update_message") or "",
                "device_banner": (fl[0] if fl and fl[0] else ""),
                "request_diagnostic": bool(fl[1]) if fl else False,
                "changelog": note,
            }
            return self.reply(200, json.dumps(result, ensure_ascii=False))

        if path == "/api/v1/subscription":
            if s.get("subscription_main_enabled") != "1":
                return self.reply(503, "Subscription temporarily unavailable", "text/plain; charset=utf-8")
            self.send_response(307)
            self.send_header("Location", UPSTREAM)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return

        if path == "/operator/logout":
            self.reply(
                302,
                "",
                "text/plain",
                {"Location": "/operator/login", "Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"},
            )
            return

        if path == "/operator/login":
            return self.reply(200, render_login(), "text/html; charset=utf-8")

        if path == "/operator/logs.txt":
            adm = self.admin()
            if not adm:
                return
            rows = db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 500").fetchall()
            body = "\n\n".join(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}] {kind}\nDevice: {device}\nIP: {ip}\n{detail}"
                for ts, kind, device, ip, detail in rows
            )
            return self.reply(200, body or "No logs", "text/plain; charset=utf-8")

        if path in ("/operator/report.txt", "/operator/report.json"):
            adm = self.admin()
            if not adm:
                return
            report = report_snapshot(db)
            if path.endswith(".json"):
                return self.reply(
                    200,
                    json.dumps(report, ensure_ascii=False, indent=2),
                    "application/json; charset=utf-8",
                    {"Content-Disposition": 'attachment; filename="quantum-control-report.json"'},
                )
            lines = [
                "Quantum Control — суточный отчёт",
                f"Сформирован: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(report['generated_at']))}",
                f"Устройства за 24ч: {report['devices_seen']}",
                f"Health checks: {report['health_checks']} (успешно {report['health_ok']}, {report['health_uptime_percent']}%)",
                f"Средняя задержка: {report['average_latency_ms']} ms",
                f"Активные инциденты: {report['open_incidents']}",
                "",
                "События:",
            ]
            lines.extend(f"- {kind}: {count}" for kind, count in sorted(report["events"].items()))
            return self.reply(
                200,
                "\n".join(lines) + "\n",
                "text/plain; charset=utf-8",
                {"Content-Disposition": 'attachment; filename="quantum-control-report.txt"'},
            )

        if path == "/operator/backup.zip":
            adm = self.admin()
            if not adm or not self.require_role(adm, "operator"):
                return
            archive = create_backup_archive()
            try:
                with open(archive, "rb") as stream:
                    payload = stream.read()
                audit(db, adm.get("user", "unknown"), adm.get("ip", ""), "backup_download", {"file": os.path.basename(archive)})
                db.commit()
                return self.reply(
                    200,
                    payload,
                    "application/zip",
                    {"Content-Disposition": f'attachment; filename="{os.path.basename(archive)}"'},
                )
            except OSError:
                return self.reply(500, "Backup unavailable", "text/plain; charset=utf-8")

        if path == "/operator/live":
            adm = self.admin(require_login_page=False)
            if not adm:
                return
            last_ts = int(query.get("since", ["0"])[0] or 0)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            deadline = time.monotonic() + 25
            try:
                while time.monotonic() < deadline:
                    rows = db.execute(
                        "select ts,kind,device,ip,detail from events where ts>? order by ts asc limit 80",
                        (last_ts,),
                    ).fetchall()
                    for ts, kind, device, ip, detail in rows:
                        last_ts = max(last_ts, int(ts))
                        payload = {"ts": int(ts), "kind": kind, "device": device, "ip": ip, "detail": detail[:1600]}
                        self.wfile.write(("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8"))
                    if not rows:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(1)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            return

        if path == "/operator":
            adm = self.admin()
            if not adm:
                return
            tab = query.get("tab", ["dashboard"])[0]
            q = query.get("q", [""])[0]
            flash = query.get("flash", [""])[0]
            if tab == "admins" and not role_at_least(adm.get("role", "viewer"), "owner"):
                return self.reply(403, "Только owner может управлять администраторами", "text/plain; charset=utf-8")
            admin_rows = db.execute(
                "select username,role,enabled,updated_at from admin_users order by username"
            ).fetchall()
            empty_summary = {"active": 0, "disabled": 0, "expired": 0, "online_15m": 0, "traffic_today_gb": 0.0, "ok": False}
            empty_status = {"rospanel": "—", "operator": "—", "xray": "—", "opera": "—", "disk_free_gb": 0, "disk_used_pct": 0, "outbounds": []}
            if tab == "devices":
                # Devices tab must stay fast: skip RosPanel/systemctl scans and heavy event dumps.
                device_rows = self.device_search(db, q)
                device = self.load_device(db, q) if q else None
                return self.reply(
                    200,
                    render_panel(
                        s,
                        [],
                        [],
                        [],
                        empty_summary,
                        empty_status,
                        [],
                        device_rows,
                        flash=unquote(flash),
                        section=tab,
                        q=q,
                        device=device,
                        actor_role=adm.get("role", "viewer"),
                    ),
                    "text/html; charset=utf-8",
                )
            if tab == "donations":
                self.ensure_donations_table(db)
                donation_rows = db.execute(
                    "select ts, amount_rub, device, ip, app_version, note from donations order by ts desc limit 300"
                ).fetchall()
                totals_row = db.execute(
                    "select coalesce(sum(amount_rub),0), count(*), count(distinct device) from donations"
                ).fetchone()
                donation_totals = {
                    "total_rub": int(totals_row[0] or 0),
                    "count": int(totals_row[1] or 0),
                    "devices": int(totals_row[2] or 0),
                }
                return self.reply(
                    200,
                    render_panel(
                        s,
                        [],
                        [],
                        [],
                        empty_summary,
                        empty_status,
                        [],
                        [],
                        flash=unquote(flash),
                        section=tab,
                        q=q,
                        donation_rows=donation_rows,
                        donation_totals=donation_totals,
                        actor_role=adm.get("role", "viewer"),
                    ),
                    "text/html; charset=utf-8",
                )
            rows = db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 100").fetchall()
            protocols = db.execute("select name,enabled from protocols order by name").fetchall()
            audit_rows = db.execute("select ts,actor,ip,action,detail from audit order by ts desc limit 100").fetchall()
            users = rospanel_users(q=q if tab == "users" else "")
            return self.reply(
                200,
                render_panel(
                    s,
                    rows,
                    users,
                    protocols,
                    cached_rospanel_summary(),
                    cached_service_status(),
                    audit_rows,
                    [],
                    flash=unquote(flash),
                    section=tab,
                    q=q,
                    device=None,
                    admin_rows=admin_rows,
                    actor_role=adm.get("role", "viewer"),
                ),
                "text/html; charset=utf-8",
            )

        self.reply(404, "Not found", "text/plain")

    def download_file(self, path, head=False):
        root = os.path.realpath(DOWNLOAD_ROOT) + os.sep
        target = os.path.realpath(os.path.join(DOWNLOAD_ROOT, path.removeprefix("/downloads/")))
        if not target.startswith(root) or not os.path.isfile(target):
            return self.reply(404, "Not found", "text/plain")
        size = os.path.getsize(target)
        range_header = self.headers.get("Range", "")
        start, end = 0, size - 1
        status = 200
        if range_header.startswith("bytes=") and "-" in range_header:
            try:
                spec = range_header.replace("bytes=", "", 1).strip()
                left, right = spec.split("-", 1)
                if left:
                    start = max(0, int(left))
                if right:
                    end = min(size - 1, int(right))
                if start > end or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers()
                    return
                status = 206
            except Exception:
                start, end = 0, size - 1
                status = 200
        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Disposition", "attachment")
        self.send_header("Cache-Control", "public, max-age=60")
        self.end_headers()
        if head:
            return
        # Prefer zero-copy sendfile only when TLS is terminated upstream (plain TCP socket).
        # OpenSSL-wrapped sockets cannot use sendfile reliably.
        if os.environ.get("QV_TLS_TERMINATED", "").strip() in ("1", "true", "yes"):
            try:
                out_fd = self.wfile.fileno()
                with open(target, "rb") as source:
                    in_fd = source.fileno()
                    offset = start
                    remaining = length
                    while remaining > 0:
                        sent = os.sendfile(out_fd, in_fd, offset, remaining)
                        if sent <= 0:
                            break
                        offset += sent
                        remaining -= sent
                    if remaining == 0:
                        return
                    start = offset
                    length = remaining
            except Exception:
                pass
        with open(target, "rb") as source:
            source.seek(start)
            remaining = length
            while remaining > 0:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path.startswith("/downloads/"):
            return self.download_file(path, True)
        self.send_response(404)
        self.end_headers()

    def redirect_operator(self, tab="dashboard", flash=""):
        loc = f"/operator?tab={quote(tab)}"
        if flash:
            loc += f"&flash={quote(flash)}"
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        db = self.connection_db()
        s = settings(db)

        if path == "/api/client/diagnostic":
            limit = int(s.get("rate_limit_per_min") or 120)
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(ip, limit):
                return self.reply(429, '{"error":"rate_limited"}')
            try:
                size = min(int(self.headers.get("Content-Length", "0")), 16_384)
                raw = self.rfile.read(size).decode("utf-8")
                payload = json.loads(raw)
                if payload.get("consent") is not True:
                    return self.reply(400, '{"error":"consent_required"}')
                dev, ip = self.client()
                detail = ("last_error=" + str(payload.get("last_error", "")) + "\n" + str(payload.get("logs", "")))[:12_500]
                db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "voluntary_diagnostic", dev, ip, detail))
                db.execute(
                    "insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) "
                    "on conflict(device) do update set request_diagnostic=0, updated_at=excluded.updated_at",
                    (dev, "", 0, "", int(time.time())),
                )
                db.commit()
                webhook_emit(
                    settings(db),
                    "diagnostic.received",
                    {"device": dev, "ip": ip, "last_error": str(payload.get("last_error", ""))[:400]},
                )
                return self.reply(201, '{"ok":true}')
            except Exception:
                return self.reply(400, '{"error":"invalid_report"}')

        if path == "/api/client/donations":
            limit = int(s.get("rate_limit_per_min") or 120)
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(ip, limit):
                return self.reply(429, '{"error":"rate_limited"}')
            try:
                self.ensure_donations_table(db)
                size = min(int(self.headers.get("Content-Length", "0")), 4096)
                raw = self.rfile.read(size).decode("utf-8")
                payload = json.loads(raw)
                amount = int(payload.get("amount_rub") or 0)
                if amount < 1 or amount > 1_000_000:
                    return self.reply(400, '{"error":"invalid_amount"}')
                note = str(payload.get("note") or "")[:80]
                app_version = str(payload.get("app_version") or "")[:32]
                dev, ip = self.client()
                db.execute(
                    "insert into donations(ts,device,ip,amount_rub,note,app_version) values (?,?,?,?,?,?)",
                    (int(time.time()), dev, ip, amount, note, app_version),
                )
                db.commit()
                return self.reply(201, json.dumps(self.donations_payload(db)))
            except Exception:
                return self.reply(400, '{"error":"invalid_donation"}')

        if path.startswith("/operator/") and self.headers.get("Origin") not in (None, PUBLIC_BASE):
            # allow same-host without Origin; block foreign browser origins
            origin = self.headers.get("Origin")
            if origin and origin != PUBLIC_BASE:
                return self.reply(403, "Invalid origin")

        if path == "/operator/login":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            code = form.get("totp", [""])[0]
            ip = self.client_address[0]
            if not ip_allowed(ip, s):
                return self.reply(403, render_login("IP не в allowlist"), "text/html; charset=utf-8")
            identity = authenticate_admin(db, user, password)
            if not identity:
                time.sleep(0.4)
                return self.reply(401, render_login("Неверный логин или пароль"), "text/html; charset=utf-8")
            if enabled(s, "totp_enabled", False):
                secret = s.get("totp_secret") or ""
                if not secret or not totp_ok(secret, code):
                    return self.reply(401, render_login("Нужен корректный код 2FA"), "text/html; charset=utf-8")
            token = sign_session({"u": identity["username"], "role": identity["role"], "exp": int(time.time()) + SESSION_TTL, "n": secrets.token_hex(8)})
            audit(db, identity["username"], ip, "login", {"ok": True, "role": identity["role"]})
            db.commit()
            self.send_response(303)
            self.send_header("Location", "/operator?tab=dashboard")
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict",
            )
            self.end_headers()
            return

        adm = self.admin()
        if not adm:
            return
        actor, ip = adm["user"], adm["ip"]
        if not self.require_role(adm, "operator"):
            return

        if path == "/operator/admins":
            if not self.require_role(adm, "owner"):
                return
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            username = (form.get("username", [""])[0] or "").strip()[:64]
            raw_password = form.get("password", [""])[0]
            role = normal_role(form.get("role", ["operator"])[0])
            is_enabled = 1 if "enabled" in form else 0
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{2,64}", username) or len(raw_password) < 10:
                return self.reply(400, "Логин или пароль не соответствуют требованиям", "text/plain; charset=utf-8")
            now = int(time.time())
            db.execute(
                "insert into admin_users(username,password_hash,role,enabled,created_at,updated_at) values (?,?,?,?,?,?) "
                "on conflict(username) do update set password_hash=excluded.password_hash, role=excluded.role, enabled=excluded.enabled, updated_at=excluded.updated_at",
                (username, password_hash(raw_password), role, is_enabled, now, now),
            )
            audit(db, actor, ip, "admin_user_upsert", {"username": username, "role": role, "enabled": bool(is_enabled)})
            db.commit()
            return self.redirect_operator("admins", "Администратор сохранён")

        if path == "/operator/actions":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            action = form.get("action", [""])[0]
            flash = "Готово"
            if action == "bump_revision":
                rev = int(s.get("config_revision") or 1) + 1
                set_settings(db, {"config_revision": rev})
                flash = f"config_revision={rev}"
            elif action == "sync_protocols":
                names = self.sync_protocols(db)
                flash = f"Протоколы: {', '.join(names) or 'пусто'}"
            elif action == "telegram_test":
                ok = telegram_send(s, "[Quantum Control] Тестовое сообщение: алерты работают.")
                flash = "Telegram OK" if ok else "Telegram ошибка (проверьте token/chat)"
            elif action == "backup_now":
                archive = create_backup_archive()
                ok = telegram_send_document(s, archive, f"Quantum Control: ручная резервная копия {time.strftime('%Y-%m-%d %H:%M UTC')}")
                flash = "Backup отправлен в Telegram" if ok else "Backup создан локально, Telegram недоступен"
                audit(db, actor, ip, "backup_now", {"ok": ok, "file": os.path.basename(archive)})
            elif action == "test_webhook":
                ok = webhook_emit(s, "webhook.test", {"actor": actor, "message": "Quantum Control webhook is working"})
                flash = "Вебхук OK" if ok else "Вебхук не доставлен: проверьте HTTPS URL, секрет и ответ получателя"
            elif action == "close_incident":
                key = (form.get("incident_key", [""])[0] or "").strip()[:160]
                ok = bool(key) and incident_close(db, key, s)
                flash = "Инцидент закрыт" if ok else "Активный инцидент не найден"
            elif action == "restart_operator":
                audit(db, actor, ip, "restart_operator", {})
                db.commit()
                threading.Thread(target=lambda: (time.sleep(0.5), subprocess.run(["systemctl", "restart", "quantumvpn-operator"])), daemon=True).start()
                flash = "Operator перезапускается"
            elif action == "restart_rospanel":
                audit(db, actor, ip, "restart_rospanel", {})
                db.commit()
                threading.Thread(target=lambda: subprocess.run(["systemctl", "restart", "rospanel"]), daemon=True).start()
                flash = "RosPanel перезапускается"
            else:
                flash = "Неизвестное действие"
            audit(db, actor, ip, action or "action", {"flash": flash})
            db.commit()
            return self.redirect_operator("dashboard", flash)

        if path in ("/operator/device", "/operator/device/clear-diagnostic"):
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            device = form.get("device", [""])[0].strip()
            if not device:
                return self.redirect_operator("devices", "Нет device id")
            if path.endswith("clear-diagnostic"):
                db.execute(
                    "insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) "
                    "on conflict(device) do update set request_diagnostic=0, updated_at=excluded.updated_at",
                    (device, "", 0, "", int(time.time())),
                )
            else:
                banner = form.get("force_banner", [""])[0][:500]
                note = form.get("note", [""])[0][:500]
                req = 1 if "request_diagnostic" in form else 0
                db.execute(
                    "insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) "
                    "on conflict(device) do update set force_banner=excluded.force_banner, request_diagnostic=excluded.request_diagnostic, note=excluded.note, updated_at=excluded.updated_at",
                    (device, banner, req, note, int(time.time())),
                )
            audit(db, actor, ip, "device_flags", {"device": device})
            db.commit()
            return self.redirect_operator("devices", "Устройство сохранено")

        if path == "/operator/upload":
            form, files = parse_multipart(self)
            version = (form.get("version", [""])[0] or "").strip()
            abi = (form.get("abi", ["arm64-v8a"])[0] or "arm64-v8a").strip()
            apk = files.get("apk")
            if not version or not apk or not apk["data"]:
                return self.redirect_operator("release", "Нужны версия и APK")
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                return self.redirect_operator("release", "Версия вида X.Y.Z")
            folder = os.path.join(DOWNLOAD_ROOT, version)
            os.makedirs(folder, exist_ok=True)
            name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
            target = os.path.join(folder, name)
            with open(target, "wb") as out:
                out.write(apk["data"])
            digest = hashlib.sha256(apk["data"]).hexdigest()
            open(target + ".sha256", "w").write(digest + "\n")
            release_info.cache_clear()
            updates = {}
            if "set_production" in form:
                updates["app_version"] = version
            audit(db, actor, ip, "upload_apk", {"version": version, "abi": abi, "sha256": digest, "size": len(apk["data"])})
            if updates:
                set_settings(db, updates)
            db.commit()
            return self.redirect_operator("release", f"Загружено {name}")

        if path == "/operator/protocols":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            for name, _ in db.execute("select name,enabled from protocols"):
                db.execute("update protocols set enabled=? where name=?", (1 if f"p_{name}" in form else 0, name))
            audit(db, actor, ip, "protocols", {})
            db.commit()
            return self.redirect_operator("service", "Протоколы сохранены")

        if path != "/operator/policy":
            return self.reply(404, "Not found", "text/plain")

        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        section = form.get("section", [""])[0]
        current = settings(db)
        values = {}
        tab = "service"

        if section == "service":
            tab = "service"
            try:
                start = parse_datetime_value(form.get("maintenance_start", [""])[0])
                end = parse_datetime_value(form.get("maintenance_end", [""])[0])
            except Exception:
                return self.reply(400, '{"error":"invalid_maintenance_time"}')
            if "maintenance_schedule_enabled" in form and (start <= 0 or end <= start):
                return self.reply(400, '{"error":"maintenance_end_must_follow_start"}')
            values = {
                "maintenance": "1" if "maintenance" in form else "0",
                "maintenance_schedule_enabled": "1" if "maintenance_schedule_enabled" in form else "0",
                "maintenance_start": str(start),
                "maintenance_end": str(end),
                "maintenance_message": form.get("maintenance_message", [""])[0][:400],
                "maintenance_message_en": form.get("maintenance_message_en", [""])[0][:400],
                "announce": form.get("announce", [""])[0][:400],
                "announce_en": form.get("announce_en", [""])[0][:400],
            }
        elif section == "subscription":
            tab = "service"
            values = {"subscription_main_enabled": "1" if "subscription_main_enabled" in form else "0"}
        elif section == "nodes":
            tab = "service"
            values = {
                "nodes_recommended": form.get("nodes_recommended", [""])[0][:1000],
                "nodes_forbidden": form.get("nodes_forbidden", [""])[0][:1000],
            }
        elif section == "release":
            tab = "release"
            try:
                rollout = max(1, min(100, int(form.get("rollout_percent", ["100"])[0])))
                vc = int(form.get("app_version_code", [str(VERSION_CODE)])[0])
                min_vc = max(0, int(form.get("min_version_code", ["0"])[0]))
                scheduled_vc = max(0, int(form.get("scheduled_app_version_code", ["0"])[0]))
                scheduled_rollout = max(1, min(100, int(form.get("scheduled_rollout_percent", ["100"])[0])))
                publish_at = max(0, int(form.get("release_publish_at", ["0"])[0] or 0))
            except Exception:
                return self.reply(400, '{"error":"invalid_release"}')
            values = {
                "app_version": form.get("app_version", [VERSION])[0][:32],
                "app_version_code": str(vc),
                "min_version_code": str(min_vc),
                "force_update_message": form.get("force_update_message", [""])[0][:400],
                "rollout_percent": str(rollout),
                "app_changelog": form.get("app_changelog", [""])[0][:1000],
                "release_schedule_enabled": "1" if "release_schedule_enabled" in form else "0",
                "release_publish_at": str(publish_at),
                "scheduled_app_version": form.get("scheduled_app_version", [""])[0][:32],
                "scheduled_app_version_code": str(scheduled_vc),
                "scheduled_rollout_percent": str(scheduled_rollout),
                "scheduled_app_changelog": form.get("scheduled_app_changelog", [""])[0][:1000],
            }
        elif section == "staging":
            tab = "release"
            try:
                rollout = max(1, min(100, int(form.get("staging_rollout_percent", ["100"])[0])))
                vc = int(form.get("staging_version_code", [str(VERSION_CODE)])[0])
            except Exception:
                return self.reply(400, '{"error":"invalid_staging"}')
            values = {
                "staging_enabled": "1" if "staging_enabled" in form else "0",
                "staging_version": form.get("staging_version", [""])[0][:32],
                "staging_version_code": str(vc),
                "staging_rollout_percent": str(rollout),
            }
        elif section == "features":
            tab = "features"
            values = {
                key: "1" if key in form else "0"
                for key in (
                    "feature_vpn_connect",
                    "feature_adblock",
                    "feature_auto_connect",
                    "feature_auto_failover",
                    "feature_kill_switch",
                    "feature_block_open_wifi",
                    "feature_selfsteal",
                    "feature_widgets",
                    "feature_changelog",
                    "feature_diagnostics",
                    "feature_timeline",
                )
            }
        elif section == "ab":
            tab = "features"
            raw = form.get("feature_ab_json", ["{}"])[0]
            try:
                json.loads(raw or "{}")
            except Exception:
                return self.reply(400, '{"error":"invalid_ab_json"}')
            values = {"feature_ab_json": raw[:4000]}
        elif section == "branding":
            tab = "branding"
            name = form.get("brand_name", ["QuantumVPN"])[0].strip()[:48]
            tagline = form.get("brand_tagline", ["HORIZON GLASS · 2026"])[0].strip()[:80]
            accent = form.get("brand_accent", ["#3DE7FF"])[0].strip().upper()
            if not name or not tagline or not re.fullmatch(r"#[0-9A-F]{6}", accent):
                return self.reply(400, '{"error":"invalid_branding"}')
            values = {
                "brand_name": name,
                "brand_tagline": tagline,
                "brand_accent": accent,
            }
        elif section == "latency":
            tab = "latency"
            try:
                probe_interval = max(15, min(300, int(form.get("latency_probe_interval", ["30"])[0])))
                max_latency = max(20, min(5000, int(form.get("latency_max_ms", ["120"])[0])))
            except Exception:
                return self.reply(400, '{"error":"invalid_latency_settings"}')
            targets = ",".join(f"{host}:{port}" for host, port in parse_latency_targets(form.get("latency_probe_targets", [""])[0]))
            if not targets:
                return self.reply(400, '{"error":"latency_targets_required"}')
            values = {
                "latency_optimization_enabled": "1" if "latency_optimization_enabled" in form else "0",
                "latency_probe_interval": str(probe_interval),
                "latency_max_ms": str(max_latency),
                "latency_probe_targets": targets,
            }
        elif section == "security":
            tab = "security"
            try:
                rl = max(10, min(5000, int(form.get("rate_limit_per_min", ["120"])[0])))
            except Exception:
                return self.reply(400, '{"error":"invalid_rate"}')
            totp_on = "totp_enabled" in form
            secret = current.get("totp_secret") or ""
            if totp_on and not secret:
                secret = totp_secret_b32()
            if not totp_on:
                secret = secret  # keep secret for re-enable
            values = {
                "totp_enabled": "1" if totp_on else "0",
                "totp_secret": secret,
                "ip_allowlist": form.get("ip_allowlist", [""])[0][:1000],
                "rate_limit_per_min": str(rl),
            }
        elif section == "telegram":
            tab = "security"
            values = {
                "telegram_alerts_enabled": "1" if "telegram_alerts_enabled" in form else "0",
                "telegram_backups_enabled": "1" if "telegram_backups_enabled" in form else "0",
                "telegram_bot_token": form.get("telegram_bot_token", [""])[0][:200],
                "telegram_chat_id": form.get("telegram_chat_id", [""])[0][:64],
            }
        elif section == "webhooks":
            tab = "integrations"
            url = (form.get("webhook_url", [""])[0] or "").strip()[:2048]
            if url and not url.lower().startswith("https://"):
                return self.reply(400, '{"error":"webhook_https_required"}')
            events = []
            for item in (form.get("webhook_events", [""])[0] or "").split(","):
                item = item.strip().lower()
                if item and re.fullmatch(r"[a-z][a-z0-9_.-]{0,48}", item) and item not in events:
                    events.append(item)
            secret = form.get("webhook_secret", [""])[0]
            values = {
                "webhook_enabled": "1" if "webhook_enabled" in form else "0",
                "webhook_url": url,
                "webhook_secret": secret[:256] if secret else current.get("webhook_secret", ""),
                "webhook_events": ",".join(events)[:500],
            }
        else:
            return self.reply(400, '{"error":"unknown_section"}')

        if section in ("service", "features", "nodes", "ab", "branding", "latency", "release") and any(current.get(k) != v for k, v in values.items()):
            values["config_revision"] = str(int(current.get("config_revision", "1") or 1) + 1)
        changes = {k: {"before": current.get(k), "after": v} for k, v in values.items() if current.get(k) != v}
        maintenance_before = effective_maintenance(current)
        set_settings(db, values)
        db.execute(
            "insert into events values (?,?,?,?,?)",
            (int(time.time()), "admin", actor, ip, json.dumps(changes, ensure_ascii=False)),
        )
        audit(db, actor, ip, f"policy:{section}", changes)
        db.commit()
        if section == "service":
            updated = dict(current)
            updated.update(values)
            maintenance_after = effective_maintenance(updated)
            if maintenance_before != maintenance_after:
                webhook_emit(
                    updated,
                    "maintenance.changed",
                    {"enabled": maintenance_after, "actor": actor, "message": updated.get("maintenance_message", "")[:400]},
                )
        return self.redirect_operator(tab, "Сохранено")


def main():
    port = int(os.environ.get("QV_PORT", "8765"))
    bind = os.environ.get("QV_BIND", "0.0.0.0")
    threading.Thread(target=alert_worker, daemon=True).start()
    threading.Thread(target=hourly_backup_worker, daemon=True).start()
    threading.Thread(target=latency_worker, daemon=True).start()
    threading.Thread(target=health_worker, daemon=True).start()
    threading.Thread(target=scheduled_release_worker, daemon=True).start()
    try:
        OperatorHTTPServer.request_queue_size = int(os.environ.get("QV_BACKLOG", "512"))
    except Exception:
        OperatorHTTPServer.request_queue_size = 512
    server = OperatorHTTPServer((bind, port), App)
    try:
        server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except Exception:
        pass
    terminated = os.environ.get("QV_TLS_TERMINATED", "").strip() in ("1", "true", "yes")
    cert, key = os.environ.get("QV_TLS_CERT"), os.environ.get("QV_TLS_KEY")
    if cert and key and not terminated:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
