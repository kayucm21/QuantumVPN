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
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from email.parser import BytesParser
from email.policy import default as email_default
from functools import lru_cache
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from urllib.request import Request, urlopen

ROOT = os.environ.get("QV_DATA_DIR", "/var/lib/quantumvpn-operator")
DB = os.path.join(ROOT, "operator.db")
USER = os.environ["QV_ADMIN_USER"]
PASSWORD = os.environ["QV_ADMIN_PASSWORD"]
UPSTREAM = os.environ["QV_SUBSCRIPTION_UPSTREAM"]
ROSPANEL_DB = os.environ.get("QV_ROSPANEL_DB", "/var/lib/rospanel/rospanel.db")
ROSPANEL_API = os.environ.get("QV_ROSPANEL_API", "").rstrip("/")
DOWNLOAD_ROOT = os.environ.get("QV_DOWNLOAD_ROOT", "/var/www/quantumvpn/downloads")
PUBLIC_BASE = os.environ.get("QV_PUBLIC_BASE", "https://tepacom.o190.com:8443")
PANEL_BUILD = "5.7.5"
VERSION = "5.7.5"
VERSION_CODE = 103
SESSION_TTL = 12 * 3600
SESSION_COOKIE = "qv_session"
_DB_INIT_LOCK = threading.Lock()
_DB_READY = False
_LAST_EVENT_CLEANUP = 0
_RATE = defaultdict(deque)
_RATE_LOCK = threading.Lock()
_ALERT_STATE = {"last": {}, "lock": threading.Lock()}

DEFAULT_NOTE = (
    "Aurora 2026: оценка качества серверов, центр состояния, история и приватность, "
    "защита публичного Wi-Fi, управляемый выпуск и расписание техработ."
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


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
        "url": f"{PUBLIC_BASE}/downloads/{version}/{name}",
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
                create index if not exists idx_events_device on events(device);
                create index if not exists idx_events_kind_ts on events(kind, ts);
                create index if not exists idx_audit_ts on audit(ts);
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
                "min_version_code": "0",
                "force_update_message": "Доступна обязательная обновлённая версия QuantumVPN.",
                "feature_vpn_connect": "1",
                "feature_adblock": "1",
                "feature_auto_connect": "1",
                "feature_auto_failover": "1",
                "feature_kill_switch": "0",
                "feature_block_open_wifi": "0",
                "feature_ab_json": "{}",
                "nodes_recommended": "",
                "nodes_forbidden": "",
                "config_revision": "1",
                "totp_enabled": "0",
                "totp_secret": "",
                "ip_allowlist": "",
                "telegram_bot_token": "",
                "telegram_chat_id": "",
                "telegram_alerts_enabled": "0",
                "rate_limit_per_min": "120",
            }
            for key, value in defaults.items():
                db.execute("insert or ignore into settings values (?,?)", (key, value))
            db.execute(
                "update settings set value=? where key='maintenance_message' and value=?",
                (
                    "Ведутся технические работы. После завершения работ мы возобновим сервис.",
                    "Технические работы. Извините за неудобства.",
                ),
            )
            _DB_READY = True
        if now - _LAST_EVENT_CLEANUP >= 3600:
            db.execute("delete from events where ts < ?", (now - 14 * 86400,))
            db.execute("delete from audit where ts < ?", (now - 90 * 86400,))
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


def probe_upstream():
    try:
        url = urlsplit(UPSTREAM)
        started = time.monotonic()
        with urlopen(f"{url.scheme}://{url.netloc}/", timeout=5) as response:
            status = response.status
        return {"ok": True, "status": status, "latency_ms": round((time.monotonic() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


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
    :root{color-scheme:dark;--bg:#050b16;--card:#0a192ae8;--line:#21546a;--text:#eaf7ff;--muted:#9ab0bf;--ok:#38efab;--off:#ff9aa7;--accent:#31dda0}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#103b47,#050b16 55%);color:var(--text);font:15px/1.45 "Segoe UI",system-ui,sans-serif}
    main{max-width:1280px;margin:auto;padding:24px 16px 72px}.hero,.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;margin:14px 0;box-shadow:0 16px 40px #0004}
    .hero{background:linear-gradient(135deg,#0d3140,#091222)}h1{margin:4px 0;font-size:30px}h2{margin:0 0 12px;font-size:18px}
    .accent,.ok{color:var(--ok)}.off{color:var(--off)}.muted{color:var(--muted)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}.grid .card{margin:0}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}.stat{background:#07121f;border:1px solid #1d3546;border-radius:14px;padding:12px}
    .stat b{display:block;font-size:22px;margin-top:4px}label{display:block;margin:10px 0}
    textarea,input,select{width:100%;background:#07121f;color:var(--text);border:1px solid #285368;border-radius:10px;padding:10px}
    input[type=checkbox]{width:auto;accent-color:var(--accent)}
    button,a.button{display:inline-block;background:linear-gradient(135deg,#31dda0,#3298ef);color:#041019;border:0;border-radius:11px;padding:10px 14px;font-weight:800;text-decoration:none;cursor:pointer}
    button.secondary,a.secondary{background:#123247;color:#dff6ff;border:1px solid #2a5b73}
    button.danger{background:linear-gradient(135deg,#ff7b8a,#ef4d6a);color:#18040a}
    .actions{display:flex;gap:8px;flex-wrap:wrap}nav.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0}
    nav.tabs a{padding:8px 12px;border-radius:999px;border:1px solid #2a5b73;color:#dff6ff;text-decoration:none;font-size:13px}
    table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px 6px;border-bottom:1px solid #1d3546;text-align:left;vertical-align:top}
    .flash{padding:10px 12px;border-radius:12px;background:#113528;border:1px solid #2f7a58;margin:10px 0}
    .login{max-width:420px;margin:10vh auto}.pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#123247;font-size:12px}
    @media(max-width:600px){main{padding:16px 10px}h1{font-size:24px}table{font-size:11px}}
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


def render_panel(s, rows, users, protocols, summary, status, audit_rows, device_rows, flash="", section="dashboard", q="", device=None):
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
    totp_setup = ""
    if not enabled(s, "totp_enabled", False) or not s.get("totp_secret"):
        totp_setup = "<p class=muted>2FA выключена. Включите и сохраните — секрет сгенерируется автоматически.</p>"
    else:
        uri = f"otpauth://totp/QuantumControl:{USER}?secret={s.get('totp_secret')}&issuer=QuantumControl"
        totp_setup = f"<p class=ok>2FA активна.</p><p class=muted>Секрет: <code>{html.escape(s.get('totp_secret'))}</code></p><p class=muted>URI: <code>{html.escape(uri)}</code></p>"

    def show(name):
        return "" if section == name else "style='display:none'"

    flash_html = f"<div class=flash>{html.escape(flash)}</div>" if flash else ""
    outbounds = ", ".join(status.get("outbounds") or []) or "—"
    return f"""<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
    <title>Quantum Control</title><style>{css()}</style><main>
    <section class=hero>
      <div class=accent>QUANTUM CONTROL · ROSPANEL · build {html.escape(PANEL_BUILD)}</div>
      <h1>Управление приложением</h1>
      <p class=muted>Политики, релизы, устройства, алерты и статус — только доп. панель. Подписчики правятся в RosPanel.</p>
      <nav class=tabs>
        <a href="/operator?tab=dashboard">Дашборд</a>
        <a href="/operator?tab=service">Сервис</a>
        <a href="/operator?tab=features">Фичи</a>
        <a href="/operator?tab=release">Релизы</a>
        <a href="/operator?tab=devices">Устройства</a>
        <a href="/operator?tab=users">Юзеры</a>
        <a href="/operator?tab=security">Безопасность</a>
        <a href="/operator?tab=audit">Аудит</a>
        <a href="/operator/logs.txt">Логи</a>
        <a href="/operator/logout">Выход</a>
      </nav>
    </section>
    {flash_html}

    <section class=card {show('dashboard')}>
      <h2>Дашборд</h2>
      <div class=stats>
        <div class=stat>Онлайн 15м (RosPanel)<b class=ok>{summary.get('online_15m','—')}</b></div>
        <div class=stat>Активны / выкл / expired<b>{summary.get('active','—')} / {summary.get('disabled','—')} / {summary.get('expired','—')}</b></div>
        <div class=stat>Трафик сегодня<b>{summary.get('traffic_today_gb','—')} GB</b></div>
        <div class=stat>Policy за час<b>{sum(1 for x in rows if x[1]=='policy' and x[0] > time.time()-3600)}</b></div>
        <div class=stat>Диагностики 24ч<b class=off>{sum(1 for x in rows if x[1]=='voluntary_diagnostic')}</b></div>
        <div class=stat>Диск<b>{status.get('disk_used_pct')}% · свободно {status.get('disk_free_gb')} GB</b></div>
      </div>
      <div class=grid style="margin-top:14px">
        <div class=card><h2>Сервисы</h2>
          <p>RosPanel: <b class={'ok' if status.get('rospanel')=='active' else 'off'}>{html.escape(str(status.get('rospanel')))}</b></p>
          <p>Operator: <b class={'ok' if status.get('operator')=='active' else 'off'}>{html.escape(str(status.get('operator')))}</b></p>
          <p>Xray: <b class={'ok' if status.get('xray')=='running' else 'off'}>{html.escape(str(status.get('xray')))}</b></p>
          <p>Opera: <b class={'ok' if status.get('opera')=='running' else 'off'}>{html.escape(str(status.get('opera')))}</b></p>
          <p class=muted>Outbounds: {html.escape(outbounds)}</p>
        </div>
        <div class=card><h2>Быстрые действия</h2>
          <form class=actions method=post action=/operator/actions>
            <button name=action value=bump_revision>Сбросить кэш политики</button>
            <button class=secondary name=action value=restart_operator>Рестарт Operator</button>
            <button class=danger name=action value=restart_rospanel onclick="return confirm('Перезапустить RosPanel/Xray/Opera?')">Рестарт RosPanel</button>
            <button class=secondary name=action value=sync_protocols>Синхронизировать протоколы</button>
          </form>
          <p class=muted style="margin-top:10px">Рестарт RosPanel кратко оборвёт VPN-сессии.</p>
        </div>
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
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=ab>
        <h2>A/B по bucket (0–99)</h2>
        <p class=muted>JSON, пример: {{"feature_kill_switch":{{"percent":50}},"new_ui":{{"buckets":"0-19,50"}}}}</p>
        <label>feature_ab_json<textarea name=feature_ab_json rows=10>{html.escape(s.get('feature_ab_json','{{}}'))}</textarea></label>
        <button>Сохранить A/B</button>
      </form>
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
        <label>Bot token<input name=telegram_bot_token value="{html.escape(s.get('telegram_bot_token',''))}" autocomplete=off></label>
        <label>Chat ID<input name=telegram_chat_id value="{html.escape(s.get('telegram_chat_id',''))}"></label>
        <div class=actions><button>Сохранить</button>
        <button class=secondary formaction=/operator/actions name=action value=telegram_test>Тест сообщения</button></div>
      </form>
    </section>

    <section class=card {show('audit')}>
      <h2>Аудит изменений</h2>
      <table><thead><tr><th>Время</th><th>Кто</th><th>IP</th><th>Действие</th><th>Diff</th></tr></thead><tbody>{audit_html}</tbody></table>
    </section>

    <script>
    const tab = new URLSearchParams(location.search).get('tab') || 'dashboard';
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
        if sess and sess.get("u") == USER:
            return {"user": USER, "db": db, "s": s, "ip": ip}
        if basic_auth_ok(self.headers.get("Authorization", "")):
            return {"user": USER, "db": db, "s": s, "ip": ip, "basic": True}
        if require_login_page and self.path.startswith("/operator") and not self.path.startswith("/operator/login"):
            self.reply(200, render_login(), "text/html; charset=utf-8")
            return None
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="QuantumControl"')
        self.end_headers()
        return None

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
        if q:
            like = f"%{q}%"
            rows = db.execute(
                """
                select device, ip, max(ts) as last_ts, max(detail) as detail
                from events
                where device like ? or ip like ? or detail like ?
                group by device
                order by last_ts desc limit ?
                """,
                (like, like, like, limit),
            ).fetchall()
        else:
            rows = db.execute(
                """
                select device, ip, max(ts) as last_ts, max(detail) as detail
                from events where kind='policy'
                group by device order by last_ts desc limit ?
                """,
                (limit,),
            ).fetchall()
        flags = {r[0]: r for r in db.execute("select device, force_banner, request_diagnostic, note, updated_at from device_flags")}
        out = []
        for device, ip, last_ts, detail in rows:
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
            return self.reply(200, json.dumps(status))

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
                "update_url": f"{PUBLIC_BASE}/downloads/{version}/QuantumVPN-{version}-operator-debug-arm64-v8a.apk",
                "update_notifications": True,
                "config_revision": int(s.get("config_revision", "1") or 1),
                "features": features,
                "nodes_recommended": [x.strip() for x in (s.get("nodes_recommended") or "").split(",") if x.strip()],
                "nodes_forbidden": [x.strip() for x in (s.get("nodes_forbidden") or "").split(",") if x.strip()],
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

        if path == "/operator":
            adm = self.admin()
            if not adm:
                return
            tab = query.get("tab", ["dashboard"])[0]
            q = query.get("q", [""])[0]
            flash = query.get("flash", [""])[0]
            rows = db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 100").fetchall()
            protocols = db.execute("select name,enabled from protocols order by name").fetchall()
            audit_rows = db.execute("select ts,actor,ip,action,detail from audit order by ts desc limit 100").fetchall()
            device_rows = self.device_search(db, q if tab == "devices" else "")
            device = self.load_device(db, q) if tab == "devices" and q else None
            users = rospanel_users(q=q if tab == "users" else "")
            return self.reply(
                200,
                render_panel(
                    s,
                    rows,
                    users,
                    protocols,
                    rospanel_summary(),
                    service_status(),
                    audit_rows,
                    device_rows,
                    flash=unquote(flash),
                    section=tab,
                    q=q,
                    device=device,
                ),
                "text/html; charset=utf-8",
            )

        self.reply(404, "Not found", "text/plain")

    def download_file(self, path, head=False):
        root = os.path.realpath(DOWNLOAD_ROOT) + os.sep
        target = os.path.realpath(os.path.join(DOWNLOAD_ROOT, path.removeprefix("/downloads/")))
        if not target.startswith(root) or not os.path.isfile(target):
            return self.reply(404, "Not found", "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Content-Length", str(os.path.getsize(target)))
        self.send_header("Content-Disposition", "attachment")
        self.end_headers()
        if not head:
            with open(target, "rb") as source:
                shutil.copyfileobj(source, self.wfile, 64 * 1024)

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
                return self.reply(201, '{"ok":true}')
            except Exception:
                return self.reply(400, '{"error":"invalid_report"}')

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
            if user != USER or password != PASSWORD:
                time.sleep(0.4)
                return self.reply(401, render_login("Неверный логин или пароль"), "text/html; charset=utf-8")
            if enabled(s, "totp_enabled", False):
                secret = s.get("totp_secret") or ""
                if not secret or not totp_ok(secret, code):
                    return self.reply(401, render_login("Нужен корректный код 2FA"), "text/html; charset=utf-8")
            token = sign_session({"u": USER, "exp": int(time.time()) + SESSION_TTL, "n": secrets.token_hex(8)})
            audit(db, USER, ip, "login", {"ok": True})
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
            except Exception:
                return self.reply(400, '{"error":"invalid_release"}')
            values = {
                "app_version": form.get("app_version", [VERSION])[0][:32],
                "app_version_code": str(vc),
                "min_version_code": str(min_vc),
                "force_update_message": form.get("force_update_message", [""])[0][:400],
                "rollout_percent": str(rollout),
                "app_changelog": form.get("app_changelog", [""])[0][:1000],
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
                "telegram_bot_token": form.get("telegram_bot_token", [""])[0][:200],
                "telegram_chat_id": form.get("telegram_chat_id", [""])[0][:64],
            }
        else:
            return self.reply(400, '{"error":"unknown_section"}')

        if section in ("service", "features", "nodes", "ab") and any(current.get(k) != v for k, v in values.items()):
            values["config_revision"] = str(int(current.get("config_revision", "1") or 1) + 1)
        changes = {k: {"before": current.get(k), "after": v} for k, v in values.items() if current.get(k) != v}
        set_settings(db, values)
        db.execute(
            "insert into events values (?,?,?,?,?)",
            (int(time.time()), "admin", actor, ip, json.dumps(changes, ensure_ascii=False)),
        )
        audit(db, actor, ip, f"policy:{section}", changes)
        db.commit()
        return self.redirect_operator(tab, "Сохранено")


def main():
    port = int(os.environ.get("QV_PORT", "8765"))
    threading.Thread(target=alert_worker, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", port), App)
    cert, key = os.environ.get("QV_TLS_CERT"), os.environ.get("QV_TLS_KEY")
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
