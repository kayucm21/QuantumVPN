#!/usr/bin/env python3
"""QuantumVPN operator control panel (stdlib only) — extended Quantum Control."""
from __future__ import annotations

import base64
import concurrent.futures
import datetime
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import random
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
import sys
from collections import defaultdict, deque
from email.parser import BytesParser
from email.policy import default as email_default
from functools import lru_cache
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

# Optional, isolated WebAuthn wheels; never load code from uploaded resources.
if os.path.isdir("/opt/quantumvpn-operator/deps"):
    sys.path.insert(0, "/opt/quantumvpn-operator/deps")

try:
    import quantumvpn_community as community
except ModuleNotFoundError:
    from tools import quantumvpn_community as community

try:  # Script deployment keeps both modules in the same directory.
    from quantumvpn_control_quality import dependency_evidence, explain_route, quality_snapshot, render_quality, subscription_evidence, validate_backup
except ModuleNotFoundError:
    from tools.quantumvpn_control_quality import dependency_evidence, explain_route, quality_snapshot, render_quality, subscription_evidence, validate_backup

try:
    import quantumvpn_resources as resources
except ModuleNotFoundError:
    from tools import quantumvpn_resources as resources

try:
    from quantumvpn_aurora import aurora_css, aurora_script
except ModuleNotFoundError:
    from tools.quantumvpn_aurora import aurora_css, aurora_script

try:
    import quantumvpn_control_next as control_next
except ModuleNotFoundError:
    from tools import quantumvpn_control_next as control_next

try:
    import quantumvpn_durak as durak
except ModuleNotFoundError:
    from tools import quantumvpn_durak as durak

try:
    import quantumvpn_bot_status as bot_status
except ModuleNotFoundError:
    from tools import quantumvpn_bot_status as bot_status

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
except ImportError:  # Optional at import time; backups fail closed if unavailable.
    AESGCM = None
    Ed25519PrivateKey = None
    Encoding = None
    NoEncryption = None
    PrivateFormat = None
    PublicFormat = None


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
PUBLIC_BASE = os.environ.get("QV_PUBLIC_BASE", "https://pecaocek.ignorelist.com:8443")
# Prefer :8443 until :443 fallback nginx is confirmed live.
DOWNLOAD_BASE = os.environ.get("QV_DOWNLOAD_BASE", "https://pecaocek.ignorelist.com:8443").rstrip("/")
# The reserve URI lives in a root-only file on the host, not in the operator
# database or in the rendered HTML.  It is appended only after RosPanel has
# accepted the device-bound upstream subscription request.
RESERVE_PROFILE_URI_FILE = os.environ.get(
    "QV_RESERVE_PROFILE_URI_FILE", "/etc/quantumvpn-reserve/trojan-uri"
)
REQUIRED_RELEASE_ABIS = ("arm64-v8a", "armeabi-v7a")
PANEL_BUILD = "2.1.1-bot.1"
VERSION = "5.10.12"
VERSION_CODE = 137
DEFAULT_NOTE = "QuantumVPN 5.10.12: стабильный игровой стол, виртуальный банк Q-coins, черновики маршрутизации и публичная страница состояния."
SESSION_TTL = 12 * 3600
SESSION_COOKIE = "qv_session"
CARD_GAME_TICKET_TTL = 6 * 3600
CARD_GAME_WAIT_TTL = 20 * 60
DURAK_SUITS = "SHDC"
DURAK_RANKS = ("6", "7", "8", "9", "10", "J", "Q", "K", "A")
_DURAK_RANK_VALUE = {rank: index for index, rank in enumerate(DURAK_RANKS)}
_DB_INIT_LOCK = threading.Lock()
_DB_READY = False
_LAST_EVENT_CLEANUP = 0
_RATE = defaultdict(deque)
_RATE_LOCK = threading.Lock()
_ALERT_STATE = {"last": {}, "lock": threading.Lock()}

# The same registry drives navigation and page headings. Legacy URLs and POST
# return_tab values remain unchanged; grouping is a presentation-only change.
PAGE_TITLES = {
    "dashboard": ("Командный центр", "Состояние VPN-инфраструктуры и приоритетные события"),
    "fleet": ("Центр флота", "Приложения, подписки и доступность VDS"),
    "quality": ("КОНТРОЛЬ КАЧЕСТВА", "Подписка, маршруты и доказательства восстановления"),
    "latency": ("Ноды", "Реестр, TCP-задержка и распределение нагрузки"),
    "automation": ("Автопилот", "Проверки и автоматические действия с заданными ограничениями"),
    "users": ("Пользователи", "Подписчики и активность"),
    "service": ("Подписки", "Доступ, протоколы и обслуживание сервиса"),
    "devices": ("Устройства", "История подключений, флаги и диагностика"),
    "support": ("Поддержка", "Обращения пользователей и заметки оператора"),
    "donations": ("Пожертвования", "История добровольной поддержки сервиса"),
    "routing": ("Маршрутизация и DNS", "Проверка целей, черновики и подписанные правила"),
    "release": ("Релизы", "Сборки APK и действующее расписание публикации"),
    "resources": ("РЕСУРСЫ И ИСПРАВЛЕНИЯ", "Подписанное оформление, тестовая группа и откат"),
    "features": ("Функции приложения", "Удалённые флаги и условия их применения"),
    "branding": ("Оформление", "Тексты, акценты и доступные параметры интерфейса"),
    "incidents": ("События", "Инциденты и состояние сервисов"),
    "logs": ("Живые логи", "События панели без перезагрузки страницы"),
    "reports": ("Отчёты", "Агрегированная статистика и экспорт"),
    "audit": ("Аудит", "Журнал действий администраторов"),
    "security": ("Безопасность", "Доступ, проверка запросов и защитные ограничения"),
    "admins": ("Администраторы", "Учётные записи и роли доступа"),
    "ai": ("ИИ‑СОВЕТНИК", "Локальный Qwen: анализ метрик и рекомендации"),
    "cards": ("Игры и награды", "Карточные столы и виртуальные Q-coins"),
    "integrations": ("Система", "Резервные копии, Telegram-бот и интеграции"),
}
AURORA_NAV_GROUPS = (
    ("overview", "Обзор", "▦", ("dashboard", "fleet", "quality")),
    ("nodes", "Ноды", "▤", ("latency", "automation")),
    ("clients", "Клиенты", "♧", ("users", "service", "devices", "support", "donations")),
    ("routes", "Маршруты", "⇄", ("routing",)),
    ("releases", "Релизы", "◇", ("release", "resources", "features", "branding")),
    ("events", "События", "≡", ("incidents", "logs", "reports", "audit")),
    ("security", "Защита", "♢", ("security", "admins", "ai")),
    ("games", "Игры", "♠", ("cards",)),
    ("system", "Система", "⚙", ("integrations",)),
)


def aurora_navigation(section: str, actor_role: str = "owner") -> tuple[str, str]:
    links, child_links = [], []
    for key, label, glyph, members in AURORA_NAV_GROUPS:
        allowed = tuple(tab for tab in members if tab != "admins" or actor_role == "owner")
        active = section in allowed
        links.append(
            f'<a class="aurora-group {"active" if active else ""}" data-group="{key}" '
            f'href="/operator?tab={allowed[0]}"'
            + (' aria-current="page"' if active else '')
            + f'><span class=nav-ico aria-hidden=true>{glyph}</span><span>{label}</span></a>'
        )
        if active:
            for tab in allowed:
                title = PAGE_TITLES[tab][0]
                links_title = {"dashboard": "Сводка", "latency": "Все ноды", "routing": "Правила и DNS", "release": "APK", "resources": "Ресурсы", "features": "Функции", "incidents": "Инциденты", "ai": "Qwen", "cards": "Столы и награды", "integrations": "Бот и резерв"}
                child_links.append(
                    f'<a class="{"active" if tab == section else ""}" href="/operator?tab={tab}"'
                    + (' aria-current="page"' if tab == section else '')
                    + f'>{html.escape(links_title.get(tab, title.capitalize()))}</a>'
                )
    return '<nav class="tabs aurora-nav" aria-label="Разделы панели">' + ''.join(links) + '</nav>', '<nav class=aurora-subnav aria-label="Страницы раздела">' + ''.join(child_links) + '</nav>'

ROUTING_PROFILES = {
    "balanced": "Оптимальный — локальные сервисы напрямую, остальное через VPN",
    "whitelist": "Белый список — напрямую только явно разрешённые адреса",
    "proxy_all": "Через VPN — весь трафик, кроме технических исключений",
}
ROUTING_DNS_MODES = {
    "vpn_only": "DNS работает только внутри VPN",
    "system": "Системный DNS (без блокировки на стороне приложения)",
}
ROUTING_SETTING_KEYS = (
    "routing_enabled",
    "routing_profile",
    "routing_adblock_enabled",
    "routing_dns_mode",
    "routing_dns_resolver",
    "routing_direct_domains",
    "routing_proxy_domains",
    "routing_block_domains",
    "routing_direct_cidrs",
    "routing_proxy_cidrs",
)
MAX_ROUTING_ITEMS = 2_000
# Target inspection is intentionally small and bounded.  The operator panel is
# not a network scanner: it only probes a short, explicitly entered list over
# TCP/443 after filtering every resolved address to public internet space.
MAX_ROUTING_SCAN_TARGETS = 24
MAX_ROUTING_SCAN_ADDRESSES = 3
ROUTING_SCAN_CONNECT_TIMEOUT_SECONDS = 1.2
ROUTING_SCAN_WALL_TIMEOUT_SECONDS = 10.0

# The assistant is intentionally local-only.  Keeping the endpoint fixed to
# loopback makes it impossible for an operator setting to turn the panel into
# an SSRF proxy or to send health data, subscriber information, or secrets to
# an external AI service.
QWEN_LOCAL_ENDPOINT = "http://127.0.0.1:11434"
QWEN_DEFAULT_MODEL = "qwen3:0.6b"
AI_MIN_INTERVAL_SECONDS = 300
AI_MAX_INTERVAL_SECONDS = 24 * 3600
_AI_RUN_LOCK = threading.Lock()
_BOT_STATE_LOCK = threading.Lock()
_BOT_RUNTIME = {"polling": False, "webhook": None, "state": "starting"}


def telegram_bot_token(s: dict) -> str:
    """Prefer the root-owned service environment over SQLite.

    Secrets entered in a browser can leak through backups or accidental HTML
    rendering. The VDS environment file is intentionally outside both.
    """
    return (os.environ.get("QV_TELEGRAM_BOT_TOKEN") or s.get("telegram_bot_token") or "").strip()


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
        with open(path, "wb") as file:
            file.write(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    with open(path, "rb") as file:
        return file.read()


def backup_key() -> bytes:
    """Load or create the local AES-256 key used for encrypted backups."""
    raw = os.environ.get("QV_BACKUP_KEY", "").strip()
    if raw:
        try:
            key = bytes.fromhex(raw) if re.fullmatch(r"[0-9a-fA-F]{64}", raw) else base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception as exc:
            raise RuntimeError("QV_BACKUP_KEY must be 32-byte hex or base64") from exc
        if len(key) != 32:
            raise RuntimeError("QV_BACKUP_KEY must decode to 32 bytes")
        return key
    path = os.path.join(ROOT, "backup.key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as stream:
            key = stream.read()
    else:
        key = secrets.token_bytes(32)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
    if len(key) != 32:
        raise RuntimeError("backup.key is invalid; refusing to create an unencrypted backup")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def encrypt_backup_archive(archive: str) -> str:
    """Encrypt a backup with AES-256-GCM and remove its plaintext copy."""
    if AESGCM is None:
        raise RuntimeError("cryptography is required for encrypted backups")
    nonce = secrets.token_bytes(12)
    with open(archive, "rb") as stream:
        plaintext = stream.read()
    ciphertext = AESGCM(backup_key()).encrypt(nonce, plaintext, b"QuantumControl backup v1")
    encrypted = archive + ".enc"
    temporary = encrypted + ".part"
    with open(temporary, "wb") as stream:
        stream.write(b"QVBK1")
        stream.write(nonce)
        stream.write(ciphertext)
    os.chmod(temporary, 0o600)
    os.replace(temporary, encrypted)
    os.remove(archive)
    return encrypted


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


def card_game_ticket(device: str, table_id: str) -> str:
    """Create a short-lived, device-bound ticket for the card lobby.

    The ticket grants access only to one table.  It cannot be used as an
    operator session because the scope is verified by card_game_ticket_data.
    """
    return sign_session({
        "scope": "card_game",
        "device": device,
        "table": table_id,
        "exp": int(time.time()) + CARD_GAME_TICKET_TTL,
        "n": secrets.token_hex(8),
    })


def card_game_ticket_data(token: str):
    payload = verify_session(token)
    if not payload or payload.get("scope") != "card_game":
        return None
    device = str(payload.get("device") or "")
    table = str(payload.get("table") or "")
    if not re.fullmatch(r"[a-f0-9]{16,64}", device) or not re.fullmatch(r"[a-f0-9]{12}", table):
        return None
    return payload


def card_game_name(value: str) -> str:
    """Normalize a display name without accepting control or markup input."""
    name = " ".join((value or "").strip().split())
    if not 2 <= len(name) <= 24:
        raise ValueError("Имя должно содержать от 2 до 24 символов")
    if any(ord(char) < 32 for char in name):
        raise ValueError("Имя содержит недопустимые символы")
    return name


def durak_new_game() -> dict:
    """Compatibility entry point; all rules live in the tested pure engine."""
    return durak.new_game()


def durak_rank(card: str) -> str:
    return durak.rank(card)


def durak_beats(defense: str, attack: str, trump: str) -> bool:
    return durak.beats(defense, attack, trump)


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


def scheduled_release_missing_abis(version: str):
    """Return required APK ABIs that are missing, empty, or outside DOWNLOAD_ROOT."""
    root = os.path.realpath(DOWNLOAD_ROOT)
    missing = []
    for abi in REQUIRED_RELEASE_ABIS:
        name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
        path = os.path.join(DOWNLOAD_ROOT, version, name)
        try:
            # Do not allow a scheduled release to be satisfied by a symlink that
            # resolves outside the public download directory.
            if os.path.commonpath((root, os.path.realpath(path))) != root:
                missing.append(abi)
                continue
            if not os.path.isfile(path) or os.path.getsize(path) <= 0:
                missing.append(abi)
        except (OSError, ValueError):
            missing.append(abi)
    return missing


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
                create table if not exists bot_receiver_state (
                    scope text primary key,
                    next_update integer not null default 0,
                    updated_at integer not null default 0
                );
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
                create table if not exists delivery_evidence (
                    device text primary key,
                    version_code integer not null default 0,
                    policy_at integer not null default 0,
                    update_at integer not null default 0,
                    download_at integer not null default 0,
                    install_at integer not null default 0,
                    notification_permission text not null default 'неизвестно'
                );
                create table if not exists ai_observations (
                    id integer primary key autoincrement,
                    ts integer not null,
                    trigger text not null,
                    status text not null,
                    advice text not null,
                    telegram_sent integer not null default 0,
                    before_json text not null default '{}'
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
                create table if not exists routing_revisions (
                    id integer primary key autoincrement,
                    revision integer not null,
                    created_at integer not null,
                    actor text not null,
                    state text not null,
                    note text not null default '',
                    payload text not null
                );
                create table if not exists card_tables (
                    id text primary key,
                    created_at integer not null,
                    updated_at integer not null,
                    state text not null default 'waiting',
                    host_device text not null,
                    host_name text not null,
                    guest_device text not null default '',
                    guest_name text not null default '',
                    last_action text not null default '',
                    game_json text not null default ''
                );
                create table if not exists card_wallets (
                    device text primary key,
                    display_name text not null default '',
                    q_coins integer not null default 1200,
                    created_at integer not null default 0,
                    updated_at integer not null default 0
                );
                create table if not exists support_tickets (
                    id integer primary key autoincrement,
                    created_at integer not null,
                    updated_at integer not null,
                    closed_at integer not null default 0,
                    source text not null default 'operator',
                    device text not null default '',
                    subject text not null,
                    body text not null default '',
                    admin_note text not null default ''
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
                create index if not exists idx_routing_revisions_created on routing_revisions(created_at desc);
                create index if not exists idx_routing_revisions_revision on routing_revisions(revision desc);
                create index if not exists idx_card_tables_state_updated on card_tables(state, updated_at desc);
                create index if not exists idx_card_wallets_updated on card_wallets(updated_at desc);
                create index if not exists idx_support_tickets_state_updated on support_tickets(closed_at, updated_at desc);
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
                "reserve_profile_enabled": "1",
                # Presence in the control panel does not manufacture a peer:
                # actual AmneziaWG keys/config are issued by the subscription.
                "amneziawg_port": "59333",
                "subscription_category_title": "Подписка",
                "subscription_category_description": "Управление доступом и резервным профилем",
                "subscription_main_label": "Встроенная подписка включена",
                "reserve_profile_label": "Публиковать пятый профиль «Резерв TLS»",
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
                # Routing is maintained independently from APK releases.  The
                # app must still explicitly support this signed policy before
                # it can apply it; the panel never rewrites a subscription.
                "routing_enabled": "1",
                "routing_profile": "balanced",
                "routing_adblock_enabled": "1",
                "routing_dns_mode": "vpn_only",
                "routing_dns_resolver": "https://dns.adguard-dns.com/dns-query",
                "routing_direct_domains": "",
                "routing_proxy_domains": "youtube.com,googlevideo.com,telegram.org,t.me,github.com,discord.com,discord.gg",
                "routing_block_domains": "",
                "routing_direct_cidrs": "",
                "routing_proxy_cidrs": "",
                "routing_revision": "1",
                "routing_staging_enabled": "0",
                "routing_staging_revision": "0",
                "routing_staging_rollout_percent": "10",
                "routing_staging_payload": "{}",
                # A draft is deliberately kept separate from the signed live
                # policy.  It gives the operator a visible Save action without
                # accidentally changing routes on devices.
                "routing_draft_payload": "{}",
                "routing_draft_updated_at": "0",
                # Saved operator-only output of the bounded target advisor.
                # It is never included in /api/client/routing or consumed by
                # APKs until a reviewed revision is explicitly published.
                "routing_scan_targets": "youtube.com,discord.com,discord.gg",
                "routing_last_scan": "[]",
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
                "telegram_daily_digest_enabled": "0",
                "telegram_digest_time_msk": "09:00",
                "telegram_digest_last_sent_date": "",
                "telegram_digest_last_attempt": "0",
                # Qwen is an advisory-only local assistant. It receives a
                # compact aggregate of service/node health, never subscriber
                # records, API keys, profile URIs, or raw request logs.
                "ai_advisor_enabled": "1",
                "ai_model": QWEN_DEFAULT_MODEL,
                "ai_interval_seconds": "900",
                "ai_telegram_enabled": "1",
                "ai_last_run": "0",
                "ai_last_status": "ожидание",
                "ai_last_advice": "Модель ещё не выполнила анализ.",
                "ai_last_error": "",
                "ai_last_notification_hash": "",
                "ai_last_notification_at": "0",
                "health_monitor_enabled": "1",
                "health_monitor_interval_seconds": "60",
                "latency_optimization_enabled": "1",
                "latency_probe_interval": "30",
                "latency_max_ms": "120",
                "latency_probe_targets": "1.1.1.1:443,8.8.8.8:443",
                # One line per node: title|host:port|latitude|longitude|location.
                # The initial VDS location comes from a public GeoIP lookup on
                # 2026-10-01 and can be changed in the Nodes page.
                "node_map_config": "Основной VDS|31.76.68.243:443|48.8534|2.3488|Париж, Франция",
                "latency_state": "unknown",
                "latency_last_probe": "0",
                "latency_best_ms": "0",
                "load_balancer_enabled": "1",
                "load_balancer_strategy": "latency_health",
                "load_balancer_max_latency_ms": "250",
                "load_balancer_last_target": "",
                "load_balancer_last_decision": "0",
                "auto_quarantine_enabled": "1",
                "auto_quarantine_failures": "3",
                "auto_quarantine_recovery_checks": "2",
                "auto_quarantine_ttl_minutes": "30",
                "node_quarantine": "{}",
                # A manual drain is an operator-controlled exclusion. It is
                # separate from auto quarantine so a recovered probe never
                # silently returns a node that is being serviced.
                "node_drains": "{}",
                "rate_limit_per_min": "120",
                "webhook_enabled": "0",
                "webhook_url": "",
                "webhook_secret": "",
                "webhook_events": "incident,release,maintenance,diagnostic",
                # The code is hashed in SQLite and is never returned through a
                # client API.  It intentionally is not the administrator's
                # password: APKs must never handle panel credentials.
                "card_game_enabled": "1",
                "card_game_access_hash": "",
                "card_game_wait_minutes": "20",
                "card_game_start_coins": "1200",
                # Q-coins are closed-loop virtual game points only.  A stake
                # is debited from both players at deal start and the complete
                # virtual pot is credited to the winner exactly once.
                "card_game_stake_q_coins": "25",
                # The public status page exposes no operator data.  Downloads
                # close automatically during maintenance and can also be
                # paused explicitly by an owner.
                "public_download_enabled": "1",
                "public_status_note_en": "Live service information for QuantumVPN users.",
            }
            for key, value in defaults.items():
                db.execute("insert or ignore into settings values (?,?)", (key, value))
            # The Android core already supports AmneziaWG .conf profiles. Keep
            # the sixth protocol visible even though a HWID-bound subscription
            # cannot be fetched generically by the operator panel.
            db.execute("insert or ignore into protocols values (?,1)", ("amneziawg",))
            card_columns = {row[1] for row in db.execute("pragma table_info(card_tables)")}
            if "game_json" not in card_columns:
                db.execute("alter table card_tables add column game_json text not null default ''")
            # The wallet contains virtual Q-coins only. No purchase, withdrawal
            # or exchange data is stored anywhere in the operator database.
            db.execute(
                "create table if not exists card_wallets (device text primary key, display_name text not null default '', q_coins integer not null default 1200, created_at integer not null default 0, updated_at integer not null default 0)"
            )
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
            community.migrate(db)
            control_next.migrate(db)
            _DB_READY = True
        if now - _LAST_EVENT_CLEANUP >= 3600:
            db.execute("delete from events where ts < ?", (now - 14 * 86400,))
            db.execute("delete from audit where ts < ?", (now - 90 * 86400,))
            db.execute("delete from server_health where ts < ?", (now - 7 * 86400,))
            db.execute("delete from delivery_evidence where max(policy_at,update_at) < ?", (now - 90 * 86400,))
            db.execute("delete from ai_observations where ts < ?", (now - 30 * 86400,))
            community.cleanup(db, now)
            _LAST_EVENT_CLEANUP = now
        db.commit()
    return db


def settings(db):
    return dict(db.execute("select key, value from settings"))


def set_settings(db, values: dict):
    policy_change = bool(set(values) & {"maintenance", "maintenance_schedule_enabled", "maintenance_start", "maintenance_end", "app_version", "app_version_code"})
    before = settings(db) if policy_change else None
    for k, v in values.items():
        db.execute("insert or replace into settings values (?,?)", (k, str(v)))
    if before is not None:
        after = dict(before, **{k: str(v) for k, v in values.items()})
        if effective_maintenance(before) != effective_maintenance(after):
            active = effective_maintenance(after)
            kind = "maintenance" if active else "recovery"
            community.append_event(db, kind, "Технические работы" if active else "Сервис восстановлен",
                after.get("maintenance_message", "") if active else "Работы завершены. Можно снова подключаться к VPN.",
                f"{kind}:{time.time_ns()}")
        if after.get("app_version_code") != before.get("app_version_code"):
            community.append_event(db, "release", "Обновление QuantumVPN " + after.get("app_version", ""),
                after.get("app_changelog", "Доступна новая версия приложения."),
                "release:" + after.get("app_version_code", ""))


def enabled(s, key, default=True):
    return s.get(key, "1" if default else "0") == "1"


def reserve_profile_uri() -> str:
    """Read the server-owned reserve profile without ever exposing its secret.

    The operator receives a profile URI from a 0600 root-owned file.  Keeping it
    outside SQLite prevents accidental inclusion in exports, support bundles and
    the operator page.  The restrictive shape check also makes a damaged file a
    fail-closed condition rather than a malformed subscription response.
    """
    try:
        value = open(RESERVE_PROFILE_URI_FILE, "r", encoding="utf-8").read().strip()
    except OSError:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme.lower() != "trojan"
        or not parsed.hostname
        or not port
        or port < 1
        or port > 65535
        or len(value) > 2048
    ):
        return ""
    return value


def subscription_inspection_headers() -> tuple[dict, str]:
    """Reuse an existing Android binding for the exact configured subscription.

    Never register a made-up HWID or choose a different subscriber. Hardware
    identifiers stay on the VDS and are sent only to the configured upstream.
    """
    headers = {"User-Agent": "QuantumVPN-Android"}
    token = urlsplit(UPSTREAM).path.rstrip("/").rsplit("/", 1)[-1]
    source = "Ручная проверка без HWID"
    if not token or not os.path.isfile(ROSPANEL_DB):
        return headers, source
    db = None
    try:
        db = sqlite3.connect(f"file:{ROSPANEL_DB}?mode=ro", uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        row = db.execute(
            "select d.hwid,d.os,d.os_version,d.model from devices d join users u on u.id=d.user_id "
            "where u.sub_token=? and u.enabled=1 and lower(d.os)='android' and d.hwid!='' "
            "order by d.last_seen desc limit 1", (token,),
        ).fetchone()
        if row:
            for field, column in (("X-Hwid", "hwid"), ("X-Device-Os", "os"), ("X-Ver-Os", "os_version"), ("X-Device-Model", "model")):
                value = str(row[column] or "")[:256]
                if value and "\r" not in value and "\n" not in value:
                    headers[field] = value
            if "X-Hwid" in headers:
                source = "Ручная проверка с зарегистрированным Android HWID"
    except sqlite3.Error:
        pass
    finally:
        if db is not None:
            db.close()
    return headers, source


def admitted_subscription_text(raw: bytes) -> str | None:
    """Recognize whole profile bodies, never links embedded in an error page.

    Upstream authorization remains authoritative. This format check prevents a
    redirect/login HTML response from becoming a reserve-only subscription or
    a credential issuer just because its text contains ``://``.
    """
    if not raw or len(raw) > 4 * 1024 * 1024:
        return None
    try:
        text = raw.decode("utf-8").strip()
        if not text.startswith(("{", "[")) and "://" not in text:
            compact = re.sub(r"\s+", "", text)
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode("utf-8").strip()
    except (ValueError, UnicodeError):
        return None
    if not text or "<" in text or ">" in text:
        return None
    schemes = {"vless", "vmess", "trojan", "hysteria", "hysteria2", "hy2",
               "ss", "ssr", "tuic", "wireguard", "wg", "amneziawg", "awg", "socks", "socks5"}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and all(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+", line)
                     and line.split(":", 1)[0].lower() in schemes for line in lines):
        return text
    # Native JSON/WireGuard subscriptions are preserved, not mixed with URIs.
    if text.startswith(("{", "[")):
        try:
            value = json.loads(text)
            configurations = value if isinstance(value, list) else [value]
            for config in configurations:
                if not isinstance(config, dict):
                    continue
                for outbound in config.get("outbounds", []) + config.get("endpoints", []):
                    if isinstance(outbound, dict) and str(outbound.get("type", outbound.get("protocol", ""))).lower() in schemes | {"shadowsocks"}:
                        return text
        except (ValueError, TypeError):
            pass
    if (re.search(r"(?im)^\s*\[Interface\]\s*$", text)
            and re.search(r"(?im)^\s*\[Peer\]\s*$", text)
            and all(re.search(r"(?im)^\s*" + key + r"\s*=\s*\S+", text)
                    for key in ("PrivateKey", "PublicKey", "Endpoint"))):
        return text
    return None


def managed_subscription(upstream_headers, s: dict) -> tuple[bytes, bool]:
    """Fetch the authenticated upstream subscription and append verified reserve.

    RosPanel remains the authority for subscriber access: device/HWID headers are
    forwarded unchanged, so an unauthenticated request cannot obtain the reserve
    profile.  A failed reserve file leaves the upstream list untouched.
    """
    forwarded = {"User-Agent": (upstream_headers.get("User-Agent") or "QuantumVPN-Android")[:256]}
    for key in ("X-Hwid", "X-Device-Os", "X-Device-Model", "X-Ver-Os", "Accept"):
        value = upstream_headers.get(key)
        if value:
            forwarded[key] = value[:256]
    with urlopen(Request(UPSTREAM, headers=forwarded), timeout=20) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    text = admitted_subscription_text(raw)
    if text is None or text.startswith(("{", "[")):
        return raw, False

    reserve = reserve_profile_uri() if enabled(s, "reserve_profile_enabled", True) else ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    appended = bool(reserve and reserve not in lines)
    if appended:
        lines.append(reserve)
    return base64.b64encode(("\n".join(lines) + "\n").encode("utf-8")), appended


def normalize_routing_domains(raw: str) -> list[str]:
    """Return a small, canonical domain list suitable for a client policy.

    This intentionally accepts host/suffix names only.  URLs, wildcards,
    regexes and geosite directives would make the policy interpreter
    ambiguous and could turn an admin typo into a broad traffic rule.
    """
    items: list[str] = []
    for value in re.split(r"[,;\r\n]+", raw or ""):
        value = value.strip().lower().rstrip(".")
        if not value:
            continue
        if value.startswith("*."):
            value = value[2:]
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", value):
            raise ValueError(f"Некорректный домен в маршрутизации: {value[:80]}")
        if value not in items:
            items.append(value)
        if len(items) > MAX_ROUTING_ITEMS:
            raise ValueError("Слишком много доменов в одном списке маршрутизации.")
    return items


def normalize_routing_cidrs(raw: str) -> list[str]:
    """Canonicalise CIDRs and reject malformed or overlarge operator input."""
    items: list[str] = []
    for value in re.split(r"[,;\r\n]+", raw or ""):
        value = value.strip()
        if not value:
            continue
        try:
            if "/" not in value:
                address = ipaddress.ip_address(value)
                value = f"{address}/{32 if address.version == 4 else 128}"
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректный IP/CIDR в маршрутизации: {value[:80]}") from exc
        canonical = network.with_prefixlen
        if canonical not in items:
            items.append(canonical)
        if len(items) > MAX_ROUTING_ITEMS:
            raise ValueError("Слишком много CIDR в одном списке маршрутизации.")
    return items


def _is_public_routing_address(value: str) -> bool:
    """Return True only for globally routable unicast addresses.

    The route advisor must never be usable as a probe for loopback, private,
    link-local or otherwise reserved VDS addresses.  DNS results are filtered
    again immediately before connecting, so a hostname cannot turn into an
    internal target through DNS rebinding.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
    )


def normalize_routing_scan_targets(raw: str) -> list[tuple[str, str]]:
    """Parse a short operator-supplied list of domains or public IP addresses.

    URLs, ports and wildcard expressions are deliberately not accepted.  The
    probe port is fixed to 443 and only domain names or public IPs can reach
    the resolver, keeping the feature useful for routing while preventing it
    from becoming an SSRF primitive.
    """
    targets: list[tuple[str, str]] = []
    for value in re.split(r"[,;\r\n]+", raw or ""):
        value = value.strip().lower().rstrip(".")
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            domain = normalize_routing_domains(value)[0] if value else ""
            item = ("domain", domain)
        else:
            if not _is_public_routing_address(str(address)):
                raise ValueError("Для проверки разрешены только публичные IP-адреса.")
            item = ("ip", str(address))
        if item not in targets:
            targets.append(item)
        if len(targets) > MAX_ROUTING_SCAN_TARGETS:
            raise ValueError(f"Можно проверить не более {MAX_ROUTING_SCAN_TARGETS} целей за один запуск.")
    if not targets:
        raise ValueError("Добавьте хотя бы один домен или публичный IP для проверки.")
    return targets


def _routing_scan_addresses(kind: str, target: str) -> list[str]:
    if kind == "ip":
        return [target] if _is_public_routing_address(target) else []
    try:
        rows = socket.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses: list[str] = []
    for _, _, _, _, sockaddr in rows:
        address = str(sockaddr[0])
        if _is_public_routing_address(address) and address not in addresses:
            addresses.append(address)
        if len(addresses) >= MAX_ROUTING_SCAN_ADDRESSES:
            break
    return addresses


def _routing_tcp_latency_ms(address: str) -> int | None:
    """Measure a TCP handshake to a public address on port 443, not ICMP."""
    if not _is_public_routing_address(address):
        return None
    sock = None
    started = time.monotonic()
    try:
        sock = socket.create_connection((address, 443), timeout=ROUTING_SCAN_CONNECT_TIMEOUT_SECONDS)
        return max(1, round((time.monotonic() - started) * 1000))
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _domain_matches_routing_rule(target: str, domains: list[str]) -> bool:
    return any(target == domain or target.endswith("." + domain) for domain in domains)


def routing_recommendation(payload: dict, kind: str, target: str) -> tuple[str, str]:
    """Return an explainable recommendation from the signed policy shape.

    This is a deterministic local route advisor, not a black-box or a remote
    AI model.  It never changes an active policy itself: the operator still
    reviews the suggestion and explicitly publishes a revision.
    """
    rules = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}
    if kind == "domain":
        if _domain_matches_routing_rule(target, rules.get("block_domains") or []):
            return "block", "Уже совпадает с блок-листом"
        if _domain_matches_routing_rule(target, rules.get("direct_domains") or []):
            return "direct", "Уже идёт напрямую"
        if _domain_matches_routing_rule(target, rules.get("proxy_domains") or []):
            return "proxy", "Уже направляется через VPN"
    else:
        address = ipaddress.ip_address(target)
        for raw in rules.get("direct_cidrs") or []:
            if address in ipaddress.ip_network(raw, strict=False):
                return "direct", "Уже совпадает с прямой сетью"
        for raw in rules.get("proxy_cidrs") or []:
            if address in ipaddress.ip_network(raw, strict=False):
                return "proxy", "Уже направляется через VPN"
    profile = payload.get("profile")
    if profile in ("whitelist", "proxy_all"):
        return "proxy", "По умолчанию этот профиль использует VPN"
    return "observe", "В оптимальном профиле решение остаётся за оператором"


def _scan_routing_target(payload: dict, kind: str, target: str) -> dict:
    addresses = _routing_scan_addresses(kind, target)
    samples = []
    for address in addresses:
        latency_ms = _routing_tcp_latency_ms(address)
        samples.append({"address": address, "latency_ms": latency_ms})
    successful = [sample["latency_ms"] for sample in samples if sample["latency_ms"] is not None]
    recommendation, reason = routing_recommendation(payload, kind, target)
    return {
        "target": target,
        "kind": kind,
        "addresses": samples,
        "latency_ms": min(successful) if successful else None,
        "status": "ok" if successful else ("timeout" if addresses else "unresolved"),
        "recommendation": recommendation,
        "reason": reason,
        "checked_at": int(time.time()),
    }


def scan_routing_targets(raw: str, payload: dict) -> list[dict]:
    """Safely inspect up to 24 public targets in parallel with a hard budget."""
    targets = normalize_routing_scan_targets(raw)
    results: list[dict] = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets)))
    futures = [executor.submit(_scan_routing_target, payload, kind, target) for kind, target in targets]
    try:
        for future in concurrent.futures.as_completed(futures, timeout=ROUTING_SCAN_WALL_TIMEOUT_SECONDS):
            try:
                results.append(future.result())
            except (OSError, ValueError):
                # Individual lookup/probe failures become an explicit unknown
                # result instead of aborting the entire reviewed scan.
                continue
    except concurrent.futures.TimeoutError:
        pass
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
    order = {target: index for index, (_, target) in enumerate(targets)}
    return sorted(results, key=lambda item: order.get(item["target"], len(order)))


def routing_payload(s: dict, revision: int | None = None) -> dict:
    """Build the only routing schema that is allowed to leave the panel.

    All list values are parsed here, not trusted as raw textarea content.  A
    future APK can therefore consume the endpoint without having to interpret
    arbitrary config syntax delivered by a web panel.
    """
    profile = s.get("routing_profile", "balanced")
    if profile not in ROUTING_PROFILES:
        profile = "balanced"
    dns_mode = s.get("routing_dns_mode", "vpn_only")
    if dns_mode not in ROUTING_DNS_MODES:
        dns_mode = "vpn_only"
    resolver = (s.get("routing_dns_resolver") or "").strip()
    if resolver and not resolver.startswith("https://"):
        resolver = ""
    return {
        "schema": 1,
        "revision": int(revision if revision is not None else s.get("routing_revision", "1") or 1),
        "enabled": enabled(s, "routing_enabled", True),
        "profile": profile,
        "dns": {
            "mode": dns_mode,
            "resolver": resolver[:512],
        },
        "adblock": {"enabled": enabled(s, "routing_adblock_enabled", True)},
        "rules": {
            "direct_domains": normalize_routing_domains(s.get("routing_direct_domains", "")),
            "proxy_domains": normalize_routing_domains(s.get("routing_proxy_domains", "")),
            "block_domains": normalize_routing_domains(s.get("routing_block_domains", "")),
            "direct_cidrs": normalize_routing_cidrs(s.get("routing_direct_cidrs", "")),
            "proxy_cidrs": normalize_routing_cidrs(s.get("routing_proxy_cidrs", "")),
        },
    }


def routing_settings_from_payload(payload: dict) -> dict:
    """Validate a stored staging/history snapshot before it becomes active."""
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise ValueError("Некорректный снимок маршрутизации.")
    rules = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}
    dns = payload.get("dns") if isinstance(payload.get("dns"), dict) else {}
    profile = payload.get("profile") if payload.get("profile") in ROUTING_PROFILES else "balanced"
    dns_mode = dns.get("mode") if dns.get("mode") in ROUTING_DNS_MODES else "vpn_only"
    resolver = str(dns.get("resolver") or "").strip()
    if resolver and not resolver.startswith("https://"):
        raise ValueError("DNS resolver должен использовать HTTPS.")

    def saved_domains(name: str) -> str:
        raw = rules.get(name) or []
        if not isinstance(raw, list):
            raise ValueError("Некорректный доменный список маршрутизации.")
        return ",".join(normalize_routing_domains(",".join(str(x) for x in raw)))

    def saved_cidrs(name: str) -> str:
        raw = rules.get(name) or []
        if not isinstance(raw, list):
            raise ValueError("Некорректный CIDR список маршрутизации.")
        return ",".join(normalize_routing_cidrs(",".join(str(x) for x in raw)))

    adblock = payload.get("adblock") if isinstance(payload.get("adblock"), dict) else {}
    return {
        "routing_enabled": "1" if payload.get("enabled", True) else "0",
        "routing_profile": profile,
        "routing_adblock_enabled": "1" if adblock.get("enabled", True) else "0",
        "routing_dns_mode": dns_mode,
        "routing_dns_resolver": resolver[:512],
        "routing_direct_domains": saved_domains("direct_domains"),
        "routing_proxy_domains": saved_domains("proxy_domains"),
        "routing_block_domains": saved_domains("block_domains"),
        "routing_direct_cidrs": saved_cidrs("direct_cidrs"),
        "routing_proxy_cidrs": saved_cidrs("proxy_cidrs"),
    }


def routing_candidate_from_form(form: dict) -> dict:
    """Validate form input by round-tripping through the public schema."""
    candidate = {
        "routing_enabled": "1" if "routing_enabled" in form else "0",
        "routing_profile": form.get("routing_profile", ["balanced"])[0],
        "routing_adblock_enabled": "1" if "routing_adblock_enabled" in form else "0",
        "routing_dns_mode": form.get("routing_dns_mode", ["vpn_only"])[0],
        "routing_dns_resolver": (form.get("routing_dns_resolver", [""])[0] or "").strip()[:512],
        "routing_direct_domains": form.get("routing_direct_domains", [""])[0],
        "routing_proxy_domains": form.get("routing_proxy_domains", [""])[0],
        "routing_block_domains": form.get("routing_block_domains", [""])[0],
        "routing_direct_cidrs": form.get("routing_direct_cidrs", [""])[0],
        "routing_proxy_cidrs": form.get("routing_proxy_cidrs", [""])[0],
    }
    if candidate["routing_profile"] not in ROUTING_PROFILES:
        raise ValueError("Неизвестный профиль маршрутизации.")
    if candidate["routing_dns_mode"] not in ROUTING_DNS_MODES:
        raise ValueError("Неизвестный режим DNS.")
    if candidate["routing_dns_resolver"] and not candidate["routing_dns_resolver"].startswith("https://"):
        raise ValueError("DNS resolver должен использовать HTTPS.")
    payload = routing_payload(candidate, revision=1)
    return routing_settings_from_payload(payload)


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def routing_signing_key():
    """Create a local Ed25519 key once; the private half never leaves ROOT."""
    if Ed25519PrivateKey is None:
        return None
    path = os.path.join(ROOT, "routing-ed25519.key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as stream:
            raw = stream.read()
    else:
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    if len(raw) != 32:
        raise RuntimeError("routing-ed25519.key is invalid")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return Ed25519PrivateKey.from_private_bytes(raw)


def signed_routing_envelope(payload: dict, channel: str) -> dict:
    """Envelope for a future APK with a pinned public Ed25519 verification key."""
    document = canonical_json(payload)
    result = {
        "schema": 1,
        "channel": channel,
        "payload": payload,
        "sha256": hashlib.sha256(document).hexdigest(),
        "issued_at": int(time.time()),
        "signature": "",
        "public_key": "",
        "signature_algorithm": "ed25519",
    }
    key = routing_signing_key()
    if key is None or Encoding is None or PublicFormat is None:
        result["signature_algorithm"] = "unavailable"
        return result
    result["signature"] = b64url(key.sign(document))
    result["public_key"] = b64url(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return result


def record_routing_revision(db, revision: int, actor: str, state: str, payload: dict, note: str = ""):
    db.execute(
        "insert into routing_revisions(revision,created_at,actor,state,note,payload) values (?,?,?,?,?,?)",
        (int(revision), int(time.time()), actor[:64], state[:24], note[:240], canonical_json(payload).decode("utf-8")),
    )


def routing_policy_for_client(s: dict, bucket: int) -> tuple[dict, str]:
    """Return staging policy only for its stable percentage bucket."""
    if enabled(s, "routing_staging_enabled", False) and bucket < int(s.get("routing_staging_rollout_percent", "10") or 10):
        try:
            staged = json.loads(s.get("routing_staging_payload") or "{}")
            staged_settings = routing_settings_from_payload(staged)
            staged_revision = max(1, int(s.get("routing_staging_revision", "0") or 0))
            return routing_payload(staged_settings, staged_revision), "staging"
        except (ValueError, TypeError, json.JSONDecodeError):
            # A corrupt or stale staging record must never displace production.
            pass
    return routing_payload(s), "production"


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
        return "https://pecaocek.ignorelist.com/"
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
    cpu_load_percent = 0.0
    memory_used_pct = 0.0
    try:
        load_1m = os.getloadavg()[0]
        cpu_load_percent = round(min(100.0, load_1m / max(1, os.cpu_count() or 1) * 100.0), 1)
    except (AttributeError, OSError):
        pass
    try:
        meminfo = {}
        with open("/proc/meminfo", encoding="utf-8") as mem_file:
            for line in mem_file:
                key, _, value = line.partition(":")
                amount = value.strip().split(" ", 1)[0]
                if amount.isdigit():
                    meminfo[key] = int(amount)
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if total > 0:
            memory_used_pct = round((total - available) / total * 100.0, 1)
    except (OSError, ValueError):
        pass
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
        "cpu_load_pct": cpu_load_percent,
        "memory_used_pct": memory_used_pct,
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


def active_quarantine(s):
    """Return non-expired automatic quarantine entries keyed by host:port."""
    try:
        raw = json.loads(s.get("node_quarantine") or "{}")
    except (TypeError, ValueError):
        return {}
    now = int(time.time())
    return {
        str(target): value
        for target, value in raw.items()
        if isinstance(value, dict) and int(value.get("until", 0) or 0) > now
    }


def manual_node_drains(s):
    """Return validated manually drained node targets with their operator note."""
    try:
        raw = json.loads(s.get("node_drains") or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    result = {}
    for target, value in raw.items():
        target = str(target).strip()[:253]
        if not target or not isinstance(value, dict):
            continue
        result[target] = {
            "since": max(0, int(value.get("since", 0) or 0)),
            "actor": str(value.get("actor") or "operator")[:64],
            "note": str(value.get("note") or "")[:240],
        }
    return result


def update_auto_quarantine(db, s, targets):
    """Quarantine repeatedly failing probe targets without touching live configs."""
    if not enabled(s, "auto_quarantine_enabled", True):
        return active_quarantine(s)
    try:
        failure_limit = max(2, min(10, int(s.get("auto_quarantine_failures", "3") or 3)))
        recovery_limit = max(1, min(10, int(s.get("auto_quarantine_recovery_checks", "2") or 2)))
        ttl = max(5, min(1440, int(s.get("auto_quarantine_ttl_minutes", "30") or 30))) * 60
    except (TypeError, ValueError):
        failure_limit, recovery_limit, ttl = 3, 2, 1800
    try:
        state = json.loads(s.get("node_quarantine") or "{}")
        if not isinstance(state, dict):
            state = {}
    except (TypeError, ValueError):
        state = {}
    now = int(time.time())
    for host, port in targets:
        key = f"{host}:{port}"
        rows = db.execute(
            "select ok from server_health where target=? order by ts desc limit ?",
            (f"latency:{key}", max(failure_limit, recovery_limit) + 2),
        ).fetchall()
        failures = 0
        for row in rows:
            if int(row[0] or 0):
                break
            failures += 1
        recoveries = 0
        for row in rows:
            if not int(row[0] or 0):
                break
            recoveries += 1
        active = state.get(key)
        if failures >= failure_limit:
            if not isinstance(active, dict) or int(active.get("until", 0) or 0) <= now:
                state[key] = {"until": now + ttl, "failures": failures, "since": now}
                db.execute(
                    "insert into events values (?,?,?,?,?)",
                    (now, "node_quarantined", "system", "", json.dumps({"target": key, "failures": failures, "ttl_minutes": ttl // 60}, ensure_ascii=False)),
                )
        elif isinstance(active, dict) and (recoveries >= recovery_limit or int(active.get("until", 0) or 0) <= now):
            state.pop(key, None)
            db.execute(
                "insert into events values (?,?,?,?,?)",
                (now, "node_quarantine_recovered", "system", "", json.dumps({"target": key, "checks": recoveries}, ensure_ascii=False)),
            )
    set_settings(db, {"node_quarantine": json.dumps(state, ensure_ascii=False, separators=(",", ":"))})
    return active_quarantine({**s, "node_quarantine": json.dumps(state)})


def load_balancer_snapshot(db, s):
    """Return a deterministic, health-aware node recommendation for the panel.

    The operator never silently rewrites subscription data. It ranks only
    endpoints registered as VPN nodes. Public probes (for example 1.1.1.1)
    may still be kept for network diagnostics, but must never be suggested to
    a client as a VPN node.
    """
    enabled_flag = enabled(s, "load_balancer_enabled", True)
    try:
        max_latency = max(20, min(5000, int(s.get("load_balancer_max_latency_ms", "250") or 250)))
    except (TypeError, ValueError):
        max_latency = 250
    rows = db.execute(
        "select ts,target,ok,latency_ms,detail from server_health "
        "where target like 'latency:%' order by ts desc limit 160"
    ).fetchall()
    latest = {}
    for row in rows:
        target = str(row[1])
        latest.setdefault(target, row)
    registered = {
        str(node["target"]).strip()
        for node in parse_node_map_config(s.get("node_map_config", ""))
        if str(node.get("target") or "").strip()
    }
    # Older installations can omit the map entirely. In that case retain the
    # former behaviour until the operator registers actual nodes instead of
    # unexpectedly disabling balancing.
    allowed = registered or {
        f"{host}:{port}" for host, port in parse_latency_targets(s.get("latency_probe_targets", ""))
    }
    candidates = []
    quarantined = active_quarantine(s)
    drained = manual_node_drains(s)
    for target, row in latest.items():
        short_target = target.removeprefix("latency:")
        if short_target not in allowed:
            continue
        if short_target in quarantined or short_target in drained:
            continue
        latency = int(row[3] or 0)
        ok = bool(row[2])
        score = 0 if not ok else max(1, min(100, round(100 - (latency / max_latency) * 70)))
        candidates.append({
            "target": target.removeprefix("latency:"),
            "ok": ok,
            "latency_ms": latency,
            "score": score,
            "last_check": int(row[0]),
            "detail": str(row[4] or "")[:160],
        })
    candidates.sort(key=lambda item: (-int(item["ok"]), -int(item["score"]), int(item["latency_ms"] or 999999)))
    selected = candidates[0]["target"] if enabled_flag and candidates and candidates[0]["ok"] else ""
    return {
        "enabled": enabled_flag,
        "strategy": s.get("load_balancer_strategy") or "latency_health",
        "max_latency_ms": max_latency,
        "selected": selected,
        "decision_at": int(s.get("load_balancer_last_decision", "0") or 0),
        "quarantined": sorted(quarantined),
        "drained": sorted(drained),
        "candidates": candidates[:12],
    }


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


def run_health_check(db, s=None):
    """Run one bounded health cycle and keep incidents in sync.

    It is deliberately read-only with respect to RosPanel/Xray: a check can
    open or close an incident, but never restarts or reconfigures a service.
    The same function is used by the timer and the operator's manual button.
    """
    s = s or settings(db)
    upstream = probe_upstream()
    record_health(db, "subscription_upstream", upstream)
    if upstream.get("ok"):
        incident_close(db, "upstream", s)
    else:
        incident_open(
            db,
            "upstream",
            "critical",
            "subscription_upstream",
            "Подписка недоступна",
            str(upstream.get("error") or "нет ответа"),
            s,
        )
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
    return {"upstream": upstream, "services": services}


def health_worker():
    """Periodically sample subscription and local service health."""
    while True:
        interval = 60
        db = None
        try:
            db = conn()
            s = settings(db)
            interval = max(30, min(600, int(s.get("health_monitor_interval_seconds", "60") or 60)))
            if enabled(s, "health_monitor_enabled", True):
                run_health_check(db, s)
        except Exception:
            pass
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
        time.sleep(interval)


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


def bounded_form_int(form: dict, key: str, fallback, minimum: int, maximum: int) -> int:
    """Read a numeric form value without turning an empty browser field into 400.

    Some embedded browsers omit an empty ``<input type=number>`` altogether.
    Treat that case as "leave the current value unchanged".  A non-empty
    malformed value is still rejected by the caller, so this does not silently
    accept a typo such as ``12ms``.
    """
    raw = (form.get(key, [""])[0] or "").strip()
    if not raw:
        raw = str(fallback)
    value = int(raw)
    return max(minimum, min(maximum, value))


def parse_node_map_config(raw: str) -> list[dict]:
    """Parse bounded, operator-maintained node locations for the network map."""
    items = []
    for line in (raw or "").splitlines():
        fields = [field.strip() for field in line.split("|")]
        if len(fields) != 5:
            continue
        label, target, latitude, longitude, location = fields
        try:
            latitude_value = float(latitude)
            longitude_value = float(longitude)
        except (TypeError, ValueError):
            continue
        if not (label and target and -90 <= latitude_value <= 90 and -180 <= longitude_value <= 180):
            continue
        if len(label) > 64 or len(target) > 253 or len(location) > 96:
            continue
        items.append({
            "label": label,
            "target": target,
            "latitude": latitude_value,
            "longitude": longitude_value,
            "location": location,
        })
    return items[:24]


def node_map_config_is_valid(raw: str) -> bool:
    lines = [line for line in (raw or "").splitlines() if line.strip()]
    return len(lines) <= 24 and (not lines or len(parse_node_map_config(raw)) == len(lines))


def probe_tcp_latency(host: str, port: int):
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=3)
        # A successful local connection can round below one millisecond.  Keep
        # that distinct from the 0 value used by failed probes in old records.
        return {"ok": True, "latency_ms": max(1, round((time.monotonic() - started) * 1000)), "status": f"tcp:{port}"}
    except Exception as exc:
        return {"ok": False, "latency_ms": 0, "error": str(exc)}
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def run_latency_probe(db, s=None):
    """Run one TCP-latency pass without changing live VPN configuration."""
    s = s or settings(db)
    if not enabled(s, "latency_optimization_enabled", True):
        return {"enabled": False, "samples": [], "best_ms": 0}
    targets = parse_latency_targets(s.get("latency_probe_targets", ""))
    registered = {
        str(node["target"]).strip()
        for node in parse_node_map_config(s.get("node_map_config", ""))
        if str(node.get("target") or "").strip()
    }
    node_targets = [
        (host, port) for host, port in targets
        if not registered or f"{host}:{port}" in registered
    ]
    samples = []
    node_samples = []
    for host, port in targets:
        result = probe_tcp_latency(host, port)
        record_health(db, f"latency:{host}:{port}", result)
        if result.get("ok"):
            latency = int(result.get("latency_ms") or 0)
            samples.append(latency)
            if (host, port) in node_targets:
                node_samples.append(latency)
    # Keep the quarantine state in the panel database.  The next policy
    # response and balancer decision automatically exclude failing targets.
    quarantine = update_auto_quarantine(db, s, node_targets)
    s = {**s, "node_quarantine": json.dumps(quarantine)}
    max_ms = max(20, min(5000, int(s.get("latency_max_ms", "120") or 120)))
    best = min(node_samples) if node_samples else 0
    state = "healthy" if node_samples and best <= max_ms else ("degraded" if node_samples else "offline")
    set_settings(db, {
        "latency_state": state,
        "latency_last_probe": str(int(time.time())),
        "latency_best_ms": str(best),
    })
    decision = load_balancer_snapshot(db, {**s, "latency_best_ms": str(best)})
    if enabled(s, "load_balancer_enabled", True):
        previous = s.get("load_balancer_last_target", "")
        selected = decision.get("selected", "")
        set_settings(db, {
            "load_balancer_last_target": selected,
            "load_balancer_last_decision": str(int(time.time())),
        })
        if selected and selected != previous:
            db.execute(
                "insert into events values (?,?,?,?,?)",
                (
                    int(time.time()),
                    "balancer_decision",
                    "operator",
                    "",
                    json.dumps({"selected": selected, "previous": previous, "strategy": decision.get("strategy")}, ensure_ascii=False),
                ),
            )
    db.commit()
    return {"enabled": True, "samples": samples, "best_ms": best, "state": state, "balancer": decision}


def latency_worker():
    """Measure the VDS egress path without requiring raw ICMP privileges."""
    while True:
        interval = 30
        db = None
        try:
            db = conn()
            s = settings(db)
            interval = max(15, min(300, int(s.get("latency_probe_interval", "30") or 30)))
            run_latency_probe(db, s)
        except Exception:
            time.sleep(5)
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
        time.sleep(interval)


def promote_scheduled_release(db, now=None):
    """Publish only a verified APK matrix, against its captured production CAS.

    Legacy schedules without a pinned manifest/baseline are retained but fail
    closed: an operator must re-stage them with the verified release utility.
    """
    s = settings(db)
    if not enabled(s, "release_schedule_enabled", False):
        return False
    now = int(time.time()) if now is None else int(now)
    version = (s.get("scheduled_app_version") or "").strip()

    def deferred(reason, **extra):
        detail = json.dumps({"version": version, "reason": reason, **extra},
                            ensure_ascii=False, sort_keys=True)
        if not db.execute(
            "select 1 from events where kind=? and device=? and detail=? limit 1",
            ("release_promotion_deferred", "operator", detail),
        ).fetchone():
            db.execute("insert into events values (?,?,?,?,?)",
                       (now, "release_promotion_deferred", "operator", "", detail))
            db.commit()
        return False

    try:
        publish_at = int(s.get("release_publish_at", "0") or 0)
        code = int(s.get("scheduled_app_version_code", "0") or 0)
    except (ValueError, TypeError):
        return deferred("invalid_schedule")
    if publish_at <= 0 or publish_at > now or not version or code <= 0:
        return False
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        return deferred("invalid_version")
    missing_abis = scheduled_release_missing_abis(version)
    if missing_abis:
        return deferred("missing_abis", version_code=code, publish_at=publish_at,
                        missing_abis=missing_abis)
    expected_version = s.get("scheduled_expected_app_version", "")
    expected_code = s.get("scheduled_expected_app_version_code", "")
    manifest_digest = s.get("scheduled_release_metadata_sha256", "")
    if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_version)
            or not expected_code.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", manifest_digest)):
        return deferred("unverified_schedule")
    if (s.get("app_version") != expected_version or s.get("app_version_code") != expected_code
            or code <= int(expected_code) or version == expected_version or code >= 2147483647):
        return deferred("production_cas_or_monotonicity_failed")

    def safe_file(version_name, file_name):
        root = os.path.realpath(DOWNLOAD_ROOT)
        path = os.path.join(DOWNLOAD_ROOT, version_name, file_name)
        if (os.path.islink(path) or os.path.islink(os.path.dirname(path))
                or os.path.commonpath((root, os.path.realpath(path))) != root
                or not os.path.isfile(path)):
            raise ValueError("release_path")
        return path

    def sha256_file(path):
        result = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                result.update(chunk)
        return result.hexdigest()

    try:
        manifest_path = safe_file(version, "release-metadata.json")
        if os.path.getsize(manifest_path) > 65536 or sha256_file(manifest_path) != manifest_digest:
            raise ValueError("metadata_digest")
        with open(manifest_path, encoding="utf-8") as stream:
            metadata = json.load(stream)
        previous_path = safe_file(expected_version, "release-metadata.json")
        if os.path.getsize(previous_path) > 65536:
            raise ValueError("production_metadata_size")
        with open(previous_path, encoding="utf-8") as stream:
            previous = json.load(stream)
        signer = metadata.get("signer_sha256", "")
        if (metadata.get("schema") != 2 or metadata.get("version_name") != version
                or metadata.get("version_code") != code or metadata.get("application_id") != "com.quantumvpn.debug"
                or not re.fullmatch(r"[0-9a-f]{64}", signer)
                or previous.get("signer_sha256") != signer
                or previous.get("application_id") != metadata["application_id"]
                or previous.get("version_name") != expected_version or previous.get("version_code") != int(expected_code)):
            raise ValueError("release_identity")
        artifacts = metadata.get("artifacts", [])
        if (not isinstance(artifacts, list) or len(artifacts) != len(REQUIRED_RELEASE_ABIS)
                or {row.get("abi") for row in artifacts} != set(REQUIRED_RELEASE_ABIS)):
            raise ValueError("release_abi_matrix")
        for artifact in artifacts:
            name = f"QuantumVPN-{version}-operator-debug-{artifact['abi']}.apk"
            path = safe_file(version, name)
            expected_digest = artifact.get("apk_sha256", "")
            if (artifact.get("apk_file") != name or type(artifact.get("apk_size")) is not int
                    or artifact["apk_size"] <= 0 or os.path.getsize(path) != artifact["apk_size"]
                    or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                    or sha256_file(path) != expected_digest):
                raise ValueError("release_artifact")
            checksum_path = safe_file(version, name + ".sha256")
            if os.path.getsize(checksum_path) > 4096:
                raise ValueError("release_checksum_size")
            with open(checksum_path, encoding="ascii") as stream:
                if stream.read().strip() != expected_digest + "  " + name:
                    raise ValueError("release_checksum")
        rollout = max(1, min(100, int(s.get("scheduled_rollout_percent", "100") or 100)))
        min_code = max(0, int(s.get("scheduled_min_version_code", "0") or 0))
        revision = int(s.get("config_revision", "1") or 1) + 1
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return deferred("artifact_integrity_or_identity_failed")
    note = s.get("scheduled_app_changelog") or DEFAULT_NOTE
    values = {
        "app_version": version,
        "app_version_code": str(code),
        "rollout_percent": str(rollout),
        "app_changelog": note[:1000],
        "min_version_code": str(min_code),
        "update_notifications_enabled": "1",
        "announce": f"Доступен QuantumVPN {version}. Откройте уведомление, чтобы обновить приложение.",
        "announce_en": f"QuantumVPN {version} is available. Open the notification to update the app.",
        "force_update_message": f"Доступно обновление QuantumVPN {version}.",
        "announce_until": "0",
        "config_revision": str(revision),
        "release_schedule_enabled": "0",
    }
    banner = f"Доступно обновление QuantumVPN {version}. Откройте уведомление, чтобы установить новую версию."
    # File hashing happens before the write lock. Recheck every publication
    # field once locked so a reschedule or another publisher cannot race it.
    snapshot_keys = tuple(key for key in s if key.startswith("scheduled_")) + (
        "app_version", "app_version_code", "release_schedule_enabled", "release_publish_at", "config_revision",
        "scheduled_app_version", "scheduled_app_version_code", "scheduled_app_changelog",
        "scheduled_rollout_percent", "scheduled_min_version_code", "scheduled_expected_app_version",
        "scheduled_expected_app_version_code", "scheduled_release_metadata_sha256",
    )
    try:
        db.execute("begin immediate")
        latest = settings(db)
        if any(latest.get(key) != s.get(key) for key in snapshot_keys):
            db.rollback()
            return False
        set_settings(db, values)
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
    except Exception:
        db.rollback()
        raise
    release_info.cache_clear()
    # This is the update signal, not evidence of push delivery. APKs receive
    # their persistent banners on the next policy refresh.
    try:
        telegram_send(settings(db), f"[Quantum Control] Выпуск {version} опубликован. Охват: {rollout}% · versionCode: {code}.")
        webhook_emit(settings(db), "release.promoted", {"version": version, "version_code": code, "rollout_percent": rollout})
    except Exception:
        pass
    return True


def scheduled_release_worker():
    last_error = ""
    last_error_at = 0
    while True:
        db = None
        try:
            db = conn()
            promote_scheduled_release(db)
            current = settings(db)
            # Opt-in only. A broad recent client sample may stop further APK
            # issuance, never active VPN sessions or the publication schedule.
            if enabled(current, "release_guard_enabled", False) and not enabled(current, "update_rollout_paused", False):
                evidence = control_next.dashboard_snapshot(db, current)
                if evidence["guard"]["pause_recommended"]:
                    decision = control_next.pause_rollout(db, current, "release-guard", "owner")
                    audit(db, "release-guard", "", "release:pause_evidence", {"devices": decision["devices"], "bad_devices": decision["bad_devices"]})
                    db.commit()
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            moment = int(time.time())
            # The worker must not silently lose a planned APK publication.
            # Coalesce repeats, otherwise a locked SQLite database could flood
            # the journal every 20 seconds.
            if message != last_error or moment - last_error_at >= 300:
                print(f"[quantumvpn] scheduled release worker: {message}", flush=True)
                last_error = message
                last_error_at = moment
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
        time.sleep(20)


def release_guard_snapshot(s):
    """Report whether production/scheduled releases have both required APKs.

    This is intentionally a preflight report, not a publishing action. It lets
    an operator see a missing ARM64 or ARMv7 artifact before any client sees a
    new release.
    """
    def inspect(name, version, code):
        version = (version or "").strip()
        try:
            code = int(code or 0)
        except (TypeError, ValueError):
            code = 0
        valid_version = bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version))
        missing = scheduled_release_missing_abis(version) if valid_version else list(REQUIRED_RELEASE_ABIS)
        return {
            "name": name,
            "version": version or "—",
            "version_code": code,
            "ready": valid_version and code > 0 and not missing,
            "missing_abis": missing,
        }

    production = inspect("Production", s.get("app_version") or VERSION, s.get("app_version_code") or VERSION_CODE)
    scheduled_version = (s.get("scheduled_app_version") or "").strip()
    scheduled = inspect("По расписанию", scheduled_version, s.get("scheduled_app_version_code"))
    scheduled["configured"] = bool(scheduled_version or enabled(s, "release_schedule_enabled", False))
    return {"production": production, "scheduled": scheduled}


def telegram_send(s, text: str):
    token = telegram_bot_token(s)
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
    token = telegram_bot_token(s)
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
    """Create an encrypted consistent snapshot of both panel SQLite stores.

    Environment secrets (including the Telegram token) are deliberately not
    part of the archive. The RosPanel snapshot is optional so an operator
    backup still succeeds during a RosPanel repair.
    """
    if AESGCM is None:
        raise RuntimeError("cryptography is required for encrypted backups")
    backup_key()  # Validate the encryption key before writing sensitive files.
    folder = os.path.join(ROOT, "backups")
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    archive = os.path.join(folder, f"quantum-control-{stamp}.zip")
    temp_db = os.path.join(folder, f".operator-{stamp}.db")
    temp_rospanel_db = os.path.join(folder, f".rospanel-{stamp}.db")
    for path in (temp_db, temp_rospanel_db, archive):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    rospanel_included = False
    try:
        source = sqlite3.connect(DB, timeout=30)
        try:
            target = sqlite3.connect(temp_db)
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        if os.path.isfile(ROSPANEL_DB):
            source = sqlite3.connect(f"file:{ROSPANEL_DB}?mode=ro", uri=True, timeout=30)
            try:
                target = sqlite3.connect(temp_rospanel_db)
                try:
                    source.backup(target)
                    rospanel_included = True
                finally:
                    target.close()
            finally:
                source.close()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.write(temp_db, "operator.db")
            if rospanel_included:
                bundle.write(temp_rospanel_db, "rospanel.db")
            # Encryption covers these restoration-critical keys as well as
            # the databases. Never embed the external AES decryption key.
            restore_files = {
                "session.secret": os.path.join(ROOT, "session.secret"),
                "routing-ed25519.key": os.path.join(ROOT, "routing-ed25519.key"),
                "rospanel/secrets.key": os.path.join(os.path.dirname(ROSPANEL_DB), "secrets.key"),
                "rospanel/certs/cert.pem": os.path.join(os.path.dirname(ROSPANEL_DB), "certs", "cert.pem"),
                "rospanel/certs/key.pem": os.path.join(os.path.dirname(ROSPANEL_DB), "certs", "key.pem"),
            }
            for name, source_file in restore_files.items():
                if os.path.isfile(source_file):
                    bundle.write(source_file, name)
            bundle.writestr(
                "backup-info.json",
                json.dumps({"created_at": int(time.time()), "panel_build": PANEL_BUILD, "rospanel_included": rospanel_included}, ensure_ascii=False),
            )
    except Exception:
        if os.path.isfile(archive):
            os.remove(archive)
        raise
    finally:
        try:
            os.remove(temp_db)
        except OSError:
            pass
        try:
            os.remove(temp_rospanel_db)
        except OSError:
            pass
    try:
        encrypted = encrypt_backup_archive(archive)
    except Exception:
        # Fail closed: never retain a plaintext copy after encryption failure.
        if os.path.isfile(archive):
            os.remove(archive)
        raise
    # Keep seven days locally; Telegram receives only encrypted .zip.enc files.
    cutoff = time.time() - 7 * 86400
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if name.endswith((".zip", ".zip.enc")) and os.path.getmtime(path) < cutoff:
            try:
                os.remove(path)
            except OSError:
                pass
    return encrypted


def latest_backup_info():
    """Return only safe metadata about the newest encrypted local backup."""
    folder = os.path.join(ROOT, "backups")
    try:
        names = [
            os.path.join(folder, name)
            for name in os.listdir(folder)
            if name.endswith(".zip.enc") and os.path.isfile(os.path.join(folder, name))
        ]
        path = max(names, key=os.path.getmtime)
        return {
            "exists": True,
            "name": os.path.basename(path),
            "ts": int(os.path.getmtime(path)),
            "size": os.path.getsize(path),
        }
    except (OSError, ValueError):
        return {"exists": False, "name": "", "ts": 0, "size": 0}


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


def moscow_clock(now=None):
    """Return a stable MSK date/time tuple without depending on server TZ."""
    stamp = time.gmtime((time.time() if now is None else now) + 3 * 3600)
    return time.strftime("%Y-%m-%d", stamp), time.strftime("%H:%M", stamp)


def maybe_send_daily_digest(db, s, now=None):
    """Send one opt-in, compact daily operations digest to the Telegram chat."""
    if not enabled(s, "telegram_daily_digest_enabled", False):
        return False
    if not telegram_bot_token(s) or not (s.get("telegram_chat_id") or "").strip():
        return False
    target = (s.get("telegram_digest_time_msk") or "09:00").strip()
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", target):
        return False
    date, clock = moscow_clock(now)
    if clock != target or s.get("telegram_digest_last_sent_date") == date:
        return False
    moment = int(time.time() if now is None else now)
    try:
        last_attempt = int(s.get("telegram_digest_last_attempt", "0") or 0)
    except (TypeError, ValueError):
        last_attempt = 0
    # A failed Telegram request is retried, but no more than once in 15 min.
    if moment - last_attempt < 900:
        return False
    set_settings(db, {"telegram_digest_last_attempt": str(moment)})
    report = report_snapshot(db)
    balancer = load_balancer_snapshot(db, s)
    selected = balancer.get("selected") or "нет доступной цели"
    message = (
        "[Quantum Control] Суточная сводка (МСК)\n"
        f"Доступность: {report['health_uptime_percent']}% · проверок: {report['health_checks']}\n"
        f"Инциденты: {report['open_incidents']} · устройств: {report['devices_seen']}\n"
        f"Средняя задержка: {report['average_latency_ms']} мс\n"
        f"Маршрут балансировщика: {selected}"
    )
    if not telegram_send(s, message):
        db.commit()
        return False
    set_settings(db, {"telegram_digest_last_sent_date": date})
    db.execute(
        "insert into events values (?,?,?,?,?)",
        (moment, "daily_digest_sent", "operator", "", json.dumps({"date_msk": date, "time_msk": target}, ensure_ascii=False)),
    )
    db.commit()
    return True


class TelegramRequestError(Exception):
    def __init__(self, code=0):
        self.code = int(code)
        super().__init__(f"Telegram request failed ({self.code})")


class _BotNoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def telegram_bot_api(s, method, payload=None):
    """Bounded fixed-host API; errors never retain the token-bearing URL."""
    if method not in {"getMe", "getUpdates", "getWebhookInfo", "setMyCommands"}:
        raise TelegramRequestError()
    token = telegram_bot_token(s)
    if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,128}", token):
        raise TelegramRequestError()
    body = json.dumps(payload or {}, separators=(",", ":")).encode()
    if len(body) > 16384:
        raise TelegramRequestError()
    try:
        request = Request(f"https://api.telegram.org/bot{token}/{method}", data=body,
                          headers={"Content-Type": "application/json"}, method="POST")
        with build_opener(_BotNoRedirect()).open(request, timeout=35) as response:
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise TelegramRequestError()
            result = json.loads(raw)
        if not isinstance(result, dict) or result.get("ok") is not True:
            code = result.get("error_code", 0) if isinstance(result, dict) else 0
            raise TelegramRequestError(code if type(code) is int else 0)
        return result.get("result")
    except HTTPError as error:
        raise TelegramRequestError(error.code) from None
    except TelegramRequestError:
        raise
    except Exception:
        raise TelegramRequestError() from None


def bot_runtime_state(state, webhook=None):
    with _BOT_STATE_LOCK:
        _BOT_RUNTIME.update(state=state, polling=state == "polling", webhook=webhook)


def bot_runtime_snapshot():
    """Actual host samples; CPU utilization is not load average or AI progress."""
    with _BOT_STATE_LOCK:
        runtime = dict(_BOT_RUNTIME)
    runtime.update(active_ai_requests=int(_AI_RUN_LOCK.locked()),
                   system_instruction=True, backup=latest_backup_info())
    runtime.update(cpu_percent=None, memory_percent=None, disk_percent=None,
                   memory_total_bytes=None)
    def cpu_ticks():
        with open("/proc/stat", encoding="ascii") as source:
            parts = source.readline().split()
        if parts[0] != "cpu" or len(parts) < 5:
            raise ValueError("CPU sample unavailable")
        values = [int(item) for item in parts[1:9]]
        return sum(values), values[3] + (values[4] if len(values) > 4 else 0)
    try:
        first = cpu_ticks()
        time.sleep(0.15)
        second = cpu_ticks()
        total, idle = second[0] - first[0], second[1] - first[1]
        if total > 0 and 0 <= idle <= total:
            runtime["cpu_percent"] = round(100 * (total - idle) / total, 1)
    except (OSError, ValueError, IndexError):
        pass
    try:
        with open("/proc/meminfo", encoding="ascii") as source:
            memory = {line.split(":", 1)[0]: int(line.split()[1]) * 1024 for line in source}
        total, available = memory["MemTotal"], memory["MemAvailable"]
        if total > 0 and 0 <= available <= total:
            runtime.update(memory_total_bytes=total,
                           memory_percent=round(100 * (total - available) / total, 1))
    except (OSError, ValueError, KeyError, IndexError):
        pass
    try:
        disk = shutil.disk_usage(ROOT)
        if disk.total > 0:
            runtime["disk_percent"] = round(100 * disk.used / disk.total, 1)
    except OSError:
        pass
    try:
        service = cached_service_status()
        runtime["services"] = {name: service.get(name) for name in ("operator", "rospanel", "xray")}
        runtime["services"]["xray"] = {"running": "active", "stopped": "inactive"}.get(service.get("xray"), service.get("xray"))
    except Exception:
        runtime["services"] = {}
    try:
        result = subprocess.run(["systemctl", "is-active", "ollama"], capture_output=True,
                                text=True, timeout=3)
        runtime["services"]["ollama"] = result.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        runtime["services"]["ollama"] = "unknown"
    return runtime


def bot_local_model_snapshot(s):
    model = s.get("ai_model") or QWEN_DEFAULT_MODEL
    result = qwen_local_status(model)
    if result.get("ok") is not True:
        # An unavailable catalogue is unknown, not proof of an absent model.
        result["ready"] = None
    result.update(loaded=None, memory_bytes=None)
    try:
        request = Request(QWEN_LOCAL_ENDPOINT + "/api/ps", headers={"Accept": "application/json"})
        with build_opener(_BotNoRedirect()).open(request, timeout=3) as response:
            raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("Oversize model response")
        payload = json.loads(raw)
        rows = payload.get("models")
        if not isinstance(rows, list):
            raise ValueError("Missing model inventory")
        loaded = next((row for row in rows if isinstance(row, dict) and
                       (row.get("name") == model or row.get("model") == model)), None)
        result["loaded"] = loaded is not None
        if loaded and type(loaded.get("size")) is int and loaded["size"] >= 0:
            result["memory_bytes"] = loaded["size"]
    except Exception:
        pass
    return result


def bot_command_reply(db, s, command):
    if command in {"/help", "/start"}:
        return bot_status.command_help()
    if command == "/get_dev":
        return "Отдельного публичного Dev-выпуска нет. /get_stable — текущий опубликованный APK. Закрытый выпуск до срока не выдаётся."
    if command == "/get_stable":
        version = s.get("app_version", "")
        if effective_maintenance(s) or not enabled(s, "public_download_enabled", True):
            return "Скачивание APK закрыто оператором или на время технических работ. /check_updates — состояние выпуска."
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            return "Нет проверенной публичной версии APK."
        if (enabled(s, "release_schedule_enabled", False) and s.get("scheduled_app_version") == version
                and int(s.get("release_publish_at", "0") or 0) > int(time.time())):
            return "Запланированный выпуск ещё закрыт."
        base = urlsplit(DOWNLOAD_BASE)
        if base.scheme != "https" or base.netloc != urlsplit(PUBLIC_BASE).netloc or base.username or base.password or base.query or base.fragment:
            return "Адрес скачивания не прошёл проверку."
        lines = [f"📦 Публичная версия QuantumVPN: {version}", "Источник: ваш VDS, без GitHub."]
        for abi in REQUIRED_RELEASE_ABIS:
            name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
            path = os.path.join(DOWNLOAD_ROOT, version, name)
            if os.path.isfile(path) and not os.path.islink(path):
                lines.append(f"{abi}: {DOWNLOAD_BASE}/downloads/{version}/{name}")
        return "\n".join(lines) if len(lines) > 2 else "Опубликованный APK пока недоступен."
    snapshot = bot_status.collect_status(db, s, runtime=bot_runtime_snapshot(),
                                         local_model=bot_local_model_snapshot(s))
    return bot_status.format_status(snapshot)


def telegram_receive_batch(db, s, updates, scope, rate=None, now=None):
    """Read-only commands, persisted cursor, no reply to another chat/user."""
    if not isinstance(updates, list) or len(updates) > 20:
        raise TelegramRequestError()
    now = int(time.time()) if now is None else int(now)
    rate = rate if rate is not None else {"last": 0, "window": now, "count": 0}
    row = db.execute("select next_update from bot_receiver_state where scope=?", (scope,)).fetchone()
    cursor = int(row[0]) if row else 0
    replies = 0
    for update in sorted((item for item in updates if isinstance(item, dict) and
                          type(item.get("update_id")) is int and 0 <= item["update_id"] < 2**63),
                         key=lambda item: item["update_id"]):
        if update["update_id"] < cursor:
            continue
        cursor = update["update_id"] + 1
        # Commit before replying. A lost response is retried by the user, not
        # silently replayed after a process restart; commands never mutate VPN.
        db.execute("insert into bot_receiver_state values (?,?,?) on conflict(scope) do update set next_update=max(next_update,excluded.next_update),updated_at=excluded.updated_at", (scope, cursor, now))
        db.commit()
        message = update.get("message")
        with _BOT_STATE_LOCK:
            username = _BOT_RUNTIME.get("username")
        command = bot_status.authorized_command(message, s.get("telegram_chat_id"), bot_username=username)
        if command is None:
            continue
        stamp = message.get("date")
        if type(stamp) is not int or not now - 300 <= stamp <= now + 60:
            continue
        if now - rate.get("window", 0) >= 300:
            rate.update(window=now, count=0)
        if now - rate.get("last", 0) < 5 or rate.get("count", 0) >= 30:
            continue
        rate.update(last=now, count=rate.get("count", 0) + 1)
        if telegram_send(s, bot_command_reply(db, s, command)):
            replies += 1
    # Empty successful polls are heartbeat evidence, not client notifications.
    db.execute("insert into bot_receiver_state values (?,?,?) on conflict(scope) do update set next_update=max(next_update,excluded.next_update),updated_at=excluded.updated_at", (scope, cursor, now))
    db.commit()
    return {"next_update": cursor, "replies": replies}


def telegram_command_worker():
    """One server-side poller. Never deletes a webhook or uses a public chat."""
    try:
        import fcntl
        descriptor = os.open(os.path.join(ROOT, "telegram-poller.lock"),
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        bot_runtime_state("unavailable")
        if 'descriptor' in locals():
            os.close(descriptor)
        return
    registered = None
    rate = {"last": 0, "window": int(time.time()), "count": 0}
    try:
        while True:
            db = None
            try:
                db = conn()
                s = settings(db)
                token, chat = telegram_bot_token(s), (s.get("telegram_chat_id") or "").strip()
                if not token or not re.fullmatch(r"[1-9]\d{0,18}", chat):
                    bot_runtime_state("unconfigured")
                    time.sleep(30)
                    continue
                scope = hashlib.sha256((token + "\n" + chat).encode()).hexdigest()
                if scope != registered:
                    info = telegram_bot_api(s, "getWebhookInfo")
                    if not isinstance(info, dict):
                        raise TelegramRequestError()
                    if info.get("url"):
                        bot_runtime_state("webhook", True)
                        return
                    identity = telegram_bot_api(s, "getMe")
                    username = identity.get("username") if isinstance(identity, dict) else None
                    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
                        raise TelegramRequestError()
                    with _BOT_STATE_LOCK:
                        _BOT_RUNTIME["username"] = username
                    bot_runtime_state("polling", False)
                    try:
                        telegram_bot_api(s, "setMyCommands", {"scope": {"type": "chat", "chat_id": int(chat)},
                                                              "commands": bot_status.bot_commands()})
                    except TelegramRequestError:
                        pass
                    registered = scope
                row = db.execute("select next_update from bot_receiver_state where scope=?", (scope,)).fetchone()
                offset = int(row[0]) if row else 0
                updates = telegram_bot_api(s, "getUpdates", {"offset": offset, "limit": 20,
                                                             "timeout": 20, "allowed_updates": ["message"]})
                bot_runtime_state("polling", False)
                telegram_receive_batch(db, s, updates, scope, rate=rate)
            except TelegramRequestError as error:
                bot_runtime_state("conflict" if error.code == 409 else "unavailable")
                if error.code == 409:
                    return  # Another receiver/webhook owns this bot. Do not displace it.
                time.sleep(30)
            except Exception:
                bot_runtime_state("unavailable")
                time.sleep(30)
            finally:
                if db is not None:
                    db.close()
    finally:
        os.close(descriptor)


def qwen_local_status(model: str = QWEN_DEFAULT_MODEL) -> dict:
    """Check only the local Ollama catalogue; never follow an operator URL."""
    try:
        request = Request(f"{QWEN_LOCAL_ENDPOINT}/api/tags", headers={"Accept": "application/json"})
        with urlopen(request, timeout=3) as response:
            if not 200 <= response.status < 300:
                return {"ok": False, "ready": False, "error": f"HTTP {response.status}"}
            payload = json.loads(response.read(64 * 1024).decode("utf-8", "replace"))
        names = {
            str(item.get("name") or "")
            for item in (payload.get("models") or [])
            if isinstance(item, dict)
        }
        ready = model in names
        return {
            "ok": True,
            "ready": ready,
            "model": model,
            "available_models": sorted(name for name in names if name.startswith("qwen"))[:12],
            "error": "" if ready else f"Модель {model} ещё не загружена",
        }
    except Exception as exc:
        return {"ok": False, "ready": False, "model": model, "available_models": [], "error": f"Ollama недоступна: {type(exc).__name__}"}


def ai_operations_snapshot(db, s: dict) -> dict:
    """Build an aggregate-only snapshot appropriate for a local advisor.

    The snapshot deliberately excludes account identifiers, profile URIs, API
    keys, operator notes and raw logs. Qwen gets infrastructure figures only,
    so an advice request cannot turn into a privacy export.
    """
    report = report_snapshot(db)
    service = cached_service_status(ttl=0)
    balancer = load_balancer_snapshot(db, s)
    backup = latest_backup_info()
    latest = {}
    for row in db.execute(
        "select ts,target,ok,latency_ms,detail from server_health "
        "where target like 'latency:%' order by ts desc limit 160"
    ).fetchall():
        latest.setdefault(str(row[1]).removeprefix("latency:"), row)
    nodes = []
    for target, row in sorted(latest.items())[:12]:
        nodes.append({
            "target": target,
            "ok": bool(row[2]),
            "latency_ms": int(row[3] or 0),
            "checked_at": int(row[0]),
        })
    return {
        "generated_at": int(time.time()),
        "services": {
            "rospanel": service.get("rospanel", "unknown"),
            "operator": service.get("operator", "unknown"),
            "xray": service.get("xray", "unknown"),
            "cpu_load_pct": service.get("cpu_load_pct", 0),
            "memory_used_pct": service.get("memory_used_pct", 0),
            "disk_used_pct": service.get("disk_used_pct", 0),
        },
        "health": {
            "uptime_percent_24h": report.get("health_uptime_percent", 0),
            "open_incidents": report.get("open_incidents", 0),
            "average_latency_ms": report.get("average_latency_ms", 0),
            "latency_state": s.get("latency_state", "unknown"),
            "best_latency_ms": int(s.get("latency_best_ms", "0") or 0),
        },
        "balancer": {
            "enabled": bool(balancer.get("enabled")),
            "selected": balancer.get("selected") or "",
            "quarantined_count": len(balancer.get("quarantined") or []),
            "drained_count": len(balancer.get("drained") or []),
        },
        "backup": {
            "exists": bool(backup.get("exists")),
            "created_at": int(backup.get("ts") or 0),
            "size_bytes": int(backup.get("size") or 0),
            "hourly_delivery_enabled": enabled(s, "telegram_backups_enabled", False),
        },
        "nodes": nodes,
    }


def ai_prompt(snapshot: dict) -> str:
    """Keep the local model in a read-only, concise operations role."""
    return (
        "Ты локальный помощник Quantum Control. Анализируй ТОЛЬКО агрегированную "
        "телеметрию ниже. Не выполняй команды, не предлагай менять конфигурацию "
        "автоматически, не запрашивай секреты и не упоминай персональные данные. "
        "Пинг зависит от физической дистанции: не обещай невозможных значений. "
        "Отдельно отметь, если резервная копия отсутствует или устарела. "
        "Ответь по-русски, максимум 900 символов, в трёх коротких частях: "
        "«Статус», «Риски», «Следующий ручной шаг». Если всё в норме, так и скажи.\n\n"
        + json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    )


def clean_ai_advice(value) -> str:
    text = " ".join(str(value or "").split())
    text = "".join(char for char in text if char >= " " or char in "\n\t")
    return (text or "Модель вернула пустой ответ.")[:1800]


def run_ai_analysis(db, s: dict, trigger: str = "scheduled") -> dict:
    """Ask local Qwen for advice without giving it execution capabilities."""
    if not _AI_RUN_LOCK.acquire(blocking=False):
        return {"ok": False, "status": "занят", "advice": "Один анализ уже выполняется; повторный не запущен.", "telegram_sent": False}
    try:
        return _run_ai_analysis(db, s, trigger)
    finally:
        _AI_RUN_LOCK.release()


def _run_ai_analysis(db, s: dict, trigger: str) -> dict:
    now = int(time.time())
    model = (s.get("ai_model") or QWEN_DEFAULT_MODEL).strip()
    if not enabled(s, "ai_advisor_enabled", True):
        result = {"ok": False, "status": "выключен", "advice": "ИИ‑советник выключен оператором."}
    elif model != QWEN_DEFAULT_MODEL:
        result = {"ok": False, "status": "ошибка", "advice": "Разрешена только локальная модель Qwen3 0.6B.", "error": "unsupported_model"}
    else:
        status = qwen_local_status(model)
        if not status.get("ready"):
            result = {"ok": False, "status": "ожидание модели", "advice": status.get("error") or "Локальная модель ещё не готова.", "error": status.get("error", "")}
        else:
            snapshot = ai_operations_snapshot(db, s)
            request_body = json.dumps({
                "model": model,
                "prompt": ai_prompt(snapshot),
                "stream": False,
                # Qwen3 defaults to long reasoning. The advisor is a small
                # operational summary, so suppress reasoning tokens to keep a
                # CPU-only VDS responsive and reserve output tokens for advice.
                "think": False,
                "options": {"temperature": 0.1, "num_predict": 260, "num_ctx": 2048},
            }, ensure_ascii=False).encode("utf-8")
            try:
                request = Request(
                    f"{QWEN_LOCAL_ENDPOINT}/api/generate",
                    data=request_body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                # The first CPU-only load can take a few minutes on a small
                # VDS. This runs in a background worker, not the HTTP request
                # path, so an operator page remains responsive while Ollama
                # warms its compact model.
                with urlopen(request, timeout=300) as response:
                    if not 200 <= response.status < 300:
                        raise RuntimeError(f"Ollama HTTP {response.status}")
                    payload = json.loads(response.read(96 * 1024).decode("utf-8", "replace"))
                result = {"ok": True, "status": "готов", "advice": clean_ai_advice(payload.get("response")), "snapshot": snapshot}
            except Exception as exc:
                result = {"ok": False, "status": "ошибка", "advice": "Локальная модель не ответила. Проверка нод и балансировщик продолжают работать без ИИ.", "error": f"{type(exc).__name__}: {exc}"[:280]}

    advice = clean_ai_advice(result.get("advice"))
    result["advice"] = advice
    values = {
        "ai_last_run": str(now),
        "ai_last_status": str(result.get("status") or "ошибка")[:64],
        "ai_last_advice": advice,
        "ai_last_error": str(result.get("error") or "")[:280],
    }
    # Bot delivery is opt-in, deduplicated and never includes the raw telemetry.
    digest = hashlib.sha256((values["ai_last_status"] + "\n" + advice).encode("utf-8")).hexdigest()
    try:
        last_notice = int(s.get("ai_last_notification_at", "0") or 0)
    except (TypeError, ValueError):
        last_notice = 0
    should_notify = (
        enabled(s, "ai_telegram_enabled", True)
        and enabled(s, "telegram_alerts_enabled", False)
        and digest != s.get("ai_last_notification_hash", "")
        and now - last_notice >= 15 * 60
    )
    sent = False
    if should_notify:
        sent = telegram_send(s, f"[Quantum Control · Qwen]\nСтатус: {values['ai_last_status']}\n{advice}")
        if sent:
            values.update({"ai_last_notification_hash": digest, "ai_last_notification_at": str(now)})
    set_settings(db, values)
    db.execute(
        "insert into ai_observations(ts,trigger,status,advice,telegram_sent,before_json) values (?,?,?,?,?,?)",
        (now, trigger[:64], values["ai_last_status"], advice, int(sent),
         json.dumps(result.get("snapshot") or {}, ensure_ascii=False)),
    )
    db.execute("delete from ai_observations where ts<?", (now - 30 * 86400,))
    db.execute(
        "insert into events values (?,?,?,?,?)",
        (now, "ai_analysis", "qwen-local", "", json.dumps({"trigger": trigger, "ok": bool(result.get("ok")), "status": values["ai_last_status"], "telegram_sent": sent}, ensure_ascii=False)),
    )
    db.commit()
    return {**result, "telegram_sent": sent}


def ai_worker():
    """Run the local advisor on a bounded cadence; it never changes a node."""
    while True:
        db = None
        try:
            db = conn()
            s = settings(db)
            interval = max(AI_MIN_INTERVAL_SECONDS, min(AI_MAX_INTERVAL_SECONDS, int(s.get("ai_interval_seconds", "900") or 900)))
            last_run = int(s.get("ai_last_run", "0") or 0)
            if enabled(s, "ai_advisor_enabled", True) and int(time.time()) - last_run >= interval:
                run_ai_analysis(db, s, "scheduled")
        except Exception as exc:
            if db is not None:
                try:
                    db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "ai_analysis_error", "qwen-local", "", f"{type(exc).__name__}: {exc}"[:500]))
                    db.commit()
                except Exception:
                    pass
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
        time.sleep(60)


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
            maybe_send_daily_digest(db, s)
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
    /* Routing workbench: a compact, review-first presentation of the existing signed policy. */
    .routing-page{position:relative;padding-top:2px}.routing-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:8px 4px 14px}.routing-kicker{color:#32d9ff;font-size:11px;font-weight:800;letter-spacing:.1em}.routing-heading h1{display:block!important;margin:4px 0 4px!important;font-size:28px!important}.routing-heading p{display:block!important;margin:0;max-width:720px}.routing-health{display:flex;gap:8px;align-items:center;padding-top:16px}.routing-top-grid{display:grid;grid-template-columns:minmax(290px,.95fr) minmax(330px,1.05fr) minmax(300px,.9fr);gap:12px;align-items:stretch}.routing-card{height:100%;margin:0!important}.routing-card h2{display:flex;gap:8px;align-items:center}.routing-card h2:before{color:var(--blue);font-size:19px}.routing-scanner h2:before{content:'◎'}.routing-rules h2:before{content:'⌘'}.routing-dns h2:before{content:'◈'}.routing-subtitle{margin:-4px 0 12px;color:#829db0;font-size:12px}.target-field{position:relative}.target-field textarea{min-height:78px;padding:11px 12px 9px;line-height:1.45;resize:vertical}.routing-submit{width:100%;margin:8px 0 12px;min-height:42px;font-size:13px}.routing-results{border-top:1px solid #153448;padding-top:8px}.routing-results-title{display:block;margin:0 0 5px;color:#b7cedd;font-size:12px}.scan-result{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid #102a3a}.scan-result:last-child{border-bottom:0}.scan-result b{display:block;color:#edf8ff;font-size:12px}.scan-result small{display:block;color:#7894aa;margin-top:2px}.scan-result span{font-size:12px;white-space:nowrap}.routing-empty{padding:14px 2px;color:#7792a7;font-size:12px}.route-group{border:1px solid #193a50;border-left:3px solid #25d5ff;border-radius:7px;background:#06131f;margin:9px 0;padding:9px 10px}.route-group.proxy{border-left-color:#3ceba8}.route-group.direct{border-left-color:#38adff}.route-group.block{border-left-color:#ff718a}.route-group-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:7px}.route-group-head b{font-size:13px}.route-group-head span{color:#7893a8;font-size:11px}.route-group label{margin:0}.route-group textarea{min-height:58px;padding:8px 9px;font:12px/1.45 "Cascadia Code",Consolas,monospace;resize:vertical}.route-group .route-cidrs{min-height:38px;margin-top:6px}.routing-dns{display:flex;flex-direction:column}.routing-switch{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #143044;margin:0}.routing-switch:last-of-type{border-bottom:0}.routing-switch input{appearance:none;width:40px;height:22px;min-width:40px;margin:2px 0 0;border-radius:999px;background:#284254;border:1px solid #41647a;position:relative;cursor:pointer}.routing-switch input:after{content:'';position:absolute;top:3px;left:3px;width:14px;height:14px;border-radius:50%;background:#c9dce7;transition:.18s}.routing-switch input:checked{background:#17cba0;border-color:#37e9ba}.routing-switch input:checked:after{transform:translateX(17px);background:#fff}.routing-switch b{display:block;font-size:13px}.routing-switch small{display:block;color:#809bb0;margin-top:2px}.dns-field{margin-top:12px}.dns-field label{margin:0}.routing-actions{margin-top:auto;padding-top:14px;display:grid;grid-template-columns:1fr 1fr;gap:8px}.routing-actions button{min-height:45px;padding:8px;font-size:12px}.routing-actions .secondary{color:#bce9fb}.routing-footer{display:grid;grid-template-columns:minmax(250px,.7fr) minmax(420px,1.3fr);gap:12px;margin-top:12px}.routing-footer .card{margin:0!important}.routing-revision{display:flex;align-items:center;gap:11px}.routing-revision i{display:grid;place-items:center;width:35px;height:35px;border-radius:8px;background:#082334;border:1px solid #245671;color:#33d9ff;font-style:normal;font-size:20px}.routing-revision small{display:block;color:#7f9aaf}.routing-revision b{font-size:16px}.routing-notice{display:flex;gap:10px;align-items:flex-start}.routing-notice i{color:#46d9ff;font-style:normal;font-size:20px}.routing-notice b{display:block;margin-bottom:3px}.routing-notice p{margin:0;color:#89a4b7;font-size:12px}.routing-history{margin-top:12px!important}.routing-history summary{cursor:pointer;color:#9ec6da;font-weight:700}.routing-history summary:hover{color:#34d9ff}.routing-history table{margin-top:12px}
    /* Keep the primary routing actions above the fold on a standard laptop. */
    .routing-top-grid{align-items:start}.target-field textarea{min-height:64px;padding:9px 10px}.routing-submit{min-height:39px;margin:7px 0 9px}.routing-results{padding-top:7px}.routing-empty{padding:11px 2px}.route-group{margin:7px 0;padding:7px 8px}.route-group-head{margin-bottom:5px}.route-group textarea{min-height:42px;padding:6px 8px;line-height:1.38}.route-advanced{margin-top:5px;color:#80a1b5;font-size:11px}.route-advanced summary{cursor:pointer;list-style:none}.route-advanced summary:before{content:'▸';display:inline-block;margin-right:5px;color:#37d4ff}.route-advanced[open] summary:before{content:'▾'}.route-advanced textarea{width:100%;margin-top:6px}.routing-switch{padding:8px 0}.dns-field{margin-top:9px}.routing-actions{padding-top:10px}.routing-actions button{min-height:41px}
    @media(max-width:1250px){.dashboard .split{grid-template-columns:1fr}.dashboard-middle{grid-template-columns:1fr 1fr}.actions-card{grid-column:1 / -1}.topology-layout{grid-template-columns:1fr}.dashboard-side{grid-template-columns:repeat(2,minmax(0,1fr))}.routing-top-grid{grid-template-columns:1fr 1fr}.routing-dns{grid-column:1 / -1}.routing-dns .routing-actions{max-width:520px}}@media(max-width:980px){.dashboard-side{grid-template-columns:1fr}.dashboard-middle{grid-template-columns:1fr}.actions-card{grid-column:auto}.stats{grid-template-columns:repeat(2,1fr)}.mini-grid{grid-template-columns:repeat(2,1fr)}.routing-top-grid,.routing-footer{grid-template-columns:1fr}.routing-dns{grid-column:auto}.routing-heading{flex-direction:column}.routing-health{padding-top:0}}
    /* The operations-center theme gives every .hero a compact fixed height. The
       login card is also a hero, so restore its natural height or the password
       and 2FA fields are clipped on short/mobile viewports. */
    .login{max-width:430px;margin:clamp(16px,8vh,80px) auto 32px}
    .login .hero{height:auto;min-height:0;margin:0;padding:20px;border-radius:12px;overflow:visible}
    .login .hero:after{display:none}
    .login .hero h1,.login .hero p{display:block}
    .login form{margin-top:16px}
    .login label{margin:12px 0}
    .login input{min-height:42px}
    .login button{width:100%;min-height:44px;margin-top:6px}
    @media(max-height:620px){.login{margin:12px auto 24px}.login .hero{padding:16px}}
    """


def control_reference_css():
    return """
    /* Quantum Control reference layout · 2026-10-01 */
    body{background:#030d1c;background-image:radial-gradient(ellipse at 65% 0,#0c244044,transparent 60%);font-size:14px}
    main{max-width:none;padding:0 20px 24px 0}.panel-shell{grid-template-columns:248px minmax(0,1fr);gap:24px}
    .sidebar{position:sticky;top:0;height:100vh;min-height:0;border-radius:0;border:0;border-right:1px solid #152c46;background:linear-gradient(170deg,#071427,#03101f);padding:22px 12px;box-shadow:none}
    .sidebar-brand{font-size:20px;text-transform:none;letter-spacing:0;padding:0 8px 24px;position:relative}.sidebar-brand:before{content:'Q';font-size:38px;color:#23d8ff;float:left;margin:0 13px 0 0;line-height:1.3}.sidebar-brand span{margin-left:52px;font-size:10px;letter-spacing:.13em}
    nav.tabs a{padding:15px 12px;margin-bottom:5px;border-radius:8px;color:#aac8e9}nav.tabs a.active{background:linear-gradient(95deg,#073646,#14264f);box-shadow:inset 4px 0 #22e4ed,0 0 20px #10bde311;color:#effaff}
    nav.tabs a[href$='cards']{border:1px solid #263558;color:#b59cff;margin-top:16px;background:linear-gradient(120deg,#0e223c,#0c1730)}
    .sidebar:after{content:'Больше свободы в безопасном мире';display:block;margin:30px 16px;color:#69bded;font-size:16px;max-width:155px}
    .panel-content{min-width:0;padding-top:0}.hero{border:0;border-bottom:1px solid #15314c;background:transparent;box-shadow:none;border-radius:0;height:70px;padding:12px 0;margin-bottom:20px}.hero-top:before{display:none}.control-search{display:flex;width:min(50%,560px);margin:0;gap:6px}.control-search input{margin:0;height:38px}.control-search button{padding:6px 12px}.system-pill:after{display:none}
    .card,.dashboard .card{background:linear-gradient(130deg,#06162b,#071426 70%,#091b30);border:1px solid #1c3d5d;border-radius:10px;box-shadow:inset 0 1px #a0e5ff08;padding:18px}
    button,.button,a.button{background:linear-gradient(130deg,#76f5ff,#16cde9);border:1px solid #61e7fa;color:#042034;border-radius:6px;font-weight:650;box-shadow:0 0 14px #21d5ee22}button.secondary,a.secondary{background:#091c32;color:#bfeeff;border-color:#285678;box-shadow:none}
    .reference-heading{display:flex;justify-content:space-between;align-items:center;margin:0 0 16px}.reference-heading h1{font-size:26px;margin:0 0 4px}.reference-heading p{margin:0;color:#8eadd0}.reference-heading small{color:#90b3d8}
    .sidebar{overflow-y:auto;box-sizing:border-box}.sidebar-brand{font-size:17px;white-space:nowrap}.sidebar-brand:before{font-size:34px;margin-right:8px}.sidebar-brand span{margin-left:42px;font-size:9px}.sidebar nav.tabs{gap:3px}.sidebar nav.tabs a{padding:11px 10px;margin-bottom:0}.panel-content a:not(.button){color:#62caff;text-decoration:none}.panel-content a:hover{text-decoration:underline}h1,h2,nav.tabs a{letter-spacing:normal!important}
    .reference-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}.reference-kpi{display:flex;gap:14px;align-items:center;min-height:96px}.reference-kpi i{font-style:normal;font-size:26px;display:grid;place-items:center;width:52px;height:54px;border-radius:12px;background:#093244;color:#23e0ee}.reference-kpi:nth-child(4) i{background:#321a35;color:#ff7196}.reference-kpi span{font-size:12px;color:#a8c3e4}.reference-kpi b{display:block;font-size:26px;margin:3px 0;color:#e9f5ff}.reference-kpi small{color:#7e9fc3}
    .reference-top{display:grid;grid-template-columns:1.35fr 1fr;gap:14px;margin-bottom:14px}.reference-bottom{display:grid;grid-template-columns:1.4fr .9fr .9fr;gap:14px}.reference-bottom>*,.reference-top>*{min-width:0}.reference-stack{display:grid;gap:14px;align-content:start}.reference-table{overflow:auto;max-width:100%}.reference-table table{font-size:12px;margin:0;width:100%}.reference-table th{white-space:nowrap;font-weight:500}.reference-table td{padding:12px 8px}
    .reference-map{position:relative;min-height:255px;background:radial-gradient(ellipse at center,#0a32415c,transparent 70%)}.reference-map svg{width:100%;height:245px}.reference-map-note{color:#7398b9;font-size:11px;text-align:center}.reference-node-strip{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.reference-node-strip span{padding:6px 9px;background:#081e30;border:1px solid #1a3d53;border-radius:6px;font-size:11px}.reference-node-strip b{color:#39e7c2;margin-left:8px}
    .reference-game{padding:20px;border-radius:10px;background:radial-gradient(ellipse at 80% 0,#6a32ba77,transparent),linear-gradient(110deg,#172965,#1c1649);border:1px solid #51427c;margin-bottom:14px}.reference-game strong{font-size:28px;display:block;color:#e5dcff}.reference-game p{color:#b9b1ef;font-size:12px}.reference-game a{display:inline-block;margin-top:5px}.reference-audit{font-size:12px;display:flex;gap:10px;border-bottom:1px solid #132e47;padding:10px 0}.reference-audit time{color:#7398b9;white-space:nowrap}.reference-audit span{overflow-wrap:anywhere}.event-row{min-height:42px;grid-template-columns:8px 42px 82px minmax(0,1fr);font-size:12px}.event-row i{display:none}
    .reference-node-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.reference-node b{font-size:15px;overflow-wrap:anywhere}.reference-node .latency{font-size:25px;color:#41ead0;margin:18px 0 5px}.reference-node small{color:#83a6c5}.badge{display:inline-block;padding:4px 8px;border-radius:15px;background:#10283e}.badge.ok{background:#06392f;color:#35eab7}.badge.off{background:#381a31;color:#ff7491}.node-map-details{margin-top:14px;border-top:1px solid #17384f;padding-top:12px}.node-map-details summary{cursor:pointer;color:#91dff7;font-weight:650}.node-map-details textarea{min-height:105px;font-family:Consolas,monospace;font-size:12px}
    @media(min-width:1100px){.panel-content>.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:1200px){.panel-shell{grid-template-columns:210px minmax(0,1fr);gap:16px}.reference-bottom{grid-template-columns:1fr 1fr}.reference-bottom>.card:first-child{grid-column:1/-1}.reference-kpi{padding:12px!important;gap:8px}.reference-kpi i{display:none}.reference-top{grid-template-columns:1fr}}
    @media(max-width:800px){main{padding:10px}.panel-shell{grid-template-columns:1fr}.sidebar{position:static;height:auto;padding:8px}.sidebar:after{display:none}.hero{height:auto}.hero-top{flex-wrap:wrap;gap:10px}.control-search{width:100%}.reference-kpis{grid-template-columns:1fr 1fr}.reference-bottom{grid-template-columns:1fr}.reference-heading h1{font-size:22px}}
    """


@lru_cache(maxsize=1)
def operator_world_geometry() -> str:
    asset = os.path.join(os.path.dirname(__file__), 'assets', 'quantumvpn-world.svg')
    try:
        with open(asset, encoding='utf-8') as stream:
            geometry = stream.read(256_001)
        if len(geometry) > 256_000 or not geometry.startswith('<g class="world-countries"'):
            return ''
        return geometry
    except OSError:
        return ''


def reference_world_map(nodes: list[dict]):
    """Render a world base plus pins supplied by the authenticated node registry."""
    markers = []
    for node in nodes:
        x = 22 + ((float(node["longitude"]) + 180) / 360) * 756
        y = 18 + ((90 - float(node["latitude"])) / 180) * 314
        color = "#35e7ad" if node.get("state") == "ok" else "#ffb44b" if node.get("state") == "unknown" else "#ff647d"
        label_x = min(700, max(8, x + 11))
        label_y = max(18, min(334, y - 10))
        title = f"{node['label']} · {node['location']} · {node['measurement']}"
        markers.append(
            f"<g><title>{html.escape(title)}</title><circle cx='{x:.1f}' cy='{y:.1f}' r='12' fill='{color}' opacity='.16'/><circle cx='{x:.1f}' cy='{y:.1f}' r='6' fill='{color}' stroke='#d8f8ff' stroke-width='1.5'/><text x='{label_x:.1f}' y='{label_y:.1f}' fill='{color}' font-size='12'>{html.escape(node['label'])}</text></g>"
        )
    geometry = operator_world_geometry()
    if not geometry:
        return '<div class="reference-map empty-state">Географическая карта недоступна. Реестр и замеры нод показаны ниже.</div>'
    return '''<div class=reference-map data-world-source=natural-earth><svg viewBox="0 0 800 350" aria-label="Карта реальных нод" role=img>
    <defs><pattern id=world-dots width=7 height=7 patternUnits=userSpaceOnUse><circle cx=2 cy=2 r=1.4 fill="#267395"/></pattern></defs>
    ''' + geometry + "".join(markers) + "</svg></div>"


def render_login(error=""):
    return f"""<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
    <title>Quantum Control · вход</title><style>{css()}{control_reference_css()}{aurora_css()}</style><body class=aurora-panel data-ui=Aurora2>
    <main class=login><section class=hero><div class=accent>QUANTUM CONTROL</div><h1>Вход в панель</h1>
    <p class=muted>Доп. веб-панель приложения. RosPanel не изменяется.</p>
    {"<p class=off>" + html.escape(error) + "</p>" if error else ""}
    <form method=post action=/operator/login>
      <label>Логин<input name=username autocomplete=username required></label>
      <label>Пароль<input type=password name=password autocomplete=current-password required></label>
      <label>Код 2FA (если включён)<input name=totp inputmode=numeric autocomplete=one-time-code placeholder=000000></label>
      <button>Войти</button>
      <button type=button class=secondary data-passkey=authenticate {'disabled' if not control_next.passkey_available() else ''}>Войти с passkey</button>
      <p id=passkey-status class=muted>Пароль и код 2FA остаются доступны для восстановления входа.</p>
    </form></section></main>{aurora_script()}{control_next.passkey_script()}</body></html>"""


def render_panel(s, rows, users, protocols, summary, status, audit_rows, device_rows, flash="", section="dashboard", q="", device=None, donation_rows=None, donation_totals=None, admin_rows=None, actor_role="owner", card_rows=None, card_wallet_rows=None, actor_user="", control_csrf=""):
    checked = lambda key: "checked" if s.get(key) == "1" else ""
    next_quality_html = next_history_html = passkey_html = ""
    if section in {"quality", "release", "security", "admins"}:
        control_db = conn()
        try:
            if section in {"quality", "release"}:
                next_quality_html = control_next.render_dashboard(control_next.dashboard_snapshot(control_db, s))
                if role_at_least(actor_role, "operator"):
                    next_history_html = control_next.render_history(control_next.config_history(control_db), control_csrf)
            if section in {"security", "admins"}:
                passkey_html = control_next.render_passkeys(control_next.passkey_list(control_db, actor_user), actor_user, control_csrf)
        finally:
            control_db.close()
    next_guard_html = control_next.render_guard_form(s, control_csrf) if section == "release" and actor_role == "owner" else ""
    # Keep an operator draft local to the panel.  The client receives only a
    # signed production/staging revision, never this data.
    routing_form_state = dict(s)
    routing_draft_label = "Черновика нет"
    try:
        routing_draft = json.loads(s.get("routing_draft_payload") or "{}")
        if routing_draft:
            routing_form_state.update(routing_settings_from_payload(routing_draft))
            updated_at = int(s.get("routing_draft_updated_at", "0") or 0)
            routing_draft_label = "Черновик сохранён" + (
                " · " + time.strftime("%d.%m %H:%M", time.localtime(updated_at)) if updated_at else ""
            )
    except (ValueError, TypeError, json.JSONDecodeError):
        routing_draft_label = "Черновик повреждён — используется текущая опубликованная политика"
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
    reserve_profile_ready = bool(reserve_profile_uri())
    reserve_profile_state = (
        "<span class=ok>● готов: Trojan / TLS, порт 9443</span>"
        if reserve_profile_ready else
        "<span class=off>● не готов: резервный профиль не опубликован</span>"
    )
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
    card_table_html = "".join(
        f"<tr><td><code>{html.escape(str(row[0]))}</code></td><td>{html.escape(str(row[5]))}</td>"
        f"<td>{html.escape(str(row[7] or 'Ожидание'))}</td>"
        f"<td><span class='badge {'ok' if row[3] == 'ready' else 'warn'}'>{'Готов' if row[3] == 'ready' else 'Ожидает'}</span></td>"
        f"<td>{time.strftime('%d.%m %H:%M', time.localtime(row[2]))}</td></tr>"
        for row in (card_rows or [])
    ) or "<tr><td colspan=5>Открытых столов нет</td></tr>"
    card_wallet_html = "".join(
        f"<tr><td><code>{html.escape(str(row[0])[:20])}</code></td><td>{html.escape(str(row[1] or 'Игрок'))}</td>"
        f"<td class=ok><b>{max(0, int(row[2] or 0)):,}</b> Q-coins</td>"
        f"<td>{time.strftime('%d.%m %H:%M', time.localtime(int(row[3] or 0))) if row[3] else '—'}</td></tr>"
        for row in (card_wallet_rows or [])
    ) or "<tr><td colspan=4>Игроки ещё не входили за стол</td></tr>"
    card_code_state = "настроен" if s.get("card_game_access_hash") else "не настроен"
    subscription_category_title = s.get("subscription_category_title", "Подписка")[:80]
    subscription_category_description = s.get("subscription_category_description", "Управление доступом и резервным профилем")[:240]
    subscription_main_label = s.get("subscription_main_label", "Встроенная подписка включена")[:160]
    reserve_profile_label = s.get("reserve_profile_label", "Публиковать пятый профиль «Резерв TLS»")[:160]
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
    telegram_env_managed = bool(os.environ.get("QV_TELEGRAM_BOT_TOKEN", "").strip())
    # Never render a usable token, even to an owner.  Server environment is
    # preferred and the legacy SQLite value remains only for migration.
    telegram_token = ""
    telegram_token_hint = "Токен управляется секретом VDS" if telegram_env_managed else "Введите токен один раз; после сохранения он не показывается"
    monitor_db = conn()
    try:
        monitor_rows = health_snapshot(monitor_db, limit=200)
        incident_rows = [dict(row) for row in monitor_db.execute(
            "select id,opened_at,closed_at,severity,source,title,detail,dedupe_key from incidents order by closed_at asc, opened_at desc limit 200"
        ).fetchall()]
        report = report_snapshot(monitor_db)
        balancer = load_balancer_snapshot(monitor_db, s)
        routing_history = [dict(row) for row in monitor_db.execute(
            "select id,revision,created_at,actor,state,note,payload from routing_revisions order by id desc limit 12"
        ).fetchall()]
        support_tickets = [dict(row) for row in monitor_db.execute(
            "select id,created_at,updated_at,closed_at,source,device,subject,body,admin_note "
            "from support_tickets order by closed_at asc, updated_at desc limit 120"
        ).fetchall()]
        community_support_html = control_next.render_support(
            community.operator_threads(monitor_db)["threads"], can_write=role_at_least(actor_role, "operator"), csrf=control_csrf
        ) if section == "support" else ""
        quality_html = render_quality(quality_snapshot(monitor_db, s, ROSPANEL_DB), s) if section == "quality" else ""
        resources_html = resources.render(monitor_db) if section == "resources" else ""
    finally:
        monitor_db.close()
    release_guard = release_guard_snapshot(s)
    backup_info = latest_backup_info()
    quarantined_nodes = balancer.get("quarantined") or []
    quarantine_html = ", ".join(html.escape(str(x)) for x in quarantined_nodes) or "нет"
    drained_nodes = manual_node_drains(s)
    drain_html = ", ".join(html.escape(str(x)) for x in drained_nodes) or "нет"
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
    health_monitor_interval = html.escape(s.get("health_monitor_interval_seconds", "60"))
    digest_time_msk = html.escape(s.get("telegram_digest_time_msk", "09:00"))
    last_digest = html.escape(s.get("telegram_digest_last_sent_date") or "ещё не отправлялся")
    health_monitor_label = "включён" if enabled(s, "health_monitor_enabled", True) else "приостановлен"
    backup_label = (
        time.strftime("%d.%m.%Y %H:%M", time.localtime(backup_info["ts"]))
        if backup_info.get("exists") else "ещё нет"
    )
    ai_last_run = int(s.get("ai_last_run", "0") or 0)
    ai_last_run_label = time.strftime("%d.%m.%Y %H:%M", time.localtime(ai_last_run)) if ai_last_run else "ещё не запускался"
    ai_status = s.get("ai_last_status", "ожидание")[:64]
    ai_advice = s.get("ai_last_advice", "Модель ещё не выполнила анализ.")[:1800]
    ai_error = s.get("ai_last_error", "")[:280]
    def release_guard_row(item):
        if item.get("ready"):
            state = "готов"
            css_class = "ok"
            detail = "ARM64 и ARMv7 найдены"
        elif not item.get("configured") and item.get("name") == "По расписанию":
            state = "не настроен"
            css_class = "muted"
            detail = "запланированного релиза нет"
        else:
            state = "не готов"
            css_class = "off"
            detail = "нет: " + ", ".join(item.get("missing_abis") or REQUIRED_RELEASE_ABIS)
        return (
            f"<tr><td><b>{html.escape(item['name'])}</b></td><td>{html.escape(item['version'])}</td>"
            f"<td>{int(item['version_code'] or 0) or '—'}</td><td class='{css_class}'>{state}</td><td>{html.escape(detail)}</td></tr>"
        )
    release_guard_html = release_guard_row(release_guard["production"]) + release_guard_row(release_guard["scheduled"])
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
    support_open = sum(1 for item in support_tickets if not int(item.get("closed_at") or 0))
    def support_row(item):
        is_open = not int(item.get("closed_at") or 0)
        action = "close" if is_open else "reopen"
        action_label = "Закрыть" if is_open else "Открыть"
        state = "Открыто" if is_open else "Закрыто"
        return (
            f"<tr><td>#{int(item['id'])}</td><td class={'warn' if is_open else 'ok'}>{state}</td>"
            f"<td><b>{html.escape(item['subject'])}</b><br><span class=muted>{html.escape(item['body'][:180])}</span></td>"
            f"<td>{html.escape(item['device'] or item['source'] or '—')}</td>"
            f"<td>{time.strftime('%d.%m %H:%M', time.localtime(item['updated_at']))}</td>"
            f"<td><form method=post action=/operator/support class=actions><input type=hidden name=action value={action}><input type=hidden name=id value={int(item['id'])}><button class=secondary>{action_label}</button></form></td></tr>"
        )
    support_html = "".join(support_row(item) for item in support_tickets) or "<tr><td colspan=6>Обращений пока нет</td></tr>"
    webhook_events = html.escape(s.get("webhook_events", "incident,release,maintenance,diagnostic"))
    routing_profile_options = "".join(
        f"<option value='{name}' {'selected' if routing_form_state.get('routing_profile', 'balanced') == name else ''}>{html.escape(label)}</option>"
        for name, label in ROUTING_PROFILES.items()
    )
    routing_dns_options = "".join(
        f"<option value='{name}' {'selected' if s.get('routing_dns_mode', 'vpn_only') == name else ''}>{html.escape(label)}</option>"
        for name, label in ROUTING_DNS_MODES.items()
    )
    routing_staging_on = enabled(s, "routing_staging_enabled", False)
    routing_staging_revision = int(s.get("routing_staging_revision", "0") or 0)
    routing_staging_rollout = max(1, min(100, int(s.get("routing_staging_rollout_percent", "10") or 10)))
    try:
        active_routing = routing_payload(s)
        routing_counts = active_routing["rules"]
        routing_counts_label = (
            f"{len(routing_counts['direct_domains'])} direct · "
            f"{len(routing_counts['proxy_domains'])} proxy · "
            f"{len(routing_counts['block_domains'])} block"
        )
    except ValueError:
        routing_counts_label = "проверьте формат списков"
    routing_history_html = "".join(
        f"<tr><td>r{int(item['revision'])}</td>"
        f"<td>{time.strftime('%d.%m %H:%M', time.localtime(item['created_at']))}</td>"
        f"<td>{html.escape(item['actor'])}</td><td>{html.escape(item['state'])}</td>"
        f"<td>{html.escape(item['note'] or '—')}</td><td>"
        + (
            "<form method=post action=/operator/routing style='margin:0'><input type=hidden name=action value=rollback>"
            f"<input type=hidden name=revision value='{int(item['revision'])}'><button class=secondary>Откатить</button></form>"
            if item["state"] == "production" else "—"
        )
        + "</td></tr>"
        for item in routing_history
    ) or "<tr><td colspan=6>История появится после первой публикации.</td></tr>"
    routing_signature_label = "Ed25519 готова" if Ed25519PrivateKey is not None else "нужен пакет cryptography"
    routing_scan_targets = (s.get("routing_scan_targets") or "").strip()[:4096]
    try:
        saved_scan = json.loads(s.get("routing_last_scan") or "[]")
        if not isinstance(saved_scan, list):
            saved_scan = []
    except (TypeError, ValueError, json.JSONDecodeError):
        saved_scan = []
    scan_recommendation_labels = {
        "direct": "напрямую",
        "proxy": "через VPN",
        "block": "блок-лист",
        "observe": "проверить вручную",
    }
    scan_rows = []
    for item in saved_scan[:MAX_ROUTING_SCAN_TARGETS]:
        if not isinstance(item, dict):
            continue
        target = str(item.get("target") or "")[:253]
        kind = str(item.get("kind") or "")
        if kind not in ("domain", "ip") or not target:
            continue
        latency = item.get("latency_ms")
        latency_label = f"{int(latency)} мс" if isinstance(latency, int) and latency >= 0 else "нет TCP-ответа"
        addresses = item.get("addresses") if isinstance(item.get("addresses"), list) else []
        address_labels = []
        for sample in addresses[:MAX_ROUTING_SCAN_ADDRESSES]:
            if not isinstance(sample, dict):
                continue
            address = str(sample.get("address") or "")[:64]
            sample_latency = sample.get("latency_ms")
            if address:
                address_labels.append(address + (f" · {int(sample_latency)} мс" if isinstance(sample_latency, int) else " · timeout"))
        scan_status = "ok" if item.get("status") == "ok" else "warn"
        recommendation = scan_recommendation_labels.get(str(item.get("recommendation") or ""), "проверить вручную")
        reason = str(item.get("reason") or "")[:180]
        scan_rows.append(
            f"<tr><td><b>{html.escape(target)}</b><br><span class=muted>{html.escape('домен' if kind == 'domain' else 'IP')}</span></td>"
            f"<td class={scan_status}>{html.escape(latency_label)}</td><td>{html.escape(', '.join(address_labels) or 'адрес не получен')}</td>"
            f"<td><b>{html.escape(recommendation)}</b><br><span class=muted>{html.escape(reason)}</span></td></tr>"
        )
    routing_scan_html = "".join(scan_rows) or "<tr><td colspan=4>Проверка ещё не запускалась.</td></tr>"
    routing_scan_compact_html = "".join(
        f"<div class='scan-result'><div><b>{html.escape(str(item.get('target') or '')[:253])}</b><small>{html.escape(scan_recommendation_labels.get(str(item.get('recommendation') or ''), 'проверить вручную'))}</small></div>"
        f"<span class={'ok' if item.get('status') == 'ok' else 'warn'}>{str(int(item.get('latency_ms'))) + ' мс' if isinstance(item.get('latency_ms'), int) and item.get('latency_ms') >= 0 else 'нет ответа'}</span></div>"
        for item in saved_scan[:MAX_ROUTING_SCAN_TARGETS]
        if isinstance(item, dict) and str(item.get('target') or '')
    ) or "<div class='routing-empty'>Добавьте домены и нажмите «Сканировать цели». Проверка выполняется TCP/443 с VDS.</div>"
    event_timeline = "".join(
        f"<div class='event-row'><span class='event-dot {'warn' if kind in ('error','incident') else 'ok'}'></span>"
        f"<time>{time.strftime('%H:%M', time.localtime(ts))}</time><b>{html.escape(device or 'Система')[:22]}</b>"
        f"<span>{html.escape(detail or kind)[:90]}</span><i>•••</i></div>"
        for ts, kind, device, ip, detail in rows[:7]
    ) or "<div class=empty-state>Событий пока нет</div>"
    map_nodes = []
    for node in parse_node_map_config(s.get("node_map_config", "")):
        sample = latest_monitor.get(f"latency:{node['target']}") or latest_monitor.get(node["target"])
        if sample and sample.get("ok"):
            state, measurement = "ok", f"{int(sample.get('latency_ms') or 0)} мс"
        elif sample:
            state, measurement = "off", "нет ответа"
        else:
            state, measurement = "unknown", "замер ещё не выполнен"
        map_nodes.append({**node, "state": state, "measurement": measurement})
    node_drain_cards = "".join(
        f"<article class='card reference-node'><b>{html.escape(node['label'])}</b><p><small>{html.escape(node['location'])} · {html.escape(node['target'])}</small></p>"
        f"<p><span class='badge {'warn' if node['target'] in drained_nodes else ('ok' if node['state'] == 'ok' else 'off')}'>{'Техобслуживание' if node['target'] in drained_nodes else 'Доступна' if node['state'] == 'ok' else 'Нет ответа' if node['state'] == 'off' else 'Ожидает замер'}</span></p>"
        f"<div class=latency>{html.escape(node['measurement'])}</div>"
        f"<form method=post action=/operator/actions class=actions style='margin-top:10px'><input type=hidden name=return_tab value=latency><input type=hidden name=target value='{html.escape(node['target'], quote=True)}'><input type=hidden name=action value={'restore_node' if node['target'] in drained_nodes else 'drain_node'}><button class=secondary>{'Вернуть в балансировку' if node['target'] in drained_nodes else 'Перевести в техработы'}</button></form></article>"
        for node in map_nodes
    ) or "<div class=card>Ноды для карты не настроены</div>"
    reference_targets = "".join(
        f"<span>{html.escape(str(target).removeprefix('latency:'))}<b class={'ok' if row.get('ok') else 'off'}>{str(row.get('latency_ms')) + ' мс' if row.get('ok') and row.get('latency_ms') is not None else 'нет ответа'}</b></span>"
        for target, row in list(latest_monitor.items())[:6]
    ) or '<span>Ожидание первых измерений</span>'
    reference_users = "".join(
        f"<tr><td>{html.escape(str(name))}</td><td><span class='badge {'ok' if en else 'off'}'>{'Активен' if en else 'Отключён'}</span></td><td>{((up or 0)+(down or 0))/1024**3:.2f} ГБ</td><td>{time.strftime('%d.%m %H:%M', time.localtime(seen)) if seen else '—'}</td></tr>"
        for name, en, status_u, up, down, expires, seen, uid in users[:6]
    ) or '<tr><td colspan=4>Пользователи пока не загружены</td></tr>'
    reference_audit = ''.join(
        f"<div class=reference-audit><time>{time.strftime('%H:%M', time.localtime(a[0]))}</time><span>{html.escape(str(a[1]))} · {html.escape(str(a[3]))}</span></div>"
        for a in audit_rows[:4]
    ) or '<p class=muted>Записей пока нет</p>'
    page_title, page_description = PAGE_TITLES.get(section, PAGE_TITLES['dashboard'])
    navigation, subnavigation = aurora_navigation(section, actor_role)
    current_missing_abis = scheduled_release_missing_abis(s.get('app_version', VERSION))
    return f"""<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
    <title>{html.escape(page_title)} · Quantum Control</title><style>{css()}{control_reference_css()}{aurora_css()}</style><body class=aurora-panel data-ui=Aurora2><main><div class=panel-shell>
      <aside class=sidebar>
      <div class=sidebar-brand>Quantum Control<span>AURORA · 2.0</span></div>
      {navigation}
      <a class=aurora-logout href="/operator/logout">Выход из панели</a>
      </aside>
      <section class=panel-content>
    <section class=hero>
      <div class=hero-top><form class=control-search method=get action=/operator><input type=hidden name=tab value=users><input name=q aria-label="Поиск пользователей" placeholder="Поиск по пользователям…" value="{html.escape(q)}"><button>Найти</button></form><span id=system-pill class=system-pill>{'● Есть открытые инциденты' if report['open_incidents'] else '● Открытых инцидентов нет'}</span><span class=top-date>{time.strftime('%d.%m.%Y %H:%M', time.gmtime(time.time()+10800))}<br><small>МСК · {html.escape(actor_role)}</small></span></div>
    </section>
    {flash_html}
    <header class=reference-heading><div><h1>{html.escape(page_title)}</h1><p>{html.escape(page_description)}</p></div><small>Aurora 2.0</small></header>
    {subnavigation}
    {quality_html}
    <section {show('quality')}>{next_quality_html}{next_history_html}</section>
    <section {show('release')}>{next_quality_html}{next_guard_html}{next_history_html}</section>
    {resources_html}

    <section class="dashboard" {show('dashboard')}>
      <div class=reference-kpis>
        <div class="card reference-kpi"><i>▤</i><div><span>Доступность проверок</span><b>{sum(1 for r in latest_monitor.values() if r.get('ok'))} / {len(latest_monitor)}</b><small>Последние измерения</small></div></div>
        <div class="card reference-kpi"><i>♙</i><div><span>Активные подписки</span><b>{summary.get('active', '—') if summary.get('ok') else '—'}</b><small>Онлайн за 15 мин: {summary.get('online_15m', '—') if summary.get('ok') else '—'}</small></div></div>
        <div class="card reference-kpi"><i>⇅</i><div><span>Трафик за сегодня</span><b>{summary.get('traffic_today_gb', '—') if summary.get('ok') else '—'} ГБ</b><small>По данным RosPanel</small></div></div>
        <div class="card reference-kpi"><i>△</i><div><span>Открытые события</span><b>{report['open_incidents']}</b><small>Требуют внимания</small></div></div>
      </div>
      <div class=reference-top>
        <section class=card><div class=section-head><h2>Карта нод и текущая нагрузка</h2><a href="/operator?tab=latency">Управлять нодами →</a></div>{reference_world_map(map_nodes) if section == 'dashboard' else ''}<div class=reference-map-note>Показаны {len(map_nodes)} нод из реестра · CPU {status.get('cpu_load_pct', 0)}% · RAM {status.get('memory_used_pct', 0)}% · диск {status.get('disk_used_pct', 0)}%. Пинг измеряется с VDS; это не пинг телефона пользователя.</div><div class=reference-node-strip>{''.join(f"<span>{html.escape(node['label'])}<b class={'ok' if node['state'] == 'ok' else 'off'}>{html.escape(node['measurement'])}</b></span>" for node in map_nodes) or reference_targets}</div></section>
        <section class=card><div class=section-head><h2>Последние события</h2><a href="/operator?tab=incidents">Все события →</a></div><div class=event-list>{event_timeline}</div></section>
      </div>
      <div class=reference-bottom>
        <section class=card><div class=section-head><h2>Пользователи</h2><a href="/operator?tab=users">Все пользователи →</a></div><div class=reference-table><table><thead><tr><th>Пользователь</th><th>Статус</th><th>Трафик</th><th>Активность</th></tr></thead><tbody>{reference_users}</tbody></table></div></section>
        <section class=card><div class=section-head><h2>Игровая активность</h2></div><div class=reference-game><strong>{sum(int(r[2] or 0) for r in (card_wallet_rows or [])):,} Q-coins</strong><p>Баланс {len(card_wallet_rows or [])} игроков в текущей выборке</p><p>Виртуальные очки · без вывода</p><a class=button href="/operator?tab=cards">Игры и награды →</a></div><div class=stat>Открытые столы<b>{len(card_rows or [])}</b></div><p class=muted>Управляйте доступом к игре и начисляйте награды игрокам.</p></section>
        <div class=reference-stack>
          <section class=card><div class=section-head><h2>Релизы</h2><a href="/operator?tab=release">Все →</a></div><p><span class="badge ok">Стабильный</span> <b>{html.escape(s.get('app_version', VERSION))}</b></p><p class=muted>Охват: {html.escape(s.get('rollout_percent','100'))}%</p><p><span class=pill>По расписанию</span> {html.escape(s.get('scheduled_app_version') or '—')}</p><a href="/operator?tab=release">Управлять публикацией →</a></section>
          <section class=card><div class=section-head><h2>Последние записи аудита</h2><a href="/operator?tab=audit">Все →</a></div>{reference_audit}</section>
        </div>
      </div>
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

    <section {show('service')}><div class=reference-kpis>
      <div class="card reference-kpi"><div><span>Активные подписки</span><b>{summary.get('active', '—')}</b></div></div>
      <div class="card reference-kpi"><div><span>Отключённые</span><b>{summary.get('disabled', '—')}</b></div></div>
      <div class="card reference-kpi"><div><span>Истёкшие</span><b>{summary.get('expired', '—')}</b></div></div>
      <div class="card reference-kpi"><div><span>Протоколы</span><b>{len(protocols)}</b></div></div>
    </div><div class="card reference-table"><div class=section-head><h2>Подписки пользователей</h2><a class=button href="{html.escape(rp_base)}" target=_blank rel=noopener>Управлять в RosPanel ↗</a></div><table><thead><tr><th>Имя</th><th>Доступ</th><th>Состояние</th><th>Трафик</th><th>Действует до</th><th>Активность</th><th>Управление</th></tr></thead><tbody>{subscribers}</tbody></table></div></section>
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
        <h2>{html.escape(subscription_category_title)}</h2>
        <p class=muted>{html.escape(subscription_category_description)}</p>
        <label><input type=checkbox name=subscription_main_enabled {checked('subscription_main_enabled')}> {html.escape(subscription_main_label)}</label>
        <label><input type=checkbox name=reserve_profile_enabled {checked('reserve_profile_enabled')}> {html.escape(reserve_profile_label)}</label>
        <p class=muted>Резерв добавляется только после проверки устройства RosPanel; секрет профиля не показывается в панели и не попадает в экспорт.</p>
        <p>{reserve_profile_state}</p>
        <p class=muted>Upstream: <code>{html.escape(UPSTREAM[:64])}…</code></p>
        <button>Сохранить</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=public_status>
        <h2>Public status site</h2>
        <p class={'off' if effective_maintenance(s) or not enabled(s, 'public_download_enabled', True) else 'ok'}>{'Downloads closed' if effective_maintenance(s) or not enabled(s, 'public_download_enabled', True) else 'Status online · downloads open'}</p>
        <p class=muted>Public English page without registration: <a href="/status" target=_blank rel=noopener>/status</a>. During maintenance downloads always close automatically.</p>
        <label><input type=checkbox name=public_download_enabled {'checked' if enabled(s, 'public_download_enabled', True) else ''}> Allow Android download when service is operational</label>
        <label>English public note<textarea name=public_status_note_en maxlength=160>{html.escape(s.get('public_status_note_en',''))}</textarea></label>
        <button>Save public site</button>
      </form>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=subscription_text>
        <h2>Тексты категории подписки</h2>
        <p class=muted>Меняет только подписи этой дополнительной панели. Данные пользователей, ссылки и настройки RosPanel не затрагиваются.</p>
        <label>Название категории<input name=subscription_category_title maxlength=80 value="{html.escape(subscription_category_title)}"></label>
        <label>Краткое описание<textarea name=subscription_category_description maxlength=240>{html.escape(subscription_category_description)}</textarea></label>
        <label>Текст основного переключателя<input name=subscription_main_label maxlength=160 value="{html.escape(subscription_main_label)}"></label>
        <label>Текст резервного переключателя<input name=reserve_profile_label maxlength=160 value="{html.escape(reserve_profile_label)}"></label>
        <button>Сохранить тексты</button>
      </form>
      <form class=card method=post action=/operator/protocols>
        <h2>Протоколы</h2>{toggles}<p class=muted>AMNEZIA‑WG: UDP {html.escape(s.get('amneziawg_port','59333'))}. Работоспособность зависит от полного профиля с ключами, выданного вашей подпиской; панель не создаёт ключи и не подменяет конфигурацию.</p><button>Сохранить протоколы</button>
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

    <section {show('latency')}>
      <div class=card><div class=section-head><h2>Карта нод</h2><span class=muted>Координаты из реестра нод</span></div>{reference_world_map(map_nodes) if section == 'latency' else ''}<p class=reference-map-note>Зелёный — последний TCP-замер успешен; красный — нет ответа; жёлтый — замер ещё не выполнялся.</p></div>
      <div class=reference-node-grid>{node_drain_cards}</div>
    </section>
    <section class=grid {show('latency')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=latency>
        <h2>Низкая задержка и стабильность</h2>
        <label><input type=checkbox name=latency_optimization_enabled {checked('latency_optimization_enabled')}> Включить автоматический мониторинг</label>
        <label>Интервал проверки, секунд<input type=number name=latency_probe_interval min=15 max=300 value="{html.escape(s.get('latency_probe_interval','30'))}"></label>
        <label>Порог деградации, мс<input type=number name=latency_max_ms min=20 max=5000 value="{html.escape(s.get('latency_max_ms','120'))}"></label>
        <label>TCP‑цели (host:port, через запятую)<textarea name=latency_probe_targets>{html.escape(s.get('latency_probe_targets','1.1.1.1:443,8.8.8.8:443'))}</textarea></label>
        <details class=node-map-details><summary>Ноды на карте</summary><p class=muted>Одна строка: название | host:port | широта | долгота | местоположение. Координаты нужны, чтобы отметить реальную ноду на карте.</p><label>Реестр нод<textarea name=node_map_config>{html.escape(s.get('node_map_config',''))}</textarea></label></details>
        <h3 style="margin-top:16px">Автоматический карантин</h3>
        <label><input type=checkbox name=auto_quarantine_enabled {checked('auto_quarantine_enabled')}> Исключать нестабильные ноды из балансировки</label>
        <label>Ошибок до исключения<input type=number name=auto_quarantine_failures min=2 max=10 value="{html.escape(s.get('auto_quarantine_failures','3'))}"></label>
        <label>Проверок для возврата<input type=number name=auto_quarantine_recovery_checks min=1 max=10 value="{html.escape(s.get('auto_quarantine_recovery_checks','2'))}"></label>
        <label>Время карантина, минут<input type=number name=auto_quarantine_ttl_minutes min=5 max=1440 value="{html.escape(s.get('auto_quarantine_ttl_minutes','30'))}"></label>
        <p class=muted>Панель помечает недоступные/нестабильные направления для автоматического выбора клиента. Для реального снижения 150–200 мс нужен VDS ближе к пользователям или дополнительная нода в другом регионе.</p>
        <p class=notice><b>Сейчас в карантине:</b> {quarantine_html}<br><b>Ручные техработы:</b> {drain_html}</p>
        <button>Сохранить оптимизацию</button>
      </form>
      <section class=card>
        <h2>Балансировщик нагрузки</h2>
        <label><input type=checkbox name=load_balancer_enabled form=latency-balancer-form {checked('load_balancer_enabled')}> Включать лучший доступный маршрут</label>
        <form id=latency-balancer-form method=post action=/operator/policy>
          <input type=hidden name=section value=latency_balancer>
          <label>Стратегия<select name=load_balancer_strategy><option value=latency_health {'selected' if s.get('load_balancer_strategy','latency_health') == 'latency_health' else ''}>Пинг + доступность</option><option value=stable {'selected' if s.get('load_balancer_strategy') == 'stable' else ''}>Стабильность</option></select></label>
          <label>Максимальный пинг для выбора, мс<input type=number name=load_balancer_max_latency_ms min=20 max=5000 value="{html.escape(s.get('load_balancer_max_latency_ms','250'))}"></label>
          <p class=muted>Выбор выполняется только по последним TCP‑проверкам. Нерабочие направления не рекомендуются.</p>
          <button>Сохранить балансировщик</button>
        </form>
        <div class=notice><b>Сейчас выбран:</b> {html.escape(balancer.get('selected') or 'нет доступной ноды')} · стратегия {html.escape(str(balancer.get('strategy')))}</div>
        <h2 style="margin-top:18px">Последние TCP‑замеры</h2>
        <table><thead><tr><th>Цель</th><th>Статус</th><th>Задержка</th><th>Время</th></tr></thead><tbody>{monitor_html}</tbody></table>
      </section>
    </section>

    <section class="routing-page" {show('routing')}>
      <header class=routing-heading>
        <div><div class=routing-kicker>ПРОВЕРКА ПЕРЕД ПУБЛИКАЦИЕЙ</div><p class=muted>Редактируйте нужные правила и публикуйте подписанную ревизию. Маршруты не меняются автоматически.</p></div>
        <div class=routing-health><span class=system-pill>r{int(s.get('routing_revision','1') or 1)} · {html.escape(routing_signature_label)}</span></div>
      </header>
      <section class=routing-top-grid>
        <section class="card routing-card routing-scanner">
          <h2>Анализатор целей</h2><p class=routing-subtitle>TCP/443 с VDS, до {MAX_ROUTING_SCAN_TARGETS} доменов или публичных IP.</p>
          <form method=post action=/operator/routing>
            <input type=hidden name=action value=scan>
            <label class=target-field><textarea rows=3 name=routing_scan_targets aria-label="Домены для проверки" placeholder="youtube.com\ndiscord.com\nmedia.discordapp.net">{html.escape(routing_scan_targets)}</textarea></label>
            <button class=routing-submit>Сканировать цели</button>
          </form>
          <div class=routing-results><span class=routing-results-title>Последняя проверка</span>{routing_scan_compact_html}</div>
        </section>
        <form id=routing-policy class="routing-policy-form" method=post action=/operator/routing>
          <section class="card routing-card routing-rules">
            <h2>Правила маршрута</h2><p class=routing-subtitle>Домен или CIDR через запятую либо с новой строки.</p>
            <section class="route-group proxy"><div class=route-group-head><b>Через VPN</b><span>защищённый маршрут</span></div><label><textarea rows=2 name=routing_proxy_domains aria-label="Домены через VPN">{html.escape(routing_form_state.get('routing_proxy_domains',''))}</textarea></label><details class=route-advanced><summary>CIDR / IP через VPN</summary><label><textarea rows=2 name=routing_proxy_cidrs aria-label="CIDR через VPN" placeholder="198.51.100.0/24">{html.escape(routing_form_state.get('routing_proxy_cidrs',''))}</textarea></label></details></section>
            <section class="route-group direct"><div class=route-group-head><b>Напрямую</b><span>исключения из VPN</span></div><label><textarea rows=1 name=routing_direct_domains aria-label="Домены напрямую" placeholder="service.example">{html.escape(routing_form_state.get('routing_direct_domains',''))}</textarea></label><details class=route-advanced><summary>CIDR / IP напрямую</summary><label><textarea rows=2 name=routing_direct_cidrs aria-label="CIDR напрямую" placeholder="203.0.113.0/24">{html.escape(routing_form_state.get('routing_direct_cidrs',''))}</textarea></label></details></section>
            <section class="route-group block"><div class=route-group-head><b>Блок-лист</b><span>реклама и трекеры</span></div><label><textarea rows=1 name=routing_block_domains aria-label="Заблокированные домены" placeholder="ads.example">{html.escape(routing_form_state.get('routing_block_domains',''))}</textarea></label></section>
          </section>
        </form>
        <section class="card routing-card routing-dns">
          <h2>DNS и публикация</h2><p class=routing-subtitle>Настройка действует только в активном VPN-туннеле.</p>
          <label class=routing-switch><span><b>Управляемая маршрутизация</b><small>Применять подписанную политику в APK с поддержкой rule-set.</small></span><input form=routing-policy type=checkbox name=routing_enabled {'checked' if routing_form_state.get('routing_enabled') == '1' else ''}></label>
          <label class=routing-switch><span><b>DNS только внутри VPN</b><small>Системный Private DNS Android не изменяется.</small></span><input form=routing-policy type=checkbox name=routing_dns_mode value=vpn_only {'checked' if routing_form_state.get('routing_dns_mode','vpn_only') == 'vpn_only' else ''}></label>
          <input form=routing-policy type=hidden name=routing_dns_mode value=vpn_only>
          <label class=routing-switch><span><b>Блокировка рекламы</b><small>Фильтрация только по опубликованному блок-листу доменов.</small></span><input form=routing-policy type=checkbox name=routing_adblock_enabled {'checked' if routing_form_state.get('routing_adblock_enabled') == '1' else ''}></label>
          <div class=dns-field><label>DNS-over-HTTPS<select form=routing-policy name=routing_dns_resolver><option value="{html.escape(routing_form_state.get('routing_dns_resolver',''))}">{html.escape(routing_form_state.get('routing_dns_resolver','') or 'Не выбран')}</option><option value="https://dns.adguard-dns.com/dns-query">AdGuard DNS</option><option value="https://cloudflare-dns.com/dns-query">Cloudflare</option></select></label><label>Профиль<select form=routing-policy name=routing_profile>{routing_profile_options}</select></label></div>
          <label style="margin:10px 0 0">Тестовый канал, %<input form=routing-policy type=number min=1 max=100 name=routing_staging_rollout_percent value="{routing_staging_rollout}"></label>
          <p class=muted>{html.escape(routing_draft_label)}. «Сохранить черновик» ничего не отправляет в APK.</p>
          <div class=routing-actions><button form=routing-policy class=secondary name=action value=save>Сохранить черновик</button><button form=routing-policy class=secondary name=action value=stage>Тестовый канал</button><button form=routing-policy name=action value=publish>Опубликовать r{int(s.get('routing_revision','1') or 1) + 1}</button></div>
        </section>
      </section>
      <section class=routing-footer>
        <section class="card routing-revision"><i>▣</i><div><small>Текущая ревизия</small><b>r{int(s.get('routing_revision','1') or 1)} <span class=ok>● Активна</span></b><small>Ed25519 · {html.escape(routing_counts_label)}</small></div></section>
        <section class="card routing-notice"><i>ⓘ</i><div><b>Блокировка рекламы не гарантируется для рекламы с доменов самого видеосервиса.</b><p>Фильтр безопасно блокирует только отдельные рекламные и трекерные домены; правила не должны ломать авторизацию, банки или обновления ОС.</p></div></section>
      </section>
      <details class="card routing-history"><summary>История маршрутизации и откат</summary><p class=muted>Откат создаёт новую ревизию — аудит и предыдущие версии сохраняются.</p><table><thead><tr><th>Ревизия</th><th>Время</th><th>Оператор</th><th>Канал</th><th>Заметка</th><th></th></tr></thead><tbody>{routing_history_html}</tbody></table></details>
    </section>

    <section class=grid {show('ai')}>
      <form class=card method=post action=/operator/policy>
        <input type=hidden name=section value=ai>
        <h2>Локальный Qwen</h2>
        <p class=muted>Советник анализирует агрегированные данные нод и сервисов на этом VDS. Он не получает пользователей, ключи, подписки, IP клиентов или журналы запросов.</p>
        <label><input type=checkbox name=ai_advisor_enabled {checked('ai_advisor_enabled')}> Включить ИИ‑советник</label>
        <label>Модель<input name=ai_model value="{html.escape(s.get('ai_model', QWEN_DEFAULT_MODEL))}" readonly></label>
        <label>Интервал анализа, секунд<input type=number name=ai_interval_seconds min=300 max=86400 value="{html.escape(s.get('ai_interval_seconds','900'))}"></label>
        <label><input type=checkbox name=ai_telegram_enabled {checked('ai_telegram_enabled')}> Отправлять новый важный вывод в Telegram</label>
        <p class=notice><b>Безопасность:</b> Qwen не имеет доступа к shell, API‑ключам, настройкам нод или кнопкам перезапуска. Балансировщик и карантин остаются детерминированными.</p>
        <button>Сохранить ИИ‑настройки</button>
      </form>
      <section class=card>
        <h2>Последний анализ</h2>
        <p><span class="badge {'ok' if ai_status == 'готов' else 'warn' if ai_status == 'ожидание модели' else 'off'}">{html.escape(ai_status)}</span> · {html.escape(ai_last_run_label)}</p>
        <p style="white-space:pre-wrap">{html.escape(ai_advice)}</p>
        {("<p class=off>" + html.escape(ai_error) + "</p>") if ai_error else ""}
        <form method=post action=/operator/actions class=actions>
          <input type=hidden name=return_tab value=ai>
          <button name=action value=run_ai_analysis>Запустить анализ</button>
          <button class=secondary name=action value=check_ai_model>Проверить модель</button>
        </form>
        <p class=muted style="margin-top:12px">Если Telegram настроен в «Безопасность», панель отправляет только новый вывод и не чаще раза в 15 минут.</p>
      </section>
    </section>

    <section class=grid {show('automation')}>
      <form class=card method=post action=/operator/policy><input type=hidden name=section value=automation>
        <h2>Автопилот панели</h2>
        <p class=muted>Проверки только читают состояние сервисов и подписки. Они не перезапускают RosPanel, Xray и не меняют конфигурацию нод.</p>
        <label><input type=checkbox name=health_monitor_enabled {checked('health_monitor_enabled')}> Мониторинг сервисов и подписки</label>
        <label>Интервал мониторинга, секунд<input type=number name=health_monitor_interval_seconds min=30 max=600 value="{health_monitor_interval}"></label>
        <label><input type=checkbox name=telegram_daily_digest_enabled {checked('telegram_daily_digest_enabled')}> Суточная сводка в Telegram</label>
        <label>Время сводки (МСК)<input type=time name=telegram_digest_time_msk value="{digest_time_msk}"></label>
        <p class=muted>Последняя отправленная сводка: {last_digest}. Для отправки должны быть заполнены Bot token и Chat ID в «Безопасность».</p>
        <button>Сохранить автопилот</button>
      </form>
      <section class=card>
        <h2>Готовность релизов</h2>
        <p class=muted>Публикация по расписанию блокируется, пока на VDS нет обоих файлов: ARM64 и ARMv7.</p>
        <table><thead><tr><th>Канал</th><th>Версия</th><th>Code</th><th>Статус</th><th>Проверка</th></tr></thead><tbody>{release_guard_html}</tbody></table>
        <div class=actions style="margin-top:14px"><a class="button secondary" href="/operator?tab=release">Открыть релизы</a></div>
      </section>
      <section class=card>
        <h2>Состояние автоматики</h2>
        <div class=stats>
          <div class=stat>Мониторинг<b class={'ok' if enabled(s, 'health_monitor_enabled', True) else 'off'}>{health_monitor_label}</b></div>
          <div class=stat>Маршрут<b>{html.escape(balancer.get('selected') or '—')}</b></div>
          <div class=stat>Пинг<b>{html.escape(str(s.get('latency_best_ms') or '—'))} мс</b></div>
          <div class=stat>Backup<b>{backup_label}</b></div>
        </div>
        <form class=actions style="margin-top:14px" method=post action=/operator/actions>
          <input type=hidden name=return_tab value=automation>
          <button class=secondary name=action value=run_health_check>Проверить сервисы</button>
          <button class=secondary name=action value=run_latency_probe>Обновить пинг</button>
          <button class=secondary name=action value=release_preflight>Проверить релизы</button>
        </form>
        <p class=muted style="margin-top:12px">Проверки выполняются в фоне. Обновите вкладку через несколько секунд, чтобы увидеть результат в журнале.</p>
      </section>
    </section>

    <section {show('release')}><div class=card><div class=section-head><h2>Текущий релиз · {html.escape(s.get('app_version', VERSION))}</h2><span class="badge ok">Стабильный</span></div><div class=reference-kpis><div class=stat>ARM64<b>{'Готов' if 'arm64-v8a' not in current_missing_abis else 'Нет файла'}</b></div><div class=stat>ARMv7<b>{'Готов' if 'armeabi-v7a' not in current_missing_abis else 'Нет файла'}</b></div><div class=stat>Охват<b>{html.escape(s.get('rollout_percent','100'))}%</b></div><div class=stat>Следующая версия<b>{html.escape(s.get('scheduled_app_version') or '—')}</b></div></div><p class=muted>Расписание и загрузка сборок доступны ниже.</p></div></section>
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

    <section class=grid {show('cards')}>
      <form class=card method=post action=/operator/cards>
        <h2>Игры и награды</h2>
        <p class=muted>Мобильные игроки входят по отдельному коду. Пароль администратора не передаётся в APK и не хранится на телефоне.</p>
        <label><input type=checkbox name=card_game_enabled {checked('card_game_enabled')}> Включить карточный стол</label>
        <label>Новый код доступа<input type=password name=card_game_access_code minlength=8 maxlength=80 autocomplete=new-password placeholder="Минимум 8 символов"></label>
        <label>Время ожидания второго игрока, минут<input type=number name=card_game_wait_minutes min=5 max=120 value="{html.escape(s.get('card_game_wait_minutes','20'))}"></label>
        <label>Ставка на игрока, Q-coins<input type=number name=card_game_stake_q_coins min=0 max=100000 value="{html.escape(s.get('card_game_stake_q_coins','25'))}"></label>
        <p class=muted>Только виртуальные Q-coins: при старте партии одинаковая ставка списывается у обоих, общий виртуальный банк получает победитель. Денег, покупки и вывода нет.</p>
        <p class={'ok' if s.get('card_game_access_hash') else 'warn'}>Код доступа: <b>{card_code_state}</b>. Оставьте поле пустым, чтобы не менять существующий код.</p>
        <button>Сохранить доступ к столу</button>
      </form>
      <section class=card>
        <h2>Открытые столы</h2>
        <p class=muted>Стол на двух игроков. Когда второй игрок входит, состояние меняется на «Готов» без обновления APK.</p>
        <table><thead><tr><th>Стол</th><th>Первый игрок</th><th>Второй игрок</th><th>Состояние</th><th>Обновлён</th></tr></thead><tbody>{card_table_html}</tbody></table>
      </section>
    </section>
    <section class=grid {show('cards')}>
      <form class=card method=post action=/operator/cards/wallet>
        <h2>Виртуальные Q-coins</h2>
        <p class=muted>Очки работают только в игре. Это не деньги: их нельзя купить, вывести, обменять или использовать вне приложения.</p>
        <label>Устройство игрока<input name=device minlength=4 maxlength=128 required placeholder="ID из таблицы справа"></label>
        <label>Выдать очков<input type=number name=amount min=1 max=100000 value=100 required></label>
        <button>Выдать Q-coins</button>
      </form>
      <section class=card>
        <h2>Игроки и баланс</h2>
        <p class=muted>Баланс обновляется после входа в игру. Секреты, логины и реальные платёжные данные здесь не хранятся.</p>
        <table><thead><tr><th>Устройство</th><th>Игрок</th><th>Баланс</th><th>Активность</th></tr></thead><tbody>{card_wallet_html}</tbody></table>
      </section>
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
      <h2>Пользователи и подписки</h2>
      <form method=get action=/operator class=actions>
        <input type=hidden name=tab value=users>
        <input name=q value="{html.escape(q)}" placeholder="имя / id / note">
        <button>Фильтр</button>
        <a class="button secondary" href="{html.escape(rp_base)}" target=_blank rel=noopener>Открыть RosPanel</a>
      </form>
      <p class=muted>Активны {summary.get('active')} · отключены {summary.get('disabled')} · истекли {summary.get('expired')} · онлайн 15м {summary.get('online_15m')}</p>
      <table><thead><tr><th>Имя</th><th>Статус</th><th>Состояние</th><th>Трафик</th><th>Действует до</th><th>Активность</th><th></th></tr></thead>
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

    <section class=grid {show('support')}>
      <form class=card method=post action=/operator/support>
        <input type=hidden name=action value=create>
        <h2>Новое обращение</h2>
        <p class=muted>Внутренний центр поддержки. Диагностика и секреты пользователей сюда не копируются автоматически.</p>
        <label>Тема<input name=subject maxlength=160 required placeholder="Например: пользователь не видит серверы"></label>
        <label>Устройство / источник<input name=device maxlength=128 placeholder="ID устройства или имя пользователя"></label>
        <label>Описание<textarea name=body maxlength=1600 placeholder="Что уже проверили, время, наблюдение"></textarea></label>
        <button>Создать обращение</button>
      </form>
      <section class=card>
        <div class=section-head><h2>Очередь поддержки</h2><span class="badge {'warn' if support_open else 'ok'}">{support_open} открыто</span></div>
        <table><thead><tr><th>#</th><th>Статус</th><th>Тема</th><th>Источник</th><th>Изменено</th><th></th></tr></thead><tbody>{support_html}</tbody></table>
        {community_support_html}
      </section>
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

    <section {show('security')}>{passkey_html}</section>
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
        <p class=muted>Бот работает на VDS без включённого ПК. В настроенном личном чате: <code>/status</code>, <code>/ai_status</code>, <code>/check_updates</code>, <code>/get_stable</code>, <code>/backups</code>, <code>/help</code>. Показывает реальные замеры; команды не меняют VPN и настройки.</p>
        <label><input type=checkbox name=telegram_alerts_enabled {checked('telegram_alerts_enabled')}> Включить</label>
        <label><input type=checkbox name=telegram_backups_enabled {checked('telegram_backups_enabled')}> Резервная копия каждый час</label>
        <label>Bot token<input type=password name=telegram_bot_token value="{html.escape(telegram_token)}" autocomplete=off {'disabled' if telegram_env_managed else ''} placeholder="{html.escape(telegram_token_hint)}"></label>
        <p class=muted>{html.escape(telegram_token_hint)}</p>
        <label>Chat ID<input name=telegram_chat_id value="{html.escape(s.get('telegram_chat_id',''))}"></label>
        <div class=actions><button>Сохранить</button>
        <button class=secondary formaction=/operator/actions name=action value=telegram_test>Тест сообщения</button>
        <button class=secondary formaction=/operator/actions name=action value=backup_now>Создать зашифрованный backup</button>
        <a class="button secondary" href="/operator/backup.zip">Скачать зашифрованный backup</a></div>
        <p class=muted>Архив содержит SQLite-конфигурацию, настройки панели и ключ сессии. Передача выполняется только в указанный Telegram-чат.</p>
      </form>
    </section>

    <section {show('admins')}>{passkey_html}</section>
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
      <div class=actions style="justify-content:space-between;align-items:center"><div><h2 style="margin-bottom:4px">Живые логи</h2><p class=muted style="margin:0">Поток событий панели в реальном времени. История не обновляет страницу и хранится по текущим правилам очистки.</p></div></div>
      <p class=muted>Журнал доступен в нижней панели на любой вкладке. Можно приостановить отображение или скачать события.</p><a class="button secondary" href="#aurora-terminal">Открыть журнал ↓</a>
    </section>

    <section class=card {show('audit')}>
      <h2>Аудит изменений</h2>
      <table><thead><tr><th>Время</th><th>Кто</th><th>IP</th><th>Действие</th><th>Diff</th></tr></thead><tbody>{audit_html}</tbody></table>
    </section>

      <details id=aurora-terminal class=aurora-live-dock {'open' if section == 'logs' else ''}>
        <summary class=aurora-live-toolbar><strong>Живой журнал</strong><span id=aurora-live-summary class=aurora-live-summary>Подключение к событиям панели…</span><span id=live-state class=pill>Подключение…</span></summary>
        <div class=aurora-live-toolbar><button type=button id=aurora-live-pause class=secondary>Пауза</button><a class="button secondary" href="/operator/logs.txt">Скачать журнал</a><button type=button id=aurora-refresh class=secondary>Обновить данные</button></div>
        <pre id=live-log class=aurora-live-output aria-label="Журнал событий">Ожидание событий…</pre>
      </details>
      </section>
    </div>

    <script>
    const tab = new URLSearchParams(location.search).get('tab') || 'dashboard';
    if (document.getElementById('live-log')) {{
      const output = document.getElementById('live-log');
      const state = document.getElementById('live-state');
      const summary = document.getElementById('aurora-live-summary');
      const pause = document.getElementById('aurora-live-pause');
      const lines = [];
      let paused = false, skipped = 0;
      const source = new EventSource('/operator/live?since=' + (Math.floor(Date.now()/1000) - 60));
      source.onopen = () => {{ state.textContent = paused ? 'Пауза' : 'LIVE'; state.className = 'pill ok'; }};
      source.onerror = () => {{ state.textContent = 'Переподключение…'; state.className = 'pill off'; }};
      source.onmessage = (event) => {{
        try {{
          const item = JSON.parse(event.data);
          const stamp = new Date(item.ts * 1000).toLocaleString('ru-RU');
          lines.unshift(`[${{stamp}}] ${{item.kind}} · ${{item.device || 'system'}} · ${{item.ip || '—'}}\\n${{item.detail || ''}}`);
          lines.length = Math.min(lines.length, 60);
          if (paused) {{ skipped += 1; state.textContent = 'Пауза · +' + skipped; return; }}
          output.textContent = lines.join('\\n\\n').slice(0, 24000);
          summary.textContent = item.kind + ' · ' + (item.detail || 'Событие получено').slice(0, 160);
        }} catch (_) {{}}
      }};
      pause.addEventListener('click', () => {{
        paused = !paused;
        pause.textContent = paused ? 'Продолжить' : 'Пауза';
        state.textContent = paused ? 'Пауза' : 'LIVE';
        if (!paused) {{ skipped = 0; output.textContent = lines.join('\\n\\n').slice(0, 24000) || 'Событий пока нет'; }}
      }});
      window.addEventListener('pagehide', () => source.close(), {{once:true}});
    }}
    document.getElementById('aurora-refresh').addEventListener('click', () => location.reload());
    if (tab === 'dashboard') {{
      let refreshing = false;
      const refreshDashboard = async () => {{
        if (document.hidden || refreshing) return;
        refreshing = true;
        try {{
          const response = await fetch('/operator?tab=dashboard', {{credentials:'same-origin',cache:'no-store'}});
          if (!response.ok) return;
          const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
          if (!doc.querySelector('[data-ui="Aurora2"]')) return;
          const fresh = doc.querySelector('.dashboard'), current = document.querySelector('.dashboard');
          if (fresh && current) {{
            current.replaceChildren(...fresh.childNodes);
            current.dispatchEvent(new Event('aurora:refresh', {{bubbles:true}}));
          }}
        }} catch (_) {{}} finally {{ refreshing = false; }}
      }};
      const timer = setInterval(refreshDashboard, 60000);
      window.addEventListener('pagehide', () => clearInterval(timer), {{once:true}});
    }}
    </script>
    {aurora_script()}{control_next.passkey_script()}</main></body></html>"""


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

    def record_delivery_evidence(self, db, stage, version_code=0):
        # A User-Agent or shared IP cannot identify a device. Old clients
        # without this header remain unknown rather than fake confirmations.
        raw = self.headers.get("X-Device-Id") or self.headers.get("X-HWID") or ""
        if not raw or len(raw) > 512 or stage not in {"policy_at", "update_at"}:
            return
        try:
            version_code = max(0, min(2_147_483_647, int(version_code or 0)))
        except (TypeError, ValueError):
            version_code = 0
        db.execute(
            f"insert into delivery_evidence(device,version_code,{stage}) values (?,?,?) "
            f"on conflict(device) do update set {stage}=excluded.{stage}, "
            "version_code=case when excluded.version_code>0 then excluded.version_code else delivery_evidence.version_code end",
            (device_id(raw), version_code, int(time.time())),
        )
        db.commit()

    def control_binding(self, adm=None):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        if morsel and self.cookie_session():
            return hashlib.sha256(morsel.value.encode()).hexdigest()
        if adm and adm.get("basic"):
            # Compatibility for authenticated owner/operator CLI usage; the
            # confirmation still requires exact origin and its rendered CSRF.
            return hashlib.sha256((self.headers.get("Authorization", "") + ":" + adm["user"]).encode()).hexdigest()
        raise PermissionError("Нужна действующая сессия панели")

    def control_csrf(self, adm):
        return control_next.csrf_token(session_secret(), self.control_binding(adm))

    def control_preview_page(self, preview, adm):
        body = control_next.render_preview(preview, self.control_csrf(adm))
        return self.reply(200, "<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Проверка изменений</title><style>" + css() + control_reference_css() + aurora_css() + "</style><body class=aurora-panel><main style='max-width:1000px;margin:24px auto;padding:16px'>" + body + "</main></body></html>", "text/html; charset=utf-8")

    def control_apply_values(self, db, values, scope, actor, ip):
        live = settings(db)
        values = dict(values)
        if scope == "routing":
            candidate = dict(live)
            candidate.update(values)
            # Revalidate through the actual APK policy generator, not a raw
            # native config. Keep revisions monotonically increasing on rollback.
            validated = routing_settings_from_payload(routing_payload(candidate))
            revision = max(1, int(live.get("routing_revision", "1") or 1))
            if not db.execute("select 1 from routing_revisions where revision=? and state='production'", (revision,)).fetchone():
                record_routing_revision(db, revision, "system", "production", routing_payload(live), "До подтверждённого изменения")
            next_revision = revision + 1
            values.update(validated)
            values.update({"routing_revision": str(next_revision), "routing_staging_enabled": "0", "routing_staging_revision": "0",
                           "routing_staging_payload": "{}", "routing_draft_payload": "{}", "routing_draft_updated_at": "0"})
            record_routing_revision(db, next_revision, actor, "production", routing_payload(candidate, next_revision), "Подтверждено после просмотра")
        values["config_revision"] = str(int(live.get("config_revision", "1") or 1) + 1)
        set_settings(db, values)
        audit(db, actor, ip, "control:apply:" + scope, {"fields": sorted(key for key in values if key in control_next.SCOPES[scope])})

    def control_post(self, db, s, path, adm):
        actor, ip = adm["user"], adm["ip"]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 256 * 1024:
                self.close_connection = True
                return self.reply(413, "Запрос слишком большой", "text/plain; charset=utf-8")
            form = parse_qs(self.rfile.read(length).decode("utf-8"))
            expected_origin, _ = control_next.public_origin(PUBLIC_BASE)
            if (self.headers.get("Origin", "") != expected_origin
                    or self.headers.get("Sec-Fetch-Site", "same-origin") not in {"same-origin", "none"}
                    or not hmac.compare_digest(self.control_csrf(adm), form.get("csrf", [""])[0])):
                return self.reply(403, "Неверное подтверждение запроса. Обновите страницу панели", "text/plain; charset=utf-8")
            current = settings(db)
            role = adm.get("role", "viewer")
            if path == "/operator/control/preview":
                scope = form.get("scope", [""])[0]
                if scope not in control_next.SCOPES:
                    raise ValueError("Неизвестный раздел")
                candidate = {key: form[key][0] for key in control_next.SCOPES[scope] if key in form}
                if scope == "release":
                    for key in control_next.BOOL_KEYS & control_next.SCOPES[scope]:
                        candidate[key] = "1" if key in form else "0"
                preview = control_next.preview_settings(db, current, candidate, actor, scope, role)
            elif path == "/operator/control/rollback":
                preview = control_next.rollback_preview(db, int(form.get("snapshot_id", ["0"])[0]), current, actor, role)
            elif path == "/operator/control/apply":
                result = control_next.apply_preview(db, form.get("preview_id", [""])[0], form.get("digest", [""])[0], current, actor, role,
                    lambda tx, values, scope: self.control_apply_values(tx, values, scope, actor, ip))
                db.commit()
                return self.redirect_operator({"routing": "routing", "nodes": "latency", "release": "release"}[result["scope"]], "Изменения подтверждены. Предыдущая конфигурация сохранена")
            else:
                return self.reply(404, "Not found", "text/plain")
            db.commit()
            return self.control_preview_page(preview, adm)
        except PermissionError:
            db.rollback()
            return self.reply(403, "Недостаточно прав или сессия истекла", "text/plain; charset=utf-8")
        except (ValueError, TypeError, UnicodeError) as error:
            db.rollback()
            return self.redirect_operator("quality", "Не применено: " + str(error)[:180])

    def passkey_post(self, db, s, path):
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        if not ip_allowed(ip, s) or rate_limited("passkey:" + ip, 10):
            return self.reply(429, '{"message":"Вход временно недоступен"}')
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 66_000:
                self.close_connection = True
                return self.reply(413, '{"message":"Некорректный размер запроса"}')
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict) or not control_next.secure_json_request(self.headers, PUBLIC_BASE):
                return self.reply(403, '{"message":"Неверный origin или формат запроса"}')
            manager = control_next.WebAuthnManager(PUBLIC_BASE)
            if not control_next.passkey_available():
                return self.reply(503, '{"message":"Passkey временно недоступен. Используйте пароль и 2FA"}')
            cookie_headers = {}
            if path.startswith("/operator/passkey/authenticate/"):
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                preauth = cookie.get("qv_passkey_preauth")
                data = verify_session(preauth.value) if preauth else None
                if path.endswith("/begin"):
                    binding = secrets.token_urlsafe(32)
                    token = sign_session({"scope": "passkey-preauth", "n": binding, "exp": int(time.time()) + control_next.PASSKEY_TTL})
                    cookie_headers["Set-Cookie"] = f"qv_passkey_preauth={token}; Path=/operator/passkey; Max-Age={control_next.PASSKEY_TTL}; HttpOnly; Secure; SameSite=Strict"
                    result = manager.begin_authentication(db, str(payload.get("username") or "")[:64], binding)
                elif path.endswith("/finish"):
                    if not data or data.get("scope") != "passkey-preauth":
                        raise PermissionError("Время входа истекло. Повторите попытку")
                    identity = manager.finish_authentication(db, data.get("n", ""), payload.get("ceremony_id", ""), payload.get("credential"))
                    token = sign_session({"u": identity["username"], "role": identity["role"], "exp": int(time.time()) + SESSION_TTL, "n": secrets.token_hex(16)})
                    cookie_headers["Set-Cookie"] = f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict"
                    result = {"authenticated": True}
                    audit(db, identity["username"], ip, "passkey:login", {"role": identity["role"]})
                else:
                    return self.reply(404, '{"message":"Not found"}')
            else:
                adm = self.admin(require_login_page=False)
                if not adm:
                    return
                if not self.cookie_session() or not control_next.secure_json_request(self.headers, PUBLIC_BASE, self.control_csrf(adm)):
                    return self.reply(403, '{"message":"Для ключей нужна браузерная сессия и подтверждение запроса"}')
                username, binding = adm["user"], self.control_binding(adm)
                if path.endswith("/begin") or path == "/operator/passkey/revoke":
                    identity = authenticate_admin(db, username, str(payload.get("password") or ""))
                    if (not identity or (enabled(s, "totp_enabled", False) and not totp_ok(s.get("totp_secret", ""), str(payload.get("totp") or "")))):
                        raise PermissionError("Подтвердите текущий пароль и корректный код 2FA")
                if path == "/operator/passkey/register/begin":
                    result = manager.begin_registration(db, username, binding, reauthenticated=True)
                elif path == "/operator/passkey/register/finish":
                    result = manager.finish_registration(db, username, binding, payload.get("ceremony_id", ""), payload.get("credential"), payload.get("label", "Мой passkey"))
                    audit(db, username, ip, "passkey:register", {"ok": True})
                elif path == "/operator/passkey/revoke":
                    result = control_next.revoke_passkey(db, username, payload.get("credential_id", ""), reauthenticated=True)
                    audit(db, username, ip, "passkey:revoke", {"ok": True})
                else:
                    return self.reply(404, '{"message":"Not found"}')
            db.commit()
            return self.reply(200, json.dumps(result, ensure_ascii=False), headers=cookie_headers)
        except (ValueError, PermissionError, TypeError, UnicodeError):
            # Challenges remain one-use after a failed assertion. Never include
            # raw credential JSON, clientData or the underlying crypto error.
            db.commit()
            return self.reply(400, '{"message":"Passkey не подтверждён или время истекло. Повторите попытку; пароль и 2FA доступны"}')

    def same_origin_request(self):
        """Accept the panel's real public origin behind an HTTPS reverse proxy.

        Browsers may omit the explicit port in Origin while nginx keeps :8443
        in Host. Comparing the raw strings rejected legitimate form submits.
        Hostname and scheme are checked, while foreign hosts remain blocked.
        """
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True
        # The embedded Codex/Android browser submits a top-level form with a
        # serialized Origin of ``null``.  It is still same-site: the request
        # Host is this panel and the browser's fetch metadata (when present)
        # confirms same-origin/same-site.  Reject explicit cross-site metadata.
        if origin.lower() == "null":
            fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            return not fetch_site or fetch_site in {"same-origin", "same-site", "none"}
        try:
            parsed = urlsplit(origin.rstrip("/"))
            expected = urlsplit(PUBLIC_BASE.rstrip("/"))
            request_host = (self.headers.get("Host") or expected.netloc).split(",", 1)[0].strip()
            request_host_name = request_host.split(":", 1)[0].strip("[]").lower()
            expected_name = (expected.hostname or "").lower()
            # Trust the configured public scheme instead of X-Forwarded-Proto:
            # nginx may pass the upstream HTTP scheme even for the public TLS
            # endpoint, which caused valid browser form posts to be rejected.
            scheme = (expected.scheme or "https").lower()
            if parsed.scheme.lower() != scheme:
                return False
            if not parsed.hostname or parsed.hostname.lower() not in {request_host_name, expected_name}:
                return False
            # The public hostname is owned by this panel. Accept an omitted
            # port, :8443, or the reverse-proxy's external port.
            parsed_port = parsed.port
            expected_port = expected.port
            host_port = None
            if ":" in request_host.rsplit("]", 1)[-1]:
                try:
                    host_port = int(request_host.rsplit(":", 1)[-1])
                except ValueError:
                    host_port = None
            return parsed_port in (None, expected_port, host_port, 443, 8443)
        except (ValueError, TypeError):
            return False

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

    def read_community_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise community.CommunityError("invalid_request_length")
        if not 0 < length <= community.MAX_REQUEST_BYTES:
            self.close_connection = True
            raise community.CommunityError("request_too_large", 413)
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise community.CommunityError("json_required", 415)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeError):
            raise community.CommunityError("invalid_json")
        if not isinstance(payload, dict):
            raise community.CommunityError("json_object_required")
        return payload

    def community_client(self, db):
        # X-Device-Id is intentionally insufficient: only an admitted HWID and
        # a privately issued credential can read or mutate client records.
        return community.authenticate_client(
            db, self.headers.get("X-HWID", ""),
            self.headers.get(community.TOKEN_HEADER, ""),
        )

    def community_get(self, db, path, query):
        try:
            identity = self.community_client(db)
            tail = path.removeprefix("/api/client/community")
            if tail == "/support":
                payload = community.list_threads(db, identity)
            elif re.fullmatch(r"/support/[1-9][0-9]{0,18}", tail):
                payload = community.get_thread(db, identity, int(tail.rsplit("/", 1)[1]))
            elif tail == "/inbox":
                after = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", ["30"])[0])
                if not 0 <= after < 2**63 or not 1 <= limit <= 50:
                    raise community.CommunityError("invalid_cursor")
                payload = community.inbox(db, identity, after, limit)
            else:
                return self.reply(404, '{"error":"not_found"}')
            return self.reply(200, json.dumps(payload, ensure_ascii=False))
        except community.CommunityError as exc:
            return self.reply(exc.status, json.dumps({"error": exc.code}))
        except ValueError:
            return self.reply(400, '{"error":"invalid_request"}')

    def community_post(self, db, path):
        try:
            identity = self.community_client(db)
            payload = self.read_community_json()
            tail = path.removeprefix("/api/client/community")
            db.execute("begin immediate")
            if tail == "/support":
                result = community.create_thread(db, identity, payload)
            elif re.fullmatch(r"/support/[1-9][0-9]{0,18}/messages", tail):
                result = community.add_message(db, identity, int(tail.split("/")[2]), payload)
            elif tail == "/inbox/read":
                result = community.mark_read(db, identity, payload.get("event_id"))
            elif tail == "/quality":
                result = community.record_quality(db, identity, payload)
            elif tail == "/delivery":
                result = community.record_delivery(db, identity, payload)
            else:
                db.rollback()
                return self.reply(404, '{"error":"not_found"}')
            db.commit()
            return self.reply(200, json.dumps(result, ensure_ascii=False))
        except community.CommunityError as exc:
            db.rollback()
            return self.reply(exc.status, json.dumps({"error": exc.code}))
        except ValueError:
            db.rollback()
            return self.reply(400, '{"error":"invalid_request"}')

    def card_game_payload(self, db, device: str, table_id: str):
        """Return only the caller's own state; the opponent hand never leaves the server."""
        row = db.execute(
            "select id,created_at,updated_at,state,host_device,host_name,guest_device,guest_name,last_action,game_json "
            "from card_tables where id=?",
            (table_id,),
        ).fetchone()
        if not row:
            return None
        if device == row[4]:
            seat, name, opponent = "host", row[5], row[7]
        elif device == row[6]:
            seat, name, opponent = "guest", row[7], row[5]
        else:
            return None
        state = row[3]
        wallet = db.execute(
            "select q_coins from card_wallets where device=?",
            (device,),
        ).fetchone()
        try:
            if len(row[9] or "") > 65_536:
                raise ValueError("Oversized stored card state")
            game = json.loads(row[9] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            game = {}
        if not isinstance(game, dict):
            game = {}
        # Only an actual waiting lobby may have no deal. A corrupt ready/playing
        # row must not look like a new lobby; preserve its stored pot for review.
        view = durak.public_view(game if game or state == "waiting" else {"phase": "unavailable"}, seat)
        try:
            stake = max(0, min(100_000, int(game.get("stake_q_coins") or 0)))
        except (TypeError, ValueError):
            stake = 0
        settled = view["game_phase"] == "finished" and game.get("stake_settled") is True
        winner_reward = stake * 2 if settled and view["winner"] in durak.SEATS else 0
        return {
            "table_id": row[0],
            "state": state,
            "seat": seat,
            "name": name,
            "opponent_name": opponent,
            "created_at": int(row[1]),
            "updated_at": int(row[2]),
            "waiting": state == "waiting",
            "ready": state in ("ready", "playing", "finished"),
            "q_coins": max(0, int(wallet[0] or 0)) if wallet else 0,
            "stake_q_coins": stake,
            "winner_reward_q_coins": winner_reward,
            "stake_refund_q_coins": stake if settled and view["winner"] == "draw" else 0,
            **view,
        }

    def join_card_game(self, db, s, device: str, ip: str, access_code: str, display_name: str):
        """Join or create a two-player card-game lobby through a hashed code."""
        if not enabled(s, "card_game_enabled", True):
            raise PermissionError("Карточный стол временно отключён оператором")
        access_hash = s.get("card_game_access_hash") or ""
        if not access_hash:
            raise PermissionError("Оператор ещё не создал код доступа к столу")
        if not password_ok(access_code, access_hash):
            raise PermissionError("Неверный код доступа")
        name = card_game_name(display_name)
        now = int(time.time())
        starting_coins = max(0, min(100_000, int(s.get("card_game_start_coins") or 1200)))
        db.execute(
            "insert into card_wallets(device,display_name,q_coins,created_at,updated_at) values (?,?,?,?,?) "
            "on conflict(device) do update set display_name=excluded.display_name, updated_at=excluded.updated_at",
            (device, name, starting_coins, now, now),
        )
        wait_seconds = max(5, min(120, int(s.get("card_game_wait_minutes") or 20))) * 60
        # Waiting rooms are short lived. This avoids an abandoned device
        # blocking the next player forever while retaining an audit event.
        db.execute(
            "update card_tables set state='expired',updated_at=?,last_action='Время ожидания истекло' "
            "where state='waiting' and updated_at<?",
            (now, now - wait_seconds),
        )
        row = db.execute(
            "select id from card_tables where state in ('waiting','ready','playing') and (host_device=? or guest_device=?) "
            "order by updated_at desc limit 1",
            (device, device),
        ).fetchone()
        if row:
            table_id = row[0]
            db.execute(
                "update card_tables set updated_at=?,host_name=case when host_device=? then ? else host_name end,"
                "guest_name=case when guest_device=? then ? else guest_name end where id=?",
                (now, device, name, device, name, table_id),
            )
        else:
            waiting = db.execute(
                "select id from card_tables where state='waiting' and host_device!=? order by created_at asc limit 1",
                (device,),
            ).fetchone()
            if waiting:
                table_id = waiting[0]
                game = durak_new_game()
                db.execute(
                    "update card_tables set state='ready',updated_at=?,guest_device=?,guest_name=?,"
                    "last_action='Второй игрок подключился',game_json=? where id=?",
                    (now, device, name, json.dumps(game, separators=(",", ":")), table_id),
                )
                detail = json.dumps({"table": table_id, "state": "ready"}, ensure_ascii=False)
            else:
                table_id = secrets.token_hex(6)
                db.execute(
                    "insert into card_tables(id,created_at,updated_at,state,host_device,host_name,guest_device,guest_name,last_action,game_json) "
                    "values (?,?,?,?,?,?,?,?,?,?)",
                    (table_id, now, now, "waiting", device, name, "", "", "Стол создан", ""),
                )
                detail = json.dumps({"table": table_id, "state": "waiting"}, ensure_ascii=False)
            db.execute("insert into events values (?,?,?,?,?)", (now, "card_table", device, ip, detail))
        db.commit()
        payload = self.card_game_payload(db, device, table_id)
        if not payload:
            raise RuntimeError("Не удалось создать игровой стол")
        payload["ticket"] = card_game_ticket(device, table_id)
        return payload

    def card_game_action(self, db, s: dict, device: str, table_id: str, action: str, card: str = "",
                         target: int | None = None, expected_revision: int | None = None,
                         action_id: str = ""):
        """Persist cards and a virtual pot atomically; retries cannot replay either."""
        if not enabled(s, "card_game_enabled", True):
            raise PermissionError("Карточный стол временно отключён оператором")
        now = int(time.time())
        db.execute("begin immediate")
        try:
            row = db.execute(
                "select state,host_device,guest_device,game_json from card_tables where id=?",
                (table_id,),
            ).fetchone()
            if not row or device not in (row[1], row[2]):
                raise PermissionError("Стол недоступен")
            seat = "host" if device == row[1] else "guest"
            try:
                if len(row[3] or "") > 65_536:
                    raise ValueError("Oversized stored card state")
                game = json.loads(row[3] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                game = {}
            result = durak.apply_action(game, seat, action, card, target, expected_revision, action_id)
            game, last_action = result.game, result.message
            if result.started and "stake_q_coins" not in game:
                stake = max(0, min(100_000, int(s.get("card_game_stake_q_coins") or 25)))
                balances = {
                    item[0]: max(0, int(item[1] or 0))
                    for item in db.execute("select device,q_coins from card_wallets where device in (?,?)",
                                           (row[1], row[2]))
                }
                if balances.get(row[1], 0) < stake or balances.get(row[2], 0) < stake:
                    raise ValueError("Для начала партии каждому игроку нужно достаточно виртуальных Q-coins")
                if stake:
                    charged = db.execute(
                        "update card_wallets set q_coins=q_coins-?,updated_at=? "
                        "where device in (?,?) and q_coins>=?",
                        (stake, now, row[1], row[2], stake),
                    )
                    if charged.rowcount != 2:
                        raise ValueError("Виртуальный банк изменился. Повторите готовность")
                game["stake_q_coins"], game["stake_settled"] = stake, False
                last_action = f"Раздача началась · банк {stake * 2} Q-coins"
            # Settlement only follows a newly completed bout, never a retry,
            # read, stale click or legacy finished state with an old outcome.
            if result.bout_completed and result.finished and not game.get("stake_settled"):
                stake = max(0, min(100_000, int(game.get("stake_q_coins") or 0)))
                if game["winner"] == "draw":
                    if stake:
                        db.execute("update card_wallets set q_coins=q_coins+?,updated_at=? where device in (?,?)",
                                   (stake, now, row[1], row[2]))
                    last_action = "Ничья: виртуальные ставки возвращены обоим игрокам"
                else:
                    winner_device = row[1] if game["winner"] == "host" else row[2]
                    if stake:
                        db.execute("update card_wallets set q_coins=q_coins+?,updated_at=? where device=?",
                                   (stake * 2, now, winner_device))
                    last_action = f"Партия завершена: банк {stake * 2} Q-coins переведён победителю"
                game["stake_settled"] = True
            if result.changed:
                db.execute(
                    "update card_tables set state=?,updated_at=?,last_action=?,game_json=? where id=?",
                    (result.state, now, last_action, json.dumps(game, separators=(",", ":")), table_id),
                )
            db.commit()
        except Exception:
            db.rollback()
            raise
        payload = self.card_game_payload(db, device, table_id)
        if not payload:
            raise RuntimeError("Не удалось обновить игровой стол")
        payload["ticket"] = card_game_ticket(device, table_id)
        return payload

    def reply(self, code, body, content_type="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if PUBLIC_BASE.lower().startswith("https://"):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if content_type.startswith("text/html") and not (headers and "Content-Security-Policy" in headers):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            )
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

    def public_status_html(self, s: dict) -> str:
        """Render the intentionally data-minimal public user status page."""
        maintenance = effective_maintenance(s)
        version, _version_code, _rollout, _note = self.current_release(s, "production")
        artifact = os.path.join(DOWNLOAD_ROOT, version, f"QuantumVPN-{version}-operator-debug-arm64-v8a.apk")
        downloads_open = not maintenance and enabled(s, "public_download_enabled", True) and os.path.isfile(artifact)
        services = cached_service_status()
        required = ("operator", "rospanel", "xray")
        services_ok = all(services.get(name) in ("active", "running") for name in required)
        state = "Maintenance" if maintenance else "Operational" if services_ok else "Degraded"
        state_class = "danger" if maintenance or not services_ok else "good"
        headline = "Scheduled maintenance is in progress." if maintenance else "The VPN service is operating normally." if services_ok else "We are investigating a service disruption."
        note = " ".join((s.get("public_status_note_en") or "").split())[:160]
        download = (
            f'<a class="download" href="/downloads/{quote(version)}/QuantumVPN-{quote(version)}-operator-debug-arm64-v8a.apk">Download for Android</a>'
            if downloads_open else
            '<span class="download closed">Android download temporarily unavailable</span>'
        )
        return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>QuantumVPN Status</title><style>
        :root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 20% 0,#153c5f,#06111f 50%,#03070e);font:16px system-ui,-apple-system,Segoe UI,sans-serif;color:#eaf6ff}}main{{width:min(620px,calc(100% - 32px));padding:42px;border:1px solid #244866;border-radius:28px;background:#09182acc;box-shadow:0 28px 90px #0008}}.brand{{font-size:28px;font-weight:800;letter-spacing:-.7px}}.brand i{{color:#3de7ff;font-style:normal}}.badge{{display:inline-flex;gap:9px;align-items:center;margin:32px 0 16px;padding:10px 15px;border-radius:999px;font-weight:700}}.badge:before{{content:'';width:9px;height:9px;border-radius:50%;background:currentColor;box-shadow:0 0 14px currentColor}}.good{{background:#0b4037;color:#62f4c4}}.danger{{background:#4b1c2a;color:#ff7790}}h1{{margin:0;font-size:32px}}p{{color:#a9bfd1;line-height:1.55}}.row{{display:flex;justify-content:space-between;gap:18px;margin:30px 0 18px;padding:17px 0;border-top:1px solid #244866;border-bottom:1px solid #244866;color:#a9bfd1}}.row b{{color:#fff}}.download{{display:block;text-align:center;text-decoration:none;margin-top:24px;padding:15px 18px;border-radius:14px;background:linear-gradient(100deg,#32d5e8,#5ce6bb);color:#04111e;font-weight:800}}.closed{{background:#45202b;color:#ffb1c0}}small{{display:block;margin-top:26px;color:#748fa7;text-align:center}}</style></head><body><main><div class=brand>Quantum<i>VPN</i></div><div class="badge {state_class}">{state}</div><h1>{html.escape(headline)}</h1><p>{html.escape(note or 'Service and Android release availability are shown here in real time.')}</p><div class=row><span>Android release</span><b>{html.escape(version)}</b></div>{download}<small>This page contains no account, subscription, or administrator data.</small></main></body></html>"""

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
        names = []
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
        except Exception:
            # The upstream subscription is HWID-bound, so an operator-side
            # generic fetch normally has no device identity and is correctly
            # rejected by RosPanel.  Preserve known rows and still surface the
            # locally verified reserve lane below.
            pass
        if reserve_profile_uri():
            db.execute("insert or replace into protocols values (?,1)", ("trojan",))
            names.append("trojan")
        db.commit()
        return sorted(set(names))

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        db = self.connection_db()
        s = settings(db)

        if path == "/status":
            # A public, registration-free page. It intentionally bypasses the
            # operator session path and includes no control-plane information.
            return self.reply(
                200,
                self.public_status_html(s),
                "text/html; charset=utf-8",
                {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"},
            )

        if path.startswith("/api/"):
            limit = int(s.get("rate_limit_per_min") or 120)
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(ip, limit):
                return self.reply(429, '{"error":"rate_limited"}')

        if path.startswith("/api/client/community/"):
            return self.community_get(db, path, query)

        if path.startswith("/api/client/update") or path.startswith("/api/app/version"):
            self.record_delivery_evidence(db, "update_at", query.get("current_version_code", ["0"])[0])
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
            rollout_paused = channel != "staging" and enabled(s, "update_rollout_paused", False)
            if rollout_paused:
                eligible = False
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
                info["note"] = "Дальнейшая раздача обновления временно приостановлена для проверки качества." if rollout_paused else f"Постепенный выпуск {rollout}%: устройство пока остаётся на текущей версии."
            info["rollout_percent"] = rollout
            info["rollout_eligible"] = eligible
            info["rollout_paused"] = rollout_paused
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
            status["monitor"] = {
                "enabled": enabled(s, "health_monitor_enabled", True),
                "interval_seconds": int(s.get("health_monitor_interval_seconds", "60") or 60),
                "samples": health_snapshot(db),
            }
            status["load_balancer"] = load_balancer_snapshot(db, s)
            status["release_guard"] = release_guard_snapshot(s)
            status["backup"] = latest_backup_info()
            status["routing"] = {
                "revision": int(s.get("routing_revision", "1") or 1),
                "profile": s.get("routing_profile", "balanced"),
                "staging": enabled(s, "routing_staging_enabled", False),
                "staging_rollout_percent": int(s.get("routing_staging_rollout_percent", "0") or 0),
            }
            return self.reply(200, json.dumps(status))

        if path.startswith("/api/client/donations"):
            return self.reply(200, json.dumps(self.donations_payload(db)))

        if path == "/api/client/cards/state":
            ticket = (query.get("ticket", [""])[0] or "")[:2048]
            ticket_data = card_game_ticket_data(ticket)
            if not ticket_data:
                return self.reply(401, '{"error":"invalid_game_ticket"}')
            device, _ip = self.client()
            if not hmac.compare_digest(str(ticket_data.get("device") or ""), device):
                return self.reply(403, '{"error":"game_ticket_device_mismatch"}')
            table_id = str(ticket_data.get("table") or "")
            db.execute(
                "update card_tables set updated_at=? where id=? and state='waiting' and (host_device=? or guest_device=?)",
                (int(time.time()), table_id, device, device),
            )
            db.commit()
            payload = self.card_game_payload(db, device, table_id)
            if not payload:
                return self.reply(404, '{"error":"game_table_not_found"}')
            # State polling must preserve the signed device-bound ticket.  If
            # it is omitted, Compose replaces the snapshot with a blank ticket
            # and cancels the lobby poll as soon as the second player joins.
            payload["ticket"] = ticket
            return self.reply(200, json.dumps(payload, ensure_ascii=False))

        if path.startswith("/api/client/policy"):
            dev, ip = self.client()
            now = int(time.time())
            self.record_delivery_evidence(db, "policy_at", query.get("version_code", [self.headers.get("X-App-Version-Code", "0")])[0])
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
            quarantined_nodes = sorted(active_quarantine(s))
            drained_nodes = sorted(manual_node_drains(s))
            manual_forbidden = [x.strip() for x in (s.get("nodes_forbidden") or "").split(",") if x.strip()]
            forbidden_nodes = list(dict.fromkeys(manual_forbidden + quarantined_nodes + drained_nodes))
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
                "nodes_forbidden": forbidden_nodes,
                "nodes_quarantined": quarantined_nodes,
                "nodes_draining": drained_nodes,
                "node_health_policy": {
                    "auto_quarantine": enabled(s, "auto_quarantine_enabled", True),
                    "failures_before_quarantine": max(2, min(10, int(s.get("auto_quarantine_failures", "3") or 3))),
                    "recovery_checks": max(1, min(10, int(s.get("auto_quarantine_recovery_checks", "2") or 2))),
                    "ttl_minutes": max(5, min(1440, int(s.get("auto_quarantine_ttl_minutes", "30") or 30))),
                },
                "latency_optimization": {
                    "enabled": enabled(s, "latency_optimization_enabled", True),
                    "probe_interval_seconds": max(15, min(300, int(s.get("latency_probe_interval", "30") or 30))),
                    "max_ms": max(20, min(5000, int(s.get("latency_max_ms", "120") or 120))),
                    "state": s.get("latency_state") or "unknown",
                    "best_ms": int(s.get("latency_best_ms", "0") or 0),
                },
                "load_balancer": load_balancer_snapshot(db, s),
                "min_version_code": min_vc,
                "force_update": force_update,
                "force_update_message": s.get("force_update_message") or "",
                "device_banner": (fl[0] if fl and fl[0] else ""),
                "request_diagnostic": bool(fl[1]) if fl else False,
                "changelog": note,
            }
            return self.reply(200, json.dumps(result, ensure_ascii=False))

        if path.startswith("/api/client/resources/assets/"):
            try:
                resources.schema(db)
                body, mime = resources.asset_bytes(db, ROOT, path.rsplit("/", 1)[-1])
                return self.reply(200, body, mime, {"Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff"})
            except (ValueError, OSError):
                return self.reply(404, '{"error":"asset_unavailable"}')

        if path == "/api/client/resources":
            try:
                dev, _ip = self.client()
                version = int(query.get("version_code", ["0"])[0])
                result = resources.client_manifest(db, dev, version, routing_signing_key)
                return self.reply(200 if result else 204, json.dumps(result, ensure_ascii=False) if result else b"", headers={"Cache-Control": "no-store"})
            except (ValueError, RuntimeError, OSError):
                return self.reply(503, '{"error":"resources_unavailable"}')

        if path == "/api/client/routing":
            # The app will pin the public key in its next routing-capable
            # release.  Until then this endpoint is harmless configuration
            # data: no currently released APK applies it automatically.
            dev, _ip = self.client()
            bucket = client_bucket(query.get("bucket", [None])[0])
            if bucket is None:
                bucket = int(hashlib.sha256(dev.encode("utf-8")).hexdigest()[:8], 16) % 100
            try:
                payload, channel = routing_policy_for_client(s, bucket)
                envelope = signed_routing_envelope(payload, channel)
                envelope["bucket"] = bucket
                envelope["rollout_percent"] = max(1, min(100, int(s.get("routing_staging_rollout_percent", "10") or 10)))
                return self.reply(200, json.dumps(envelope, ensure_ascii=False))
            except (RuntimeError, ValueError) as exc:
                # Avoid exposing storage paths, key material or raw user input
                # through a client endpoint.
                print(f"routing policy unavailable: {type(exc).__name__}", flush=True)
                return self.reply(503, '{"error":"routing_policy_unavailable"}')

        if path == "/api/v1/subscription":
            if s.get("subscription_main_enabled") != "1":
                return self.reply(503, "Subscription temporarily unavailable", "text/plain; charset=utf-8")
            try:
                body, appended = managed_subscription(self.headers, s)
                # Persist only protocol counts/format, never links or keys.
                report = subscription_evidence(body)
                report["source"] = "Ответ на запрос клиента"
                set_settings(db, {"quality_subscription": json.dumps(report, ensure_ascii=False)})
            except Exception:
                # Do not leak the upstream address, HWID result or network error
                # through a public endpoint.  The app can keep its last verified
                # list and retry on its normal subscription schedule.
                return self.reply(502, "Subscription temporarily unavailable", "text/plain; charset=utf-8")
            db.execute(
                "insert into events values (?,?,?,?,?)",
                (
                    int(time.time()),
                    "subscription_served",
                    "managed",
                    "",
                    "reserve_profile=appended" if appended else "reserve_profile=not_appended",
                ),
            )
            response_headers = {"Content-Disposition": 'attachment; filename="quantumvpn-subscription.txt"'}
            admitted_hwid = self.headers.get("X-HWID", "")
            if admitted_hwid and len(admitted_hwid) <= 256 and report.get("protocols") and admitted_subscription_text(body) is not None:
                response_headers[community.TOKEN_HEADER] = community.issue_device_credential(db, admitted_hwid)
            db.commit()
            return self.reply(
                200,
                body,
                "text/plain; charset=utf-8",
                response_headers,
            )

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
                    "application/octet-stream",
                    {"Content-Disposition": f'attachment; filename="{os.path.basename(archive)}"'},
                )
            except OSError:
                return self.reply(500, "Backup unavailable", "text/plain; charset=utf-8")

        if path == "/operator/live":
            adm = self.admin(require_login_page=False)
            if not adm:
                return
            # Event timestamps are second-granular. The rowid breaks ties, so a
            # reconnect cannot drop/replay events written in the same second.
            cursor = self.headers.get("Last-Event-ID", "").strip()
            if cursor:
                match = re.fullmatch(r"([0-9]{1,12}):([0-9]{1,19})", cursor)
                if not match:
                    return self.reply(400, "Invalid event cursor", "text/plain; charset=utf-8")
                last_ts, last_rowid = map(int, match.groups())
                if last_rowid > 9_223_372_036_854_775_807:
                    return self.reply(400, "Invalid event cursor", "text/plain; charset=utf-8")
            else:
                raw_since = query.get("since", ["0"])[0] or "0"
                if not re.fullmatch(r"[0-9]{1,12}", raw_since):
                    return self.reply(400, "Invalid event timestamp", "text/plain; charset=utf-8")
                last_ts, last_rowid = int(raw_since), 9_223_372_036_854_775_807
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
                        "select rowid,ts,kind,device,ip,detail from events where ts>? or (ts=? and rowid>?) order by ts asc,rowid asc limit 80",
                        (last_ts, last_ts, last_rowid),
                    ).fetchall()
                    for rowid, ts, kind, device, ip, detail in rows:
                        last_ts, last_rowid = int(ts), int(rowid)
                        payload = {"ts": int(ts), "kind": kind, "device": device, "ip": ip, "detail": detail[:1600]}
                        self.wfile.write((f"id: {last_ts}:{last_rowid}\n" + "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8"))
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
                        actor_user=adm["user"],
                        control_csrf=self.control_csrf(adm),
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
                        actor_user=adm["user"],
                        control_csrf=self.control_csrf(adm),
                    ),
                    "text/html; charset=utf-8",
                )
            rows = db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 100").fetchall()
            protocols = db.execute("select name,enabled from protocols order by name").fetchall()
            audit_rows = db.execute("select ts,actor,ip,action,detail from audit order by ts desc limit 100").fetchall()
            card_rows = db.execute(
                "select id,created_at,updated_at,state,host_device,host_name,guest_device,guest_name,last_action "
                "from card_tables where state in ('waiting','ready','playing') order by updated_at desc limit 80"
            ).fetchall()
            card_wallet_rows = db.execute(
                "select device,display_name,q_coins,updated_at from card_wallets order by updated_at desc limit 80"
            ).fetchall()
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
                    actor_user=adm["user"],
                    control_csrf=self.control_csrf(adm),
                    card_rows=card_rows,
                    card_wallet_rows=card_wallet_rows,
                ),
                "text/html; charset=utf-8",
            )

        self.reply(404, "Not found", "text/plain")

    def download_file(self, path, head=False):
        # A scheduled release is uploaded early so its integrity can be
        # verified, but its predictable download path must not make it public
        # before the configured publication time.
        relative = path.removeprefix("/downloads/").lstrip("/")
        if any(part in (".", "..") for part in relative.split("/")):
            return self.reply(404, "Not found", "text/plain")
        root = os.path.realpath(DOWNLOAD_ROOT) + os.sep
        target = os.path.realpath(os.path.join(DOWNLOAD_ROOT, relative))
        if not target.startswith(root) or not os.path.isfile(target):
            return self.reply(404, "Not found", "text/plain")
        # Use the resolved version, including a possible in-root symlink. The
        # raw first segment must not bypass the pending release embargo.
        scheduled_version = os.path.relpath(target, root).split(os.sep, 1)[0]
        db = self.connection_db()
        s = settings(db)
        if effective_maintenance(s) or not enabled(s, "public_download_enabled", True):
            return self.reply(503, "Downloads temporarily unavailable", "text/plain; charset=utf-8", {"Retry-After": "300"})
        if (
            enabled(s, "release_schedule_enabled", False)
            and scheduled_version == (s.get("scheduled_app_version") or "").strip()
            and scheduled_version != s.get("app_version")
        ):
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

        if path.startswith("/api/client/community/"):
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(ip, int(s.get("rate_limit_per_min") or 120)):
                return self.reply(429, '{"error":"rate_limited"}')
            return self.community_post(db, path)

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

        if path == "/api/client/cards/join":
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(f"card-game:{ip}", max(3, min(20, int(s.get("rate_limit_per_min") or 120) // 6))):
                return self.reply(429, '{"error":"rate_limited"}')
            try:
                size = min(int(self.headers.get("Content-Length", "0")), 4096)
                payload = json.loads(self.rfile.read(size).decode("utf-8"))
                device, client_ip = self.client()
                result = self.join_card_game(
                    db,
                    s,
                    device,
                    client_ip,
                    str(payload.get("access_code") or ""),
                    str(payload.get("display_name") or ""),
                )
                return self.reply(200, json.dumps(result, ensure_ascii=False))
            except PermissionError as exc:
                return self.reply(403, json.dumps({"error": "access_denied", "message": str(exc)}, ensure_ascii=False))
            except ValueError as exc:
                return self.reply(400, json.dumps({"error": "invalid_request", "message": str(exc)}, ensure_ascii=False))
            except Exception:
                return self.reply(400, '{"error":"card_game_unavailable"}')

        if path == "/api/client/cards/action":
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            if rate_limited(f"card-game-action:{ip}", max(12, min(60, int(s.get("rate_limit_per_min") or 120)))):
                return self.reply(429, '{"error":"rate_limited"}')
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size > 4096:
                    return self.reply(413, '{"error":"card_action_too_large"}')
                if size <= 0:
                    raise ValueError("Пустое действие игры")
                payload = json.loads(self.rfile.read(size).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Неверный формат действия игры")
                ticket_data = card_game_ticket_data(str(payload.get("ticket") or "")[:2048])
                if not ticket_data:
                    return self.reply(401, '{"error":"invalid_game_ticket"}')
                device, _client_ip = self.client()
                if not hmac.compare_digest(str(ticket_data.get("device") or ""), device):
                    return self.reply(403, '{"error":"game_ticket_device_mismatch"}')
                result = self.card_game_action(
                    db,
                    s,
                    device,
                    str(ticket_data.get("table") or ""),
                    str(payload.get("action") or ""),
                    str(payload.get("card") or ""),
                    payload.get("target"),
                    payload.get("expected_revision"),
                    payload.get("action_id", ""),
                )
                return self.reply(200, json.dumps(result, ensure_ascii=False))
            except PermissionError as exc:
                return self.reply(403, json.dumps({"error": "access_denied", "message": str(exc)}, ensure_ascii=False))
            except durak.StaleStateError as exc:
                return self.reply(409, json.dumps({"error": "stale_game_state", "message": str(exc)}, ensure_ascii=False))
            except ValueError as exc:
                return self.reply(400, json.dumps({"error": "invalid_action", "message": str(exc)}, ensure_ascii=False))
            except Exception:
                return self.reply(400, '{"error":"card_game_unavailable"}')

        if path.startswith("/operator/passkey/"):
            return self.passkey_post(db, s, path)

        if path.startswith("/operator/") and not self.same_origin_request():
            # Keep a redacted diagnostic in the service journal so reverse-proxy
            # origin mismatches can be fixed without logging credentials.
            print(
                "origin rejected: origin=%r host=%r sec_fetch=%r referer=%r forwarded=%r public=%r"
                % (
                    self.headers.get("Origin"),
                    self.headers.get("Host"),
                    self.headers.get("Sec-Fetch-Site"),
                    self.headers.get("Referer"),
                    self.headers.get("X-Forwarded-Proto"),
                    PUBLIC_BASE,
                ),
                flush=True,
            )
            return self.reply(403, "Invalid origin")

        if path == "/operator/login":
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            login_limit = max(3, min(20, int(s.get("login_rate_limit_per_min") or 5)))
            if rate_limited(f"login:{ip}", login_limit):
                return self.reply(429, render_login("Слишком много попыток. Попробуйте позже."), "text/html; charset=utf-8", {"Retry-After": "60"})
            length = min(int(self.headers.get("Content-Length", "0")), 16_384)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            user = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            code = form.get("totp", [""])[0]
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

        if path.startswith("/operator/control/"):
            return self.control_post(db, s, path, adm)

        if path in ("/operator/community/reply", "/operator/community/state"):
            if not self.require_role(adm, "operator"):
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= community.MAX_REQUEST_BYTES:
                    self.close_connection = True
                    return self.reply(413, "Сообщение слишком большое", "text/plain; charset=utf-8")
                form = parse_qs(self.rfile.read(length).decode("utf-8"))
                expected_origin, _ = control_next.public_origin(PUBLIC_BASE)
                if (self.headers.get("Origin", "") != expected_origin
                        or self.headers.get("Sec-Fetch-Site", "same-origin") not in {"same-origin", "none"}
                        or not hmac.compare_digest(self.control_csrf(adm), form.get("csrf", [""])[0])):
                    return self.reply(403, "Неверное подтверждение запроса. Обновите страницу панели", "text/plain; charset=utf-8")
                thread_id = int(form.get("thread_id", ["0"])[0])
                db.execute("begin immediate")
                if path.endswith("/reply"):
                    community.operator_reply(db, thread_id, form.get("body", [""])[0], form.get("request_id", [""])[0])
                else:
                    community.set_thread_state(db, thread_id, form.get("state", [""])[0])
                audit(db, actor, ip, "community:" + path.rsplit("/", 1)[1], {"thread_id": thread_id})
                db.commit()
                return self.redirect_operator("support", "Обращение обновлено")
            except (community.CommunityError, ValueError, UnicodeError):
                db.rollback()
                return self.redirect_operator("support", "Обращение не изменено. Проверьте сообщение и статус.")
        if not self.require_role(adm, "operator"):
            return

        if path == "/operator/resources":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 5 * 1024 * 1024:
                    return self.reply(413, "Пакет: не более 5 МБ", "text/plain; charset=utf-8")
                form, files = parse_multipart(self)
                message = resources.action(db, ROOT, form, files, actor)
                audit(db, actor, ip, "resources:" + form.get("action", [""])[0], {"result": message})
                db.commit()
                return self.redirect_operator("resources", message)
            except (ValueError, OSError, ImportError):
                db.rollback()
                return self.redirect_operator("resources", "Пакет не принят. Проверьте поля, формат и лимиты изображений.")

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

        if path == "/operator/cards":
            if not self.require_role(adm, "owner"):
                return
            length = min(int(self.headers.get("Content-Length", "0")), 8192)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            raw_code = (form.get("card_game_access_code", [""])[0] or "").strip()
            try:
                wait_minutes = max(5, min(120, int(form.get("card_game_wait_minutes", ["20"])[0] or 20)))
                stake_q_coins = max(0, min(100_000, int(form.get("card_game_stake_q_coins", ["25"])[0] or 0)))
            except ValueError:
                wait_minutes = 20
                stake_q_coins = 25
            values = {
                "card_game_enabled": "1" if "card_game_enabled" in form else "0",
                "card_game_wait_minutes": str(wait_minutes),
                "card_game_stake_q_coins": str(stake_q_coins),
            }
            if raw_code:
                if len(raw_code) < 8 or len(raw_code) > 80:
                    return self.redirect_operator("cards", "Код должен содержать от 8 до 80 символов")
                values["card_game_access_hash"] = password_hash(raw_code)
            set_settings(db, values)
            audit(db, actor, ip, "card_game_config", {
                "enabled": values["card_game_enabled"] == "1",
                "wait_minutes": wait_minutes,
                "stake_q_coins": stake_q_coins,
                "code_rotated": bool(raw_code),
            })
            db.execute(
                "insert into events values (?,?,?,?,?)",
                (int(time.time()), "card_game_config", actor, ip, json.dumps({"enabled": values["card_game_enabled"] == "1"})),
            )
            db.commit()
            return self.redirect_operator("cards", "Настройки карточного стола сохранены")

        if path == "/operator/cards/wallet":
            if not self.require_role(adm, "owner"):
                return
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            device = (form.get("device", [""])[0] or "").strip()
            try:
                amount = int(form.get("amount", ["0"])[0] or 0)
            except ValueError:
                amount = 0
            if not re.fullmatch(r"[A-Za-z0-9_-]{4,128}", device) or not 1 <= amount <= 100_000:
                return self.redirect_operator("cards", "Проверьте ID устройства и число Q-coins")
            now = int(time.time())
            row = db.execute("select q_coins from card_wallets where device=?", (device,)).fetchone()
            if not row:
                return self.redirect_operator("cards", "Игрок с таким ID ещё не входил за стол")
            db.execute(
                "update card_wallets set q_coins=q_coins+?, updated_at=? where device=?",
                (amount, now, device),
            )
            audit(db, actor, ip, "card_wallet_credit", {"device": device, "q_coins": amount})
            db.execute(
                "insert into events values (?,?,?,?,?)",
                (now, "card_wallet", device, ip, json.dumps({"q_coins": amount}, ensure_ascii=False)),
            )
            db.commit()
            return self.redirect_operator("cards", "Виртуальные Q-coins начислены")

        if path == "/operator/routing":
            length = min(int(self.headers.get("Content-Length", "0")), 256 * 1024)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            action = (form.get("action", ["publish"])[0] or "publish").strip()
            try:
                if action == "scan":
                    raw_targets = (form.get("routing_scan_targets", [""])[0] or "")[:4096]
                    active_payload = routing_payload(s)
                    findings = scan_routing_targets(raw_targets, active_payload)
                    # Keep this operator-only evidence outside the signed
                    # policy.  A scan cannot push a rule to clients; a human
                    # must still add a target and publish a reviewed revision.
                    set_settings(db, {"routing_scan_targets": raw_targets})
                    # Store a plain list for the renderer and audit only the
                    # number/statuses, not the complete target history.
                    db.execute(
                        "insert or replace into settings values (?,?)",
                        ("routing_last_scan", json.dumps(findings, ensure_ascii=False, separators=(",", ":"))),
                    )
                    audit(db, actor, ip, "routing:scan", {
                        "targets": len(findings),
                        "ok": sum(1 for item in findings if item.get("status") == "ok"),
                    })
                    db.execute(
                        "insert into events values (?,?,?,?,?)",
                        (int(time.time()), "routing_scan", actor, ip, json.dumps({"targets": len(findings)}, ensure_ascii=False)),
                    )
                    db.commit()
                    ready = sum(1 for item in findings if item.get("status") == "ok")
                    return self.redirect_operator("routing", f"Проверено целей: {len(findings)}, TCP/443 доступно: {ready}")

                if action in ("save", "publish", "stage"):
                    candidate_values = routing_candidate_from_form(form)
                    candidate_state = dict(s)
                    candidate_state.update(candidate_values)
                    current_revision = max(1, int(s.get("routing_revision", "1") or 1))
                    if action == "save":
                        draft_payload = routing_payload(candidate_state, current_revision)
                        now = int(time.time())
                        set_settings(db, {
                            "routing_draft_payload": canonical_json(draft_payload).decode("utf-8"),
                            "routing_draft_updated_at": str(now),
                        })
                        audit(db, actor, ip, "routing:save_draft", {
                            "revision_base": current_revision,
                            "sha256": hashlib.sha256(canonical_json(draft_payload)).hexdigest(),
                        })
                        db.execute(
                            "insert into events values (?,?,?,?,?)",
                            (now, "routing_draft_saved", actor, ip, json.dumps({"revision_base": current_revision}, ensure_ascii=False)),
                        )
                        db.commit()
                        return self.redirect_operator("routing", "Черновик маршрутизации сохранён. APK его не получает до публикации.")
                    if action == "stage":
                        staged_revision = current_revision + 1
                        staged_payload = routing_payload(candidate_state, staged_revision)
                        rollout = max(1, min(100, int(form.get("routing_staging_rollout_percent", ["10"])[0])))
                        values = {
                            "routing_staging_enabled": "1",
                            "routing_staging_revision": str(staged_revision),
                            "routing_staging_rollout_percent": str(rollout),
                            "routing_staging_payload": canonical_json(staged_payload).decode("utf-8"),
                        }
                        set_settings(db, values)
                        audit(db, actor, ip, "routing:stage", {"revision": staged_revision, "rollout_percent": rollout})
                        db.execute(
                            "insert into events values (?,?,?,?,?)",
                            (int(time.time()), "routing_staged", actor, ip, json.dumps({"revision": staged_revision, "rollout_percent": rollout}, ensure_ascii=False)),
                        )
                        db.commit()
                        return self.redirect_operator("routing", f"Тестовый канал r{staged_revision}: {rollout}% устройств")

                    preview = control_next.preview_settings(db, settings(db), candidate_values, actor, "routing", adm.get("role", "viewer"))
                    db.commit()
                    return self.control_preview_page(preview, adm)

                if action == "promote":
                    if not enabled(s, "routing_staging_enabled", False):
                        return self.redirect_operator("routing", "Нет тестового канала для публикации")
                    staged = json.loads(s.get("routing_staging_payload") or "{}")
                    staged_values = routing_settings_from_payload(staged)
                    preview = control_next.preview_settings(db, settings(db), staged_values, actor, "routing", adm.get("role", "viewer"))
                    db.commit()
                    return self.control_preview_page(preview, adm)
                if action == "discard_stage":
                    set_settings(db, {
                        "routing_staging_enabled": "0",
                        "routing_staging_revision": "0",
                        "routing_staging_payload": "{}",
                    })
                    audit(db, actor, ip, "routing:discard_stage", {})
                    db.commit()
                    return self.redirect_operator("routing", "Тестовый канал удалён")

                if action == "rollback":
                    target_revision = max(1, int(form.get("revision", ["0"])[0] or 0))
                    row = db.execute(
                        "select payload from routing_revisions where revision=? and state='production' order by id desc limit 1",
                        (target_revision,),
                    ).fetchone()
                    if not row:
                        return self.redirect_operator("routing", "Ревизия для отката не найдена")
                    rollback_values = routing_settings_from_payload(json.loads(row[0]))
                    preview = control_next.preview_settings(db, settings(db), rollback_values, actor, "routing", adm.get("role", "viewer"))
                    db.commit()
                    return self.control_preview_page(preview, adm)
                return self.redirect_operator("routing", "Неизвестное действие маршрутизации")
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                audit(db, actor, ip, "routing:rejected", {"action": action, "error": str(exc)[:160]})
                db.commit()
                return self.redirect_operator("routing", f"Не сохранено: {str(exc)[:160]}")

        if path == "/operator/actions":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            action = form.get("action", [""])[0]
            return_tab = form.get("return_tab", ["dashboard"])[0]
            if return_tab not in {"dashboard", "automation", "latency", "routing", "release", "service", "incidents", "security", "support", "ai", "quality"}:
                return_tab = "dashboard"
            flash = "Готово"
            if action == "inspect_subscription":
                try:
                    inspection_headers, source = subscription_inspection_headers()
                    body, _ = managed_subscription(inspection_headers, s)
                    report = subscription_evidence(body)
                    report["source"] = source
                    set_settings(db, {"quality_subscription": json.dumps(report, ensure_ascii=False)})
                    flash = "Выдача проверена; индивидуальная выдача APK обновит отчёт при следующем запросе"
                except Exception:
                    flash = "Не удалось получить подписку от основной панели. Последний успешный отчёт сохранён; обновите подписку в авторизованном APK"
                audit(db, actor, ip, "quality:subscription", {"result": flash})
            elif action == "explain_route":
                try:
                    result = explain_route(routing_payload(s), form.get("route_target", [""])[0])
                    set_settings(db, {"quality_route": json.dumps(result, ensure_ascii=False)})
                    flash = "Правило проверено; опубликованная политика не изменялась"
                    audit(db, actor, ip, "quality:route", {"target": result["target"], "direction": result["direction"]})
                except ValueError as exc:
                    flash = str(exc)
            elif action == "verify_backup":
                try:
                    info = latest_backup_info()
                    if not info["exists"]:
                        create_backup_archive()
                        info = latest_backup_info()
                    if not os.environ.get("QV_BACKUP_KEY") and not os.path.isfile(os.path.join(ROOT, "backup.key")):
                        raise ValueError("Ключ расшифровки недоступен")
                    path = os.path.join(ROOT, "backups", info["name"])
                    with open(path, "rb") as stream:
                        result = validate_backup(stream.read(128 * 1024 * 1024 + 1), backup_key(), AESGCM)
                    result["name"] = info["name"]
                    flash = "Копия восстановлена и проверена в изолированном каталоге; рабочие базы не изменялись"
                except Exception as exc:
                    result = {"checked_at": int(time.time()), "ok": False, "note": "Архив или ключ не прошёл проверку; рабочие базы не изменялись", "error_type": type(exc).__name__}
                    flash = result["note"]
                set_settings(db, {"quality_backup": json.dumps(result, ensure_ascii=False)})
                audit(db, actor, ip, "quality:backup", {"ok": result["ok"], "missing": result.get("missing", [])})
            elif action == "bump_revision":
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
            elif action in ("drain_node", "restore_node"):
                target = (form.get("target", [""])[0] or "").strip()[:253]
                allowed_targets = {
                    node["target"] for node in parse_node_map_config(s.get("node_map_config", ""))
                }
                allowed_targets.update(f"{host}:{port}" for host, port in parse_latency_targets(s.get("latency_probe_targets", "")))
                if target not in allowed_targets:
                    flash = "Нода не найдена в реестре"
                else:
                    drains = manual_node_drains(s)
                    if action == "drain_node":
                        drains[target] = {"since": int(time.time()), "actor": actor, "note": "manual maintenance"}
                        event_kind = "node_drained"
                        flash = f"{target} исключена из балансировки"
                    else:
                        drains.pop(target, None)
                        event_kind = "node_restored"
                        flash = f"{target} возвращена в балансировку"
                    set_settings(db, {"node_drains": json.dumps(drains, ensure_ascii=False, separators=(",", ":"))})
                    db.execute(
                        "insert into events values (?,?,?,?,?)",
                        (int(time.time()), event_kind, actor, ip, json.dumps({"target": target}, ensure_ascii=False)),
                    )
            elif action in ("run_health_check", "run_latency_probe"):
                def background_probe(kind=action, requested_by=actor, requested_ip=ip):
                    probe_db = None
                    try:
                        probe_db = conn()
                        snapshot = settings(probe_db)
                        result = run_health_check(probe_db, snapshot) if kind == "run_health_check" else run_latency_probe(probe_db, snapshot)
                        probe_db.execute(
                            "insert into events values (?,?,?,?,?)",
                            (
                                int(time.time()),
                                "manual_health_check" if kind == "run_health_check" else "manual_latency_probe",
                                requested_by,
                                requested_ip,
                                json.dumps({"ok": True, "result": result}, ensure_ascii=False)[:1500],
                            ),
                        )
                        probe_db.commit()
                    except Exception as exc:
                        if probe_db is not None:
                            try:
                                probe_db.execute(
                                    "insert into events values (?,?,?,?,?)",
                                    (int(time.time()), "manual_probe_error", requested_by, requested_ip, str(exc)[:500]),
                                )
                                probe_db.commit()
                            except Exception:
                                pass
                    finally:
                        if probe_db is not None:
                            try:
                                probe_db.close()
                            except Exception:
                                pass
                threading.Thread(target=background_probe, daemon=True).start()
                flash = "Проверка запущена в фоне"
            elif action in ("run_ai_analysis", "check_ai_model"):
                if action == "check_ai_model":
                    model_status = qwen_local_status(s.get("ai_model") or QWEN_DEFAULT_MODEL)
                    flash = "Qwen готова" if model_status.get("ready") else (model_status.get("error") or "Qwen недоступна")
                    db.execute(
                        "insert into events values (?,?,?,?,?)",
                        (int(time.time()), "ai_model_check", actor, ip, json.dumps({"ready": bool(model_status.get("ready"))}, ensure_ascii=False)),
                    )
                else:
                    def background_ai(requested_by=actor, requested_ip=ip):
                        analysis_db = None
                        try:
                            analysis_db = conn()
                            result = run_ai_analysis(analysis_db, settings(analysis_db), "manual")
                            audit(analysis_db, requested_by, requested_ip, "ai_analysis_manual", {"ok": bool(result.get("ok")), "status": result.get("status", "")})
                            analysis_db.commit()
                        except Exception as exc:
                            if analysis_db is not None:
                                try:
                                    analysis_db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "ai_analysis_error", requested_by, requested_ip, f"{type(exc).__name__}: {exc}"[:500]))
                                    analysis_db.commit()
                                except Exception:
                                    pass
                        finally:
                            if analysis_db is not None:
                                try:
                                    analysis_db.close()
                                except Exception:
                                    pass
                    threading.Thread(target=background_ai, daemon=True).start()
                    flash = "Анализ Qwen запущен в фоне"
            elif action == "release_preflight":
                guard = release_guard_snapshot(s)
                failures = [item["name"] for item in guard.values() if item.get("configured", True) and not item.get("ready")]
                flash = "Релизы готовы: ARM64 и ARMv7 на месте" if not failures else "Не готовы: " + ", ".join(failures)
                db.execute(
                    "insert into events values (?,?,?,?,?)",
                    (int(time.time()), "release_preflight", actor, ip, json.dumps(guard, ensure_ascii=False)),
                )
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
            return self.redirect_operator(return_tab, flash)

        if path == "/operator/support":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            action = (form.get("action", [""])[0] or "").strip()
            now = int(time.time())
            if action == "create":
                subject = (form.get("subject", [""])[0] or "").strip()[:160]
                device = (form.get("device", [""])[0] or "").strip()[:128]
                body = (form.get("body", [""])[0] or "").strip()[:1600]
                if not subject:
                    return self.redirect_operator("support", "Укажите тему обращения")
                db.execute(
                    "insert into support_tickets(created_at,updated_at,closed_at,source,device,subject,body,admin_note) values (?,?,?,?,?,?,?,?)",
                    (now, now, 0, "operator", device, subject, body, ""),
                )
                db.execute(
                    "insert into events values (?,?,?,?,?)",
                    (now, "support_ticket_created", actor, ip, json.dumps({"subject": subject, "device": device}, ensure_ascii=False)),
                )
                flash = "Обращение создано"
            elif action in ("close", "reopen"):
                try:
                    ticket_id = int(form.get("id", ["0"])[0])
                except (TypeError, ValueError):
                    ticket_id = 0
                if ticket_id <= 0:
                    return self.redirect_operator("support", "Некорректный номер обращения")
                closed = now if action == "close" else 0
                cursor = db.execute(
                    "update support_tickets set closed_at=?, updated_at=? where id=?",
                    (closed, now, ticket_id),
                )
                if not cursor.rowcount:
                    return self.redirect_operator("support", "Обращение не найдено")
                db.execute(
                    "insert into events values (?,?,?,?,?)",
                    (now, "support_ticket_" + action, actor, ip, json.dumps({"id": ticket_id}, ensure_ascii=False)),
                )
                flash = "Обращение закрыто" if action == "close" else "Обращение снова открыто"
            else:
                return self.redirect_operator("support", "Неизвестное действие поддержки")
            audit(db, actor, ip, "support:" + action, {"result": flash})
            db.commit()
            return self.redirect_operator("support", flash)

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
                return self.redirect_operator(tab, "Не сохранено: проверьте время технических работ")
            if "maintenance_schedule_enabled" in form and (start <= 0 or end <= start):
                return self.redirect_operator(tab, "Не сохранено: окончание работ должно быть позже начала")
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
            values = {
                "subscription_main_enabled": "1" if "subscription_main_enabled" in form else "0",
                "reserve_profile_enabled": "1" if "reserve_profile_enabled" in form else "0",
            }
        elif section == "subscription_text":
            tab = "service"
            title = " ".join((form.get("subscription_category_title", [""])[0] or "").split())[:80]
            description = " ".join((form.get("subscription_category_description", [""])[0] or "").split())[:240]
            main_label = " ".join((form.get("subscription_main_label", [""])[0] or "").split())[:160]
            reserve_label = " ".join((form.get("reserve_profile_label", [""])[0] or "").split())[:160]
            if not all((title, description, main_label, reserve_label)):
                return self.redirect_operator(tab, "Не сохранено: заполните все четыре текста категории")
            values = {
                "subscription_category_title": title,
                "subscription_category_description": description,
                "subscription_main_label": main_label,
                "reserve_profile_label": reserve_label,
            }
        elif section == "public_status":
            tab = "service"
            public_note = " ".join((form.get("public_status_note_en", [""])[0] or "").split())[:160]
            values = {
                "public_download_enabled": "1" if "public_download_enabled" in form else "0",
                "public_status_note_en": public_note or "Live service information for QuantumVPN users.",
            }
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
                return self.redirect_operator(tab, "Не сохранено: проверьте версию, versionCode и процент выпуска")
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
                return self.redirect_operator(tab, "Не сохранено: проверьте staging versionCode и процент выпуска")
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
                return self.redirect_operator(tab, "Не сохранено: заполните название, подзаголовок и цвет вида #12AB34")
            values = {
                "brand_name": name,
                "brand_tagline": tagline,
                "brand_accent": accent,
            }
        elif section == "latency":
            tab = "latency"
            try:
                probe_interval = bounded_form_int(form, "latency_probe_interval", current.get("latency_probe_interval", "30"), 15, 300)
                max_latency = bounded_form_int(form, "latency_max_ms", current.get("latency_max_ms", "120"), 20, 5000)
                quarantine_failures = bounded_form_int(form, "auto_quarantine_failures", current.get("auto_quarantine_failures", "3"), 2, 10)
                quarantine_recovery = bounded_form_int(form, "auto_quarantine_recovery_checks", current.get("auto_quarantine_recovery_checks", "2"), 1, 10)
                quarantine_ttl = bounded_form_int(form, "auto_quarantine_ttl_minutes", current.get("auto_quarantine_ttl_minutes", "30"), 5, 1440)
            except Exception:
                return self.redirect_operator(tab, "Не сохранено: в оптимизации нод укажите целые числа")
            targets = ",".join(f"{host}:{port}" for host, port in parse_latency_targets(form.get("latency_probe_targets", [""])[0]))
            if not targets:
                return self.redirect_operator(tab, "Не сохранено: добавьте хотя бы одну TCP-цель ноды")
            node_map_config = form.get("node_map_config", [""])[0].strip()[:5000]
            if not node_map_config_is_valid(node_map_config):
                return self.redirect_operator(tab, "Не сохранено: реестр нод — одна строка «название | host:порт | широта | долгота | регион»")
            values = {
                "latency_optimization_enabled": "1" if "latency_optimization_enabled" in form else "0",
                "latency_probe_interval": str(probe_interval),
                "latency_max_ms": str(max_latency),
                "latency_probe_targets": targets,
                "node_map_config": node_map_config,
                "auto_quarantine_enabled": "1" if "auto_quarantine_enabled" in form else "0",
                "auto_quarantine_failures": str(quarantine_failures),
                "auto_quarantine_recovery_checks": str(quarantine_recovery),
                "auto_quarantine_ttl_minutes": str(quarantine_ttl),
            }
        elif section == "latency_balancer":
            tab = "latency"
            try:
                max_balancer_latency = bounded_form_int(form, "load_balancer_max_latency_ms", current.get("load_balancer_max_latency_ms", "250"), 20, 5000)
            except Exception:
                return self.redirect_operator(tab, "Не сохранено: максимальный пинг должен быть целым числом")
            strategy = form.get("load_balancer_strategy", ["latency_health"])[0]
            if strategy not in ("latency_health", "stable"):
                strategy = "latency_health"
            values = {
                "load_balancer_enabled": "1" if "load_balancer_enabled" in form else "0",
                "load_balancer_strategy": strategy,
                "load_balancer_max_latency_ms": str(max_balancer_latency),
            }
        elif section == "automation":
            tab = "automation"
            try:
                health_interval = bounded_form_int(form, "health_monitor_interval_seconds", current.get("health_monitor_interval_seconds", "60"), 30, 600)
            except Exception:
                return self.redirect_operator(tab, "Не сохранено: интервал мониторинга должен быть целым числом")
            digest_time = (form.get("telegram_digest_time_msk", ["09:00"])[0] or "").strip()
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", digest_time):
                return self.redirect_operator(tab, "Не сохранено: время сводки укажите в формате ЧЧ:ММ")
            values = {
                "health_monitor_enabled": "1" if "health_monitor_enabled" in form else "0",
                "health_monitor_interval_seconds": str(health_interval),
                "telegram_daily_digest_enabled": "1" if "telegram_daily_digest_enabled" in form else "0",
                "telegram_digest_time_msk": digest_time,
            }
        elif section == "ai":
            tab = "ai"
            try:
                interval = bounded_form_int(form, "ai_interval_seconds", current.get("ai_interval_seconds", "900"), AI_MIN_INTERVAL_SECONDS, AI_MAX_INTERVAL_SECONDS)
            except Exception:
                return self.redirect_operator(tab, "Не сохранено: интервал ИИ должен быть целым числом")
            requested_model = (form.get("ai_model", [QWEN_DEFAULT_MODEL])[0] or "").strip()
            if requested_model != QWEN_DEFAULT_MODEL:
                return self.redirect_operator(tab, "Не сохранено: разрешена только локальная Qwen3 0.6B")
            values = {
                "ai_advisor_enabled": "1" if "ai_advisor_enabled" in form else "0",
                "ai_model": QWEN_DEFAULT_MODEL,
                "ai_interval_seconds": str(interval),
                "ai_telegram_enabled": "1" if "ai_telegram_enabled" in form else "0",
            }
        elif section == "security":
            tab = "security"
            try:
                rl = bounded_form_int(form, "rate_limit_per_min", current.get("rate_limit_per_min", "120"), 10, 5000)
            except Exception:
                return self.redirect_operator(tab, "Не сохранено: лимит запросов должен быть целым числом")
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
                "telegram_chat_id": form.get("telegram_chat_id", [""])[0][:64],
            }
            supplied_token = (form.get("telegram_bot_token", [""])[0] or "").strip()
            if supplied_token and not os.environ.get("QV_TELEGRAM_BOT_TOKEN", "").strip():
                values["telegram_bot_token"] = supplied_token[:200]
        elif section == "webhooks":
            tab = "integrations"
            url = (form.get("webhook_url", [""])[0] or "").strip()[:2048]
            if url and not url.lower().startswith("https://"):
                return self.redirect_operator(tab, "Не сохранено: вебхук должен начинаться с https://")
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
            return self.redirect_operator("dashboard", "Неизвестный раздел настроек")

        if section in {"nodes", "latency", "latency_balancer"}:
            try:
                preview = control_next.preview_settings(db, current, values, actor, "nodes", adm.get("role", "viewer"))
                db.commit()
                return self.control_preview_page(preview, adm)
            except (ValueError, PermissionError) as error:
                db.rollback()
                return self.redirect_operator("latency", "Не применено: " + str(error)[:180])

        if section in ("service", "subscription_text", "public_status", "features", "nodes", "ab", "branding", "latency", "release", "automation", "ai") and any(current.get(k) != v for k, v in values.items()):
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
    threading.Thread(target=ai_worker, daemon=True).start()
    threading.Thread(target=scheduled_release_worker, daemon=True).start()
    threading.Thread(target=telegram_command_worker, daemon=True).start()
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
