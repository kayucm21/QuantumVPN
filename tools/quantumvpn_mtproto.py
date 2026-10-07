"""Local, bounded MTProxy operations; ordinary status never returns credentials.

Protocol references: https://core.telegram.org/mtproto/mtproto-transports and
https://core.telegram.org/mtproto/auth_key. The installer pins official MTProxy.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


COMMIT = "f36d8af769ffaeac36978d38c2c0f6d1104c2137"
SECURITY_PATCH = "systemd-secret-file-v2"
SECURITY_PATCH_SHA256 = "fd3e0b1e17c1b8265a12c604f35dc0873ae31388260675185f9ad1201d62aa36"
BASE_SOURCE_SHA256 = "31116c17d5245b8d564d04b252a4d80e24c23f637342e09e33c47b08973defad"
SERVICE = "quantumvpn-mtproto.service"
ROOT = Path("/opt/quantumvpn-mtproto")
PRIVATE = Path("/etc/quantumvpn-mtproto")
CONFIG = PRIVATE / "config.json"
SECRET = PRIVATE / "client-secret"
PUBLIC_PORT = 3443
STATS_PORT = 18888
PUBLIC_HOST = "150.241.96.191"
_LAST_PROBE: dict = {"ok": None, "status": "not_checked"}
_STATS_KEYS = frozenset(("uptime", "total_connections", "total_special_connections",
                         "total_ready_targets", "total_allocated_outbound_connections",
                         "tot_forwarded_queries", "tot_forwarded_responses", "mtproto_proxy_errors"))
_PROBE_FAILURE_CODES = frozenset(("invalid_probe_secret", "protocol_frame_too_large",
                                "protocol_crypto_unavailable", "protocol_entropy_failure",
                                "protocol_deadline", "protocol_connection_closed",
                                "invalid_mtproto_frame_length", "invalid_mtproto_response",
                                "invalid_mtproto_message_length", "telegram_nonce_not_confirmed",
                                "invalid_telegram_res_pq"))


def _read_bytes(path: Path, maximum: int, *, private: bool = False, owner: int = 0, credential: bool = False) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise RuntimeError("unsafe_local_file")
        if os.name != "nt":
            if credential:
                # systemd may supply root-owned 0440 + per-service ACL, on a
                # read-only credential mount. Ordinary private files stay 0600.
                readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
                if not _credential_permissions(info, owner, os.getegid(), readonly):
                    raise RuntimeError("unsafe_systemd_credential")
            elif info.st_uid != owner or info.st_mode & (0o077 if private else 0o022):
                raise RuntimeError("unsafe_local_permissions")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise RuntimeError("local_file_too_large")
        return data
    finally:
        os.close(fd)


def _credential_permissions(info, owner: int, group: int, readonly: bool) -> bool:
    return (readonly and (info.st_uid, info.st_gid) in ((0, 0), (owner, group))
            and stat.S_IMODE(info.st_mode) in (0o400, 0o440))


def _validate_config(value: dict) -> dict:
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value.get("schema") != 1 or value.get("managed_by") != "quantumvpn":
        raise RuntimeError("unmanaged_configuration")
    if value.get("commit") != COMMIT or type(value.get("port")) is not int or value.get("port") != PUBLIC_PORT or type(value.get("stats_port")) is not int or value.get("stats_port") != STATS_PORT:
        raise RuntimeError("unexpected_configuration")
    if value.get("security_patch") != SECURITY_PATCH:
        raise RuntimeError("unexpected_security_patch")
    if value.get("patch_sha256") != SECURITY_PATCH_SHA256 or value.get("source_file_sha256") != BASE_SOURCE_SHA256:
        raise RuntimeError("unexpected_source_identity")
    if value.get("server") != PUBLIC_HOST or not ipaddress.ip_address(value["server"]).is_global:
        raise RuntimeError("unexpected_server")
    for key in ("binary_sha256", "module_sha256", "patch_sha256"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise RuntimeError("invalid_binary_identity")
    if type(value.get("created_at")) is not int or not 0 <= value["created_at"] < 1 << 53:
        raise RuntimeError("invalid_install_timestamp")
    return value


def _config() -> dict:
    return _validate_config(json.loads(_read_bytes(CONFIG, 8192, private=True)))


def _secret() -> str:
    value = _read_bytes(SECRET, 64, private=True).decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{32}", value):
        raise RuntimeError("invalid_local_secret")
    return value


def _service_state() -> str:
    try:
        result = subprocess.run(["systemctl", "is-active", SERVICE], capture_output=True,
                                text=True, timeout=3, check=False)
        value = result.stdout.strip()
        return value if value in ("active", "inactive", "failed", "activating", "deactivating", "unknown") else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _stats() -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(f"http://127.0.0.1:{STATS_PORT}/stats", headers={"Accept": "text/plain"})
    with opener.open(request, timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("stats_unavailable")
        data = response.read(131073)
    if len(data) > 131072:
        raise RuntimeError("stats_too_large")
    result = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in _STATS_KEYS and re.fullmatch(r"[0-9]{1,18}", fields[1]):
            result[fields[0]] = int(fields[1])
    return result


def snapshot() -> dict:
    """GET-safe local status: no writes, random secrets, links or raw process data."""
    result = {"installed": False, "service": _service_state(), "port": PUBLIC_PORT,
              "server": PUBLIC_HOST, "stats_loopback_only": True,
              "protocol_health": dict(_LAST_PROBE), "secret_available": False}
    try:
        config = _config()
        result.update(installed=True, commit=config["commit"], security_patch=config["security_patch"], created_at=config.get("created_at"),
                      secret_available=SECRET.is_file() and not SECRET.is_symlink())
    except FileNotFoundError:
        result["status"] = "not_installed"
        return result
    except Exception:
        result["status"] = "configuration_unavailable"
        return result
    result["status"] = result["service"]
    if result["service"] == "active":
        try:
            result["stats"] = _stats()
            result["upstream_ready"] = result["stats"].get("total_ready_targets", 0) > 0
        except Exception:
            result["stats"] = {}
            result["upstream_ready"] = None
    return result


def owner_connection_links() -> dict:
    """Credential-bearing result: callers must enforce explicit owner access."""
    config = _config()
    query = urllib.parse.urlencode({"server": config["server"], "port": config["port"], "secret": "dd" + _secret()})
    return {"telegram": "tg://proxy?" + query, "https": "https://t.me/proxy?" + query}


def control(action: str) -> dict:
    """Call only after the panel has checked owner, CSRF and explicit confirmation."""
    if action not in ("start", "stop", "restart"):
        raise ValueError("unsupported_mtproto_action")
    _config()
    try:
        result = subprocess.run(["systemctl", action, SERVICE], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
        ok = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    return {"ok": ok, "action": action, "status": snapshot()}


def _aes_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) > 65536:
        raise RuntimeError("protocol_frame_too_large")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        transform = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return transform.update(data) + transform.finalize()
    except ImportError:
        # openssl is an installation dependency; no third-party Python package is required.
        result = subprocess.run(["/usr/bin/openssl", "enc", "-aes-256-ctr", "-nosalt", "-nopad",
                                 "-K", key.hex(), "-iv", iv.hex()], input=data,
                                capture_output=True, timeout=2, check=False)
        if result.returncode or len(result.stdout) != len(data):
            raise RuntimeError("protocol_crypto_unavailable")
        return result.stdout


def _request(secret: str) -> tuple[bytes, bytes, bytes, bytes]:
    secret_bytes = bytes.fromhex(secret)
    for _ in range(32):
        init = bytearray(os.urandom(64))
        if init[0] != 0xef and init[:4] not in (b"\xdd" * 4, b"\xee" * 4, b"POST", b"GET ", b"HEAD", b"OPTI", b"\x16\x03\x01\x02") and init[4:8] != b"\0" * 4:
            break
    else:
        raise RuntimeError("protocol_entropy_failure")
    init[56:60] = b"\xdd" * 4
    init[60:62] = struct.pack("<h", 2)
    reverse = bytes(init)[::-1]
    encryption_key = hashlib.sha256(bytes(init[8:40]) + secret_bytes).digest()
    decryption_key = hashlib.sha256(reverse[8:40] + secret_bytes).digest()
    nonce = os.urandom(16)
    message = struct.pack("<I", 0xbe7e8ef1) + nonce
    message_id = int(time.time() * (1 << 32)) & ~3
    packet = struct.pack("<QQI", 0, message_id, len(message)) + message + os.urandom(12)
    encrypted = _aes_ctr(bytes(init) + struct.pack("<I", len(packet)) + packet,
                         encryption_key, bytes(init[40:56]))
    return bytes(init[:56]) + encrypted[56:], decryption_key, reverse[40:56], nonce


def _receive_exact(connection, count: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("protocol_deadline")
        connection.settimeout(remaining)
        piece = connection.recv(count - len(result))
        if not piece:
            raise RuntimeError("protocol_connection_closed")
        result.extend(piece)
    return bytes(result)


def _validate_response(frame: bytes, nonce: bytes) -> None:
    if len(frame) < 56 or frame[:8] != b"\0" * 8:
        raise RuntimeError("invalid_mtproto_response")
    message_length = struct.unpack_from("<I", frame, 16)[0]
    # Do not confuse transport's 0..15 padding with padding already supplied
    # inside the forwarded Telegram payload (real resPQ can carry >15 bytes).
    # Keep both the full frame and total extra padding strictly bounded.
    if (not 36 <= message_length <= len(frame) - 20 or message_length % 4
            or len(frame) - 20 - message_length > 1024 + 15):
        raise RuntimeError("invalid_mtproto_message_length")
    body = frame[20:20 + message_length]
    if struct.unpack_from("<I", body)[0] != 0x05162463 or body[4:20] != nonce:
        raise RuntimeError("telegram_nonce_not_confirmed")
    if len(body) < 56 or body[20:36] == b"\0" * 16 or not 1 <= body[36] <= 8:
        raise RuntimeError("invalid_telegram_res_pq")
    vector = (37 + body[36] + 3) & ~3
    if vector + 8 > len(body) or struct.unpack_from("<I", body, vector)[0] != 0x1cb5c415:
        raise RuntimeError("invalid_telegram_res_pq")
    fingerprints = struct.unpack_from("<I", body, vector + 4)[0]
    if not 1 <= fingerprints <= 64 or vector + 8 + fingerprints * 8 != len(body):
        raise RuntimeError("invalid_telegram_res_pq")


def _probe_endpoint(secret: str, endpoint: str) -> dict:
    """Protocol-only helper, limited to the two explicitly managed endpoints."""
    if endpoint not in ("127.0.0.1", PUBLIC_HOST):
        raise ValueError("unmanaged_probe_endpoint")
    started = time.monotonic()
    result = {"ok": False, "status": "protocol_failed", "method": "mtproto_req_pq_multi", "checked_at": int(time.time())}
    try:
        if not isinstance(secret, str) or not re.fullmatch(r"[a-f0-9]{32}", secret):
            raise RuntimeError("invalid_probe_secret")
        request, key, iv, nonce = _request(secret)
        deadline = started + 6
        with socket.create_connection((endpoint, PUBLIC_PORT), timeout=2) as connection:
            connection.sendall(request)
            header = _receive_exact(connection, 4, deadline)
            size = struct.unpack("<I", _aes_ctr(header, key, iv))[0]
            if not 56 <= size <= 4096:
                raise RuntimeError("invalid_mtproto_frame_length")
            encrypted = header + _receive_exact(connection, size, deadline)
            _validate_response(_aes_ctr(encrypted, key, iv)[4:], nonce)
        result.update(ok=True, status="protocol_confirmed", latency_ms=round((time.monotonic() - started) * 1000))
    except Exception as error:
        # A closed allowlist preserves actionable diagnostics without arbitrary
        # exception text, packets, argv, remote errors or credentials.
        code = str(error) if isinstance(error, (RuntimeError, TimeoutError)) else ""
        result["failure_code"] = code if code in _PROBE_FAILURE_CODES else "bounded_protocol_failure"
    return result


def health_probe() -> dict:
    """Loopback req_pq_multi -> resPQ nonce proof, not an account/RSA login."""
    global _LAST_PROBE
    try:
        _config()
        result = _probe_endpoint(_secret(), "127.0.0.1")
    except Exception:
        result = {"ok": False, "status": "configuration_unavailable", "method": "mtproto_req_pq_multi", "checked_at": int(time.time())}
    _LAST_PROBE = dict(result)
    return result


def external_health_probe(secret: str) -> dict:
    """Installer-only external nonce proof; secret remains in process memory."""
    return _probe_endpoint(secret, PUBLIC_HOST)


def serve() -> None:
    """systemd credential launcher; all paths and binary arguments are fixed."""
    credentials = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    if not credentials.is_absolute() or credentials.parent != Path("/run/credentials") or credentials.name != SERVICE:
        raise RuntimeError("systemd_credentials_required")
    owner = os.geteuid()
    config = _validate_config(json.loads(_read_bytes(credentials / "runtime-config", 8192, owner=owner, credential=True)))
    secret = _read_bytes(credentials / "client-secret", 64, owner=owner, credential=True).decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{32}", secret):
        raise RuntimeError("invalid_local_secret")
    binary = ROOT / "mtproto-proxy"
    if hashlib.sha256(_read_bytes(binary, 100 * 1024 * 1024)).hexdigest() != config["binary_sha256"]:
        raise RuntimeError("binary_identity_mismatch")
    args = [str(binary), "-p", str(STATS_PORT), "-H", str(PUBLIC_PORT),
            "--secret-file", str(credentials / "client-secret"),
            "--aes-pwd", str(credentials / "proxy-secret"), str(credentials / "proxy-config"),
            "-M", "1", "-C", "2048", "-c", "4096", "--http-stats"]
    os.execv(str(binary), args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--probe", action="store_true")
    options = parser.parse_args()
    if options.serve:
        serve()
    else:
        print(json.dumps(health_probe() if options.probe else snapshot(), separators=(",", ":")))


if __name__ == "__main__":
    main()
