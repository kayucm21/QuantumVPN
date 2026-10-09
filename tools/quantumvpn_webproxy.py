"""Bounded operations for an independently managed Telegram WEB relay.

The wire contract is Telegram's pinned tproxy-server PROTOCOL.md / BASE_PATH.md.
No upstream code is vendored. A successful probe proves WEB -> MTProxy -> resPQ
nonce continuity, not account authorization, calls, or end-user performance.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import subprocess
import time
import types
import urllib.error
import urllib.parse
import urllib.request

COMMIT = "c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8"
ARCHIVE_SHA256 = "a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549"
SERVICE = "quantumvpn-webproxy.service"
ROOT = Path("/opt/quantumvpn-webproxy")
PRIVATE = Path("/etc/quantumvpn-webproxy")
MANIFEST = PRIVATE / "manifest.json"
CONFIG = PRIVATE / "config.json"
PROFILES = PRIVATE / "profiles.json"
RUNTIME = Path("/run/quantumvpn-webproxy")
PUBLIC_HOST = "pecaocek.ignorelist.com"
PUBLIC_PORT = 443
RELAY_PORT = 18082
ADMIN_PORT = 18083
BACKEND = "127.0.0.1:3443"
PUBLIC_UPSTREAM = "http://127.0.0.1:8080"
MAX_PROBE_SECONDS = 20
_LAST_PROBE = {"ok": None, "status": "not_checked"}
_FAILURES = frozenset((
    "configuration_unavailable", "crypto_unavailable", "mtproto_helper_unavailable",
    "public_tls_failed", "bridge_unavailable", "bridge_contract_invalid",
    "unsupported_carrier", "session_rejected", "session_contract_invalid",
    "uplink_rejected", "downlink_rejected", "cursor_invalid", "frame_invalid",
    "stream_closed", "relay_closed", "protocol_deadline", "response_too_large",
    "telegram_nonce_not_confirmed", "invalid_mtproto_frame_length",
    "invalid_mtproto_response", "invalid_mtproto_message_length",
    "invalid_telegram_res_pq", "protocol_entropy_failure", "http_redirect_refused",
    "bounded_transport_failure",
))


def _credential_permissions(info, owner: int, group: int, readonly: bool) -> bool:
    return (readonly and (info.st_uid, info.st_gid) in ((0, 0), (owner, group))
            and stat.S_IMODE(info.st_mode) in (0o400, 0o440))


def _read_file(path: Path, maximum: int, *, private: bool = False,
               credential: bool = False) -> bytes:
    # Every production caller supplies a constant or a validated fixed credential
    # path. Reject symlink ancestors too, not merely the final pathname.
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError("unsafe_local_file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
            raise RuntimeError("unsafe_local_file")
        if os.name != "nt":
            if credential:
                readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
                if not _credential_permissions(info, os.geteuid(), os.getegid(), readonly):
                    raise RuntimeError("unsafe_systemd_credential")
            elif info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
                raise RuntimeError("unsafe_local_permissions")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise RuntimeError("local_file_too_large")
        return data
    finally:
        os.close(fd)


def _validate_manifest(value: dict) -> dict:
    if (not isinstance(value, dict) or type(value.get("schema")) is not int
            or value["schema"] != 1 or value.get("managed_by") != "quantumvpn-webproxy"):
        raise RuntimeError("unmanaged_configuration")
    fixed = {"commit": COMMIT, "archive_sha256": ARCHIVE_SHA256,
             "public_host": PUBLIC_HOST, "public_port": PUBLIC_PORT,
             "listen": f"127.0.0.1:{RELAY_PORT}",
             "admin_listen": f"127.0.0.1:{ADMIN_PORT}", "backend": BACKEND,
             "carrier_mode": "https"}
    if any(value.get(key) != expected or type(value.get(key)) is not type(expected)
           for key, expected in fixed.items()):
        raise RuntimeError("unexpected_configuration")
    if not isinstance(value.get("base_path"), str) or not re.fullmatch(r"qweb-[a-z0-9-]{8,80}", value["base_path"]):
        raise RuntimeError("invalid_base_path")
    for key in ("binary_sha256", "helper_sha256"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise RuntimeError("invalid_binary_identity")
    if type(value.get("created_at")) is not int or not 0 <= value["created_at"] < 1 << 53:
        raise RuntimeError("invalid_install_timestamp")
    return value


def _validate_runtime(value: dict, manifest: dict) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError("unexpected_runtime_configuration")
    credentials = f"/run/credentials/{SERVICE}"
    fixed = {"public_hostname": PUBLIC_HOST, "base_path": manifest["base_path"],
             "listen": manifest["listen"], "admin_listen": manifest["admin_listen"],
             "public_upstream": PUBLIC_UPSTREAM, "static_routes": "exact",
             "profiles_file": credentials + "/profiles.json",
             "token_key_file": (RUNTIME / "token.key").as_posix(), "enable_pprof": False}
    if any(value.get(key) != expected or type(value.get(key)) is not type(expected)
           for key, expected in fixed.items()) or value.get("public_dir"):
        raise RuntimeError("unexpected_runtime_configuration")
    limits = value.get("limits")
    # The Go server performs the complete consistency/budget validation. These
    # are independent hard caps needed to remain inside the managed unit budget.
    if not isinstance(limits, dict):
        raise RuntimeError("invalid_runtime_limits")
    caps = {"max_pending_global": 64 * 1024 * 1024,
            "max_pending_per_session": 8 * 1024 * 1024,
            "max_sessions_global": 32, "max_streams_global": 512,
            "max_backend_dials_in_flight": 32, "max_body_bytes": 2 * 1024 * 1024,
            "max_frame_payload": 1024 * 1024, "carrier_batch_bytes": 2 * 1024 * 1024}
    for key, maximum in caps.items():
        if type(limits.get(key)) is not int or not 1 <= limits[key] <= maximum:
            raise RuntimeError("invalid_runtime_limits")
    return value


def _configuration() -> tuple[dict, dict]:
    manifest = _validate_manifest(json.loads(_read_file(MANIFEST, 16384, private=True)))
    runtime = _validate_runtime(json.loads(_read_file(CONFIG, 16384, private=True)), manifest)
    return manifest, runtime


def _profile() -> dict:
    value = json.loads(_read_file(PROFILES, 16384, private=True))
    profiles = value.get("profiles") if isinstance(value, dict) else None
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise RuntimeError("unexpected_profiles")
    profile = profiles[0]
    if (profile.get("name") != "quantumvpn" or profile.get("backend") != BACKEND
            or profile.get("carrier_mode") != "https"
            or not isinstance(profile.get("secret"), str)
            or not re.fullmatch(r"[a-f0-9]{32}", profile["secret"])):
        raise RuntimeError("unexpected_profiles")
    return profile


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
        raise RuntimeError("http_redirect_refused")


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def _http(opener, url: str, method: str, body: bytes | None, headers: dict,
          timeout: float, maximum: int) -> tuple[int, dict, bytes]:
    # An empty byte body makes urllib synthesize a form Content-Type. The WEB
    # downlink contract requires no Content-Type, so keep empty requests bodyless.
    request = urllib.request.Request(url, data=body or None, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(maximum + 1)
        if len(raw) > maximum:
            raise RuntimeError("response_too_large")
        return response.status, {key.lower(): value for key, value in response.headers.items()}, raw


def _admin_ready() -> bool:
    status, _, body = _http(_opener(), f"http://127.0.0.1:{ADMIN_PORT}/readyz",
                            "GET", None, {}, 2, 1024)
    return status == 200 and body == b"ready\n"


def snapshot() -> dict:
    """GET-safe: no profile/secret reads, credential-bearing probes or mutation."""
    result = {"installed": False, "managed": False, "service": _service_state(),
              "public_host": PUBLIC_HOST, "public_port": PUBLIC_PORT,
              "relay_port": RELAY_PORT, "admin_port": ADMIN_PORT,
              "loopback_only": True, "runtime_ready": None,
              "protocol_health": dict(_LAST_PROBE)}
    try:
        manifest, _ = _configuration()
    except FileNotFoundError:
        result["status"] = "not_installed"
        return result
    except Exception:
        result["status"] = "configuration_unavailable"
        return result
    result.update(installed=True, managed=True, config_valid=True,
                  status=result["service"], base_path=manifest["base_path"],
                  carrier_mode=manifest["carrier_mode"], created_at=manifest["created_at"],
                  commit=COMMIT)
    if result["service"] == "active":
        try:
            result["runtime_ready"] = _admin_ready()
        except Exception:
            result["runtime_ready"] = False
    return result


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def owner_connection_links() -> dict:
    """Credential-bearing result: explicit owner POST/CSRF check required upstream.

    Import formats follow the pinned BASE_PATH.md. They require a compatible
    Telegram client; a link alone does not guarantee client-side activation.
    """
    manifest, _ = _configuration()
    proof = _LAST_PROBE
    now = int(time.time())
    if (proof.get("ok") is not True or proof.get("tls_confirmed") is not True
            or proof.get("telegram_nonce_confirmed") is not True
            or proof.get("endpoint") != "public_https"
            or type(proof.get("checked_at")) is not int
            or not 0 <= now - proof["checked_at"] <= 300):
        raise RuntimeError("public_protocol_not_confirmed")
    profile = _profile()
    query = urllib.parse.urlencode({"server": PUBLIC_HOST + "/" + manifest["base_path"],
                                    "secret": _b64(b"\x70" + bytes.fromhex(profile["secret"]))})
    return {"telegram": "tg://webproxy?" + query, "https": "https://t.me/webproxy?" + query}


def control(action: str) -> dict:
    """Only after owner, CSRF and confirmation validation by the panel."""
    global _LAST_PROBE
    if action not in ("start", "stop", "restart"):
        raise ValueError("unsupported_webproxy_action")
    _configuration()
    try:
        result = subprocess.run(["systemctl", action, SERVICE], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
        ok = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    if ok:
        _LAST_PROBE = {"ok": None, "status": "not_checked"}
    return {"ok": ok, "action": action, "status": snapshot()}


def _capability(host: str, base_path: str, secret: str) -> str:
    context = "tdesktop-web-proxy-bridge-v2\n" + host + "\n" + base_path
    return _b64(hmac.new(bytes.fromhex(secret), context.encode("ascii"), hashlib.sha256).digest())


def _token(value: str) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return False
    try:
        return _b64(base64.urlsafe_b64decode(value + "=")) == value
    except (ValueError, TypeError):
        return False


def _bootstrap(body: bytes, base_url: str) -> str:
    # Parse the pinned HTML's data declaration, never eval or execute JavaScript.
    pattern = rb'const relayBase=("[^"\r\n]{1,256}"),bootstrap=("[A-Za-z0-9_-]{43}"),carrierMode=("[a-z-]{1,32}");'
    matches = list(re.finditer(pattern, body))
    if len(matches) != 1:
        raise RuntimeError("bridge_contract_invalid")
    relay, token, mode = (json.loads(item) for item in matches[0].groups())
    if relay != base_url or not _token(token):
        raise RuntimeError("bridge_contract_invalid")
    if mode != "https":
        raise RuntimeError("unsupported_carrier")
    return token


def _frame(kind: int, stream: int, body: bytes = b"") -> bytes:
    return bytes((kind,)) + stream.to_bytes(3, "big") + struct.pack(">I", len(body)) + body


def _frames(body: bytes) -> list[tuple[int, int, bytes]]:
    result, offset = [], 0
    while offset < len(body):
        if len(body) - offset < 8 or len(result) >= 128:
            raise RuntimeError("frame_invalid")
        kind, stream = body[offset], int.from_bytes(body[offset + 1:offset + 4], "big")
        size = struct.unpack_from(">I", body, offset + 4)[0]
        if size > 4096 or offset + 8 + size > len(body):
            raise RuntimeError("frame_invalid")
        payload = body[offset + 8:offset + 8 + size]
        if not ((kind == 2 and stream == 1 and size > 0)
                or (kind == 3 and stream == 1 and size == 0)
                or (kind == 4 and stream == 1 and size == 4 and int.from_bytes(payload, "big") > 0)
                or (kind in (5, 0x1f) and stream == 0 and size <= 64)):
            raise RuntimeError("frame_invalid")
        result.append((kind, stream, payload))
        offset += 8 + size
    if not result:
        raise RuntimeError("frame_invalid")
    return result


def _mtproto_helper():
    # Reuse only our installed, checksum-verified helper, not third-party code.
    path = Path("/opt/quantumvpn-mtproto/quantumvpn_mtproto.py")
    config = json.loads(_read_file(Path("/etc/quantumvpn-mtproto/config.json"), 8192, private=True))
    source = _read_file(path, 131072)
    if (not isinstance(config, dict) or config.get("managed_by") != "quantumvpn"
            or config.get("commit") != "f36d8af769ffaeac36978d38c2c0f6d1104c2137"
            or hashlib.sha256(source).hexdigest() != config.get("module_sha256")):
        raise RuntimeError("mtproto_helper_unavailable")
    module = types.ModuleType("_quantumvpn_web_mtproto")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def _crypto_available() -> None:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
    except ImportError:
        # No openssl subprocess with derived secret material in its argv.
        raise RuntimeError("crypto_unavailable") from None


def _probe(manifest: dict, secret: str, *, public: bool = True) -> dict:
    started = time.monotonic()
    result = {"ok": False, "status": "protocol_failed", "method": "web_mtproto_req_pq_multi",
              "checked_at": int(time.time()), "tls_confirmed": False,
              "bridge_confirmed": False, "session_confirmed": False,
              "telegram_nonce_confirmed": False, "account_authorization_tested": False,
              "endpoint": "public_https" if public else "loopback"}
    session, opener, base_url = "", None, ""
    try:
        _validate_manifest(manifest)
        if not isinstance(secret, str) or not re.fullmatch(r"[a-f0-9]{32}", secret):
            raise RuntimeError("configuration_unavailable")
        _crypto_available()
        mtproto = _mtproto_helper()
        opener = _opener()
        base_url = "https://" + PUBLIC_HOST + "/" + manifest["base_path"] + "/"
        transport_url = base_url if public else f"http://127.0.0.1:{RELAY_PORT}/" + manifest["base_path"] + "/"
        deadline = started + MAX_PROBE_SECONDS

        def request(path, method="POST", body=b"", headers=None, maximum=65536):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("protocol_deadline")
            values = {"Accept": "application/octet-stream", "Cache-Control": "no-store"}
            if not public:
                values["Host"] = PUBLIC_HOST
            if session:
                values["Authorization"] = "Bearer " + session
            if body:
                values["Content-Type"] = "application/octet-stream"
            values.update(headers or {})
            return _http(opener, transport_url + path, method, body, values, min(remaining, 8), maximum)

        capability = _capability(PUBLIC_HOST, manifest["base_path"], secret)
        status, headers, body = request("?bridge=" + capability, "GET", None, maximum=131072)
        result["tls_confirmed"] = public  # Default trust store + exact HTTPS URL, no redirects.
        if status != 200 or not headers.get("content-type", "").lower().startswith("text/html"):
            raise RuntimeError("bridge_unavailable")
        bootstrap = _bootstrap(body, base_url)
        result["bridge_confirmed"] = True
        status, headers, body = request("api/v1/session", body=_frame(0x10, 0, b"\x01"),
                                        headers={"Authorization": "Bearer " + bootstrap}, maximum=64)
        if status != 200:
            raise RuntimeError("session_rejected")
        candidate = headers.get("x-session-token", "")
        # Save a well-formed token before validating remaining response so our
        # session is closed even if a subsequent contract check fails.
        if _token(candidate):
            session = candidate
        if (not session or headers.get("x-down-cursor") != "0"
                or headers.get("x-carrier-mode") != "https" or body != _frame(0x11, 0)):
            raise RuntimeError("session_contract_invalid")
        result["session_confirmed"] = True
        wire, key, iv, nonce = mtproto._request(secret)
        seq = 1

        def up(payload):
            nonlocal seq
            status, headers, body = request("api/v1/up", body=payload,
                                            headers={"X-Up-Seq": str(seq)}, maximum=1024)
            if status != 204 or headers.get("x-up-ack") != str(seq) or body:
                raise RuntimeError("uplink_rejected")
            seq += 1

        up(_frame(1, 1) + _frame(2, 1, wire))
        encrypted, cursor = bytearray(), 0
        for _ in range(12):
            status, headers, body = request("api/v1/down", headers={"X-Down-Cursor": str(cursor)})
            if status not in (200, 204):
                raise RuntimeError("downlink_rejected")
            next_cursor = headers.get("x-down-cursor", "")
            if not re.fullmatch(r"0|[1-9][0-9]{0,15}", next_cursor):
                raise RuntimeError("cursor_invalid")
            if status == 204:
                if body or int(next_cursor) != cursor:
                    raise RuntimeError("cursor_invalid")
                continue
            if int(next_cursor) != cursor + 1:
                raise RuntimeError("cursor_invalid")
            cursor = int(next_cursor)
            for kind, _, payload in _frames(body):
                if kind == 2:
                    encrypted.extend(payload)
                    if len(encrypted) > 8192:
                        raise RuntimeError("response_too_large")
                elif kind == 3:
                    raise RuntimeError("stream_closed")
                elif kind == 0x1f:
                    raise RuntimeError("relay_closed")
                elif kind == 5:
                    up(_frame(6, 0, payload))
            if len(encrypted) >= 4:
                plain = mtproto._aes_ctr(bytes(encrypted), key, iv)
                size = struct.unpack_from("<I", plain)[0]
                if not 56 <= size <= 4096:
                    raise RuntimeError("invalid_mtproto_frame_length")
                if len(plain) >= size + 4:
                    mtproto._validate_response(plain[4:4 + size], nonce)
                    result.update(ok=True, status="protocol_confirmed", telegram_nonce_confirmed=True,
                                  latency_ms=round((time.monotonic() - started) * 1000))
                    break
        else:
            raise RuntimeError("protocol_deadline")
    except Exception as error:
        code = str(error) if isinstance(error, RuntimeError) else ""
        if isinstance(error, (ssl.SSLError, ssl.CertificateError)):
            code = "public_tls_failed"
        elif isinstance(error, urllib.error.URLError) and isinstance(error.reason, ssl.SSLError):
            code = "public_tls_failed"
        result["failure_code"] = code if code in _FAILURES else "bounded_transport_failure"
    finally:
        if session and opener and base_url:
            # Delete only the disposable session this probe created. Never touch
            # real clients or emit URL, bearer, exception or body to logs.
            try:
                values = {"Authorization": "Bearer " + session}
                if not public:
                    values["Host"] = PUBLIC_HOST
                status, _, _ = _http(opener, transport_url + "api/v1/session", "DELETE", b"",
                                      values, 2, 1024)
                result["probe_session_closed"] = status in (200, 204, 404)
            except Exception:
                result["probe_session_closed"] = False
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def health_probe() -> dict:
    """Explicit owner action: bounded real public WEB carrier/nonce proof."""
    global _LAST_PROBE
    try:
        manifest, _ = _configuration()
        result = _probe(manifest, _profile()["secret"])
    except Exception:
        result = {"ok": False, "status": "configuration_unavailable",
                  "failure_code": "configuration_unavailable", "checked_at": int(time.time())}
    _LAST_PROBE = dict(result)
    return result


def private_health_probe() -> dict:
    """Installer-only fixed loopback proof: does not assert public TLS reachability."""
    try:
        manifest, _ = _configuration()
        return _probe(manifest, _profile()["secret"], public=False)
    except Exception:
        return {"ok": False, "status": "configuration_unavailable", "endpoint": "loopback",
                "tls_confirmed": False, "failure_code": "configuration_unavailable",
                "checked_at": int(time.time())}


def _write_runtime_key(value: bytes) -> None:
    if len(value) != 32:
        raise RuntimeError("invalid_token_key")
    fd = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "token.key.pending"
    created = False
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("unsafe_runtime_directory")
        try:
            old = os.stat("token.key", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None and (not stat.S_ISREG(old.st_mode) or old.st_uid != os.geteuid()
                                or stat.S_IMODE(old.st_mode) != 0o400):
            raise RuntimeError("unsafe_runtime_token")
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd)
        created = True
        os.fchmod(out, 0o400)
        with os.fdopen(out, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, "token.key", src_dir_fd=fd, dst_dir_fd=fd)
        created = False
        os.fsync(fd)
    finally:
        if created:
            os.unlink(temporary, dir_fd=fd)
        os.close(fd)


def serve() -> None:
    """Fixed systemd launcher; credentials never appear in process arguments."""
    credentials = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    if (not credentials.is_absolute() or credentials.parent != Path("/run/credentials")
            or credentials.name != SERVICE):
        raise RuntimeError("systemd_credentials_required")
    manifest = _validate_manifest(json.loads(_read_file(credentials / "manifest.json", 16384, credential=True)))
    _validate_runtime(json.loads(_read_file(credentials / "config.json", 16384, credential=True)), manifest)
    binary = ROOT / "tproxy-server"
    if hashlib.sha256(_read_file(binary, 100 * 1024 * 1024)).hexdigest() != manifest["binary_sha256"]:
        raise RuntimeError("binary_identity_mismatch")
    if hashlib.sha256(_read_file(ROOT / "quantumvpn_webproxy.py", 131072)).hexdigest() != manifest["helper_sha256"]:
        raise RuntimeError("helper_identity_mismatch")
    _write_runtime_key(_read_file(credentials / "token.key", 32, credential=True))
    os.execv(str(binary), [str(binary), "-config", str(credentials / "config.json"),
                           "-profiles-file", str(credentials / "profiles.json")])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--probe-local", action="store_true")
    options = parser.parse_args()
    if options.serve:
        serve()
    else:
        value = private_health_probe() if options.probe_local else health_probe() if options.probe else snapshot()
        print(json.dumps(value, separators=(",", ":")))


if __name__ == "__main__":
    main()
