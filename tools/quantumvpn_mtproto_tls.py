"""Independent official MTProxy FakeTLS endpoint; no credentials in GET status.

The padded 3443 service and WEB HTTPS 443 relay are never reconfigured here.
Only explicit owner actions control this separate, fixed TLS service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request

try:
    import quantumvpn_mtproto as base
    import quantumvpn_mtproto_tls_protocol as protocol
except ModuleNotFoundError as error:
    if error.name not in ("quantumvpn_mtproto", "quantumvpn_mtproto_tls_protocol"):
        raise
    from tools import quantumvpn_mtproto as base
    from tools import quantumvpn_mtproto_tls_protocol as protocol

COMMIT = base.COMMIT
BASE_SOURCE_SHA256 = base.BASE_SOURCE_SHA256
BASE_MODULE_SHA256 = "8cb2724840d0c912912e875c92e13fb28ed0ae75404aaa296f8f12f23ba92810"
SECURITY_PATCH = "systemd-secret-file-tls-v1"
SECURITY_PATCH_SHA256 = "04762e7126ca87a151ded7be645ded6408060607257e53f2ff8d2b0c9816c473"
SERVICE = "quantumvpn-mtproto-tls.service"
ROOT = Path("/opt/quantumvpn-mtproto-tls")
PRIVATE = Path("/etc/quantumvpn-mtproto-tls")
CONFIG = PRIVATE / "config.json"
SECRET = PRIVATE / "client-secret"
PUBLIC_HOST = "150.241.96.191"
DOMAIN = "pecaocek.ignorelist.com"
PUBLIC_PORT = 5443
STATS_PORT = 18889
_LAST_PROBE = {"ok": None, "status": "not_checked"}


def _validate_config(value: dict) -> dict:
    if (not isinstance(value, dict) or type(value.get("schema")) is not int
            or value["schema"] != 1 or value.get("managed_by") != "quantumvpn"):
        raise RuntimeError("unmanaged_configuration")
    fixed = {"commit": COMMIT, "security_patch": SECURITY_PATCH,
             "patch_sha256": SECURITY_PATCH_SHA256,
             "source_file_sha256": BASE_SOURCE_SHA256,
             "base_module_sha256": BASE_MODULE_SHA256,
             "server": PUBLIC_HOST, "domain": DOMAIN}
    if any(value.get(key) != expected for key, expected in fixed.items()):
        raise RuntimeError("unexpected_tls_configuration")
    for key, expected in (("port", PUBLIC_PORT), ("stats_port", STATS_PORT), ("workers", 0)):
        if type(value.get(key)) is not int or value[key] != expected:
            raise RuntimeError("unexpected_tls_configuration")
    for key in ("binary_sha256", "module_sha256", "protocol_sha256", "base_module_sha256"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", value[key]):
            raise RuntimeError("invalid_runtime_identity")
    if type(value.get("created_at")) is not int or not 0 <= value["created_at"] < 1 << 53:
        raise RuntimeError("invalid_install_timestamp")
    return value


def _private_parent_guard() -> None:
    for directory in (PRIVATE.parent, PRIVATE):
        if not directory.exists() and not directory.is_symlink():
            raise FileNotFoundError("managed_private_directory_missing")
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("unsafe_private_directory")
        info = directory.stat()
        if os.name != "nt" and (info.st_uid != 0 or info.st_mode & (0o077 if directory == PRIVATE else 0o022)):
            raise RuntimeError("unsafe_private_directory")


def _config() -> dict:
    _private_parent_guard()
    return _validate_config(json.loads(base._read_bytes(CONFIG, 8192, private=True)))


def _secret() -> str:
    _private_parent_guard()
    value = base._read_bytes(SECRET, 64, private=True).decode("ascii")
    if not re.fullmatch(r"[a-f0-9]{32}\n", value):
        raise RuntimeError("invalid_local_secret")
    return value.strip()


def _verify_runtime(config: dict) -> None:
    if ROOT.is_symlink() or not ROOT.is_dir():
        raise RuntimeError("unsafe_runtime_directory")
    info = ROOT.stat()
    if os.name != "nt" and (info.st_uid != 0 or info.st_mode & 0o022):
        raise RuntimeError("unsafe_runtime_directory")
    files = (("mtproto-proxy", "binary_sha256", 100 * 1024 * 1024),
             ("quantumvpn_mtproto_tls.py", "module_sha256", 1024 * 1024),
             ("quantumvpn_mtproto_tls_protocol.py", "protocol_sha256", 1024 * 1024),
             ("quantumvpn_mtproto.py", "base_module_sha256", 1024 * 1024),
             ("security-patch.json", "patch_sha256", 65536))
    for filename, key, maximum in files:
        if hashlib.sha256(base._read_bytes(ROOT / filename, maximum)).hexdigest() != config[key]:
            raise RuntimeError("runtime_identity_mismatch")


def _service_state() -> str:
    try:
        result = subprocess.run(["systemctl", "is-active", SERVICE], capture_output=True,
                                text=True, timeout=3, check=False)
        state = result.stdout.strip()
        return state if state in ("active", "inactive", "failed", "activating", "deactivating") else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _stats() -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), base._NoRedirect())
    with opener.open(f"http://127.0.0.1:{STATS_PORT}/stats", timeout=2) as response:
        if response.status != 200:
            raise RuntimeError("stats_unavailable")
        data = response.read(131073)
    if len(data) > 131072:
        raise RuntimeError("stats_too_large")
    result = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in base._STATS_KEYS and re.fullmatch(r"[0-9]{1,18}", fields[1]):
            result[fields[0]] = int(fields[1])
    return result


def snapshot() -> dict:
    result = {"installed": False, "service": _service_state(), "port": PUBLIC_PORT,
              "server": PUBLIC_HOST, "domain": DOMAIN, "transport": "mtproto_native_fake_tls",
              "stats_loopback_only": True, "protocol_health": dict(_LAST_PROBE)}
    try:
        config = _config()
        _verify_runtime(config)
    except FileNotFoundError:
        result["status"] = "not_installed"
        return result
    except Exception:
        result["status"] = "configuration_unavailable"
        return result
    result.update(installed=True, status=result["service"], commit=COMMIT,
                  security_patch=SECURITY_PATCH, created_at=config["created_at"])
    if result["service"] == "active":
        try:
            result["stats"] = _stats()
            result["upstream_ready"] = result["stats"].get("total_ready_targets", 0) > 0
        except Exception:
            result["stats"] = {}
            result["upstream_ready"] = None
    return result


def health_probe() -> dict:
    global _LAST_PROBE
    try:
        config = _config()
        _verify_runtime(config)
        result = protocol.probe(_secret(), "127.0.0.1", PUBLIC_PORT, DOMAIN)
    except Exception:
        result = {"ok": False, "status": "configuration_unavailable",
                  "method": "mtproto_fake_tls_req_pq_multi", "checked_at": int(time.time())}
    _LAST_PROBE = dict(result)
    return result


def external_health_probe(secret: str) -> dict:
    return protocol.probe(secret, PUBLIC_HOST, PUBLIC_PORT, DOMAIN)


def owner_connection_links() -> dict:
    """Explicit owner POST only; never called from status or ordinary GET."""
    config = _config()
    _verify_runtime(config)
    if _service_state() != "active":
        raise RuntimeError("tls_proxy_not_active")
    proof = health_probe()
    if proof.get("ok") is not True:
        raise RuntimeError("tls_protocol_not_confirmed")
    secret = "ee" + _secret() + DOMAIN.encode("ascii").hex()
    query = urllib.parse.urlencode({"server": config["server"], "port": PUBLIC_PORT, "secret": secret})
    return {"telegram": "tg://proxy?" + query, "https": "https://t.me/proxy?" + query}


def control(action: str) -> dict:
    if action not in ("start", "stop", "restart"):
        raise ValueError("unsupported_tls_proxy_action")
    _verify_runtime(_config())
    try:
        result = subprocess.run(["systemctl", action, SERVICE], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=30, check=False)
        ok = result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    return {"ok": ok, "action": action, "status": snapshot()}


def serve() -> None:
    credentials = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    if credentials != Path("/run/credentials") / SERVICE:
        raise RuntimeError("systemd_credentials_required")
    owner = os.geteuid()
    config = _validate_config(json.loads(base._read_bytes(credentials / "runtime-config", 8192,
                                                         owner=owner, credential=True)))
    raw = base._read_bytes(credentials / "client-secret", 64, owner=owner, credential=True)
    if not re.fullmatch(rb"[a-f0-9]{32}\n", raw):
        raise RuntimeError("invalid_local_secret")
    _verify_runtime(config)
    binary = ROOT / "mtproto-proxy"
    args = [str(binary), "-p", str(STATS_PORT), "-H", str(PUBLIC_PORT),
            "--secret-file", str(credentials / "client-secret"),
            "--aes-pwd", str(credentials / "proxy-secret"), str(credentials / "proxy-config"),
            "-D", DOMAIN, "-M", "0", "-C", "2048", "-c", "4096", "--http-stats"]
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
