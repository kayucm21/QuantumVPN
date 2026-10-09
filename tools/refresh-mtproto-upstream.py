"""Inspect or explicitly refresh only the owned, pinned Telegram MTProxy upstream.

Run on the Linux server as root. Without --apply this is read-only. Client keys,
runtime configuration, the binary, and other services are never changed. A
pending transaction is recovered on the next --apply; backups are kept private.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path("/opt/quantumvpn-mtproto")
PRIVATE = Path("/etc/quantumvpn-mtproto")
UNIT = Path("/etc/systemd/system/quantumvpn-mtproto.service")
SERVICE = "quantumvpn-mtproto.service"
BACKUPS = Path("/var/lib/quantumvpn-operator/mtproto-upstream-backups")
MODULE_SHA256 = "8cb2724840d0c912912e875c92e13fb28ed0ae75404aaa296f8f12f23ba92810"
UNIT_SHA256 = "a16be395ad5865c30064f9e714ec142f455dfbeb452865c990e38f0ed7a276b7"
UPSTREAM_FILES = ("proxy-secret", "proxy-multi.conf")
LIMITS = {"proxy-secret": 128, "proxy-multi.conf": 65536}
ENDPOINTS = {"proxy-secret": "getProxySecret", "proxy-multi.conf": "getProxyConfig"}


class Refused(RuntimeError):
    """All public error messages are fixed codes, never remote exception text."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _metadata(info, *, directory=False, mode=None):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022 or (not directory and info.st_nlink != 1)
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        raise Refused("unsafe_owned_path")


def _parents(path: Path):
    for parent in reversed(path.parents):
        _metadata(parent.lstat(), directory=True)


def directory(path: Path, mode=0o700):
    _parents(path)
    _metadata(path.lstat(), directory=True, mode=mode)


def read_file(path: Path, maximum: int, mode=0o600) -> bytes:
    _parents(path)
    if path.is_symlink():
        raise Refused("symlink_refused")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        _metadata(info, mode=mode)
        if not 0 < info.st_size <= maximum:
            raise Refused("owned_file_size_refused")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(maximum + 1)
        if len(value) != info.st_size or len(value) > maximum:
            raise Refused("owned_file_changed_during_read")
        return value
    finally:
        os.close(fd)


def _global_address(value: str):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise Refused("upstream_address_invalid") from None
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_unspecified or getattr(address, "ipv4_mapped", None) is not None):
        raise Refused("upstream_address_not_global")
    return address


def validate_secret(data: bytes):
    # Telegram's official upstream AES key file is 128 binary bytes.
    if len(data) != 128 or len(set(data)) < 16:
        raise Refused("upstream_secret_format_refused")


def validate_config(data: bytes) -> int:
    if not 32 <= len(data) <= LIMITS["proxy-multi.conf"]:
        raise Refused("upstream_config_size_refused")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise Refused("upstream_config_not_ascii") from None
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise Refused("upstream_config_control_character")
    default = None
    targets = set()
    for line in text.splitlines():
        if len(line) > 512:
            raise Refused("upstream_config_line_too_long")
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"default\s+([1-9][0-9]{0,2});", line)
        if match:
            if default is not None:
                raise Refused("upstream_config_duplicate_default")
            default = int(match[1])
            continue
        match = re.fullmatch(r"proxy_for\s+(-?[1-9][0-9]{0,2})\s+(\[[0-9a-fA-F:]+\]|[0-9.]+):([1-9][0-9]{0,4});", line)
        if not match:
            raise Refused("upstream_config_directive_refused")
        dc, raw_address, port = int(match[1]), match[2], int(match[3])
        address = _global_address(raw_address.strip("[]"))
        if (port > 65535 or (address.version == 6) != raw_address.startswith("[")
                or str(address) != raw_address.strip("[]").lower()):
            raise Refused("upstream_endpoint_invalid")
        target = (dc, str(address), port)
        if target in targets or len(targets) >= 256:
            raise Refused("upstream_config_duplicate_or_excess_targets")
        targets.add(target)
    if default is None or not any(dc == default for dc, _, _ in targets) or not any(dc == 2 for dc, _, _ in targets):
        raise Refused("upstream_config_required_dc_missing")
    return len(targets)


def validate_upstream(values: dict) -> int:
    validate_secret(values["proxy-secret"])
    return validate_config(values["proxy-multi.conf"])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("official_redirect_refused")


def fetch_official(name: str) -> bytes:
    if name not in ENDPOINTS:
        raise Refused("official_endpoint_refused")
    url = "https://core.telegram.org/" + ENDPOINTS[name]
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "QuantumVPN-MTProxy-refresh",
                                                  "Accept-Encoding": "identity"})
    try:
        with opener.open(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != url:
                raise Refused("official_response_refused")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise Refused("official_encoding_refused")
            data = response.read(LIMITS[name] + 1)
        if not 1 <= len(data) <= LIMITS[name]:
            raise Refused("official_download_size_refused")
    except Refused:
        raise
    except Exception:
        raise Refused("official_download_failed") from None
    return data


def _command(args, timeout=10) -> str:
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        raise Refused("bounded_service_command_failed") from None
    if result.returncode:
        raise Refused("bounded_service_command_failed")
    return result.stdout


def verify_service():
    raw = _command(["systemctl", "show", SERVICE, "--no-pager",
                    "--property=ActiveState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,MainPID"])
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if (values.get("ActiveState") != "active" or values.get("FragmentPath") != str(UNIT)
            or values.get("DropInPaths") != "" or values.get("NeedDaemonReload") != "no"
            or values.get("User") != "qvpn-mtproto" or values.get("Group") != "qvpn-mtproto"
            or not re.fullmatch(r"[1-9][0-9]{0,9}", values.get("MainPID", ""))):
        raise Refused("owned_active_service_required")
    if (Path("/proc") / values["MainPID"] / "exe").resolve() != ROOT / "mtproto-proxy":
        raise Refused("running_binary_identity_mismatch")
    listeners = []
    for line in _command(["ss", "-H", "-ltn"]).splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].endswith(":18888"):
            listeners.append(fields[3])
    if listeners != ["127.0.0.1:18888"]:
        raise Refused("stats_listener_not_exclusively_loopback")


def owned_install() -> dict:
    directory(ROOT, 0o755)
    directory(PRIVATE)
    helper = read_file(ROOT / "quantumvpn_mtproto.py", 65536, 0o644)
    unit = read_file(UNIT, 8192, 0o644)
    if sha256(helper) != MODULE_SHA256 or sha256(unit) != UNIT_SHA256:
        raise Refused("pinned_helper_or_unit_mismatch")
    module = {"__name__": "quantumvpn_mtproto_refresh_helpers"}
    exec(compile(helper, "<pinned-mtproto-helper>", "exec"), module)
    config_bytes = read_file(PRIVATE / "config.json", 8192)
    config = module["_validate_config"](json.loads(config_bytes))
    client = read_file(PRIVATE / "client-secret", 33)
    if not re.fullmatch(rb"[a-f0-9]{32}\n", client):
        raise Refused("client_secret_format_refused")
    fixed = {"config.json": sha256(config_bytes), "client-secret": sha256(client),
             "quantumvpn_mtproto.py": sha256(helper), "service-unit": sha256(unit)}
    for name, maximum, expected in (("mtproto-proxy", 100 * 1024 * 1024, config["binary_sha256"]),
                                    ("security-patch.json", 8192, config["patch_sha256"]),
                                    ("mtproto-proxy-base.c", 1024 * 1024, config["source_file_sha256"])):
        value = read_file(ROOT / name, maximum, 0o755 if name == "mtproto-proxy" else 0o644)
        if sha256(value) != expected:
            raise Refused("pinned_install_identity_mismatch")
        fixed[name] = sha256(value)
    if config["module_sha256"] != MODULE_SHA256:
        raise Refused("configuration_helper_identity_mismatch")
    upstream = {name: read_file(PRIVATE / name, LIMITS[name]) for name in UPSTREAM_FILES}
    validate_upstream(upstream)
    return {"module": module, "fixed": fixed, "upstream": upstream}


def assert_install(original):
    if owned_install()["fixed"] != original["fixed"]:
        raise Refused("immutable_install_changed")


def proof(module) -> dict:
    # Never use the helper's openssl subprocess fallback: derived AES keys would
    # appear in argv. All crypto in this updater must remain in this process.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise Refused("in_process_crypto_required") from None

    def aes(data, key, iv):
        if len(data) > 65536:
            raise Refused("protocol_frame_too_large")
        transform = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return transform.update(data) + transform.finalize()

    module["_aes_ctr"] = aes
    value = module["health_probe"]()
    if value.get("ok") is not True or value.get("method") != "mtproto_req_pq_multi" or value.get("status") != "protocol_confirmed":
        raise Refused("genuine_loopback_nonce_not_confirmed")
    stats = module["_stats"]()
    count = stats.get("total_ready_targets")
    if type(count) is not int or count <= 0:
        raise Refused("upstream_targets_not_ready")
    return {"ok": True, "method": "mtproto_req_pq_multi", "upstream_ready_count": count}


def _sync_dir(path: Path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes):
    directory(path.parent)
    if path.exists() or path.is_symlink():
        read_file(path, max(len(data), 65536))
    fd, name = tempfile.mkstemp(prefix=".upstream-", dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
        _sync_dir(path.parent)
    finally:
        if staged.exists():
            staged.unlink()


def _private_store():
    for path in (BACKUPS.parent, BACKUPS):
        _parents(path)
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700)
            _sync_dir(path.parent)
        directory(path, 0o700 if path == BACKUPS else None)


@contextmanager
def refresh_lock():
    import fcntl

    _private_store()
    fd = os.open(BACKUPS / ".refresh.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        _metadata(os.fstat(fd), mode=0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Refused("another_refresh_in_progress") from None
        yield
    finally:
        os.close(fd)


def _journal_write(journal):
    atomic_write(BACKUPS / "pending.json", (json.dumps(journal, sort_keys=True) + "\n").encode())


def _journal_read():
    path = BACKUPS / "pending.json"
    if not path.exists() and not path.is_symlink():
        return None
    directory(BACKUPS)
    try:
        value = json.loads(read_file(path, 8192))
    except (ValueError, UnicodeError):
        raise Refused("pending_journal_invalid") from None
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("phase") not in ("prepared", "applying")
            or not re.fullmatch(r"txn-[0-9]{14}-[a-f0-9]{16}", value.get("backup", ""))
            or not isinstance(value.get("fixed"), dict)):
        raise Refused("pending_journal_invalid")
    for key in ("old", "new"):
        values = value.get(key)
        if not isinstance(values, dict) or set(values) != set(UPSTREAM_FILES) or any(not isinstance(x, str) or not re.fullmatch(r"[a-f0-9]{64}", x) for x in values.values()):
            raise Refused("pending_journal_invalid")
    return value


def _journal_clear():
    # Only this exact root-owned transaction marker is removed; backups remain.
    read_file(BACKUPS / "pending.json", 8192)
    (BACKUPS / "pending.json").unlink()
    _sync_dir(BACKUPS)


def assert_upstream(expected):
    if any(read_file(PRIVATE / name, LIMITS[name]) != expected[name] for name in UPSTREAM_FILES):
        raise Refused("upstream_changed_concurrently")


def restart_and_verify(install, expected):
    _command(["systemctl", "restart", SERVICE], timeout=30)
    deadline = time.monotonic() + 40
    while True:
        try:
            assert_install(install)
            assert_upstream(expected)
            verify_service()
            return proof(install["module"])
        except Exception:
            if time.monotonic() >= deadline:
                raise Refused("post_restart_verification_failed") from None
            time.sleep(1)


def rollback(journal, install) -> dict:
    assert_install(install)
    if journal["fixed"] != install["fixed"]:
        raise Refused("recovery_install_identity_mismatch")
    backup = BACKUPS / journal["backup"]
    directory(backup)
    old = {name: read_file(backup / name, LIMITS[name]) for name in UPSTREAM_FILES}
    validate_upstream(old)
    current = {name: read_file(PRIVATE / name, LIMITS[name]) for name in UPSTREAM_FILES}
    if any(sha256(old[name]) != journal["old"][name] or sha256(current[name]) not in (journal["old"][name], journal["new"][name]) for name in UPSTREAM_FILES):
        raise Refused("recovery_file_identity_mismatch")
    changed = any(current[name] != old[name] for name in UPSTREAM_FILES)
    for name in UPSTREAM_FILES:
        if current[name] != old[name]:
            atomic_write(PRIVATE / name, old[name])
    health = restart_and_verify(install, old) if changed or journal["phase"] == "applying" else proof(install["module"])
    _journal_clear()
    return health


def inspect_or_refresh(apply=False) -> dict:
    install = owned_install()
    verify_service()
    pending = _journal_read()
    if pending and apply:
        health = rollback(pending, install)
        return {"status": "Recovered", "changed": True, "health": health, "backup": pending["backup"]}
    fresh = {name: fetch_official(name) for name in UPSTREAM_FILES}
    count = validate_upstream(fresh)
    changes = {name: fresh[name] != install["upstream"][name] for name in UPSTREAM_FILES}
    if not apply:
        return {"status": "ReadOnly", "changed": False, "would_change": any(changes.values()),
                "config_changed": changes["proxy-multi.conf"], "upstream_secret_changed": changes["proxy-secret"],
                "official_target_count": count, "pending_recovery": pending is not None}
    if pending:
        raise Refused("pending_recovery_required")
    if not any(changes.values()):
        return {"status": "Unchanged", "changed": False, "official_target_count": count}
    proof(install["module"])
    assert_install(install)
    verify_service()
    if owned_install()["upstream"] != install["upstream"]:
        raise Refused("upstream_changed_concurrently")
    name = "txn-" + time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + os.urandom(8).hex()
    backup = BACKUPS / name
    backup.mkdir(mode=0o700)
    _sync_dir(BACKUPS)
    for filename in UPSTREAM_FILES:
        atomic_write(backup / filename, install["upstream"][filename])
    journal = {"schema": 1, "backup": name, "phase": "prepared", "fixed": install["fixed"],
               "old": {key: sha256(value) for key, value in install["upstream"].items()},
               "new": {key: sha256(value) for key, value in fresh.items()}}
    _journal_write(journal)
    try:
        journal["phase"] = "applying"
        _journal_write(journal)
        for filename in UPSTREAM_FILES:
            if changes[filename]:
                atomic_write(PRIVATE / filename, fresh[filename])
        health = restart_and_verify(install, fresh)
        _journal_clear()
        return {"status": "Updated", "changed": True, "health": health, "backup": name,
                "official_target_count": count}
    except BaseException:
        # SIGKILL/power loss leaves the durable journal for the next --apply.
        try:
            rollback(journal, install)
        except BaseException:
            raise Refused("rollback_incomplete_pending_recovery_kept") from None
        raise Refused("refresh_failed_rolled_back") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Update only a verified active owned installation")
    args = parser.parse_args()
    try:
        if os.name != "posix" or os.geteuid() != 0:
            raise Refused("linux_root_required")

        def interrupted(*unused):
            raise Refused("refresh_interrupted")

        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(240)
        if args.apply:
            # Refuse uninstalled/stopped/unowned services before even creating
            # the private lock and backup directory, then recheck under lock.
            owned_install()
            verify_service()
            with refresh_lock():
                result = inspect_or_refresh(True)
        else:
            result = inspect_or_refresh()
        print(json.dumps(result, separators=(",", ":")))
    except Exception as error:
        code = str(error) if isinstance(error, Refused) and re.fullmatch(r"[a-z_]{1,96}", str(error)) else "bounded_refresh_failed"
        print(json.dumps({"status": "Failed", "reason": code}, separators=(",", ":")))
        raise SystemExit(1) from None
    finally:
        if os.name == "posix":
            signal.alarm(0)


if __name__ == "__main__":
    main()
