"""Bounded VDS-local VLESS Vision regression, with no SSH or file writes.

Run on the already authorized VDS, or import and call probe(server_name=...).
The SNI must be the already verified legacy VPN certificate hostname. UUIDs
are read from the existing protected server configuration into memory only.
This tests the host OUTPUT path, not external PREROUTING or Android routing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import time
import uuid


BINARY = "/var/lib/rospanel/bin/xray"
SERVER_CONFIG = "/var/lib/rospanel/xray/config.json"
PUBLIC_IPV4 = "150.241.96.191"
SOCKS_PORT = 18991
URL = "https://example.com/"
BODY_LIMIT = 65536
HEADER_LIMIT = 8192
SOURCE_URLS = (
    "https://xtls.github.io/en/document/command.html",
    "https://xtls.github.io/en/config/outbounds/vless.html",
    "https://xtls.github.io/en/config/inbounds/socks.html",
    "https://xtls.github.io/en/config/log.html",
    "https://raw.githubusercontent.com/XTLS/Xray-core/v25.3.6/infra/conf/vless.go",
)


class ProbeError(RuntimeError):
    """A fixed, nonsensitive diagnostic code, never raw process output."""


def client_config(client_id: str, server_name: str) -> dict:
    identifier = str(uuid.UUID(client_id))
    if (not isinstance(server_name, str) or len(server_name) > 253
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", server_name)
            or "." not in server_name or ".." in server_name
            or server_name.lower() == "safehop.crabdance.com"):
        raise ProbeError("verified_legacy_sni_required")
    return {
        "log": {"access": "none", "error": "none", "loglevel": "none", "dnsLog": False},
        "inbounds": [{"listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}, "tag": "probe-socks"}],
        "outbounds": [{"protocol": "vless", "tag": "probe-vless", "settings": {
            "vnext": [{"address": PUBLIC_IPV4, "port": 443, "users": [{
                "id": identifier, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                "serverName": server_name, "allowInsecure": False, "fingerprint": "chrome"}},
            "mux": {"enabled": False}}],
    }


def vision_client(server: dict) -> str:
    for inbound in server.get("inbounds", []):
        stream = inbound.get("streamSettings", {})
        if (inbound.get("protocol") != "vless" or inbound.get("port") != 18443
                or inbound.get("listen") != "127.0.0.1" or stream.get("security") != "tls"
                or stream.get("network", "tcp") not in ("tcp", "raw")):
            continue
        for client in inbound.get("settings", {}).get("clients", []):
            if client.get("flow") == "xtls-rprx-vision" and not client.get("reverse"):
                try:
                    return str(uuid.UUID(client["id"]))
                except (ValueError, TypeError, AttributeError, KeyError):
                    continue
    raise ProbeError("existing_vision_client_unavailable")


def _protected_read(path: str, maximum: int) -> bytes:
    item = Path(path)
    info = item.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or info.st_size > maximum):
        raise ProbeError("protected_file_required")
    return item.read_bytes()


def _stop_owned(process) -> bool:
    if process is None:
        return True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    return process.poll() is not None


def _owns_listener(pid: int) -> bool:
    try:
        inodes = {item.readlink().as_posix() for item in Path(f"/proc/{pid}/fd").iterdir()}
        for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if (fields[1] == f"0100007F:{SOCKS_PORT:04X}" and fields[3] == "0A"
                    and f"socket:[{fields[9]}]" in inodes):
                return True
    except (OSError, IndexError):
        pass
    return False


def _wait_listener(process) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ProbeError("temporary_client_exited")
        if _owns_listener(process.pid):
            return
        time.sleep(0.05)
    raise ProbeError("owned_socks_listener_unavailable")


def _curl_probe(environment: dict) -> dict:
    arguments = ["/usr/bin/curl", "--disable", "--silent", "--fail", "--proto", "=https",
                 "--tlsv1.2", "--http1.1", "--connect-timeout", "5", "--max-time", "10",
                 "--max-filesize", str(BODY_LIMIT), "--max-redirs", "0", "--noproxy", "",
                 "--proxy", f"socks5h://127.0.0.1:{SOCKS_PORT}", "--include", "--output", "-", URL]
    process = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
        headers = bytearray()
        while True:
            line = process.stdout.readline(HEADER_LIMIT + 1 - len(headers))
            headers.extend(line)
            if len(headers) > HEADER_LIMIT:
                raise ProbeError("probe_response_headers_too_large")
            if line in (b"\r\n", b"\n"):
                break
            if not line:
                raise ProbeError("probe_response_headers_missing")
        match = re.match(rb"HTTP/1\.[01] ([0-9]{3})(?: |\r?\n)", headers)
        body = process.stdout.read(BODY_LIMIT + 1)
        if len(body) > BODY_LIMIT:
            raise ProbeError("probe_response_body_too_large")
        code = process.wait(timeout=3)
        status = int(match.group(1)) if match else 0
        return {"success": code == 0 and status == 200 and bool(body), "curl_exit": code,
                "http_status": status, "body_bytes": len(body),
                "elapsed_seconds": round(time.monotonic() - started, 3)}
    finally:
        _stop_owned(process)
        if process is not None and process.stdout is not None:
            process.stdout.close()


def probe(*, server_name: str) -> dict:
    source = _protected_read(SERVER_CONFIG, 16777216)
    # Verify the unchanged existing binary, without loading private key files.
    _protected_read(BINARY, 268435456)
    payload = json.dumps(client_config(vision_client(json.loads(source)), server_name),
                         separators=(",", ":")).encode()
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    check = subprocess.run([BINARY, "run", "-test", "-config", "stdin:", "-format", "json"],
                           input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, env=environment)
    if check.returncode:
        raise ProbeError("temporary_client_config_rejected")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        try:
            reservation.bind(("127.0.0.1", SOCKS_PORT))
        except OSError as error:
            raise ProbeError("probe_port_in_use") from error
    process = None
    stopped = False
    try:
        process = subprocess.Popen([BINARY, "run", "-config", "stdin:", "-format", "json"],
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
        process.stdin.write(payload)
        process.stdin.close()  # stdin: needs EOF; do not leave Xray waiting.
        _wait_listener(process)
        result = _curl_probe(environment)
    finally:
        stopped = _stop_owned(process)
        if hashlib.sha256(_protected_read(SERVER_CONFIG, 16777216)).digest() != hashlib.sha256(source).digest():
            raise ProbeError("server_configuration_changed_during_probe")
    result.update({"client_config_validated": True, "temporary_client_stopped": stopped,
                   "vds_local_output_path_only": True, "server_configuration_unchanged": True})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-name", required=True, help="Already verified legacy VPN TLS hostname")
    options = parser.parse_args()
    try:
        result = probe(server_name=options.server_name)
    except ProbeError as error:
        result = {"success": False, "error_code": str(error)}
    except Exception:
        result = {"success": False, "error_code": "probe_execution_failed"}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
