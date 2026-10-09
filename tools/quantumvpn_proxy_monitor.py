"""TTL-bounded observations of only the three owned Telegram proxy transports.

``snapshot`` is an in-memory, secret-free operation. Only explicit ``refresh``
performs the existing bounded protocol probes. WEB creates and closes its own
disposable probe session; real clients, services, keys and routes are untouched.
Server-to-Telegram nonce continuity is not account authorization, client-side
reachability without a VPN, throughput, or evidence of a particular blocker.
"""
from __future__ import annotations

import copy
import importlib
import math
import subprocess
import threading
import time


TTL_SECONDS = 300
_SERVICES = frozenset(("active", "inactive", "failed", "activating", "deactivating", "unknown"))
_TRANSPORTS = {
    "mtproto": ("quantumvpn_mtproto", "mtproto_req_pq_multi", (18888,)),
    "native_tls": ("quantumvpn_mtproto_tls", "mtproto_fake_tls_req_pq_multi", (18889,)),
    "web": ("quantumvpn_webproxy", "web_mtproto_req_pq_multi", (18082, 18083)),
}
_LOCK = threading.Lock()
_CACHE: dict = {}
_CACHE_TICK: float | None = None


def _cold(protocol: str, *, checked_at: int | None = None) -> dict:
    return {"service": "unknown", "checked_at": checked_at, "stage": "not_checked",
            "protocol": protocol, "ready": None, "isolation_verified": None}


def _fresh(tick: float) -> bool:
    return (_CACHE_TICK is not None and math.isfinite(tick)
            and 0 <= tick - _CACHE_TICK < TTL_SECONDS)


def snapshot() -> dict:
    """Never read files, run commands, import a runtime, or perform a probe."""
    if _fresh(time.monotonic()):
        return copy.deepcopy(_CACHE)
    return {name: _cold(values[1], checked_at=_CACHE.get(name, {}).get("checked_at"))
            for name, values in _TRANSPORTS.items()}


def _runtime(name: str):
    # Names come only from the fixed catalogue, never from AI or settings.
    module = _TRANSPORTS[name][0]
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as error:
        if error.name != module:
            raise
        return importlib.import_module("tools." + module)


def _listener_isolation() -> dict:
    """Verify private stats/admin/relay binds, not merely helper intent flags."""
    unknown = {name: None for name in _TRANSPORTS}
    try:
        result = subprocess.run(["ss", "-H", "-ltn"], capture_output=True,
                                text=True, timeout=3, check=False)
        if result.returncode or len(result.stdout) > 65536:
            return unknown
        listeners: dict[int, list[str]] = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            address, separator, port = fields[3].rpartition(":")
            if separator and port.isascii() and port.isdecimal() and len(port) <= 5:
                listeners.setdefault(int(port), []).append(address)
        return {name: all(listeners.get(port) and all(address in ("127.0.0.1", "[::1]", "::1")
                                                    for address in listeners[port])
                          for port in values[2])
                for name, values in _TRANSPORTS.items()}
    except Exception:
        # No stderr, exception text, socket addresses or process arguments leave
        # this adapter. Unknown is not proof of safe isolation or a network fault.
        return unknown


def _nonce(name: str, proof: dict) -> bool | None:
    if not isinstance(proof, dict):
        return None
    if proof.get("ok") is False:
        return False
    if proof.get("ok") is not True:
        return None
    if proof.get("method") != _TRANSPORTS[name][1] or proof.get("status") != "protocol_confirmed":
        return False
    if name == "mtproto":
        # The pinned padded helper sets success only after _validate_response
        # checks Telegram's resPQ nonce; it has no separate nonce flag.
        return True
    if name == "native_tls":
        return (proof.get("fake_tls_authenticated") is True
                and proof.get("telegram_nonce_confirmed") is True)
    return (proof.get("endpoint") == "public_https" and proof.get("tls_confirmed") is True
            and proof.get("bridge_confirmed") is True and proof.get("session_confirmed") is True
            and proof.get("telegram_nonce_confirmed") is True)


def _stage(name: str, proof: dict, nonce: bool | None) -> str:
    if nonce is True:
        return "telegram"
    if not isinstance(proof, dict) or nonce is None:
        return "not_checked"
    if name == "native_tls" and proof.get("fake_tls_authenticated") is True:
        return "tls"
    if name == "web":
        if proof.get("bridge_confirmed") is True:
            return "bridge"
        if proof.get("tls_confirmed") is True:
            return "tls"
    return "failed"


def _observe(name: str, isolation: bool | None) -> dict:
    result = _cold(_TRANSPORTS[name][1])
    result["isolation_verified"] = isolation
    try:
        runtime = _runtime(name)
        status = runtime.snapshot()
        if not isinstance(status, dict):
            return result
        state = status.get("service")
        result["service"] = state if isinstance(state, str) and state in _SERVICES else "unknown"
        result["checked_at"] = int(time.time())
        if status.get("installed") is False or result["service"] in ("inactive", "failed", "deactivating"):
            result.update(stage="failed", ready=False)
            return result
        if status.get("installed") is not True or result["service"] != "active":
            return result
        proof = runtime.health_probe()
        nonce = _nonce(name, proof)
        upstream = status.get("runtime_ready" if name == "web" else "upstream_ready")
        if type(upstream) is not bool:
            upstream = None
        result["stage"] = _stage(name, proof, nonce)
        result["ready"] = (False if nonce is False or upstream is False else
                           True if nonce is True and upstream is True else None)
        return result
    except Exception:
        # Never forward a helper exception, link, secret, bootstrap or raw body.
        return result


def refresh() -> dict:
    """At most one refresh per TTL; concurrent callers never wait on probes.

    Existing helper timeouts cap padded/native/WEB probes at 6/10/20 seconds.
    There is no caller-provided endpoint, port, secret, command or action.
    Failed observations are cached too, preventing a millisecond retry loop.
    """
    global _CACHE, _CACHE_TICK
    if _fresh(time.monotonic()) or not _LOCK.acquire(blocking=False):
        return snapshot()
    try:
        if _fresh(time.monotonic()):
            return snapshot()
        isolation = _listener_isolation()
        _CACHE = {name: _observe(name, isolation[name]) for name in _TRANSPORTS}
        _CACHE_TICK = time.monotonic()
        return snapshot()
    finally:
        _LOCK.release()


def advisory(value: dict | None = None) -> dict | None:
    """Static recommendation only: never switch clients, keys, ports or routes."""
    value = snapshot() if value is None else value
    if not isinstance(value, dict):
        return None
    native = value.get("mtproto")
    tls = value.get("native_tls")
    if (isinstance(native, dict) and native.get("ready") is False
            and isinstance(tls, dict) and tls.get("ready") is True):
        return {"code": "try_native_tls",
                "message": "Основной MTProto не подтвердился; проверенный резерв — Native TLS в панели.",
                "scope": "server_to_telegram_not_client", "account_authorization_tested": False}
    return None


def evidence_scope() -> dict:
    return {"scope": "server_to_telegram_not_client", "client_without_vpn_tested": False,
            "account_authorization_tested": False, "blocker_cause_proven": False,
            "ttl_seconds": TTL_SECONDS}
