"""Bounded, credential-in-memory proof for official MTProxy Native FakeTLS.

This is Telegram's shared-secret FakeTLS transport, not certificate-verified
HTTPS: authenticate the ClientHello/ServerHello HMAC and then require a real
Telegram resPQ with our req_pq_multi nonce. A TCP or TLS-looking reply is not
success. No account authorization is attempted.

Wire references (independent implementation, no copied source templates):
https://github.com/TelegramMessenger/MTProxy/blob/f36d8af769ffaeac36978d38c2c0f6d1104c2137/net/net-tcp-rpc-ext-server.c
https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/mtproto/details/mtproto_tls_socket.cpp

Opt-in iOS diagnostic profiles independently encode the observable structures:
https://github.com/TelegramMessenger/Telegram-iOS/blob/5145b9e/submodules/MtProtoKit/Sources/MTTcpConnection.m
https://github.com/TelegramMessenger/Telegram-iOS/blob/f1dd7a2dbd02cbbf513e75d5695d8d36d1cf5838/submodules/MtProtoKit/Sources/MTTcpConnection.m
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import socket
import struct
import time

try:
    import quantumvpn_mtproto as base
except ModuleNotFoundError as error:
    if error.name != "quantumvpn_mtproto":
        raise
    from tools import quantumvpn_mtproto as base


PUBLIC_HOST = "150.241.96.191"
DOMAIN = "pecaocek.ignorelist.com"
MANAGED_PORTS = frozenset((5443, 4433))
DEADLINE_SECONDS = 10
MAX_TLS_RECORD = 16384
MAX_MT_FRAME = 4096
CLIENT_RECORD_SIZE = 2878
IOS_LEGACY_BROKEN_SNI = "ios_12_2_broken_sni"
IOS_MODERN_SAFARI = "ios_modern_safari"
_CCS = b"\x14\x03\x03\x00\x01\x01"
_FAILURES = base._PROBE_FAILURE_CODES | frozenset((
    "unmanaged_probe_endpoint", "unmanaged_probe_port", "invalid_probe_domain",
    "invalid_client_hello", "invalid_tls_record", "tls_record_too_large",
    "invalid_server_hello", "server_hello_not_authenticated",
    "invalid_tls_application_record", "tls_record_budget_exceeded",
    "invalid_client_profile",
))


def _secret_bytes(secret: str) -> bytes:
    if not isinstance(secret, str) or not re.fullmatch(r"[a-f0-9]{32}", secret):
        raise RuntimeError("invalid_probe_secret")
    return bytes.fromhex(secret)


def _domain_bytes(domain: str) -> bytes:
    if not isinstance(domain, str) or not 3 <= len(domain) <= 253:
        raise RuntimeError("invalid_probe_domain")
    labels = domain.split(".")
    if (len(labels) < 2 or domain != domain.lower()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                   for part in labels) or labels[-1].isdigit()):
        raise RuntimeError("invalid_probe_domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain.encode("ascii")
    raise RuntimeError("invalid_probe_domain")


def _require_inprocess_crypto() -> None:
    # base._request/_aes_ctr share the existing wire implementation. Require
    # its Python AES backend before using either: its legacy openssl CLI
    # fallback must never receive derived keys via argv in this endpoint.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        if not all((Cipher, algorithms.AES, modes.CTR, X25519PrivateKey,
                    Encoding.Raw, PublicFormat.Raw)):
            raise ImportError
        # Exercise the backend before any credential-derived key is used.
        # A package import alone does not prove its native AES backend works.
        transform = Cipher(algorithms.AES(b"\0" * 32), modes.CTR(b"\0" * 16)).encryptor()
        if len(transform.update(b"\0" * 16) + transform.finalize()) != 16:
            raise ImportError
    except ImportError:
        raise RuntimeError("protocol_crypto_unavailable") from None


def _extension(kind: int, value: bytes) -> bytes:
    return struct.pack(">HH", kind, len(value)) + value


def build_client_hello(secret: str, domain: str = DOMAIN, *, timestamp: int | None = None,
                       client_profile: str = "standard") -> bytes:
    """A valid 517-byte TLS 1.3-shaped hello authenticated as Telegram FakeTLS.

    Random session/key share make replay-cache tokens fresh. The HMAC slot
    starts at byte 11; its last four bytes XOR the little-endian Unix time.
    Return wire bytes only to the caller; never log or persist them.
    """
    if client_profile != "standard":
        return build_ios_client_hello(secret, domain, profile=client_profile, timestamp=timestamp)
    key = _secret_bytes(secret)
    name = _domain_bytes(domain)
    _require_inprocess_crypto()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    stamp = int(time.time()) if timestamp is None else timestamp
    if type(stamp) is not int or not 0 <= stamp < (1 << 31):
        raise RuntimeError("invalid_client_hello")
    session = os.urandom(32)
    public_key = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # SNI, supported versions/groups, real X25519 key share, signatures and
    # ALPN use ordinary TLS structures; padding meets MTProxy's >=512 gate.
    server_name = b"\0" + struct.pack(">H", len(name)) + name
    extensions = _extension(0, struct.pack(">H", len(server_name)) + server_name)
    extensions += _extension(43, b"\x04\x03\x04\x03\x03")
    extensions += _extension(10, b"\x00\x02\x00\x1d")
    share = b"\x00\x1d\x00\x20" + public_key
    extensions += _extension(51, struct.pack(">H", len(share)) + share)
    signatures = b"\x04\x03\x08\x04\x08\x05\x08\x06"
    extensions += _extension(13, struct.pack(">H", len(signatures)) + signatures)
    alpn = b"\x02h2\x08http/1.1"
    extensions += _extension(16, struct.pack(">H", len(alpn)) + alpn)
    ciphers = b"\x13\x01\x13\x02\x13\x03"
    body = (b"\x03\x03" + b"\0" * 32 + b"\x20" + session
            + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00")
    padding = 517 - (5 + 4 + len(body) + 2 + len(extensions) + 4)
    if padding < 0:
        raise RuntimeError("invalid_client_hello")
    extensions += _extension(21, b"\0" * padding)
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    hello = bytearray(b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake)
    digest = bytearray(hmac.new(key, hello, hashlib.sha256).digest())
    digest[28:32] = struct.pack("<I", struct.unpack("<I", digest[28:32])[0] ^ stamp)
    hello[11:43] = digest
    if len(hello) != 517 or hello[43] != 32:
        raise RuntimeError("invalid_client_hello")
    return bytes(hello)


def build_ios_client_hello(secret: str, domain: str = DOMAIN, *,
                           profile: str = IOS_LEGACY_BROKEN_SNI,
                           timestamp: int | None = None) -> bytes:
    """Build a fresh authenticated iOS-shaped diagnostic hello, never log it.

    The legacy profile reproduces 5145b9e's length-placeholder error: the
    otherwise ordinary SNI body is inside a GREASE extension, with no SNI
    extension at all. It is intentionally malformed for strict SNI routing.
    The modern profile exercises the larger Safari hybrid key-share shape.
    Its ML-KEM public-key coefficients follow iOS's synthetic FakeTLS shape;
    no actual TLS or post-quantum session is negotiated by this transport.
    Neither profile changes the default Android-compatible health proof.
    """
    if profile not in (IOS_LEGACY_BROKEN_SNI, IOS_MODERN_SAFARI):
        raise RuntimeError("invalid_client_profile")
    key = _secret_bytes(secret)
    name = _domain_bytes(domain)
    _require_inprocess_crypto()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    stamp = int(time.time()) if timestamp is None else timestamp
    if type(stamp) is not int or not 0 <= stamp < (1 << 31):
        raise RuntimeError("invalid_client_hello")

    def public_key() -> bytes:
        return X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def vector(value: bytes) -> bytes:
        return struct.pack(">H", len(value)) + value

    def words(values) -> bytes:
        return b"".join(struct.pack(">H", value) for value in values)

    grease = [(value & 0xf0) | 0x0a for value in os.urandom(8)]
    for index in range(0, 8, 2):
        if grease[index] == grease[index + 1]:
            grease[index + 1] ^= 0x10
    grease = [value * 257 for value in grease]
    modern = profile == IOS_MODERN_SAFARI
    # Both iOS cipher-list variants are supported by the pinned server. Use
    # the full variant, with the modern Safari preference for AES-256 first.
    cipher_ids = ([0x1302, 0x1303, 0x1301] if modern else [0x1301, 0x1302, 0x1303])
    cipher_ids += [0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
                   0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c,
                   0x0035, 0x002f, 0xc008, 0xc012, 0x000a]
    ciphers = words([grease[0]] + cipher_ids)
    name_body = vector(b"\0" + vector(name))
    if modern:
        extensions = _extension(grease[2], b"") + _extension(0, name_body)
    else:
        # This is the exact resulting structure, independently encoded from
        # TLS fields rather than executing or copying iOS's source template.
        extensions = _extension(grease[2], name_body)
    extensions += _extension(23, b"") + _extension(0xff01, b"\0")
    groups = [grease[4]] + ([0x11ec] if modern else []) + [0x001d, 0x0017, 0x0018, 0x0019]
    extensions += _extension(10, vector(words(groups)))
    extensions += _extension(11, b"\x01\0")
    extensions += _extension(16, vector(b"\x02h2\x08http/1.1"))
    extensions += _extension(5, b"\x01\0\0\0\0")
    signatures = words([0x0403, 0x0804, 0x0401, 0x0503, 0x0805,
                        0x0805, 0x0501, 0x0806, 0x0601, 0x0201])
    extensions += _extension(13, vector(signatures)) + _extension(18, b"")
    shares = words([grease[4]]) + vector(b"\0")
    if modern:
        coefficients = struct.unpack("<768I", os.urandom(768 * 4))
        kem_key = bytearray()
        for index in range(0, len(coefficients), 2):
            first, second = coefficients[index] % 3329, coefficients[index + 1] % 3329
            kem_key.extend((first & 255, (first >> 8) | ((second & 15) << 4), second >> 4))
        kem_key.extend(os.urandom(32))
        shares += words([0x11ec]) + vector(bytes(kem_key) + public_key())
    shares += words([0x001d]) + vector(public_key())
    extensions += _extension(51, vector(shares)) + _extension(45, b"\x01\x01")
    versions = words([grease[6], 0x0304, 0x0303] + ([] if modern else [0x0302, 0x0301]))
    extensions += _extension(43, bytes((len(versions),)) + versions)
    extensions += _extension(27, b"\x02\0\x01") + _extension(grease[3], b"\0")
    body = b"\x03\x03" + b"\0" * 32 + b"\x20" + os.urandom(32) + vector(ciphers) + b"\x01\0"
    if not modern:
        padding = 517 - (9 + len(body) + 2 + len(extensions) + 4)
        if padding < 0:
            raise RuntimeError("invalid_client_hello")
        extensions += _extension(21, b"\0" * padding)
    body += vector(extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    hello = bytearray(b"\x16\x03\x01" + vector(handshake))
    if not 517 <= len(hello) <= 4096 or (not modern and len(hello) != 517):
        raise RuntimeError("invalid_client_hello")
    digest = bytearray(hmac.new(key, hello, hashlib.sha256).digest())
    digest[28:32] = struct.pack("<I", struct.unpack("<I", digest[28:32])[0] ^ stamp)
    hello[11:43] = digest
    return bytes(hello)


def _read_record(connection, deadline: float, *, kind: int, allow_empty: bool = False) -> bytes:
    header = base._receive_exact(connection, 5, deadline)
    if header[:3] != bytes((kind, 3, 3)):
        raise RuntimeError("invalid_tls_record")
    size = struct.unpack(">H", header[3:5])[0]
    if size > MAX_TLS_RECORD:
        raise RuntimeError("tls_record_too_large")
    if not size and not allow_empty:
        raise RuntimeError("invalid_tls_record")
    return header + base._receive_exact(connection, size, deadline)


def _authenticate_server(connection, hello: bytes, secret: str, deadline: float) -> None:
    server = _read_record(connection, deadline, kind=22)
    # The pinned server emits one ServerHello with exactly these two TLS 1.3
    # extensions; either order is legal. No certificate/full HTTPS fallback.
    if (len(server) != 127 or server[:11] != b"\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03"
            or server[43] != 32 or server[44:76] != hello[44:76]
            or server[76:81] not in (b"\x13\x01\x00\x00\x2e",
                                    b"\x13\x02\x00\x00\x2e", b"\x13\x03\x00\x00\x2e")):
        raise RuntimeError("invalid_server_hello")
    position, extensions = 81, {}
    while position < len(server):
        if position + 4 > len(server):
            raise RuntimeError("invalid_server_hello")
        kind, size = struct.unpack_from(">HH", server, position)
        position += 4
        if kind in extensions or position + size > len(server):
            raise RuntimeError("invalid_server_hello")
        extensions[kind] = server[position:position + size]
        position += size
    share = extensions.get(51, b"")
    if (set(extensions) != {43, 51} or extensions[43] != b"\x03\x04"
            or len(share) != 36 or share[:4] != b"\x00\x1d\x00\x20"):
        raise RuntimeError("invalid_server_hello")
    ccs = _read_record(connection, deadline, kind=20)
    if ccs != _CCS:
        raise RuntimeError("invalid_server_hello")
    encrypted_hello = _read_record(connection, deadline, kind=23)
    response = bytearray(server + ccs + encrypted_hello)
    received = bytes(response[11:43])
    response[11:43] = b"\0" * 32
    expected = hmac.new(_secret_bytes(secret), hello[11:43] + response, hashlib.sha256).digest()
    if not hmac.compare_digest(received, expected):
        raise RuntimeError("server_hello_not_authenticated")


def wrap_application_records(payload: bytes, *, first: bool = True) -> bytes:
    """TLS record framing around obfuscated2 ciphertext, with initial CCS."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 65536 or (first and len(payload) < 64):
        raise RuntimeError("invalid_tls_application_record")
    chunks = [payload[index:index + CLIENT_RECORD_SIZE] for index in range(0, len(payload), CLIENT_RECORD_SIZE)]
    return (_CCS if first else b"") + b"".join(
        b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk for chunk in chunks)


class _ApplicationStream:
    """Bound TLS framing, preserving continuous obfuscated2 AES-CTR bytes."""
    def __init__(self, connection, deadline: float):
        self.connection, self.deadline = connection, deadline
        self.pending = bytearray()
        self.record_count = 0
        self.total = 0

    def read_exact(self, count: int) -> bytes:
        if type(count) is not int or not 0 <= count <= MAX_MT_FRAME + 4:
            raise RuntimeError("protocol_frame_too_large")
        while len(self.pending) < count:
            self.record_count += 1
            if self.record_count > 128:
                raise RuntimeError("tls_record_budget_exceeded")
            record = _read_record(self.connection, self.deadline, kind=23, allow_empty=True)
            self.total += len(record)
            if self.total > 65536:
                raise RuntimeError("tls_record_budget_exceeded")
            self.pending.extend(record[5:])
        result = bytes(self.pending[:count])
        del self.pending[:count]
        return result


def probe(secret: str, endpoint: str = "127.0.0.1", port: int = 5443, domain: str = DOMAIN, *,
          client_profile: str = "standard") -> dict:
    """No arbitrary endpoints, files, subprocesses, logs, or account login.

    Inputs remain in memory. The only successful outcome authenticates both
    the Native FakeTLS shared-secret handshake and Telegram's resPQ nonce.
    """
    started = time.monotonic()
    result = {"ok": False, "status": "protocol_failed",
              "method": "mtproto_fake_tls_req_pq_multi", "checked_at": int(time.time()),
              "fake_tls_authenticated": False, "telegram_nonce_confirmed": False,
              "account_authorization_tested": False}
    try:
        if client_profile not in ("standard", IOS_LEGACY_BROKEN_SNI, IOS_MODERN_SAFARI):
            raise RuntimeError("invalid_client_profile")
        if client_profile != "standard":
            result["client_profile"] = client_profile
        if endpoint not in ("127.0.0.1", PUBLIC_HOST):
            raise RuntimeError("unmanaged_probe_endpoint")
        if type(port) is not int or port not in MANAGED_PORTS:
            raise RuntimeError("unmanaged_probe_port")
        _secret_bytes(secret)
        _domain_bytes(domain)
        _require_inprocess_crypto()
        deadline = started + DEADLINE_SECONDS
        hello = (build_client_hello(secret, domain) if client_profile == "standard"
                 else build_ios_client_hello(secret, domain, profile=client_profile))
        with socket.create_connection((endpoint, port), timeout=2) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            # Do not pipeline payload with ClientHello: official MTProxy
            # rejects extra bytes before its authenticated ServerHello.
            connection.sendall(hello)
            _authenticate_server(connection, hello, secret, deadline)
            result["fake_tls_authenticated"] = True
            wire, key, iv, nonce = base._request(secret)
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.sendall(wrap_application_records(wire))
            stream = _ApplicationStream(connection, deadline)
            header = stream.read_exact(4)
            size = struct.unpack("<I", base._aes_ctr(header, key, iv))[0]
            if not 56 <= size <= MAX_MT_FRAME:
                raise RuntimeError("invalid_mtproto_frame_length")
            encrypted = header + stream.read_exact(size)
            base._validate_response(base._aes_ctr(encrypted, key, iv)[4:], nonce)
        result.update(ok=True, status="protocol_confirmed", telegram_nonce_confirmed=True,
                      latency_ms=round((time.monotonic() - started) * 1000))
    except Exception as error:
        code = str(error) if isinstance(error, (RuntimeError, TimeoutError)) else ""
        if isinstance(error, TimeoutError):
            code = "protocol_deadline"
        result["failure_code"] = code if code in _FAILURES else "bounded_protocol_failure"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def external_health_probe(secret: str, endpoint: str = PUBLIC_HOST, port: int = 5443, domain: str = DOMAIN) -> dict:
    return probe(secret, endpoint, port, domain)
