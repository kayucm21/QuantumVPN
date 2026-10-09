"""Offline official FakeTLS handshake/framing/Telegram nonce/security regressions."""
from __future__ import annotations

import builtins
import hashlib
import hmac
import json
import os
import struct
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tools import quantumvpn_mtproto_tls_protocol as tls


SECRET = "0123456789abcdef0123456789abcdef"
CCS = bytes.fromhex("140303000101")


def aes(data, key, iv):
    transform = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return transform.update(data) + transform.finalize()


def record(kind, payload, version=b"\x03\x03"):
    return bytes((kind,)) + version + struct.pack(">H", len(payload)) + payload


def server_hello(client, *, corrupt_digest=False, wrong_session=False, reverse=False,
                 malformed_extension=False, corrupt_random=False):
    session = b"q" * 32 if wrong_session else client[44:76]
    share = bytes.fromhex("00330024001d0020") + bytes(range(32))
    version = bytes.fromhex("002b00020304")
    extensions = version + share if reverse else share + version
    if malformed_extension:
        extensions = extensions[:-1] + b"\x02"
    response = bytearray(bytes.fromhex("160303007a020000760303") + b"\0" * 32
                         + b"\x20" + session + bytes.fromhex("130100002e") + extensions
                         + CCS + record(23, b"cover-hello" * 30))
    response[11:43] = hmac.new(bytes.fromhex(SECRET), client[11:43] + response, hashlib.sha256).digest()
    if corrupt_digest:
        response[11] ^= 1
    if corrupt_random:
        response[-1] ^= 1
    return bytes(response)


def telegram_response(nonce, *, wrong_nonce=False):
    body = struct.pack("<I", 0x05162463) + (b"n" * 16 if wrong_nonce else nonce) + b"s" * 16
    body += b"\x08" + b"p" * 8 + b"\0" * 3
    body += struct.pack("<IIQ", 0x1cb5c415, 1, 0x0123456789abcdef)
    return struct.pack("<QQI", 0, (int(time.time()) << 32) | 1, len(body)) + body + b"\0" * 7


def parse_client_extensions(client):
    position = 76
    cipher_length = struct.unpack_from(">H", client, position)[0]
    position += 2 + cipher_length
    if client[position:position + 2] != b"\x01\x00":
        raise AssertionError("compression")
    position += 2
    extension_length = struct.unpack_from(">H", client, position)[0]
    position += 2
    if position + extension_length != len(client):
        raise AssertionError("extensions length")
    result = {}
    while position < len(client):
        kind, size = struct.unpack_from(">HH", client, position)
        position += 4
        if kind in result or position + size > len(client):
            raise AssertionError("extension bounds")
        result[kind] = client[position:position + size]
        position += size
    return result


class Connection:
    """Independent server fixture validates the actual obfuscated2 request."""
    def __init__(self, *, hello_options=None, wrong_nonce=False, no_response=False,
                 response_prefix=b"", oversized_frame=False, initial_reply=None):
        self.incoming = b""
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.hello_options = hello_options or {}
        self.wrong_nonce = wrong_nonce
        self.no_response = no_response
        self.response_prefix = response_prefix
        self.oversized_frame = oversized_frame
        self.initial_reply = initial_reply

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, count):
        size = min(count, 3)
        result, self.incoming = self.incoming[:size], self.incoming[size:]
        return result

    def sendall(self, payload):
        self.sent.append(payload)
        if len(self.sent) == 1:
            if len(payload) != 517 or payload[:5] != bytes.fromhex("1603010200"):
                raise AssertionError("hello record")
            extensions = parse_client_extensions(payload)
            name = tls.DOMAIN.encode()
            if extensions[0] != struct.pack(">H", 3 + len(name)) + b"\0" + struct.pack(">H", len(name)) + name:
                raise AssertionError("SNI")
            zeroed = bytearray(payload)
            zeroed[11:43] = b"\0" * 32
            digest = hmac.new(bytes.fromhex(SECRET), zeroed, hashlib.sha256).digest()
            if digest[:28] != payload[11:39]:
                raise AssertionError("client HMAC")
            stamp = struct.unpack("<I", digest[28:32])[0] ^ struct.unpack("<I", payload[39:43])[0]
            if not int(time.time()) - 600 < stamp <= int(time.time()) + 3:
                raise AssertionError("timestamp")
            self.incoming = self.initial_reply if self.initial_reply is not None else server_hello(payload, **self.hello_options)
            return
        if self.no_response:
            return
        if not payload.startswith(CCS):
            raise AssertionError("missing client CCS")
        wire, position = bytearray(), len(CCS)
        while position < len(payload):
            if payload[position:position + 3] != bytes.fromhex("170303"):
                raise AssertionError("application record")
            size = struct.unpack_from(">H", payload, position + 3)[0]
            position += 5
            wire.extend(payload[position:position + size])
            position += size
        if position != len(payload):
            raise AssertionError("application bounds")
        wire = bytes(wire)
        secret = bytes.fromhex(SECRET)
        read_key = hashlib.sha256(wire[8:40] + secret).digest()
        decoded = aes(wire, read_key, wire[40:56])
        if decoded[56:60] != b"\xdd" * 4 or struct.unpack_from("<h", decoded, 60)[0] != 2:
            raise AssertionError("padded intermediate DC2")
        packet_length = struct.unpack_from("<I", decoded, 64)[0]
        packet = decoded[68:]
        if len(packet) != packet_length or packet[:8] != b"\0" * 8:
            raise AssertionError("auth key / length")
        if struct.unpack_from("<I", packet, 16)[0] != 20 or struct.unpack_from("<I", packet, 20)[0] != 0xbe7e8ef1:
            raise AssertionError("req_pq_multi")
        nonce = packet[24:40]
        response = telegram_response(nonce, wrong_nonce=self.wrong_nonce)
        write_key = hashlib.sha256(wire[24:56][::-1] + secret).digest()
        write_iv = wire[8:24][::-1]
        size = 65537 if self.oversized_frame else len(response)
        encrypted = aes(struct.pack("<I", size) + response, write_key, write_iv)
        # The four-byte MTProto size crosses TLS records; CTR remains one stream.
        self.incoming = (self.response_prefix + record(23, encrypted[:1])
                         + record(23, encrypted[1:3]) + record(23, encrypted[3:]))


class NativeFakeTlsTests(unittest.TestCase):
    def assert_redacted(self, result):
        text = json.dumps(result)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("secret=", text)
        self.assertNotIn("client_random", text)
        self.assertFalse(result["account_authorization_tested"])

    def run_probe(self, connection, endpoint="127.0.0.1", port=5443):
        with patch.object(tls.socket, "create_connection", return_value=connection) as connect:
            result = tls.probe(SECRET, endpoint, port, tls.DOMAIN)
        self.assert_redacted(result)
        connect.assert_called_once_with((endpoint, port), timeout=2)
        return result

    def test_client_hello_tls_lengths_sni_hmac_and_little_endian_time(self):
        stamp = 1700000000
        hello = tls.build_client_hello(SECRET, timestamp=stamp)
        self.assertEqual(len(hello), 517)
        self.assertEqual(hello[:5], bytes.fromhex("1603010200"))
        self.assertEqual(int.from_bytes(hello[6:9], "big"), len(hello) - 9)
        self.assertEqual(hello[5], 1)
        self.assertEqual(hello[43], 32)
        self.assertEqual(hello[76:84], bytes.fromhex("0006130113021303"))
        extensions = parse_client_extensions(hello)
        name = tls.DOMAIN.encode()
        self.assertEqual(extensions[0], struct.pack(">H", len(name) + 3) + b"\0" + struct.pack(">H", len(name)) + name)
        self.assertEqual(extensions[43], bytes.fromhex("0403040303"))
        self.assertEqual(extensions[51][:6], bytes.fromhex("0024001d0020"))
        self.assertEqual(len(extensions[51]), 38)
        self.assertTrue(extensions[21])
        zeroed = bytearray(hello)
        zeroed[11:43] = b"\0" * 32
        expected = hmac.new(bytes.fromhex(SECRET), zeroed, hashlib.sha256).digest()
        self.assertEqual(hello[11:39], expected[:28])
        recovered = struct.unpack("<I", expected[-4:])[0] ^ struct.unpack("<I", hello[39:43])[0]
        self.assertEqual(recovered, stamp)

    def test_client_hellos_are_replay_distinct(self):
        first = tls.build_client_hello(SECRET, timestamp=1700000000)
        second = tls.build_client_hello(SECRET, timestamp=1700000000)
        self.assertNotEqual(first[11:43], second[11:43])
        self.assertNotEqual(first[44:76], second[44:76])

    def test_input_validation_before_any_socket_or_request(self):
        cases = [("SECRET", "127.0.0.1", 5443, tls.DOMAIN, "invalid_probe_secret"),
                 (SECRET, "192.168.1.2", 5443, tls.DOMAIN, "unmanaged_probe_endpoint"),
                 (SECRET, "pecaocek.ignorelist.com", 5443, tls.DOMAIN, "unmanaged_probe_endpoint"),
                 (SECRET, "127.0.0.1", 443, tls.DOMAIN, "unmanaged_probe_port"),
                 (SECRET, "127.0.0.1", True, tls.DOMAIN, "unmanaged_probe_port"),
                 (SECRET, "127.0.0.1", 5443, "https://example.com", "invalid_probe_domain"),
                 (SECRET, "127.0.0.1", 5443, "127.0.0.1", "invalid_probe_domain"),
                 (SECRET, "127.0.0.1", 5443, "EXAMPLE.COM", "invalid_probe_domain"),
                 (SECRET, "127.0.0.1", 5443, "example.com\0x", "invalid_probe_domain")]
        with patch.object(tls.socket, "create_connection") as connect, patch.object(tls.base, "_request") as request:
            for secret, endpoint, port, domain, code in cases:
                with self.subTest(code=code, domain=domain):
                    result = tls.probe(secret, endpoint, port, domain)
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["failure_code"], code)
                    self.assert_redacted(result)
            connect.assert_not_called()
            request.assert_not_called()

    def test_inprocess_crypto_missing_fails_without_openssl_or_key_argv(self):
        original_import = builtins.__import__
        def without_crypto(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("not installed")
            return original_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=without_crypto), \
             patch.object(tls.base.subprocess, "run") as subprocess_run, \
             patch.object(tls.socket, "create_connection") as connect, \
             patch.object(tls.base, "_request") as request:
            result = tls.probe(SECRET)
        self.assertEqual(result["failure_code"], "protocol_crypto_unavailable")
        self.assertFalse(result["ok"])
        self.assert_redacted(result)
        subprocess_run.assert_not_called()
        connect.assert_not_called()
        request.assert_not_called()

    def test_full_server_auth_and_real_nonce_proof_with_fragmented_tls_stream(self):
        for reverse in (False, True):
            for endpoint, port in (("127.0.0.1", 5443), (tls.PUBLIC_HOST, 4433)):
                with self.subTest(reverse=reverse, endpoint=endpoint, port=port):
                    connection = Connection(hello_options={"reverse": reverse})
                    result = self.run_probe(connection, endpoint, port)
                    self.assertTrue(result["ok"], result)
                    self.assertEqual(result["status"], "protocol_confirmed")
                    self.assertTrue(result["fake_tls_authenticated"])
                    self.assertTrue(result["telegram_nonce_confirmed"])
                    self.assertTrue(connection.closed)
                    self.assertEqual(len(connection.sent), 2)
                    self.assertTrue(all(0 < timeout <= tls.DEADLINE_SECONDS for timeout in connection.timeouts))
                    self.assertIsInstance(result["latency_ms"], int)
                    self.assertNotIn("tls_confirmed", result)  # Not CA-authenticated HTTPS.

    def test_bad_server_hmac_or_modified_cover_random_rejected_before_payload(self):
        for options in ({"corrupt_digest": True}, {"corrupt_random": True}):
            connection = Connection(hello_options=options)
            result = self.run_probe(connection)
            self.assertFalse(result["ok"])
            self.assertEqual(result["failure_code"], "server_hello_not_authenticated")
            self.assertFalse(result["fake_tls_authenticated"])
            self.assertEqual(len(connection.sent), 1)

    def test_authenticated_but_malformed_server_hello_is_rejected(self):
        for options in ({"wrong_session": True}, {"malformed_extension": True}):
            connection = Connection(hello_options=options)
            result = self.run_probe(connection)
            self.assertFalse(result["ok"])
            self.assertEqual(result["failure_code"], "invalid_server_hello")
            self.assertEqual(len(connection.sent), 1)

    def test_hello_only_never_proves_telegram(self):
        result = self.run_probe(Connection(no_response=True))
        self.assertFalse(result["ok"])
        self.assertTrue(result["fake_tls_authenticated"])
        self.assertFalse(result["telegram_nonce_confirmed"])
        self.assertEqual(result["failure_code"], "protocol_connection_closed")

    def test_wrong_telegram_nonce_is_failure_even_after_good_hello(self):
        result = self.run_probe(Connection(wrong_nonce=True))
        self.assertFalse(result["ok"])
        self.assertTrue(result["fake_tls_authenticated"])
        self.assertFalse(result["telegram_nonce_confirmed"])
        self.assertEqual(result["failure_code"], "telegram_nonce_not_confirmed")

    def test_invalid_tls_record_types_versions_and_oversized_records_bounded(self):
        cases = [(record(21, b"\x02\x28"), "invalid_tls_record"),
                 (record(22, b"x", b"\x03\x01"), "invalid_tls_record"),
                 (bytes.fromhex("160303ffff"), "tls_record_too_large"),
                 (bytes.fromhex("1603030000"), "invalid_tls_record")]
        for reply, expected in cases:
            with self.subTest(expected=expected, reply=reply):
                connection = Connection(initial_reply=reply)
                result = self.run_probe(connection)
                self.assertFalse(result["ok"])
                self.assertEqual(result["failure_code"], expected)
                self.assertEqual(len(connection.sent), 1)

    def test_invalid_mtproto_size_and_post_hello_alert_fail(self):
        for connection, code in ((Connection(oversized_frame=True), "invalid_mtproto_frame_length"),
                                 (Connection(response_prefix=record(21, b"\x02\x28")), "invalid_tls_record")):
            result = self.run_probe(connection)
            self.assertFalse(result["ok"])
            self.assertTrue(result["fake_tls_authenticated"])
            self.assertEqual(result["failure_code"], code)

    def test_empty_records_allowed_but_record_budget_enforced(self):
        result = self.run_probe(Connection(response_prefix=record(23, b"") * 2))
        self.assertTrue(result["ok"], result)
        result = self.run_probe(Connection(response_prefix=record(23, b"") * 129))
        self.assertFalse(result["ok"])
        self.assertEqual(result["failure_code"], "tls_record_budget_exceeded")

    def test_record_wrapping_is_2878_bytes_and_ccs_only_once(self):
        data = bytes(range(256)) * 24
        wrapped = tls.wrap_application_records(data)
        self.assertTrue(wrapped.startswith(CCS))
        position, decoded, sizes = len(CCS), b"", []
        while position < len(wrapped):
            self.assertEqual(wrapped[position:position + 3], bytes.fromhex("170303"))
            size = struct.unpack_from(">H", wrapped, position + 3)[0]
            sizes.append(size)
            position += 5
            decoded += wrapped[position:position + size]
            position += size
        self.assertEqual(decoded, data)
        self.assertEqual(sizes[:2], [2878, 2878])
        self.assertTrue(tls.wrap_application_records(b"x", first=False).startswith(bytes.fromhex("170303")))
        for bad in (b"", b"x" * 63, b"x" * 65537, "x" * 64):
            with self.subTest(length=len(bad)), self.assertRaisesRegex(RuntimeError, "invalid_tls_application_record"):
                tls.wrap_application_records(bad)

    def test_timeouts_and_unknown_errors_never_return_arbitrary_text(self):
        for error, expected in ((TimeoutError(SECRET), "protocol_deadline"),
                                (OSError(SECRET), "bounded_protocol_failure"),
                                (RuntimeError(SECRET), "bounded_protocol_failure")):
            with patch.object(tls.socket, "create_connection", side_effect=error):
                result = tls.probe(SECRET)
            self.assertFalse(result["ok"])
            self.assertEqual(result["failure_code"], expected)
            self.assert_redacted(result)

    def test_external_wrapper_uses_fixed_public_endpoint(self):
        with patch.object(tls, "probe", return_value={"ok": False}) as probe:
            result = tls.external_health_probe(SECRET)
        probe.assert_called_once_with(SECRET, tls.PUBLIC_HOST, 5443, tls.DOMAIN)
        self.assertEqual(result, {"ok": False})


if __name__ == "__main__":
    unittest.main()
