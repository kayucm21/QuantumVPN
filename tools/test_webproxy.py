"""Contract/security tests use synthetic secrets only and no live VDS writes."""
import base64
import hashlib
import json
import io
from pathlib import Path, PurePosixPath
import ssl
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse

import quantumvpn_webproxy as web
import quantumvpn_mtproto as mt

SECRET = "000102030405060708090a0b0c0d0e0f"
BOOTSTRAP = web._b64(b"b" * 32)
SESSION = web._b64(b"s" * 32)
NONCE = b"n" * 16
KEY = b"k" * 32
IV = b"i" * 16


def manifest():
    return {"schema": 1, "managed_by": "quantumvpn-webproxy", "commit": web.COMMIT,
            "archive_sha256": web.ARCHIVE_SHA256, "binary_sha256": "a" * 64,
            "helper_sha256": "b" * 64, "public_host": web.PUBLIC_HOST,
            "public_port": 443, "listen": "127.0.0.1:18082", "admin_listen": "127.0.0.1:18083",
            "base_path": "qweb-0123456789abcdef", "backend": web.BACKEND,
            "carrier_mode": "https", "created_at": 1700000000}


def runtime():
    return {"public_hostname": web.PUBLIC_HOST, "base_path": manifest()["base_path"],
            "listen": "127.0.0.1:18082", "admin_listen": "127.0.0.1:18083",
            "public_upstream": web.PUBLIC_UPSTREAM, "static_routes": "exact",
            "profiles_file": f"/run/credentials/{web.SERVICE}/profiles.json",
            "token_key_file": "/run/quantumvpn-webproxy/token.key", "enable_pprof": False,
            "limits": {"max_pending_global": 64 * 1024 * 1024,
                       "max_pending_per_session": 8 * 1024 * 1024,
                       "max_sessions_global": 32, "max_streams_global": 512,
                       "max_backend_dials_in_flight": 32, "max_body_bytes": 2 * 1024 * 1024,
                       "max_frame_payload": 1024 * 1024, "carrier_batch_bytes": 2 * 1024 * 1024}}


def profile():
    return {"name": "quantumvpn", "backend": web.BACKEND,
            "carrier_mode": "https", "secret": SECRET}


def res_pq(nonce=NONCE):
    body = (struct.pack("<I", 0x05162463) + nonce + b"r" * 16 + b"\x08" + b"q" * 8
            + b"\0" * 3 + struct.pack("<II", 0x1cb5c415, 3) + b"f" * 24)
    return struct.pack("<QQI", 0, 1700000000000, len(body)) + body + b"p" * 55


class FakeCarrier:
    def __init__(self, *, nonce=NONCE, public=True, failure=None, fragmented=True):
        self.calls = []
        self.failure = failure
        self.public = public
        packet = res_pq(nonce)
        self.encrypted = mt._aes_ctr(struct.pack("<I", len(packet)) + packet, KEY, IV)
        self.parts = [self.encrypted[:2], self.encrypted[2:19], self.encrypted[19:]] if fragmented else [self.encrypted]
        self.cursor = 0

    def __call__(self, opener, url, method, body, headers, timeout, maximum):
        self.calls.append((url, method, body, headers.copy(), timeout, maximum))
        expected = ("https://" + web.PUBLIC_HOST + "/" if self.public else "http://127.0.0.1:18082/") + manifest()["base_path"] + "/"
        if not url.startswith(expected):
            raise AssertionError("destination escaped fixed endpoint")
        if not self.public:
            assert headers.get("Host") == web.PUBLIC_HOST
        if method == "DELETE":
            assert headers["Authorization"] == "Bearer " + SESSION
            return 204, {}, b""
        if "?bridge=" in url:
            if self.failure == "bridge":
                return 200, {"content-type": "text/html"}, b"wrong public site"
            base = "https://" + web.PUBLIC_HOST + "/" + manifest()["base_path"] + "/"
            page = f'const relayBase="{base}",bootstrap="{BOOTSTRAP}",carrierMode="https";'
            return 200, {"content-type": "text/html; charset=utf-8"}, page.encode()
        if url.endswith("/session"):
            assert headers["Authorization"] == "Bearer " + BOOTSTRAP
            assert body == web._frame(0x10, 0, b"\x01")
            return 200, {"x-session-token": SESSION, "x-down-cursor": "0", "x-carrier-mode": "https"}, web._frame(0x11, 0) if self.failure != "session" else b"bad"
        assert headers["Authorization"] == "Bearer " + SESSION
        if url.endswith("/up"):
            if self.failure == "up":
                return 503, {}, b"private error " + SECRET.encode()
            assert headers["Content-Type"] == "application/octet-stream"
            assert body == web._frame(1, 1) + web._frame(2, 1, b"request")
            return 204, {"x-up-ack": "1"}, b""
        if url.endswith("/down"):
            assert headers["X-Down-Cursor"] == str(self.cursor)
            self.cursor += 1
            if self.failure == "cursor":
                return 200, {"x-down-cursor": "99"}, web._frame(2, 1, self.encrypted)
            if self.failure == "close":
                return 200, {"x-down-cursor": str(self.cursor)}, web._frame(3, 1)
            return 200, {"x-down-cursor": str(self.cursor)}, web._frame(4, 1, struct.pack(">I", 128)) + web._frame(2, 1, self.parts.pop(0))
        raise AssertionError("unknown endpoint")


class ConfigurationTests(unittest.TestCase):
    def test_pinned_manifest_exact_endpoints_and_identity(self):
        self.assertEqual(web._validate_manifest(manifest()), manifest())
        for key, bad in (("commit", "0" * 40), ("archive_sha256", "0" * 64),
                         ("public_host", "other.invalid"), ("public_port", 8443),
                         ("public_port", True), ("listen", "0.0.0.0:18082"),
                         ("admin_listen", "[::]:18083"), ("backend", "10.0.0.1:443"),
                         ("carrier_mode", "websocket"), ("binary_sha256", "x" * 64),
                         ("helper_sha256", "x" * 64), ("created_at", True),
                         ("base_path", "qweb-../../evil"), ("base_path", ""),
                         ("base_path", "qweb-uppercaseA"), ("managed_by", "other")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                web._validate_manifest({**manifest(), key: bad})

    def test_runtime_fixed_credential_paths_no_remote_destination_or_debug(self):
        self.assertEqual(web._validate_runtime(runtime(), manifest()), runtime())
        for key, bad in (("public_upstream", "https://example.org"),
                         ("public_upstream", "http://127.0.0.1:8443"),
                         ("profiles_file", "/tmp/profiles.json"),
                         ("token_key_file", "/run/credentials/other/token.key"),
                         ("enable_pprof", True), ("static_routes", "legacy"),
                         ("public_dir", "/tmp/site")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                web._validate_runtime({**runtime(), key: bad}, manifest())
        for key in runtime()["limits"]:
            for bad in (0, -1, True, 1 << 35):
                value = runtime()
                value["limits"][key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(RuntimeError):
                    web._validate_runtime(value, manifest())

    def test_single_fixed_profile(self):
        with patch.object(web, "_read_file", return_value=json.dumps({"profiles": [profile()]}).encode()):
            self.assertEqual(web._profile(), profile())
        for value in ({"profiles": []}, {"profiles": [profile(), profile()]},
                      {"profiles": [{**profile(), "secret": "dd" + SECRET}]},
                      {"profiles": [{**profile(), "backend": "127.0.0.1:1"}]},
                      {"profiles": [{**profile(), "carrier_mode": "websocket"}]}):
            with patch.object(web, "_read_file", return_value=json.dumps(value).encode()), self.assertRaises(RuntimeError):
                web._profile()

    def test_private_bounded_nofollow_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"
            path.write_bytes(b"safe")
            self.assertEqual(web._read_file(path, 4), b"safe")
            with self.assertRaises(RuntimeError):
                web._read_file(path, 3)
            with self.assertRaises((OSError, RuntimeError)):
                web._read_file(Path(directory), 100)
        with patch.object(Path, "is_symlink", return_value=True), self.assertRaises(RuntimeError):
            web._read_file(web.PROFILES, 100, private=True)

    def test_systemd_acl_credential_contract(self):
        for uid, gid, mode in ((0, 0, 0o440), (0, 0, 0o400), (996, 987, 0o400)):
            info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)
            self.assertTrue(web._credential_permissions(info, 996, 987, True))
            self.assertFalse(web._credential_permissions(info, 996, 987, False))
        for uid, gid, mode in ((1, 0, 0o440), (0, 1, 0o440), (0, 0, 0o444), (996, 987, 0o600)):
            self.assertFalse(web._credential_permissions(SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode), 996, 987, True))

    def test_snapshot_never_reads_profile_nor_runs_credential_probe(self):
        with patch.object(web, "_configuration", return_value=(manifest(), runtime())), \
             patch.object(web, "_service_state", return_value="active"), \
             patch.object(web, "_admin_ready", return_value=True), \
             patch.object(web, "_profile", side_effect=AssertionError("secret read")), \
             patch.object(web, "health_probe", side_effect=AssertionError("secret probe")):
            value = web.snapshot()
        self.assertTrue(value["runtime_ready"])
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertNotIn("secret=", json.dumps(value))

    def test_unavailable_snapshot_is_redacted(self):
        for error, expected in ((FileNotFoundError(SECRET), "not_installed"),
                                (RuntimeError(SECRET), "configuration_unavailable")):
            with patch.object(web, "_configuration", side_effect=error), patch.object(web, "_service_state", return_value="unknown"):
                value = web.snapshot()
            self.assertEqual(value["status"], expected)
            self.assertNotIn(SECRET, json.dumps(value))

    def test_owner_import_link_exact_p_tag_and_path_percent_encoding(self):
        proof = {"ok": True, "tls_confirmed": True, "telegram_nonce_confirmed": True,
                 "endpoint": "public_https", "checked_at": int(web.time.time())}
        with patch.object(web, "_configuration", return_value=(manifest(), runtime())), patch.object(web, "_profile", return_value=profile()), \
             patch.object(web, "_LAST_PROBE", proof):
            value = web.owner_connection_links()
        self.assertTrue(value["telegram"].startswith("tg://webproxy?"))
        self.assertIn("%2F", value["telegram"])
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(value["telegram"]).query)
        self.assertEqual(query["server"], [web.PUBLIC_HOST + "/" + manifest()["base_path"]])
        self.assertEqual(base64.urlsafe_b64decode(query["secret"][0] + "="), b"\x70" + bytes.fromhex(SECRET))
        self.assertNotIn("port", query)
        self.assertEqual(set(value), {"telegram", "https"})
        self.assertTrue(value["https"].startswith("https://t.me/webproxy?"))

    def test_owner_links_require_recent_genuine_public_proof(self):
        good = {"ok": True, "tls_confirmed": True, "telegram_nonce_confirmed": True,
                "endpoint": "public_https", "checked_at": int(web.time.time())}
        values = [{}, {**good, "endpoint": "loopback"}, {**good, "tls_confirmed": False},
                  {**good, "telegram_nonce_confirmed": False},
                  {**good, "checked_at": int(web.time.time()) - 301}]
        for proof in values:
            with patch.object(web, "_LAST_PROBE", proof), \
                 patch.object(web, "_configuration", return_value=(manifest(), runtime())), \
                 patch.object(web, "_profile") as private, \
                 self.assertRaisesRegex(RuntimeError, "public_protocol_not_confirmed"):
                web.owner_connection_links()
            private.assert_not_called()

    def test_control_only_fixed_systemd_commands(self):
        for action in ("start", "stop", "restart"):
            with patch.object(web, "_configuration", return_value=(manifest(), runtime())), \
                 patch.object(web, "snapshot", return_value={}), \
                 patch.object(web.subprocess, "run", return_value=Mock(returncode=0)) as run:
                self.assertTrue(web.control(action)["ok"])
            self.assertEqual(run.call_args.args[0], ["systemctl", action, web.SERVICE])
        for action in ("reload", "stop; rm", "../service", ["stop"]):
            with self.assertRaises(ValueError):
                web.control(action)

    def test_service_output_closed_enum(self):
        with patch.object(web.subprocess, "run", return_value=Mock(stdout=SECRET)):
            self.assertEqual(web._service_state(), "unknown")


class ProtocolTests(unittest.TestCase):
    def probe(self, carrier, **kwargs):
        helper = SimpleNamespace(_request=Mock(return_value=(b"request", KEY, IV, NONCE)),
                                 _aes_ctr=mt._aes_ctr, _validate_response=mt._validate_response)
        with patch.object(web, "_mtproto_helper", return_value=helper), \
             patch.object(web, "_crypto_available"), patch.object(web, "_http", side_effect=carrier), \
             patch.object(web, "_opener", return_value=object()):
            result = web._probe(manifest(), SECRET, **kwargs)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(BOOTSTRAP, json.dumps(result))
        self.assertNotIn(SESSION, json.dumps(result))
        self.assertTrue(all(0 < call[4] <= 8 for call in carrier.calls))
        return result

    def test_genuine_nonce_contract_with_fragmented_data_and_window(self):
        carrier = FakeCarrier()
        value = self.probe(carrier)
        self.assertTrue(value["ok"])
        self.assertEqual(value["status"], "protocol_confirmed")
        self.assertTrue(value["tls_confirmed"])
        self.assertTrue(value["telegram_nonce_confirmed"])
        self.assertFalse(value["account_authorization_tested"])
        self.assertTrue(value["probe_session_closed"])
        self.assertEqual(carrier.calls[-1][1], "DELETE")

    def test_loopback_genuine_nonce_does_not_claim_public_tls(self):
        carrier = FakeCarrier(public=False)
        value = self.probe(carrier, public=False)
        self.assertTrue(value["ok"])
        self.assertFalse(value["tls_confirmed"])
        self.assertEqual(value["endpoint"], "loopback")

    def test_wrong_nonce_rejected_even_with_valid_https_session(self):
        carrier = FakeCarrier(nonce=b"X" * 16)
        value = self.probe(carrier)
        self.assertFalse(value["ok"])
        self.assertEqual(value["failure_code"], "telegram_nonce_not_confirmed")
        self.assertTrue(value["probe_session_closed"])

    def test_session_is_closed_after_malformed_contract_uplink_cursor_or_stream_error(self):
        for failure, expected in (("session", "session_contract_invalid"), ("up", "uplink_rejected"),
                                  ("cursor", "cursor_invalid"), ("close", "stream_closed")):
            carrier = FakeCarrier(failure=failure)
            with self.subTest(failure=failure):
                value = self.probe(carrier)
                self.assertEqual(value["failure_code"], expected)
                self.assertTrue(value["probe_session_closed"])

    def test_invalid_bridge_is_not_a_success_and_does_not_create_session(self):
        carrier = FakeCarrier(failure="bridge")
        value = self.probe(carrier)
        self.assertEqual(value["failure_code"], "bridge_contract_invalid")
        self.assertEqual(len(carrier.calls), 1)
        self.assertFalse(value["bridge_confirmed"])

    def test_bootstrap_parser_exact_origin_mode_and_single_declaration(self):
        base = "https://pecaocek.ignorelist.com/qweb-0123456789abcdef/"
        page = f'const relayBase="{base}",bootstrap="{BOOTSTRAP}",carrierMode="https";'.encode()
        self.assertEqual(web._bootstrap(page, base), BOOTSTRAP)
        for invalid in (page + page, page.replace(b"https://", b"http://"),
                        page.replace(b'"https"', b'"websocket"'), b"alert('secret')"):
            with self.assertRaises(RuntimeError):
                web._bootstrap(invalid, base)

    def test_capability_is_bound_to_host_and_path(self):
        a = web._capability(web.PUBLIC_HOST, "qweb-0123456789abcdef", SECRET)
        self.assertTrue(web._token(a))
        self.assertNotEqual(a, web._capability(web.PUBLIC_HOST, "qweb-0123456789abcdeg", SECRET))
        self.assertNotEqual(a, web._capability("other.example.com", "qweb-0123456789abcdef", SECRET))

    def test_tokens_canonical_not_merely_43_characters(self):
        self.assertTrue(web._token(SESSION))
        for value in ("B" * 43, "A" * 42, "A" * 44, None, SESSION + "=", "/" * 43):
            self.assertFalse(web._token(value))

    def test_frames_bounded_direction_stream_credit_and_size(self):
        good = web._frame(4, 1, struct.pack(">I", 1)) + web._frame(2, 1, b"x")
        self.assertEqual(len(web._frames(good)), 2)
        for bad in (b"", b"x", web._frame(2, 1), web._frame(2, 2, b"x"),
                    web._frame(4, 1, b"\0" * 4), web._frame(4, 1, b"x"),
                    web._frame(1, 1), web._frame(6, 0), web._frame(0x11, 0),
                    web._frame(2, 1, b"x" * 4097), good * 129,
                    b"\x02\0\0\1" + struct.pack(">I", 4294967295)):
            with self.assertRaises(RuntimeError):
                web._frames(bad)

    def test_no_redirect_or_ambient_proxy_and_default_certificate_validation(self):
        with self.assertRaises(RuntimeError):
            web._NoRedirect().redirect_request(Mock(full_url="fixed"), None, 302, "Moved", {}, "https://other.invalid")
        with patch.object(web.urllib.request, "build_opener", return_value=object()) as build:
            web._opener()
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], web._NoRedirect)
        self.assertTrue(handlers[2]._context.check_hostname)
        self.assertEqual(handlers[2]._context.verify_mode, ssl.CERT_REQUIRED)

    def test_body_read_limit_and_no_raw_exception_output(self):
        response = Mock(status=200, headers={})
        response.read.return_value = b"x" * 65
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with self.assertRaisesRegex(RuntimeError, "response_too_large"):
            web._http(opener, "https://fixed", "GET", None, {}, 1, 64)
        carrier = FakeCarrier()
        with patch.object(web, "_mtproto_helper", side_effect=RuntimeError(SECRET)), patch.object(web, "_crypto_available"):
            result = web._probe(manifest(), SECRET)
        self.assertEqual(result["failure_code"], "bounded_transport_failure")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(carrier.calls, [])

    def test_missing_crypto_does_not_start_http_or_fallback_process(self):
        with patch.object(web, "_crypto_available", side_effect=RuntimeError("crypto_unavailable")), \
             patch.object(web, "_http") as http, patch.object(web.subprocess, "run") as run:
            result = web._probe(manifest(), SECRET)
        http.assert_not_called()
        run.assert_not_called()
        self.assertEqual(result["failure_code"], "crypto_unavailable")

    def test_probe_rejects_unmanaged_endpoint_before_network(self):
        with patch.object(web, "_http") as http:
            result = web._probe({**manifest(), "public_host": "10.0.0.1"}, SECRET)
        self.assertFalse(result["ok"])
        http.assert_not_called()

    def test_public_probe_cache_and_private_probe_do_not_overwrite_public_evidence(self):
        with patch.object(web, "_configuration", return_value=(manifest(), runtime())), patch.object(web, "_profile", return_value=profile()), \
             patch.object(web, "_probe", return_value={"ok": True, "endpoint": "public_https"}) as probe:
            public = web.health_probe()
        self.assertEqual(web._LAST_PROBE, public)
        probe.assert_called_once_with(manifest(), SECRET)
        with patch.object(web, "_configuration", return_value=(manifest(), runtime())), patch.object(web, "_profile", return_value=profile()), \
             patch.object(web, "_probe", return_value={"ok": True, "endpoint": "loopback"}) as probe:
            web.private_health_probe()
        self.assertEqual(web._LAST_PROBE, public)
        probe.assert_called_once_with(manifest(), SECRET, public=False)


class ServeTests(unittest.TestCase):
    def test_serve_uses_only_validated_paths_and_no_secret_arguments(self):
        credentials = f"/run/credentials/{web.SERVICE}"
        binary, helper, token = b"binary", b"helper", b"t" * 32
        conf = {**manifest(), "binary_sha256": hashlib.sha256(binary).hexdigest(),
                "helper_sha256": hashlib.sha256(helper).hexdigest()}
        values = {"manifest.json": json.dumps(conf).encode(), "config.json": json.dumps(runtime()).encode(),
                  "tproxy-server": binary, "quantumvpn_webproxy.py": helper, "token.key": token}
        with patch.dict(web.os.environ, {"CREDENTIALS_DIRECTORY": credentials}), \
             patch.object(web, "Path", PurePosixPath), \
             patch.object(web, "_read_file", side_effect=lambda p, *a, **kw: values[p.name]), \
             patch.object(web, "_write_runtime_key") as write, patch.object(web.os, "execv") as execute:
            web.serve()
        write.assert_called_once_with(token)
        args = execute.call_args.args[1]
        self.assertEqual(args, [str(web.ROOT / "tproxy-server"), "-config", credentials + "/config.json", "-profiles-file", credentials + "/profiles.json"])
        self.assertNotIn(SECRET, " ".join(args))
        self.assertNotIn(token.decode(), " ".join(args))

    def test_no_non_systemd_credentials(self):
        for credentials in ("", "relative", "/tmp/quantumvpn-webproxy.service", "/run/credentials/other.service"):
            with patch.dict(web.os.environ, {"CREDENTIALS_DIRECTORY": credentials}), self.assertRaises(RuntimeError):
                web.serve()

    def test_serve_rejects_hash_mismatch_before_key_write(self):
        values = {"manifest.json": json.dumps(manifest()).encode(), "config.json": json.dumps(runtime()).encode(), "tproxy-server": b"wrong"}
        with patch.dict(web.os.environ, {"CREDENTIALS_DIRECTORY": f"/run/credentials/{web.SERVICE}"}), \
             patch.object(web, "Path", PurePosixPath), \
             patch.object(web, "_read_file", side_effect=lambda p, *a, **kw: values[p.name]), \
             patch.object(web, "_write_runtime_key") as write, patch.object(web.os, "execv") as execute, \
             self.assertRaisesRegex(RuntimeError, "binary_identity_mismatch"):
            web.serve()
        write.assert_not_called()
        execute.assert_not_called()

    def test_runtime_key_guard_exact_length(self):
        for value in (b"", b"x" * 31, b"x" * 33):
            with patch.object(web.os, "open") as opening, self.assertRaises(RuntimeError):
                web._write_runtime_key(value)
            opening.assert_not_called()

    def test_runtime_key_atomic_private_fixed_path_nofollow(self):
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream)
        stream.__exit__ = Mock(return_value=False)
        stream.fileno.return_value = 23
        info = SimpleNamespace(st_uid=996, st_mode=stat.S_IFDIR | 0o700)
        with patch.object(web.os, "open", side_effect=[22, 23]) as opening, \
             patch.object(web.os, "fstat", return_value=info), \
             patch.object(web.os, "stat", side_effect=FileNotFoundError), \
             patch.object(web.os, "geteuid", return_value=996, create=True), \
             patch.object(web.os, "O_DIRECTORY", 0o200000, create=True), \
             patch.object(web.os, "O_NOFOLLOW", 0o400000, create=True), \
             patch.object(web.os, "fchmod", create=True) as chmod, \
             patch.object(web.os, "fdopen", return_value=stream), \
             patch.object(web.os, "fsync") as sync, patch.object(web.os, "replace") as replace, \
             patch.object(web.os, "close") as close, patch.object(web.os, "unlink") as unlink:
            web._write_runtime_key(b"t" * 32)
        self.assertEqual(opening.call_args_list[0].args[0], web.RUNTIME)
        flags = opening.call_args_list[1].args[1]
        self.assertTrue(flags & web.os.O_EXCL)
        self.assertEqual(opening.call_args_list[1].args[2], 0o400)
        self.assertEqual(opening.call_args_list[1].kwargs, {"dir_fd": 22})
        chmod.assert_called_once_with(23, 0o400)
        replace.assert_called_once_with("token.key.pending", "token.key", src_dir_fd=22, dst_dir_fd=22)
        close.assert_called_once_with(22)
        unlink.assert_not_called()
        stream.write.assert_called_once_with(b"t" * 32)
        self.assertEqual([call.args[0] for call in sync.call_args_list], [23, 22])

    def test_runtime_key_refuses_directory_owner_mode_before_write(self):
        for uid, mode in ((0, 0o700), (996, 0o755), (996, 0o777)):
            with patch.object(web.os, "open", return_value=22) as opening, \
                 patch.object(web.os, "fstat", return_value=SimpleNamespace(st_uid=uid, st_mode=stat.S_IFDIR | mode)), \
                 patch.object(web.os, "geteuid", return_value=996, create=True), \
                 patch.object(web.os, "O_DIRECTORY", 0o200000, create=True), \
                 patch.object(web.os, "O_NOFOLLOW", 0o400000, create=True), \
                 patch.object(web.os, "close"), self.assertRaisesRegex(RuntimeError, "unsafe_runtime_directory"):
                web._write_runtime_key(b"t" * 32)
            self.assertEqual(opening.call_count, 1)

    def test_runtime_key_refuses_symlink_or_unsafe_existing_token(self):
        for uid, mode in ((996, stat.S_IFLNK | 0o777), (0, stat.S_IFREG | 0o400), (996, stat.S_IFREG | 0o440)):
            with patch.object(web.os, "open", return_value=22) as opening, \
                 patch.object(web.os, "fstat", return_value=SimpleNamespace(st_uid=996, st_mode=stat.S_IFDIR | 0o700)), \
                 patch.object(web.os, "stat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)), \
                 patch.object(web.os, "geteuid", return_value=996, create=True), \
                 patch.object(web.os, "O_DIRECTORY", 0o200000, create=True), \
                 patch.object(web.os, "O_NOFOLLOW", 0o400000, create=True), \
                 patch.object(web.os, "close"), self.assertRaisesRegex(RuntimeError, "unsafe_runtime_token"):
                web._write_runtime_key(b"t" * 32)
            self.assertEqual(opening.call_count, 1)

    def test_verified_mtproto_helper_only_fixed_installed_hash(self):
        source = b"MARKER = 123\n"
        conf = {"managed_by": "quantumvpn", "commit": mt.COMMIT,
                "module_sha256": hashlib.sha256(source).hexdigest()}
        with patch.object(web, "_read_file", side_effect=[json.dumps(conf).encode(), source]) as read:
            helper = web._mtproto_helper()
        self.assertEqual(helper.MARKER, 123)
        self.assertEqual(read.call_args_list[0].args[0], Path("/etc/quantumvpn-mtproto/config.json"))
        self.assertEqual(read.call_args_list[1].args[0], Path("/opt/quantumvpn-mtproto/quantumvpn_mtproto.py"))
        for value in ({**conf, "module_sha256": "0" * 64}, {**conf, "commit": "0" * 40}, {**conf, "managed_by": "other"}):
            with patch.object(web, "_read_file", side_effect=[json.dumps(value).encode(), source]), self.assertRaisesRegex(RuntimeError, "mtproto_helper_unavailable"):
                web._mtproto_helper()


if __name__ == "__main__":
    unittest.main()
