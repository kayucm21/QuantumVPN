"""Offline protocol/security tests; never accesses a VDS or a real service."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools import quantumvpn_mtproto as mt


_SPEC = importlib.util.spec_from_file_location("mtproto_installer", Path(__file__).with_name("install-mtproto-vds.py"))
installer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(installer)
REMOTE = {"RUN_REMOTE": False}
with patch.dict(sys.modules, {"fcntl": Mock(), "pwd": Mock()}):
    exec(compile(installer.REMOTE, "<installer-remote-under-test>", "exec"), REMOTE)

SECRET = "0123456789abcdef0123456789abcdef"
NONCE = bytes(range(16))


def config():
    return {"schema": 1, "managed_by": "quantumvpn", "commit": mt.COMMIT,
            "security_patch": mt.SECURITY_PATCH, "server": mt.PUBLIC_HOST,
            "port": mt.PUBLIC_PORT, "stats_port": mt.STATS_PORT, "created_at": 1700000000,
            "binary_sha256": "a" * 64, "module_sha256": "b" * 64,
            "patch_sha256": mt.SECURITY_PATCH_SHA256, "source_file_sha256": mt.BASE_SOURCE_SHA256}


def response(nonce=NONCE, padding=7, fingerprints=1):
    # Real TL resPQ layout, including the pq bytes and fingerprints vector.
    body = struct.pack("<I", 0x05162463) + nonce + b"s" * 16
    body += b"\x08" + b"p" * 8 + b"\0" * 3
    body += struct.pack("<II", 0x1cb5c415, fingerprints)
    body += b"".join(struct.pack("<Q", 0x12345678 + i) for i in range(fingerprints))
    return struct.pack("<QQI", 0, 1700000001 << 32 | 1, len(body)) + body + b"x" * padding


class FakeConnection:
    def __init__(self, wire):
        self.wire = wire
        self.sent = b""
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def sendall(self, wire):
        self.sent += wire

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, count):
        value, self.wire = self.wire[:min(count, 3)], self.wire[min(count, 3):]
        return value


class ModuleSecurityTests(unittest.TestCase):
    def test_config_contract_is_pinned_and_strict(self):
        self.assertEqual(mt._validate_config(config()), config())
        for key, value in (("schema", True), ("schema", 2), ("managed_by", "foreign"),
                           ("commit", "HEAD"), ("port", 443), ("stats_port", 0),
                           ("security_patch", "unknown"), ("server", "127.0.0.1"),
                           ("binary_sha256", []), ("module_sha256", "X" * 64),
                           ("patch_sha256", "bad"), ("created_at", True)):
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                mt._validate_config({**config(), key: value})

    def test_read_only_snapshot_never_reads_secret_or_probes(self):
        with patch.object(mt, "_config", return_value=config()), \
             patch.object(mt, "_service_state", return_value="active"), \
             patch.object(mt, "_stats", return_value={"total_ready_targets": 2}), \
             patch.object(mt, "_secret", side_effect=AssertionError("secret read")), \
             patch.object(mt, "health_probe", side_effect=AssertionError("active probe")):
            value = mt.snapshot()
        self.assertTrue(value["installed"])
        self.assertTrue(value["upstream_ready"])
        self.assertNotIn("secret=", json.dumps(value))
        self.assertNotIn(SECRET, json.dumps(value))

    def test_uninstalled_and_unreadable_snapshot_are_redacted(self):
        for error, expected in ((FileNotFoundError(SECRET), "not_installed"),
                                (ValueError(SECRET), "configuration_unavailable")):
            with patch.object(mt, "_config", side_effect=error), patch.object(mt, "_service_state", return_value="unknown"):
                value = mt.snapshot()
            self.assertFalse(value["installed"])
            self.assertEqual(value["status"], expected)
            self.assertNotIn(SECRET, json.dumps(value))

    def test_owner_links_are_explicit_padded_mtproto(self):
        with patch.object(mt, "_config", return_value=config()), patch.object(mt, "_secret", return_value=SECRET):
            links = mt.owner_connection_links()
        self.assertEqual(set(links), {"telegram", "https"})
        self.assertEqual(links["telegram"], f"tg://proxy?server={mt.PUBLIC_HOST}&port=3443&secret=dd{SECRET}")
        self.assertTrue(links["https"].startswith("https://t.me/proxy?"))

    def test_fixed_service_commands_and_no_arbitrary_action(self):
        for action in ("start", "stop", "restart"):
            with patch.object(mt, "_config", return_value=config()), \
                 patch.object(mt.subprocess, "run", return_value=Mock(returncode=0)) as run, \
                 patch.object(mt, "snapshot", return_value={"installed": True}):
                self.assertTrue(mt.control(action)["ok"])
                self.assertEqual(run.call_args.args[0], ["systemctl", action, mt.SERVICE])
                self.assertLessEqual(run.call_args.kwargs["timeout"], 30)
        for action in ("reload", "stop; rm", "../service", ["stop"]):
            with self.assertRaises(ValueError):
                mt.control(action)

    def test_service_state_filters_unexpected_stdout(self):
        for raw, expected in (("active\n", "active"), (SECRET, "unknown")):
            with patch.object(mt.subprocess, "run", return_value=Mock(stdout=raw)):
                self.assertEqual(mt._service_state(), expected)

    def test_bounded_private_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "value"
            file.write_bytes(b"test")  # Test-only fixture, never product artifacts.
            self.assertEqual(mt._read_bytes(file, 4), b"test")
            with self.assertRaises(RuntimeError):
                mt._read_bytes(file, 3)
            with self.assertRaises((OSError, RuntimeError)):
                mt._read_bytes(Path(directory), 100)

    def test_systemd_credentials_support_root_acl_readonly_mount_not_loose_private_files(self):
        for uid, gid, mode in ((0, 0, 0o440), (0, 0, 0o400), (996, 987, 0o400)):
            info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)
            self.assertTrue(mt._credential_permissions(info, 996, 987, True))
            self.assertFalse(mt._credential_permissions(info, 996, 987, False))
        for uid, gid, mode in ((1, 0, 0o440), (0, 1, 0o440), (0, 0, 0o444),
                               (996, 987, 0o600), (0, 0, 0o640), (0, 0, 0o450)):
            info = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)
            self.assertFalse(mt._credential_permissions(info, 996, 987, True))

    def test_stats_allowlist_numeric_values_only(self):
        response_object = Mock(status=200)
        response_object.read.return_value = (f"total_ready_targets 2\ntot_forwarded_queries 13\n"
                                             f"secret {SECRET}\nuptime secret\nmtproto_proxy_errors -1\n").encode()
        response_object.__enter__ = Mock(return_value=response_object)
        response_object.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response_object
        with patch.object(mt.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(mt._stats(), {"total_ready_targets": 2, "tot_forwarded_queries": 13})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:18888/stats")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 2)

    def test_no_redirect_stats_and_body_limit(self):
        with self.assertRaises(mt.urllib.error.HTTPError):
            mt._NoRedirect().redirect_request(Mock(full_url="fixed"), None, 302, "Moved", {}, "https://secret.invalid")
        response_object = Mock(status=200)
        response_object.read.return_value = b"x" * 131073
        response_object.__enter__ = Mock(return_value=response_object)
        response_object.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response_object
        with patch.object(mt.urllib.request, "build_opener", return_value=opener), self.assertRaises(RuntimeError):
            mt._stats()


class ProtocolTests(unittest.TestCase):
    def test_aes_ctr_known_vector_and_frame_bound(self):
        key, iv, plain = b"\0" * 32, b"\0" * 16, b"\0" * 16
        cipher = bytes.fromhex("dc95c078a2408989ad48a21492842087")
        self.assertEqual(mt._aes_ctr(plain, key, iv), cipher)
        self.assertEqual(mt._aes_ctr(cipher, key, iv), plain)
        with self.assertRaises(RuntimeError):
            mt._aes_ctr(b"x" * 65537, key, iv)

    def test_request_obfuscation_keys_nonce_and_real_padded_message(self):
        initial = bytearray(range(64))
        initial[56:60] = b"\xdd" * 4
        initial[60:62] = struct.pack("<h", 2)
        with patch.object(mt.os, "urandom", side_effect=[bytes(range(64)), NONCE, b"p" * 12]), \
             patch.object(mt.time, "time", return_value=1700000000):
            wire, key, iv, nonce = mt._request(SECRET)
        enc_key = hashlib.sha256(bytes(initial[8:40]) + bytes.fromhex(SECRET)).digest()
        reverse = bytes(initial)[::-1]
        self.assertEqual(key, hashlib.sha256(reverse[8:40] + bytes.fromhex(SECRET)).digest())
        self.assertEqual(iv, reverse[40:56])
        self.assertEqual(nonce, NONCE)
        decoded = mt._aes_ctr(bytes(initial[:56]) + wire[56:], enc_key, bytes(initial[40:56]))
        self.assertEqual(decoded[56:64], bytes(initial[56:64]))
        packet_size = struct.unpack_from("<I", decoded, 64)[0]
        self.assertEqual(packet_size, len(decoded) - 68)
        packet = decoded[68:]
        self.assertEqual(packet[:8], b"\0" * 8)
        self.assertEqual(struct.unpack_from("<Q", packet, 8)[0] % 4, 0)
        self.assertEqual(struct.unpack_from("<I", packet, 16)[0], 20)
        self.assertEqual(packet[20:24], struct.pack("<I", 0xbe7e8ef1))
        self.assertEqual(packet[24:40], NONCE)
        self.assertEqual(packet[40:], b"p" * 12)

    def test_entropy_rejects_reserved_prefixes(self):
        bad = b"GET " + b"x" * 60
        with patch.object(mt.os, "urandom", return_value=bad), self.assertRaisesRegex(RuntimeError, "entropy"):
            mt._request(SECRET)

    def test_response_validates_nonce_constructor_length_and_tl_vector(self):
        mt._validate_response(response(), NONCE)
        malformed = []
        for offset in (0, 16, 20, 24, 56, 68, 72):
            packet = bytearray(response())
            packet[offset] ^= 255
            malformed.append(bytes(packet))
        malformed += [response(b"X" * 16), b"short", response(padding=1040)]
        for packet in malformed:
            with self.subTest(packet=packet[:25]), self.assertRaises(RuntimeError):
                mt._validate_response(packet, NONCE)

    def test_real_res_pq_three_fingerprints_and_payload_padding(self):
        # Metadata from the real forwarded response: 155 bytes, TL body80,
        # fingerprints3, matching nonce and 55 bytes of combined padding.
        packet = response(padding=55, fingerprints=3)
        self.assertEqual(len(packet), 155)
        self.assertEqual(struct.unpack_from('<I', packet, 16)[0], 80)
        mt._validate_response(packet, NONCE)

    def protocol_probe(self, endpoint, good=True):
        key, iv = b"k" * 32, b"i" * 16
        packet = response(NONCE if good else b"X" * 16)
        wire = mt._aes_ctr(struct.pack("<I", len(packet)) + packet, key, iv)
        connection = FakeConnection(wire)
        with patch.object(mt, "_request", return_value=(b"request", key, iv, NONCE)), \
             patch.object(mt.socket, "create_connection", return_value=connection) as connect:
            value = mt._probe_endpoint(SECRET, endpoint)
        self.assertEqual(connect.call_args.args[0], (endpoint, 3443))
        self.assertEqual(connection.sent, b"request")
        self.assertTrue(all(0 < seconds <= 6 for seconds in connection.timeouts))
        return value

    def test_local_and_external_real_nonce_success(self):
        for endpoint in ("127.0.0.1", mt.PUBLIC_HOST):
            proof = self.protocol_probe(endpoint)
            self.assertTrue(proof["ok"])
            self.assertEqual(proof["status"], "protocol_confirmed")

    def test_wrong_nonce_fails_and_does_not_leak_credentials(self):
        proof = self.protocol_probe(mt.PUBLIC_HOST, False)
        self.assertFalse(proof["ok"])
        self.assertEqual(proof["failure_code"], "telegram_nonce_not_confirmed")
        self.assertNotIn(SECRET, json.dumps(proof))
        with patch.object(mt.socket, "create_connection", side_effect=RuntimeError(SECRET)):
            self.assertNotIn(SECRET, json.dumps(mt.external_health_probe(SECRET)))

    def test_public_probe_cannot_probe_arbitrary_hosts(self):
        for endpoint in ("example.org", "10.0.0.1", "::1", "150.241.96.190"):
            with self.assertRaises(ValueError):
                mt._probe_endpoint(SECRET, endpoint)
        for secret in ("", "z" * 32, "a" * 33, None):
            with patch.object(mt.socket, "create_connection") as socket_call:
                self.assertFalse(mt.external_health_probe(secret)["ok"])
                socket_call.assert_not_called()

    def test_probe_requires_safe_config_and_updates_cached_redacted_result(self):
        with patch.object(mt, "_config", return_value=config()), patch.object(mt, "_secret", return_value=SECRET), \
             patch.object(mt, "_probe_endpoint", return_value={"ok": True, "status": "protocol_confirmed"}) as probe:
            value = mt.health_probe()
        self.assertEqual(mt._LAST_PROBE, value)
        probe.assert_called_once_with(SECRET, "127.0.0.1")
        with patch.object(mt, "_config", side_effect=RuntimeError(SECRET)):
            value = mt.health_probe()
        self.assertFalse(value["ok"])
        self.assertNotIn(SECRET, json.dumps(value))

    def test_receive_eof_deadline_and_bounded_reads(self):
        with self.assertRaises(RuntimeError):
            mt._receive_exact(FakeConnection(b""), 4, mt.time.monotonic() + 1)
        with self.assertRaises(TimeoutError):
            mt._receive_exact(FakeConnection(b"1234"), 4, mt.time.monotonic() - 1)


class InstallerTests(unittest.TestCase):
    def test_unit_runs_unprivileged_with_private_credentials_and_resource_caps(self):
        unit = REMOTE["unit_text"]()
        for item in ("User=qvpn-mtproto", "NoNewPrivileges=true", "ProtectSystem=strict",
                     "ProtectHome=true", "LoadCredential=client-secret:", "MemoryMax=512M",
                     "CPUQuota=75%", "LimitCORE=0", "PrivateDevices=true", "CapabilityBoundingSet=\n"):
            self.assertIn(item, unit)
        self.assertNotIn(SECRET, unit)
        self.assertNotIn(" -S ", unit)
        self.assertNotIn("ExecStart=/bin/sh", unit)

    def test_service_launcher_does_not_put_secret_in_argv(self):
        credentials = f"/run/credentials/{mt.SERVICE}"
        binary = b"binary"
        conf = {**config(), "binary_sha256": hashlib.sha256(binary).hexdigest()}
        def local_read(path, *args, **kwargs):
            return {"runtime-config": json.dumps(conf).encode(), "client-secret": SECRET.encode(),
                    "mtproto-proxy": binary}[path.name]
        with patch.dict(mt.os.environ, {"CREDENTIALS_DIRECTORY": credentials}), \
             patch.object(mt, "Path", PurePosixPath), \
             patch.object(mt.os, "geteuid", return_value=123, create=True), \
             patch.object(mt, "_read_bytes", side_effect=local_read), patch.object(mt.os, "execv") as execute:
            mt.serve()
        args = execute.call_args.args[1]
        self.assertIn("--secret-file", args)
        self.assertNotIn("-S", args)
        self.assertNotIn(SECRET, " ".join(args))
        self.assertEqual(args[args.index("--secret-file") + 1], credentials + "/client-secret")

    def test_service_launcher_refuses_non_systemd_credentials(self):
        for credentials in ("", "relative", "/tmp/quantumvpn-mtproto.service", "/run/credentials/other.service"):
            with patch.dict(mt.os.environ, {"CREDENTIALS_DIRECTORY": credentials}), self.assertRaises(RuntimeError):
                mt.serve()

    def test_security_patch_has_fixed_private_path_and_strict_file_contract(self):
        patch_case = REMOTE["PATCH_CASE"]
        for item in ("O_NOFOLLOW", "S_ISREG", "info.st_uid == geteuid", "info.st_mode & 0777",
                     "fstatvfs", "ST_RDONLY", "info.st_uid == 0 && info.st_gid == 0",
                     "info.st_size != 33", "got != 33", "memset (value, 0", "f_parse_option ('S')",
                     "/run/credentials/quantumvpn-mtproto.service/client-secret"):
            self.assertIn(item, patch_case)
        self.assertIn("case 3000:", patch_case)
        self.assertEqual(json.loads(REMOTE["patch_manifest"]())["id"], mt.SECURITY_PATCH)
        self.assertEqual(hashlib.sha256(REMOTE["patch_manifest"]()).hexdigest(), mt.SECURITY_PATCH_SHA256)

    def test_patch_applies_exactly_once_to_the_expected_base_anchors(self):
        sample = ("#include <assert.h>\nvoid f() {\n  case 'S':\n  case 'P':\n}\n"
                  '  parse_option ("mtproto-secret", required_argument, 0, \'S\', "16-byte secret in hex mode");\n')
        value = REMOTE["patch_source"](sample)
        self.assertEqual(value.count(REMOTE["PATCH_CASE"]), 1)
        self.assertEqual(value.count(REMOTE["PATCH_OPTION"]), 1)
        self.assertIn("#include <fcntl.h>", value)
        for invalid in (value, sample + sample, sample.replace("case 'S'", "case 'Z'")):
            with self.assertRaises(RuntimeError):
                REMOTE["patch_source"](invalid)

    def test_port_guards_account_for_ipv4_ipv6_and_refuse_occupied(self):
        output = "LISTEN 0 128 0.0.0.0:3443 0.0.0.0:*\nLISTEN 0 64 [::1]:18888 [::]:*\n"
        self.assertEqual(REMOTE["ports_in_use"](output), {3443, 18888})
        old = REMOTE["run"]
        try:
            REMOTE["run"] = Mock(return_value=output)
            with self.assertRaises(RuntimeError):
                REMOTE["require_free_ports"]()
        finally:
            REMOTE["run"] = old

    def test_official_download_redirects_are_host_and_https_limited(self):
        redirect = REMOTE["OfficialRedirect"]()
        for target in ("http://core.telegram.org/x", "https://other.invalid/x", "https://core.telegram.org.evil.invalid/x"):
            with self.assertRaises(RuntimeError):
                redirect.redirect_request(None, None, 302, "move", {}, target)

    def test_stats_listener_must_actually_be_loopback_only(self):
        old = REMOTE["run"]
        try:
            REMOTE["run"] = Mock(return_value="LISTEN 0 128 127.0.0.1:18888 0.0.0.0:*\n")
            REMOTE["verify_stats_listener"]()
            for output in ("", "LISTEN 0 128 0.0.0.0:18888 0.0.0.0:*\n",
                           "LISTEN 0 128 [::]:18888 [::]:*\n"):
                REMOTE["run"] = Mock(return_value=output)
                with self.assertRaises(RuntimeError):
                    REMOTE["verify_stats_listener"]()
        finally:
            REMOTE["run"] = old

    def test_installer_is_explicit_pinned_and_does_not_reconfigure_existing_services(self):
        self.assertIn("parser.add_argument(\"--apply\", action=\"store_true\")", Path(installer.__file__).read_text())
        self.assertIn("paramiko.RejectPolicy()", Path(installer.__file__).read_text())
        self.assertIn("QVPN_VDS_PASSWORD", Path(installer.__file__).read_text())
        self.assertIn("fetch','--depth','1','origin',COMMIT", installer.REMOTE)
        for forbidden in ("iptables", "ufw", "sysctl -w", "systemctl','restart','rospanel", "systemctl','restart','nginx"):
            self.assertNotIn(forbidden, installer.REMOTE)

    def test_existing_apply_keeps_an_owner_stopped_service_stopped(self):
        code = installer.REMOTE
        existing = code[code.index("    if existing:\n"):code.index("    if missing and not INSTALL_DEPS")]
        self.assertIn("service_state_preserved", existing)
        self.assertNotIn("systemctl", existing)

    def test_server_command_errors_have_safe_stage_not_raw_output(self):
        with patch.object(REMOTE['subprocess'], 'run', return_value=Mock(returncode=1, stdout=SECRET)):
            with self.assertRaisesRegex(RuntimeError, '^server_command_failed_systemctl_start$'):
                REMOTE['run'](['systemctl','start',SECRET])
        with self.assertRaisesRegex(RuntimeError, '^invalid_command_stage$'):
            REMOTE['run'](['systemctl'], stage='invalid arbitrary secret stage')

    def test_failed_new_install_has_recoverable_rollback_and_bound_cleanup(self):
        self.assertIn("rollback_created(created)", installer.REMOTE)
        self.assertIn("path.rename(destination/recovery_names[path])", installer.REMOTE)
        self.assertIn("recovery_names={ROOT:'runtime',PRIVATE:'private'", installer.REMOTE)
        self.assertIn("rollback_target_not_managed", installer.REMOTE)
        self.assertIn("rollback_identity_changed_manual_review_required", installer.REMOTE)
        self.assertIn("rollback_unit_changed_manual_review_required", installer.REMOTE)
        self.assertIn("target.parent!=Path('/var/tmp')", installer.REMOTE)
        self.assertNotIn("shutil.rmtree(ROOT)", installer.REMOTE)
        self.assertNotIn("shutil.rmtree(PRIVATE)", installer.REMOTE)


if __name__ == "__main__":
    unittest.main()
