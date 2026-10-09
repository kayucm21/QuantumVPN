"""Offline bounded upstream refresh/security tests; no VDS or real service calls."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tools import quantumvpn_mtproto as mt


SPEC = importlib.util.spec_from_file_location("refresh_mtproto", Path(__file__).with_name("refresh-mtproto-upstream.py"))
refresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh)
SECRET = bytes(range(128))
NEW_SECRET = bytes(reversed(range(128)))
CONFIG = b"# force_probability 10 10\ndefault 2;\nproxy_for 2 149.154.161.144:8888;\nproxy_for -203 91.105.192.110:443;\n"
NEW_CONFIG = CONFIG + b"proxy_for 4 91.108.4.182:8888;\n"
HEALTH = {"ok": True, "method": "mtproto_req_pq_multi", "upstream_ready_count": 3}


class FormatAndDownloadTests(unittest.TestCase):
    def test_official_signed_dc_configuration_and_binary_key(self):
        refresh.validate_secret(SECRET)
        refresh.validate_secret(b"<" + SECRET[1:])  # Any first byte is valid binary key material.
        self.assertEqual(refresh.validate_config(CONFIG), 2)
        self.assertEqual(refresh.validate_config(NEW_CONFIG), 3)
        self.assertEqual(refresh.validate_config(CONFIG + b"proxy_for -2 [2001:4860:4860::8888]:443;\n"), 3)

    def test_refuses_non_global_and_noncanonical_endpoints(self):
        for endpoint in ("127.0.0.1:443", "10.0.0.1:443", "100.64.0.1:443", "169.254.1.1:443",
                         "0.0.0.0:443", "192.0.2.1:443", "198.51.100.1:443", "203.0.113.1:443",
                         "224.0.0.1:443", "255.255.255.255:443", "[::1]:443", "[fe80::1]:443",
                         "[fc00::1]:443", "[ff02::1]:443", "[::ffff:8.8.8.8]:443",
                         "[2001:4860:4860:0:0:0:0:8888]:443", "08.8.8.8:443",
                         "example.org:443", "8.8.8.8:65536", "8.8.8.8:0"):
            with self.subTest(endpoint=endpoint), self.assertRaises(refresh.Refused):
                refresh.validate_config(b"default 2;\nproxy_for 2 " + endpoint.encode() + b";\n")

    def test_rejects_unknown_directives_size_duplicates_missing_dc_and_control_bytes(self):
        for invalid in (b"", b"x" * 65537, CONFIG + b"proxy_for 2 149.154.161.144:8888;\n",
                        CONFIG + b"default 2;\n", CONFIG + b"listen 0.0.0.0:443;\n",
                        CONFIG + b"maxconn 2048;\n", CONFIG.replace(b"default 2;", b"default 3;"),
                        CONFIG.replace(b"proxy_for 2", b"proxy_for 3"), CONFIG + b"\x00",
                        CONFIG + b"#\xff", CONFIG + b"#" + b"a" * 512,
                        CONFIG.replace(b"proxy_for 2", b"proxy_for 0"),
                        CONFIG.replace(b"proxy_for 2", b"proxy_for 1000")):
            with self.subTest(invalid=invalid[:32]), self.assertRaises(refresh.Refused):
                refresh.validate_config(invalid)
        for invalid in (b"", SECRET[:-1], SECRET + b"x", b"x" * 128):
            with self.assertRaises(refresh.Refused):
                refresh.validate_secret(invalid)

    def test_http_download_uses_fixed_https_tls_direct_route_and_small_read(self):
        response = Mock(status=200)
        response.geturl.return_value = "https://core.telegram.org/getProxySecret"
        response.headers = {}
        response.read.return_value = SECRET
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(refresh.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(refresh.fetch_official("proxy-secret"), SECRET)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertTrue(handlers[1]._context.check_hostname)
        self.assertEqual(handlers[1]._context.verify_mode, refresh.ssl.CERT_REQUIRED)
        self.assertIsInstance(handlers[2], refresh.NoRedirect)
        self.assertEqual(opener.open.call_args.args[0].full_url, "https://core.telegram.org/getProxySecret")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
        response.read.assert_called_once_with(129)

    def test_all_redirects_wrong_final_url_encoding_failure_and_oversize_refused(self):
        for url in ("https://core.telegram.org/getProxySecret", "https://evil.invalid/", "http://core.telegram.org/"):
            with self.assertRaisesRegex(refresh.Refused, "official_redirect_refused"):
                refresh.NoRedirect().redirect_request(Mock(), None, 302, "Moved", {}, url)
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(refresh.urllib.request, "build_opener", return_value=opener):
            for status, final, headers, data in ((301, "https://core.telegram.org/getProxySecret", {}, SECRET),
                    (200, "https://evil.invalid/", {}, SECRET),
                    (200, "https://core.telegram.org/getProxySecret", {"Content-Encoding": "gzip"}, SECRET),
                    (200, "https://core.telegram.org/getProxySecret", {}, SECRET + b"x")):
                response.status, response.headers = status, headers
                response.geturl.return_value, response.read.return_value = final, data
                with self.assertRaises(refresh.Refused):
                    refresh.fetch_official("proxy-secret")
            opener.open.side_effect = RuntimeError(SECRET.hex())
            with self.assertRaisesRegex(refresh.Refused, "^official_download_failed$"):
                refresh.fetch_official("proxy-secret")
        with self.assertRaisesRegex(refresh.Refused, "official_endpoint_refused"):
            refresh.fetch_official("getProxySecret?arbitrary")


class OwnershipAndProofTests(unittest.TestCase):
    def test_exact_private_permissions_root_owner_regular_file_and_no_hardlinks(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1)
        refresh._metadata(good, mode=0o600)
        for change in ({"st_mode": stat.S_IFREG | 0o640}, {"st_mode": stat.S_IFLNK | 0o600},
                       {"st_uid": 1}, {"st_gid": 1}, {"st_nlink": 2}):
            with self.assertRaises(refresh.Refused):
                refresh._metadata(SimpleNamespace(**{**vars(good), **change}), mode=0o600)
        with patch.object(refresh, "_parents"), patch.object(refresh.Path, "is_symlink", return_value=True), \
             patch.object(refresh.os, "open") as opening, self.assertRaises(refresh.Refused):
            refresh.read_file(Path("/fixed/private/value"), 128)
        opening.assert_not_called()

    def test_pinned_helper_and_unit_rejected_before_any_execution(self):
        with patch.object(refresh, "directory"), patch.object(refresh, "read_file", return_value=b"untrusted"), \
             patch("builtins.exec") as execute, self.assertRaisesRegex(refresh.Refused, "pinned_helper_or_unit_mismatch"):
            refresh.owned_install()
        execute.assert_not_called()
        self.assertEqual(refresh.sha256(Path(mt.__file__).read_bytes()), refresh.MODULE_SHA256)

    def test_owned_install_pins_binary_configuration_patch_and_client_secret(self):
        binary, unit = b"test binary", b"test unit"
        config = {"schema": 1, "managed_by": "quantumvpn", "commit": mt.COMMIT,
                  "security_patch": mt.SECURITY_PATCH, "server": mt.PUBLIC_HOST,
                  "port": mt.PUBLIC_PORT, "stats_port": mt.STATS_PORT, "created_at": 1700000000,
                  "binary_sha256": refresh.sha256(binary), "module_sha256": refresh.MODULE_SHA256,
                  "patch_sha256": mt.SECURITY_PATCH_SHA256, "source_file_sha256": mt.BASE_SOURCE_SHA256}
        files = {"quantumvpn_mtproto.py": Path(mt.__file__).read_bytes(),
                 "quantumvpn-mtproto.service": unit, "mtproto-proxy": binary,
                 "security-patch.json": b"patch", "mtproto-proxy-base.c": b"base",
                 "config.json": json.dumps(config).encode(), "client-secret": b"a" * 32 + b"\n",
                 "proxy-secret": SECRET, "proxy-multi.conf": CONFIG}
        real_hash = refresh.sha256
        def fixture_hash(data):
            return {b"patch": mt.SECURITY_PATCH_SHA256, b"base": mt.BASE_SOURCE_SHA256}.get(data, real_hash(data))
        with patch.object(refresh, "directory"), \
             patch.object(refresh, "read_file", side_effect=lambda path, *args: files[path.name]), \
             patch.object(refresh, "UNIT_SHA256", real_hash(unit)), patch.object(refresh, "sha256", side_effect=fixture_hash):
            self.assertEqual(refresh.owned_install()["fixed"]["mtproto-proxy"], real_hash(binary))
            files["mtproto-proxy"] = b"replaced binary"
            with self.assertRaisesRegex(refresh.Refused, "pinned_install_identity_mismatch"):
                refresh.owned_install()
            files["mtproto-proxy"] = binary
            files["client-secret"] = b"client key must stay private"
            with self.assertRaisesRegex(refresh.Refused, "client_secret_format_refused"):
                refresh.owned_install()
            files["client-secret"] = b"a" * 32 + b"\n"
            files["config.json"] = json.dumps({**config, "module_sha256": "b" * 64}).encode()
            with self.assertRaisesRegex(refresh.Refused, "configuration_helper_identity_mismatch"):
                refresh.owned_install()

    def test_nonce_and_upstream_count_required_without_key_arguments(self):
        health = {"ok": True, "method": "mtproto_req_pq_multi", "status": "protocol_confirmed"}
        module = {"health_probe": Mock(return_value=health), "_stats": Mock(return_value={"total_ready_targets": 2})}
        with patch.object(refresh.subprocess, "run") as command:
            self.assertEqual(refresh.proof(module), {**HEALTH, "upstream_ready_count": 2})
            encrypted = module["_aes_ctr"](b"\0" * 16, b"\0" * 32, b"\0" * 16)
        self.assertEqual(encrypted.hex(), "dc95c078a2408989ad48a21492842087")
        command.assert_not_called()
        for value in ({"ok": True, "status": "TCP_connected"}, {**health, "ok": False}):
            module["health_probe"].return_value = value
            with self.assertRaisesRegex(refresh.Refused, "genuine_loopback_nonce_not_confirmed"):
                refresh.proof(module)
        module["health_probe"].return_value = health
        for count in (0, -1, None, True, "1"):
            module["_stats"].return_value = {"total_ready_targets": count}
            with self.assertRaisesRegex(refresh.Refused, "upstream_targets_not_ready"):
                refresh.proof(module)

    def test_missing_in_process_crypto_never_calls_helper_fallback(self):
        module = {"health_probe": Mock()}
        with patch.dict(sys.modules, {"cryptography.hazmat.primitives.ciphers": None}), \
             self.assertRaisesRegex(refresh.Refused, "in_process_crypto_required"):
            refresh.proof(module)
        module["health_probe"].assert_not_called()

    def test_service_runtime_overrides_stopped_state_or_public_stats_refused(self):
        values = {"ActiveState": "active", "FragmentPath": str(refresh.UNIT), "DropInPaths": "",
                  "NeedDaemonReload": "no", "User": "qvpn-mtproto", "Group": "qvpn-mtproto", "MainPID": "123"}
        listeners = "LISTEN 0 128 127.0.0.1:18888 0.0.0.0:*\n"
        def output(changed=None):
            return "\n".join(key + "=" + value for key, value in {**values, **(changed or {})}.items())
        with patch.object(refresh.Path, "resolve", return_value=refresh.ROOT / "mtproto-proxy"), \
             patch.object(refresh, "_command", side_effect=[output(), listeners]):
            refresh.verify_service()
        for key, value in (("ActiveState", "inactive"), ("FragmentPath", "/tmp/service"),
                           ("DropInPaths", "/etc/systemd/system/override.conf"), ("NeedDaemonReload", "yes"),
                           ("User", "root"), ("MainPID", "0")):
            with patch.object(refresh, "_command", return_value=output({key: value})), self.assertRaises(refresh.Refused):
                refresh.verify_service()
        with patch.object(refresh.Path, "resolve", return_value=refresh.ROOT / "mtproto-proxy"), \
             patch.object(refresh, "_command", side_effect=[output(), listeners.replace("127.0.0.1", "0.0.0.0")]), \
             self.assertRaisesRegex(refresh.Refused, "stats_listener_not_exclusively_loopback"):
            refresh.verify_service()

    def test_cli_errors_suppress_unknown_text_and_credentials(self):
        output = io.StringIO()
        with patch.object(refresh.os, "name", "posix"), patch.object(refresh.os, "geteuid", return_value=0, create=True), \
             patch.object(refresh.signal, "signal"), patch.object(refresh.signal, "alarm", create=True), \
             patch.object(refresh.signal, "SIGALRM", 14, create=True), \
             patch.object(sys, "argv", ["refresh"]), \
             patch.object(refresh, "inspect_or_refresh", side_effect=RuntimeError(SECRET.hex())), \
             redirect_stdout(output), self.assertRaises(SystemExit):
            refresh.main()
        self.assertEqual(json.loads(output.getvalue()), {"status": "Failed", "reason": "bounded_refresh_failed"})

    def test_apply_preflight_refuses_unowned_install_before_creating_any_lock_or_backup(self):
        output = io.StringIO()
        with patch.object(refresh.os, "name", "posix"), patch.object(refresh.os, "geteuid", return_value=0, create=True), \
             patch.object(refresh.signal, "signal"), patch.object(refresh.signal, "alarm", create=True), \
             patch.object(refresh.signal, "SIGALRM", 14, create=True), \
             patch.object(sys, "argv", ["refresh", "--apply"]), \
             patch.object(refresh, "owned_install", side_effect=refresh.Refused("pinned_install_identity_mismatch")), \
             patch.object(refresh, "refresh_lock") as lock, redirect_stdout(output), self.assertRaises(SystemExit):
            refresh.main()
        lock.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["reason"], "pinned_install_identity_mismatch")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.private, self.backups = root / "private", root / "state" / "backups"
        self.private.mkdir()
        self.backups.mkdir(parents=True)
        (self.private / "proxy-secret").write_bytes(SECRET)
        (self.private / "proxy-multi.conf").write_bytes(CONFIG)
        self.fixed = {"config.json": "a" * 64, "client-secret": "b" * 64}
        self.stack.enter_context(patch.object(refresh, "PRIVATE", self.private))
        self.stack.enter_context(patch.object(refresh, "BACKUPS", self.backups))
        # Windows has no POSIX uid/mode/fsync-directory/fchmod contract. Security
        # predicates are tested separately; transaction IO remains real here.
        self.stack.enter_context(patch.object(refresh, "_metadata"))
        self.stack.enter_context(patch.object(refresh, "_sync_dir"))
        if not hasattr(os, "fchmod"):
            self.stack.enter_context(patch.object(refresh.os, "fchmod", create=True))
        self.install = self.stack.enter_context(patch.object(refresh, "owned_install", side_effect=self.current_install))
        self.service = self.stack.enter_context(patch.object(refresh, "verify_service"))
        self.proof = self.stack.enter_context(patch.object(refresh, "proof", return_value=HEALTH))
        self.command = self.stack.enter_context(patch.object(refresh, "_command", return_value=""))
        self.fresh = {"proxy-secret": NEW_SECRET, "proxy-multi.conf": NEW_CONFIG}
        self.download = self.stack.enter_context(patch.object(refresh, "fetch_official", side_effect=lambda name: self.fresh[name]))

    def current_install(self):
        return {"fixed": dict(self.fixed), "module": {},
                "upstream": {name: (self.private / name).read_bytes() for name in refresh.UPSTREAM_FILES}}

    def old_restored(self):
        self.assertEqual((self.private / "proxy-secret").read_bytes(), SECRET)
        self.assertEqual((self.private / "proxy-multi.conf").read_bytes(), CONFIG)
        self.assertFalse((self.backups / "pending.json").exists())

    def test_default_inspection_and_identical_apply_never_write_or_restart(self):
        with patch.object(refresh, "atomic_write") as write:
            report = refresh.inspect_or_refresh()
            self.assertEqual(report["status"], "ReadOnly")
            self.assertTrue(report["would_change"])
            write.assert_not_called()
        self.fresh = {"proxy-secret": SECRET, "proxy-multi.conf": CONFIG}
        self.assertEqual(refresh.inspect_or_refresh(True)["status"], "Unchanged")
        self.command.assert_not_called()
        self.proof.assert_not_called()
        self.assertEqual(list(self.backups.iterdir()), [])
        self.assertNotIn(SECRET.hex(), json.dumps(report))

    def test_verified_change_atomic_private_backup_and_only_one_owned_restart(self):
        report = refresh.inspect_or_refresh(True)
        self.assertEqual(report["status"], "Updated")
        self.assertEqual((self.private / "proxy-secret").read_bytes(), NEW_SECRET)
        self.assertEqual((self.private / "proxy-multi.conf").read_bytes(), NEW_CONFIG)
        self.command.assert_called_once_with(["systemctl", "restart", refresh.SERVICE], timeout=30)
        self.assertEqual(self.proof.call_count, 2)
        saved = self.backups / report["backup"]
        self.assertEqual((saved / "proxy-secret").read_bytes(), SECRET)
        self.assertEqual((saved / "proxy-multi.conf").read_bytes(), CONFIG)
        self.assertFalse((self.backups / "pending.json").exists())
        self.assertNotIn(SECRET.hex(), json.dumps(report))
        self.assertEqual(set(path.name for path in saved.iterdir()), set(refresh.UPSTREAM_FILES))

    def test_failed_prechange_nonce_or_invalid_official_data_prevents_all_writes(self):
        self.proof.side_effect = refresh.Refused("genuine_loopback_nonce_not_confirmed")
        with self.assertRaises(refresh.Refused):
            refresh.inspect_or_refresh(True)
        self.assertEqual(list(self.backups.iterdir()), [])
        self.proof.side_effect = None
        self.fresh["proxy-multi.conf"] = CONFIG + b"include /tmp/secret;\n"
        with self.assertRaises(refresh.Refused):
            refresh.inspect_or_refresh(True)
        self.command.assert_not_called()

    def test_failed_second_replace_rolls_back_partial_pair_and_retains_backup(self):
        original_write = refresh.atomic_write
        def fail_new_config(path, data):
            if path == self.private / "proxy-multi.conf" and data == NEW_CONFIG:
                raise OSError("raw details suppressed")
            return original_write(path, data)
        with patch.object(refresh, "atomic_write", side_effect=fail_new_config), \
             self.assertRaisesRegex(refresh.Refused, "^refresh_failed_rolled_back$"):
            refresh.inspect_or_refresh(True)
        self.old_restored()
        self.command.assert_called_once_with(["systemctl", "restart", refresh.SERVICE], timeout=30)
        self.assertEqual(len(list(self.backups.iterdir())), 1)

    def test_failed_post_nonce_restores_old_pair_and_restarts_then_confirms_old(self):
        self.proof.side_effect = [HEALTH, refresh.Refused("nonce_failed"), HEALTH]
        with patch.object(refresh.time, "monotonic", side_effect=[0, 41, 82]), \
             self.assertRaisesRegex(refresh.Refused, "^refresh_failed_rolled_back$"):
            refresh.inspect_or_refresh(True)
        self.old_restored()
        self.assertEqual(self.command.call_count, 2)
        self.assertEqual(self.proof.call_count, 3)

    def pending(self, phase="applying"):
        name = "txn-20261009120000-0123456789abcdef"
        folder = self.backups / name
        folder.mkdir()
        (folder / "proxy-secret").write_bytes(SECRET)
        (folder / "proxy-multi.conf").write_bytes(CONFIG)
        journal = {"schema": 1, "phase": phase, "backup": name, "fixed": self.fixed,
                   "old": {"proxy-secret": refresh.sha256(SECRET), "proxy-multi.conf": refresh.sha256(CONFIG)},
                   "new": {key: refresh.sha256(value) for key, value in self.fresh.items()}}
        refresh._journal_write(journal)
        return journal

    def test_crash_between_replacements_recovers_before_any_new_download(self):
        self.pending()
        (self.private / "proxy-secret").write_bytes(NEW_SECRET)
        result = refresh.inspect_or_refresh(True)
        self.assertEqual(result["status"], "Recovered")
        self.old_restored()
        self.download.assert_not_called()
        self.command.assert_called_once_with(["systemctl", "restart", refresh.SERVICE], timeout=30)

    def test_prepared_crash_without_file_changes_requires_no_restart(self):
        self.pending("prepared")
        self.assertEqual(refresh.inspect_or_refresh(True)["status"], "Recovered")
        self.old_restored()
        self.command.assert_not_called()

    def test_external_modification_refuses_recovery_instead_of_overwriting(self):
        self.pending()
        external = bytes(range(1, 129))
        (self.private / "proxy-secret").write_bytes(external)
        with self.assertRaisesRegex(refresh.Refused, "recovery_file_identity_mismatch"):
            refresh.inspect_or_refresh(True)
        self.assertEqual((self.private / "proxy-secret").read_bytes(), external)
        self.assertTrue((self.backups / "pending.json").exists())
        self.command.assert_not_called()

    def test_failed_rollback_keeps_durable_journal_for_manual_or_next_apply_recovery(self):
        self.command.side_effect = refresh.Refused("bounded_service_command_failed")
        with self.assertRaisesRegex(refresh.Refused, "rollback_incomplete_pending_recovery_kept"):
            refresh.inspect_or_refresh(True)
        self.assertEqual((self.private / "proxy-secret").read_bytes(), SECRET)
        self.assertEqual((self.private / "proxy-multi.conf").read_bytes(), CONFIG)
        self.assertIsNotNone(refresh._journal_read())

    def test_journal_path_traversal_refused_and_atomic_stage_cleaned_on_failed_replace(self):
        journal = self.pending()
        journal["backup"] = "../../other"
        refresh._journal_write(journal)
        with self.assertRaisesRegex(refresh.Refused, "pending_journal_invalid"):
            refresh._journal_read()
        with patch.object(refresh.os, "replace", side_effect=OSError("failed")), self.assertRaises(OSError):
            refresh.atomic_write(self.private / "proxy-secret", NEW_SECRET)
        self.assertEqual((self.private / "proxy-secret").read_bytes(), SECRET)
        self.assertEqual(set(path.name for path in self.private.iterdir()), set(refresh.UPSTREAM_FILES))

    def test_lock_is_nonblocking_and_refuses_insecure_existing_lock(self):
        fcntl = Mock(LOCK_EX=2, LOCK_NB=4)
        with patch.dict(sys.modules, {"fcntl": fcntl}):
            with refresh.refresh_lock():
                pass
            fcntl.flock.assert_called_once()
            self.assertEqual(fcntl.flock.call_args.args[1], 6)
            fcntl.flock.side_effect = BlockingIOError()
            with self.assertRaisesRegex(refresh.Refused, "another_refresh_in_progress"):
                with refresh.refresh_lock():
                    self.fail("must not enter")
            fcntl.flock.reset_mock()
            with patch.object(refresh, "_private_store"), \
                 patch.object(refresh, "_metadata", side_effect=refresh.Refused("unsafe_owned_path")), \
                 self.assertRaisesRegex(refresh.Refused, "unsafe_owned_path"):
                with refresh.refresh_lock():
                    self.fail("must not enter insecure lock")
            fcntl.flock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
