"""Offline adapter tests: no live VDS, Telegram account, secret or client changes."""
from __future__ import annotations

import json
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock, patch

from tools import quantumvpn_proxy_monitor as monitor


def good(name):
    status = {"installed": True, "service": "active", "upstream_ready": True,
              "runtime_ready": True, "secret": "DO_NOT_PUBLISH"}
    proof = {"ok": True, "status": "protocol_confirmed", "method": monitor._TRANSPORTS[name][1],
             "fake_tls_authenticated": True, "telegram_nonce_confirmed": True,
             "tls_confirmed": True, "bridge_confirmed": True, "session_confirmed": True,
             "endpoint": "public_https", "link": "DO_NOT_PUBLISH"}
    return SimpleNamespace(snapshot=Mock(return_value=status), health_probe=Mock(return_value=proof))


class ProxyMonitorTests(unittest.TestCase):
    def setUp(self):
        self.saved = monitor._CACHE, monitor._CACHE_TICK
        monitor._CACHE, monitor._CACHE_TICK = {}, None
        self.runtimes = {name: good(name) for name in monitor._TRANSPORTS}
        self.stack = []

    def tearDown(self):
        monitor._CACHE, monitor._CACHE_TICK = self.saved
        for entered in reversed(self.stack):
            entered.stop()

    def helpers(self):
        runtime = patch.object(monitor, "_runtime", side_effect=self.runtimes.__getitem__)
        isolation = patch.object(monitor, "_listener_isolation", return_value={name: True for name in self.runtimes})
        self.stack.extend((runtime, isolation))
        return runtime.start(), isolation.start()

    def test_cold_snapshot_and_scope_do_not_import_probe_or_run_command(self):
        with patch.object(monitor, "_runtime", side_effect=AssertionError("import")), \
                patch.object(monitor.subprocess, "run", side_effect=AssertionError("command")):
            value = monitor.snapshot()
            scope = monitor.evidence_scope()
        self.assertEqual(set(value), {"mtproto", "native_tls", "web"})
        self.assertTrue(all(item["ready"] is None and item["stage"] == "not_checked" for item in value.values()))
        self.assertFalse(scope["client_without_vpn_tested"])
        self.assertFalse(scope["account_authorization_tested"])
        self.assertFalse(scope["blocker_cause_proven"])

    def test_success_requires_actual_matching_nonce_contract(self):
        self.helpers()
        value = monitor.refresh()
        self.assertTrue(all(item["ready"] is True and item["stage"] == "telegram" for item in value.values()))
        expected = {"service", "checked_at", "stage", "protocol", "ready", "isolation_verified"}
        self.assertTrue(all(set(item) == expected for item in value.values()))
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(value))
        for name, runtime in self.runtimes.items():
            runtime.snapshot.assert_called_once_with()
            runtime.health_probe.assert_called_once_with()
            self.assertEqual(value[name]["protocol"], monitor._TRANSPORTS[name][1])

    def test_ttl_caps_even_repeated_failed_refreshes(self):
        self.helpers()
        self.runtimes["mtproto"].health_probe.side_effect = RuntimeError("DO_NOT_PUBLISH")
        with patch.object(monitor.time, "monotonic", return_value=100):
            first = monitor.refresh()
        self.assertIsNone(first["mtproto"]["ready"])
        with patch.object(monitor.time, "monotonic", return_value=399):
            for _ in range(25):
                monitor.refresh()
        self.runtimes["mtproto"].health_probe.assert_called_once()
        with patch.object(monitor.time, "monotonic", return_value=400):
            stale = monitor.snapshot()
            self.assertEqual(stale["mtproto"]["stage"], "not_checked")
            self.assertIsNone(stale["mtproto"]["ready"])
            self.assertEqual(stale["mtproto"]["service"], "unknown")
            monitor.refresh()
        self.assertEqual(self.runtimes["mtproto"].health_probe.call_count, 2)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(stale))

    def test_unknown_or_absent_upstream_never_becomes_ready(self):
        self.helpers()
        self.runtimes["mtproto"].snapshot.return_value["upstream_ready"] = None
        self.runtimes["native_tls"].snapshot.return_value["upstream_ready"] = False
        self.runtimes["web"].snapshot.return_value["runtime_ready"] = 1
        value = monitor.refresh()
        self.assertIsNone(value["mtproto"]["ready"])
        self.assertFalse(value["native_tls"]["ready"])
        self.assertIsNone(value["web"]["ready"])

    def test_tls_looking_or_bridge_only_reply_is_not_nonce_success(self):
        self.helpers()
        self.runtimes["native_tls"].health_probe.return_value["telegram_nonce_confirmed"] = False
        self.runtimes["web"].health_probe.return_value["telegram_nonce_confirmed"] = False
        value = monitor.refresh()
        self.assertFalse(value["native_tls"]["ready"])
        self.assertEqual(value["native_tls"]["stage"], "tls")
        self.assertFalse(value["web"]["ready"])
        self.assertEqual(value["web"]["stage"], "bridge")

    def test_wrong_method_status_or_public_web_endpoint_is_rejected(self):
        for name, change in (("mtproto", {"method": "DO_NOT_PUBLISH"}),
                             ("native_tls", {"status": "active"}),
                             ("web", {"endpoint": "loopback"})):
            with self.subTest(name=name), patch.object(monitor, "_runtime", return_value=good(name)):
                runtime = monitor._runtime(name)
                runtime.health_probe.return_value.update(change)
                with patch.object(monitor, "_runtime", return_value=runtime):
                    item = monitor._observe(name, True)
                self.assertFalse(item["ready"])
                self.assertNotIn("DO_NOT_PUBLISH", json.dumps(item))

    def test_inactive_service_or_missing_install_skips_secret_bearing_probe(self):
        self.helpers()
        self.runtimes["mtproto"].snapshot.return_value["service"] = "inactive"
        self.runtimes["native_tls"].snapshot.return_value["installed"] = False
        self.runtimes["web"].snapshot.side_effect = RuntimeError("DO_NOT_PUBLISH")
        value = monitor.refresh()
        self.assertFalse(value["mtproto"]["ready"])
        self.assertFalse(value["native_tls"]["ready"])
        self.assertIsNone(value["web"]["ready"])
        for runtime in self.runtimes.values():
            runtime.health_probe.assert_not_called()
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(value))

    def test_concurrent_refresh_never_waits_or_starts_second_probe(self):
        runtime, _ = self.helpers()
        self.assertTrue(monitor._LOCK.acquire(blocking=False))
        try:
            value = monitor.refresh()
        finally:
            monitor._LOCK.release()
        runtime.assert_not_called()
        self.assertTrue(all(item["ready"] is None for item in value.values()))

    def test_snapshot_is_detached_from_cached_mutable_results(self):
        self.helpers()
        value = monitor.refresh()
        value["mtproto"]["ready"] = False
        self.assertTrue(monitor.snapshot()["mtproto"]["ready"])

    def test_listener_isolation_checks_all_fixed_private_ports(self):
        lines = "\n".join("LISTEN 0 128 127.0.0.1:%s 0.0.0.0:*" % port
                          for port in (18888, 18889, 18082, 18083))
        with patch.object(monitor.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=lines)) as command:
            self.assertEqual(monitor._listener_isolation(), {name: True for name in self.runtimes})
        self.assertEqual(command.call_args.args[0], ["ss", "-H", "-ltn"])
        self.assertEqual(command.call_args.kwargs["timeout"], 3)
        with patch.object(monitor.subprocess, "run", return_value=SimpleNamespace(returncode=0,
                          stdout=lines.replace("127.0.0.1:18888", "0.0.0.0:18888")
                          + "\nLISTEN 0 128 [::]:18083 [::]:*")):
            value = monitor._listener_isolation()
        self.assertFalse(value["mtproto"])
        self.assertFalse(value["web"])
        self.assertTrue(value["native_tls"])

    def test_isolation_errors_unknown_and_missing_listener_false(self):
        for response in (SimpleNamespace(returncode=1, stdout="DO_NOT_PUBLISH"),
                         SimpleNamespace(returncode=0, stdout="x" * 65537)):
            with patch.object(monitor.subprocess, "run", return_value=response):
                self.assertTrue(all(value is None for value in monitor._listener_isolation().values()))
        with patch.object(monitor.subprocess, "run", side_effect=RuntimeError("DO_NOT_PUBLISH")):
            self.assertTrue(all(value is None for value in monitor._listener_isolation().values()))
        with patch.object(monitor.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")):
            self.assertTrue(all(value is False for value in monitor._listener_isolation().values()))

    def test_advisory_requires_explicit_primary_failure_and_proven_reserve(self):
        self.assertIsNone(monitor.advisory(monitor.snapshot()))
        self.helpers()
        self.runtimes["mtproto"].health_probe.return_value.update(ok=False, status="protocol_failed")
        value = monitor.refresh()
        advice = monitor.advisory(value)
        self.assertEqual(advice["code"], "try_native_tls")
        self.assertFalse(advice["account_authorization_tested"])
        self.assertNotIn("secret", json.dumps(advice))
        value["native_tls"]["ready"] = None
        self.assertIsNone(monitor.advisory(value))


if __name__ == "__main__":
    unittest.main()
