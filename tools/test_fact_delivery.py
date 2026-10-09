"""Actual panel delivery function + SQLite + pure factual adapters, without I/O.

Compile the four real functions from the panel AST instead of importing its
startup environment or generating production keys. Only Telegram and runtime
collection are mocked; ledger writes, commits, confirmation and formatting are
the implementation used by the live worker.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import sqlite3
import threading
import time
import unittest
from unittest.mock import Mock

from tools import quantumvpn_bot_operations as operations
from tools import quantumvpn_bot_status as status


def delivery_namespace():
    source = Path(__file__).with_name("quantumvpn_operator_panel.py").read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    names = {"settings", "set_settings", "enabled", "send_factual_alert"}
    functions = [item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name in names]
    if len(functions) != len(names):
        raise AssertionError("Expected the four real panel delivery functions")
    namespace = {"json": json, "time": time, "bot_status": status,
                 "bot_operations": operations, "_ALERT_STATE": {"confirmation": {}, "lock": threading.Lock()},
                 "telegram_send": Mock(return_value=True), "operations_status_snapshot": Mock()}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "<panel-delivery-functions>", "exec"), namespace)
    return namespace


def healthy_snapshot(now):
    return {"generated_at": now,
            "server": {"cpu_percent": 12, "memory_percent": 25, "disk_percent": 40,
                       "services": {"operator": "active", "rospanel": "active", "xray": "active"},
                       "network_status": "healthy"},
            "ai": {"enabled": False}, "backup": {"hourly_enabled": False}}


class FactDeliveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.ns = delivery_namespace()
        self.send = self.ns["telegram_send"]
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.executescript("""
            create table settings(key text primary key,value text);
            create table events(ts integer,kind text,source text,device text,detail text);
        """)
        self.put(telegram_alerts_enabled="1", ai_telegram_enabled="1")

    def tearDown(self):
        self.db.close()

    def put(self, **values):
        self.ns["set_settings"](self.db, values)
        self.db.commit()

    def stored(self):
        return self.ns["settings"](self.db)

    def delivered(self, *issues):
        ledger = {"schema": 1, "open": list(issues)}
        self.put(bot_fact_state=json.dumps(ledger, separators=(",", ":")),
                 bot_fact_last_hash=status._issue_fingerprint(issues))
        return self.stored()["bot_fact_state"], self.stored()["bot_fact_last_hash"]

    def observe(self, now, *, disk=40, xray="active", snapshot=None):
        value = healthy_snapshot(now) if snapshot is None else copy.deepcopy(snapshot)
        if snapshot is None:
            value["server"]["disk_percent"] = disk
            value["server"]["services"]["xray"] = xray
        return self.ns["send_factual_alert"](self.db, now=now, snapshot=value)

    def ledger(self):
        values = self.stored()
        return values.get("bot_fact_state"), values.get("bot_fact_last_hash")

    def test_initial_bad_samples_do_not_save_an_unconfirmed_incident(self):
        for stamp in (1000, 1060):
            self.assertFalse(self.observe(stamp, disk=91))
            self.assertEqual(json.loads(self.ledger()[0]), {"schema": 1, "open": []})
            self.assertEqual(self.ledger()[1], status._issue_fingerprint(()))
        self.send.assert_not_called()
        self.assertTrue(self.observe(1120, disk=91))
        self.assertEqual(json.loads(self.ledger()[0])["open"], ["disk_percent"])
        self.send.assert_called_once()

    def test_failed_telegram_preserves_delivered_state_and_hash_until_retry(self):
        baseline = self.delivered()
        self.send.return_value = False
        for stamp in (1000, 1060, 1120):
            self.assertFalse(self.observe(stamp, disk=91))
        self.assertEqual(self.ledger(), baseline)
        self.assertEqual(self.stored()["bot_fact_last_attempt"], "1120")
        self.assertNotIn("bot_fact_last_sent", self.stored())
        self.send.assert_called_once()
        detail = json.loads(self.db.execute("select detail from events").fetchone()[0])
        self.assertFalse(detail["sent"])
        self.assertEqual(detail["transition"], "incident")
        self.send.return_value = True
        self.assertTrue(self.observe(1180, disk=91))
        self.assertEqual(self.stored()["bot_fact_last_sent"], "1180")
        self.assertEqual(json.loads(self.ledger()[0])["open"], ["disk_percent"])
        self.assertEqual(self.send.call_count, 2)
        self.assertFalse(self.observe(1240, disk=94))
        self.assertEqual(self.send.call_count, 2)

    def test_cooldown_never_acknowledges_changed_unsent_candidate(self):
        baseline = self.delivered()
        self.put(bot_fact_last_sent="1110")
        for stamp in (1000, 1060, 1120, 1150):
            self.assertFalse(self.observe(stamp, disk=91))
        self.assertEqual(self.ledger(), baseline)
        self.assertNotIn("bot_fact_last_attempt", self.stored())
        self.send.assert_not_called()
        self.assertTrue(self.observe(1170, disk=91))
        self.send.assert_called_once()
        self.assertEqual(json.loads(self.ledger()[0])["open"], ["disk_percent"])

    def test_failed_attempt_cooldown_does_not_discard_pending_notification(self):
        baseline = self.delivered()
        self.send.return_value = False
        for stamp in (1000, 1060, 1120, 1130, 1179):
            self.assertFalse(self.observe(stamp, disk=91))
        self.assertEqual(self.ledger(), baseline)
        self.send.assert_called_once()
        self.send.return_value = True
        self.assertTrue(self.observe(1180, disk=91))
        self.assertEqual(self.send.call_count, 2)

    def test_partial_recovery_acknowledged_only_after_successful_delivery(self):
        previous = self.delivered("disk_percent", "service_xray")
        self.send.return_value = False
        for stamp in (1000, 1060, 1120):
            self.assertFalse(self.observe(stamp, disk=40, xray="failed"))
        self.assertEqual(self.ledger(), previous)
        self.send.assert_called_once()
        self.assertIn("частичное восстановление", self.send.call_args.args[1])
        self.assertIn("VPN Xray: ошибка службы", self.send.call_args.args[1])
        self.send.return_value = True
        self.assertTrue(self.observe(1180, disk=40, xray="failed"))
        self.assertEqual(json.loads(self.ledger()[0]), {"schema": 1, "open": ["service_xray"]})
        self.assertEqual(self.ledger()[1], status._issue_fingerprint(["service_xray"]))
        self.assertFalse(self.observe(1240, disk=40, xray=None))
        self.assertEqual(json.loads(self.ledger()[0])["open"], ["service_xray"])
        self.assertEqual(self.send.call_count, 2)

    def test_unknown_cannot_announce_recovery_or_erase_an_open_incident(self):
        previous = self.delivered("service_xray")
        for stamp in (1000, 1060, 1120, 1180):
            self.assertFalse(self.observe(stamp, xray=None))
            self.assertEqual(self.ledger(), previous)
        self.send.assert_not_called()
        self.assertEqual(self.db.execute("select count(*) from events").fetchone()[0], 0)

    def test_quiet_healthy_or_missing_initial_baseline_is_safe(self):
        self.assertFalse(self.observe(1000, snapshot={"generated_at": 1000}))
        self.assertEqual(json.loads(self.ledger()[0]), {"schema": 1, "open": []})
        self.assertEqual(self.ledger()[1], status._issue_fingerprint(()))
        for stamp in (1060, 1120, 1180):
            self.assertFalse(self.observe(stamp))
        self.send.assert_not_called()
        self.assertNotIn("bot_fact_last_sent", self.stored())
        self.assertNotIn("bot_fact_last_attempt", self.stored())

    def test_missing_telemetry_cannot_materialize_or_overwrite_opaque_legacy_hash(self):
        previous_hash = status._issue_fingerprint(["service_xray"])
        self.put(ai_last_notification_hash=previous_hash)
        before = self.stored()
        for stamp in (1000, 1060, 1120):
            self.assertFalse(self.observe(stamp, snapshot={"generated_at": stamp}))
        self.assertEqual(self.stored(), before)
        self.send.assert_not_called()

    def test_full_recovery_requires_three_healthy_samples_and_successful_send(self):
        previous = self.delivered("service_xray")
        for stamp in (1000, 1060):
            self.assertFalse(self.observe(stamp))
            self.assertEqual(self.ledger(), previous)
        self.assertTrue(self.observe(1120))
        self.assertEqual(json.loads(self.ledger()[0]), {"schema": 1, "open": []})
        self.assertIn("проверки восстановились", self.send.call_args.args[1])

    def test_parallel_callers_send_changed_facts_only_once(self):
        self.delivered()
        self.observe(1000, disk=91)
        self.observe(1060, disk=91)
        entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
        results, errors = [], []

        def telegram(settings, message):
            entered.set()
            if not release.wait(timeout=2):
                raise AssertionError("Bounded test release not signaled")
            return True

        def run(second=False):
            if second:
                second_started.set()
            try:
                results.append(self.observe(1120, disk=91))
            except Exception as error:
                errors.append(type(error).__name__)

        self.send.side_effect = telegram
        first = threading.Thread(target=run)
        second = threading.Thread(target=run, args=(True,))
        first.start()
        self.assertTrue(entered.wait(timeout=2))
        second.start()
        self.assertTrue(second_started.wait(timeout=2))
        release.set()
        first.join(timeout=3)
        second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [False, True])
        self.send.assert_called_once()
        self.assertEqual(self.db.execute("select count(*) from events").fetchone()[0], 1)

    def test_disabled_alerts_cannot_collect_runtime_send_or_change_ledger(self):
        self.put(telegram_alerts_enabled="0")
        before = self.stored()
        self.assertFalse(self.ns["send_factual_alert"](self.db, now=1000))
        self.ns["operations_status_snapshot"].assert_not_called()
        self.send.assert_not_called()
        self.assertEqual(self.stored(), before)

    def test_ai_notification_opt_out_never_clears_an_open_ai_fault(self):
        self.put(ai_telegram_enabled="0")
        previous = self.delivered("analysis_error")
        value = healthy_snapshot(1000)
        value["ai"] = {"enabled": True, "provider": "gemini", "last_status": "готов"}
        for stamp in (1000, 1060, 1120):
            value["generated_at"] = stamp
            self.assertFalse(self.observe(stamp, snapshot=value))
        self.assertEqual(self.ledger(), previous)
        self.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
