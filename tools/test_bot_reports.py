"""Hourly report captions and factual, non-repetitive notification evidence."""
import copy
import json
import sqlite3
import unittest

import quantumvpn_bot_status as bot


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "generated_at": 1791302700,
            "ai": {"enabled": True, "model": "qwen3:0.6b", "engine": "llama.cpp", "provider": "qwen", "last_status": "готов", "catalogue_available": True, "loaded": True, "memory_bytes": 600000000, "active_requests": 0, "instruction_present": True},
            "server": {"cpu_percent": 12.5, "memory_percent": 24.8, "disk_percent": 41, "memory_total_bytes": 4 * 1024**3, "network_status": "healthy", "services": {"operator": "active", "rospanel": "active", "xray": "active", "llama_cpp": "active", "ollama": "inactive"}},
            "backup": {"exists": True, "ts": 1791302400, "size_bytes": 1400000, "hourly_enabled": True, "last_delivery_ok": True},
            "release": {"version": "5.11.3", "scheduled_enabled": False},
        }

    def test_caption_attached_report_description_moscow_bounded_and_private(self):
        self.snapshot["ai"]["advice"] = "**SECRET_MODEL_TEXT**"
        self.snapshot["backup"]["path"] = "/SECRET_PATH"
        self.snapshot["token"] = "SECRET_TOKEN"
        text = bot.format_backup_caption(self.snapshot)
        self.assertIn("часовая резервная копия", text)
        self.assertIn("МСК", text)
        self.assertIn("1.3 МБ", text)
        self.assertIn("llama.cpp", text)
        self.assertIn("в ответе к этому файлу", text)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("**", text)
        self.assertLessEqual(len(text.encode("utf-16-le")) // 2, 1024)
        self.assertIn("ручная", bot.format_backup_caption(self.snapshot, "manual"))

    def test_full_report_uses_actual_runtime_and_controlled_action_evidence(self):
        self.snapshot["automation"] = {"enabled": True, "mode": "bounded", "actions_24h": 3, "last_action": "node_restored", "last_result": "verified"}
        text = bot.format_status(self.snapshot)
        self.assertIn("llama.cpp: ✅ работает", text)
        self.assertNotIn("Ollama:", text)
        self.assertIn("Действий за 24 ч: 3", text)
        self.assertIn("нода возвращена · проверено", text)
        self.assertNotIn("**", text)
        self.assertIn("/help", text)
        self.assertLessEqual(len(text.encode("utf-16-le")) // 2, 4096)

    def test_applied_change_waiting_for_evidence_is_not_labelled_verified(self):
        self.snapshot["automation"] = {"enabled": True, "mode": "bounded", "actions_24h": 1, "last_action": "recommendation_changed", "last_result": "verifying"}
        text = bot.format_status(self.snapshot)
        self.assertIn("ожидаются контрольные проверки", text)
        self.assertNotIn("обновлена рекомендация · проверено", text)
        self.assertNotIn("действие не применено", text)
        database = sqlite3.connect(":memory:")
        try:
            result = bot.collect_status(database, {}, runtime={"automation": self.snapshot["automation"]}, now=1791302700)
            self.assertEqual("verifying", result["automation"]["last_result"])
        finally:
            database.close()

    def test_extreme_valid_report_retains_every_command_in_bounds(self):
        self.snapshot["ai"].update(model="x" * 80, observations_30d=2**63 - 1, succeeded_30d=2**63 - 1, last_run=253402290000)
        self.snapshot["release"].update(version="1" * 40, version_code=2**63 - 1, protocols_enabled=2**63 - 1, protocols_total=2**63 - 1, scheduled_enabled=True, scheduled_version="2" * 40, scheduled_at=253402290000)
        self.snapshot["automation"] = {"enabled": True, "mode": "bounded", "actions_24h": 2**63 - 1, "last_action": "recommendation_changed", "last_result": "verifying"}
        for section, fields in (("server", ("health_checks_24h",)), ("delivery", ("notification_received", "download_complete", "install_handoff", "app_started")), ("support", ("open_threads",))):
            self.snapshot.setdefault(section, {}).update({field: 2**63 - 1 for field in fields})
        text = bot.format_status(self.snapshot)
        self.assertLessEqual(len(text), bot.MAX_STATUS_CHARS)
        self.assertLessEqual(len(text.encode("utf-16-le")) // 2, 4096)
        for command in ("/status", "/ai_status", "/check_updates", "/get_stable", "/get_dev", "/backups", "/help"):
            self.assertIn(command, text)
        self.assertTrue(text.endswith("/backups — состояние копий · /help — помощь"))

    def test_normal_analysis_is_quiet_and_raw_prose_never_notify(self):
        initial = bot.fact_alert(self.snapshot)
        self.assertFalse(initial["should_notify"])
        self.assertEqual(initial["message"], "")
        self.snapshot["ai"]["advice"] = "**NEW SECRET FORMULATION**"
        self.snapshot["generated_at"] += 3600
        unchanged = bot.fact_alert(self.snapshot, initial["fingerprint"])
        self.assertFalse(unchanged["should_notify"])
        self.assertEqual(initial["fingerprint"], unchanged["fingerprint"])

    def test_real_issue_changes_alert_once_without_numeric_chatter(self):
        previous = bot.notification_fingerprint(self.snapshot)
        self.snapshot["server"]["disk_percent"] = 86
        alert = bot.fact_alert(self.snapshot, previous)
        self.assertTrue(alert["should_notify"])
        self.assertEqual(alert["issues"], ["disk_percent"])
        self.assertIn("86%", alert["message"])
        self.snapshot["server"]["disk_percent"] = 87.8
        self.snapshot["ai"]["advice"] = "other text"
        again = bot.fact_alert(self.snapshot, alert["fingerprint"])
        self.assertFalse(again["should_notify"])
        self.assertEqual(alert["fingerprint"], again["fingerprint"])

    def test_network_issue_honest_scope_and_known_recovery(self):
        self.snapshot["server"]["network_status"] = "degraded"
        alert = bot.fact_alert(self.snapshot)
        self.assertIn("Причина сбоя пока не установлена", alert["message"])
        self.assertIn("с VDS", alert["message"])
        self.snapshot["server"]["network_status"] = "healthy"
        recovered = bot.fact_alert(self.snapshot, alert["fingerprint"])
        self.assertTrue(recovered["should_notify"])
        self.assertTrue(recovered["recovery"])
        self.assertIn("восстановились", recovered["message"])

    def test_missing_evidence_cannot_assert_recovery_or_failure(self):
        self.snapshot["server"]["network_status"] = "degraded"
        previous = bot.notification_fingerprint(self.snapshot)
        for missing in ({}, {"server": {"network_status": "healthy"}}, {"server": {"cpu_percent": float("nan")}}):
            result = bot.fact_alert(missing, previous)
            self.assertFalse(result["recovery"])
            self.assertFalse(result["should_notify"])
            self.assertFalse(result["issues"])

    def test_backups_and_local_engine_failures_not_invented(self):
        self.snapshot["backup"]["last_delivery_ok"] = False
        self.snapshot["backup"]["ts"] -= 3 * 3600
        self.snapshot["server"]["services"]["llama_cpp"] = "failed"
        alert = bot.fact_alert(self.snapshot)
        self.assertEqual(set(alert["issues"]), {"service_llama_cpp", "backup_stale", "backup_delivery_failed"})
        self.assertNotIn("service_ollama", alert["issues"])

    def test_untrusted_unknown_model_actions_and_runtime_strings_discarded(self):
        database = sqlite3.connect(":memory:")
        try:
            result = bot.collect_status(database, {"ai_model": "qwen3:0.6b"}, runtime={"automation": {"enabled": True, "mode": "SECRET_SHELL", "last_action": "rm -rf SECRET", "last_result": "SECRET_ERROR"}, "services": {"llama_cpp": "SECRET_OUTPUT"}}, local_model={"engine": "SECRET_CLOUD", "provider": "SECRET", "ready": True}, now=1791302700)
            self.assertNotIn("SECRET", json.dumps(result))
            self.assertIsNone(result["automation"]["last_action"])
            self.assertIsNone(result["server"]["services"]["llama_cpp"])
        finally:
            database.close()

    def test_malformed_nested_direct_snapshots_do_not_raise_or_leak(self):
        broken = copy.deepcopy(self.snapshot)
        broken["server"]["network_status"] = {"status": "SECRET"}
        broken["ai"]["model"] = "SECRET\u202e"
        broken["automation"] = {"enabled": True, "mode": [], "last_action": {}, "last_result": []}
        for text in (bot.format_status(broken), bot.format_backup_caption(broken), bot.fact_alert(broken)["message"]):
            self.assertNotIn("SECRET", text)


if __name__ == "__main__":
    unittest.main()
