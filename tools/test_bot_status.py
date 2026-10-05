"""Offline status facts, private command admission and payload privacy tests."""
import json
import sqlite3
import unittest

import quantumvpn_bot_status as bot


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.now = 1800000000
        self.db.executescript("""
            create table ai_observations (ts integer,status text,advice text);
            create table server_health (ts integer,ok integer,latency_ms integer,target text);
            create table audit (ts integer,action text,detail text);
            create table protocols (name text,enabled integer);
            create table community_delivery (device text,version_code integer,stage text,ts integer);
            create table community_threads (state text,device text,subject text);
        """)
        self.settings = {
            "ai_advisor_enabled": "1", "ai_model": "qwen3:0.6b", "ai_last_status": "готов",
            "ai_last_run": str(self.now - 60), "app_version": "5.11.2", "app_version_code": "501102099",
            "rollout_percent": "100", "update_notifications_enabled": "1", "maintenance": "0",
            "maintenance_schedule_enabled": "0", "maintenance_start": "0", "maintenance_end": "0",
            "public_download_enabled": "1", "release_schedule_enabled": "1",
            "scheduled_app_version": "5.11.3", "release_publish_at": str(self.now + 3600),
            "telegram_backups_enabled": "1", "telegram_alerts_enabled": "1",
            "telegram_bot_token": "SECRET_TOKEN", "totp_secret": "SECRET_TOTP",
            "telegram_chat_id": "8898492653", "subscription_url": "https://secret.invalid/sub/SECRET_SUB",
            "ai_last_advice": "SECRET_ADVICE", "ai_last_error": "SECRET_ERROR",
        }
        self.runtime = {
            "cpu_percent": 12.5, "memory_percent": 31.2, "disk_percent": 57,
            "memory_total_bytes": 4 * 1024**3, "active_ai_requests": 1,
            "system_instruction": True, "polling": True, "webhook": False,
            "services": {"operator": "active", "rospanel": "active", "xray": "active", "ollama": "active"},
            "backup": {"exists": True, "ts": self.now - 900, "size": 1024**2, "name": "SECRET_PATH"},
            "webhook_url": "SECRET_WEBHOOK", "errors": "SECRET_RUNTIME_ERROR",
        }
        self.model = {"ready": True, "loaded": False, "memory_bytes": 0, "error": "SECRET_MODEL_ERROR"}

    def tearDown(self):
        self.db.close()

    def snapshot(self):
        return bot.collect_status(self.db, self.settings, self.runtime, self.model, self.now)

    def test_actual_aggregates_and_retention_window(self):
        self.db.executemany("insert into ai_observations values (?,?,?)", [
            (self.now - 1, "готов", "secret"), (self.now - 2, "ошибка", "secret"),
            (self.now - 31 * 86400, "готов", "old"), (self.now + 1, "готов", "future"),
        ])
        self.db.executemany("insert into server_health values (?,?,?,?)", [
            (self.now - 1, 1, 40, "IP_SECRET"), (self.now - 2, 1, 60, "IP_SECRET"),
            (self.now - 3, 0, 0, "IP_SECRET"), (self.now - 4, 1, 0, "IP_SECRET"),
            (self.now - 90000, 1, 999, "old"),
        ])
        self.db.executemany("insert into protocols values (?,?)", [("vless", 1), ("hy2", 1), ("trojan", 0)])
        result = self.snapshot()
        self.assertEqual(result["ai"]["observations_30d"], 2)
        self.assertEqual(result["ai"]["succeeded_30d"], 1)
        self.assertEqual(result["ai"]["success_percent"], 50)
        self.assertEqual(result["server"]["health_checks_24h"], 4)
        self.assertEqual(result["server"]["health_ok_percent_24h"], 75)
        self.assertEqual(result["server"]["mean_latency_ms"], 50)
        self.assertEqual(result["release"]["protocols_enabled"], 2)

    def test_no_empty_metric_success_percentage(self):
        result = self.snapshot()
        self.assertIsNone(result["ai"]["success_percent"])
        self.assertIsNone(result["server"]["health_ok_percent_24h"])
        self.assertIsNone(result["server"]["mean_latency_ms"])
        self.assertEqual(result["ai"]["observations_30d"], 0)

    def test_missing_schema_and_runtime_stay_unknown(self):
        db = sqlite3.connect(":memory:")
        try:
            result = bot.collect_status(db, {}, now=self.now)
            self.assertIsNone(result["ai"]["observations_30d"])
            self.assertIsNone(result["server"]["cpu_percent"])
            self.assertIsNone(result["backup"]["exists"])
            self.assertIsNone(result["delivery"]["app_started"])
            self.assertIn("CPU: нет данных", bot.format_status(result))
        finally:
            db.close()

    def test_delivery_distinct_devices_current_version_not_install_claim(self):
        self.db.executemany("insert into community_delivery values (?,?,?,?)", [
            ("SECRET_DEVICE_A", 501102099, "install_handoff", self.now),
            ("SECRET_DEVICE_A", 501102099, "install_handoff", self.now - 1),
            ("SECRET_DEVICE_B", 501102099, "app_started", self.now),
            ("SECRET_DEVICE_C", 501103099, "app_started", self.now),
            ("SECRET_DEVICE_D", 501102099, "app_started", self.now - 8 * 86400),
        ])
        result = self.snapshot()
        self.assertEqual(result["delivery"]["install_handoff"], 1)
        self.assertEqual(result["delivery"]["app_started"], 1)
        text = bot.format_status(result)
        self.assertIn("открытие установщика ≠ установка", text)
        self.assertNotIn("SECRET_DEVICE", text)

    def test_latest_backup_delivery_failed_not_old_success(self):
        self.db.executemany("insert into audit values (?,?,?)", [
            (self.now - 10, "hourly_backup", json.dumps({"ok": True, "file": "SECRET_FILE"})),
            (self.now - 5, "backup_now", json.dumps({"ok": False, "file": "SECRET_FILE"})),
        ])
        result = self.snapshot()
        self.assertFalse(result["backup"]["last_delivery_ok"])
        self.assertEqual(result["backup"]["last_delivery_at"], self.now - 5)
        self.assertNotIn("SECRET_FILE", json.dumps(result))

    def test_corrupt_or_untyped_backup_delivery_is_unknown(self):
        for detail in ("{", "[]", '{"ok":1}', '{"ok":"1"}', "x" * 4097):
            self.db.execute("delete from audit")
            self.db.execute("insert into audit values (?,?,?)", (self.now, "backup_now", detail))
            self.assertIsNone(self.snapshot()["backup"]["last_delivery_ok"])

    def test_private_fields_not_returned_or_rendered(self):
        result = self.snapshot()
        self.assertNotIn("SECRET_", json.dumps(result))
        self.assertNotIn("SECRET_", bot.format_status(result))
        self.assertNotIn("8898492653", bot.format_status(result))
        self.assertNotIn("gemini", bot.format_status(result).lower())

    def test_no_sqlite_writes(self):
        before = self.db.total_changes
        self.snapshot()
        self.assertEqual(before, self.db.total_changes)

    def test_configured_installed_and_loaded_are_separate(self):
        text = bot.format_status(self.snapshot())
        self.assertIn("Модель: qwen3:0.6b", text)
        self.assertIn("Модель установлена: ✅ включено", text)
        self.assertIn("В RAM: ⏸ выключено", text)
        self.assertIn("RAM сервера", text)

    def test_maintenance_closes_download_in_report(self):
        self.settings["maintenance"] = "1"
        self.assertIn("Скачивание: ⏸ выключено", bot.format_status(self.snapshot()))

    def test_scheduled_maintenance_and_bad_schedule(self):
        self.settings.update({"maintenance_schedule_enabled": "1", "maintenance_start": str(self.now - 10), "maintenance_end": str(self.now + 10)})
        self.assertTrue(self.snapshot()["release"]["maintenance"])
        self.settings["maintenance_end"] = str(self.now)
        self.assertFalse(self.snapshot()["release"]["maintenance"])
        self.settings["maintenance_end"] = "bad"
        self.assertIsNone(self.snapshot()["release"]["maintenance"])

    def test_wrong_nested_runtime_types_safe_unknown(self):
        self.runtime["services"]["operator"] = {"value": "active"}
        self.settings["ai_last_status"] = []
        result = self.snapshot()
        self.assertIsNone(result["server"]["services"]["operator"])
        self.assertIsNone(result["ai"]["last_status"])
        result["server"]["services"]["operator"] = []
        result["ai"]["last_status"] = {}
        self.assertIn("Доп. панель: нет данных", bot.format_status(result))

    def test_no_embargo_download_url(self):
        self.settings["scheduled_download_url"] = "https://secret.invalid/5.11.3.apk"
        result = self.snapshot()
        text = bot.format_status(result)
        self.assertIn("Запланировано: 5.11.3", text)
        self.assertNotIn("https://", text)
        self.assertNotIn(".apk", text)

    def test_real_percentages_and_invalid_values(self):
        self.runtime.update({"cpu_percent": float("nan"), "memory_percent": 101, "disk_percent": -1})
        result = self.snapshot()
        self.assertIsNone(result["server"]["cpu_percent"])
        self.assertIsNone(result["server"]["memory_percent"])
        self.assertIsNone(result["server"]["disk_percent"])
        self.assertIn("CPU: ▰▱▱▱▱▱▱▱▱▱ 12.5%", bot.format_status(bot.collect_status(self.db, self.settings, {"cpu_percent": 12.5}, now=self.now)))
        self.runtime["cpu_percent"] = 2**10000
        self.assertIsNone(self.snapshot()["server"]["cpu_percent"])

    def test_timestamps_moscow_not_host_timezone(self):
        text = bot.format_status(self.snapshot())
        self.assertIn("15.01.2027 11:00 МСК", text)

    def test_formatter_size_unknown_and_long_name_bounds(self):
        result = self.snapshot()
        self.assertLessEqual(len(bot.format_status(result)), bot.MAX_STATUS_CHARS)
        result["ai"]["model"] = "x" * 10000
        result["release"]["version"] = "<b>SECRET</b>\x00\u202e"
        text = bot.format_status(result)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("\x00", text)
        self.assertNotIn("\u202e", text)
        self.assertLessEqual(len(text), bot.MAX_STATUS_CHARS)
        self.assertIn("/help", text)

    def test_extreme_counters_still_bounded(self):
        result = self.snapshot()
        for area in result.values():
            if isinstance(area, dict):
                for key, value in list(area.items()):
                    if type(value) is int:
                        area[key] = 2**63 - 1
        self.assertLessEqual(len(bot.format_status(result)), bot.MAX_STATUS_CHARS)


class AuthorizationTests(unittest.TestCase):
    def message(self, text="/status"):
        return {"chat": {"id": 12345, "type": "private"}, "from": {"id": 12345, "is_bot": False}, "text": text}

    def test_private_configured_chat_with_same_sender(self):
        self.assertEqual(bot.authorized_command(self.message(), "12345"), "/status")
        self.assertEqual(bot.authorized_command(self.message(), 12345, [12345]), "/status")

    def test_wrong_chat_and_sender_rejected(self):
        self.assertIsNone(bot.authorized_command(self.message(), 12346))
        message = self.message()
        message["from"]["id"] = 999
        self.assertIsNone(bot.authorized_command(message, 12345, [999]))
        self.assertIsNone(bot.authorized_command(self.message(), True))

    def test_group_channel_and_sender_chat_rejected(self):
        for kind in ("group", "supergroup", "channel"):
            message = self.message()
            message["chat"]["type"] = kind
            self.assertIsNone(bot.authorized_command(message, 12345, [12345]))
        message = self.message()
        message["sender_chat"] = {"id": 12345}
        self.assertIsNone(bot.authorized_command(message, 12345))

    def test_forwarded_and_bot_messages_rejected(self):
        for key in ("forward_origin", "forward_from", "forward_from_chat", "forward_date"):
            message = self.message()
            message[key] = {}
            self.assertIsNone(bot.authorized_command(message, 12345))
        message = self.message()
        message["from"]["is_bot"] = True
        self.assertIsNone(bot.authorized_command(message, 12345))

    def test_optional_allowlist_never_broadens_scope(self):
        self.assertIsNone(bot.authorized_command(self.message(), 12345, [999]))
        self.assertIsNone(bot.authorized_command(self.message(), 12345, "12345"))
        self.assertIsNone(bot.authorized_command(self.message(), 999, [12345]))

    def test_command_allowlist_no_mutations(self):
        for command in bot.COMMANDS:
            self.assertEqual(bot.authorized_command(self.message(command), 12345), command)
        for text in ("/backup", "/backup_now", "/ai_analyze", "/clear", "/reload", "/status anything", "x /status", "/status\n/help", "/STATUS", "/status" + "x" * 200):
            self.assertIsNone(bot.authorized_command(self.message(text), 12345))

    def test_command_mentions_match_actual_bot(self):
        message = self.message("/status@QuantumStatusBot")
        self.assertIsNone(bot.authorized_command(message, 12345))
        self.assertIsNone(bot.authorized_command(message, 12345, bot_username="OtherStatusBot"))
        self.assertEqual(bot.authorized_command(message, 12345, bot_username="quantumstatusbot"), "/status")

    def test_malformed_payload(self):
        for message in (None, [], {}, {"chat": []}, {"chat": self.message()["chat"], "from": self.message()["from"], "text": []}):
            self.assertIsNone(bot.authorized_command(message, 12345))

    def test_menu_matches_authorized_readonly_commands(self):
        menu = bot.bot_commands()
        self.assertEqual({"/" + item["command"] for item in menu}, bot.COMMANDS)
        self.assertTrue(all(len(item["description"]) <= 256 for item in menu))
        self.assertTrue(all(not item["command"].startswith("/") for item in menu))
        self.assertIn("ПК и Codex не нужны", bot.command_help())
        self.assertLessEqual(len(bot.command_help()), 3500)
        self.assertNotIn("/backup_now", bot.command_help())


if __name__ == "__main__":
    unittest.main()
