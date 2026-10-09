"""Offline status facts, private command admission and payload privacy tests."""
import json
import copy
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

    def test_ai_error_reason_is_allowlisted_and_not_a_vpn_failure(self):
        self.settings["ai_last_status"] = "ошибка"
        self.settings["ai_last_error"] = "truncated_response"
        snapshot = self.snapshot()
        self.assertEqual(snapshot["ai"]["last_error_code"], "truncated_response")
        status = bot.format_status(snapshot)
        self.assertIn("обрезан лимитом генерации", status)
        alert = bot.fact_alert(snapshot)
        self.assertIn("не подтверждение сбоя VPN", alert["message"])
        self.assertIn("обрезан лимитом генерации", alert["message"])
        self.settings["ai_last_error"] = "invalid_response"
        self.settings["ai_last_error_reason"] = "recommendation_not_allowed"
        snapshot = self.snapshot()
        self.assertIn("вне разрешённого списка", bot.format_status(snapshot))
        self.assertIn("вне разрешённого списка", bot.fact_alert(snapshot)["message"])
        self.settings["ai_last_error"] = "SECRET_KEY /etc/private failure"
        self.settings["ai_last_error_reason"] = "SECRET_MODEL_OUTPUT"
        snapshot = self.snapshot()
        self.assertIsNone(snapshot["ai"]["last_error_code"])
        self.assertIsNone(snapshot["ai"]["last_error_reason"])
        for rendered in (bot.format_status(snapshot), bot.fact_alert(snapshot)["message"]):
            self.assertNotIn("SECRET_KEY", rendered)
            self.assertNotIn("/etc/private", rendered)

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
        self.assertIn("модель выгружена", text)
        self.model.update(loaded=True, memory_bytes=1024**2)
        self.assertIn("RAM сервера", bot.format_status(self.snapshot()))

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


    def test_archive_encryption_is_observed_not_inferred_from_name(self):
        self.runtime["backup"]["name"] = "SECRET_ARCHIVE.zip.enc"
        for value, label in ((None, "нет данных"), (False, "❌ не подтверждено"), (True, "✅ подтверждено")):
            self.runtime["backup"]["encrypted"] = value
            snapshot = self.snapshot()
            self.assertIs(snapshot["backup"]["encrypted"], value)
            self.assertIn("Шифрование архива: " + label, bot.format_status(snapshot))
            self.assertIn("шифрование: " + label, bot.format_backup_caption(snapshot))
            self.assertNotIn("SECRET", bot.format_backup_caption(snapshot))

    def test_typed_operations_and_proxy_summary_no_links_or_credentials(self):
        self.runtime["operations"] = {
            "monitor_interval_seconds": 60, "confirm_samples": 3, "ai_interval_seconds": 900,
            "knowledge_version": "SECRET_MODEL_KNOWLEDGE", "backup_verified": True,
            "backup_checked_at": self.now - 10, "backup_db_count": 2, "backup_missing_count": 0,
            "paths": ["SECRET_DATABASE"], "encryption_key": "SECRET_KEY",
        }
        self.runtime["proxies"] = {
            kind: {"service": "active", "checked_at": self.now - 20, "stage": "telegram", "protocol": method,
                   "ready": True, "isolation_verified": True, "ip": "SECRET_IP", "secret": "SECRET_PROXY",
                   "path": "/SECRET", "link": "tg://proxy?secret=SECRET"}
            for kind, method in (("mtproto", "mtproto_req_pq_multi"), ("native_tls", "mtproto_fake_tls_req_pq_multi"), ("web", "web_mtproto_req_pq_multi"))
        }
        self.runtime["proxies"]["SECRET_ARBITRARY_KIND"] = {"ready": True}
        result = self.snapshot()
        self.assertEqual(result["operations"]["knowledge_version"], bot.OPERATIONS_KNOWLEDGE_VERSION)
        self.assertEqual(result["operations"]["confirm_samples"], 3)
        self.assertEqual(set(result["proxies"]), {"mtproto", "native_tls", "web"})
        self.assertNotIn("SECRET", json.dumps(result))
        text = bot.format_status(result)
        for expected in ("каждые 60 с", "подтверждение 3 замерами", "MTProto · 3443", "Native TLS · 5443", "WEB Proxy · 443", "изоляция: подтверждена", "Проверка восстановления", "Баз проверено: 2"):
            self.assertIn(expected, text)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("tg://", text)
        self.assertIn("не процент прогресса ИИ", text)
        self.assertIn("не доступность с телефона без VPN", text)
        self.assertLessEqual(len(text), bot.MAX_STATUS_CHARS)
        self.assertLessEqual(len(text.encode("utf-16-le")) // 2, 4096)

    def test_invalid_operation_aggregates_stay_unknown(self):
        self.model["engine"] = "llama.cpp"
        self.runtime["operations"] = {"monitor_interval_seconds": 1, "confirm_samples": True,
            "ai_interval_seconds": 300, "backup_checked_at": self.now + 1, "backup_db_count": 3,
            "backup_missing_count": 1000000, "backup_verified": {"SECRET": True}}
        result = self.snapshot()
        for field, value in result["operations"].items():
            if field != "knowledge_version":
                self.assertIsNone(value, field)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_proxy_running_process_never_proves_nonce_or_isolation(self):
        cases = (
            {"service": "active", "ready": True},
            {"service": "active", "ready": True, "checked_at": self.now, "stage": "tcp", "protocol": "mtproto_req_pq_multi"},
            {"service": "active", "ready": True, "checked_at": self.now, "stage": "telegram", "protocol": "web_mtproto_req_pq_multi"},
            {"service": "active", "ready": True, "checked_at": self.now + 1, "stage": "telegram", "protocol": "mtproto_req_pq_multi"},
        )
        for item in cases:
            self.runtime["proxies"] = {"mtproto": item}
            result = self.snapshot()
            self.assertIsNone(result["proxies"]["mtproto"]["ready"])
            self.assertIsNone(result["proxies"]["mtproto"]["isolation_verified"])
            self.assertNotIn("✅ nonce подтверждён", bot.format_status(result))
        self.runtime["proxies"] = {"mtproto": {"service": "active", "ready": False, "checked_at": self.now,
            "stage": "failed", "protocol": "mtproto_req_pq_multi", "isolation_verified": False}}
        self.assertIn("❌ nonce не подтверждён", bot.format_status(self.snapshot()))
        self.assertIn("изоляция: не подтверждена", bot.format_status(self.snapshot()))


class IncidentLedgerTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "generated_at": 1800000000,
            "server": {"cpu_percent": 12, "memory_percent": 31, "disk_percent": 41,
                "network_status": "healthy", "services": {"operator": "active", "rospanel": "active",
                    "xray": "active", "llama_cpp": "active", "ollama": "inactive"}},
            "ai": {"enabled": True, "engine": "llama.cpp", "provider": "qwen", "last_status": "готов"},
            "backup": {"hourly_enabled": True, "exists": True, "ts": 1799999100, "last_delivery_ok": True},
        }
        self.empty = {"schema": 1, "open": []}

    def alert(self, state=None, fingerprint="", **kwargs):
        return bot.fact_alert(self.snapshot, fingerprint, previous_state=self.empty if state is None else state, **kwargs)

    def test_observation_is_typed_and_allowlisted_not_model_text(self):
        self.snapshot["ai"]["advice"] = "SECRET: all servers failed"
        observation = bot.fact_observation(self.snapshot)
        self.assertEqual(observation["schema"], 1)
        self.assertEqual(tuple(observation["conditions"]), bot.FACT_ISSUE_CODES)
        self.assertEqual(observation["conditions"]["service_xray"], "healthy")
        self.assertEqual(observation["conditions"]["service_ollama"], "unknown")
        self.assertEqual(set(bot.fact_observation({})["conditions"].values()), {"unknown"})
        self.assertNotIn("SECRET", json.dumps(observation))

    def test_initial_incidents_group_facts_and_one_safe_action_per_group(self):
        self.snapshot["server"].update(cpu_percent=92, memory_percent=94, disk_percent=87, network_status="degraded")
        self.snapshot["server"]["services"]["xray"] = "failed"
        self.snapshot["ai"].update(last_status="ошибка", last_error_reason="recommendation_not_allowed", advice="SECRET_RAW_AI")
        self.snapshot["backup"].update(ts=1799990000, last_delivery_ok=False, error="SECRET_RAW_ERROR")
        alert = self.alert()
        self.assertTrue(alert["should_notify"])
        self.assertEqual(alert["transition"], "incident")
        self.assertEqual(alert["new_issues"], alert["issues"])
        self.assertEqual(alert["state"]["open"], alert["issues"])
        self.assertEqual(alert["message"].count("Действие:"), 5)
        self.assertIn("92%", alert["message"])
        self.assertIn("VPN Xray: ошибка службы", alert["message"])
        self.assertIn("вне разрешённого списка", alert["message"])
        self.assertIn("ТСПУ не доказана", alert["message"])
        self.assertIn("Не удаляйте базы", alert["message"])
        self.assertNotIn("SECRET", json.dumps(alert))
        self.assertNotIn("**", alert["message"])

    def test_dedup_ignores_numeric_fluctuations_and_ai_paraphrases(self):
        self.snapshot["server"]["disk_percent"] = 86
        first = self.alert()
        self.snapshot["server"]["disk_percent"] = 94.5
        self.snapshot["generated_at"] += 60
        self.snapshot["ai"]["advice"] = "SECRET_NEW_ADVICE"
        again = self.alert(first["state"], first["fingerprint"])
        self.assertFalse(again["should_notify"])
        self.assertEqual(again["fingerprint"], first["fingerprint"])
        self.assertEqual(again["message"], "")

    def test_partial_recovery_only_resolves_component_with_evidence(self):
        self.snapshot["server"]["disk_percent"] = 86
        self.snapshot["server"]["services"]["xray"] = "failed"
        first = self.alert()
        self.snapshot["server"]["disk_percent"] = 50
        partial = self.alert(first["state"], first["fingerprint"])
        self.assertTrue(partial["should_notify"])
        self.assertFalse(partial["recovery"])
        self.assertEqual(partial["resolved_issues"], ["disk_percent"])
        self.assertEqual(partial["state"]["open"], ["service_xray"])
        self.assertEqual(partial["transition"], "update")
        self.assertIn("частичное восстановление", partial["message"])
        self.assertIn("VPN Xray: ошибка службы", partial["message"])
        self.assertFalse(self.alert(partial["state"], partial["fingerprint"])["should_notify"])

    def test_missing_measurement_retains_incident_hash_and_is_quiet(self):
        self.snapshot["server"]["disk_percent"] = 90
        first = self.alert()
        self.snapshot["server"].pop("disk_percent")
        lost = self.alert(first["state"], first["fingerprint"])
        self.assertEqual(lost["issues"], [])
        self.assertEqual(lost["unverified_issues"], ["disk_percent"])
        self.assertEqual(lost["state"], first["state"])
        self.assertEqual(lost["fingerprint"], first["fingerprint"])
        self.assertFalse(lost["should_notify"])
        self.assertFalse(lost["recovery"])
        self.snapshot["server"]["disk_percent"] = 45
        recovered = self.alert(lost["state"], lost["fingerprint"])
        self.assertTrue(recovered["recovery"])
        self.assertEqual(recovered["state"], self.empty)

    def test_new_incident_can_report_prior_unknown_without_false_recovery(self):
        self.snapshot["server"]["disk_percent"] = 90
        first = self.alert()
        self.snapshot["server"].update(disk_percent=None, cpu_percent=99)
        alert = self.alert(first["state"], first["fingerprint"])
        self.assertEqual(alert["new_issues"], ["cpu_percent"])
        self.assertEqual(alert["unverified_issues"], ["disk_percent"])
        self.assertEqual(alert["state"]["open"], ["cpu_percent", "disk_percent"])
        self.assertIn("Нет нового результата: Диск", alert["message"])
        self.assertNotIn("замер ниже порога", alert["message"])

    def test_transitional_invalid_and_absent_services_never_recover(self):
        first_state = {"schema": 1, "open": ["service_xray"]}
        for value in ("activating", "deactivating", None, {"state": "active"}, "SECRET_OUTPUT"):
            self.snapshot["server"]["services"]["xray"] = value
            alert = self.alert(first_state)
            self.assertFalse(alert["should_notify"])
            self.assertFalse(alert["recovery"])
            self.assertEqual(alert["state"], first_state)
            self.assertNotIn("SECRET", json.dumps(alert))

    def test_disabling_ai_or_backup_is_not_incident_recovery(self):
        state = {"schema": 1, "open": ["service_llama_cpp", "analysis_error", "backup_stale", "backup_delivery_failed"]}
        self.snapshot["ai"]["enabled"] = False
        self.snapshot["backup"]["hourly_enabled"] = False
        alert = self.alert(state)
        self.assertFalse(alert["should_notify"])
        self.assertEqual(alert["state"], state)
        self.assertEqual(alert["unverified_issues"], state["open"])

    def test_switching_model_engine_never_recovers_old_engine_incident(self):
        state = {"schema": 1, "open": ["service_llama_cpp"]}
        self.snapshot["ai"]["engine"] = "ollama"
        self.snapshot["server"]["services"]["ollama"] = "active"
        alert = self.alert(state)
        self.assertFalse(alert["should_notify"])
        self.assertEqual(alert["state"], state)

    def test_future_or_missing_backup_timestamp_does_not_recover(self):
        state = {"schema": 1, "open": ["backup_stale", "backup_delivery_failed"]}
        for stamp in (None, self.snapshot["generated_at"] + 1, True, -1):
            self.snapshot["backup"].update(ts=stamp, last_delivery_ok=None)
            result = self.alert(state)
            self.assertFalse(result["recovery"])
            self.assertFalse(result["should_notify"])
            self.assertEqual(result["state"], state)
        self.snapshot["backup"].update(ts=self.snapshot["generated_at"] - 10, last_delivery_ok=None)
        partial = self.alert(state)
        self.assertEqual(partial["resolved_issues"], ["backup_stale"])
        self.assertEqual(partial["state"]["open"], ["backup_delivery_failed"])
        self.assertIn("ещё не подтверждено", partial["message"])

    def test_failed_delivery_or_cooldown_keeps_candidate_retryable(self):
        prior = {"schema": 1, "open": ["service_xray"]}
        self.snapshot["server"]["disk_percent"] = 91
        first = self.alert(prior)
        retry = self.alert(prior)
        self.assertEqual(first, retry)
        self.assertTrue(retry["should_notify"])
        acknowledged = self.alert(retry["state"], retry["fingerprint"])
        self.assertFalse(acknowledged["should_notify"])

    def test_recovery_does_not_require_unrelated_missing_metrics(self):
        prior = {"schema": 1, "open": ["service_xray"]}
        self.snapshot["server"].pop("cpu_percent")
        result = self.alert(prior)
        self.assertTrue(result["should_notify"])
        self.assertTrue(result["recovery"])
        self.assertEqual(result["resolved_issues"], ["service_xray"])
        self.assertNotIn("ресурсы и сетевые проверки снова в норме", result["message"])

    def test_confirmation_filters_gate_each_direction_independently(self):
        self.snapshot["server"]["disk_percent"] = 91
        pending = self.alert(confirmed_issues=[], confirmed_healthy=[])
        self.assertFalse(pending["should_notify"])
        admitted = self.alert(confirmed_issues=["disk_percent"], confirmed_healthy=[])
        self.assertTrue(admitted["should_notify"])
        retained = self.alert(admitted["state"], confirmed_issues=[], confirmed_healthy=[])
        self.assertEqual(retained["state"], admitted["state"])
        self.assertFalse(retained["should_notify"])
        self.snapshot["server"]["disk_percent"] = 45
        pending_recovery = self.alert(admitted["state"], confirmed_issues=[], confirmed_healthy=[])
        self.assertFalse(pending_recovery["recovery"])
        self.assertEqual(pending_recovery["state"], admitted["state"])
        recovered = self.alert(admitted["state"], confirmed_issues=[], confirmed_healthy=["disk_percent"])
        self.assertTrue(recovered["recovery"])

    def test_invalid_confirmation_filters_fail_closed(self):
        self.snapshot["server"]["disk_percent"] = 91
        for invalid in ("disk_percent", {"disk_percent": True}, ["disk_percent", "SECRET"], [None], True):
            result = self.alert(confirmed_issues=invalid)
            self.assertFalse(result["should_notify"])
            self.assertNotIn("SECRET", json.dumps(result))
        self.snapshot["server"]["disk_percent"] = 40
        prior = {"schema": 1, "open": ["disk_percent"]}
        for invalid in (["SECRET"], "disk_percent", [True], {}):
            self.assertFalse(self.alert(prior, confirmed_healthy=invalid)["recovery"])

    def test_state_json_roundtrip_order_canonical_and_inputs_unchanged(self):
        prior = {"schema": 1, "open": ["service_xray", "disk_percent"]}
        self.snapshot["server"].update(disk_percent=None)
        self.snapshot["server"]["services"]["xray"] = None
        original = copy.deepcopy((self.snapshot, prior))
        first = self.alert(prior)
        second = self.alert(json.dumps({"open": list(reversed(prior["open"])), "schema": 1}))
        self.assertEqual(first, second)
        self.assertEqual(first["state"]["open"], ["disk_percent", "service_xray"])
        self.assertEqual((self.snapshot, prior), original)

    def test_invalid_ledger_does_not_leak_or_ack_opaque_hash(self):
        self.snapshot["server"]["disk_percent"] = 90
        previous = bot.notification_fingerprint(self.snapshot)
        for invalid in ("SECRET" * 1000, "{", {}, {"schema": True, "open": []},
                        {"schema": 1, "open": ["disk_percent", "disk_percent"]},
                        {"schema": 1, "open": ["SECRET"]}, {"schema": 1, "open": [], "secret": "SECRET"}):
            result = bot.fact_alert({}, previous, previous_state=invalid)
            self.assertFalse(result["should_notify"])
            self.assertFalse(result["recovery"])
            self.assertIsNone(result["state"])
            self.assertEqual(result["fingerprint"], previous)
            self.assertNotIn("SECRET", json.dumps(result))

    def test_legacy_recovery_requires_known_feature_flags_and_confirmed_metrics(self):
        self.snapshot["server"]["disk_percent"] = 90
        previous = bot.notification_fingerprint(self.snapshot)
        self.snapshot["server"]["disk_percent"] = 40
        complete = copy.deepcopy(self.snapshot)
        for section, field in (("ai", "enabled"), ("backup", "hourly_enabled")):
            self.snapshot = copy.deepcopy(complete)
            self.snapshot[section].pop(field)
            self.assertFalse(bot.fact_alert(self.snapshot, previous)["recovery"])
        self.snapshot = complete
        self.assertFalse(bot.fact_alert(self.snapshot, previous, confirmed_healthy=[])["recovery"])
        recovered = bot.fact_alert(self.snapshot, previous)
        self.assertTrue(recovered["recovery"])
        self.assertEqual(recovered["state"], self.empty)

    def test_legacy_suppressed_bad_sample_is_not_recovery(self):
        self.snapshot["server"]["disk_percent"] = 90
        previous = bot.notification_fingerprint(self.snapshot)
        result = bot.fact_alert(self.snapshot, previous, confirmed_issues=[])
        self.assertFalse(result["recovery"])
        self.assertFalse(result["should_notify"])
        self.assertEqual(result["fingerprint"], previous)

    def test_alert_size_bound_keeps_commands_and_factual_qualification(self):
        self.snapshot["server"].update(cpu_percent=100, memory_percent=100, disk_percent=100, network_status="degraded")
        self.snapshot["server"]["services"].update(operator="failed", rospanel="failed", xray="failed", llama_cpp="failed")
        self.snapshot["ai"].update(last_status="ошибка", last_error_reason="recommendations_shape")
        self.snapshot["backup"].update(exists=False, last_delivery_ok=False)
        self.snapshot["proxies"] = {kind: {"service": "failed"} for kind in ("mtproto", "native_tls", "web")}
        result = self.alert({"schema": 1, "open": ["service_ollama"]})
        self.assertLessEqual(len(result["message"]), bot.MAX_ALERT_CHARS)
        self.assertLessEqual(len(result["message"].encode("utf-16-le")) // 2, 4096)
        self.assertIn("/status", result["message"])
        self.assertIn("/backups", result["message"])
        self.assertIn("ТСПУ не доказана", result["message"])

    def test_legacy_opaque_or_proxy_hash_without_proof_never_recovers(self):
        for previous in ("a" * 64, bot._issue_fingerprint(["proxy_mtproto"]),
                         bot._issue_fingerprint(["proxy_web", "disk_percent"])):
            result = bot.fact_alert(self.snapshot, previous)
            self.assertFalse(result["should_notify"])
            self.assertFalse(result["recovery"])
            self.assertEqual(result["fingerprint"], previous)
        self.snapshot["proxies"] = {"mtproto": {"service": "active", "checked_at": self.snapshot["generated_at"],
            "stage": "telegram", "protocol": "mtproto_req_pq_multi", "ready": True}}
        self.assertTrue(bot.fact_alert(self.snapshot, bot._issue_fingerprint(["proxy_mtproto"]))["recovery"])

    def test_proxy_fresh_protocol_evidence_required_not_listener_alone(self):
        item = {"service": "active", "checked_at": self.snapshot["generated_at"], "stage": "telegram",
                "protocol": "mtproto_req_pq_multi", "ready": True}
        self.snapshot["proxies"] = {"mtproto": item}
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "healthy")
        for delta in (901, 3600):
            item["checked_at"] = self.snapshot["generated_at"] - delta
            self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "unknown")
        item["checked_at"] = self.snapshot["generated_at"]
        item["stage"] = "tcp"
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "unknown")
        item["stage"] = "not_checked"
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "unknown")
        item["stage"] = "failed"
        item["ready"] = False
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "bad")
        item["checked_at"] -= 901
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "unknown")
        item["service"] = "inactive"
        self.assertEqual(bot.fact_observation(self.snapshot)["conditions"]["proxy_mtproto"], "bad")

    def test_proxy_failure_safe_reserve_recommendation_not_client_promise(self):
        self.snapshot["proxies"] = {
            "mtproto": {"service": "active", "checked_at": self.snapshot["generated_at"], "stage": "failed",
                "protocol": "mtproto_req_pq_multi", "ready": False, "secret": "SECRET"},
            "native_tls": {"service": "active", "checked_at": self.snapshot["generated_at"], "stage": "telegram",
                "protocol": "mtproto_fake_tls_req_pq_multi", "ready": True, "link": "SECRET"},
        }
        alert = self.alert()
        self.assertEqual(alert["issues"], ["proxy_mtproto"])
        self.assertIn("📨 Telegram", alert["message"])
        self.assertIn("FakeTLS/WEB", alert["message"])
        self.assertIn("не путь вашего оператора без VPN", alert["message"])
        self.assertNotIn("SECRET", json.dumps(alert))
        self.snapshot["proxies"]["native_tls"]["checked_at"] -= 901
        self.assertNotIn("Резерв прошёл", self.alert()["message"])

    def test_proxy_unknown_retains_prior_failure_until_fresh_nonce_recovery(self):
        state = {"schema": 1, "open": ["proxy_web"]}
        self.snapshot["proxies"] = {"web": {"service": "active"}}
        missing = self.alert(state)
        self.assertFalse(missing["should_notify"])
        self.assertEqual(missing["state"], state)
        self.snapshot["proxies"]["web"].update(ready=True, checked_at=self.snapshot["generated_at"],
            stage="telegram", protocol="web_mtproto_req_pq_multi")
        pending = self.alert(state, confirmed_healthy=[])
        self.assertFalse(pending["recovery"])
        recovered = self.alert(state, confirmed_healthy=["proxy_web"])
        self.assertTrue(recovered["recovery"])
        self.assertEqual(recovered["resolved_issues"], ["proxy_web"])
        self.assertIn("Nonce проверяет", recovered["message"])


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
