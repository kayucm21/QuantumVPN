import hashlib
import json
import sqlite3
import unittest

from tools import quantumvpn_community as community


class CommunityTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        community.migrate(self.db)
        self.token = community.issue_device_credential(self.db, "test-android-hwid", now=100)
        self.device = community.authenticate_client(self.db, "test-android-hwid", self.token, now=101)
        self.other = hashlib.sha256(b"other").hexdigest()[:16]

    def tearDown(self):
        self.db.close()

    def create(self, request="create-0001", **extra):
        return community.create_thread(self.db, self.device,
            {"request_id": request, "subject": "Не подключается", "body": "Сеть Wi-Fi, подключение не проходит", **extra}, now=200)["thread"]

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(community.CommunityError) as caught:
            function(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)

    def test_migration_is_idempotent_and_preserves_data(self):
        self.create()
        community.migrate(self.db)
        self.assertEqual(1, len(community.list_threads(self.db, self.device)["threads"]))

    def test_device_credentials_bound_to_hwid_and_expire(self):
        self.assert_code("client_authentication_required", community.authenticate_client, self.db, "other", self.token, now=101)
        self.assert_code("client_authentication_required", community.authenticate_client, self.db, "test-android-hwid", self.token, now=100 + 90 * 86_400)
        stored = self.db.execute("select * from community_credentials").fetchall()
        self.assertNotIn(self.token, json.dumps(stored))
        self.assertNotIn("test-android-hwid", json.dumps(stored))

    def test_arbitrary_device_without_bearer_is_denied(self):
        self.assert_code("client_authentication_required", community.authenticate_client, self.db, "test-android-hwid", "")
        self.assert_code("client_authentication_required", community.list_threads, self.db, "anonymous")

    def test_concurrent_subscription_credentials_have_bounded_overlap(self):
        tokens = [community.issue_device_credential(self.db, "test-android-hwid", now=300 + index) for index in range(6)]
        self.assertEqual(4, self.db.execute("select count(*) from community_credentials").fetchone()[0])
        self.assert_code("client_authentication_required", community.authenticate_client, self.db, "test-android-hwid", tokens[0], now=310)
        self.assertEqual(self.device, community.authenticate_client(self.db, "test-android-hwid", tokens[-1], now=310))

    def test_support_is_private_and_idempotent(self):
        first, second = self.create(), self.create()
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(1, len(first["messages"]))
        self.assertNotIn("device", first)
        self.assert_code("thread_not_found", community.get_thread, self.db, self.other, first["id"])
        self.assertEqual([], community.list_threads(self.db, self.other)["threads"])

    def test_message_ownership_and_duplicate_retries(self):
        thread = self.create()
        payload = {"request_id": "message-0001", "body": "Уточнение"}
        for _ in range(2):
            result = community.add_message(self.db, self.device, thread["id"], payload, now=210)
        self.assertEqual(2, len(result["thread"]["messages"]))
        self.assert_code("thread_not_found", community.add_message, self.db, self.other, thread["id"], payload)

    def test_diagnostic_requires_consent_and_strict_allowlist(self):
        self.assert_code("diagnostic_consent_required", self.create, diagnostic={"logs": "example"})
        self.create(diagnostic_consent=True, diagnostic={"summary": "IP 10.2.3.4", "logs": "token=abcd https://example.invalid/sub/secret", "profile": "private configuration", "password": "never"})
        diagnostic = self.db.execute("select diagnostic_json from community_messages").fetchone()[0]
        self.assertNotIn("abcd", diagnostic)
        self.assertNotIn("10.2.3.4", diagnostic)
        self.assertNotIn("secret", diagnostic)
        self.assertNotIn("configuration", diagnostic)
        self.assertEqual({"summary", "logs"}, set(json.loads(diagnostic)))

    def test_support_open_thread_limit(self):
        for index in range(5):
            self.create(request=f"create-{index:04}")
        self.assert_code("support_limit_reached", self.create, request="create-extra")

    def test_redactor_handles_quoted_keys_and_russian_secrets(self):
        text = community.redact_text('"private_key":"private-material" пароль user-secret ' + 'A' * 43 + '=')
        for value in ("private-material", "user-secret", 'A' * 43):
            self.assertNotIn(value, text)

    def test_closed_thread_rejects_user_writes(self):
        thread = self.create()
        community.set_thread_state(self.db, thread["id"], "closed")
        self.assert_code("thread_closed", community.add_message, self.db, self.device, thread["id"], {"request_id": "closed-0001", "body": "Нет"})

    def test_operator_reply_is_targeted_and_deduplicated(self):
        thread = self.create()
        for _ in range(2):
            community.operator_reply(self.db, thread["id"], "Исправлено", "reply-0001", now=220)
        events = community.inbox(self.db, self.device)["events"]
        self.assertEqual(1, len(events))
        self.assertEqual("support_reply", events[0]["kind"])
        self.assertEqual([], community.inbox(self.db, self.other)["events"])
        self.assertEqual(2, len(community.get_thread(self.db, self.device, thread["id"])["thread"]["messages"]))

    def test_inbox_stable_pagination_and_read_ownership(self):
        ids = []
        for index in range(4):
            ids.append(community.append_event(self.db, "release", "Обновление", "Версия", f"release-{index}", now=250))
        private = community.append_event(self.db, "support_reply", "Секрет", "Ответ", "private", device=self.other, now=251)
        first = community.inbox(self.db, self.device, limit=2)
        self.assertTrue(first["has_more"])
        self.assertEqual(ids[:2], [entry["id"] for entry in first["events"]])
        next_page = community.inbox(self.db, self.device, after=first["cursor"], limit=2)
        self.assertEqual(ids[2:], [entry["id"] for entry in next_page["events"]])
        self.assertFalse(next_page["has_more"])
        community.mark_read(self.db, self.device, private)
        self.assertEqual(ids[-1], community.inbox(self.db, self.device)["read_through"])
        self.assertEqual(0, community.inbox(self.db, self.device)["unread"])

    def test_broadcast_deduplication(self):
        first = community.append_event(self.db, "maintenance", "Работы", "Подождите", "maint-1", now=250)
        second = community.append_event(self.db, "maintenance", "Работы", "Подождите", "maint-1", now=251)
        self.assertEqual(first, second)

    def quality(self, **extra):
        return {"consent": True, "event_id": "quality-0001", "node_key": "node_1", "protocol": "vless", "network": "wifi", "app_version": "5.11.3", "connect_ms": 1200, "ping_ms": 53, "disconnects": 0, "success": True, **extra}

    def test_quality_is_opt_in_sanitized_and_idempotent(self):
        self.assert_code("quality_consent_required", community.record_quality, self.db, self.device, self.quality(consent=False))
        community.record_quality(self.db, self.device, self.quality(browsing_history="must never be stored"), now=300)
        result = community.record_quality(self.db, self.device, self.quality(), now=301)
        self.assertTrue(result["duplicate"])
        rows = community.quality_snapshot(self.db, now=302)["reports"]
        self.assertEqual(1, len(rows))
        self.assertNotIn("browsing_history", rows[0])
        self.assert_code("invalid_node_key", community.record_quality, self.db, self.device, self.quality(node_key="10.1.2.3"))

    def test_quality_hourly_limit_and_numeric_bounds(self):
        for index in range(24):
            community.record_quality(self.db, self.device, self.quality(event_id=f"quality-{index:04}"), now=300)
        self.assert_code("quality_limit_reached", community.record_quality, self.db, self.device, self.quality(event_id="quality-extra"), now=310)
        self.assert_code("invalid_ping_ms", community.record_quality, self.db, self.device, self.quality(ping_ms=-1))

    def test_delivery_never_counts_handoff_as_installation(self):
        for stage in ("notification_received", "download_complete", "install_handoff", "app_started"):
            payload = {"event_id": f"event-{stage}", "stage": stage, "version_code": 501103099}
            community.record_delivery(self.db, self.device, payload, now=400)
            community.record_delivery(self.db, self.device, payload, now=401)
        snapshot = community.delivery_snapshot(self.db, now=410)
        self.assertEqual(4, len(snapshot["reports"]))
        self.assertFalse(snapshot["handoff_is_installation"])
        self.assertEqual(1, snapshot["stages"]["app_started"])
        self.assertNotIn("installed", snapshot["stages"])
        self.assert_code("invalid_delivery_stage", community.record_delivery, self.db, self.device, {"event_id": "event-invalid", "stage": "installed", "version_code": 1})

    def test_delivery_old_hook_names_normalize(self):
        community.record_delivery(self.db, self.device, {"event_id": "first-launch-1", "stage": "first_launch", "version_code": 10}, now=400)
        self.assertEqual("app_started", community.delivery_snapshot(self.db, now=410)["reports"][0]["stage"])

    def test_cleanup_preserves_open_support_and_recent_reports(self):
        thread = self.create()
        community.record_quality(self.db, self.device, self.quality(), now=300)
        community.cleanup(self.db, now=300 + 31 * 86_400)
        self.assertEqual([], community.quality_snapshot(self.db)["reports"])
        self.assertEqual(thread["id"], community.get_thread(self.db, self.device, thread["id"])["thread"]["id"])


if __name__ == "__main__":
    unittest.main()
