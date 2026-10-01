import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from contextlib import closing
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class OperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ.update(QV_DATA_DIR=cls.tmp.name, QV_DOWNLOAD_ROOT=cls.tmp.name,
                          QV_ADMIN_USER="test", QV_ADMIN_PASSWORD="test",
                          QV_SUBSCRIPTION_UPSTREAM="https://example.invalid/sub")
        spec = importlib.util.spec_from_file_location("panel", Path(__file__).with_name("quantumvpn_operator_panel.py"))
        cls.panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.panel)
        for abi in ("arm64-v8a", "armeabi-v7a"):
            file = Path(cls.tmp.name) / cls.panel.VERSION / f"QuantumVPN-{cls.panel.VERSION}-operator-debug-{abi}.apk"
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(abi.encode())
        cls.server = cls.panel.ThreadingHTTPServer(("127.0.0.1", 0), cls.panel.App)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_abi_metadata_and_head(self):
        for abi in ("arm64-v8a", "armeabi-v7a"):
            with urlopen(self.base + "/api/app/version?abi=" + abi) as response:
                info = json.load(response)
            self.assertIn(abi, info["url"])
            self.assertEqual(len(info["sha256"]), 64)
            path = "/downloads/" + info["url"].split("/downloads/")[1]
            with urlopen(Request(self.base + path, method="HEAD")) as response:
                self.assertEqual(int(response.headers["Content-Length"]), info["size"])

    def test_forms_preserve_other_settings(self):
        token = base64.b64encode(b"test:test").decode()
        with closing(self.panel.conn()) as db:
            initial_audit_count = db.execute("select count(*) from audit where action like 'policy:%'").fetchone()[0]
        for body in (b"section=service&maintenance=on&maintenance_message=test", b"section=subscription&subscription_main_enabled=on"):
            with urlopen(Request(self.base + "/operator/policy", data=body, headers={"Authorization": "Basic " + token})) as response:
                self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            settings = self.panel.settings(db)
            self.assertEqual(settings["maintenance"], "1")
            self.assertEqual(settings["subscription_main_enabled"], "1")
            self.assertEqual(
                db.execute("select count(*) from audit where action like 'policy:%'").fetchone()[0],
                initial_audit_count + 2,
            )

    def test_operator_download_buttons_use_current_version(self):
        token = base64.b64encode(b"test:test").decode()
        with urlopen(Request(self.base + "/operator", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        self.assertIn(f'value="{self.panel.VERSION}"', page)
        with urlopen(self.base + "/api/app/version?abi=arm64-v8a") as response:
            info = json.load(response)
        self.assertEqual(info["version"], self.panel.VERSION)
        self.assertIn(f"/downloads/{self.panel.VERSION}/", info["url"])
        self.assertNotIn("5.6.13", page)

    def test_staged_rollout_holds_devices_outside_percentage(self):
        token = base64.b64encode(b"test:test").decode()
        body = b"section=release&rollout_percent=10"
        with urlopen(Request(self.base + "/operator/policy", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/app/version?abi=arm64-v8a&bucket=75&current_version=5.6.15&current_version_code=96") as response:
            info = json.load(response)
        self.assertFalse(info["rollout_eligible"])
        self.assertEqual(info["version"], "5.6.15")
        self.assertEqual(info["version_code"], 96)

    def test_scheduled_maintenance_is_effective_in_policy(self):
        token = base64.b64encode(b"test:test").decode()
        now = int(time.time())
        with closing(self.panel.conn()) as db:
            db.execute("insert or replace into settings values ('maintenance','0')")
            db.execute("insert or replace into settings values ('maintenance_schedule_enabled','1')")
            db.execute("insert or replace into settings values ('maintenance_start',?)", (str(now - 60),))
            db.execute("insert or replace into settings values ('maintenance_end',?)", (str(now + 60),))
            db.commit()
        with urlopen(self.base + "/api/client/policy") as response:
            policy = json.load(response)
        self.assertTrue(policy["maintenance"])
        self.assertFalse(policy["features"]["vpn_connect"])

    def test_scheduled_release_requires_both_nonempty_abis(self):
        version = "9.9.9"
        version_code = 9999
        now = int(time.time())
        setting_keys = (
            "app_version",
            "app_version_code",
            "rollout_percent",
            "app_changelog",
            "min_version_code",
            "update_notifications_enabled",
            "announce",
            "announce_en",
            "force_update_message",
            "config_revision",
            "release_schedule_enabled",
            "release_publish_at",
            "scheduled_app_version",
            "scheduled_app_version_code",
            "scheduled_rollout_percent",
            "scheduled_app_changelog",
            "scheduled_min_version_code",
        )
        with closing(self.panel.conn()) as db:
            original = {key: self.panel.settings(db).get(key, "") for key in setting_keys}
            try:
                self.panel.set_settings(db, {
                    "release_schedule_enabled": "1",
                    "release_publish_at": str(now - 1),
                    "scheduled_app_version": version,
                    "scheduled_app_version_code": str(version_code),
                    "scheduled_rollout_percent": "100",
                    "scheduled_app_changelog": "ready when both APKs exist",
                })
                db.commit()
                folder = Path(self.tmp.name) / version
                folder.mkdir(exist_ok=True)
                (folder / f"QuantumVPN-{version}-operator-debug-arm64-v8a.apk").write_bytes(b"arm64")
                (folder / f"QuantumVPN-{version}-operator-debug-armeabi-v7a.apk").write_bytes(b"")

                self.assertFalse(self.panel.promote_scheduled_release(db, now=now))
                deferred = self.panel.settings(db)
                self.assertEqual(deferred["app_version"], original["app_version"])
                self.assertEqual(deferred["release_schedule_enabled"], "1")
                row = db.execute(
                    "select detail from events where kind='release_promotion_deferred' order by ts desc limit 1"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(json.loads(row[0])["missing_abis"], ["armeabi-v7a"])

                (folder / f"QuantumVPN-{version}-operator-debug-armeabi-v7a.apk").write_bytes(b"armv7")
                self.assertTrue(self.panel.promote_scheduled_release(db, now=now))
                promoted = self.panel.settings(db)
                self.assertEqual(promoted["app_version"], version)
                self.assertEqual(promoted["release_schedule_enabled"], "0")
            finally:
                self.panel.set_settings(db, original)
                db.execute(
                    "delete from events where kind in ('release_promotion_deferred', 'release_promoted') and detail like ?",
                    (f'%"version": "{version}"%',),
                )
                db.commit()
                self.panel.release_info.cache_clear()

    def test_card_table_uses_hashed_code_and_device_bound_ticket(self):
        """A player can only read their own lobby with a short-lived ticket."""
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {
                "card_game_enabled": "1",
                "card_game_access_hash": self.panel.password_hash("table-code-2026"),
                "card_game_wait_minutes": "20",
            })
            db.commit()

        def join(device, name, code="table-code-2026"):
            body = json.dumps({"access_code": code, "display_name": name}).encode()
            request = Request(
                self.base + "/api/client/cards/join",
                data=body,
                headers={"Content-Type": "application/json", "X-Device-Id": device},
            )
            with urlopen(request) as response:
                return json.load(response)

        host = join("device-host-0001", "Алина")
        self.assertEqual(host["state"], "waiting")
        self.assertTrue(host["ticket"])
        guest = join("device-guest-002", "Борис")
        self.assertEqual(guest["state"], "ready")
        self.assertEqual(guest["opponent_name"], "Алина")

        request = Request(
            self.base + "/api/client/cards/state?ticket=" + host["ticket"],
            headers={"X-Device-Id": "device-host-0001"},
        )
        with urlopen(request) as response:
            restored = json.load(response)
        self.assertEqual(restored["state"], "ready")
        self.assertEqual(restored["opponent_name"], "Борис")

        wrong_device = Request(
            self.base + "/api/client/cards/state?ticket=" + host["ticket"],
            headers={"X-Device-Id": "some-other-device"},
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(wrong_device)
        self.assertEqual(error.exception.code, 403)

        with self.assertRaises(HTTPError) as denied:
            join("device-denied-3", "Вера", code="bad-code")
        self.assertEqual(denied.exception.code, 403)

    def test_card_game_deal_is_server_authoritative_and_wallet_is_virtual(self):
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {
                "card_game_enabled": "1",
                "card_game_access_hash": self.panel.password_hash("durak-code-2026"),
                "card_game_start_coins": "1200",
            })
            db.commit()

        def request(device, path, payload):
            body = json.dumps(payload).encode()
            with urlopen(Request(
                self.base + path,
                data=body,
                headers={"Content-Type": "application/json", "X-Device-Id": device},
            )) as response:
                return json.load(response)

        host = request("durak-host-0001", "/api/client/cards/join", {
            "access_code": "durak-code-2026", "display_name": "Игрок А",
        })
        guest = request("durak-guest-002", "/api/client/cards/join", {
            "access_code": "durak-code-2026", "display_name": "Игрок Б",
        })
        self.assertEqual(host["q_coins"], 1200)
        self.assertEqual(guest["q_coins"], 1200)

        host_ready = request("durak-host-0001", "/api/client/cards/action", {
            "ticket": host["ticket"], "action": "ready",
        })
        self.assertEqual(host_ready["game_phase"], "ready")
        guest_ready = request("durak-guest-002", "/api/client/cards/action", {
            "ticket": guest["ticket"], "action": "ready",
        })
        self.assertEqual(guest_ready["game_phase"], "playing")
        self.assertEqual(len(guest_ready["hand"]), 6)

        host_state_request = Request(
            self.base + "/api/client/cards/state?ticket=" + host["ticket"],
            headers={"X-Device-Id": "durak-host-0001"},
        )
        with urlopen(host_state_request) as response:
            host_state = json.load(response)
        attacked = request("durak-host-0001", "/api/client/cards/action", {
            "ticket": host["ticket"], "action": "attack", "card": host_state["hand"][0],
        })
        self.assertEqual(len(attacked["table_cards"]), 1)
        self.assertNotIn(host_state["hand"][0], attacked["hand"])

        with closing(self.panel.conn()) as db:
            wallet = db.execute(
                "select q_coins from card_wallets where device=?",
                (self.panel.device_id("durak-host-0001"),),
            ).fetchone()
        self.assertEqual(wallet[0], 1200)

    def test_automation_policy_and_release_guard(self):
        token = base64.b64encode(b"test:test").decode()
        body = (
            b"section=automation&health_monitor_enabled=on&health_monitor_interval_seconds=45"
            b"&telegram_daily_digest_enabled=on&telegram_digest_time_msk=21%3A00"
        )
        with urlopen(Request(self.base + "/operator/policy", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            current = self.panel.settings(db)
            self.assertEqual(current["health_monitor_enabled"], "1")
            self.assertEqual(current["health_monitor_interval_seconds"], "45")
            self.assertEqual(current["telegram_daily_digest_enabled"], "1")
            self.assertEqual(current["telegram_digest_time_msk"], "21:00")
            guard = self.panel.release_guard_snapshot(current)
        self.assertTrue(guard["production"]["ready"])
        self.assertFalse(guard["scheduled"]["configured"])
        with urlopen(Request(self.base + "/operator?tab=automation", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        self.assertIn("Автопилот панели", page)
        self.assertIn("Готовность релизов", page)

    def test_manual_node_drain_is_excluded_from_policy(self):
        token = base64.b64encode(b"test:test").decode()
        target = "31.76.68.243:443"
        with urlopen(Request(
            self.base + "/operator/actions",
            data=("action=drain_node&return_tab=latency&target=" + target.replace(":", "%3A")).encode(),
            headers={"Authorization": "Basic " + token},
        )) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/policy") as response:
            policy = json.load(response)
        self.assertIn(target, policy["nodes_draining"])
        self.assertIn(target, policy["nodes_forbidden"])
        with urlopen(Request(
            self.base + "/operator/actions",
            data=("action=restore_node&return_tab=latency&target=" + target.replace(":", "%3A")).encode(),
            headers={"Authorization": "Basic " + token},
        )) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/policy") as response:
            policy = json.load(response)
        self.assertNotIn(target, policy["nodes_draining"])

    def test_balancer_ignores_public_probe_not_registered_as_node(self):
        with closing(self.panel.conn()) as db:
            previous = self.panel.settings(db)
            try:
                self.panel.set_settings(db, {
                    "node_map_config": "VPN node|31.76.68.243:443|50.1109|8.6821|Frankfurt",
                    "latency_probe_targets": "1.1.1.1:443,31.76.68.243:443",
                    "node_drains": "{}",
                    "node_quarantine": "{}",
                })
                self.panel.record_health(db, "latency:1.1.1.1:443", {"ok": True, "latency_ms": 5, "status": "tcp:443"})
                self.panel.record_health(db, "latency:31.76.68.243:443", {"ok": True, "latency_ms": 45, "status": "tcp:443"})
                snapshot = self.panel.load_balancer_snapshot(db, self.panel.settings(db))
                self.assertEqual(snapshot["selected"], "31.76.68.243:443")
                self.assertEqual([item["target"] for item in snapshot["candidates"]], ["31.76.68.243:443"])
            finally:
                self.panel.set_settings(db, {
                    key: previous[key]
                    for key in ("node_map_config", "latency_probe_targets", "node_drains", "node_quarantine")
                })

    def test_support_queue_creates_and_closes_ticket(self):
        token = base64.b64encode(b"test:test").decode()
        with urlopen(Request(
            self.base + "/operator/support",
            data=b"action=create&subject=No+servers&device=device-test-123&body=Check+subscription",
            headers={"Authorization": "Basic " + token},
        )) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            ticket_id = db.execute(
                "select id from support_tickets where subject='No servers' order by id desc limit 1"
            ).fetchone()[0]
        with urlopen(Request(
            self.base + "/operator/support",
            data=f"action=close&id={ticket_id}".encode(),
            headers={"Authorization": "Basic " + token},
        )) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            closed = db.execute("select closed_at from support_tickets where id=?", (ticket_id,)).fetchone()[0]
        self.assertGreater(closed, 0)

    def test_routing_policy_is_validated_versioned_and_signed(self):
        token = base64.b64encode(b"test:test").decode()
        body = (
            b"action=publish&routing_enabled=on&routing_profile=whitelist"
            b"&routing_adblock_enabled=on&routing_dns_mode=vpn_only"
            b"&routing_dns_resolver=https%3A%2F%2Fdns.example%2Fdns-query"
            b"&routing_direct_domains=bank.example%2Cservice.example"
            b"&routing_proxy_domains=video.example&routing_block_domains=ads.example"
            b"&routing_direct_cidrs=203.0.113.11&routing_proxy_cidrs=198.51.100.0%2F24"
        )
        with urlopen(Request(self.base + "/operator/routing", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            envelope = json.load(response)
        self.assertEqual(envelope["channel"], "production")
        self.assertEqual(envelope["payload"]["profile"], "whitelist")
        self.assertIn("bank.example", envelope["payload"]["rules"]["direct_domains"])
        self.assertEqual(envelope["payload"]["rules"]["direct_cidrs"], ["203.0.113.11/32"])
        self.assertEqual(len(envelope["sha256"]), 64)
        if envelope["signature"]:
            signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
            self.panel.routing_signing_key().public_key().verify(
                signature,
                self.panel.canonical_json(envelope["payload"]),
            )
        with urlopen(Request(self.base + "/operator?tab=routing", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        self.assertIn("Маршрутизация и DNS", page)
        self.assertIn("Тестовый канал", page)
        self.assertIn("Анализатор целей", page)
        self.assertIn("Правила маршрута", page)
        self.assertIn("DNS и публикация", page)
        self.assertIn('id=routing-policy', page)
        self.assertIn("Блокировка рекламы не гарантируется", page)
        with closing(self.panel.conn()) as db:
            history = db.execute("select count(*) from routing_revisions where state='production'").fetchone()[0]
        self.assertGreaterEqual(history, 2)

    def test_routing_staging_is_bucketed_then_can_be_promoted(self):
        token = base64.b64encode(b"test:test").decode()
        stage = (
            b"action=stage&routing_enabled=on&routing_profile=proxy_all"
            b"&routing_adblock_enabled=on&routing_dns_mode=vpn_only"
            b"&routing_dns_resolver=https%3A%2F%2Fdns.example%2Fdns-query"
            b"&routing_proxy_domains=stage.example&routing_staging_rollout_percent=7"
        )
        with urlopen(Request(self.base + "/operator/routing", data=stage, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/routing?bucket=0") as response:
            staged = json.load(response)
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            stable = json.load(response)
        self.assertEqual(staged["channel"], "staging")
        self.assertEqual(staged["payload"]["profile"], "proxy_all")
        self.assertEqual(stable["channel"], "production")
        with urlopen(Request(self.base + "/operator/routing", data=b"action=promote", headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            promoted = json.load(response)
        self.assertEqual(promoted["channel"], "production")
        self.assertEqual(promoted["payload"]["profile"], "proxy_all")

    def test_routing_target_advisor_is_bounded_and_never_publishes(self):
        token = base64.b64encode(b"test:test").decode()
        with closing(self.panel.conn()) as db:
            revision_before = self.panel.settings(db)["routing_revision"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=["1.1.1.1"]), \
             mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=17):
            request = Request(
                self.base + "/operator/routing",
                data=b"action=scan&routing_scan_targets=example.com%0A1.1.1.1",
                headers={"Authorization": "Basic " + token},
            )
            with urlopen(request) as response:
                self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            current = self.panel.settings(db)
            scan = json.loads(current["routing_last_scan"])
            self.assertEqual([item["target"] for item in scan], ["example.com", "1.1.1.1"])
            self.assertEqual(current["routing_revision"], revision_before)
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            envelope = json.load(response)
        self.assertNotIn("routing_last_scan", envelope["payload"])
        self.assertNotIn("example.com", json.dumps(envelope["payload"]))
        with urlopen(Request(self.base + "/operator?tab=routing", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        self.assertIn("Анализатор целей", page)
        self.assertIn("Последняя проверка", page)
        self.assertIn("routing-empty", page)
        with self.assertRaises(ValueError):
            self.panel.normalize_routing_scan_targets("127.0.0.1")

    def test_node_map_registry_only_accepts_complete_coordinates(self):
        raw = "Paris node|31.76.68.243:443|48.8534|2.3488|Paris, France"
        nodes = self.panel.parse_node_map_config(raw)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["target"], "31.76.68.243:443")
        self.assertTrue(self.panel.node_map_config_is_valid(raw))
        self.assertFalse(self.panel.node_map_config_is_valid("missing|fields"))
        self.assertFalse(self.panel.node_map_config_is_valid("bad|host:443|91|2|location"))


if __name__ == "__main__":
    unittest.main()
