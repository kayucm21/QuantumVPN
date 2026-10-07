import base64
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import random
import tempfile
import threading
import time
import unittest
from unittest import mock
from contextlib import closing
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlencode


def confirmed_control_fields(page):
    class Inputs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.fields = {}
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "input" and attrs.get("name") in {"preview_id", "digest", "csrf"}:
                self.fields[attrs["name"]] = attrs.get("value", "")
    parser = Inputs()
    parser.feed(page)
    if set(parser.fields) != {"preview_id", "digest", "csrf"}:
        raise AssertionError("Expected a guarded control preview")
    return parser.fields


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

    def test_resource_post_preserves_tab_and_signed_manifest(self):
        token = base64.b64encode(b"test:test").decode()
        headers = {"Authorization": "Basic " + token}
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)["app_version"]
        with urlopen(Request(self.base + "/operator/resources", data=b"action=save&brand_name=QuantumVPN&accent=%2358F4CE&note=resource-test", headers=headers)) as response:
            self.assertIn("tab=resources", response.url)
            self.assertIn("РЕСУРСЫ И ИСПРАВЛЕНИЯ", response.read().decode())
        with closing(self.panel.conn()) as db:
            revision = db.execute("select max(id) from resource_bundles").fetchone()[0]
        with urlopen(Request(self.base + "/operator/resources", data=f"action=production&revision={revision}".encode(), headers=headers)) as response:
            self.assertIn("tab=resources", response.url)
        with urlopen(self.base + "/api/client/resources?version_code=501101099") as response:
            value = json.load(response)
            self.assertEqual(value["payload"]["texts"]["brand_name"], "QuantumVPN")
            self.assertEqual(value["payload"]["kind"], "quantumvpn-resources-v1")
        with urlopen(self.base + "/api/client/resources?version_code=137") as response:
            self.assertEqual(response.status, 204)
        with closing(self.panel.conn()) as db:
            self.assertEqual(self.panel.settings(db)["app_version"], before)

    def test_resource_post_rejects_foreign_origin_and_oversized_body(self):
        token = base64.b64encode(b"test:test").decode()
        request = Request(self.base + "/operator/resources", data=b"action=save", headers={"Authorization": "Basic " + token, "Origin": "https://evil.invalid"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 403)
        request = Request(self.base + "/operator/resources", data=b"x" * (5 * 1024 * 1024 + 1), headers={"Authorization": "Basic " + token})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 413)

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

    def test_subscription_category_texts_are_saved_without_changing_access(self):
        token = base64.b64encode(b"test:test").decode()
        body = (
            "section=subscription_text&subscription_category_title=%D0%A2%D0%B0%D1%80%D0%B8%D1%84%D1%8B"
            "&subscription_category_description=%D0%94%D0%BE%D1%81%D1%82%D1%83%D0%BF"
            "&subscription_main_label=%D0%9E%D1%81%D0%BD%D0%BE%D0%B2%D0%BD%D0%B0%D1%8F"
            "&reserve_profile_label=%D0%A0%D0%B5%D0%B7%D0%B5%D1%80%D0%B2"
        ).encode()
        with urlopen(Request(self.base + "/operator/policy", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            saved = self.panel.settings(db)
            self.assertEqual(saved["subscription_category_title"], "Тарифы")
            self.assertEqual(saved["subscription_main_enabled"], "1")

    def test_local_qwen_advice_is_aggregate_only_and_cannot_execute(self):
        class Reply:
            status = 200
            def read(self, _size=-1):
                return json.dumps({"response": "Статус: стабильно. Риски: нет. Следующий ручной шаг: наблюдать."}, ensure_ascii=False).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False

        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {
                "ai_advisor_enabled": "1",
                "ai_model": self.panel.QWEN_DEFAULT_MODEL,
                "telegram_bot_token": "secret-must-not-reach-model",
                "telegram_chat_id": "12345",
            })
            db.commit()
            captured = []
            def fake_urlopen(request, timeout=0):
                captured.append(request)
                return Reply()
            with mock.patch.object(self.panel, "qwen_local_status", return_value={"ok": True, "ready": True}), \
                    mock.patch.object(self.panel, "urlopen", side_effect=fake_urlopen):
                result = self.panel.run_ai_analysis(db, self.panel.settings(db), "test")
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "готов")
            payload = captured[0].data.decode("utf-8")
            self.assertNotIn("secret-must-not-reach-model", payload)
            self.assertNotIn("telegram_chat_id", payload)
            saved = self.panel.settings(db)
            self.assertEqual(saved["ai_last_status"], "готов")
            row = db.execute("select advice,before_json from ai_observations order by id desc limit 1").fetchone()
            self.assertIn("стабильно", row["advice"])
            self.assertNotIn("secret-must-not-reach-model", row["before_json"])

    def test_quality_route_action_preserves_tab_and_revision(self):
        token = base64.b64encode(b"test:test").decode()
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)["routing_revision"]
        with urlopen(Request(self.base + "/operator/actions", data=b"action=explain_route&return_tab=quality&route_target=youtube.com", headers={"Authorization": "Basic " + token})) as response:
            self.assertIn("tab=quality", response.url)
            page = response.read().decode("utf-8")
            self.assertIn("КОНТРОЛЬ КАЧЕСТВА", page)
            self.assertIn("youtube.com", page)
            self.assertIn("Запрос политики не доказывает", page)
        with closing(self.panel.conn()) as db:
            saved = self.panel.settings(db)
            self.assertEqual(saved["routing_revision"], before)
            self.assertEqual(json.loads(saved["quality_route"])["target"], "youtube.com")

    def test_quality_records_only_identified_client_reports(self):
        device = "quality-test-device"
        for url in ("/api/client/policy", "/api/app/version?current_version_code=137"):
            with urlopen(Request(self.base + url, headers={"X-HWID": device})) as response:
                self.assertEqual(response.status, 200)
        with urlopen(Request(self.base + "/api/client/policy", headers={"User-Agent": "not-a-device"})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            row = db.execute("select * from delivery_evidence where device=?", (self.panel.device_id(device),)).fetchone()
            self.assertGreater(row["policy_at"], 0)
            self.assertGreater(row["update_at"], 0)
            self.assertEqual(row["version_code"], 137)
            self.assertEqual(row["notification_permission"], "неизвестно")
            self.assertEqual(row["download_at"], 0)
            self.assertEqual(row["install_at"], 0)
            self.assertIsNone(db.execute("select * from delivery_evidence where device=?", (self.panel.device_id("not-a-device"),)).fetchone())

    def test_quality_backup_is_encrypted_and_checked_without_live_restore(self):
        token = base64.b64encode(b"test:test").decode()
        with mock.patch.object(self.panel, "latest_backup_info", wraps=self.panel.latest_backup_info):
            with urlopen(Request(self.base + "/operator/actions", data=b"action=verify_backup&return_tab=quality", headers={"Authorization": "Basic " + token})) as response:
                self.assertIn("tab=quality", response.url)
        with closing(self.panel.conn()) as db:
            result = json.loads(self.panel.settings(db)["quality_backup"])
            self.assertTrue(result["ok"])
            self.assertIn("operator.db", result["databases"])
            self.assertEqual(db.execute("pragma integrity_check").fetchone()[0], "ok")
        folder = Path(self.panel.ROOT) / "backups"
        self.assertFalse(list(folder.glob("*.zip")))
        self.assertFalse(list(folder.glob(".*.db")))
        self.assertTrue(list(folder.glob("*.zip.enc")))

    def test_backup_encryption_failure_leaves_no_plaintext(self):
        with closing(self.panel.conn()):
            pass
        with mock.patch.object(self.panel, "encrypt_backup_archive", side_effect=RuntimeError("Encryption failed")):
            with self.assertRaises(RuntimeError):
                self.panel.create_backup_archive()
        folder = Path(self.panel.ROOT) / "backups"
        self.assertFalse(list(folder.glob("*.zip")))
        self.assertFalse(list(folder.glob(".*.db")))

    def test_quality_mutation_requires_operator_role(self):
        with closing(self.panel.conn()) as db:
            db.execute("insert or replace into admin_users values (?,?,?,?,?,?)", ("quality-viewer", self.panel.password_hash("viewer-password"), "viewer", 1, 0, 0))
            db.commit()
        token = base64.b64encode(b"quality-viewer:viewer-password").decode()
        with self.assertRaises(HTTPError) as denied:
            urlopen(Request(self.base + "/operator/actions", data=b"action=explain_route&return_tab=quality&route_target=example.com", headers={"Authorization": "Basic " + token}))
        self.assertEqual(denied.exception.code, 403)
        denied.exception.close()

    def test_quality_failed_subscription_inspection_keeps_previous_report(self):
        token = base64.b64encode(b"test:test").decode()
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"quality_subscription": '{"protocols":{"vless":2},"checked_at":1}'})
            db.commit()
        with mock.patch.object(self.panel, "managed_subscription", side_effect=RuntimeError("SECRET-UPSTREAM-URL")):
            with urlopen(Request(self.base + "/operator/actions", data=b"action=inspect_subscription&return_tab=quality", headers={"Authorization": "Basic " + token})) as response:
                page = response.read().decode("utf-8")
                self.assertNotIn("SECRET-UPSTREAM-URL", page)
        with closing(self.panel.conn()) as db:
            self.assertEqual(json.loads(self.panel.settings(db)["quality_subscription"])["protocols"], {"vless": 2})

    def test_subscription_inspection_reuses_only_matching_existing_android(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            file = str(Path(folder) / "primary.db")
            db = sqlite3.connect(file)
            db.executescript("""
                create table users(id,sub_token,enabled);
                insert into users values(1,'sub',1),(2,'other-token',1);
                create table devices(user_id,hwid,os,os_version,model,last_seen);
                insert into devices values(1,'windows-hwid','windows','11','Desktop',300);
                insert into devices values(1,'registered-android-hwid','android','14','Phone',100);
                insert into devices values(2,'other-user-hwid','android','15','Other',400);
            """)
            db.commit(); db.close()
            with mock.patch.object(self.panel, "ROSPANEL_DB", file):
                headers, source = self.panel.subscription_inspection_headers()
                self.assertEqual(headers["X-Hwid"], "registered-android-hwid")
                self.assertIn("зарегистрированным", source)
                with mock.patch.object(self.panel, "UPSTREAM", "https://example.invalid/sub/unknown"):
                    headers, source = self.panel.subscription_inspection_headers()
                    self.assertNotIn("X-Hwid", headers)

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
        version_code = 999999999
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
            "scheduled_expected_app_version",
            "scheduled_expected_app_version_code",
            "scheduled_release_metadata_sha256",
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
                signer = "4" * 64
                metadata = {
                    "schema": 2, "version_name": version, "version_code": version_code,
                    "application_id": "com.quantumvpn.debug", "signer_sha256": signer, "artifacts": [],
                }
                for abi in self.panel.REQUIRED_RELEASE_ABIS:
                    name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
                    artifact = folder / name
                    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                    metadata["artifacts"].append({"abi": abi, "apk_file": name,
                                                  "apk_size": artifact.stat().st_size, "apk_sha256": digest})
                    (folder / (name + ".sha256")).write_text(digest + "  " + name + "\n", encoding="ascii")
                manifest = folder / "release-metadata.json"
                manifest.write_text(json.dumps(metadata), encoding="utf-8")
                production_manifest = Path(self.tmp.name) / original["app_version"] / "release-metadata.json"
                production_manifest.parent.mkdir(exist_ok=True)
                production_manifest.write_text(json.dumps({
                    "application_id": "com.quantumvpn.debug", "signer_sha256": signer,
                    "version_name": original["app_version"], "version_code": int(original["app_version_code"]),
                }), encoding="utf-8")
                self.panel.set_settings(db, {
                    "scheduled_expected_app_version": original["app_version"],
                    "scheduled_expected_app_version_code": original["app_version_code"],
                    "scheduled_release_metadata_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                })
                db.commit()
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
        self.assertEqual(restored["ticket"], host["ticket"])

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
                "card_game_stake_q_coins": "25",
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
        attacking_state = host_state if host_state["attacker"] == "host" else guest_ready
        attacking_device = "durak-host-0001" if attacking_state["seat"] == "host" else "durak-guest-002"
        attacked = request(attacking_device, "/api/client/cards/action", {
            "ticket": attacking_state["ticket"], "action": "attack", "card": attacking_state["hand"][0],
        })
        self.assertEqual(len(attacked["table_cards"]), 1)
        self.assertNotIn(attacking_state["hand"][0], attacked["hand"])

        with closing(self.panel.conn()) as db:
            wallet = db.execute(
                "select q_coins from card_wallets where device=?",
                (self.panel.device_id("durak-host-0001"),),
            ).fetchone()
        # A ready deal now reserves 25 virtual Q-coins from each player; the
        # complete virtual pot is paid only when the server decides a winner.
        self.assertEqual(wallet[0], 1175)

    def test_card_game_virtual_pot_transfers_only_after_server_finish(self):
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {
                "card_game_enabled": "1",
                "card_game_access_hash": self.panel.password_hash("pot-code-2026"),
                "card_game_start_coins": "1200",
                "card_game_stake_q_coins": "40",
            })
            host_device = self.panel.device_id("pot-host-0001")
            guest_device = self.panel.device_id("pot-guest-002")
            handler = object.__new__(self.panel.App)
            host = handler.join_card_game(db, self.panel.settings(db), host_device, "127.0.0.1", "pot-code-2026", "Хост")
            guest = handler.join_card_game(db, self.panel.settings(db), guest_device, "127.0.0.1", "pot-code-2026", "Гость")
            handler.card_game_action(db, self.panel.settings(db), host_device, host["table_id"], "ready")
            handler.card_game_action(db, self.panel.settings(db), guest_device, guest["table_id"], "ready")
            row = db.execute("select game_json from card_tables where id=?", (host["table_id"],)).fetchone()
            game = json.loads(row[0])
            game.update({"deck": [], "hands": {"host": ["6S"], "guest": ["7H"]},
                         "attacker": "guest", "table": [], "bout_limit": 1,
                         "discard": sorted(self.panel.durak.CARDS.difference(["6S", "7H"]))})
            db.execute("update card_tables set state='playing',game_json=? where id=?", (json.dumps(game), host["table_id"]))
            db.commit()
            attacked = handler.card_game_action(db, self.panel.settings(db), guest_device, host["table_id"], "attack", "7H")
            self.assertEqual(attacked["game_phase"], "playing")
            self.assertEqual(attacked["winner_reward_q_coins"], 0)
            result = handler.card_game_action(db, self.panel.settings(db), host_device, host["table_id"], "take")
            self.assertEqual(result["game_phase"], "finished")
            self.assertEqual(result["winner"], "guest")
            self.assertEqual(result["winner_reward_q_coins"], 80)
            host_wallet = db.execute("select q_coins from card_wallets where device=?", (host_device,)).fetchone()[0]
            guest_wallet = db.execute("select q_coins from card_wallets where device=?", (guest_device,)).fetchone()[0]
            self.assertEqual((host_wallet, guest_wallet), (1160, 1240))

    def _card_http(self, device, path, payload=None):
        headers = {"X-Device-Id": device}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        with urlopen(Request(self.base + path, headers=headers,
                             data=json.dumps(payload).encode() if payload is not None else None)) as response:
            return json.load(response)

    def _card_pair(self, prefix, stake=40):
        code = prefix + "-code-2026"
        devices = {"host": prefix + "-host-device", "guest": prefix + "-guest-device"}
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"card_game_enabled": "1", "card_game_access_hash": self.panel.password_hash(code),
                                         "card_game_start_coins": "1200", "card_game_stake_q_coins": str(stake)})
            db.commit()
        snapshots = {seat: self._card_http(device, "/api/client/cards/join",
                                         {"access_code": code, "display_name": "Игрок " + seat})
                     for seat, device in devices.items()}
        return devices, snapshots

    def _card_state(self, device, ticket):
        return self._card_http(device, "/api/client/cards/state?ticket=" + ticket)

    def test_card_game_http_complete_match_and_payout_retry(self):
        rng = random.Random(42)
        deal = self.panel.durak.new_game(rng=rng)
        with mock.patch.object(self.panel, "rate_limited", return_value=False), \
                mock.patch.object(self.panel, "durak_new_game", return_value=deal):
            devices, snapshots = self._card_pair("full-match")
            self.assertEqual(snapshots["host"]["game_phase"], "waiting")
            self.assertFalse(snapshots["host"]["can_take"])
            self.assertFalse(snapshots["guest"]["can_pass"])
            self.assertEqual(snapshots["guest"]["hand"], [])
            ready = self._card_http(devices["host"], "/api/client/cards/action", {
                "ticket": snapshots["host"]["ticket"], "action": "ready",
                "expected_revision": 0, "action_id": "full-match-ready-host",
            })
            current = self._card_http(devices["guest"], "/api/client/cards/action", {
                "ticket": snapshots["guest"]["ticket"], "action": "ready",
                "expected_revision": ready["revision"], "action_id": "full-match-ready-guest",
            })
            self.assertEqual(current["q_coins"], 1160)
            tickets = {seat: snapshot["ticket"] for seat, snapshot in snapshots.items()}
            actions = set()
            for sequence in range(1000):
                if current["game_phase"] == "finished":
                    break
                attacker = current["attacker"]
                defender = "guest" if attacker == "host" else "host"
                if not current["table_cards"]:
                    seat = attacker
                    view = self._card_state(devices[seat], tickets[seat])
                    payload = {"action": "attack", "card": rng.choice(view["legal_attack_cards"])}
                elif any(not pair["defense"] for pair in current["table_cards"]):
                    seat = defender
                    view = self._card_state(devices[seat], tickets[seat])
                    if view["legal_defenses"]:
                        option = rng.choice(view["legal_defenses"])
                        payload = {"action": "defend", **option}
                    else:
                        payload = {"action": "take"}
                else:
                    seat = attacker
                    view = self._card_state(devices[seat], tickets[seat])
                    payload = {"action": "pass"}
                payload.update(ticket=tickets[seat], expected_revision=view["revision"],
                               action_id=f"full-match-action-{sequence:04}")
                actions.add(payload["action"])
                current = self._card_http(devices[seat], "/api/client/cards/action", payload)
                self.assertNotIn("hands", current)
                self.assertNotIn("deck", current)
                with closing(self.panel.conn()) as db:
                    game = json.loads(db.execute("select game_json from card_tables where id=?",
                                                 (current["table_id"],)).fetchone()[0])
                self.panel.durak.validate_state(game)
            else:
                self.fail("HTTP match did not complete")
            self.assertEqual(actions, {"attack", "defend", "take", "pass"})
            self.assertEqual(current["table_cards"], [])
            self.assertEqual(current["deck_count"], 0)
            before_retry = {seat: self._card_state(device, tickets[seat])["q_coins"] for seat, device in devices.items()}
            duplicate = self._card_http(devices[seat], "/api/client/cards/action", payload)
            after_retry = {player: self._card_state(device, tickets[player])["q_coins"]
                           for player, device in devices.items()}
            self.assertEqual(duplicate["revision"], current["revision"])
            self.assertEqual(before_retry, after_retry)
            self.assertEqual(sum(after_retry.values()), 2400)
            if current["winner"] == "draw":
                self.assertEqual(set(after_retry.values()), {1200})
            else:
                self.assertEqual(after_retry[current["winner"]], 1240)
                self.assertEqual(after_retry[self.panel.durak.other(current["winner"])], 1160)

    def test_card_game_stale_http_action_is_409_and_non_mutating(self):
        devices, snapshots = self._card_pair("stale-match")
        ready = self._card_http(devices["host"], "/api/client/cards/action", {
            "ticket": snapshots["host"]["ticket"], "action": "ready", "expected_revision": 0,
            "action_id": "stale-ready-host",
        })
        request = {"ticket": snapshots["guest"]["ticket"], "action": "ready", "expected_revision": 0,
                   "action_id": "stale-ready-guest"}
        with self.assertRaises(HTTPError) as caught:
            self._card_http(devices["guest"], "/api/client/cards/action", request)
        self.assertEqual(caught.exception.code, 409)
        self.assertEqual(json.load(caught.exception)["error"], "stale_game_state")
        unchanged = self._card_state(devices["guest"], snapshots["guest"]["ticket"])
        self.assertEqual(unchanged["revision"], ready["revision"])
        self.assertEqual(unchanged["q_coins"], 1200)
        self.assertTrue(unchanged["can_ready"])

    def test_card_game_draw_refunds_each_stake_exactly_once(self):
        devices, snapshots = self._card_pair("draw-match")
        for seat in self.panel.durak.SEATS:
            self._card_http(devices[seat], "/api/client/cards/action", {
                "ticket": snapshots[seat]["ticket"], "action": "ready", "action_id": "draw-ready-" + seat,
            })
        with closing(self.panel.conn()) as db:
            game = json.loads(db.execute("select game_json from card_tables where id=?",
                                         (snapshots["host"]["table_id"],)).fetchone()[0])
            game.update(deck=[], hands={"host": ["6H"], "guest": ["7H"]}, attacker="host", table=[],
                        bout_limit=1, discard=sorted(self.panel.durak.CARDS.difference(["6H", "7H"])))
            db.execute("update card_tables set game_json=? where id=?",
                       (json.dumps(game), snapshots["host"]["table_id"]))
            db.commit()
        for seat, action, card in (("host", "attack", "6H"), ("guest", "defend", "7H"), ("host", "pass", "")):
            payload = {"ticket": snapshots[seat]["ticket"], "action": action, "card": card,
                       "action_id": "draw-action-" + action}
            current = self._card_http(devices[seat], "/api/client/cards/action", payload)
        self.assertEqual(current["winner"], "draw")
        self.assertEqual(current["winner_reward_q_coins"], 0)
        self.assertEqual(current["stake_refund_q_coins"], 40)
        duplicate = self._card_http(devices["host"], "/api/client/cards/action", payload)
        self.assertEqual(duplicate["revision"], current["revision"])
        for seat in self.panel.durak.SEATS:
            self.assertEqual(self._card_state(devices[seat], snapshots[seat]["ticket"])["q_coins"], 1200)

    def test_card_game_insufficient_balance_rolls_back_ready_and_cards(self):
        devices, snapshots = self._card_pair("poor-match")
        self._card_http(devices["host"], "/api/client/cards/action", {
            "ticket": snapshots["host"]["ticket"], "action": "ready",
        })
        with closing(self.panel.conn()) as db:
            db.execute("update card_wallets set q_coins=0 where device=?", (self.panel.device_id(devices["guest"]),))
            db.commit()
        with self.assertRaises(HTTPError) as caught:
            self._card_http(devices["guest"], "/api/client/cards/action", {
                "ticket": snapshots["guest"]["ticket"], "action": "ready",
            })
        self.assertEqual(caught.exception.code, 400)
        host = self._card_state(devices["host"], snapshots["host"]["ticket"])
        guest = self._card_state(devices["guest"], snapshots["guest"]["ticket"])
        self.assertEqual(host["game_phase"], "ready")
        self.assertEqual(host["q_coins"], 1200)
        self.assertTrue(guest["can_ready"])
        self.assertEqual(host["revision"], guest["revision"])

    def test_card_game_http_selects_the_correct_uncovered_attack(self):
        devices, snapshots = self._card_pair("target-match")
        for seat in self.panel.durak.SEATS:
            self._card_http(devices[seat], "/api/client/cards/action", {
                "ticket": snapshots[seat]["ticket"], "action": "ready",
            })
        with closing(self.panel.conn()) as db:
            game = json.loads(db.execute("select game_json from card_tables where id=?",
                                         (snapshots["host"]["table_id"],)).fetchone()[0])
            game.update(deck=[], hands={"host": ["8C"], "guest": ["7S", "8H"]}, attacker="host",
                        trump="AC", table=[{"attack": "6H", "defense": ""}, {"attack": "6S", "defense": ""}],
                        bout_limit=2, discard=sorted(self.panel.durak.CARDS.difference(["8C", "7S", "8H", "6H", "6S"])))
            db.execute("update card_tables set game_json=? where id=?",
                       (json.dumps(game), snapshots["host"]["table_id"]))
            db.commit()
        payload = {"ticket": snapshots["guest"]["ticket"], "action": "defend", "card": "7S", "target": 0,
                   "expected_revision": game["revision"], "action_id": "target-defense-01"}
        with self.assertRaises(HTTPError) as caught:
            self._card_http(devices["guest"], "/api/client/cards/action", payload)
        self.assertEqual(caught.exception.code, 400)
        payload["target"] = 1
        defended = self._card_http(devices["guest"], "/api/client/cards/action", payload)
        self.assertEqual(defended["table_cards"], [{"attack": "6H", "defense": ""}, {"attack": "6S", "defense": "7S"}])
        self.assertEqual(defended["revision"], game["revision"] + 1)
        self.assertTrue(defended["can_defend"])

    def test_card_game_concurrent_double_click_replays_only_once(self):
        with mock.patch.object(self.panel, "rate_limited", return_value=False):
            devices, snapshots = self._card_pair("double-match")
            for seat in self.panel.durak.SEATS:
                current = self._card_http(devices[seat], "/api/client/cards/action", {
                    "ticket": snapshots[seat]["ticket"], "action": "ready", "action_id": "double-ready-" + seat,
                })
            seat = current["attacker"]
            view = self._card_state(devices[seat], snapshots[seat]["ticket"])
            payload = {"ticket": snapshots[seat]["ticket"], "action": "attack", "card": view["legal_attack_cards"][0],
                       "expected_revision": view["revision"], "action_id": "double-attack-same-id"}
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                calls = [pool.submit(self._card_http, devices[seat], "/api/client/cards/action", payload) for _ in range(2)]
                replies = [call.result(timeout=10) for call in calls]
            for reply in replies:
                self.assertEqual(reply["revision"], view["revision"] + 1)
                self.assertEqual(len(reply["table_cards"]), 1)
                self.assertEqual(len(reply["hand"]), 5)
                self.assertEqual(reply["q_coins"], 1160)

    def test_card_game_rejoin_restores_active_room_then_deals_fresh_after_finish(self):
        """The existing authenticated join is also the safe new-party path."""
        with mock.patch.object(self.panel, "rate_limited", return_value=False):
            devices, snapshots = self._card_pair("fresh-match")
            code = "fresh-match-code-2026"
            for seat in self.panel.durak.SEATS:
                self._card_http(devices[seat], "/api/client/cards/action", {
                    "ticket": snapshots[seat]["ticket"], "action": "ready",
                })
            before = self._card_state(devices["host"], snapshots["host"]["ticket"])
            restored = self._card_http(devices["host"], "/api/client/cards/join", {
                "access_code": code, "display_name": "Игрок host",
            })
            self.assertEqual(restored["table_id"], before["table_id"])
            self.assertEqual(restored["hand"], before["hand"])
            self.assertEqual(restored["revision"], before["revision"])
            self.assertEqual(restored["q_coins"], 1160)
            with closing(self.panel.conn()) as db:
                game = json.loads(db.execute("select game_json from card_tables where id=?",
                                             (before["table_id"],)).fetchone()[0])
                game.update(deck=[], hands={"host": ["6H"], "guest": ["7H"]}, attacker="host", table=[],
                            bout_limit=1, discard=sorted(self.panel.durak.CARDS.difference(["6H", "7H"])))
                db.execute("update card_tables set game_json=? where id=?", (json.dumps(game), before["table_id"]))
                db.commit()
            for seat, action, card in (("host", "attack", "6H"), ("guest", "defend", "7H"), ("host", "pass", "")):
                finished = self._card_http(devices[seat], "/api/client/cards/action", {
                    "ticket": snapshots[seat]["ticket"], "action": action, "card": card,
                })
            self.assertEqual(finished["game_phase"], "finished")
            self.assertEqual(finished["winner"], "draw")
            fresh_deal = self.panel.durak.new_game(rng=random.Random(71))
            with mock.patch.object(self.panel, "durak_new_game", return_value=fresh_deal):
                new_host = self._card_http(devices["host"], "/api/client/cards/join", {
                    "access_code": code, "display_name": "Игрок host",
                })
                self.assertNotEqual(new_host["table_id"], before["table_id"])
                self.assertEqual(new_host["game_phase"], "waiting")
                self.assertEqual(new_host["hand"], [])
                self.assertEqual(new_host["q_coins"], 1200)
                new_guest = self._card_http(devices["guest"], "/api/client/cards/join", {
                    "access_code": code, "display_name": "Игрок guest",
                })
            self.assertEqual(new_guest["table_id"], new_host["table_id"])
            self.assertEqual(new_guest["game_phase"], "ready")
            self.assertEqual(new_guest["deck_count"], 24)
            self.assertEqual(new_guest["discard_count"], 0)
            self.assertEqual(new_guest["revision"], 0)
            self.assertFalse(new_guest["can_take"])
            old_room = self._card_state(devices["host"], snapshots["host"]["ticket"])
            self.assertEqual(old_room["game_phase"], "finished")
            with self.assertRaises(HTTPError) as old_action:
                self._card_http(devices["host"], "/api/client/cards/action", {
                    "ticket": snapshots["host"]["ticket"], "action": "attack", "card": "6H",
                })
            old_action.exception.close()
            for seat in self.panel.durak.SEATS:
                current = self._card_http(devices[seat], "/api/client/cards/action", {
                    "ticket": (new_host if seat == "host" else new_guest)["ticket"], "action": "ready",
                    "action_id": "fresh-party-ready-" + seat,
                })
            self.assertEqual(current["game_phase"], "playing")
            for seat in self.panel.durak.SEATS:
                view = self._card_state(devices[seat], (new_host if seat == "host" else new_guest)["ticket"])
                self.assertEqual(view["hand"], fresh_deal["hands"][seat])
                self.assertEqual(view["q_coins"], 1160)

    def test_routing_draft_saves_doh_without_publishing(self):
        token = base64.b64encode(b"test:test").decode()
        with closing(self.panel.conn()) as db:
            initial = self.panel.settings(db)
            revision = initial["routing_revision"]
        body = (
            b"action=save&routing_enabled=on&routing_profile=balanced&routing_adblock_enabled=on"
            b"&routing_dns_mode=vpn_only&routing_dns_resolver=https%3A%2F%2Fdns.adguard-dns.com%2Fdns-query"
            b"&routing_proxy_domains=youtube.com&routing_direct_domains=&routing_block_domains="
            b"&routing_proxy_cidrs=&routing_direct_cidrs="
        )
        with urlopen(Request(self.base + "/operator/routing", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            saved = self.panel.settings(db)
            self.assertEqual(saved["routing_revision"], revision)
            draft = json.loads(saved["routing_draft_payload"])
            self.assertEqual(draft["dns"]["resolver"], "https://dns.adguard-dns.com/dns-query")

    def test_public_status_hides_download_during_maintenance(self):
        with closing(self.panel.conn()) as db:
            previous = self.panel.settings(db)
            self.panel.set_settings(db, {"maintenance": "1", "public_download_enabled": "1"})
            db.commit()
        try:
            with urlopen(self.base + "/status") as response:
                page = response.read().decode("utf-8")
            self.assertIn("Maintenance", page)
            self.assertIn("download temporarily unavailable", page)
            self.assertNotIn("QuantumVPN-", page)
        finally:
            with closing(self.panel.conn()) as db:
                self.panel.set_settings(db, {"maintenance": previous["maintenance"], "public_download_enabled": previous["public_download_enabled"]})
                db.commit()

    def test_public_status_settings_save_without_cross_tab_redirect(self):
        token = base64.b64encode(b"test:test").decode()
        body = (
            b"section=public_status&public_download_enabled=on&"
            b"public_status_note_en=All+services+are+being+monitored."
        )
        with urlopen(
            Request(
                self.base + "/operator/policy",
                data=body,
                headers={"Authorization": "Basic " + token},
            ),
        ) as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"Public status site", response.read())
        with closing(self.panel.conn()) as db:
            saved = self.panel.settings(db)
            self.assertEqual(saved["public_download_enabled"], "1")
            self.assertEqual(saved["public_status_note_en"], "All services are being monitored.")

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
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)
        with urlopen(Request(self.base + "/operator/routing", data=body, headers={"Authorization": "Basic " + token})) as response:
            self.assertEqual(response.status, 200)
            preview = confirmed_control_fields(response.read().decode("utf-8"))
        with closing(self.panel.conn()) as db:
            unchanged = self.panel.settings(db)
        self.assertEqual(unchanged["routing_profile"], before["routing_profile"])
        self.assertEqual(unchanged["routing_revision"], before["routing_revision"])
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(),
                             headers={"Authorization": "Basic " + token, "Origin": self.panel.PUBLIC_BASE})) as response:
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
        self.assertIn("Каталог и анализатор целей", page)
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
            preview = confirmed_control_fields(response.read().decode("utf-8"))
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            not_yet_promoted = json.load(response)
        self.assertEqual(not_yet_promoted["payload"], stable["payload"])
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(),
                             headers={"Authorization": "Basic " + token, "Origin": self.panel.PUBLIC_BASE})) as response:
            self.assertEqual(response.status, 200)
        with urlopen(self.base + "/api/client/routing?bucket=99") as response:
            promoted = json.load(response)
        self.assertEqual(promoted["channel"], "production")
        self.assertEqual(promoted["payload"]["profile"], "proxy_all")

    def test_routing_target_advisor_is_bounded_and_never_publishes(self):
        token = base64.b64encode(b"test:test").decode()
        with urlopen(Request(self.base + "/operator?tab=routing", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        class CSRF(HTMLParser):
            value = ""
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "input" and attrs.get("id") == "routing-catalog-csrf":
                    self.value = attrs.get("value", "")
        parser = CSRF()
        parser.feed(page)
        self.assertTrue(parser.value)
        with closing(self.panel.conn()) as db:
            revision_before = self.panel.settings(db)["routing_revision"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=["1.1.1.1"]), \
             mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=17):
            request = Request(
                self.base + "/operator/routing",
                data=urlencode({"action": "scan", "routing_scan_targets": "example.com\n1.1.1.1", "csrf": parser.value}).encode(),
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
        self.assertIn("Каталог и анализатор целей", page)
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
