import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from contextlib import closing
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
        for body in (b"section=service&maintenance=on&maintenance_message=test", b"section=subscription&subscription_main_enabled=on"):
            with urlopen(Request(self.base + "/operator/policy", data=body, headers={"Authorization": "Basic " + token})) as response:
                self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            settings = self.panel.settings(db)
            self.assertEqual(settings["maintenance"], "1")
            self.assertEqual(settings["subscription_main_enabled"], "1")
            self.assertEqual(db.execute("select count(*) from audit where action like 'policy:%'").fetchone()[0], 2)

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


if __name__ == "__main__":
    unittest.main()
