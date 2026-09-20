import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
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
            self.assertEqual(db.execute("select count(*) from events where kind='admin'").fetchone()[0], 2)

    def test_operator_download_buttons_use_current_version(self):
        token = base64.b64encode(b"test:test").decode()
        with urlopen(Request(self.base + "/operator", headers={"Authorization": "Basic " + token})) as response:
            page = response.read().decode("utf-8")
        self.assertIn(f"APK {self.panel.VERSION}", page)
        self.assertIn(f"/downloads/{self.panel.VERSION}/QuantumVPN-{self.panel.VERSION}-operator-debug-arm64-v8a.apk", page)
        self.assertNotIn("5.6.13", page)


if __name__ == "__main__":
    unittest.main()
