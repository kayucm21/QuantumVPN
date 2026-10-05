"""Isolated HTTP contract tests: browser origin, CSRF, recovery and real keys."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from http.cookies import SimpleCookie
from html.parser import HTMLParser
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from tools import quantumvpn_control_next as controls
from tools import test_control_next as control_fixtures
from tools.test_operator_panel import confirmed_control_fields

ORIGIN = control_fixtures.ORIGIN


def browser_form_origin(page, response_headers, document_url, action_url):
    """Model Fetch's Origin serialization for a top-level form POST.

    urllib does not apply the document's referrer policy. In browsers, the
    response header initializes it and a referrer meta element overrides it;
    a non-CORS POST under no-referrer then sends Origin: null.
    https://fetch.spec.whatwg.org/#append-a-request-origin-header
    """
    class ReferrerMeta(HTMLParser):
        policy = response_headers.get("Referrer-Policy", "strict-origin-when-cross-origin")

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "meta" and attrs.get("name", "").lower() == "referrer":
                self.policy = attrs.get("content", "").lower()

    metadata = ReferrerMeta()
    metadata.feed(page)
    source, target = urlsplit(document_url), urlsplit(action_url)
    source_origin = (source.scheme, source.hostname, source.port or (443 if source.scheme == "https" else 80))
    target_origin = (target.scheme, target.hostname, target.port or (443 if target.scheme == "https" else 80))
    if metadata.policy == "no-referrer" or (metadata.policy == "same-origin" and source_origin != target_origin):
        return "null"
    return source.scheme + "://" + source.netloc


class ControlHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ)
        os.environ.update(QV_DATA_DIR=cls.tmp.name, QV_DOWNLOAD_ROOT=cls.tmp.name, QV_ADMIN_USER="owner-test", QV_ADMIN_PASSWORD="strong-unit-test-password",
                          QV_SUBSCRIPTION_UPSTREAM="https://example.invalid/sub", QV_PUBLIC_BASE=ORIGIN)
        spec = importlib.util.spec_from_file_location("panel_control_http", Path(__file__).with_name("quantumvpn_operator_panel.py"))
        cls.panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.panel)
        os.environ.clear()
        os.environ.update(cls.env)
        with closing(cls.panel.conn()) as db:
            db.execute("insert into admin_users values (?,?,?,?,?,?)", ("operator-test", cls.panel.password_hash("operator-password"), "operator", 1, 1, 1))
            db.execute("insert into admin_users values (?,?,?,?,?,?)", ("viewer-test", cls.panel.password_hash("viewer-password"), "viewer", 1, 1, 1))
            db.commit()
        for abi in ("arm64-v8a", "armeabi-v7a"):
            file = Path(cls.tmp.name) / cls.panel.VERSION / f"QuantumVPN-{cls.panel.VERSION}-operator-debug-{abi}.apk"
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(b"unit-test-only")
        cls.server = cls.panel.OperatorHTTPServer(("127.0.0.1", 0), cls.panel.App)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.panel._RATE.clear()
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"routing_enabled": "1", "routing_profile": "balanced", "update_rollout_paused": "0", "totp_enabled": "0", "totp_secret": "", "release_guard_enabled": "0"})
            db.execute("delete from control_passkeys")
            db.execute("delete from control_passkey_users")
            db.execute("delete from control_passkey_challenges")
            db.commit()
        self.cookie = self.make_cookie("owner-test")
        self.csrf = controls.csrf_token(self.panel.session_secret(), hashlib.sha256(self.cookie.split("=", 1)[1].encode()).hexdigest())

    def make_cookie(self, user, nonce="unit-test-browser-session-nonce"):
        value = self.panel.sign_session({"u": user, "exp": int(time.time()) + 3600, "n": nonce})
        return self.panel.SESSION_COOKIE + "=" + value

    def json_post(self, path, payload, headers=None):
        request_headers = {"Origin": ORIGIN, "Content-Type": "application/json", "X-QV-Request": "1", "Cookie": self.cookie, "X-QV-CSRF": self.csrf}
        request_headers.update(headers or {})
        try:
            response = urlopen(Request(self.base + path, data=json.dumps(payload).encode(), headers=request_headers))
        except HTTPError as error:
            response = error
        with response:
            return response.status, dict(response.headers), json.loads(response.read())

    def routing_preview(self):
        # The public HTTPS reverse proxy forwards to this isolated HTTP server.
        headers = {"Cookie": self.cookie, "Host": urlsplit(ORIGIN).netloc}
        with urlopen(Request(self.base + "/operator?tab=routing", headers=headers)) as response:
            panel_headers = dict(response.headers)
            panel_page = response.read().decode()
        headers.update({"Origin": browser_form_origin(panel_page, panel_headers, ORIGIN + "/operator?tab=routing", ORIGIN + "/operator/routing"),
                        "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"})
        body = urlencode({"action": "publish", "routing_enabled": "on", "routing_profile": "whitelist", "routing_dns_mode": "vpn_only",
                          "routing_dns_resolver": "https://dns.example/dns-query", "routing_proxy_domains": "video.example"}).encode()
        with urlopen(Request(self.base + "/operator/routing", data=body, headers=headers)) as response:
            preview_headers = dict(response.headers)
            preview_page = response.read().decode()
        return confirmed_control_fields(preview_page), browser_form_origin(
            preview_page, preview_headers, ORIGIN + "/operator/routing", ORIGIN + "/operator/control/apply")

    def test_routing_publish_browser_form_confirmation(self):
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)
        preview, origin = self.routing_preview()
        self.assertEqual(origin, ORIGIN)
        self.assertEqual(preview["csrf"], self.csrf)
        with closing(self.panel.conn()) as db:
            current = self.panel.settings(db)
            self.assertEqual(current["routing_profile"], before["routing_profile"])
            self.assertEqual(current["routing_revision"], before["routing_revision"])
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(),
                             headers={"Cookie": self.cookie, "Origin": origin, "Sec-Fetch-Site": "same-origin"})) as response:
            self.assertIn("tab=routing", response.url)
            self.assertIn("Изменения подтверждены", response.read().decode())
        with closing(self.panel.conn()) as db:
            current = self.panel.settings(db)
            self.assertEqual(current["routing_profile"], "whitelist")
            self.assertEqual(int(current["routing_revision"]), int(before["routing_revision"]) + 1)

    def test_routing_confirmation_retains_strict_origin_and_session_csrf(self):
        preview, _ = self.routing_preview()
        other_session = self.make_cookie("owner-test", "a-different-browser-session")
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)
        attempts = (
            {"Origin": "null"}, {"Origin": ""}, {"Origin": "https://evil.example"},
            {"Origin": "https://" + urlsplit(ORIGIN).hostname}, {"Sec-Fetch-Site": "cross-site"},
            {"Cookie": other_session},
        )
        for override in attempts:
            with self.subTest(override=override):
                headers = {"Cookie": self.cookie, "Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}
                headers.update(override)
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(), headers=headers))
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.base + "/operator/control/apply", data=urlencode({**preview, "csrf": "wrong"}).encode(),
                            headers={"Cookie": self.cookie, "Origin": ORIGIN}))
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()
        with closing(self.panel.conn()) as db:
            current = self.panel.settings(db)
            self.assertEqual(current["routing_revision"], before["routing_revision"])
            self.assertEqual(current["routing_profile"], before["routing_profile"])
        # Failed requests do not consume the legitimate confirmation.
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(),
                             headers={"Cookie": self.cookie, "Origin": ORIGIN})) as response:
            self.assertIn("tab=routing", response.url)

    def test_nodes_preview_and_confirmation_origin_csrf(self):
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)["nodes_recommended"]
        with urlopen(Request(self.base + "/operator/policy", data=b"section=nodes&nodes_recommended=main&nodes_forbidden=", headers={"Cookie": self.cookie, "Origin": ORIGIN})) as response:
            preview = confirmed_control_fields(response.read().decode())
        with closing(self.panel.conn()) as db:
            self.assertEqual(self.panel.settings(db)["nodes_recommended"], before)
        for origin, csrf in (("https://evil.example", preview["csrf"]), (ORIGIN, "wrong")):
            with self.assertRaises(HTTPError) as caught:
                urlopen(Request(self.base + "/operator/control/apply", data=urlencode({**preview, "csrf": csrf}).encode(), headers={"Cookie": self.cookie, "Origin": origin}))
            self.assertEqual(caught.exception.code, 403)
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(), headers={"Cookie": self.cookie, "Origin": ORIGIN})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            self.assertEqual(self.panel.settings(db)["nodes_recommended"], "main")
        with closing(self.panel.conn()) as db:
            db.execute("update settings set value=? where key='nodes_recommended'", (before,))
            db.commit()

    def test_release_controls_owner_only_and_no_schedule_change(self):
        cookie = self.make_cookie("operator-test")
        csrf = controls.csrf_token(self.panel.session_secret(), hashlib.sha256(cookie.split("=", 1)[1].encode()).hexdigest())
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.base + "/operator/control/preview", data=urlencode({"scope": "release", "rollout_percent": "50", "csrf": csrf}).encode(), headers={"Cookie": cookie, "Origin": ORIGIN}))
        self.assertEqual(caught.exception.code, 403)
        with closing(self.panel.conn()) as db:
            before = self.panel.settings(db)
        body = urlencode({"scope": "release", "rollout_percent": "50", "update_rollout_paused": "on", "csrf": self.csrf}).encode()
        with urlopen(Request(self.base + "/operator/control/preview", data=body, headers={"Cookie": self.cookie, "Origin": ORIGIN})) as response:
            preview = confirmed_control_fields(response.read().decode())
        with urlopen(Request(self.base + "/operator/control/apply", data=urlencode(preview).encode(), headers={"Cookie": self.cookie, "Origin": ORIGIN})) as response:
            self.assertEqual(response.status, 200)
        with closing(self.panel.conn()) as db:
            after = self.panel.settings(db)
        for key in ("app_version", "app_version_code", "release_publish_at", "scheduled_app_version", "release_schedule_enabled"):
            self.assertEqual(before[key], after[key])
        with urlopen(self.base + "/api/client/update?abi=arm64-v8a&current_version_code=1&current_version=0.0.1") as response:
            info = json.load(response)
        self.assertTrue(info["rollout_paused"])
        self.assertFalse(info["rollout_eligible"])
        self.assertEqual(info["version_code"], 1)

    def test_passkey_strict_origin_json_and_csrf(self):
        path = "/operator/passkey/register/begin"
        for override in ({"Origin": "null"}, {"Origin": "https://evil.example"}, {"Origin": ""}, {"Content-Type": "text/plain"}, {"X-QV-Request": ""}):
            status, _, _ = self.json_post(path, {"password": "strong-unit-test-password"}, override)
            self.assertEqual(status, 403)
        if controls.passkey_available():
            status, _, _ = self.json_post(path, {"password": "strong-unit-test-password"}, {"X-QV-CSRF": "wrong"})
            self.assertEqual(status, 403)

    @unittest.skipUnless(controls.passkey_available(), "Optional official webauthn package not installed")
    def test_enrollment_requires_fresh_password_and_enabled_totp(self):
        status, _, _ = self.json_post("/operator/passkey/register/begin", {"password": "wrong"})
        self.assertEqual(status, 400)
        secret = "JBSWY3DPEHPK3PXP"
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"totp_enabled": "1", "totp_secret": secret})
            db.commit()
        status, _, _ = self.json_post("/operator/passkey/register/begin", {"password": "strong-unit-test-password", "totp": "000000"})
        self.assertEqual(status, 400)
        status, _, value = self.json_post("/operator/passkey/register/begin", {"password": "strong-unit-test-password", "totp": self.panel.totp_at(secret)})
        self.assertEqual(status, 200)
        self.assertEqual(value["options"]["authenticatorSelection"]["userVerification"], "required")

    @unittest.skipUnless(controls.passkey_available(), "Optional official webauthn package not installed")
    def test_real_http_register_authenticate_cookie_and_recovery(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"real-http-test-only-credential"
        self.client_data = control_fixtures.PasskeyTests.client_data.__get__(self)
        self.register_credential = control_fixtures.PasskeyTests.register_credential.__get__(self)
        self.authenticate_credential = control_fixtures.PasskeyTests.authenticate_credential.__get__(self)
        status, _, begin = self.json_post("/operator/passkey/register/begin", {"password": "strong-unit-test-password"})
        self.assertEqual(status, 200)
        status, _, result = self.json_post("/operator/passkey/register/finish", {"ceremony_id": begin["ceremony_id"], "credential": self.register_credential(begin), "label": "Test key"})
        self.assertEqual(status, 200)
        self.assertTrue(result["registered"])
        status, headers, begin = self.json_post("/operator/passkey/authenticate/begin", {"username": "owner-test"}, {"Cookie": ""})
        self.assertEqual(status, 200)
        preauth = SimpleCookie(headers["Set-Cookie"])
        self.assertTrue(preauth["qv_passkey_preauth"]["httponly"])
        self.assertTrue(preauth["qv_passkey_preauth"]["secure"])
        cookie = "qv_passkey_preauth=" + preauth["qv_passkey_preauth"].value
        status, headers, result = self.json_post("/operator/passkey/authenticate/finish", {"ceremony_id": begin["ceremony_id"], "credential": self.authenticate_credential(begin)}, {"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertTrue(result["authenticated"])
        session = SimpleCookie(headers["Set-Cookie"])
        self.assertEqual(self.panel.verify_session(session[self.panel.SESSION_COOKIE].value)["u"], "owner-test")
        # Enrollment never disables the existing password recovery login.
        with urlopen(Request(self.base + "/operator/login", data=b"username=owner-test&password=strong-unit-test-password", headers={"Origin": ORIGIN})) as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
