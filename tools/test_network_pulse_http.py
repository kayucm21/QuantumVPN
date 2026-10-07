"""Isolated Network-center HTTP contracts: roles, CSRF, typed writes and secrets.

No real proxy, DNS lookup, service operation or VDS connection is used. The
production request handler and SQLite database are exercised through HTTP.
"""
from contextlib import closing
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from tools import quantumvpn_control_next as controls
from tools import quantumvpn_network_center as network_center
from tools.test_control_next import ORIGIN


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def hidden_fields(page):
    class Inputs(HTMLParser):
        def __init__(self):
            super().__init__()
            self.fields = {}

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
                self.fields[attrs["name"]] = attrs.get("value", "")

    parser = Inputs()
    parser.feed(page)
    return parser.fields


class NetworkPulseHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with mock.patch.dict(os.environ, {
                "QV_DATA_DIR": cls.tmp.name, "QV_DOWNLOAD_ROOT": cls.tmp.name,
                "QV_ADMIN_USER": "owner-test", "QV_ADMIN_PASSWORD": "strong-unit-test-password",
                "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub", "QV_PUBLIC_BASE": ORIGIN}):
            spec = importlib.util.spec_from_file_location(
                "panel_network_pulse_http", Path(__file__).with_name("quantumvpn_operator_panel.py"))
            cls.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.panel)
        with closing(cls.panel.conn()) as db:
            for user, role in (("operator-test", "operator"), ("viewer-test", "viewer")):
                db.execute("insert into admin_users values (?,?,?,?,?,?)", (
                    user, cls.panel.password_hash("strong-test-password"), role, 1, 1, 1))
            cls.panel.set_settings(db, {
                "routing_enabled": "1", "routing_profile": "balanced", "routing_proxy_domains": "video.example",
                "ai_engine": "llama.cpp", "ai_model": "qwen3:0.6b", "ai_autopilot_enabled": "1",
                "ai_monitor_interval_seconds": "60", "ai_action_cooldown_seconds": "900", "ai_required_checks": "3",
                "totp_enabled": "0", "totp_secret": "", "release_guard_enabled": "0"})
            db.commit()
            cls.baseline = cls.panel.settings(db)
        for abi in ("arm64-v8a", "armeabi-v7a"):
            artifact = Path(cls.tmp.name) / cls.panel.VERSION / f"QuantumVPN-{cls.panel.VERSION}-operator-debug-{abi}.apk"
            artifact.parent.mkdir(exist_ok=True)
            artifact.write_bytes(b"isolated-network-http-test-only")
        cls.server = cls.panel.OperatorHTTPServer(("127.0.0.1", 0), cls.panel.App)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)
        cls.opener = build_opener(_NoRedirect())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.panel._RATE.clear()
        with closing(self.panel.conn()) as db:
            db.execute("delete from settings")
            self.panel.set_settings(db, self.baseline)
            db.execute("delete from audit")
            db.commit()
        self.cookie = self.make_cookie("owner-test")
        self.csrf = self.csrf_for(self.cookie)
        self.secret = "dd" + "ab" * 16
        self.links = {
            "telegram": "tg://proxy?server=150.241.96.191&port=3443&secret=" + self.secret,
            "https": "https://t.me/proxy?server=150.241.96.191&port=3443&secret=" + self.secret}
        self.status = {"installed": True, "service": "active", "status": "active", "port": 3443,
                       "server": "150.241.96.191", "stats_loopback_only": True, "secret_available": True,
                       "protocol_health": {"ok": True, "status": "confirmed"}, "upstream_ready": True}
        self.snapshot = network_center.sanitize_xray_config({
            "inbounds": [{"tag": "vless-in"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "wireguard"}],
            "routing": {"rules": [{"type": "field", "domain": ["domain:video.example"], "outboundTag": "warp"}]}})
        for target, value in ((self.panel.mtproto, "snapshot"), (self.panel.network_center, "read_xray_snapshot")):
            patch = mock.patch.object(target, value, return_value=self.status if value == "snapshot" else self.snapshot)
            patch.start()
            self.addCleanup(patch.stop)

    def make_cookie(self, user, nonce="network-http-test-session-nonce"):
        return self.panel.SESSION_COOKIE + "=" + self.panel.sign_session({
            "u": user, "exp": int(time.time()) + 3600, "n": nonce})

    def csrf_for(self, cookie):
        binding = hashlib.sha256(cookie.split("=", 1)[1].encode()).hexdigest()
        return controls.csrf_token(self.panel.session_secret(), binding)

    def settings(self):
        with closing(self.panel.conn()) as db:
            return self.panel.settings(db)

    def audit_text(self):
        with closing(self.panel.conn()) as db:
            return json.dumps([list(row) for row in db.execute("select action,detail from audit")], ensure_ascii=False)

    def request(self, path, data=None, *, user=None, headers=None, raw=None):
        cookie = self.make_cookie(user) if user else self.cookie
        request_headers = {"Cookie": cookie, "Host": urlsplit(ORIGIN).netloc}
        if data is not None or raw is not None:
            request_headers.update({"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin",
                                    "Content-Type": "application/x-www-form-urlencoded"})
        request_headers.update(headers or {})
        payload = raw if raw is not None else (urlencode(data, doseq=True).encode() if data is not None else None)
        try:
            response = self.opener.open(Request(self.base + path, data=payload, headers=request_headers), timeout=20)
        except HTTPError as error:
            response = error
        with response:
            return response.status, dict(response.headers), response.read().decode("utf-8", errors="replace")

    def form(self, user=None, **values):
        cookie = self.make_cookie(user) if user else self.cookie
        return {"csrf": self.csrf_for(cookie), **values}

    def assert_network_redirect(self, status, headers, view):
        self.assertEqual(status, 303)
        query = parse_qs(urlsplit(headers["Location"]).query)
        self.assertEqual(query["tab"], ["network"])
        self.assertEqual(query["network_view"], [view])
        return query

    def test_all_network_views_are_get_safe_for_owner_and_viewer(self):
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", return_value=self.links) as links, \
                mock.patch.object(self.panel.mtproto, "control") as control, \
                mock.patch.object(self.panel.mtproto, "health_probe") as probe:
            for user in ("owner-test", "viewer-test"):
                for view in network_center.NETWORK_VIEWS:
                    with self.subTest(user=user, view=view):
                        status, headers, page = self.request("/operator?tab=network&network_view=" + view, user=user)
                        self.assertEqual(status, 200)
                        self.assertIn("Сеть", page)
                        self.assertNotIn(self.secret, page)
                        self.assertIn("no-store", headers.get("Cache-Control", ""))
            links.assert_not_called()
            control.assert_not_called()
            probe.assert_not_called()

    def test_other_page_does_not_include_hidden_totp_secret(self):
        secret = "JBSWY3DPEHPK3PXP"
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"totp_enabled": "1", "totp_secret": secret})
            db.commit()
        for role in ("owner-test", "operator-test", "viewer-test"):
            with self.subTest(role=role):
                self.cookie = self.make_cookie(role)
                status, headers, body = self.request("/operator?tab=network&network_view=mtproto")
                self.assertEqual(status, 200)
                self.assertNotIn(secret, body)
                self.assertNotIn("otpauth://", body)

    def test_lab_normalizes_target_and_preserves_all_settings(self):
        before = self.settings()
        for raw, canonical in (("Video.Example.", "video.example"), ("8.8.8.8", "8.8.8.8"),
                               ("[2606:4700:4700::1111]", "2606:4700:4700::1111")):
            with self.subTest(target=raw):
                status, headers, _ = self.request("/operator/network/lab", self.form(
                    route_target=raw, policy_source="production"))
                query = self.assert_network_redirect(status, headers, "routes")
                self.assertEqual(query["network_target"], [canonical])
                self.assertEqual(query["policy_source"], ["production"])
        self.assertEqual(before, self.settings())

    def test_lab_rejects_private_targets_urls_and_unknown_policy(self):
        before = self.settings()
        for target in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "localhost.localdomain",
                       "host.internal", "https://video.example/path", "video.example:443", "a@video.example", "*.example", ""):
            with self.subTest(target=target):
                status, _, _ = self.request("/operator/network/lab", self.form(route_target=target, policy_source="production"))
                self.assertEqual(status, 400)
        status, _, _ = self.request("/operator/network/lab", self.form(route_target="video.example", policy_source="untrusted"))
        self.assertEqual(status, 400)
        self.assertEqual(before, self.settings())

    def test_lab_retains_exact_origin_fetch_site_and_session_csrf(self):
        before = self.settings()
        cases = ({"Origin": "null"}, {"Origin": ""}, {"Origin": "https://evil.example"},
                 {"Origin": "https://" + urlsplit(ORIGIN).hostname}, {"Sec-Fetch-Site": "cross-site"},
                 {"Cookie": self.make_cookie("owner-test", "another-network-session")})
        for override in cases:
            with self.subTest(headers=override):
                status, _, _ = self.request("/operator/network/lab", self.form(route_target="video.example"), headers=override)
                self.assertEqual(status, 403)
        for token in ("wrong", ""):
            status, _, _ = self.request("/operator/network/lab", self.form(route_target="video.example", csrf=token))
            self.assertEqual(status, 403)
        self.assertEqual(before, self.settings())

    def test_network_forms_bound_size_and_reject_duplicate_fields(self):
        before = self.settings()
        for fields in ({"route_target": ["video.example", "8.8.8.8"], "csrf": self.csrf},
                       {"route_target": "video.example", "csrf": [self.csrf, self.csrf]}):
            status, _, _ = self.request("/operator/network/lab", fields)
            self.assertEqual(status, 400)
        status, _, _ = self.request("/operator/network/lab", self.form(route_target="video.example", **{f"field{i}": "x" for i in range(12)}))
        self.assertEqual(status, 400)
        status, _, _ = self.request("/operator/network/lab", raw=b"route_target=" + b"a" * 8193)
        self.assertEqual(status, 413)
        self.assertEqual(before, self.settings())

    def test_viewer_cannot_run_lab_or_change_ai_policy(self):
        before = self.settings()
        for path, fields in (("lab", {"route_target": "video.example"}), ("ai", {"action": "freeze"})):
            status, _, _ = self.request("/operator/network/" + path, self.form("viewer-test", **fields), user="viewer-test")
            self.assertEqual(status, 403)
        self.assertEqual(before, self.settings())

    def test_ai_save_is_typed_and_preserves_model_release_and_routes(self):
        before = self.settings()
        status, headers, _ = self.request("/operator/network/ai", self.form("operator-test", action="save",
            ai_monitor_interval_seconds="120", ai_action_cooldown_seconds="1800", ai_required_checks="4",
            ai_autopilot_enabled="on"), user="operator-test")
        self.assert_network_redirect(status, headers, "ai")
        expected = {**before, "ai_monitor_interval_seconds": "120", "ai_action_cooldown_seconds": "1800",
                    "ai_required_checks": "4", "ai_autopilot_enabled": "1"}
        self.assertEqual(self.settings(), expected)
        self.assertIn("network:ai:save", self.audit_text())

    def test_ai_rejects_millisecond_churn_and_malformed_integers(self):
        before = self.settings()
        invalid = {"ai_monitor_interval_seconds": ("1", "59", "3601", "60.0", "true", "-1", "1e3"),
                   "ai_action_cooldown_seconds": ("299", "86401", "300.5"),
                   "ai_required_checks": ("2", "11", "3.0")}
        for key, candidates in invalid.items():
            for candidate in candidates:
                with self.subTest(field=key, value=candidate):
                    fields = self.form(action="save", ai_monitor_interval_seconds="60",
                                       ai_action_cooldown_seconds="900", ai_required_checks="3")
                    fields[key] = candidate
                    status, _, _ = self.request("/operator/network/ai", fields)
                    self.assertEqual(status, 400)
        self.assertEqual(before, self.settings())

    def test_ai_freeze_and_resume_only_change_autopilot_switch(self):
        before = self.settings()
        for action, enabled in (("freeze", "0"), ("unfreeze", "1")):
            status, headers, _ = self.request("/operator/network/ai", self.form(action=action))
            self.assert_network_redirect(status, headers, "ai")
            self.assertEqual(self.settings(), {**before, "ai_autopilot_enabled": enabled})

    def test_mtproto_actions_require_owner(self):
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", return_value=self.links) as links, \
                mock.patch.object(self.panel.mtproto, "control") as control, \
                mock.patch.object(self.panel.mtproto, "health_probe") as probe:
            for user in ("operator-test", "viewer-test"):
                for action in ("links", "probe", "start", "stop", "restart"):
                    with self.subTest(user=user, action=action):
                        status, _, page = self.request("/operator/network/mtproto", self.form(user, action=action, confirm="yes"), user=user)
                        self.assertEqual(status, 403)
                        self.assertNotIn(self.secret, page)
            links.assert_not_called()
            control.assert_not_called()
            probe.assert_not_called()

    def test_owner_proxy_links_are_explicit_post_only_no_store_and_not_logged(self):
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", return_value=self.links) as links:
            for token in ("", "wrong"):
                status, _, page = self.request("/operator/network/mtproto", self.form(action="links", csrf=token))
                self.assertEqual(status, 403)
                self.assertNotIn(self.secret, page)
            links.assert_not_called()
            status, headers, page = self.request("/operator/network/mtproto", self.form(action="links"))
            self.assertEqual(status, 200)
            links.assert_called_once_with()
            self.assertIn(self.secret, page)
            self.assertIn("no-store", headers.get("Cache-Control", ""))
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
            self.assertIn("noindex", headers.get("X-Robots-Tag", ""))
            audit = self.audit_text()
            self.assertIn("revealed_to_owner", audit)
            self.assertNotIn(self.secret, audit)
            self.assertNotIn("tg://", audit)
        status, _, public = self.request("/api/client/config")
        self.assertNotIn(self.secret, public)

    def test_proxy_start_stop_restart_require_checkbox_confirmation(self):
        with mock.patch.object(self.panel.mtproto, "control", return_value={"ok": True}) as control:
            for action in ("start", "stop", "restart"):
                for confirm in (None, "no"):
                    with self.subTest(action=action, confirm=confirm):
                        fields = self.form(action=action)
                        if confirm is not None:
                            fields["confirm"] = confirm
                        status, _, _ = self.request("/operator/network/mtproto", fields)
                        self.assertEqual(status, 400)
                control.assert_not_called()
                status, headers, _ = self.request("/operator/network/mtproto", self.form(action=action, confirm="yes"))
                self.assert_network_redirect(status, headers, "mtproto")
                control.assert_called_once_with(action)
                control.reset_mock()

    def test_proxy_probe_uses_fixed_helper_without_secret_logging(self):
        with mock.patch.object(self.panel.mtproto, "health_probe", return_value={"ok": True, "status": "confirmed"}) as probe:
            status, headers, _ = self.request("/operator/network/mtproto", self.form(action="probe"))
            self.assert_network_redirect(status, headers, "mtproto")
            probe.assert_called_once_with()
            self.assertIn("network:mtproto:probe", self.audit_text())
            self.assertNotIn(self.secret, self.audit_text())

    def test_proxy_internal_errors_do_not_expose_secret_or_paths(self):
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", side_effect=RuntimeError(self.secret + "/etc/private")):
            status, _, page = self.request("/operator/network/mtproto", self.form(action="links"))
            self.assertEqual(status, 503)
            self.assertNotIn(self.secret, page)
            self.assertNotIn("/etc/private", page)
            self.assertNotIn(self.secret, self.audit_text())

    def routing_form(self, action="save", view="routes"):
        return self.form(action=action, return_tab="network", return_view=view,
            routing_enabled="on", routing_profile="whitelist", routing_dns_mode="vpn_only",
            routing_dns_resolver="https://dns.example/dns-query", routing_proxy_domains="video.example")

    def test_routing_save_stays_in_network_and_is_only_a_draft(self):
        before = self.settings()
        for view in ("routes", "dns"):
            status, headers, _ = self.request("/operator/routing", self.routing_form(view=view))
            self.assert_network_redirect(status, headers, view)
        after = self.settings()
        self.assertEqual(after["routing_profile"], before["routing_profile"])
        self.assertEqual(after["routing_revision"], before["routing_revision"])
        self.assertEqual(json.loads(after["routing_draft_payload"])["profile"], "whitelist")

    def test_network_routing_save_requires_csrf_without_mutation(self):
        before = self.settings()
        status, _, _ = self.request("/operator/routing", {**self.routing_form(), "csrf": "wrong"})
        self.assertEqual(status, 403)
        self.assertEqual(self.settings(), before)

    def test_large_valid_dns_form_saves_all_hidden_rules_without_truncation(self):
        before = self.settings()
        domains = [f"{index:04d}." + "a" * 60 + "." + "b" * 60 + ".example" for index in range(2000)]
        values = self.routing_form(view="dns")
        values["routing_proxy_domains"] = "\n".join(domains)
        # Real browser buttons are serialized after the long hidden lists.
        action = values.pop("action")
        values["action"] = action
        self.assertGreater(len(urlencode(values).encode()), 256 * 1024)
        status, headers, _ = self.request("/operator/routing", values)
        self.assert_network_redirect(status, headers, "dns")
        after = self.settings()
        self.assertEqual(after["routing_revision"], before["routing_revision"])
        self.assertEqual(json.loads(after["routing_draft_payload"])["rules"]["proxy_domains"], domains)

    def test_routing_oversize_duplicate_or_missing_action_never_mutates(self):
        before = self.settings()
        # Refusal happens from the declared size, before reading an oversized
        # body. Avoid sending megabytes into an already closed Windows socket.
        status, _, _ = self.request("/operator/routing", raw=b"x",
            headers={"Content-Length": str(self.panel.MAX_ROUTING_FORM_BYTES + 1)})
        self.assertEqual(status, 413)
        self.assertEqual(self.settings(), before)
        for values in ({**self.routing_form(), "action": ["save", "publish"]},
                       {key: value for key, value in self.routing_form().items() if key != "action"}):
            status, _, _ = self.request("/operator/routing", values)
            self.assertEqual(status, 400)
            self.assertEqual(self.settings(), before)

    def test_routing_preview_confirm_returns_to_network_and_preserves_guard(self):
        before = self.settings()
        status, _, preview = self.request("/operator/routing", self.routing_form(action="publish"))
        self.assertEqual(status, 200)
        fields = hidden_fields(preview)
        self.assertEqual(fields["csrf"], self.csrf)
        self.assertEqual(fields["return_tab"], "network")
        self.assertEqual(fields["return_view"], "routes")
        self.assertIn('href="/operator?tab=network&amp;network_view=routes&amp;policy_source=draft">Отмена', preview)
        self.assertEqual(self.settings()["routing_revision"], before["routing_revision"])
        status, _, _ = self.request("/operator/control/apply", {**fields, "csrf": "wrong"})
        self.assertEqual(status, 403)
        status, headers, _ = self.request("/operator/control/apply", fields)
        self.assert_network_redirect(status, headers, "routes")
        self.assertEqual(self.settings()["routing_profile"], "whitelist")
        self.assertEqual(int(self.settings()["routing_revision"]), int(before["routing_revision"]) + 1)


if __name__ == "__main__":
    unittest.main()
