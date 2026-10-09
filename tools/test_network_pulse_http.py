"""Isolated Network-center HTTP contracts: roles, CSRF, typed writes and secrets.

No real proxy, DNS lookup, service operation or VDS connection is used. The
production request handler and SQLite database are exercised through HTTP.
"""
from contextlib import closing
import base64
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
from tools import quantumvpn_webproxy as webproxy
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


class _NetworkMarkup(HTMLParser):
    """Inspect rendered DOM controls, not matching IDs inside JavaScript strings."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, page):
        super().__init__()
        self.stack = []
        self.ids = {}
        self.forms = {}
        self.form_field_names = {}
        self.form_items = {}
        self.elements = []
        self.nested_forms = []
        self.feed(page)

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        parents = list(self.stack)
        forms = [parent for parent in parents if parent[0] == "form"]
        form_id = attrs.get("id") if tag == "form" else forms[-1][1].get("id") if forms else None
        hidden = any("hidden" in parent_attrs or "display:none" in parent_attrs.get("style", "").replace(" ", "").lower()
                     for _, parent_attrs in [*parents, (tag, attrs)])
        disabled = "disabled" in attrs or any(parent_tag == "fieldset" and "disabled" in parent_attrs
                                               for parent_tag, parent_attrs in parents)
        item = {"tag": tag, "attrs": attrs, "form": form_id, "hidden": hidden, "disabled": disabled}
        self.elements.append(item)
        if attrs.get("id"):
            self.ids.setdefault(attrs["id"], []).append(item)
        if tag == "form":
            item["fields"] = {}
            item["field_names"] = []
            self.form_items[id(attrs)] = item
            if forms:
                self.nested_forms.append((forms[-1][1].get("id"), attrs.get("id")))
            if form_id:
                self.forms[form_id] = {}
                self.form_field_names[form_id] = []
        elif tag == "input" and form_id in self.forms and attrs.get("type") == "hidden" and attrs.get("name"):
            self.forms[form_id][attrs["name"]] = attrs.get("value", "")
            self.form_field_names[form_id].append(attrs["name"])
        if tag == "input" and forms and attrs.get("type") == "hidden" and attrs.get("name"):
            parent_form = self.form_items[id(forms[-1][1])]
            parent_form["fields"][attrs["name"]] = attrs.get("value", "")
            parent_form["field_names"].append(attrs["name"])
        if tag not in self.VOID:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def one(self, element_id):
        items = self.ids.get(element_id, [])
        if len(items) != 1:
            raise AssertionError(f"Expected one {element_id}, found {len(items)}")
        return items[0]


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
        # A real browser retains the exact signed cookie across the scan POST
        # and redirect GET. Reissuing it with a new expiry second would change
        # its session-bound CSRF and invalidate evidence in the test fixture.
        self.role_cookies = {"owner-test": self.cookie,
                             "operator-test": self.make_cookie("operator-test"),
                             "viewer-test": self.make_cookie("viewer-test")}
        self.csrf = self.csrf_for(self.cookie)
        self.secret = "dd" + "ab" * 16
        self.links = {
            "telegram": "tg://proxy?server=150.241.96.191&port=3443&secret=" + self.secret,
            "https": "https://t.me/proxy?server=150.241.96.191&port=3443&secret=" + self.secret}
        self.status = {"installed": True, "service": "active", "status": "active", "port": 3443,
                       "server": "150.241.96.191", "stats_loopback_only": True, "secret_available": True,
                       "protocol_health": {"ok": True, "status": "confirmed"}, "upstream_ready": True}
        self.web_provider = getattr(self.panel, "webproxy", webproxy)
        self.web_secret = base64.urlsafe_b64encode(b"\x70" + bytes.fromhex("ac" * 16)).decode().rstrip("=")
        web_query = urlencode({"server": "pecaocek.ignorelist.com/quantum_test", "secret": self.web_secret})
        self.web_links = {"telegram": "tg://webproxy?" + web_query, "https": "https://t.me/webproxy?" + web_query}
        self.web_status = {"installed": True, "managed": True, "service": "active", "status": "active",
                           "public_host": "pecaocek.ignorelist.com", "public_port": 443,
                           "relay_port": 18082, "admin_port": 18083, "loopback_only": True,
                           "runtime_ready": True, "config_valid": True, "base_path": "quantum_test",
                           "carrier_mode": "https", "protocol_health": {"ok": True, "status": "confirmed"}}
        self.snapshot = network_center.sanitize_xray_config({
            "inbounds": [{"tag": "vless-in"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "wireguard"}],
            "routing": {"rules": [{"type": "field", "domain": ["domain:video.example"], "outboundTag": "warp"}]}})
        for target, value, result in ((self.panel.mtproto, "snapshot", self.status),
                                      (self.web_provider, "snapshot", self.web_status),
                                      (self.panel.network_center, "read_xray_snapshot", self.snapshot)):
            patch = mock.patch.object(target, value, return_value=result)
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
        cookie = self.role_cookies[user] if user else self.cookie
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
        cookie = self.role_cookies[user] if user else self.cookie
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

    def test_catalog_has_one_live_scanner_and_dialog_set_without_nested_forms(self):
        for user in ("owner-test", "operator-test", "viewer-test"):
            writable = user != "viewer-test"
            for view in ("overview", "routes", "dns"):
                with self.subTest(user=user, view=view):
                    status, _, page = self.request("/operator?tab=network&network_view=" + view, user=user)
                    self.assertEqual(status, 200)
                    markup = _NetworkMarkup(page)
                    self.assertEqual(markup.nested_forms, [])
                    for element_id in ("routing-scan-form", "routing-scan-dialog", "routing-catalog-dialog"):
                        self.assertFalse(markup.one(element_id)["hidden"])
                    catalog = markup.one("routing-catalog-dialog")
                    self.assertEqual(catalog["attrs"]["data-can-write"], "1" if writable else "0")
                    self.assertFalse(markup.one("routing-catalog-search")["disabled"])
                    self.assertEqual(markup.one("routing-catalog-select-all")["disabled"], not writable)
                    self.assertEqual(markup.one("routing-catalog-file")["disabled"], not writable)
                    self.assertEqual(markup.one("routing-catalog-import")["disabled"], not writable)
                    textarea = [item for item in markup.elements if item["tag"] == "textarea"
                                and item["form"] == "routing-scan-form"]
                    self.assertEqual(len(textarea), 1)
                    self.assertEqual(textarea[0]["disabled"], not writable)
                    self.assertTrue(markup.one("routing-scan-confirm")["disabled"])
                    launch = [item for item in markup.elements if "data-catalog-open" in item["attrs"] and not item["hidden"]]
                    self.assertEqual(len(launch), 1)
                    source = markup.forms["routing-scan-form"]
                    self.assertEqual(source["action"], "scan")
                    self.assertEqual(source["csrf"], self.csrf_for(self.role_cookies[user]))
                    self.assertEqual(source["return_tab"], "network")
                    self.assertEqual(source["return_view"], "dns" if view == "dns" else "routes")
                    self.assertEqual(source["policy_source"], "draft")
                    for name in ("csrf", "return_tab", "return_view", "policy_source"):
                        self.assertEqual(markup.form_field_names["routing-scan-form"].count(name), 1)

    def test_unrelated_network_views_have_no_active_catalog_or_scanner(self):
        for view in ("nodes", "ai", "mtproto"):
            with self.subTest(view=view):
                status, _, page = self.request("/operator?tab=network&network_view=" + view)
                self.assertEqual(status, 200)
                markup = _NetworkMarkup(page)
                self.assertEqual(markup.nested_forms, [])
                for element_id in ("routing-scan-form", "routing-scan-dialog", "routing-catalog-dialog"):
                    self.assertFalse(any(not item["hidden"] for item in markup.ids.get(element_id, [])))
                self.assertFalse(any("data-catalog-open" in item["attrs"] and not item["hidden"] for item in markup.elements))

    def scanned_network_page(self, view="routes", targets="example.com\nmedia.example.com\n2606:4700:4700::1111", user=None):
        status, _, page = self.request("/operator?tab=network&network_view=" + view, user=user)
        self.assertEqual(status, 200)
        fields = _NetworkMarkup(page).forms["routing-scan-form"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", side_effect=lambda kind, target: [target] if kind == "ip" else ["1.1.1.1"]), \
                mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=19):
            status, headers, _ = self.request("/operator/routing", {**fields, "routing_scan_targets": targets}, user=user)
        query = self.assert_network_redirect(status, headers, view)
        self.assertEqual(query["policy_source"], ["draft"])
        status, _, page = self.request(headers["Location"], user=user)
        self.assertEqual(status, 200)
        return page

    def test_selected_scan_returns_to_network_with_refreshed_token_and_no_policy_write(self):
        old_token = ""
        for view in ("routes", "dns"):
            with self.subTest(view=view):
                before = self.settings()
                targets = f"{view}.example.com\nmedia.example.com\n2606:4700:4700::1111"
                page = self.scanned_network_page(view, targets, user="operator-test")
                markup = _NetworkMarkup(page)
                token = markup.forms["routing-scan-apply"]["scan_token"]
                self.assertTrue(token)
                self.assertNotEqual(token, old_token)
                old_token = token
                self.assertEqual(markup.one("routing-scan-dialog")["attrs"]["data-auto-open"], "1")
                self.assertIn("open", markup.one("routing-scan-dialog")["attrs"])
                self.assertFalse(markup.one("routing-scan-confirm")["disabled"])
                for text in ("Подтвердить и добавить в черновик", "Публичный IPv6", "2606:4700:4700::1111 · 19 мс"):
                    self.assertTrue(text in page, f"Missing scan evidence: {text}")
                apply_fields = markup.forms["routing-scan-apply"]
                self.assertEqual(apply_fields["return_tab"], "network")
                self.assertEqual(apply_fields["return_view"], view)
                self.assertEqual(apply_fields["policy_source"], "draft")
                after = self.settings()
                self.assertEqual(self.panel.routing_payload(after), self.panel.routing_payload(before))
                self.assertEqual(after["routing_draft_payload"], before["routing_draft_payload"])
                self.assertEqual(after["routing_staging_payload"], before["routing_staging_payload"])
                findings = json.loads(after["routing_last_scan"])
                self.assertEqual([item["target"] for item in findings], targets.splitlines())
                self.assertTrue(all(item["status"] == "ok" and item["latency_ms"] == 19 for item in findings))

    def test_network_scan_confirmation_adds_selected_targets_to_draft_only(self):
        before = self.settings()
        page = self.scanned_network_page("dns", user="operator-test")
        fields = _NetworkMarkup(page).forms["routing-scan-apply"]
        # Merely scanning, opening or submitting no selection never edits rules.
        status, headers, _ = self.request("/operator/routing", fields, user="operator-test")
        query = self.assert_network_redirect(status, headers, "dns")
        self.assertTrue(query["flash"][0].startswith("Не сохранено:"))
        self.assertEqual(self.settings()["routing_draft_payload"], before["routing_draft_payload"])
        selected = {**fields, "scan_selected": ["0", "1", "2"],
                    "scan_direction_0": "proxy", "scan_direction_1": "block", "scan_direction_2": "direct"}
        state = self.settings()
        status, _, _ = self.request("/operator/routing", {**selected, "csrf": "wrong"}, user="operator-test")
        self.assertEqual(status, 403)
        self.assertEqual(self.settings(), state)
        with mock.patch.object(self.panel, "_routing_scan_addresses", side_effect=lambda kind, target: [target] if kind == "ip" else ["1.1.1.1"]), \
                mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=20):
            status, headers, _ = self.request("/operator/routing", selected, user="operator-test")
        query = self.assert_network_redirect(status, headers, "dns")
        self.assertEqual(query["policy_source"], ["draft"])
        self.assertTrue(query["flash"][0].startswith("Добавлено в черновик: 3"))
        after = self.settings()
        draft = json.loads(after["routing_draft_payload"])
        self.assertIn("example.com", draft["rules"]["proxy_domains"])
        self.assertIn("media.example.com", draft["rules"]["block_domains"])
        self.assertIn("2606:4700:4700::1111/128", draft["rules"]["direct_cidrs"])
        self.assertEqual(self.panel.routing_payload(after), self.panel.routing_payload(before))
        self.assertEqual(after["routing_staging_payload"], before["routing_staging_payload"])
        self.assertEqual(after["routing_scan_token"], "")
        self.assertNotIn("routing:publish", self.audit_text())
        self.assertNotIn("control:apply", self.audit_text())
        status, headers, _ = self.request("/operator/routing", selected, user="operator-test")
        query = self.assert_network_redirect(status, headers, "dns")
        self.assertIn("уже использована", query["flash"][0])
        self.assertEqual(self.settings()["routing_draft_payload"], after["routing_draft_payload"])

    def test_network_catalog_scan_and_confirmation_retain_role_origin_and_csrf_guards(self):
        before = self.settings()
        for action in ("scan", "apply_scan"):
            values = self.form(action=action, return_tab="network", return_view="routes", policy_source="draft",
                               routing_scan_targets="example.com", scan_token="forged", scan_selected=["0"])
            for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
                with self.subTest(action=action, headers=headers):
                    status, _, _ = self.request("/operator/routing", values, headers=headers)
                    self.assertEqual(status, 403)
            status, _, _ = self.request("/operator/routing", {**values, "csrf": "wrong"})
            self.assertEqual(status, 403)
            status, _, _ = self.request("/operator/routing", {**values, "csrf": self.csrf_for(self.role_cookies["viewer-test"])}, user="viewer-test")
            self.assertEqual(status, 403)
        self.assertEqual(self.settings(), before)

    def test_local_ai_persists_only_known_error_reason_and_success_clears_it(self):
        with mock.patch.object(self.panel, "ai_operations_snapshot", return_value={}), \
                mock.patch.object(self.panel, "network_guard_snapshot", return_value={}), \
                mock.patch.object(self.panel.autopilot, "plan_actions", return_value={"allowed_actions": []}), \
                mock.patch.object(self.panel, "operations_status_snapshot", return_value={}), \
                mock.patch.object(self.panel.bot_status, "fact_alert", return_value={"fingerprint": "test-only", "should_notify": False}), \
                mock.patch.object(self.panel, "telegram_send") as telegram, \
                mock.patch.object(self.panel, "run_autopilot_step") as autopilot:
            with closing(self.panel.conn()) as db:
                self.panel.set_settings(db, {"ai_advisor_enabled": "1", "ai_autopilot_enabled": "0",
                                             "ai_telegram_enabled": "0", "telegram_alerts_enabled": "0"})
                db.commit()
                for reason, expected in (("recommendation_not_allowed", "recommendation_not_allowed"), ("private-untrusted-output", "")):
                    with self.subTest(reason=reason), mock.patch.object(self.panel.llama, "analyze", side_effect=self.panel.llama.LlamaError(
                            "invalid_response", reason=reason)):
                        result = self.panel._run_ai_analysis(db, self.panel.settings(db), "isolated-unit-test")
                        self.assertFalse(result["ok"])
                        state = self.panel.settings(db)
                        self.assertEqual(state["ai_last_error"], "invalid_response")
                        self.assertEqual(state["ai_last_error_reason"], expected)
                        self.assertNotIn("private-untrusted-output", json.dumps(state))
                self.panel.set_settings(db, {"ai_last_error_reason": "recommendation_not_allowed"})
                db.commit()
                with mock.patch.object(self.panel.llama, "analyze", return_value={
                        "advice": "Проверки завершены.", "snapshot": {}, "analysis": {"recommendations": []}}):
                    result = self.panel._run_ai_analysis(db, self.panel.settings(db), "isolated-unit-test")
                self.assertTrue(result["ok"])
                self.assertEqual(self.panel.settings(db)["ai_last_error"], "")
                self.assertEqual(self.panel.settings(db)["ai_last_error_reason"], "")
            telegram.assert_not_called()
            autopilot.assert_not_called()

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

    def test_all_proxy_cards_are_get_safe_with_owner_only_inline_reveal_forms(self):
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", return_value=self.links) as mt_links, \
                mock.patch.object(self.panel.mtproto, "control") as mt_control, \
                mock.patch.object(self.panel.mtproto, "health_probe") as mt_probe, \
                mock.patch.object(self.web_provider, "owner_connection_links", return_value=self.web_links) as web_links, \
                mock.patch.object(self.web_provider, "control") as web_control, \
                mock.patch.object(self.web_provider, "health_probe") as web_probe, \
                mock.patch.object(self.panel.mtproto_tls, "owner_connection_links") as tls_links, \
                mock.patch.object(self.panel.mtproto_tls, "control") as tls_control, \
                mock.patch.object(self.panel.mtproto_tls, "health_probe") as tls_probe:
            for user in ("owner-test", "operator-test", "viewer-test"):
                with self.subTest(user=user):
                    status, headers, page = self.request("/operator?tab=network&network_view=mtproto", user=user)
                    self.assertEqual(status, 200)
                    self.assertTrue("MTProto" in page)
                    self.assertTrue("WEB Proxy" in page)
                    self.assertNotIn(self.secret, page)
                    self.assertNotIn(self.web_secret, page)
                    self.assertNotIn("tg://webproxy?", page)
                    self.assertIn("no-store", headers.get("Cache-Control", ""))
                    markup = _NetworkMarkup(page)
                    self.assertEqual(markup.nested_forms, [])
                    forms = [item for item in markup.elements if item["tag"] == "form"
                             and "data-proxy-reveal" in item["attrs"] and not item["hidden"]]
                    self.assertEqual(len(forms), 3 if user == "owner-test" else 0)
                    for form in forms:
                        attrs = form["attrs"]
                        self.assertEqual(attrs["action"], "/operator/network/mtproto")
                        self.assertEqual(attrs["method"].lower(), "post")
                        self.assertIn(form["fields"]["action"], {"links", "web_links", "tls_links"})
                        kind = {"links": "mtproto", "web_links": "web", "tls_links": "tls"}[form["fields"]["action"]]
                        self.assertEqual(form["fields"]["csrf"], self.csrf_for(self.role_cookies[user]))
                        self.assertEqual(form["field_names"].count("csrf"), 1)
                        self.assertEqual(form["field_names"].count("action"), 1)
                        for key in ("data-proxy-container", "data-proxy-status"):
                            self.assertRegex(attrs[key], r"^proxy-(mtproto|web|tls)-[a-z0-9-]{1,48}$")
                            self.assertTrue(attrs[key].startswith(f"proxy-{kind}-"))
                            self.assertFalse(markup.one(attrs[key])["hidden"])
            for helper in (mt_links, mt_control, mt_probe, web_links, web_control, web_probe, tls_links, tls_control, tls_probe):
                helper.assert_not_called()

    def test_native_tls_owner_only_csrf_origin_and_secret_safe(self):
        secret = "ee" + self.secret.removeprefix("dd") + "pecaocek.ignorelist.com".encode().hex()
        query = urlencode({"server": "150.241.96.191", "port": 5443, "secret": secret})
        value = {"telegram": "tg://proxy?" + query, "https": "https://t.me/proxy?" + query}
        with mock.patch.object(self.panel.mtproto_tls, "owner_connection_links", return_value=value) as reveal, \
                mock.patch.object(self.panel.mtproto_tls, "health_probe", return_value={"ok": True}) as probe, \
                mock.patch.object(self.panel.mtproto_tls, "control", return_value={"ok": True}) as control:
            for user in ("operator-test", "viewer-test"):
                for action in ("tls_links", "tls_probe", "tls_start", "tls_stop", "tls_restart"):
                    status, _, page = self.request("/operator/network/mtproto", self.form(user, action=action, confirm="yes"), user=user)
                    self.assertEqual(status, 403)
                    self.assertNotIn(secret, page)
            reveal.assert_not_called(); probe.assert_not_called(); control.assert_not_called()
            for action in ("tls_links", "tls_probe", "tls_start", "tls_stop", "tls_restart"):
                status, _, page = self.request("/operator/network/mtproto", self.form(action=action, confirm="yes"),
                                                headers={"Origin": "https://evil.example"})
                self.assertEqual(status, 403)
                self.assertNotIn(secret, page)
                status, _, page = self.request("/operator/network/mtproto", {"csrf": "invalid", "action": action, "confirm": "yes"})
                self.assertEqual(status, 403)
                self.assertNotIn(secret, page)
            reveal.assert_not_called(); probe.assert_not_called(); control.assert_not_called()
            status, headers, page = self.request("/operator/network/mtproto", self.form(action="tls_links"))
            self.assertEqual(status, 200)
            self.assertIn("no-store", headers.get("Cache-Control", ""))
            self.assertIn("proxy-tls-telegram-link", page)
            self.assertIn(secret, page)
            status, _, _ = self.request("/operator/network/mtproto", self.form(action="tls_probe"))
            self.assertEqual(status, 303)
            status, _, _ = self.request("/operator/network/mtproto", self.form(action="tls_restart"))
            self.assertEqual(status, 400)
            control.assert_not_called()
            status, _, _ = self.request("/operator/network/mtproto", self.form(action="tls_restart", confirm="yes"))
            self.assertEqual(status, 303)
            control.assert_called_once_with("restart")

    def test_web_proxy_all_actions_require_owner_without_helper_calls(self):
        with mock.patch.object(self.web_provider, "owner_connection_links", return_value=self.web_links) as links, \
                mock.patch.object(self.web_provider, "control") as control, \
                mock.patch.object(self.web_provider, "health_probe") as probe:
            for user in ("operator-test", "viewer-test"):
                for action in ("web_links", "web_probe", "web_start", "web_stop", "web_restart"):
                    with self.subTest(user=user, action=action):
                        status, _, page = self.request("/operator/network/mtproto", self.form(user, action=action, confirm="yes"), user=user)
                        self.assertEqual(status, 403)
                        self.assertNotIn(self.web_secret, page)
            links.assert_not_called()
            control.assert_not_called()
            probe.assert_not_called()

    def test_proxy_reveal_json_is_negotiated_explicitly_and_no_store_without_audit_leaks(self):
        before = self.settings()
        with mock.patch.object(self.panel.mtproto, "owner_connection_links", return_value=self.links), \
                mock.patch.object(self.web_provider, "owner_connection_links", return_value=self.web_links):
            for kind, action, value in (("mtproto", "links", self.secret), ("web", "web_links", self.web_secret)):
                for negotiation in ({}, {"Accept": "application/json"}, {"X-QV-Request": "1"},
                                    {"Accept": "application/json", "X-QV-Request": "1"}):
                    with self.subTest(kind=kind, negotiation=negotiation):
                        status, headers, page = self.request("/operator/network/mtproto", self.form(action=action), headers=negotiation)
                        self.assertEqual(status, 200)
                        json_requested = negotiation == {"Accept": "application/json", "X-QV-Request": "1"}
                        if json_requested:
                            self.assertTrue(headers.get("Content-Type", "").startswith("application/json"))
                            data = json.loads(page)
                            self.assertEqual(set(data), {"html"})
                            fragment = data["html"]
                            self.assertNotIn("<script", fragment)
                            self.assertNotIn("<form", fragment)
                        else:
                            self.assertTrue(headers.get("Content-Type", "").startswith("text/html"))
                            self.assertTrue("<!doctype html>" in page.lower())
                            fragment = page
                        self.assertIn(value, fragment)
                        markup = _NetworkMarkup(fragment)
                        for variant in ("telegram", "https"):
                            item = markup.one(f"proxy-{kind}-{variant}-link")
                            self.assertEqual(item["tag"], "textarea")
                            self.assertIn("readonly", item["attrs"])
                        self.assertIn("no-store", headers.get("Cache-Control", ""))
                        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
                        self.assertIn("noindex", headers.get("X-Robots-Tag", ""))
        self.assertEqual(self.settings(), before)
        audit = self.audit_text()
        for value in (self.secret, self.web_secret, "tg://", "https://t.me", "quantum_test"):
            self.assertNotIn(value, audit)
        with closing(self.panel.conn()) as db:
            records = list(db.execute("select detail from audit where action like 'network:%'"))
        self.assertTrue(records)
        for row in records:
            detail = json.loads(row[0])
            self.assertTrue(detail and all(type(value) is bool for value in detail.values()))

    def test_web_proxy_origin_session_csrf_and_typed_actions_fail_without_mutation(self):
        before = self.settings()
        with mock.patch.object(self.web_provider, "owner_connection_links") as links, \
                mock.patch.object(self.web_provider, "control") as control, \
                mock.patch.object(self.web_provider, "health_probe") as probe:
            for action in ("web_links", "web_probe", "web_start", "web_stop", "web_restart"):
                for override in ({"Origin": "https://evil.example"}, {"Origin": ""},
                                 {"Sec-Fetch-Site": "cross-site"}, {"Cookie": self.make_cookie("owner-test", "other-web-session")}):
                    with self.subTest(action=action, override=override):
                        status, _, body = self.request("/operator/network/mtproto", self.form(action=action, confirm="yes"), headers=override)
                        self.assertEqual(status, 403)
                        self.assertNotIn(self.web_secret, body)
                status, _, _ = self.request("/operator/network/mtproto", self.form(action=action, confirm="yes", csrf="wrong"))
                self.assertEqual(status, 403)
            for values in (self.form(action=["web_start", "web_stop"], confirm="yes"),
                           self.form(action="web_links", command="read-secret"), self.form(action="web_exec", confirm="yes")):
                status, _, _ = self.request("/operator/network/mtproto", values)
                self.assertEqual(status, 400)
            links.assert_not_called()
            control.assert_not_called()
            probe.assert_not_called()
        self.assertEqual(self.settings(), before)

    def test_web_proxy_service_actions_require_confirmation_and_dispatch_fixed_suffix(self):
        before = self.settings()
        with mock.patch.object(self.web_provider, "control", return_value={"ok": True}) as control, \
                mock.patch.object(self.panel.mtproto, "control") as mt_control:
            for action in ("start", "stop", "restart"):
                for confirm in (None, "no"):
                    values = self.form(action="web_" + action)
                    if confirm is not None:
                        values["confirm"] = confirm
                    status, _, _ = self.request("/operator/network/mtproto", values)
                    self.assertEqual(status, 400)
                control.assert_not_called()
                status, headers, _ = self.request("/operator/network/mtproto", self.form(action="web_" + action, confirm="yes"))
                self.assert_network_redirect(status, headers, "mtproto")
                control.assert_called_once_with(action)
                control.reset_mock()
            mt_control.assert_not_called()
        self.assertEqual(self.settings(), before)

    def test_web_proxy_probe_is_explicit_fixed_and_logs_only_success(self):
        before = self.settings()
        with mock.patch.object(self.web_provider, "health_probe", return_value={"ok": True, "status": "confirmed"}) as probe, \
                mock.patch.object(self.panel.mtproto, "health_probe") as mt_probe:
            status, headers, _ = self.request("/operator/network/mtproto", self.form(action="web_probe"))
            self.assert_network_redirect(status, headers, "mtproto")
            probe.assert_called_once_with()
            mt_probe.assert_not_called()
        self.assertEqual(self.settings(), before)
        with closing(self.panel.conn()) as db:
            rows = list(db.execute("select detail from audit where action like 'network:%'"))
        self.assertEqual([json.loads(row[0]) for row in rows], [{"ok": True}])

    def test_web_proxy_internal_errors_are_suppressed_in_html_json_requests_and_audit(self):
        before = self.settings()
        for action, helper in (("web_links", "owner_connection_links"), ("web_probe", "health_probe"), ("web_start", "control")):
            for headers in ({}, {"Accept": "application/json", "X-QV-Request": "1"}):
                with self.subTest(action=action, json=bool(headers)), mock.patch.object(self.web_provider, helper,
                        side_effect=RuntimeError(self.web_secret + "/etc/quantumvpn-webproxy/private.json")):
                    status, _, body = self.request("/operator/network/mtproto", self.form(action=action, confirm="yes"), headers=headers)
                    self.assertEqual(status, 503)
                    self.assertNotIn(self.web_secret, body)
                    self.assertNotIn("/etc/quantumvpn-webproxy", body)
                    self.assertNotIn(self.web_secret, self.audit_text())
        self.assertEqual(self.settings(), before)

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
