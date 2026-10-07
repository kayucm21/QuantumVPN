"""Routing target scanner: reviewed UI, bounded probes and draft-only writes."""
import base64
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from contextlib import closing
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class ScanForms(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.forms = {}
        self.current = None
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = attrs.get("id")
            if self.current:
                self.forms[self.current] = {}
        elif tag == "input" and self.current and attrs.get("name"):
            self.forms[self.current][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class RoutingScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        environment = {
            "QV_DATA_DIR": cls.tmp.name, "QV_DOWNLOAD_ROOT": cls.tmp.name,
            "QV_ADMIN_USER": "scan-owner", "QV_ADMIN_PASSWORD": "scan-owner-password",
            "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub",
        }
        with mock.patch.dict(os.environ, environment):
            spec = importlib.util.spec_from_file_location("scan_panel", Path(__file__).with_name("quantumvpn_operator_panel.py"))
            cls.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.panel)
        with closing(cls.panel.conn()) as db:
            cls.baseline = cls.panel.settings(db)
        cls.server = cls.panel.ThreadingHTTPServer(("127.0.0.1", 0), cls.panel.App)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.panel.PUBLIC_BASE = cls.base
        cls.basic = {"Authorization": "Basic " + base64.b64encode(b"scan-owner:scan-owner-password").decode()}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {**self.baseline, "routing_scan_token": ""})
            db.commit()

    def current(self):
        with closing(self.panel.conn()) as db:
            return self.panel.settings(db)

    def page(self, headers=None):
        with urlopen(Request(self.base + "/operator?tab=routing", headers=headers or self.basic), timeout=15) as response:
            return response.read().decode()

    def post(self, values, headers=None):
        with urlopen(Request(self.base + "/operator/routing", data=urlencode(values, doseq=True).encode(),
                             headers=headers or self.basic), timeout=15) as response:
            return response.read().decode()

    def scan(self, targets="example.com\nmedia.example.com\n1.1.1.1", headers=None):
        request_headers = headers or self.basic
        csrf = ScanForms(self.page(request_headers)).forms["routing-scan-form"]["csrf"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=["1.1.1.1"]), \
             mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=19):
            return self.post({"action": "scan", "routing_scan_targets": targets, "csrf": csrf}, request_headers)

    def selection(self, page, selected=(0,), direction="proxy"):
        fields = dict(ScanForms(page).forms["routing-scan-apply"])
        fields.pop("scan_selected", None)
        fields["scan_selected"] = [str(index) for index in selected]
        fields.update({f"scan_direction_{index}": direction for index in selected})
        return fields

    def apply(self, fields, headers=None):
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=["1.1.1.1"]), \
             mock.patch.object(self.panel, "_routing_tcp_latency_ms", return_value=20):
            return self.post(fields, headers)

    def test_dialog_has_real_evidence_multiselect_explicit_confirm_and_sample_explanation(self):
        page = self.scan()
        self.assertIn('id="routing-scan-dialog"', page)
        self.assertIn('data-auto-open="1" open', page)
        self.assertIn("Каталог и анализатор целей", page)
        self.assertIn("data-catalog-open", page)
        self.assertIn("Рекомендация и резерв", page)
        self.assertIn("1.1.1.1 · 19 мс", page)
        self.assertIn("Это не ICMP-пинг", page)
        self.assertIn("его поддомены", page)
        self.assertIn('name="scan_selected" value="0"', page)
        self.assertIn('name="scan_selected" value="2"', page)
        self.assertIn("Подтвердить и добавить в черновик", page)
        self.assertIn("showModal", page)
        self.assertIn("Проверяем заданные цели", page)
        self.assertIn("new URLSearchParams(new FormData(source))", page)
        self.assertIn("fetch(source.getAttribute('action')", page)

    def test_scan_and_close_leave_active_policy_and_draft_unchanged(self):
        before = self.current()
        self.scan()
        self.page()
        after = self.current()
        self.assertEqual(self.panel.routing_payload(before), self.panel.routing_payload(after))
        self.assertEqual(before["routing_draft_payload"], after["routing_draft_payload"])
        with urlopen(self.base + "/api/client/routing?bucket=99", timeout=15) as response:
            envelope = json.load(response)
        self.assertNotIn("scan_token", json.dumps(envelope))
        self.assertNotIn("example.com", json.dumps(envelope))

    def test_selected_domain_subdomain_and_ip_merge_into_draft_only_and_token_is_consumed(self):
        before = self.current()
        page = self.scan()
        fields = self.selection(page, (0, 1, 2))
        result = self.apply(fields)
        self.assertIn("Добавлено в черновик: 3", result)
        after = self.current()
        draft = json.loads(after["routing_draft_payload"])
        self.assertEqual(draft["rules"]["proxy_domains"][-2:], ["example.com", "media.example.com"])
        self.assertIn("1.1.1.1/32", draft["rules"]["proxy_cidrs"])
        self.assertEqual(self.panel.routing_payload(before), self.panel.routing_payload(after))
        self.assertEqual(after["routing_scan_token"], "")
        unchanged = after["routing_draft_payload"]
        self.assertIn("уже использована", self.apply(fields))
        self.assertEqual(self.current()["routing_draft_payload"], unchanged)

    def test_selection_can_apply_direct_and_domain_block_and_keeps_other_draft_edits(self):
        state = self.current()
        draft = self.panel.routing_payload(state)
        draft["rules"]["proxy_domains"].append("draft.example.org")
        draft["rules"]["proxy_domains"].append("example.com")
        with closing(self.panel.conn()) as db:
            self.panel.set_settings(db, {"routing_draft_payload": json.dumps(draft)})
            db.commit()
        page = self.scan()
        fields = self.selection(page, (0, 1, 2), "direct")
        fields["scan_direction_1"] = "block"
        self.apply(fields)
        draft = json.loads(self.current()["routing_draft_payload"])
        self.assertIn("draft.example.org", draft["rules"]["proxy_domains"])
        self.assertNotIn("example.com", draft["rules"]["proxy_domains"])
        self.assertIn("example.com", draft["rules"]["direct_domains"])
        self.assertIn("media.example.com", draft["rules"]["block_domains"])
        self.assertIn("1.1.1.1/32", draft["rules"]["direct_cidrs"])

    def test_forged_missing_empty_duplicate_or_unknown_selection_is_rejected(self):
        page = self.scan()
        fields = self.selection(page)
        invalid = [
            {**fields, "scan_token": "forged"}, {key: value for key, value in fields.items() if key != "scan_token"},
            {**fields, "scan_selected": []}, {**fields, "scan_selected": ["0", "0"]},
            {**fields, "scan_selected": ["99"], "scan_direction_99": "proxy"},
            {**fields, "scan_selected": ["example.com"]}, {**fields, "scan_direction_0": "reserve"},
        ]
        before = self.current()["routing_draft_payload"]
        for values in invalid:
            with self.subTest(values=values):
                self.assertIn("Не сохранено:", self.apply(values))
                self.assertEqual(self.current()["routing_draft_payload"], before)

    def test_findings_tampering_expiry_revision_or_draft_change_invalidates_selection(self):
        for mutation in ("findings", "expired", "revision", "draft"):
            with self.subTest(mutation=mutation):
                page = self.scan()
                fields = self.selection(page)
                state = self.current()
                if mutation == "findings":
                    findings = json.loads(state["routing_last_scan"])
                    findings[0]["target"] = "forged.example.org"
                    values = {"routing_last_scan": json.dumps(findings)}
                elif mutation == "expired":
                    evidence = self.panel.verify_session(fields["scan_token"])
                    evidence["exp"] = int(time.time()) - 1
                    fields["scan_token"] = self.panel.sign_session(evidence)
                    values = {"routing_scan_token": fields["scan_token"]}
                elif mutation == "revision":
                    values = {"routing_revision": str(int(state["routing_revision"]) + 1)}
                else:
                    draft = self.panel.routing_payload(state)
                    draft["rules"]["proxy_domains"].append("changed.example.org")
                    values = {"routing_draft_payload": json.dumps(draft)}
                with closing(self.panel.conn()) as db:
                    self.panel.set_settings(db, values)
                    db.commit()
                unchanged = self.current()["routing_draft_payload"]
                self.assertIn("Не сохранено:", self.apply(fields))
                self.assertEqual(self.current()["routing_draft_payload"], unchanged)

    def test_cookie_sessions_require_csrf_and_cannot_use_another_sessions_evidence(self):
        def headers(nonce):
            token = self.panel.sign_session({"u": "scan-owner", "exp": int(time.time()) + 3600, "n": nonce})
            return {"Cookie": self.panel.SESSION_COOKIE + "=" + token}
        first, second = headers("first"), headers("second")
        for action in ("scan", "apply_scan"):
            with self.subTest(action=action), self.assertRaises(HTTPError) as denied:
                self.post({"action": action, "routing_scan_targets": "example.com"}, first)
            self.assertEqual(denied.exception.code, 403)
            denied.exception.close()
        page = self.scan(headers=first)
        self.assertNotIn('name="scan_selected" value="0"', self.page(second))
        fields = self.selection(page)
        fields["csrf"] = ScanForms(self.page(second)).forms["routing-scan-form"]["csrf"]
        self.assertIn("другой сессии", self.apply(fields, second))
        self.assertEqual(self.current()["routing_draft_payload"], self.baseline["routing_draft_payload"])

    def test_apply_requires_csrf_for_basic_auth_too(self):
        fields = self.selection(self.scan())
        fields["csrf"] = "invalid"
        with self.assertRaises(HTTPError) as denied:
            self.apply(fields)
        self.assertEqual(denied.exception.code, 403)
        denied.exception.close()

    def test_server_rechecks_selected_targets_and_rejects_new_failure(self):
        page = self.scan()
        before = self.current()["routing_draft_payload"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=[]):
            result = self.post(self.selection(page))
        self.assertIn("больше не доступна", result)
        self.assertEqual(self.current()["routing_draft_payload"], before)

    def test_unavailable_result_is_visible_but_not_selectable(self):
        csrf = ScanForms(self.page()).forms["routing-scan-form"]["csrf"]
        with mock.patch.object(self.panel, "_routing_scan_addresses", return_value=[]):
            page = self.post({"action": "scan", "routing_scan_targets": "unresolved.example.org", "csrf": csrf})
        self.assertIn("Нет публичного DNS-адреса", page)
        self.assertIn('aria-label="Выбрать unresolved.example.org" disabled', page)
        self.assertIn("только проверенную", self.apply(self.selection(page)))

    def test_normalization_bounds_and_rejects_url_ports_wildcards_private_ips(self):
        for target in ("https://example.org/path", "example.org:443", "*.example.org", "127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "224.0.0.1", "[2606:4700:4700::1111]", "x" * 4097):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.panel.normalize_routing_scan_targets(target)
        self.assertEqual(self.panel.normalize_routing_scan_targets("EXAMPLE.COM.,example.com;media.example.com\n1.1.1.1"),
                         [("domain", "example.com"), ("domain", "media.example.com"), ("ip", "1.1.1.1")])
        targets = "\n".join(f"target{index}.example.org" for index in range(24))
        self.assertEqual(len(self.panel.normalize_routing_scan_targets(targets)), 24)
        with self.assertRaises(ValueError):
            self.panel.normalize_routing_scan_targets(targets + "\nextra.example.org")

    def test_mixed_private_dns_never_reaches_tcp_probe(self):
        records = [(None, None, None, None, ("1.1.1.1", 443)), (None, None, None, None, ("127.0.0.1", 443))]
        with mock.patch.object(self.panel.socket, "getaddrinfo", return_value=records), \
             mock.patch.object(self.panel, "_routing_tcp_latency_ms") as probe:
            findings = self.panel.scan_routing_targets("example.org", self.panel.routing_payload(self.current()))
        self.assertEqual(findings[0]["status"], "unresolved")
        probe.assert_not_called()

    def test_global_deadline_returns_every_requested_target_and_bounds_lingering_workers(self):
        hold = threading.Event()
        slots = threading.BoundedSemaphore(2)
        def delayed(payload, kind, target):
            hold.wait(2)
            return {"target": target}
        try:
            with mock.patch.object(self.panel, "_ROUTING_SCAN_SLOTS", slots), \
                 mock.patch.object(self.panel, "ROUTING_SCAN_WALL_TIMEOUT_SECONDS", .01), \
                 mock.patch.object(self.panel, "_scan_routing_target", side_effect=delayed):
                payload = self.panel.routing_payload(self.current())
                first = self.panel.scan_routing_targets("one.example.org\ntwo.example.org", payload)
                second = self.panel.scan_routing_targets("three.example.org", payload)
                self.assertEqual([item["target"] for item in first], ["one.example.org", "two.example.org"])
                self.assertTrue(all(item["status"] == "budget" for item in first + second))
                with self.assertRaises(ValueError):
                    self.panel.scan_routing_targets("four.example.org", payload)
        finally:
            hold.set()

    def test_scan_markup_escapes_server_evidence(self):
        from tools.quantumvpn_target_scan import scan_dialog
        result = scan_dialog([{"target": '<img src=x onerror="alert(1)">', "kind": "domain", "reason": "<script>bad</script>",
                               "status": "timeout", "addresses": []}], "token", "csrf")
        self.assertNotIn('<img src=x', result)
        self.assertNotIn('<script>bad', result)
        self.assertIn("&lt;script&gt;bad", result)

    def catalog(self, **query):
        with urlopen(Request(self.base + "/operator/routing/catalog?" + urlencode(query), headers=self.basic), timeout=15) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            return json.load(response)

    def test_catalog_has_all_known_targets_with_search_pagination_no_duplicate_rows_or_probes(self):
        before = self.current()
        from tools import quantumvpn_target_catalog as catalog
        with closing(self.panel.conn()) as db:
            catalog.import_entries(db, "\n".join(f"catalog-http-{index:03d}.example.org" for index in range(115)))
            db.commit()
        with mock.patch.object(self.panel, "_routing_scan_addresses") as resolver, mock.patch.object(self.panel, "_routing_tcp_latency_ms") as probe:
            first = self.catalog(q="catalog-http-", limit=50)
            second = self.catalog(q="catalog-http-", offset=50, limit=50)
            last = self.catalog(q="catalog-http-", offset=100, limit=50)
        self.assertEqual(first["matched"], 115)
        self.assertEqual([len(page["items"]) for page in (first, second, last)], [50, 50, 15])
        self.assertEqual(len({item["target"] for page in (first, second, last) for item in page["items"]}), 115)
        self.assertTrue(all(item["latency_ms"] is None for item in first["items"]))
        resolver.assert_not_called(); probe.assert_not_called()
        self.assertEqual(self.panel.routing_payload(before), self.panel.routing_payload(self.current()))
        self.assertEqual(before["routing_draft_payload"], self.current()["routing_draft_payload"])

    def test_catalog_searches_subdomains_and_resolved_public_ip_without_unchecked_latency(self):
        self.scan("media.catalog-search.example.org")
        found = self.catalog(q="media.catalog-search", kind="domain")
        self.assertEqual([item["target"] for item in found["items"]], ["media.catalog-search.example.org"])
        self.assertEqual(found["items"][0]["latency_ms"], 19)
        found = self.catalog(q="1.1.1.1", kind="domain")
        self.assertIn("media.catalog-search.example.org", [item["target"] for item in found["items"]])
        self.assertTrue(self.catalog(kind="ip")["matched"] >= 1)

    def test_catalog_import_requires_csrf_is_additive_and_never_changes_live_rules(self):
        before = self.current()
        csrf = ScanForms(self.page()).forms["routing-scan-form"]["csrf"]
        path = self.base + "/operator/routing/catalog/import"
        for token in ("", "wrong"):
            with self.assertRaises(HTTPError) as denied:
                urlopen(Request(path, data=urlencode({"csrf": token, "targets": "new.catalog-import.example.org"}).encode(), headers=self.basic))
            self.assertEqual(denied.exception.code, 403); denied.exception.close()
        def upload(targets):
            with urlopen(Request(path, data=urlencode({"csrf": csrf, "targets": targets}).encode(), headers=self.basic), timeout=15) as response:
                return json.load(response)
        result = upload("new.catalog-import.example.org\nNEW.CATALOG-IMPORT.EXAMPLE.ORG\n1.0.0.0/24")
        self.assertGreaterEqual(result["added"], 1)
        self.assertEqual(upload("new.catalog-import.example.org")["added"], 0)
        result = self.catalog(q="1.0.0.0/24")
        self.assertFalse(result["items"][0]["selectable"])
        with self.assertRaises(HTTPError) as invalid:
            upload("should-not-save.catalog-import.example.org\n127.0.0.1")
        self.assertEqual(invalid.exception.code, 400); invalid.exception.close()
        self.assertEqual(self.catalog(q="should-not-save.catalog-import")["matched"], 0)
        self.assertEqual(self.panel.routing_payload(before), self.panel.routing_payload(self.current()))
        self.assertEqual(before["routing_draft_payload"], self.current()["routing_draft_payload"])

    def test_catalog_api_requires_auth_validates_bounds_and_survives_scan_pressure(self):
        with self.assertRaises(HTTPError) as denied:
            urlopen(self.base + "/operator/routing/catalog")
        self.assertEqual(denied.exception.code, 401); denied.exception.close()
        for query in ({"limit": 51}, {"offset": -1}, {"q": "a" * 161}, {"kind": "anything"}):
            with self.subTest(query=query), self.assertRaises(HTTPError) as bad:
                self.catalog(**query)
            self.assertEqual(bad.exception.code, 400); bad.exception.close()
        with mock.patch.object(self.panel.target_catalog, "workload_workers", side_effect=ValueError("Сервер занят, повторите позже")):
            page = self.catalog()
            self.assertFalse(page["scan_available"])
            self.assertGreater(page["total"], 3)
            slots = threading.BoundedSemaphore(1)
            with mock.patch.object(self.panel, "_ROUTING_SCAN_SLOTS", slots), self.assertRaises(ValueError):
                self.panel.scan_routing_targets("example.org", self.panel.routing_payload(self.current()))
            self.assertTrue(slots.acquire(blocking=False))
            slots.release()


if __name__ == "__main__":
    unittest.main()
