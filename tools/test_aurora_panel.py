"""Regression checks for the Aurora shell and existing operator workflows."""
import base64
from contextlib import closing
from html.parser import HTMLParser
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen


LEGACY_TABS = {
    "dashboard", "latency", "routing", "quality", "users", "cards",
    "service", "release", "resources", "incidents", "audit", "ai",
    "fleet", "automation", "devices", "features", "branding", "donations",
    "reports", "support", "integrations", "security", "logs", "admins",
}


class PanelHTML(HTMLParser):
    """Inspect links and form ownership without depending on HTML formatting."""

    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.nodes = []
        self.stack = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        node = {"tag": tag, "attrs": dict(attributes), "text": "",
                "parent": self.stack[-1] if self.stack else None}
        self.nodes.append(node)
        if tag not in self.VOID:
            self.stack.append(len(self.nodes) - 1)

    def handle_startendtag(self, tag, attributes):
        self.handle_starttag(tag, attributes)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for offset in range(len(self.stack) - 1, -1, -1):
            if self.nodes[self.stack[offset]]["tag"] == tag:
                del self.stack[offset:]
                break

    def handle_data(self, data):
        for index in self.stack:
            self.nodes[index]["text"] += data

    def visible(self, node):
        while node is not None:
            attributes = node["attrs"]
            if "hidden" in attributes or "display:none" in attributes.get("style", "").replace(" ", ""):
                return False
            parent = node["parent"]
            node = self.nodes[parent] if parent is not None else None
        return True

    def inside(self, node, tag):
        parent = node["parent"]
        while parent is not None:
            ancestor = self.nodes[parent]
            if ancestor["tag"] == tag:
                return True
            parent = ancestor["parent"]
        return False

    def tab_links(self):
        links = []
        for node in self.nodes:
            if node["tag"] != "a":
                continue
            target = urlsplit(node["attrs"].get("href", ""))
            tab = parse_qs(target.query).get("tab", [])
            if target.path == "/operator" and tab:
                links.append((tab[0], node))
        return links

    @staticmethod
    def active(node):
        return "active" in node["attrs"].get("class", "").split() or node["attrs"].get("aria-current") == "page"


class AuroraPanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        environment = {
            "QV_DATA_DIR": str(root / "data"),
            "QV_DOWNLOAD_ROOT": str(root / "downloads"),
            "QV_ROSPANEL_DB": str(root / "missing-rospanel.db"),
            "QV_ROSPANEL_API": "",
            "QV_RESERVE_PROFILE_URI_FILE": str(root / "missing-reserve-uri"),
            "QV_ADMIN_USER": "aurora-owner",
            "QV_ADMIN_PASSWORD": "aurora-test-password",
            "QV_SUBSCRIPTION_UPSTREAM": "https://example.invalid/sub",
            "QV_PUBLIC_BASE": "https://operator.example.invalid",
            "QV_DOWNLOAD_BASE": "https://operator.example.invalid",
            "QV_TELEGRAM_BOT_TOKEN": "",
        }
        cls.environment = mock.patch.dict(os.environ, environment)
        cls.environment.start()
        cls.addClassCleanup(cls.environment.stop)
        spec = importlib.util.spec_from_file_location(
            "aurora_test_panel", Path(__file__).with_name("quantumvpn_operator_panel.py")
        )
        cls.panel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.panel)
        summary = {"ok": True, "active": 7, "disabled": 1, "expired": 0,
                   "online_15m": 3, "traffic_today_gb": 1.25}
        status = {"rospanel": "active", "operator": "active", "xray": "running",
                  "opera": "running", "disk_free_gb": 10, "disk_used_pct": 30,
                  "cpu_load_pct": 12, "memory_used_pct": 24, "outbounds": []}
        for name, value in (("rospanel_users", []), ("cached_rospanel_summary", summary),
                            ("cached_service_status", status)):
            patcher = mock.patch.object(cls.panel, name, return_value=value)
            patcher.start()
            cls.addClassCleanup(patcher.stop)
        network = mock.patch.object(cls.panel, "urlopen", side_effect=AssertionError("Unexpected external network request"))
        network.start()
        cls.addClassCleanup(network.stop)
        with closing(cls.panel.conn()) as db:
            db.execute(
                "insert into admin_users(username,password_hash,role,enabled,created_at,updated_at) values (?,?,?,?,?,?)",
                ("aurora-viewer", cls.panel.password_hash("aurora-viewer-password"), "viewer", 1, int(time.time()), int(time.time())),
            )
            db.commit()
        cls.server = cls.panel.OperatorHTTPServer(("127.0.0.1", 0), cls.panel.App)
        cls.addClassCleanup(cls.server.server_close)
        thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(cls.server.shutdown)
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)
        cls.owner_headers = {"Authorization": "Basic " + base64.b64encode(b"aurora-owner:aurora-test-password").decode()}

    def page(self, tab):
        with urlopen(Request(self.base + "/operator?tab=" + tab, headers=self.owner_headers), timeout=10) as response:
            self.assertEqual(response.status, 200)
            return response.read().decode("utf-8")

    def test_build_and_tab_registry_cover_existing_routes(self):
        self.assertTrue(self.panel.PANEL_BUILD.startswith("2.1.1-bot"))
        self.assertEqual(set(self.panel.PAGE_TITLES), LEGACY_TABS)
        self.assertEqual(len(self.panel.AURORA_NAV_GROUPS), 9)
        for tab, title in self.panel.PAGE_TITLES.items():
            with self.subTest(tab=tab):
                self.assertTrue(title[0])
                self.assertNotEqual(title[0], "Quantum Control")

    def test_navigation_preserves_all_routes_and_marks_selected_group(self):
        reachable = set()
        for tab in sorted(LEGACY_TABS):
            with self.subTest(tab=tab):
                primary_html, subnav_html = self.panel.aurora_navigation(tab, "owner")
                primary = PanelHTML(primary_html).tab_links()
                subnav = PanelHTML(subnav_html).tab_links()
                self.assertEqual(len(primary), 9)
                self.assertEqual(sum(PanelHTML.active(node) for _, node in primary), 1)
                current = [name for name, node in subnav if PanelHTML.active(node)]
                if subnav:
                    self.assertEqual(current, [tab])
                else:
                    self.assertIn((tab, True), [(name, PanelHTML.active(node)) for name, node in primary])
                reachable.update(name for name, _ in primary + subnav)
        self.assertEqual(reachable, LEGACY_TABS)

    def test_admin_link_is_visible_only_to_owner(self):
        for role in ("owner", "operator", "viewer"):
            reachable = set()
            for tab in sorted(LEGACY_TABS - {"admins"}):
                primary, subnav = self.panel.aurora_navigation(tab, role)
                reachable.update(name for name, _ in PanelHTML(primary + subnav).tab_links())
            with self.subTest(role=role):
                self.assertEqual("admins" in reachable, role == "owner")
        headers = {"Authorization": "Basic " + base64.b64encode(b"aurora-viewer:aurora-viewer-password").decode()}
        with self.assertRaises(HTTPError) as denied:
            urlopen(Request(self.base + "/operator?tab=admins", headers=headers), timeout=10)
        self.assertEqual(denied.exception.code, 403)
        denied.exception.close()

    def test_every_legacy_get_has_its_title_and_navigation(self):
        for tab in sorted(LEGACY_TABS):
            with self.subTest(tab=tab):
                page = self.page(tab)
                document = PanelHTML(page)
                title = self.panel.PAGE_TITLES[tab][0]
                titles = [node["text"].strip() for node in document.nodes if node["tag"] == "title" and not document.inside(node, "svg")]
                self.assertEqual(len(titles), 1)
                self.assertTrue(titles[0].startswith(title), (tab, titles[0], title))
                headings = [node["text"].strip() for node in document.nodes if node["tag"] == "h1" and document.visible(node)]
                self.assertIn(title, headings)
                primary, subnav = self.panel.aurora_navigation(tab, "owner")
                self.assertTrue(primary in page, f"{tab}: primary navigation is not rendered")
                if subnav:
                    self.assertTrue(subnav in page, f"{tab}: selected group navigation is not rendered")

    def test_routing_and_latency_keep_external_form_associations(self):
        routing = PanelHTML(self.page("routing"))
        forms = [node for node in routing.nodes if node["tag"] == "form" and node["attrs"].get("id") == "routing-policy"]
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["attrs"].get("method"), "post")
        self.assertEqual(forms[0]["attrs"].get("action"), "/operator/routing")
        attached = [node for node in routing.nodes if node["attrs"].get("form") == "routing-policy"]
        names = {node["attrs"].get("name") for node in attached}
        self.assertTrue({"routing_enabled", "routing_dns_mode", "routing_adblock_enabled",
                         "routing_dns_resolver", "routing_profile", "routing_staging_rollout_percent"} <= names)
        actions = {node["attrs"].get("value") for node in attached if node["attrs"].get("name") == "action"}
        self.assertTrue({"save", "stage", "publish"} <= actions)
        latency = PanelHTML(self.page("latency"))
        forms = [node for node in latency.nodes if node["tag"] == "form" and node["attrs"].get("id") == "latency-balancer-form"]
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["attrs"].get("action"), "/operator/policy")
        attached = [node for node in latency.nodes if node["attrs"].get("name") == "load_balancer_enabled"]
        self.assertEqual(len(attached), 1)
        self.assertEqual(attached[0]["attrs"].get("form"), "latency-balancer-form")

    def test_selected_forms_keep_post_endpoints_and_upload_encoding(self):
        endpoints = {
            "service": {"/operator/policy", "/operator/protocols"},
            "routing": {"/operator/routing"},
            "quality": {"/operator/actions"},
            "resources": {"/operator/resources"},
            "ai": {"/operator/policy", "/operator/actions"},
            "automation": {"/operator/policy", "/operator/actions"},
            "release": {"/operator/policy", "/operator/upload"},
            "cards": {"/operator/cards", "/operator/cards/wallet"},
            "support": {"/operator/support"},
            "security": {"/operator/policy"},
            "admins": {"/operator/admins"},
        }
        for tab, expected in endpoints.items():
            with self.subTest(tab=tab):
                document = PanelHTML(self.page(tab))
                forms = [node for node in document.nodes if node["tag"] == "form" and document.visible(node)]
                actions = {node["attrs"].get("action") for node in forms if node["attrs"].get("method") == "post"}
                self.assertTrue(expected <= actions, (tab, expected, actions))
                if tab in {"release", "resources"}:
                    target = "/operator/upload" if tab == "release" else "/operator/resources"
                    self.assertTrue(any(node["attrs"].get("action") == target and node["attrs"].get("enctype") == "multipart/form-data" for node in forms))
                if tab in {"quality", "ai", "automation"}:
                    returns = [node["attrs"].get("value") for node in document.nodes if node["attrs"].get("name") == "return_tab" and document.visible(node)]
                    self.assertIn(tab, returns)

    def test_map_escapes_registry_labels_and_has_no_fake_nodes(self):
        empty = PanelHTML(self.panel.reference_world_map([]))
        self.assertFalse(any(node["tag"] == "text" for node in empty.nodes))
        label = '<script>alert("node")</script> & real'
        location = '<img src=x onerror="alert(1)">'
        source = self.panel.reference_world_map([{
            "label": label, "location": location, "longitude": 2.3488,
            "latitude": 48.8534, "measurement": "17 мс", "state": "ok",
        }])
        document = PanelHTML(source)
        self.assertFalse(any(node["tag"] in {"script", "img"} for node in document.nodes))
        self.assertEqual([node["text"] for node in document.nodes if node["tag"] == "text"], [label])
        self.assertTrue(any(label in node["text"] and location in node["text"] for node in document.nodes if node["tag"] == "title"))

    def test_live_stream_resumes_after_last_event_id_even_at_same_timestamp(self):
        stamp = int(time.time())
        with closing(self.panel.conn()) as db:
            db.execute("delete from events")
            previous_id = db.execute("insert into events values (?,?,?,?,?)", (stamp, "old_event", "fixture", "", "already-delivered")).lastrowid
            next_id = db.execute("insert into events values (?,?,?,?,?)", (stamp, "new_event", "fixture", "", "new-after-reconnect")).lastrowid
            db.commit()
        handler = self.panel.App.__new__(self.panel.App)
        handler.path = "/operator/live"
        handler.headers = {**self.owner_headers, "Last-Event-ID": f"{stamp}:{previous_id}"}
        handler.client_address = ("127.0.0.1", 12345)
        handler.wfile = io.BytesIO()
        statuses = []
        response_headers = {}
        handler.send_response = statuses.append
        handler.send_header = lambda name, value: response_headers.__setitem__(name, value)
        handler.end_headers = lambda: None
        try:
            with mock.patch.object(self.panel.time, "monotonic", side_effect=[0, 0, 26]), mock.patch.object(self.panel.time, "sleep"):
                handler.do_GET()
            body = handler.wfile.getvalue().decode("utf-8")
        finally:
            for db in getattr(handler, "_dbs", []):
                db.close()
        self.assertEqual(statuses, [200])
        self.assertEqual(response_headers["Content-Type"], "text/event-stream; charset=utf-8")
        self.assertIn(f"id: {stamp}:{next_id}\n", body)
        self.assertNotIn("already-delivered", body)
        items = [json.loads(line.removeprefix("data: ")) for line in body.splitlines() if line.startswith("data: ")]
        self.assertEqual([item["detail"] for item in items], ["new-after-reconnect"])


if __name__ == "__main__":
    unittest.main()
