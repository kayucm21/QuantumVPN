"""Offline guards for the redacted, read-only Network-center verifier."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit


def verifier_module():
    fake = types.ModuleType("paramiko")
    with mock.patch.dict(sys.modules, {"paramiko": fake}):
        spec = importlib.util.spec_from_file_location("network_verifier_test", Path(__file__).with_name("verify-network-pulse.py"))
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value


class VerificationGuardsTests(unittest.TestCase):
    def setUp(self):
        self.module = verifier_module()
        source = self.module.REMOTE_SOURCE.split("\ntry:\n    result = verify(CONFIG)", 1)[0]
        self.remote = {}
        exec(compile(source, "<read-only-verification>", "exec"), self.remote)

    def result(self):
        module = self.module
        page = {"status": 200, "network_marker": True, "build_matched": True,
                "credential_free": True, "csrf_forms": 2, "lab_scenario": False, "nested_forms": 0,
                "scanner_ids": {identifier: 1 for identifier in module.SCANNER_IDS}}
        return {"ok": True, "mode": "read-only", "panel_build": module.EXPECTED_BUILD,
                "services": {"quantumvpn-operator": "active", "rospanel": "active"},
                "pages": {view: copy.deepcopy(page) for view in module.VIEWS},
                "route_lab": {name: {**page, "lab_scenario": True} for name in ("instagram_domain", "public_ipv6")},
                "catalog": {name: {"status": 200, "total": 100, "matched": 100, "returned": 50,
                                    "limit": 50, "max_scan": 24, "ip_family": 4 if name == "ipv4" else (6 if name == "ipv6" else None)}
                            for name in module.CATALOG_PROBES},
                "local_apis": {abi: {name: {"status": 200, "version": module.EXPECTED_VERSION,
                                            "version_code": module.EXPECTED_CODE}
                                     for name in ("legacy", "updater")} for abi in module.ABIS},
                "mtproto": {"installed": True, "service": "active", "stats_loopback_only": True,
                            "secret_available": True, "upstream_ready": True, "ready_targets": 5},
                "warp": {"scope": "unconditional-diagnostic-SOCKS-not-subscriber-routing",
                         **{name: {"status": 200, "tls_verified": True, "warp": True, "ip_family": family}
                            for name, family in (("ipv4", 4), ("ipv6", 6))}}}

    def test_remote_source_is_valid_and_never_imports_app_or_writes_files(self):
        tree = ast.parse(self.module.REMOTE_SOURCE)
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("app" == alias.name or "quantumvpn_operator_panel" in alias.name
                             for node in imports for alias in getattr(node, "names", [])))
        self.assertIn("?mode=ro", self.module.REMOTE_SOURCE)
        self.assertIn("pragma query_only=on", self.module.REMOTE_SOURCE)
        self.assertNotIn("'POST'", self.module.REMOTE_SOURCE)
        self.assertNotIn("--insecure", self.module.REMOTE_SOURCE)
        self.assertNotIn("_create_unverified_context", self.module.REMOTE_SOURCE)
        self.assertEqual(self.module.EXPECTED_BUILD, "2.3.0-pulse.6")
        self.assertEqual(self.remote["BUILD"], self.module.EXPECTED_BUILD)
        self.assertNotIn("detector404", self.module.REMOTE_SOURCE)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {"write_bytes", "write_text", "mkdir", "unlink", "chmod", "chown", "remove", "replace"})

    def test_cli_has_no_apply_host_override_or_secret_argument(self):
        args = self.module.parser().parse_args([])
        self.assertFalse(args.require_mtproto)
        self.assertNotIn("password", vars(args))
        self.assertNotIn("host", vars(args))
        self.assertNotIn("apply", vars(args))
        self.assertEqual(self.module.HOST, "150.241.96.191")

    def test_artifact_url_accepts_only_exact_tls_origin_and_abi_name(self):
        for abi in self.module.ABIS:
            expected = f"{self.module.PUBLIC}/downloads/5.11.4/QuantumVPN-5.11.4-operator-debug-{abi}.apk"
            self.assertEqual(self.module.artifact_url(expected, abi), expected)
            for value in (expected.replace("https:", "http:"), expected.replace("pecaocek.ignorelist.com", "evil.example"),
                          expected + "?token=private", expected + "#fragment", expected.replace(":8443", ""),
                          expected.replace("5.11.4", "5.11.5"), "https://user:password@pecaocek.ignorelist.com:8443/private"):
                with self.subTest(value=value), self.assertRaises(self.module.CheckFailed):
                    self.module.artifact_url(value, abi)

    def test_nested_remote_private_fields_are_not_printable(self):
        raw = self.result()
        for view in self.module.VIEWS:
            raw["pages"][view]["html"] = "secret=DO_NOT_PUBLISH"
        raw["mtproto"]["secret"] = "DO_NOT_PUBLISH"
        raw["warp"]["ipv6"]["ip"] = "DO_NOT_PUBLISH"
        raw["local_apis"]["arm64-v8a"]["legacy"]["upstream"] = "DO_NOT_PUBLISH"
        raw["catalog"]["ipv4"]["items"] = [{"target": "DO_NOT_PUBLISH"}]
        raw["catalog"]["seed_search"]["query"] = "DO_NOT_PUBLISH"
        output = self.module.redact_result(raw)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(output))
        self.assertNotIn("html", output["pages"]["routes"])
        self.assertNotIn("secret", output["mtproto"])
        self.assertNotIn("ip", output["warp"]["ipv6"])
        self.assertNotIn("items", output["catalog"]["ipv4"])
        self.assertNotIn("query", output["catalog"]["seed_search"])

    def test_top_level_extra_field_or_wrong_release_is_rejected(self):
        for changed in ({**self.result(), "cookie": "private"}, {**self.result(), "panel_build": "old"}):
            with self.assertRaises(self.module.CheckFailed):
                self.module.redact_result(changed)
        changed = self.result()
        changed["local_apis"]["armeabi-v7a"]["updater"]["version"] = "old"
        with self.assertRaises(self.module.CheckFailed):
            self.module.redact_result(changed)

    def test_result_typed_leaves_do_not_accept_strings_or_boolean_counters(self):
        for path, bad in ((["pages", "routes", "credential_free"], "true"),
                          (["mtproto", "ready_targets"], True), (["warp", "ipv6", "ip_family"], 4),
                          (["catalog", "ipv4", "ip_family"], "4"), (["catalog", "domain", "returned"], True),
                          (["catalog", "ipv6", "max_scan"], 25), (["catalog", "ipv4", "limit"], 51),
                          (["pages", "routes", "nested_forms"], 1),
                          (["pages", "overview", "scanner_ids", "routing-scan-form"], 2)):
            changed = self.result()
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = bad
            with self.subTest(path=path), self.assertRaises(self.module.CheckFailed):
                self.module.redact_result(changed)

    def test_remote_error_output_never_accepts_unknown_private_string(self):
        channel = mock.Mock()
        channel.recv_exit_status.return_value = 1
        stdin = mock.Mock()
        stdout = mock.Mock(channel=channel)
        stdout.read.return_value = json.dumps({"ok": False, "error": "a" * 32}).encode()
        stderr = mock.Mock()
        stderr.read.return_value = b"private exception and secret"
        client = mock.Mock()
        client.exec_command.return_value = stdin, stdout, stderr
        with self.assertRaisesRegex(self.module.CheckFailed, "^remote_verification_failed$"):
            self.module.remote_verification(client)
        client.exec_command.assert_called_once_with("python3 -B -", timeout=240)
        stdin.channel.shutdown_write.assert_called_once_with()

    def page_html(self, view, csrf=True):
        token = "a" * 64 if csrf else ""
        scan = ""
        if view in self.module.SCANNER_VIEWS:
            scan = ('<form id=routing-scan-form action=/operator/routing><input name=return_tab value=network>'
                    '<input name=csrf value="' + token + '"></form>'
                    '<dialog id=routing-scan-dialog><form id=routing-scan-apply action=/operator/routing>'
                    '<input name=return_tab value=network><input name=csrf value="' + token + '"></form></dialog>'
                    '<dialog id=routing-catalog-dialog><input id=routing-catalog-search></dialog>')
        return ('<section data-network-view=' + view + '>NETWORK CENTER'
                '<form action=/operator/network/ai><input name=csrf value="' + token + '"></form>' + scan + '</section>').encode()

    def headers(self):
        return {"Server": "QuantumControl/" + self.module.EXPECTED_BUILD + " Python", "Cache-Control": "no-store"}

    def test_remote_page_check_requires_real_view_current_build_and_csrf(self):
        headers = self.headers()
        request = mock.Mock(return_value=(200, headers, self.page_html("ai")))
        with mock.patch.dict(self.remote, request=request):
            output = self.remote["page_check"]({}, "ephemeral-cookie", "ai")
        self.assertEqual(output["csrf_forms"], 1)
        self.assertNotIn("ephemeral-cookie", json.dumps(output))
        request.assert_called_once_with({}, "/operator?tab=network&network_view=ai", "ephemeral-cookie")
        for body in (self.page_html("nodes"), self.page_html("ai", csrf=False), self.page_html("ai") + b"secret=private"):
            with self.subTest(body=body), mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, headers, body))):
                with self.assertRaises(self.remote["CheckFailed"]):
                    self.remote["page_check"]({}, "ephemeral-cookie", "ai")

    def test_read_only_node_cards_allow_zero_forms_without_weakening_mutating_views(self):
        headers = self.headers()
        body = b"<section data-network-view=nodes>NETWORK CENTER<article>Read-only node card</article></section>"
        with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, headers, body))):
            result = self.remote["page_check"]({}, "ephemeral-cookie", "nodes")
        self.assertEqual(result["csrf_forms"], 0)
        self.assertTrue(result["network_marker"])
        for view in ("overview", "dns", "routes", "ai", "mtproto"):
            no_forms = body.replace(b"data-network-view=nodes", ("data-network-view=" + view).encode())
            with self.subTest(view=view), mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, headers, no_forms))):
                with self.assertRaises(self.remote["CheckFailed"]):
                    self.remote["page_check"]({}, "ephemeral-cookie", view)
        # A future writable node form still needs a token; the allowance is for
        # absence of forms, not exemption of unsafe forms from CSRF checks.
        unsafe_form = self.page_html("nodes", csrf=False)
        with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, headers, unsafe_form))):
            with self.assertRaises(self.remote["CheckFailed"]):
                self.remote["page_check"]({}, "ephemeral-cookie", "nodes")

    def test_redactor_accepts_zero_forms_on_read_only_nodes(self):
        result = self.result()
        result["pages"]["nodes"]["csrf_forms"] = 0
        redacted = self.module.redact_result(result)
        self.assertEqual(redacted["pages"]["nodes"]["csrf_forms"], 0)
        result["pages"]["nodes"]["csrf_forms"] = -1
        with self.assertRaises(self.module.CheckFailed):
            self.module.redact_result(result)

    def test_three_network_scanner_views_require_one_correct_tag_per_id_unquoted_or_quoted(self):
        for view in self.module.SCANNER_VIEWS:
            body = self.page_html(view)
            with self.subTest(view=view), mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), body))):
                result = self.remote["page_check"]({}, "ephemeral-cookie", view)
                self.assertEqual(result["scanner_ids"], {identifier: 1 for identifier in self.module.SCANNER_IDS})
                self.assertEqual(result["nested_forms"], 0)
            quoted = body.replace(("data-network-view=" + view).encode(), ('data-network-view="' + view + '"').encode())
            for identifier in self.module.SCANNER_IDS:
                quoted = quoted.replace(("id=" + identifier).encode(), ('id="' + identifier + '"').encode())
            with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), quoted))):
                self.remote["page_check"]({}, "ephemeral-cookie", view)
            for identifier in self.module.SCANNER_IDS:
                wrong = body.replace(("id=" + identifier).encode(), ("id=wrong-" + identifier).encode())
                duplicate = body + ('<div id="' + identifier + '"></div>').encode()
                for invalid in (wrong, duplicate):
                    with self.subTest(view=view, identifier=identifier), mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), invalid))):
                        with self.assertRaisesRegex(self.remote["CheckFailed"], "page_scanner_ids_" + view):
                            self.remote["page_check"]({}, "ephemeral-cookie", view)
        wrong_tag = self.page_html("routes").replace(b'<dialog id=routing-catalog-dialog>', b'<div id=routing-catalog-dialog>')
        with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), wrong_tag))):
            with self.assertRaisesRegex(self.remote["CheckFailed"], "page_scanner_ids_routes"):
                self.remote["page_check"]({}, "ephemeral-cookie", "routes")

    def test_remote_pages_reject_nested_and_unclosed_forms(self):
        body = self.page_html("ai")
        nested = body.replace(b'</form>', b'<form action=/operator/network/ai></form></form>')
        unclosed = body.replace(b'</form>', b'')
        for invalid in (nested, unclosed):
            with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), invalid))):
                with self.assertRaisesRegex(self.remote["CheckFailed"], "page_forms_ai"):
                    self.remote["page_check"]({}, "ephemeral-cookie", "ai")

    def catalog_payload(self, name):
        family = 4 if name == "ipv4" else (6 if name == "ipv6" else None)
        target = "1.1.1.1" if family == 4 else ("2606:4700:4700::1111" if family == 6 else ("youtube.com" if name == "seed_search" else "google.com"))
        return {"total": 2883, "matched": 1, "offset": 0, "limit": 50, "max_scan": 24,
                "kind": name if family else "domain", "query": "youtube" if name == "seed_search" else "",
                "items": [{"target": target, "kind": "ip" if family else "domain", "ip_version": family,
                           "selectable": True, "sources": ["private-source-name"], "addresses": ["private-address"]}]}

    def test_catalog_get_probes_are_authenticated_fixed_local_paths_bounded_and_redacted(self):
        calls = []
        for name in self.module.CATALOG_PROBES:
            raw = self.catalog_payload(name)
            request = mock.Mock(return_value=(200, self.headers(), json.dumps(raw).encode()))
            with mock.patch.dict(self.remote, request=request):
                result = self.remote["catalog_check"]({}, "ephemeral-cookie", name)
            calls.append(request.call_args.args)
            self.assertEqual(result["returned"], 1)
            self.assertEqual(result["limit"], 50)
            self.assertEqual(result["max_scan"], 24)
            self.assertEqual(result["ip_family"], raw["items"][0]["ip_version"])
            self.assertNotIn(raw["items"][0]["target"], json.dumps(result))
            self.assertNotIn("private", json.dumps(result))
        self.assertEqual(len(calls), 4)
        for environment, path, cookie in calls:
            parsed = urlsplit(path)
            self.assertEqual(environment, {})
            self.assertEqual(cookie, "ephemeral-cookie")
            self.assertEqual(parsed.scheme, "")
            self.assertEqual(parsed.netloc, "")
            self.assertEqual(parsed.path, "/operator/routing/catalog")
            query = parse_qs(parsed.query, keep_blank_values=True)
            self.assertEqual(set(query), {"kind", "q", "offset", "limit"})
            self.assertEqual(query["limit"], ["50"])
            self.assertEqual(query["offset"], ["0"])
            self.assertIn(query["kind"], (["ipv4"], ["ipv6"], ["domain"]))
            self.assertIn(query["q"], ([""], ["youtube"]))

    def test_catalog_probe_rejects_wrong_family_private_cidr_duplicate_and_unbounded_shape(self):
        baseline = self.catalog_payload("ipv4")
        invalid = []
        for patch in ({"limit": 51}, {"max_scan": 25}, {"max_scan": True}, {"matched": 0}, {"kind": "ipv6"}):
            invalid.append({**baseline, **patch})
        for patch in ({"ip_version": 6}, {"ip_version": "4"}, {"target": "127.0.0.1"},
                      {"target": "224.0.0.1"}, {"target": "2606:4700:4700::1111"},
                      {"target": "1.1.1.0/24", "kind": "cidr", "selectable": False}, {"selectable": False}):
            invalid.append({**baseline, "items": [{**baseline["items"][0], **patch}]})
        invalid.append({**baseline, "matched": 2, "items": baseline["items"] * 2})
        invalid.append({**baseline, "matched": 51, "items": baseline["items"] * 51})
        for value in invalid:
            with self.subTest(value=value), mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), json.dumps(value).encode()))):
                with self.assertRaises(self.remote["CheckFailed"]):
                    self.remote["catalog_check"]({}, "ephemeral-cookie", "ipv4")
        for name in ("ipv4", "ipv6"):
            empty = {**self.catalog_payload(name), "matched": 0, "items": []}
            with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), json.dumps(empty).encode()))):
                self.assertEqual(self.remote["catalog_check"]({}, "ephemeral-cookie", name)["returned"], 0)
        search = {**self.catalog_payload("seed_search"), "matched": 0, "items": []}
        with mock.patch.dict(self.remote, request=mock.Mock(return_value=(200, self.headers(), json.dumps(search).encode()))):
            with self.assertRaisesRegex(self.remote["CheckFailed"], "catalog_search_seed_search"):
                self.remote["catalog_check"]({}, "ephemeral-cookie", "seed_search")

    def test_catalog_response_and_probe_allowlist_fail_closed_with_safe_labels(self):
        good = json.dumps(self.catalog_payload("domain")).encode()
        for status, headers, body, label in (
                (403, self.headers(), good, "catalog_status_domain"),
                (200, {}, good, "catalog_cache_domain"),
                (200, self.headers(), b"x" * 131073, "catalog_bound_domain"),
                (200, self.headers(), b'{"cookie":"private",', "catalog_shape_domain"),
                (200, self.headers(), b'[]', "catalog_shape_domain")):
            with self.subTest(label=label), mock.patch.dict(self.remote, request=mock.Mock(return_value=(status, headers, body))):
                with self.assertRaisesRegex(self.remote["CheckFailed"], "^" + label + "$"):
                    self.remote["catalog_check"]({}, "ephemeral-cookie", "domain")
                self.assertIn(label, self.module.SAFE_REMOTE_ERRORS)
        request = mock.Mock()
        with mock.patch.dict(self.remote, request=request):
            with self.assertRaises(self.remote["CheckFailed"]):
                self.remote["catalog_check"]({}, "ephemeral-cookie", "https://third-party.example/")
        request.assert_not_called()

    def test_remote_warp_output_redacts_exit_address_and_has_explicit_scope(self):
        ip = "2606:4700:abcd::1234"
        raw = f"ip={ip}\nwarp=on\n" + json.dumps({"ssl_verify_result": 0, "http_code": 200})
        command = mock.Mock(return_value=raw.encode())
        with mock.patch.dict(self.remote, command=command):
            result = self.remote["warp_trace"](6)
        self.assertEqual(result, {"status": 200, "tls_verified": True, "warp": True, "ip_family": 6})
        self.assertNotIn(ip, json.dumps(result))
        argv = command.call_args.args[0]
        self.assertIn("127.0.0.1:18081", argv)
        self.assertNotIn("--insecure", argv)

    def test_remote_proxy_snapshot_drops_credentials_and_requires_upstream(self):
        snapshot = {"installed": True, "service": "active", "stats_loopback_only": True,
                    "secret_available": True, "upstream_ready": True,
                    "stats": {"total_ready_targets": 5}, "secret": "DO_NOT_PUBLISH"}
        with mock.patch.dict(self.remote, command=mock.Mock(return_value=json.dumps(snapshot).encode())):
            with mock.patch.object(self.remote["Path"], "is_file", return_value=True), \
                    mock.patch.object(self.remote["Path"], "is_symlink", return_value=False):
                result = self.remote["mtproto_status"](True)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(result))
        self.assertEqual(result["ready_targets"], 5)
        snapshot["upstream_ready"] = False
        with mock.patch.dict(self.remote, command=mock.Mock(return_value=json.dumps(snapshot).encode())):
            with mock.patch.object(self.remote["Path"], "is_file", return_value=True), \
                    mock.patch.object(self.remote["Path"], "is_symlink", return_value=False), \
                    self.assertRaises(self.remote["CheckFailed"]):
                self.remote["mtproto_status"](True)


if __name__ == "__main__":
    unittest.main()
