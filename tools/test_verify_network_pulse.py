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
                "credential_free": True, "csrf_forms": 2, "lab_scenario": False}
        return {"ok": True, "mode": "read-only", "panel_build": module.EXPECTED_BUILD,
                "services": {"quantumvpn-operator": "active", "rospanel": "active"},
                "pages": {view: copy.deepcopy(page) for view in module.VIEWS},
                "route_lab": {name: {**page, "lab_scenario": True} for name in ("instagram_domain", "public_ipv6")},
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
        output = self.module.redact_result(raw)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(output))
        self.assertNotIn("html", output["pages"]["routes"])
        self.assertNotIn("secret", output["mtproto"])
        self.assertNotIn("ip", output["warp"]["ipv6"])

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
                          (["mtproto", "ready_targets"], True), (["warp", "ipv6", "ip_family"], 4)):
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
        return ('<section data-network-view=' + view + '>NETWORK CENTER'
                '<form action=/operator/network/ai><input name=csrf value="' + ("a" * 64 if csrf else "") + '"></form></section>').encode()

    def test_remote_page_check_requires_real_view_current_build_and_csrf(self):
        headers = {"Server": "QuantumControl/2.3.0-pulse.1 Python", "Cache-Control": "no-store"}
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
        headers = {"Server": "QuantumControl/2.3.0-pulse.1 Python", "Cache-Control": "no-store"}
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
