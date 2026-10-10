"""Offline Safehop deployment guards: no SSH, packages or host service changes."""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import sys
from types import SimpleNamespace
import types
import unittest
from unittest.mock import Mock, patch

import quantumvpn_safehop_dns as dns
import quantumvpn_safehop_front as front


INSTALLER_PATH = Path(__file__).with_name("install-safehop-dns-vds.py")
SPEC = importlib.util.spec_from_file_location("safehop_installer", INSTALLER_PATH)
installer = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"paramiko": Mock()}):
    SPEC.loader.exec_module(installer)
REMOTE_TREE = ast.parse(installer.REMOTE)
CONSTANTS = {"ROOT", "CFG", "MANIFEST", "FRONT_UNIT", "ROUTE_UNIT", "DOMAIN", "PUBLIC",
             "TABLE", "KEY_FINGERPRINT", "PROTECTED", "ROUTE_SERVICE", "ROUTE_SOURCE", "RENEW_SOURCE"}
REMOTE = dict(Path=Path, base64=base64, hashlib=hashlib, json=json, os=os, re=re,
              types=types, ipaddress=ipaddress, socket=socket, dns=dns, front=front)
# Load definitions, not the remote entry point or its platform-specific imports.
definitions = [node for node in REMOTE_TREE.body if isinstance(node, ast.FunctionDef)
               or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
               and target.id in CONSTANTS for target in node.targets)]
exec(compile(ast.Module(body=definitions, type_ignores=[]), "<safehop-offline>", "exec"), REMOTE)


class MemoryPath:
    """Only the path operations required by mocked package and helper tests."""

    files = {}
    links = {}

    def __init__(self, value):
        self.value = PurePosixPath(str(value))

    def __str__(self):
        return str(self.value)

    def __truediv__(self, value):
        return type(self)(self.value / value)

    def __eq__(self, other):
        return str(self) == str(other)

    @property
    def parent(self):
        return type(self)(self.value.parent)

    def exists(self):
        return str(self) in self.files or str(self) in self.links

    def is_symlink(self):
        return str(self) in self.links

    def unlink(self):
        self.links.pop(str(self), None)
        self.files.pop(str(self), None)

    def read_bytes(self):
        return self.files[str(self)]

    def read_text(self):
        value = self.read_bytes()
        return value.decode() if isinstance(value, bytes) else value


def function_tree(name):
    return next(node for node in REMOTE_TREE.body
                if isinstance(node, ast.FunctionDef) and node.name == name)


class InstallerContractTests(unittest.TestCase):
    def test_outer_and_all_embedded_scripts_compile(self):
        compile(INSTALLER_PATH.read_text(encoding="utf-8"), str(INSTALLER_PATH), "exec")
        for name, source in (("REMOTE", installer.REMOTE), ("ROUTE_SOURCE", REMOTE["ROUTE_SOURCE"]),
                             ("RENEW_SOURCE", REMOTE["RENEW_SOURCE"])):
            with self.subTest(script=name):
                compile(source, "<" + name + ">", "exec")

    def test_inventory_dispatch_never_acquires_mutation_lock(self):
        result = {"status": "ReadOnly"}
        mutations = {name: Mock(side_effect=AssertionError(name)) for name in
                     ("bootstrap", "activate", "verify", "inspect")}
        output = io.StringIO()
        with patch.dict(REMOTE, {"MODE": "inventory", "inventory": Mock(return_value=result),
                                "os": SimpleNamespace(open=Mock(side_effect=AssertionError("lock"))),
                                **mutations}), contextlib.redirect_stdout(output):
            exec(compile(ast.Module(body=[REMOTE_TREE.body[-1]], type_ignores=[]),
                         "<inventory-dispatch>", "exec"), REMOTE)
        self.assertEqual(json.loads(output.getvalue()), result)
        for mutation in mutations.values():
            mutation.assert_not_called()

    def test_outer_default_payload_is_inventory_and_credentials_are_environment_only(self):
        client = Mock()
        stdin, stdout, stderr = Mock(), Mock(), Mock()
        stdout.read.return_value = b'{"status":"ReadOnly"}\n'
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = stdin, stdout, stderr
        ssh = Mock(SSHClient=Mock(return_value=client))
        with patch.object(installer, "paramiko", ssh), patch.dict(os.environ, {"QVPN_VDS_PASSWORD": "offline-sentinel"}, clear=True), \
                patch.object(sys, "argv", [str(INSTALLER_PATH)]), contextlib.redirect_stdout(io.StringIO()):
            installer.main()
        payload = stdin.write.call_args.args[0]
        self.assertIn("MODE='inventory'", payload)
        self.assertNotIn("offline-sentinel", payload)
        client.connect.assert_called_once_with("150.241.96.191", username="root", password="offline-sentinel",
                                               allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        client.set_missing_host_key_policy.assert_called_once_with(ssh.RejectPolicy.return_value)
        client.close.assert_called_once()

    def test_missing_password_and_missing_bootstrap_hashes_fail_before_ssh(self):
        ssh = Mock()
        for argv in ([str(INSTALLER_PATH)], [str(INSTALLER_PATH), "--mode", "bootstrap"]):
            with self.subTest(argv=argv), patch.object(installer, "paramiko", ssh), \
                    patch.dict(os.environ, {}, clear=True), patch.object(sys, "argv", argv), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                installer.main()
        ssh.SSHClient.assert_not_called()

    def test_protected_paths_cover_existing_vpn_private_material_and_host_resolver(self):
        self.assertTrue({"/usr/local/bin/rospanel", "/var/lib/rospanel/xray/config.json",
                         "/var/lib/rospanel/certs/cert.pem", "/var/lib/rospanel/certs/key.pem",
                         "/var/lib/rospanel/secrets.key", "/etc/nginx/nginx.conf", "/etc/resolv.conf"}
                        <= set(REMOTE["PROTECTED"]))
        self.assertIn("/run/systemd/resolve/stub-resolv.conf", ast.unparse(function_tree("protected")))

    def test_bootstrap_hash_mismatch_precedes_any_mutation(self):
        mutate = Mock(side_effect=AssertionError("must not mutate"))
        with patch.dict(REMOTE, {"EXPECTED": {"vpn": "expected"},
                                "inventory": Mock(return_value={"protected_hashes": {"vpn": "changed"}}),
                                "mkdir": mutate, "packages": mutate, "save": mutate}):
            with self.assertRaisesRegex(RuntimeError, "protected_identity_changed"):
                REMOTE["bootstrap"]()
        mutate.assert_not_called()

    def test_inventory_requires_proxy_protocol_and_unknown_sni_rejection(self):
        inbound = {"tag": "vless-in", "listen": "127.0.0.1", "port": 18443,
                   "streamSettings": {"sockopt": {"acceptProxyProtocol": True},
                                      "tlsSettings": {"rejectUnknownSni": True}}}
        for field, error in (("acceptProxyProtocol", "proxy_protocol_required"),
                             ("rejectUnknownSni", "unknown_sni_must_fail_closed")):
            candidate = json.loads(json.dumps(inbound))
            branch = "sockopt" if field == "acceptProxyProtocol" else "tlsSettings"
            candidate["streamSettings"][branch][field] = False
            with self.subTest(field=field), patch.dict(REMOTE, {
                    "os": SimpleNamespace(geteuid=lambda: 0),
                    "Path": Mock(return_value=SimpleNamespace(read_text=lambda: 'VERSION_ID="24.04"')),
                    "read": Mock(return_value=json.dumps({"inbounds": [candidate]})),
                    "run": Mock(side_effect=AssertionError("must stop before network inventory"))}):
                with self.assertRaisesRegex(RuntimeError, error):
                    REMOTE["inventory"]()

    def test_installed_nginx_directories_match_configuration(self):
        loops = [node for node in ast.walk(function_tree("bootstrap")) if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name) and node.target.id == "name"
                 and isinstance(node.iter, ast.Tuple)]
        created = next({item.value for item in node.iter.elts} for node in loops
                       if any(isinstance(item, ast.Constant) and item.value == "client-body" for item in node.iter.elts))
        configured = set(re.findall(re.escape(front.PREFIX) + r"/([a-z-]+) 1 2;", front.bootstrap_config()))
        self.assertEqual(created, configured)
        source = ast.unparse(function_tree("bootstrap"))
        self.assertIn("mkdir(front.PREFIX", source)
        self.assertIn("mkdir(front.RUNTIME_DIRECTORY", source)

    def test_ready_query_retries_only_startup_socket_races(self):
        query = Mock(side_effect=[ConnectionRefusedError(), TimeoutError(), {"ok": True}])
        sleep = Mock()
        with patch.dict(REMOTE, {"query": query, "time": SimpleNamespace(sleep=sleep)}):
            self.assertEqual(REMOTE["ready_query"]("127.0.0.1", 18553), {"ok": True})
        self.assertEqual(query.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        with patch.dict(REMOTE, {"query": Mock(side_effect=RuntimeError("dnssec_failed")),
                                "time": SimpleNamespace(sleep=sleep)}):
            with self.assertRaisesRegex(RuntimeError, "dnssec_failed"):
                REMOTE["ready_query"]("127.0.0.1", 18553)

    def test_ready_query_retry_budget_is_bounded(self):
        query, sleep = Mock(side_effect=ConnectionRefusedError()), Mock()
        with patch.dict(REMOTE, {"query": query, "time": SimpleNamespace(sleep=sleep)}):
            with self.assertRaises(ConnectionRefusedError):
                REMOTE["ready_query"]("127.0.0.1", 18553)
        self.assertEqual(query.call_count, 10)
        self.assertEqual(sleep.call_count, 9)

    def test_embedded_configuration_digest_is_checked_before_execution(self):
        source = b"raise AssertionError('must not execute changed source')"
        with self.assertRaisesRegex(RuntimeError, "local_source_identity_failed"):
            REMOTE["source"](base64.b64encode(source), "0" * 64, "offline-config")


class PackageAndActivationTests(unittest.TestCase):
    def setUp(self):
        MemoryPath.files = {}
        MemoryPath.links = {}

    def package_run(self, candidate="2.1.2", fail_install=False):
        def run(args, *unused, **kwargs):
            if args[0] == "gpg":
                value = "fpr:::::::::" + REMOTE["KEY_FINGERPRINT"] + ":\n"
            elif args[:2] == ["apt-cache", "policy"]:
                value = "Candidate: " + candidate + "-1pdns.ubuntu24.04\n noble-dnsdist-21\n"
            elif args[:2] == ["dnsdist", "--version"]:
                value = "dnsdist 2.1.2\n dns-over-https dns-over-tls\n"
            else:
                value = ""
            if args[:2] == ["apt-get", "install"]:
                self.assertEqual(set(MemoryPath.links), {"/run/systemd/system/" + unit for unit in
                                 ("unbound.service", "unbound-resolvconf.service", "dnsdist.service")})
                if fail_install:
                    raise RuntimeError("install_failed")
            return SimpleNamespace(stdout=value, returncode=0)
        return Mock(side_effect=run)

    @contextlib.contextmanager
    def package_environment(self, run):
        remote_os = SimpleNamespace(symlink=lambda target, path: MemoryPath.links.update({str(path): target}),
                                    readlink=lambda path: MemoryPath.links[str(path)])
        urlopen = Mock(return_value=SimpleNamespace(read=lambda bound: b"test signed key"))
        with patch.dict(REMOTE, {"Path": MemoryPath, "os": remote_os, "run": run,
                                "urllib": SimpleNamespace(request=SimpleNamespace(urlopen=urlopen)),
                                "mkdir": Mock(), "write": Mock(), "save": Mock()}):
            yield

    def test_all_stock_dns_units_are_masked_and_masks_removed_even_on_install_failure(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                run = self.package_run(fail_install=failed)
                state = {}
                with self.package_environment(run):
                    if failed:
                        with self.assertRaisesRegex(RuntimeError, "install_failed"):
                            REMOTE["packages"](state)
                    else:
                        REMOTE["packages"](state)
                        self.assertTrue(state["packages_ready"])
                self.assertEqual(MemoryPath.links, {})
                self.assertEqual(run.call_args.args[0], ["systemctl", "daemon-reload"])

    def test_candidate_gate_rejects_old_patch_and_accepts_double_digit_patch(self):
        for version, allowed in (("2.1.1", False), ("2.1.2", True), ("2.1.10", True)):
            with self.subTest(version=version), self.package_environment(self.package_run(candidate=version)):
                if allowed:
                    REMOTE["packages"]({})
                else:
                    with self.assertRaisesRegex(RuntimeError, "supported_signed_dnsdist_candidate_required"):
                        REMOTE["packages"]({})

    def test_activation_preconditions_prevent_commands(self):
        run = Mock(side_effect=AssertionError("must not issue command"))
        for stage, hashes, error in (("preparing", {"vpn": "expected"}, "certificate_ready_required"),
                                     ("certificate_ready", {"vpn": "changed"}, "protected_identity_changed")):
            state = {"stage": stage, "protected_hashes": {"vpn": "expected"}}
            with self.subTest(stage=stage, hashes=hashes), patch.dict(REMOTE, {
                    "state": Mock(return_value=state), "protected": Mock(return_value=hashes), "run": run}):
                with self.assertRaisesRegex(RuntimeError, error):
                    REMOTE["activate"]()
        run.assert_not_called()

    def test_failed_route_enable_restores_bootstrap_rules_config_and_stops_dns(self):
        state = {"stage": "certificate_ready", "protected_hashes": {"vpn": "same"},
                 "nft_rules": front.nftables_rules(bootstrap=True)}
        writes, switches, commands = [], [], []
        def run(args, *unused, **kwargs):
            commands.append(args)
            if args == ["systemctl", "start", REMOTE["ROUTE_UNIT"]]:
                raise RuntimeError("route_start_failed")
        def switch(rules, current):
            switches.append(rules)
            current["nft_rules"] = rules
        with patch.dict(REMOTE, {"state": Mock(return_value=state), "protected": Mock(return_value={"vpn": "same"}),
                                "run": run, "ready_query": Mock(), "query": Mock(),
                                "doh_probe": Mock(return_value={"ok": True}),
                                "read": Mock(return_value=b"old nginx config"),
                                "write": lambda path, data, *args: writes.append((path, data)),
                                "switch_rules": switch, "save": Mock()}):
            with self.assertRaisesRegex(RuntimeError, "route_start_failed"):
                REMOTE["activate"]()
        self.assertEqual(switches, [front.nftables_rules(), front.nftables_rules(bootstrap=True)])
        self.assertEqual(writes[-1], (front.NGINX_CONFIG, b"old nginx config"))
        self.assertEqual(state["stage"], "certificate_ready")
        self.assertIn(["systemctl", "stop", dns.DNSDIST_SERVICE], commands)
        for command in commands:
            self.assertFalse({"rospanel", "nginx", "quantumvpn-operator"} & set(command[1:]))

    def test_foreign_nft_table_is_never_changed_or_deleted(self):
        run = Mock(side_effect=AssertionError("foreign table must not be mutated"))
        state = {"nft_fingerprint": "different"}
        with patch.dict(REMOTE, {"table": Mock(return_value=front.nft_table_data()), "run": run}):
            with self.assertRaisesRegex(RuntimeError, "foreign_or_changed_nft_table"):
                REMOTE["switch_rules"](front.nftables_rules(), state)
            with self.assertRaisesRegex(RuntimeError, "changed_nft_table_no_delete"):
                REMOTE["stop_rules"](state)
        run.assert_not_called()

    def test_verification_rejects_inactive_units_before_network_queries(self):
        table = front.nft_table_data()
        state = {"stage": "active", "protected_hashes": {"vpn": "same"},
                 "nft_fingerprint": REMOTE["identity"](table)}
        query = Mock(side_effect=AssertionError("must fail before networking"))
        with patch.dict(REMOTE, {"state": Mock(return_value=state),
                                "protected": Mock(return_value={"vpn": "same"}),
                                "table": Mock(return_value=table),
                                "service": Mock(side_effect=lambda unit: unit != dns.DNSDIST_SERVICE),
                                "query": query, "doh_probe": query}):
            with self.assertRaisesRegex(RuntimeError, "active_services_required"):
                REMOTE["verify"]()
        query.assert_not_called()

    def test_failed_refresh_doh_gate_restores_owned_config_and_rules(self):
        state = {"stage": "active", "protected_hashes": {"vpn": "same"},
                 "nft_rules": "old owned rules"}
        writes, switches = [], []
        commands = Mock()
        with patch.dict(REMOTE, {"state": Mock(return_value=state),
                                "protected": Mock(return_value={"vpn": "same"}),
                                "read": Mock(return_value=b"old owned config"),
                                "write": lambda path, data, *args: writes.append((path, data)),
                                "run": commands, "save": Mock(),
                                "switch_rules": lambda rules, unused: switches.append(rules),
                                "doh_probe": Mock(side_effect=RuntimeError("doh_http_contract"))}):
            with self.assertRaisesRegex(RuntimeError, "doh_http_contract"):
                REMOTE["refresh"]()
        self.assertEqual(switches, [front.nftables_rules(), "old owned rules"])
        self.assertEqual(writes[-1], (front.NGINX_CONFIG, b"old owned config"))
        self.assertEqual(commands.call_args.args[0], ["systemctl", "reload", REMOTE["FRONT_UNIT"]])


class EmbeddedHelperTests(unittest.TestCase):
    def setUp(self):
        MemoryPath.files = {}
        MemoryPath.links = {}

    def test_route_restores_comment_prefixed_generated_rules_and_verifies_identity(self):
        table = front.nft_table_data()
        state = {"managed_by": "quantumvpn-safehop-dns", "schema": 1, "stage": "active",
                 "nft_rules": front.nftables_rules(), "nft_fingerprint": REMOTE["identity"](table)}
        MemoryPath.files["/var/lib/quantumvpn-safehop-dns/installation.json"] = json.dumps(state)
        self.assertTrue(state["nft_rules"].startswith("#"))
        results = [SimpleNamespace(returncode=1, stdout=""), SimpleNamespace(returncode=0, stdout=""),
                   SimpleNamespace(returncode=0, stdout=""), SimpleNamespace(returncode=0, stdout=json.dumps(table))]
        run = Mock(side_effect=results)
        with patch("pathlib.Path", MemoryPath), patch("subprocess.run", run), patch.object(sys, "argv", ["route", "start"]):
            exec(compile(REMOTE["ROUTE_SOURCE"], "<route-offline>", "exec"), {})
        self.assertEqual(run.call_args_list[1].args[0], ["nft", "--check", "-f", "-"])
        self.assertEqual(run.call_args_list[2].kwargs["input"], state["nft_rules"])

    def test_route_refuses_modified_existing_table_without_mutating_it(self):
        MemoryPath.files["/var/lib/quantumvpn-safehop-dns/installation.json"] = json.dumps({
            "managed_by": "quantumvpn-safehop-dns", "schema": 1, "nft_fingerprint": "different"})
        run = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(front.nft_table_data())))
        with patch("pathlib.Path", MemoryPath), patch("subprocess.run", run), patch.object(sys, "argv", ["route", "stop"]):
            with self.assertRaisesRegex(AssertionError, "foreign_route_no_change"):
                exec(compile(REMOTE["ROUTE_SOURCE"], "<route-offline>", "exec"), {})
        self.assertEqual(run.call_count, 1)

    def renewal_environment(self, lineage, run=None):
        root = "/var/lib/quantumvpn-safehop-dns/tls/"
        live = "/etc/letsencrypt/live/" + front.DOMAIN + "/"
        MemoryPath.files.update({root + "fullchain.pem": b"old cert", root + "privkey.pem": b"old key",
                                 live + "fullchain.pem": b"new cert", live + "privkey.pem": b"new key"})
        ssl = SimpleNamespace(_ssl=SimpleNamespace(_test_decode_cert=Mock(return_value={
                              "subjectAltName": (("DNS", front.DOMAIN),), "notAfter": "valid"})),
                              cert_time_to_seconds=Mock(return_value=3 * 86400), PROTOCOL_TLS_SERVER=1,
                              SSLContext=Mock())
        writes = []
        def write(path, data):
            writes.append((str(path), data))
            MemoryPath.files[str(path)] = data
        namespace = {"Path": MemoryPath, "os": SimpleNamespace(environ={"RENEWED_LINEAGE": lineage}),
                     "ssl": ssl, "time": SimpleNamespace(time=lambda: 0),
                     "run": run or Mock(), "active": Mock(return_value=True), "write": write}
        tree = ast.parse(REMOTE["RENEW_SOURCE"])
        tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
        return namespace, writes, compile(tree, "<renewal-offline>", "exec")

    def test_other_certificate_lineage_exits_before_reading_keys_or_reloading(self):
        namespace, writes, code = self.renewal_environment("/etc/letsencrypt/live/other.example")
        with self.assertRaises(SystemExit) as failure:
            exec(code, namespace)
        self.assertEqual(failure.exception.code, 0)
        namespace["ssl"]._ssl._test_decode_cert.assert_not_called()
        namespace["run"].assert_not_called()
        namespace["active"].assert_not_called()
        self.assertEqual(writes, [])

    def test_failed_dns_restart_restores_both_keys_and_restarts_using_old_certificate(self):
        calls = []
        def run(args):
            calls.append(args)
            if args == ["systemctl", "restart", dns.DNSDIST_SERVICE] and calls.count(args) == 1:
                raise RuntimeError("restart_failed")
        namespace, writes, code = self.renewal_environment("/etc/letsencrypt/live/" + front.DOMAIN, run=run)
        with self.assertRaisesRegex(RuntimeError, "restart_failed"):
            exec(code, namespace)
        self.assertEqual([data for path, data in writes], [b"new cert", b"new key", b"old cert", b"old key"])
        self.assertEqual(calls.count(["systemctl", "restart", dns.DNSDIST_SERVICE]), 2)
        self.assertTrue(all(path.startswith("/var/lib/quantumvpn-safehop-dns/tls/") for path, data in writes))
        for call in calls:
            self.assertFalse({"rospanel", "nginx", "quantumvpn-operator"} & set(call[1:]))


if __name__ == "__main__":
    unittest.main()
