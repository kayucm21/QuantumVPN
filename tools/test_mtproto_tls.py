"""Owner credential isolation, fixed endpoint and independent service guards."""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import quantumvpn_mtproto_tls as tls
import quantumvpn_proxy_links as links


SECRET = "a1" * 16


def config():
    return {"schema": 1, "managed_by": "quantumvpn", "commit": tls.COMMIT,
            "security_patch": tls.SECURITY_PATCH, "patch_sha256": tls.SECURITY_PATCH_SHA256,
            "source_file_sha256": tls.BASE_SOURCE_SHA256, "base_module_sha256": tls.BASE_MODULE_SHA256,
            "server": tls.PUBLIC_HOST, "domain": tls.DOMAIN, "port": tls.PUBLIC_PORT,
            "stats_port": tls.STATS_PORT, "workers": 0, "created_at": 1791520000,
            "binary_sha256": "a" * 64, "module_sha256": "b" * 64, "protocol_sha256": "c" * 64}


class TLSHelperTests(unittest.TestCase):
    def test_fixed_install_identity(self):
        value = config()
        self.assertEqual(tls._validate_config(value), value)
        for key, invalid in (("schema", True), ("port", 3443), ("stats_port", 18888),
                             ("workers", 1), ("workers", False), ("server", "127.0.0.1"),
                             ("domain", "unowned.example"), ("security_patch", "systemd-secret-file-v2"),
                             ("patch_sha256", "a" * 64), ("base_module_sha256", "b" * 64),
                             ("protocol_sha256", "bad"), ("created_at", True)):
            altered = copy.deepcopy(value); altered[key] = invalid
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                tls._validate_config(altered)

    def test_get_status_never_probes_or_reads_client_secret(self):
        with patch.object(tls, "_config", return_value=config()), \
                patch.object(tls, "_verify_runtime"), patch.object(tls, "_service_state", return_value="active"), \
                patch.object(tls, "_stats", return_value={"total_ready_targets": 24}), \
                patch.object(tls, "_secret") as secret, patch.object(tls.protocol, "probe") as probe:
            status = tls.snapshot()
        secret.assert_not_called(); probe.assert_not_called()
        self.assertTrue(status["installed"]); self.assertTrue(status["upstream_ready"])
        self.assertNotIn(SECRET, json.dumps(status))

    def test_missing_install_is_not_claimed_ready(self):
        with patch.object(tls, "_config", side_effect=FileNotFoundError), \
                patch.object(tls, "_service_state", return_value="unknown"):
            self.assertFalse(tls.snapshot()["installed"])

    def test_owner_links_require_genuine_nonce_and_active_service(self):
        with patch.object(tls, "_config", return_value=config()), patch.object(tls, "_verify_runtime"), \
                patch.object(tls, "_secret", return_value=SECRET), patch.object(tls, "_service_state", return_value="active"), \
                patch.object(tls, "health_probe", return_value={"ok": True}) as probe:
            value = tls.owner_connection_links()
        probe.assert_called_once()
        parsed = parse_qs(urlsplit(value["telegram"]).query)
        self.assertEqual(parsed["secret"], ["ee" + SECRET + tls.DOMAIN.encode().hex()])
        self.assertEqual(parsed["port"], ["5443"])
        self.assertEqual(links.validated_links(value, kind="tls"), value)
        with patch.object(tls, "_config", return_value=config()), patch.object(tls, "_verify_runtime"), \
                patch.object(tls, "_service_state", return_value="inactive"), \
                patch.object(tls, "health_probe") as probe, self.assertRaises(RuntimeError):
            tls.owner_connection_links()
        probe.assert_not_called()
        with patch.object(tls, "_config", return_value=config()), patch.object(tls, "_verify_runtime"), \
                patch.object(tls, "_service_state", return_value="active"), \
                patch.object(tls, "health_probe", return_value={"ok": False}), self.assertRaises(RuntimeError):
            tls.owner_connection_links()

    def test_control_cannot_address_old_or_arbitrary_services(self):
        for action in ("exec", "rospanel", "3443", "web_restart", "restart; reboot"):
            with self.assertRaises(ValueError): tls.control(action)
        with patch.object(tls, "_config", return_value=config()), patch.object(tls, "_verify_runtime"), \
                patch.object(tls, "snapshot", return_value={}), \
                patch.object(tls.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertTrue(tls.control("restart")["ok"])
        self.assertEqual(run.call_args.args[0], ["systemctl", "restart", "quantumvpn-mtproto-tls.service"])

    def test_credential_launcher_is_tls_only_no_secret_argv(self):
        credentials = "/run/credentials/quantumvpn-mtproto-tls.service"
        def read(path, maximum, **kwargs):
            if path.name == "runtime-config": return json.dumps(config()).encode()
            if path.name == "client-secret": return (SECRET + "\n").encode()
            raise AssertionError("unexpected_read")
        with patch.dict(tls.os.environ, {"CREDENTIALS_DIRECTORY": credentials}), \
                patch.object(tls, "Path", PurePosixPath), patch.object(tls.os, "geteuid", return_value=123, create=True), \
                patch.object(tls.base, "_read_bytes", side_effect=read), patch.object(tls, "_verify_runtime"), \
                patch.object(tls.os, "execv") as execute:
            tls.serve()
        argv = execute.call_args.args[1]
        self.assertIn("--secret-file", argv); self.assertNotIn("-S", argv)
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertEqual(argv[argv.index("-D") + 1], tls.DOMAIN)
        self.assertEqual(argv[argv.index("-M") + 1], "0")
        self.assertEqual(argv[argv.index("-H") + 1], "5443")
        for invalid in ("", "relative", "/tmp/credentials", "/run/credentials/quantumvpn-mtproto.service"):
            with patch.dict(tls.os.environ, {"CREDENTIALS_DIRECTORY": invalid}), self.assertRaises(RuntimeError):
                tls.serve()

    def test_tls_link_validation_is_transport_specific_and_fixed(self):
        query = "server=150.241.96.191&port=5443&secret=ee" + SECRET + tls.DOMAIN.encode().hex()
        value = {"telegram": "tg://proxy?" + query, "https": "https://t.me/proxy?" + query}
        fragment = links.render_links(value, kind="tls")
        self.assertIn("proxy-tls-telegram-link", fragment)
        self.assertIn("MTProto TLS", fragment)
        for kind in ("mtproto", "web"):
            with self.assertRaisesRegex(ValueError, "^invalid_proxy_links$"): links.validated_links(value, kind=kind)
        for changed in (query.replace("5443", "3443"), query.replace("150.241.96.191", "1.1.1.1"),
                        query[:-2], query.replace("ee" + SECRET, "dd" + SECRET),
                        query + "&secret=duplicate"):
            invalid = {"telegram": "tg://proxy?" + changed, "https": "https://t.me/proxy?" + changed}
            with self.assertRaisesRegex(ValueError, "^invalid_proxy_links$"):
                links.validated_links(invalid, kind="tls")


if __name__ == "__main__":
    unittest.main()
