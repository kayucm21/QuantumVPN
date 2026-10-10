"""Offline checks for bounded VLESS regression and owned process cleanup."""
import io
import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import quantumvpn_safehop_vless_probe as probe


IDENTIFIER = "00000000-0000-4000-8000-000000000001"


class SafehopVlessProbeTests(unittest.TestCase):
    def server(self):
        return {"inbounds": [{"protocol": "vless", "port": 18443, "listen": "127.0.0.1",
            "streamSettings": {"security": "tls", "network": "tcp"},
            "settings": {"clients": [{"id": IDENTIFIER, "flow": "xtls-rprx-vision"}]}}]}

    def test_client_is_tls_verified_single_vision_user_and_loopback_socks(self):
        config = probe.client_config(IDENTIFIER, "legacy.example.org")
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertFalse(config["inbounds"][0]["settings"]["udp"])
        self.assertEqual(config["log"]["loglevel"], "none")
        endpoint = config["outbounds"][0]
        self.assertFalse(endpoint["streamSettings"]["tlsSettings"]["allowInsecure"])
        self.assertEqual(endpoint["settings"]["vnext"][0]["address"], probe.PUBLIC_IPV4)
        self.assertEqual(endpoint["settings"]["vnext"][0]["port"], 443)
        self.assertEqual(endpoint["settings"]["vnext"][0]["users"], [{"id": IDENTIFIER, "encryption": "none", "flow": "xtls-rprx-vision"}])
        self.assertEqual(probe.vision_client(self.server()), IDENTIFIER)
        for name in ("safehop.crabdance.com", "legacy.example.org\n", "../private", "", "localhost"):
            with self.subTest(name=name), self.assertRaises(probe.ProbeError):
                probe.client_config(IDENTIFIER, name)

    def test_client_selection_does_not_use_other_protocols_or_users(self):
        for field, value in (("listen", "0.0.0.0"), ("port", 443), ("protocol", "trojan")):
            server = self.server()
            server["inbounds"][0][field] = value
            with self.assertRaises(probe.ProbeError):
                probe.vision_client(server)
        server = self.server()
        server["inbounds"][0]["settings"]["clients"][0]["flow"] = ""
        with self.assertRaises(probe.ProbeError):
            probe.vision_client(server)

    def test_stop_only_owned_process_and_escalate_if_needed(self):
        process = MagicMock()
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = [subprocess.TimeoutExpired("owned", 3), 0]
        self.assertTrue(probe._stop_owned(process))
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()

    def test_curl_body_limit_stops_owned_process(self):
        process = MagicMock()
        process.stdout = io.BytesIO(b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * (probe.BODY_LIMIT + 1))
        process.poll.side_effect = [None, 0]
        with patch.object(probe.subprocess, "Popen", return_value=process) as start:
            with self.assertRaisesRegex(probe.ProbeError, "body_too_large"):
                probe._curl_probe({"PATH": "/usr/bin:/bin"})
        process.terminate.assert_called_once_with()
        args = start.call_args.args[0]
        self.assertEqual(args[-1], "https://example.com/")
        self.assertEqual(args[1], "--disable")
        self.assertNotIn("-k", args)
        self.assertNotIn("--insecure", args)
        self.assertNotIn("--location", args)

    def test_probe_config_uses_stdin_and_always_stops_client(self):
        source = json.dumps(self.server()).encode()
        process = MagicMock()
        process.poll.side_effect = [None, 0]
        with patch.object(probe, "_protected_read", return_value=source), \
             patch.object(probe.subprocess, "run", return_value=MagicMock(returncode=0)) as validate, \
             patch.object(probe.socket, "socket") as reserve, \
             patch.object(probe.subprocess, "Popen", return_value=process) as start, \
             patch.object(probe, "_wait_listener"), \
             patch.object(probe, "_curl_probe", side_effect=probe.ProbeError("fixed_failure")):
            with self.assertRaisesRegex(probe.ProbeError, "fixed_failure"):
                probe.probe(server_name="legacy.example.org")
        self.assertIn("stdin:", validate.call_args.args[0])
        self.assertIn("stdin:", start.call_args.args[0])
        self.assertNotIn(IDENTIFIER, " ".join(start.call_args.args[0]))
        process.stdin.close.assert_called_once_with()
        process.terminate.assert_called_once_with()
        reserve.return_value.__enter__.return_value.bind.assert_called_once_with(("127.0.0.1", probe.SOCKS_PORT))


if __name__ == "__main__":
    unittest.main()
