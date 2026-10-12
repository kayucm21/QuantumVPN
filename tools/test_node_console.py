"""Offline guards for measured node evidence and its report rendering."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import quantumvpn_node_console as node


class NodeConsoleTests(unittest.TestCase):
    def config(self, **values):
        return {"protocol": "vless", "port": 12087, "listen": "0.0.0.0",
                "streamSettings": {"network": "xhttp", "security": "reality"}, **values}

    def test_private_config_fields_are_excluded_and_only_typed_ports_survive(self):
        secret = "PRIVATE-CLIENT-UUID-PASSWORD"
        config = {"inbounds": [self.config(settings={"clients": [{"id": secret}]}, tag=secret),
                               self.config(port="443"), self.config(port=True), self.config(port=65536),
                               self.config(protocol=["vless"]), self.config(protocol="invented"),
                               self.config(port=8443, protocol="hysteria", streamSettings={"network": "hysteria", "security": "tls"})]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            result = node.configured_ports(path)
        self.assertTrue(result["available"])
        self.assertEqual([row["port"] for row in result["ports"]], [12087, 8443])
        self.assertTrue(result["ports"][0]["tcp_expected"])
        self.assertFalse(result["ports"][1]["tcp_expected"])
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn("clients", json.dumps(result))

    def test_missing_corrupt_oversized_config_remains_unknown(self):
        with mock.patch.object(node, "_read", return_value=""):
            self.assertFalse(node.configured_ports()["available"])
        for config in ([], {"inbounds": "wrong"}, None):
            with mock.patch.object(node, "_read", return_value=json.dumps(config)):
                self.assertFalse(node.configured_ports()["available"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large"
            path.write_bytes(b"x" * 129)
            self.assertEqual(node._read(path, 128), "")

    def test_port_inventory_is_bounded_and_bind_addresses_are_not_returned(self):
        config = {"inbounds": [self.config(port=20000 + i, listen="150.241.96.191") for i in range(60)]}
        with mock.patch.object(node, "_read", return_value=json.dumps(config)):
            result = node.configured_ports()
        self.assertEqual(len(result["ports"]), node.MAX_PORTS)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["ports"][0]["probe_allowed"])
        self.assertNotIn("150.241.96.191", json.dumps(result))

    def test_listeners_strip_peer_addresses_and_distinguish_udp_and_tcp(self):
        listeners = node.listening_ports("tcp LISTEN 0 4096 127.0.0.1:12087 0.0.0.0:*\n"
                                        "tcp LISTEN 0 4096 [::]:12087 [::]:*\n"
                                        "udp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*\n"
                                        "tcp LISTEN 0 4096 [::1]:9443 [::]:*\n")
        self.assertEqual(len(listeners), 3)
        self.assertTrue(next(row for row in listeners if row["port"] == 12087)["network_listener"])
        self.assertFalse(next(row for row in listeners if row["port"] == 9443)["network_listener"])
        self.assertEqual(next(row for row in listeners if row["port"] == 8443)["network"], "udp")
        self.assertNotIn("127.0.0.1", json.dumps(listeners))

    def test_traffic_rate_is_a_delta_and_counter_reset_or_missing_sample_is_unknown(self):
        before = {"rx_bytes": 100, "tx_bytes": 200, "interfaces": 1}
        after = {"rx_bytes": 12500100, "tx_bytes": 25000200, "interfaces": 1}
        self.assertEqual(node.traffic_rate(before, after, 1), {"rx_mbps": 100.0, "tx_mbps": 200.0})
        for previous, current, elapsed in ((None, after, 1), (before, None, 1), (before, after, .1),
                                           (before, after, 121), (before, {**after, "interfaces": 2}, 1)):
            self.assertIsNone(node.traffic_rate(previous, current, elapsed)["rx_mbps"])
        self.assertIsNone(node.traffic_rate(after, before, 1)["rx_mbps"])
        counts = node.traffic_counters("lo: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"
                                       "eth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0")
        self.assertEqual(counts, {"rx_bytes": 10, "tx_bytes": 20, "interfaces": 1})

    def test_rate_caps_use_known_json_units_and_never_copy_shell_text(self):
        result = node.qdisc_summary(json.dumps([{"kind": "htb", "options": {"rate": 12500000, "ceil": 25000000}, "dev": "secret-interface"},
                                               {"kind": ["fq"]}, {"kind": "shell attack", "options": {"rate": "run command"}}]))
        self.assertEqual(result["rate_caps_bps"], [200000000])
        self.assertEqual(result["kinds"], ["htb"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertFalse(node.qdisc_summary("")["available"])
        self.assertFalse(result["available"])
        self.assertEqual(node.qdisc_summary('[{"kind":"tbf","options":{"rate":12500000}}]')["rate_caps_bps"], [100000000])
        self.assertFalse(node.qdisc_summary('[{"kind":"hfsc"}]')["available"])

    def fixture_snapshot(self, *, probe=False):
        configured = {"available": True, "truncated": False, "ports": [
            {"protocol": "vless", "port": 12087, "transport": "xhttp", "security": "reality", "scope": "network",
             "probe_host": "127.0.0.1", "probe_allowed": True, "tcp_expected": True},
            {"protocol": "hysteria", "port": 8443, "transport": "hysteria", "security": "tls", "scope": "network",
             "probe_host": "127.0.0.1", "probe_allowed": True, "tcp_expected": False}]}
        reads = {"/proc/meminfo": "MemTotal: 1000 kB\nMemAvailable: 500 kB\n", "/proc/loadavg": "0.5 0.5 0.5 1/100 1",
                 "/proc/net/dev": "eth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0", "/proc/sys/net/ipv4/tcp_congestion_control": "bbr"}
        commands = {("ss", "-H", "-lntu"): "tcp LISTEN 0 4096 0.0.0.0:12087 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*",
                    ("tc", "-j", "qdisc", "show"): '[{"kind":"fq"}]', ("tc", "-j", "class", "show"): '[]'}
        with mock.patch.object(node, "configured_ports", side_effect=[copy.deepcopy(configured), {"available": False, "truncated": False, "ports": []}]), \
                mock.patch.object(node, "_read", side_effect=lambda path, *args: reads.get(path, "")), \
                mock.patch.object(node, "_command", side_effect=lambda argv: commands.get(tuple(argv), "")), \
                mock.patch.dict(os.environ, {"QV_NODE_PUBLIC_ADDRESS": "150.241.96.191"}):
            return node.snapshot(probe=probe)

    def test_probe_targets_only_registered_loopback_tcp_and_never_udp(self):
        connection = mock.MagicMock()
        with mock.patch.object(node.socket, "create_connection", return_value=connection) as connect:
            result = self.fixture_snapshot(probe=True)
        connect.assert_called_once_with(("127.0.0.1", 12087), timeout=.15)
        self.assertTrue(result["ports"][0]["loopback_probe"])
        self.assertIsNone(result["ports"][1]["loopback_probe"])
        self.assertEqual(result["diagnostic"]["external_reachability"], "not_measured")
        self.assertFalse(result["traffic"]["vpn_throughput_measured"])

    def test_unknown_sources_do_not_imply_zero_load_or_healthy_protocols(self):
        with mock.patch.object(node, "_read", return_value=""), mock.patch.object(node, "_command", return_value=""):
            result = node.snapshot()
        self.assertIsNone(result["resources"]["load_1m_pct"])
        self.assertIsNone(result["resources"]["memory_used_pct"])
        self.assertIsNone(result["listener_count"])
        self.assertFalse(result["config_available"])
        self.assertIn("xray_config_unavailable", result["diagnostic"]["findings"])

    def test_html_escapes_embedded_json_and_real_controls_use_authenticated_routes(self):
        result = self.fixture_snapshot()
        result["public_address"] = "</script><script>alert(1)</script>"
        rendered = node.render(result, csrf="a" * 64, embedded=True)
        self.assertNotIn(result["public_address"], rendered)
        self.assertIn('href="/operator?tab=service"', rendered)
        self.assertIn('href="/operator?tab=network"', rendered)
        self.assertIn("/diagnostics", rendered)
        self.assertIn("URL.createObjectURL", rendered)
        viewer = node.render(result, embedded=True, can_probe=False)
        self.assertNotIn('<button id=node-diagnose>', viewer)


if __name__ == "__main__":
    unittest.main()
