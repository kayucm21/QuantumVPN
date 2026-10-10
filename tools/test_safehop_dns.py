"""Safety properties of the generated Safehop DNS deployment data."""
import ast
from pathlib import Path, PurePosixPath
import re
import unittest

import quantumvpn_safehop_dns as dns


class SafehopConfigTests(unittest.TestCase):
    def test_generator_has_no_io_or_command_execution(self):
        tree = ast.parse(Path(dns.__file__).read_text(encoding="utf-8"))
        imported = {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
        self.assertEqual(imported, {"ipaddress"})
        calls = [node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertTrue(set(calls).isdisjoint({"open", "exec", "eval", "compile", "__import__"}))
        files = dns.generated_files()
        self.assertEqual(len(files), 4)
        for path, content in files.items():
            self.assertTrue(PurePosixPath(path).is_absolute())
            self.assertTrue(content.endswith("\n"))

    def test_no_ipv6_without_explicit_verified_global_assignment(self):
        for value in ("::", "::1", "fe80::1", "fe80::1%eth0", "fd00::1", "ff02::1",
                      "::ffff:150.241.96.191", "2001:db8::1", "150.241.96.191",
                      "2001:4860:4860::8888/64", "not-an-address", "", 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dns.generated_files(value, public_ipv6_verified=True)
        with self.assertRaises(ValueError):
            dns.generated_files("2001:4860:4860::8888")
        with self.assertRaises(ValueError):
            dns.generated_files(public_ipv6_verified=True)
        with self.assertRaises(ValueError):
            dns.generated_files(public_ipv6_verified=1)
        self.assertIsNone(dns.verified_ipv6())

    def test_public_listeners_have_exact_host_bindings(self):
        config = dns.dnsdist_config()
        bindings = re.findall(r'^(?:setLocal|addLocal|addTLSLocal|addDOHLocal)\("([^"]+)"',
                              config, re.MULTILINE)
        self.assertEqual(bindings, [dns.PUBLIC_IPV4 + ":53", dns.PUBLIC_IPV4 + ":853",
                                    "127.0.0.1:18554"])
        self.assertNotIn('setLocal("0.0.0.0', config)
        self.assertNotIn('addLocal("[::]', config)
        self.assertNotIn("AF_INET6", dns.dnsdist_service())
        self.assertIn("do-ip6: no", dns.unbound_config())

    def test_verified_ipv6_adds_only_that_exact_address(self):
        address = "2001:4860:4860:0000:0000:0000:0000:8888"
        config = dns.dnsdist_config(address, public_ipv6_verified=True)
        self.assertIn('addLocal("[2001:4860:4860::8888]:53"', config)
        self.assertIn('addTLSLocal("[2001:4860:4860::8888]:853"', config)
        self.assertNotIn('addDOHLocal("[', config)
        self.assertIn("do-ip6: yes", dns.unbound_config(address, public_ipv6_verified=True))
        self.assertIn("AF_INET6", dns.dnsdist_service(address, public_ipv6_verified=True))

    def test_recursive_backend_is_loopback_only_and_dnssec_validating(self):
        config = dns.unbound_config()
        interfaces = re.findall(r"^    interface: (.+)$", config, re.MULTILINE)
        self.assertEqual(interfaces, ["127.0.0.1@18553"])
        for setting in ('module-config: "validator iterator"', 'auto-trust-anchor-file: "' + dns.ROOT_KEY + '"',
                        "access-control: 127.0.0.1/32 allow", "access-control: 0.0.0.0/0 refuse",
                        "control-enable: no", "val-permissive-mode: no", "ignore-cd-flag: yes"):
            self.assertIn(setting, config)
        for override in ("forward-zone:", "forward-addr:", "stub-zone:", "local-data:", "private-domain:"):
            self.assertNotIn(override, config)

    def test_cache_memory_and_rebinding_limits(self):
        config = dns.unbound_config()
        self.assertIn("msg-cache-size: 64m", config)
        self.assertIn("rrset-cache-size: 128m", config)
        for subnet in ("10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                       "172.16.0.0/12", "192.168.0.0/16", "::1/128", "::ffff:0:0/96",
                       "fc00::/7", "fe80::/10"):
            self.assertIn("private-address: " + subnet, config)
        self.assertIn("max-udp-size: 1232", config)
        self.assertIn("minimal-responses: yes", config)

    def test_global_rate_limit_precedes_per_client_state_allocation(self):
        config = dns.dnsdist_config()
        global_rule = "addAction(NotRule(MaxQPSRule(500)), DropAction())"
        client_rule = "addAction(MaxQPSIPRule(100, 32, 64, 150, 60, 30, 1, 4), DropAction())"
        self.assertIn(global_rule, config)
        self.assertIn(client_rule, config)
        self.assertLess(config.index(global_rule), config.index(client_rule))
        self.assertIn("setMaxUDPOutstanding(512)", config)
        self.assertIn("setMaxTCPConnectionsPerClient(8)", config)
        self.assertIn("maxConcurrentTCPConnections=128", config)

    def test_forbidden_query_types_apply_on_every_transport(self):
        config = dns.dnsdist_config()
        policy = next(line for line in config.splitlines() if "QTypeRule(DNSQType.ANY)" in line)
        for qtype in ("ANY", "AXFR", "IXFR"):
            self.assertIn("QTypeRule(DNSQType." + qtype + ")", policy)
        self.assertIn("RCodeAction(DNSRCode.REFUSED)", policy)
        self.assertNotIn("TCPRule", policy)
        self.assertNotIn("IncomingProtocolRule", policy)

    def test_internal_doh_and_tls_contract(self):
        config = dns.dnsdist_config()
        self.assertIn('addDOHLocal("127.0.0.1:18554", nil, nil, {"/dns-query"}', config)
        self.assertIn("trustForwardedForHeader=true", config)
        self.assertIn("exactPathMatching=true", config)
        self.assertIn('provider="openssl", minTLSVersion="tls1.2"', config)
        self.assertIn(dns.FULLCHAIN, config)
        self.assertIn(dns.PRIVATE_KEY, config)
        self.assertNotIn("tls=false", config)

    def test_no_query_logs_ring_history_or_management_sockets(self):
        unbound = dns.unbound_config()
        for setting in ("verbosity: 0", "log-queries: no", "log-replies: no", "log-servfail: no",
                        "log-local-actions: no", "statistics-interval: 0", "extended-statistics: no"):
            self.assertIn(setting, unbound)
        frontend = dns.dnsdist_config()
        self.assertIn("setRingBuffersOptions({recordQueries=false, recordResponses=false})", frontend)
        for directive in ("controlSocket(", "webserver(", "LogAction(", "DnstapLogAction(",
                          "RemoteLogAction(", "newPacketCache(", "includeDirectory("):
            self.assertNotIn(directive, frontend)

    def test_services_use_distinct_users_and_minimum_capabilities(self):
        resolver = dns.unbound_service()
        frontend = dns.dnsdist_service()
        self.assertNotEqual(dns.UNBOUND_USER, dns.DNSDIST_USER)
        self.assertIn("User=" + dns.UNBOUND_USER, resolver)
        self.assertIn("User=" + dns.DNSDIST_USER, frontend)
        self.assertIn("CapabilityBoundingSet=\n", resolver)
        self.assertIn("AmbientCapabilities=\n", resolver)
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", frontend)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE\n", frontend)
        self.assertIn("Requires=" + dns.UNBOUND_SERVICE, frontend)
        self.assertNotIn("MemoryDenyWriteExecute=true", frontend)
        for config in (resolver, frontend):
            for setting in ("NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true",
                            "PrivateTmp=true", "PrivateDevices=true", "UMask=0077",
                            "CacheDirectoryMode=0700", "TasksMax=32", "LimitCORE=0",
                            "LimitNOFILE=4096", "CPUQuota=150%", "MemoryMax="):
                self.assertIn(setting, config)


if __name__ == "__main__":
    unittest.main()
