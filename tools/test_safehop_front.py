"""Policy and ownership checks for pure Safehop HTTPS deployment data."""
import ast
import copy
import json
from pathlib import Path, PurePosixPath
import re
import unittest

import quantumvpn_safehop_front as front


class SafehopFrontTests(unittest.TestCase):
    def test_generator_is_pure(self):
        tree = ast.parse(Path(front.__file__).read_text(encoding="utf-8"))
        imports = {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
        self.assertEqual(imports, {"hashlib", "json"})
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({"open", "exec", "eval", "compile", "__import__"}))
        for mode in (False, True):
            files = front.generated_files(bootstrap=mode)
            self.assertEqual(len(files), 3)
            for path, content in files.items():
                self.assertTrue(PurePosixPath(path).is_absolute())
                self.assertTrue(content.endswith("\n"))
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                front.generated_files(bootstrap=value)

    def test_tls_passthrough_and_proxy_v1_contract(self):
        config = front.nginx_config()
        self.assertIn("load_module " + front.STREAM_MODULE + ";", config)
        stream = config.split("stream {", 1)[1].split("http {", 1)[0]
        self.assertIn("map $ssl_preread_server_name $safehop_tls_upstream", stream)
        self.assertIn(front.DOMAIN + " 127.0.0.1:18555;", stream)
        self.assertIn("default 127.0.0.1:18443;", stream)
        self.assertIn("listen " + front.PUBLIC_IPV4 + ":18556;", stream)
        self.assertIn("ssl_preread on;", stream)
        self.assertIn("proxy_protocol on;", stream)
        self.assertIn("proxy_timeout 24h;", stream)
        self.assertIn("limit_conn safehop_tls_connections 1500;", stream)
        self.assertNotIn("listen " + front.PUBLIC_IPV4 + ":18556 proxy_protocol", stream)
        self.assertNotIn("ssl_certificate", stream)
        self.assertNotIn("proxy_ssl on", stream)
        self.assertNotIn("resolver ", config)

    def test_exact_bindings_and_trusted_client_address(self):
        config = front.nginx_config()
        listens = re.findall(r"^\s*listen (.+);$", config, re.MULTILINE)
        self.assertEqual(listens, [front.PUBLIC_IPV4 + ":18556", front.PUBLIC_IPV4 + ":18557 default_server",
                                  front.PUBLIC_IPV4 + ":18557", "127.0.0.1:18555 ssl http2 proxy_protocol default_server"])
        self.assertIn("set_real_ip_from 127.0.0.1;", config)
        self.assertIn("real_ip_header proxy_protocol;", config)
        self.assertNotIn("set_real_ip_from 0.0.0.0", config)
        self.assertNotIn("listen " + front.PUBLIC_IPV4 + ":18555", config)
        self.assertNotIn("listen 0.0.0.0:18555", config)
        self.assertNotIn("$proxy_add_x_forwarded_for", config)
        self.assertNotIn("http2 on;", config)
        doh = config.split("listen 127.0.0.1:18555", 1)[1]
        self.assertIn("grpc_set_header X-Forwarded-For $remote_addr;", doh)
        for name in ("X-Real-IP", "Forwarded", "X-Forwarded-Host"):
            self.assertIn("grpc_set_header " + name + ' "";', doh)
        self.assertIn("grpc_pass grpc://127.0.0.1:18554;", doh)

    def test_doh_uses_http2_upstream_and_suppresses_client_credentials(self):
        doh = front.nginx_config().split("listen 127.0.0.1:18555", 1)[1]
        self.assertIn("grpc_pass grpc://127.0.0.1:18554;", doh)
        self.assertNotRegex(doh, r"(?m)^\s*proxy_\w+")
        self.assertNotIn("grpc_pass_request_headers", doh)
        self.assertIn("grpc_set_header Host " + front.DOMAIN + ";", doh)
        self.assertIn("grpc_set_header Content-Type application/dns-message;", doh)
        self.assertIn("grpc_set_header Accept application/dns-message;", doh)
        self.assertIn("grpc_set_header Content-Length $content_length;", doh)
        replacements = dict(re.findall(r"^\s*grpc_set_header ([^ ]+) ([^;]+);$", doh, re.MULTILINE))
        self.assertEqual(replacements["X-Forwarded-For"], "$remote_addr")
        self.assertEqual(replacements["X-Forwarded-Proto"], "https")
        self.assertEqual(replacements["X-Forwarded-Port"], "443")
        for header in ("Cookie", "Authorization", "Proxy-Authorization", "Forwarded",
                       "X-Real-IP", "X-Forwarded-Host", "CF-Connecting-IP", "True-Client-IP",
                       "User-Agent", "Referer", "Origin", "Traceparent", "Tracestate", "Baggage",
                       "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Upgrade", "Expect"):
            with self.subTest(header=header):
                self.assertEqual(replacements[header], '""')
        for setting in ("grpc_connect_timeout 3s;", "grpc_read_timeout 10s;",
                        "grpc_send_timeout 10s;", "grpc_buffer_size 8k;",
                        "grpc_next_upstream off;", "grpc_hide_header Set-Cookie;",
                        "grpc_ignore_headers X-Accel-Redirect X-Accel-Charset;"):
            self.assertIn(setting, doh)
        for guard in ("host", "method", "request", "type", "length", "encoding"):
            self.assertIn("if ($safehop_doh_" + guard + " = 0)", doh)
        self.assertIn("client_max_body_size 4096;", doh)

    def test_optional_loopback_probe_exercises_the_same_sni_proxy(self):
        default = front.nginx_config()
        self.assertNotIn("listen 127.0.0.1:18556;", default)
        probe = front.nginx_config(loopback_probe=True)
        self.assertIn("listen 127.0.0.1:18556;", probe)
        self.assertEqual(probe.replace("        listen 127.0.0.1:18556;\n", ""), default)
        self.assertNotIn("listen 127.0.0.1:18556 proxy_protocol", probe)
        self.assertEqual(front.generated_files(loopback_probe=True)[front.NGINX_CONFIG], probe)
        with self.assertRaises(ValueError):
            front.generated_files(bootstrap=True, loopback_probe=True)
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                front.nginx_config(loopback_probe=value)

    def test_raw_doh_uri_regex_rejects_aliases_and_non_wire_queries(self):
        query = "A" * 16
        self.assertRegex("GET:/dns-query?dns=" + query, front.GET_REQUEST_PATTERN)
        for length in (16, 18, 19, 20, 2046, 2047, 2048):
            self.assertRegex("GET:/dns-query?dns=" + "A" * length, front.GET_REQUEST_PATTERN)
        invalid = [
            "GET:/dns-query", "HEAD:/dns-query?dns=" + query,
            "GET:/dns-query/?dns=" + query, "GET:/%64ns-query?dns=" + query,
            "GET://dns-query?dns=" + query, "GET:/a/../dns-query?dns=" + query,
            "GET:/dns-query?dns=" + query + "&x=1", "GET:/dns-query?x=1&dns=" + query,
            "GET:/dns-query?dns=" + query + "&dns=" + query, "GET:/dns-query?DNS=" + query,
            "GET:/dns-query?dns=" + query + "=", "GET:/dns-query?dns=" + "A" * 17,
            "GET:/dns-query?dns=" + "A" * 15, "GET:/dns-query?dns=" + "A" * 2049,
            "GET:/dns-query?dns=" + query + "%00", "GET:/dns-query?dns=" + "A+" * 8,
        ]
        for uri in invalid:
            with self.subTest(uri=uri[:100]):
                self.assertIsNone(re.fullmatch(front.GET_REQUEST_PATTERN, uri))
        config = front.nginx_config()
        self.assertIn('map "$request_method:$request_uri" $safehop_doh_request', config)
        self.assertIn('"POST:/dns-query" 1;', config)
        self.assertIn("location = /dns-query", config)
        for guard in ("host", "method", "request", "type", "length", "encoding"):
            self.assertIn("if ($safehop_doh_" + guard + " = 0)", config)

    def test_doh_body_query_and_resource_limits(self):
        config = front.nginx_config()
        self.assertIn("client_max_body_size 4096;", config)
        self.assertIn('"~*^POST:application/dns-message$" 1;', config)
        for size in (12, 19, 20, 99, 100, 999, 1000, 3999, 4000, 4089, 4090, 4096):
            self.assertRegex("POST:" + str(size), front.POST_LENGTH_PATTERN)
        for size in (0, 1, 11, 4097, 9999, 10000):
            self.assertIsNone(re.fullmatch(front.POST_LENGTH_PATTERN, "POST:" + str(size)))
        for setting in ("rate=100r/s", "rate=500r/s", "grpc_buffer_size 8k;",
                        "grpc_next_upstream off;",
                        "client_body_timeout 10s;", "limit_conn safehop_http_connections 8;"):
            self.assertIn(setting, config)

    def test_acme_has_only_canonical_tokens_and_http_fallback_is_local(self):
        self.assertRegex("GET:/.well-known/acme-challenge/" + "A" * 22, front.ACME_REQUEST_PATTERN)
        self.assertRegex("HEAD:/.well-known/acme-challenge/" + "A" * 128, front.ACME_REQUEST_PATTERN)
        for value in ("A" * 21, "A" * 129, "A" * 22 + "?x=1", "A" * 22 + "/x",
                      "../" + "A" * 22, "%41" * 22):
            self.assertIsNone(re.fullmatch(front.ACME_REQUEST_PATTERN, "GET:/.well-known/acme-challenge/" + value))
        config = front.nginx_config()
        http = config.split("server_name _;", 1)[1].split("listen 127.0.0.1:18555", 1)[0]
        self.assertIn("proxy_pass http://127.0.0.1:80;", http)
        self.assertIn("proxy_set_header Host $http_host;", http)
        self.assertIn("root " + front.ACME_WEBROOT + ";", http)
        self.assertIn("disable_symlinks on;", http)
        self.assertIn("if ($safehop_http_host = 0) { return 404; }", http)
        self.assertIn("if ($safehop_acme_request = 0) { return 404; }", http)
        safehop = http.split("server_name " + front.DOMAIN + ";", 1)[1]
        self.assertNotIn("proxy_pass", safehop)
        self.assertIn("location / { return 404; }", safehop)

    def test_bootstrap_has_no_tls_or_certificate_dependency(self):
        config = front.bootstrap_config()
        for value in ("ssl_certificate", "ssl_preread", "stream {", front.PRIVATE_KEY,
                      "18555", "18556", front.STREAM_MODULE):
            self.assertNotIn(value, config)
        rules = front.nftables_rules(bootstrap=True)
        self.assertIn("tcp dport 80 dnat ip to " + front.PUBLIC_IPV4 + ":18557", rules)
        self.assertNotIn("tcp dport 443 dnat", rules)
        self.assertNotIn("allow-dnat-https", rules)

    def test_no_query_or_hostname_logs_or_root_privileges(self):
        config = front.nginx_config()
        self.assertIn("error_log /dev/null crit;", config)
        self.assertIn("access_log off;", config)
        self.assertIn("server_tokens off;", config)
        self.assertNotRegex(config, r"(?m)^\s*user\s")
        self.assertNotIn("include ", config)
        service = front.front_service()
        self.assertIn("User=" + front.FRONT_USER, service)
        self.assertIn("Group=" + front.FRONT_GROUP, service)
        self.assertIn("CapabilityBoundingSet=\n", service)
        self.assertIn("AmbientCapabilities=\n", service)
        self.assertNotIn("CAP_", service)
        self.assertIn("RuntimeDirectory=" + front.FRONT_USER, service)
        self.assertIn("CacheDirectory=" + front.FRONT_USER, service)
        self.assertIn("-p " + front.PREFIX + "/ -c " + front.NGINX_CONFIG, service)

    def test_nft_is_owned_and_rejects_direct_high_ports(self):
        rules = front.nftables_rules()
        self.assertIn("table inet " + front.NFT_TABLE, rules)
        self.assertNotIn("flush ", rules)
        self.assertNotIn("delete ", rules)
        self.assertIn("type nat hook output priority dstnat", rules)
        self.assertIn("type nat hook prerouting priority dstnat", rules)
        self.assertIn("ip daddr " + front.PUBLIC_IPV4 + " tcp dport 80 dnat ip to " + front.PUBLIC_IPV4 + ":18557", rules)
        self.assertIn("ip daddr " + front.PUBLIC_IPV4 + " tcp dport 443 dnat ip to " + front.PUBLIC_IPV4 + ":18556", rules)
        for auxiliary, original in ((18556, 443), (18557, 80)):
            self.assertIn("ip daddr " + front.PUBLIC_IPV4 + " tcp dport " + str(auxiliary)
                          + " ct status dnat ct original ip daddr " + front.PUBLIC_IPV4
                          + " ct original proto-dst " + str(original) + " accept", rules)
        self.assertNotIn("ct status dnat accept", rules)
        self.assertIn("tcp dport { 18554, 18555 } reject with tcp reset", rules)
        self.assertIn("reject with tcp reset", rules)
        self.assertLess(rules.index("allow-dnat-https"), rules.index("reject with tcp reset"))

    def test_output_dnat_only_matches_exact_own_http_https_endpoints(self):
        for mode in (False, True):
            data = front.nft_table_data(bootstrap=mode)
            output_chain = next(record["chain"] for record in data["nftables"]
                                if "chain" in record and record["chain"]["name"] == "output")
            self.assertEqual((output_chain["type"], output_chain["hook"], output_chain["prio"]), ("nat", "output", -100))
            output_rules = [record["rule"] for record in data["nftables"]
                            if "rule" in record and record["rule"]["chain"] == "output"]
            expected = [(80, 18557)] if mode else [(80, 18557), (443, 18556)]
            self.assertEqual(len(output_rules), len(expected))
            for rule, (source, target) in zip(output_rules, expected):
                self.assertEqual(rule["expr"], [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": front.PUBLIC_IPV4}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": source}},
                    {"dnat": {"addr": front.PUBLIC_IPV4, "family": "ip", "port": target}},
                ])
                for index, unsafe_value in ((0, "0.0.0.0/0"), (1, {"set": [80, 443, 853]})):
                    changed = copy.deepcopy(data)
                    changed_rule = next(record["rule"] for record in changed["nftables"]
                                        if "rule" in record and record["rule"]["comment"] == rule["comment"])
                    changed_rule["expr"][index]["match"]["right"] = unsafe_value
                    self.assertFalse(front.owned_nft_table(changed))
            text = front.nftables_rules(bootstrap=mode).split("    chain output {", 1)[1].split("    chain input {", 1)[0]
            self.assertEqual(text.count("dnat ip to"), len(expected))
            self.assertNotIn("127.0.0.1", text)
            self.assertNotIn("18554", text)
            self.assertNotIn("18555", text)

    def test_auxiliary_permits_require_the_original_public_destination(self):
        for mode in (False, True):
            data = front.nft_table_data(bootstrap=mode)
            permits = [record["rule"] for record in data["nftables"]
                       if "rule" in record and record["rule"]["expr"][-1] == {"accept": None}]
            self.assertEqual(len(permits), 1 if mode else 2)
            for permit in permits:
                https = permit["comment"].endswith("https")
                expressions = permit["expr"]
                self.assertEqual(expressions[1]["match"]["right"], front.STREAM_PORT if https else front.HTTP_PORT)
                self.assertEqual(expressions[2], {"match": {"op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"}})
                self.assertEqual(expressions[3], {"match": {"op": "==", "left": {"ct": {"key": "daddr", "family": "ip", "dir": "original"}}, "right": front.PUBLIC_IPV4}})
                self.assertEqual(expressions[4], {"match": {"op": "==", "left": {"ct": {"key": "proto-dst", "dir": "original"}}, "right": 443 if https else 80}})
                for weakened_index in (2, 3, 4):
                    weakened = copy.deepcopy(data)
                    changed = next(record["rule"] for record in weakened["nftables"]
                                   if "rule" in record and record["rule"]["comment"] == permit["comment"])
                    changed["expr"].pop(weakened_index)
                    self.assertFalse(front.owned_nft_table(weakened))

    def test_owned_nft_json_fingerprint_ignores_handles_and_rejects_changes(self):
        for mode in (False, True):
            data = front.nft_table_data(bootstrap=mode)
            self.assertTrue(front.owned_nft_table(data, bootstrap=mode))
            self.assertFalse(front.owned_nft_table(data, bootstrap=not mode))
            runtime = copy.deepcopy(data)
            runtime["nftables"].insert(0, {"metainfo": {"version": "1.0.9"}})
            for index, record in enumerate(runtime["nftables"][1:]):
                next(iter(record.values()))["handle"] = index + 10
            self.assertEqual(front.nft_table_fingerprint(runtime), front.nft_table_fingerprint(data))
            self.assertTrue(front.owned_nft_table(json.dumps(runtime)))
            tampered = copy.deepcopy(data)
            tampered["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
            self.assertFalse(front.owned_nft_table(tampered))
            duplicated = copy.deepcopy(data)
            duplicated["nftables"].append(copy.deepcopy(duplicated["nftables"][-1]))
            self.assertFalse(front.owned_nft_table(duplicated))
        for value in ({}, {"nftables": []}, '{"invalid":}', {"nftables": [{"set": {}}]},
                      {"nftables": [{"table": {"family": "inet", "name": "foreign"}}]}):
            self.assertFalse(front.owned_nft_table(value))

    def test_owned_nft_json_keeps_rule_order_and_full_contents(self):
        data = front.nft_table_data()
        reordered = copy.deepcopy(data)
        reordered["nftables"][-1], reordered["nftables"][-2] = reordered["nftables"][-2], reordered["nftables"][-1]
        self.assertFalse(front.owned_nft_table(reordered))
        extra = copy.deepcopy(data)
        extra["nftables"][-1]["rule"]["expr"].insert(0, {"counter": {"packets": 0, "bytes": 0}})
        self.assertFalse(front.owned_nft_table(extra))


if __name__ == "__main__":
    unittest.main()
