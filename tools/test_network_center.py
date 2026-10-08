import copy
import ipaddress
import json
import tempfile
import unittest
from unittest import mock
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from tools.quantumvpn_control_quality import explain_route
from tools.quantumvpn_target_scan import catalog_dialog, scan_dialog
from tools import quantumvpn_network_center as network_center
from tools.quantumvpn_network_center import (
    NETWORK_VIEWS,
    explain_xray_route,
    normalize_lab_target,
    read_xray_snapshot,
    render_network_hub,
    route_laboratory,
    sanitize_xray_config,
    signed_policy_conflicts,
)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.current, self.nested, self.links = [], None, False, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "form":
            self.nested |= self.current is not None
            self.current = {"action": attrs.get("action"), "fields": {}}
            self.forms.append(self.current)
        if tag in {"input", "textarea", "select", "button"} and self.current is not None and "name" in attrs:
            self.current["fields"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class NetworkCenterTests(unittest.TestCase):
    def policy(self, **rules):
        return {"enabled": True, "revision": 9, "profile": "proxy_all", "rules": rules,
                "adblock": {"enabled": True}, "dns": {"mode": "vpn_only", "resolver": "https://dns.example/dns-query"}}

    def xray(self, rules, strategy="AsIs"):
        return sanitize_xray_config({"routing": {"domainStrategy": strategy, "rules": rules},
                                     "outbounds": [{"tag": "vpn", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"}]})

    def test_idna_and_public_ipv4_ipv6_are_canonical_without_network(self):
        self.assertEqual(normalize_lab_target("  ПРИМЕР.РФ. "), {"kind": "domain", "target": "xn--e1afmkfd.xn--p1ai"})
        self.assertEqual(normalize_lab_target("[2001:4860:4860::8888]"), {"kind": "ip", "target": "2001:4860:4860::8888"})
        self.assertEqual(normalize_lab_target("8.8.8.8"), {"kind": "ip", "target": "8.8.8.8"})

    def test_private_reserved_multicast_and_ambiguous_targets_rejected(self):
        values = ("", "localhost", "api.local", "api.internal", "localhost.localdomain", "x.home.arpa",
                  "127.0.0.1", "10.0.0.1", "100.64.1.2", "169.254.1.1", "192.0.2.1", "224.0.0.1",
                  "::1", "fe80::1", "ff02::1", "https://example.com", "example.com:443", "user@example.com",
                  "*.example.com", "a..example", "a.-example", "bad host", "8.008.8.8", "8.8.8.999")
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_lab_target(value)

    def test_apk_outcome_reuses_existing_explainer_and_preserves_payload(self):
        policy = self.policy(block_domains=["example.com"], direct_domains=["sub.example.com"], proxy_domains=["example.com"])
        original = copy.deepcopy(policy)
        result = route_laboratory(policy, "sub.example.com")
        expected = explain_route(policy, "sub.example.com")
        for key in ("direction", "reason", "matched", "revision"):
            self.assertEqual(result["signed"][key], expected[key])
        self.assertEqual(result["signed"]["scope"], "signed-apk-policy")
        self.assertEqual(policy, original)

    def test_balanced_ru_membership_is_unknown_even_with_proxy_match(self):
        policy = self.policy(proxy_domains=["example.com"])
        policy["profile"] = "balanced"
        result = route_laboratory(policy, "example.com")
        self.assertEqual(result["signed"]["certainty"], "unknown")
        self.assertEqual(result["signed"]["direction"], "Зависит от RU-списка APK")
        policy["enabled"] = False
        self.assertEqual(route_laboratory(policy, "example.com")["signed"]["certainty"], "unknown")

    def test_conflicts_include_descendant_suffixes_and_cidr_intersections(self):
        policy = self.policy(block_domains=["example.com"], direct_domains=["sub.example.com"],
                             proxy_domains=["sub.example.com", "unrelated.example"],
                             direct_cidrs=["8.8.0.0/16", "2001:4860::/32"],
                             proxy_cidrs=["8.8.8.0/24", "2001:4860:4860::/48"])
        report = signed_policy_conflicts(policy)
        self.assertFalse(report["truncated"])
        self.assertEqual(len(report["items"]), 5)
        self.assertEqual([row["winner"] for row in report["items"] if row["kind"] == "cidr"], ["direct", "direct"])
        self.assertNotIn("unrelated.example", json.dumps(report))

    def test_conflicts_are_bounded_and_do_not_claim_complete_report(self):
        policy = self.policy(block_domains=["example.com"], proxy_domains=["a.example.com", "b.example.com"])
        report = signed_policy_conflicts(policy, limit=1)
        self.assertEqual(len(report["items"]), 1)
        self.assertTrue(report["truncated"])

    def test_cidr_sweep_reports_every_parent_subnet_pair_in_both_directions(self):
        direct = ["8.0.0.0/8", "8.8.8.0/24", "8.8.8.1/24", "2001:4860::/32", "8.0.0.0/8"]
        proxy = ["8.8.0.0/16", "8.8.8.8/32", "2001:4860:4860::/48", "2001::/16", "9.0.0.0/8"]
        report = signed_policy_conflicts(self.policy(direct_cidrs=direct, proxy_cidrs=proxy))
        expected = set()
        for left_value in direct:
            left = ipaddress.ip_network(left_value, strict=False)
            for right_value in proxy:
                right = ipaddress.ip_network(right_value, strict=False)
                if left.version == right.version and left.overlaps(right):
                    expected.add((left_value, right_value, str(left if left.prefixlen >= right.prefixlen else right)))
        actual = {(item["first"]["rule"], item["second"]["rule"], item["target"]) for item in report["items"]}
        self.assertEqual(expected, actual)
        self.assertFalse(report["truncated"])
        self.assertTrue(all(item["winner"] == "direct" for item in report["items"]))
        self.assertTrue(all(item["first"]["index"] == 0 for item in report["items"] if item["first"]["rule"] == "8.0.0.0/8"))

    def test_disjoint_thousand_cidr_lists_do_not_use_a_cross_product(self):
        count = 1000
        direct = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("8.0.0.0")) + index * 2)) + "/32" for index in range(count)]
        proxy = [str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("8.0.0.0")) + index * 2 + 1)) + "/32" for index in range(count)]
        # Count operations, rather than a wall-clock threshold which depends on
        # the developer's PC. The former nested scan called overlaps 1M times;
        # the sweep visits each sorted interval once and never tests disjoint
        # pairs. Heap operations are linear in the number of input intervals.
        with mock.patch.object(ipaddress.IPv4Network, "overlaps", side_effect=AssertionError("pairwise CIDR scan")), \
                mock.patch.object(network_center.heapq, "heappush", wraps=network_center.heapq.heappush) as push, \
                mock.patch.object(network_center.heapq, "heappop", wraps=network_center.heapq.heappop) as pop:
            report = signed_policy_conflicts(self.policy(direct_cidrs=direct, proxy_cidrs=proxy))
        self.assertEqual(report["items"], [])
        self.assertFalse(report["truncated"])
        self.assertEqual(push.call_count, count * 2)
        self.assertLessEqual(pop.call_count, count * 2)

    def test_cidr_conflict_cap_is_faithful_and_repeated_text_is_deduplicated(self):
        report = signed_policy_conflicts(self.policy(direct_cidrs=["8.0.0.0/8"] * 1000,
                                                     proxy_cidrs=["8.8.0.0/16"] * 1000))
        self.assertEqual(len(report["items"]), 1)
        self.assertFalse(report["truncated"])
        report = signed_policy_conflicts(self.policy(direct_cidrs=["8.0.0.0/8"],
                                                     proxy_cidrs=["8.8.8.0/24", "8.9.9.0/24"]), limit=1)
        self.assertEqual(len(report["items"]), 1)
        self.assertTrue(report["truncated"])
        self.assertEqual(report["items"][0]["target"], "8.8.8.0/24")

    def test_xray_snapshot_excludes_all_users_endpoints_keys_urls_and_headers(self):
        raw = {"inbounds": [{"settings": {"clients": [{"id": "private-uuid", "email": "private@example.com"}]},
                             "streamSettings": {"realitySettings": {"privateKey": "private-reality"}}}],
               "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"password": "private-password", "address": "hidden.example"}}],
               "routing": {"rules": [{"domain": ["domain:example.com"], "user": ["private@example.com"],
                                        "source": ["10.42.0.1"], "attrs": {"authorization": "private-bearer"},
                                        "webhook": {"url": "https://hidden.example/?token=private-token"}, "outboundTag": "direct"}]}}
        original = copy.deepcopy(raw)
        report = sanitize_xray_config(raw)
        rendered = json.dumps(report)
        for secret in ("private-uuid", "private@example.com", "private-reality", "private-password", "hidden.example", "10.42.0.1", "private-bearer", "private-token"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(report["rules"][0]["context_fields"], ["user", "source", "attrs"])
        self.assertEqual(raw, original)

    def test_server_first_match_suffix_and_ip_rules_are_separate_from_apk(self):
        snapshot = self.xray([{"domain": ["domain:example.com"], "outboundTag": "direct"},
                              {"domain": ["full:sub.example.com"], "outboundTag": "vpn"}])
        result = route_laboratory(self.policy(proxy_domains=["example.com"]), "sub.example.com", snapshot)
        self.assertEqual(result["signed"]["direction"], "Через выбранный VPN")
        self.assertEqual(result["server"]["direction"], "direct")
        self.assertEqual(result["server"]["matched_rule"]["index"], 0)
        ip_result = explain_xray_route(self.xray([{"ip": ["8.8.8.0/24"], "outboundTag": "direct"}]), "8.8.8.8")
        self.assertEqual(ip_result["matched_rule"]["matched"], "8.8.8.0/24")

    def test_xray_plain_domain_is_keyword_full_is_exact_suffix_has_boundary(self):
        cases = (("example.com", "notexample.com", True), ("domain:example.com", "notexample.com", False),
                 ("domain:example.com", "sub.example.com", True), ("full:example.com", "sub.example.com", False))
        for rule, target, matched in cases:
            with self.subTest(rule=rule):
                report = explain_xray_route(self.xray([{"domain": [rule], "outboundTag": "direct"}]), target)
                self.assertEqual(report["matched_rule"] is not None, matched)

    def test_unknown_earlier_geodata_prevents_a_fake_later_winner(self):
        cases = (("domain", "geosite:ru", "example.com"), ("ip", "geoip:ru", "8.8.8.8"),
                 ("domain", "regexp:.*", "example.com"), ("ip", "ext:secret-path.dat:ru", "8.8.8.8"))
        for field, selector, target in cases:
            with self.subTest(selector=selector):
                exact = "domain:" + target if field == "domain" else target
                report = explain_xray_route(self.xray([{field: [selector], "outboundTag": "direct"},
                                                      {field: [exact], "outboundTag": "vpn"}]), target)
                self.assertEqual(report["certainty"], "unknown")
                self.assertIsNone(report["matched_rule"])
                self.assertEqual(report["provisional_rule"]["index"], 1)

    def test_exact_or_match_is_known_even_if_same_field_contains_unknown_geodata(self):
        snapshot = self.xray([{"ip": ["geoip:ru", "8.8.8.0/24"], "outboundTag": "direct"}])
        self.assertEqual(explain_xray_route(snapshot, "8.8.8.8")["certainty"], "known")

    def test_missing_port_or_inbound_context_is_unknown_but_known_mismatch_wins(self):
        snapshot = self.xray([{"domain": ["domain:example.com"], "port": "443", "inboundTag": ["user-vpn"], "outboundTag": "direct"}])
        self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")
        report = explain_xray_route(snapshot, "unrelated.example")
        self.assertEqual(report["certainty"], "known")
        self.assertEqual(report["direction"], "vpn")

    def test_truncated_domain_ip_or_inbound_values_never_claim_later_winner(self):
        context = {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
        cases = (
            ({"domain": ["full:unrelated.example"] * network_center.MAX_RULE_VALUES + ["domain:example.com"]}, "example.com"),
            ({"ip": ["9.9.9.9/32"] * network_center.MAX_RULE_VALUES + ["8.8.8.8/32"]}, "8.8.8.8"),
            ({"inboundTag": ["api"] * network_center.MAX_RULE_VALUES + ["vless-in"]}, "example.com"),
            ({"domain": ["domain:example.com"] * (network_center.MAX_RULE_VALUES + 1)}, "example.com"),
        )
        for condition, target in cases:
            with self.subTest(field=next(iter(condition))):
                snapshot = self.xray([{**condition, "outboundTag": "direct"},
                                      {"network": "tcp,udp", "outboundTag": "vpn"}])
                self.assertTrue(snapshot["rules"][0]["incomplete"])
                result = explain_xray_route(snapshot, target, context)
                self.assertEqual(result["certainty"], "unknown")
                self.assertIsNone(result["matched_rule"])
                self.assertEqual(result["provisional_rule"]["index"], 1)

    def test_redacted_or_unavailable_context_never_becomes_a_known_match(self):
        context = {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
        for condition in ({"inboundTag": ["private@example.com"]}, {"sourceIP": ["10.0.0.1"]},
                          {"port": "secret-token"}, {"network": "tcp,udp,"},
                          {"network": "tcp,udp," * 1000 + "tcp"}):
            with self.subTest(field=next(iter(condition))):
                snapshot = self.xray([{**condition, "domain": ["domain:example.com"], "outboundTag": "direct"}])
                result = explain_xray_route(snapshot, "example.com", context)
                self.assertEqual(result["certainty"], "unknown")
                self.assertIsNone(result["matched_rule"])
                self.assertLess(len(json.dumps(snapshot)), 1500)
                self.assertNotIn("private@example.com", json.dumps(snapshot))
                self.assertNotIn("secret-token", json.dumps(snapshot))
                self.assertNotIn("10.0.0.1", json.dumps(snapshot))

    def test_fixed_vless_scenario_skips_api_and_socks_rules_before_domain_match(self):
        snapshot = self.xray([
            {"inboundTag": ["api"], "outboundTag": "api"},
            {"inboundTag": ["panel-egress-in"], "outboundTag": "direct"},
            {"domain": ["domain:example.com"], "network": "tcp", "port": "443,8443-8444", "outboundTag": "vpn"},
        ])
        context = {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
        self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")
        report = route_laboratory(self.policy(), "example.com", snapshot, traffic_context=context)
        server = report["server"]
        self.assertEqual(server["certainty"], "known")
        self.assertEqual(server["matched_rule"]["index"], 2)
        self.assertEqual([row["state"] for row in server["trace"]], ["no", "no", "yes"])
        self.assertEqual(server["scenario_label"], "Серверный сценарий VLESS/TCP 443, не личная сессия")
        self.assertIn(server["scenario_label"], render_network_hub({}, "csrf", payload=self.policy(), lab_result=report))

    def test_fixed_context_does_not_invent_unknown_geosite_or_geoip_membership(self):
        context = {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
        for field, selector, target in (("domain", "geosite:ru", "example.com"), ("ip", "geoip:ru", "8.8.8.8")):
            with self.subTest(selector=selector):
                snapshot = self.xray([{ "inboundTag": ["api"], "outboundTag": "api"},
                                      {field: [selector], "outboundTag": "direct"},
                                      {"network": "tcp,udp", "outboundTag": "vpn"}])
                report = explain_xray_route(snapshot, target, context)
                self.assertEqual(report["trace"][0]["state"], "no")
                self.assertEqual(report["certainty"], "unknown")
                self.assertEqual(report["possible_rules"][0]["index"], 1)
                self.assertIsNone(report["matched_rule"])

    def test_known_transport_or_port_mismatch_defeats_unknown_domain_membership(self):
        context = {"inbound_tag": "vless-in", "network": "tcp", "port": 443}
        for condition in ({"network": "udp"}, {"port": "53"}):
            snapshot = self.xray([{**condition, "domain": ["geosite:ru"], "outboundTag": "direct"}])
            self.assertEqual(explain_xray_route(snapshot, "example.com", context)["direction"], "vpn")

    def test_traffic_context_rejects_extra_conditions_and_invalid_values(self):
        for context in ({"source": "10.0.0.1"}, {"inbound_tag": "user@example.com"}, {"network": "http"}, {"port": 0}, {"port": True}):
            with self.subTest(context=context), self.assertRaises(ValueError):
                explain_xray_route(self.xray([]), "example.com", context)

    def test_dns_strategy_honors_domain_first_pass_and_unknown_ip_on_demand(self):
        rules = [{"ip": ["8.8.8.0/24"], "outboundTag": "direct"},
                 {"domain": ["domain:example.com"], "outboundTag": "vpn"}]
        self.assertEqual(explain_xray_route(self.xray(rules, "AsIs"), "example.com")["certainty"], "known")
        self.assertEqual(explain_xray_route(self.xray(rules, "IPIfNonMatch"), "example.com")["matched_rule"]["index"], 1)
        self.assertEqual(explain_xray_route(self.xray(rules, "IPOnDemand"), "example.com")["certainty"], "unknown")
        report = explain_xray_route(self.xray(rules[:1], "IPIfNonMatch"), "example.com")
        self.assertEqual(report["certainty"], "unknown")
        self.assertEqual(report["possible_rules"][0]["pass"], 2)

    def test_default_is_first_outbound_and_universal_transport_rule_is_known(self):
        self.assertEqual(explain_xray_route(self.xray([]), "example.com")["direction"], "vpn")
        snapshot = self.xray([{"network": "tcp,udp", "outboundTag": "direct"}])
        self.assertEqual(explain_xray_route(snapshot, "example.com")["matched_rule"]["index"], 0)

    def test_rule_without_effective_conditions_does_not_claim_catch_all(self):
        snapshot = self.xray([{"outboundTag": "direct"}])
        self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")

    def test_apk_matching_evidence_has_explicit_block_before_builtin_adblock(self):
        report = route_laboratory(self.policy(block_domains=["doubleclick.net"], direct_domains=["doubleclick.net"]), "ads.doubleclick.net")
        self.assertEqual([item["list"] for item in report["signed"]["matching_rules"]], ["block_domains", "apk_adblock", "direct_domains"])

    def test_unavailable_unsanitized_or_truncated_snapshot_never_claims_default(self):
        for snapshot in (None, {"available": False}, {"available": True, "sanitized": False}):
            self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")
        snapshot = self.xray([])
        snapshot["truncated"] = True
        self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")

    def test_invalid_first_outbound_does_not_fall_through_to_second_as_default(self):
        for first in (None, "invalid-outbound", 123):
            with self.subTest(first=first):
                snapshot = sanitize_xray_config({"routing": {"rules": []},
                                                 "outbounds": [first, {"tag": "direct", "protocol": "freedom"}]})
                self.assertFalse(snapshot["default_outbound_known"])
                self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")

    def test_unknown_domain_strategy_type_is_safe_and_never_resolved(self):
        snapshot = self.xray([], strategy={"private": "value"})
        self.assertEqual(snapshot["domain_strategy"], "unknown")
        self.assertNotIn("private", json.dumps(snapshot))
        self.assertEqual(explain_xray_route(snapshot, "example.com")["certainty"], "unknown")

    def test_config_reader_does_not_modify_file_and_does_not_expose_path(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-name.json"
            raw = json.dumps({"routing": {"rules": []}, "outbounds": [{"tag": "direct", "protocol": "freedom"}]}).encode()
            path.write_bytes(raw)
            report = read_xray_snapshot(path)
            self.assertTrue(report["available"])
            self.assertEqual(path.read_bytes(), raw)
            self.assertNotIn("private-name", json.dumps(report))
            self.assertFalse(read_xray_snapshot(Path(folder) / "missing.json")["available"])

    def test_forms_are_complete_have_csrf_and_never_nested(self):
        policy = self.policy(direct_domains=["example.com"])
        for view in NETWORK_VIEWS:
            with self.subTest(view=view):
                page = render_network_hub({"routing_staging_enabled": "1", "routing_staging_revision": "10"}, "csrf<&token",
                                          payload=policy, active=view, history=[{"revision": 8, "state": "production", "actor": "owner", "note": "safe"}])
                parser = FormParser()
                parser.feed(page)
                self.assertFalse(parser.nested)
                for form in parser.forms:
                    self.assertEqual(form["fields"]["csrf"], "csrf<&token")
                    if "routing_profile" in form["fields"]:
                        for key in ("enabled", "adblock_enabled", "profile", "dns_mode", "dns_resolver", "direct_domains", "proxy_domains", "block_domains", "direct_cidrs", "proxy_cidrs"):
                            self.assertIn("routing_" + key, form["fields"])
                self.assertIn('network_view=mtproto', page)

    def test_local_tabs_and_workflow_links_preserve_selected_policy_source(self):
        for source in ("production", "draft", "staging"):
            for view in NETWORK_VIEWS:
                with self.subTest(source=source, view=view):
                    page = render_network_hub({}, "token", payload=self.policy(proxy_domains=["pending.example"]),
                                              active=view, policy_source=source)
                    parser = FormParser()
                    parser.feed(page)
                    local_queries = [parse_qs(urlsplit(href).query) for href in parser.links
                                     if parse_qs(urlsplit(href).query).get("tab") == ["network"]]
                    self.assertGreaterEqual(len(local_queries), len(NETWORK_VIEWS))
                    self.assertEqual({query["network_view"][0] for query in local_queries}, set(NETWORK_VIEWS))
                    self.assertTrue(all(query.get("policy_source") == [source] for query in local_queries))

    def test_routing_editor_stage_and_history_forms_carry_source_and_dns_return_view(self):
        for source in ("production", "draft", "staging"):
            for view in ("overview", "routes", "dns"):
                with self.subTest(source=source, view=view):
                    page = render_network_hub({"routing_staging_enabled": "1"}, "token", payload=self.policy(),
                                              active=view, policy_source=source,
                                              history=[{"revision": 8, "state": "production"}])
                    parser = FormParser()
                    parser.feed(page)
                    forms = [form for form in parser.forms if form["action"] == "/operator/routing"]
                    self.assertGreaterEqual(len(forms), 3)
                    self.assertTrue(all(form["fields"].get("policy_source") == source for form in forms))
                    self.assertTrue(all(form["fields"].get("return_view") == ("dns" if view == "dns" else "routes") for form in forms))

    def test_link_policy_source_is_allowlisted_not_interpolated_from_untrusted_value(self):
        page = render_network_hub({}, "token", payload=self.policy(), active="overview",
                                  policy_source='draft&admin=true" onclick="bad')
        parser = FormParser()
        parser.feed(page)
        local_queries = [parse_qs(urlsplit(href).query) for href in parser.links
                         if parse_qs(urlsplit(href).query).get("tab") == ["network"]]
        self.assertTrue(all(query.get("policy_source") == ["production"] for query in local_queries))
        self.assertNotIn("onclick", page)
        self.assertNotIn("admin=true", page)

    def test_viewer_controls_disabled_and_untrusted_data_escaped(self):
        policy = self.policy()
        page = render_network_hub({}, "token", payload=policy, active="routes", can_write=False,
                                  lab_result={"target": "<script>bad</script>", "signed": {"direction": "<img>"}, "server": {}})
        self.assertIn("<fieldset disabled>", page)
        self.assertNotIn("<script>bad</script>", page)
        self.assertNotIn("<img>", page)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;", page)
        self.assertNotIn("value=rollback", page)

    def catalog_fragment(self, source="production", view="routes", can_write=True):
        fields = (f'<input type=hidden name=csrf value="catalog-token">'
                  f'<input type=hidden name=return_tab value=network>'
                  f'<input type=hidden name=return_view value={view}>'
                  f'<input type=hidden name=policy_source value={source}>')
        scanner = ('<form id=routing-scan-form method=post action=/operator/routing>'
                   '<input type=hidden name=action value=scan>' + fields
                   + '<textarea name=routing_scan_targets></textarea><button '
                   + ("disabled" if not can_write else "") + '>Проверить</button></form>')
        findings = [{"target": "2606:4700:4700::1111", "kind": "ip", "status": "ok", "latency_ms": 40}]
        results = scan_dialog(findings, "fresh-evidence-token", "catalog-token", can_write=can_write)
        # HTTP owner supplies context on the existing apply form, not the hub.
        results = results.replace('</form>', fields.replace('<input type=hidden name=csrf value="catalog-token">', '') + '</form>')
        return scanner + catalog_dialog("catalog-token", can_write=can_write) + results

    def test_trusted_catalog_is_adjacent_to_lab_without_nested_or_duplicate_forms(self):
        for view in ("overview", "routes", "dns"):
            with self.subTest(view=view):
                fragment = self.catalog_fragment(view="dns" if view == "dns" else "routes")
                page = render_network_hub({}, "hub-token", payload=self.policy(), active=view,
                                          panel_html={"catalog": fragment})
                parser = FormParser()
                parser.feed(page)
                self.assertFalse(parser.nested)
                self.assertIn('type=button class=secondary data-catalog-open', page)
                self.assertIn("Найти и сканировать цели", page)
                self.assertIn("IPv4 · IPv6 · домены", page)
                self.assertIn("это не список всех адресов Интернета", page)
                self.assertIn("2606:4700:4700::1111", page)
                self.assertIn(fragment, page)
                for identifier in ('id=routing-scan-form', 'id="routing-catalog-dialog"', 'id="routing-scan-dialog"'):
                    self.assertEqual(page.count(identifier), 1)
                self.assertGreater(page.index('network-catalog-tools'), page.index('action=/operator/network/lab'))

    def test_catalog_context_is_preserved_for_scans_and_reviewed_apply(self):
        for source in ("production", "draft", "staging"):
            for view in ("routes", "dns"):
                with self.subTest(source=source, view=view):
                    page = render_network_hub({}, "hub-token", payload=self.policy(), active=view,
                                              policy_source=source, panel_html={"catalog": self.catalog_fragment(source, view)})
                    parser = FormParser()
                    parser.feed(page)
                    catalog_forms = [form for form in parser.forms if form["fields"].get("action") in {"scan", "apply_scan"}]
                    self.assertEqual(len(catalog_forms), 2)
                    for form in catalog_forms:
                        self.assertEqual(form["action"], "/operator/routing")
                        for key, value in (("csrf", "catalog-token"), ("return_tab", "network"),
                                           ("return_view", view), ("policy_source", source)):
                            self.assertEqual(form["fields"].get(key), value)

    def test_catalog_appears_only_on_route_lab_views_and_is_optional(self):
        for view in NETWORK_VIEWS:
            with self.subTest(view=view):
                page = render_network_hub({}, "hub-token", payload=self.policy(), active=view,
                                          panel_html={"catalog": "<div>trusted-catalog-marker</div>"})
                self.assertEqual("trusted-catalog-marker" in page, view in {"overview", "routes", "dns"})
                absent = render_network_hub({}, "hub-token", payload=self.policy(), active=view)
                self.assertNotIn("data-catalog-open", absent)

    def test_viewer_can_open_catalog_search_but_supplied_scan_writes_are_disabled(self):
        page = render_network_hub({}, "hub-token", payload=self.policy(), active="routes", can_write=False,
                                  panel_html={"catalog": self.catalog_fragment(can_write=False)})
        self.assertIn('type=button class=secondary data-catalog-open', page)
        self.assertIn('data-can-write="0"', page)
        self.assertIn('id="routing-catalog-search"', page)
        self.assertIn('id="routing-catalog-file" accept=".txt,text/plain" disabled', page)
        self.assertIn('id="routing-catalog-scan" disabled', page)
        self.assertIn('<button disabled>Проверить</button>', page)


if __name__ == "__main__":
    unittest.main()
