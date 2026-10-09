"""Offline fixed-front guards. No network, SSH, service or firewall mutation."""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('web_front', Path(__file__).with_name('activate-webproxy-front.py'))
front = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(front)
REMOTE = {'RUN_REMOTE': False, 'APPLY': False, 'EXPECTED': {}}
with patch.dict(sys.modules, {'fcntl': Mock()}):
    exec(compile(front.REMOTE, '<front-offline>', 'exec'), REMOTE)
ROUTE = {'__name__': 'route_offline'}
exec(compile(front.ROUTE_RUNTIME, '<route-offline>', 'exec'), ROUTE)


class FrontGuards(unittest.TestCase):
    def test_python_sources_parse(self):
        ast.parse(front.REMOTE)
        ast.parse(front.ROUTE_RUNTIME)

    def test_default_inventory_returns_before_mutation(self):
        inventory = {'status': 'ReadOnly', 'public_ready': False}
        targets = {name: Mock(side_effect=AssertionError(name)) for name in
                   ('helper', 'exclusive', 'run', 'public_site')}
        output = io.StringIO()
        with patch.dict(REMOTE, targets | {'APPLY': False, 'inventory': Mock(return_value=(inventory, {}))}), contextlib.redirect_stdout(output):
            REMOTE['main']()
        self.assertEqual(json.loads(output.getvalue()), inventory)
        for value in targets.values():
            value.assert_not_called()

    def test_apply_hash_mismatch_prevents_services_and_build(self):
        observed = {str(p): 'a' * 64 for p in REMOTE['PROTECTED'][:4]}
        mutations = {name: Mock(side_effect=AssertionError(name)) for name in ('helper', 'run', 'exclusive')}
        with patch.dict(REMOTE, mutations | {'APPLY': True, 'EXPECTED': {}, 'inventory': Mock(return_value=({'installed': False}, observed))}):
            with self.assertRaisesRegex(RuntimeError, 'protected_preflight_hash_changed'):
                REMOTE['main']()
        for value in mutations.values():
            value.assert_not_called()

    def test_partial_existing_front_refused(self):
        observed = {str(p): 'a' * 64 for p in REMOTE['PROTECTED'][:4]}
        with patch.dict(REMOTE, {'APPLY': True, 'EXPECTED': observed, 'inventory': Mock(return_value=({'installed': True}, observed))}):
            with self.assertRaisesRegex(RuntimeError, 'existing_or_partial_front_refused'):
                REMOTE['main']()

    def test_only_exact_main_cgroup_fallback_nft_scope(self):
        text = ROUTE['rules']('a' * 32)
        self.assertIn('table ip quantumvpn_web_front', text)
        self.assertIn('ip daddr 127.0.0.1 tcp dport 8080', text)
        self.assertIn('socket cgroupv2 level 2 "system.slice/rospanel.service"', text)
        self.assertIn('dnat to 127.0.0.1:18084', text)
        for bad in ('flush ruleset', 'meta skuid 0', 'hook prerouting', '3443', '18443'):
            self.assertNotIn(bad, text)

    def test_nft_fingerprint_ignores_only_runtime_counters(self):
        before = {'nftables': [{'metainfo': {'time': 1}}, {'rule': {'handle': 8, 'expr': [{'counter': {'packets': 1, 'bytes': 2}}, {'dnat': {'addr': '127.0.0.1', 'port': 18084}}]}}]}
        after = {'nftables': [{'metainfo': {'time': 2}}, {'rule': {'handle': 9, 'expr': [{'counter': {'packets': 900, 'bytes': 1000}}, {'dnat': {'addr': '127.0.0.1', 'port': 18084}}]}}]}
        self.assertEqual(ROUTE['fingerprint'](before), ROUTE['fingerprint'](after))
        after['nftables'][1]['rule']['expr'][1]['dnat']['port'] = 10085
        self.assertNotEqual(ROUTE['fingerprint'](before), ROUTE['fingerprint'](after))

    def test_route_unknown_action_refused_before_reads(self):
        reader = Mock(side_effect=AssertionError('read'))
        with patch.dict(ROUTE, {'read': reader}), patch.object(ROUTE['os'], 'geteuid', return_value=0, create=True):
            for action in ('restart', 'flush', '', 'start; true'):
                with self.assertRaisesRegex(RuntimeError, 'fixed_route_action_required'):
                    ROUTE['main'](action)
        reader.assert_not_called()

    def test_service_has_automatic_persistent_order_and_limits(self):
        unit = REMOTE['front_unit']()
        for value in ('Type=notify', 'NotifyAccess=main', 'DynamicUser=yes', 'BindsTo=rospanel.service',
                      'PartOf=rospanel.service', 'MemoryMax=128M', 'CPUQuota=50%',
                      'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'StandardError=null'):
            self.assertIn(value, unit)
        self.assertNotIn('ExecStart=/usr/local/bin/rospanel', unit)
        route = REMOTE['route_unit']()
        self.assertIn('After=rospanel.service quantumvpn-webproxy-front.service', route)
        self.assertIn('ExecStop=/usr/bin/python3 -B /opt/quantumvpn-webproxy/front-route.py stop', route)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN', route)

    def test_go_gateway_destinations_and_client_address_preservation(self):
        code = front.GATEWAY_GO
        for text in ('const listenAddr = "127.0.0.1:18084"', 'const siteAddr = "127.0.0.1:8080"',
                     'const relayAddr = "127.0.0.1:18082"', 'DisableKeepAlives:site',
                     'address!=siteAddr', 'proxyHeader(client)', 'netip.ParseAddrPort',
                     'SetUnencryptedHTTP2(true)', 'MaxConcurrentStreams:32', 'io.Discard',
                     'p.Out.Host=p.In.Host', 'p.Out.Header.Set("X-Forwarded-For",client.IP.String())'):
            self.assertIn(text, code)
        self.assertNotIn('ProxyFromEnvironment', code)
        self.assertNotIn('log.Printf', code)
        self.assertNotIn('r.URL.String()', code)
        self.assertNotIn('Header.Get("X-Forwarded-For")', code)

    def test_native_tests_cover_protocols_and_production_proxy_serializer(self):
        code = front.GATEWAY_TEST_GO
        for name in ('TestHTTP1AndH2CWithProxyClient', 'TestFragmentationAndIPv6Address',
                     'TestForwardingDoesNotAppendSpoofedChains', 'TestSiteDialRefusesUserDestinationAndMissingClient',
                     'TestProxySerialization'):
            self.assertIn(name, code)
        self.assertIn('proxyHeader(a)', code)

    def test_no_database_updates_public_rebinding_or_nginx_reload(self):
        code = front.REMOTE
        for bad in ('UPDATE settings', 'update settings', 'UPDATE inbounds', 'write_text(',
                    "['systemctl','restart','rospanel", "['systemctl','reload','nginx", '0.0.0.0:18084'):
            self.assertNotIn(bad, code)
        self.assertIn("require(before==protected(),'protected_configuration_changed_after_apply')", code)
        self.assertIn("site_after==site_before and site_h2_after==site_h2_before", code)
        self.assertIn("proof.get('telegram_nonce_confirmed')", code)

    def test_retained_build_cache_verified_and_compile_has_one_cpu(self):
        code = front.REMOTE
        self.assertIn("'--property=CPUQuota=100%'", code)
        self.assertIn("read(index,8*1024*1024)==cache_index(cache,user)", code)
        self.assertIn("'--setenv=GOPROXY=off'", code)
        self.assertIn("'--setenv=GO111MODULE=off'", code)
        self.assertIn("'--setenv=GOTOOLCHAIN=local'", code)
        self.assertIn("'--property=RuntimeMaxSec=600'", code)
        self.assertIn('CPUQuota=50%', REMOTE['front_unit']())
        self.assertIn("'rollback_target_content_changed_manual_recovery_required'", code)
        self.assertIn('current.st_dev,current.st_ino', code)

    def test_relay_restart_also_recovers_front_and_route(self):
        code = front.REMOTE
        self.assertIn('/etc/systemd/system/quantumvpn-webproxy.service.d/60-quantumvpn-webproxy-front.conf', code)
        self.assertIn('PartOf=rospanel.service quantumvpn-webproxy.service', REMOTE['front_unit']())
        self.assertIn('PartOf=rospanel.service quantumvpn-webproxy-front.service', REMOTE['route_unit']())


if __name__ == '__main__':
    unittest.main()
