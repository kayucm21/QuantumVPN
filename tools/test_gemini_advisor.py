"""Offline official-provider boundaries. Never calls Google or real Telegram."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError
from tools import quantumvpn_gemini as gemini


class GeminiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {'QV_GEMINI_API_KEY': 'A' * 39,
                                               'GEMINI_API_KEY': '', 'GOOGLE_API_KEY': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.snapshot = {'generated_at': 1791210000, 'services': {'operator': 'active', 'cpu_load_pct': 25},
                         'nodes': [{'target': '203.0.113.99:443', 'ok': True, 'latency_ms': 40, 'checked_at': 1791210000}],
                         'SECRET': 'private_user', 'backup': {'password': 'super-secret'},
                         'health': {'subscription_url': 'https://private/token'}}
        self.allowed = {row['node_id'] for row in gemini.cloud_snapshot(self.snapshot)['nodes']}
        self.analysis = {'status': 'watch', 'summary': 'Данных мало.', 'risk': 'Причина неизвестна.',
                         'next_step': 'Сравнить измерения.', 'recommendations': [{'node_id': next(iter(self.allowed)), 'action': 'observe'}]}

    def response(self, raw=None):
        reply = mock.MagicMock()
        reply.__enter__.return_value = reply
        reply.read.return_value = raw or json.dumps({'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'text': json.dumps(self.analysis)}]}}]}).encode()
        return reply

    def test_snapshot_drops_addresses_secrets_and_free_text(self):
        text = json.dumps(gemini.cloud_snapshot(self.snapshot))
        for secret in ('203.0.113', 'super-secret', 'private_user', '/token', 'subscription_url'):
            self.assertNotIn(secret, text)

    def test_malformed_projection_is_safe_and_unknown_not_a_crash(self):
        self.assertIsNone(gemini.number(10**1000))
        for value in ([], {'services': {'operator': []}}, {'health': {'latency_state': []}},
                      {'nodes': [{'target': '\ud800'}]}):
            json.dumps(gemini.cloud_snapshot(value)).encode()

    def test_offline_or_unmeasured_nodes_cannot_be_reserve_candidates(self):
        unsafe = dict(self.analysis, recommendations=[{'node_id': next(iter(self.allowed)), 'action': 'reserve_candidate'}])
        with self.assertRaises(gemini.GeminiError):
            gemini.validate_analysis(unsafe, self.allowed)
        self.assertEqual(gemini.validate_analysis(unsafe, self.allowed, self.allowed), unsafe)

    def test_missing_or_invalid_key_never_opens_network(self):
        with mock.patch.object(gemini, 'build_opener') as opener:
            for key, code in (('', 'missing_key'), ('secret\nheader', 'invalid_key')):
                with mock.patch.dict(os.environ, {'QV_GEMINI_API_KEY': key}):
                    with self.assertRaises(gemini.GeminiError) as caught:
                        gemini.analyze(self.snapshot)
                    self.assertEqual(caught.exception.code, code)
            opener.assert_not_called()

    def test_fixed_endpoint_secret_in_header_no_tools_and_bounded_response(self):
        reply = self.response()
        with mock.patch.object(gemini, 'build_opener') as opener:
            opener.return_value.open.return_value = reply
            result = gemini.analyze(self.snapshot)
        request = opener.return_value.open.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, gemini.ENDPOINT)
        self.assertNotIn('key=', request.full_url)
        self.assertNotIn('A' * 39, request.data.decode())
        self.assertNotIn('tools', body)
        self.assertFalse(body['store'])
        self.assertIsInstance(opener.call_args.args[0], gemini.NoRedirect)
        self.assertEqual(reply.read.call_args.args[0], 65537)
        self.assertEqual(result['model'], gemini.MODEL)

    def test_http_failure_does_not_expose_secret_url_or_body(self):
        with mock.patch.object(gemini, 'build_opener') as opener:
            opener.return_value.open.side_effect = HTTPError('https://evil/SECRET', 429, 'SECRET', {}, None)
            with self.assertRaises(gemini.GeminiError) as caught:
                gemini.analyze(self.snapshot)
        self.assertEqual(caught.exception.code, 'quota')
        self.assertNotIn('SECRET', str(caught.exception))

    def test_large_blocked_or_tool_response_rejected(self):
        bad = [b'x' * 65537, b'{}', json.dumps({'candidates': [{'finishReason': 'SAFETY'}]}).encode(),
               json.dumps({'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'functionCall': {'name': 'restart'}}]}}]}).encode()]
        for raw in bad:
            with mock.patch.object(gemini, 'build_opener') as opener:
                opener.return_value.open.return_value = self.response(raw)
                with self.assertRaises(gemini.GeminiError):
                    gemini.analyze(self.snapshot)

    def test_invented_nodes_actions_fields_and_control_characters_rejected(self):
        bad = [dict(self.analysis, recommendations=[{'node_id': 'new_node', 'action': 'observe'}]),
               dict(self.analysis, recommendations=[{'node_id': next(iter(self.allowed)), 'action': 'restart'}]),
               dict(self.analysis, command='rm'), dict(self.analysis, summary='line\nother')]
        for value in bad:
            with self.assertRaises(gemini.GeminiError):
                gemini.validate_analysis(value, self.allowed)


class NetworkAIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with mock.patch.dict(os.environ, {'QV_DATA_DIR': self.temp.name, 'QV_DOWNLOAD_ROOT': self.temp.name,
                                         'QV_ADMIN_USER': 'test', 'QV_ADMIN_PASSWORD': 'test',
                                         'QV_SUBSCRIPTION_UPSTREAM': 'https://example.invalid/sub'}):
            spec = importlib.util.spec_from_file_location('network_ai_fixture', Path(__file__).with_name('quantumvpn_operator_panel.py'))
            self.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.panel)
        self.db = self.panel.conn()
        self.addCleanup(self.db.close)
        self.s = self.panel.settings(self.db)

    def test_missing_gemini_key_does_not_execute_or_change_node_routing_release(self):
        self.s['ai_model'] = gemini.MODEL
        before = {key: value for key, value in self.panel.settings(self.db).items() if key.startswith(('node_', 'routing_', 'release_', 'app_version'))}
        with mock.patch.dict(os.environ, {'QV_GEMINI_API_KEY': '', 'GEMINI_API_KEY': '', 'GOOGLE_API_KEY': ''}), \
                mock.patch.object(gemini, 'build_opener') as opener:
            result = self.panel.run_ai_analysis(self.db, self.s)
        opener.assert_not_called()
        self.assertEqual(result['error'], 'missing_key')
        after = {key: value for key, value in self.panel.settings(self.db).items() if key.startswith(('node_', 'routing_', 'release_', 'app_version'))}
        self.assertEqual(before, after)

    def test_empty_registry_never_recommends_public_diagnostic_probe(self):
        self.s.update(node_map_config='', node_quarantine='{}', node_drains='{}', latency_probe_targets='1.1.1.1:443')
        self.panel.record_health(self.db, 'latency:1.1.1.1:443', {'ok': True, 'latency_ms': 1})
        result = self.panel.load_balancer_snapshot(self.db, self.s)
        self.assertEqual(result['selected'], '')
        self.assertEqual(result['candidates'], [])

    def test_network_alerts_use_repeated_evidence_and_state_not_settings(self):
        self.s.update(node_map_config='VPN|8.8.8.8:443|1|1|Test', telegram_alerts_enabled='1', routing_scan_targets='example.com')
        now = 1791210000
        for i in range(3):
            self.db.execute('insert into server_health values (?,?,?,?,?)', (now - 60 + i * 10, 'latency:8.8.8.8:443', 0, 0, 'timeout'))
        before = dict(self.db.execute('select key,value from settings'))
        with mock.patch.object(self.panel.time, 'time', return_value=now), \
                mock.patch.object(self.panel, 'scan_routing_targets', return_value=[]) as scan, \
                mock.patch.object(self.panel, 'telegram_send', return_value=True) as send:
            first = self.panel.monitor_network_health(self.db, self.s)
            second = self.panel.monitor_network_health(self.db, self.s)
        self.assertEqual(len(first['alerts']), 1)
        self.assertEqual(second['alerts'], [])
        # Network measurements journal one confirmed transition. Telegram is
        # emitted only by the shared factual worker, not this raw target path.
        self.assertEqual(send.call_count, 0)
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(before, dict(self.db.execute('select key,value from settings')))
        self.assertEqual(first['cause'], 'unconfirmed')
        self.assertEqual(first['throughput'], 'not_measured')


if __name__ == '__main__':
    unittest.main()
