"""Offline tests of the read-only server evidence collector (no SSH/network)."""
import ast
import base64
import json
import re
import unittest

from tools.check_youtube_vds import REMOTE
from tools.apply_youtube_udp_buffers import REMOTE as REPAIR_REMOTE, POSTCHECK


class YoutubeVdsEvidenceTest(unittest.TestCase):
    def helpers(self, responder):
        tree = ast.parse(REMOTE)
        definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        namespace = {'json': json, 're': re, 'command': responder}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), '<remote-functions>', 'exec'), namespace)
        namespace['command'] = responder
        return namespace

    def test_remote_program_is_valid_python(self):
        compile('PROXY = False\n' + REMOTE, '<remote-program>', 'exec')
        compile('MODE = "inspect"\nBACKUP = None\n' + REPAIR_REMOTE, '<repair-program>', 'exec')
        compile('TRANSACTION = "test"\n' + POSTCHECK, '<repair-read-only-reconciliation>', 'exec')

    def test_repair_does_not_lower_existing_larger_buffers(self):
        tree = ast.parse(REPAIR_REMOTE)
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'desired_values')
        limits = {'net.core.rmem_default': 1048576, 'net.core.rmem_max': 16777216, 'net.core.wmem_max': 16777216}
        namespace = {'LIMITS': limits}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), '<repair-policy>', 'exec'), namespace)
        old = {'net.core.rmem_default': 2097152, 'net.core.rmem_max': 33554432, 'net.core.wmem_max': 212992}
        self.assertEqual({**old, 'net.core.wmem_max': 16777216}, namespace['desired_values'](old))

    def test_reconciliation_requires_completed_restart_and_health_gates(self):
        tree = ast.parse(POSTCHECK)
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'require_verified')
        namespace = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), '<repair-completion-gate>', 'exec'), namespace)
        namespace['require_verified']({'phase': 'verified'})
        for state in ({}, {'phase': 'prepared'}, {'phase': 'failed'}):
            with self.assertRaises(RuntimeError):
                namespace['require_verified'](state)
        # The marker must be emitted after both the restart and the state check.
        self.assertLess(REPAIR_REMOTE.index('replace_file(content.encode());set_values(desired);restart_and_check()'), REPAIR_REMOTE.index('mark_verified(backup,state)\n'))
        self.assertLess(REPAIR_REMOTE.index("raise RuntimeError('Post-restart configuration mismatch')"), REPAIR_REMOTE.index('mark_verified(backup,state)\n'))

    def test_runtime_values_alone_do_not_confirm_persistence(self):
        tree = ast.parse(REPAIR_REMOTE)
        fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'persistent_settings_match')
        namespace = {'base64': base64, 'HEADER': '# managed\n'}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), '<repair-persistence-gate>', 'exec'), namespace)
        match = namespace['persistent_settings_match']
        settings = {'net.core.rmem_default': 1048576}
        exact = {'data_b64': base64.b64encode(b'# managed\nnet.core.rmem_default = 1048576\n').decode()}
        stale = {'data_b64': base64.b64encode(b'# managed\nnet.core.rmem_default = 212992\n').decode()}
        self.assertFalse(match(None, settings))
        self.assertFalse(match(stale, settings))
        self.assertTrue(match(exact, settings))
        self.assertIn('if desired==previous and persistent_settings_match(old_file,desired):', REPAIR_REMOTE)

    def test_socket_rates_use_ss_whitespace_format(self):
        ns = self.helpers(lambda args, timeout=15: (0, 'ESTAB peer hidden\n    rtt:42.1/0.2 cwnd:10 pacing_rate 20Mbps delivery_rate 10Mbps\n'))
        metrics = ns['socket_metrics']()['tcp_metric_samples'][0]
        self.assertEqual('42.1/0.2', metrics['rtt'])
        self.assertEqual('20Mbps', metrics['pacing_rate'])
        self.assertEqual('10Mbps', metrics['delivery_rate'])

    def test_short_error_responses_are_not_speed_results(self):
        ns = self.helpers(lambda args, timeout: (0, json.dumps({'http_code': 404, 'size_download': 1449, 'speed_download': 9000})))
        rows = ns['egress'](True)
        self.assertTrue(rows)
        self.assertTrue(all(not row['valid_probe'] and row['mbps'] is None for row in rows))

    def test_incomplete_download_is_not_a_speed_result(self):
        ns = self.helpers(lambda args, timeout: (0, json.dumps({'http_code': 200, 'size_download': 400, 'speed_download': 1e8})))
        rows = [r for r in ns['egress'](False) if r['target'] == 'cloudflare8m']
        self.assertTrue(all(not row['valid_probe'] and row['mbps'] is None for row in rows))

    def test_complete_google_range_requires_206_and_exact_size(self):
        calls = []
        def responder(args, timeout):
            calls.append(args)
            return 0, json.dumps({'http_code': 206, 'size_download': 8388608, 'speed_download': 12500000})
        ns = self.helpers(responder)
        rows = [r for r in ns['egress'](True) if r['target'] == 'google8m']
        self.assertEqual(3, len(rows))
        self.assertTrue(all(r['valid_probe'] and r['mbps'] == 100 for r in rows))
        google_calls = [a for a in calls if '--range' in a]
        self.assertEqual(3, len(google_calls))
        self.assertTrue(all('--http1.1' in a and '0-8388607' in a and '--socks5-hostname' in a for a in google_calls))
        self.assertTrue(all('--max-time' in a and '--max-filesize' in a for a in calls))

    def test_proxy_family_is_not_claimed_to_be_ipv6(self):
        ns = self.helpers(lambda args, timeout: (7, '{}'))
        self.assertEqual({'remote'}, {r['family'] for r in ns['egress'](True)})

    def test_local_noauth_endpoint_is_required(self):
        ns = self.helpers(lambda args, timeout: (0, '{}'))
        ns['require_local_socks']([{'port': 18081, 'listen': '127.0.0.1', 'auth': 'noauth'}])
        for listen, auth in [('0.0.0.0', 'noauth'), ('::1', 'noauth'), ('localhost', 'noauth'), ('127.0.0.1', 'password')]:
            with self.assertRaises(RuntimeError):
                ns['require_local_socks']([{'port': 18081, 'listen': listen, 'auth': auth}])


if __name__ == '__main__':
    unittest.main()
