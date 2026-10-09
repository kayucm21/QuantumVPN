"""Offline fail-closed/additive native FakeTLS installer tests; no VDS access."""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('tls_installer', Path(__file__).with_name('install-mtproto-tls-vds.py'))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
REMOTE = {'RUN_REMOTE': False, 'APPLY': False, 'EXPECTED_PATCH_SHA256': installer.SECURITY_PATCH_SHA256,
          'MODULE_B64': '', 'MODULE_SHA256': 'a' * 64, 'PROTOCOL_B64': '', 'PROTOCOL_SHA256': 'b' * 64,
          'BASE_MODULE_B64': '', 'BASE_MODULE_SHA256': 'c' * 64}
with patch.dict(sys.modules, {'fcntl': Mock(), 'pwd': Mock()}):
    exec(compile(installer.REMOTE, '<native-tls-installer-offline>', 'exec'), REMOTE)


class DerivationAndContractTests(unittest.TestCase):
    def test_derivation_is_exact_base_guarded_and_syntactically_valid(self):
        ast.parse(installer.REMOTE)
        self.assertEqual(installer._reviewed_remote(), installer.REMOTE)
        with patch.object(Path, 'read_text', return_value="REMOTE='unexpected new implementation'\n"):
            with self.assertRaisesRegex(RuntimeError, 'base_installer_changed_review_required'):
                installer._reviewed_remote()

    def test_official_commit_and_original_base_source_are_unchanged(self):
        self.assertEqual(REMOTE['COMMIT'], 'f36d8af769ffaeac36978d38c2c0f6d1104c2137')
        self.assertEqual(REMOTE['BASE_SOURCE_SHA256'], '31116c17d5245b8d564d04b252a4d80e24c23f637342e09e33c47b08973defad')
        self.assertEqual(REMOTE['SOURCE'], 'https://github.com/TelegramMessenger/MTProxy.git')
        self.assertIn("fetch','--depth','1','origin',COMMIT", installer.REMOTE)
        self.assertIn('official_commit_identity_mismatch', installer.REMOTE)
        self.assertIn('official_base_source_digest_mismatch', installer.REMOTE)

    def test_all_new_service_paths_and_ports_are_independent(self):
        for key, value in (('ROOT', '/opt/quantumvpn-mtproto-tls'), ('PRIVATE', '/etc/quantumvpn-mtproto-tls'),
                           ('UNIT', '/etc/systemd/system/quantumvpn-mtproto-tls.service')):
            self.assertEqual(REMOTE[key], Path(value))
        self.assertEqual(REMOTE['SERVICE'], 'quantumvpn-mtproto-tls.service')
        self.assertEqual(REMOTE['USER'], 'qvpn-mtproto-tls')
        self.assertEqual(REMOTE['PORT'], 5443)
        self.assertEqual(REMOTE['STATS_PORT'], 18889)
        self.assertEqual(REMOTE['DOMAIN'], 'pecaocek.ignorelist.com')

    def test_original_vpn_mtproxy_and_web_files_are_protected_not_replaced(self):
        protected = {str(path).replace('\\', '/') for path in REMOTE['PROTECTED']}
        for path in ('/etc/quantumvpn-mtproto/client-secret', '/etc/quantumvpn-mtproto/config.json',
                     '/opt/quantumvpn-mtproto/mtproto-proxy', '/etc/systemd/system/quantumvpn-mtproto.service',
                     '/etc/quantumvpn-webproxy/token.key', '/etc/systemd/system/quantumvpn-webproxy.service',
                     '/var/lib/rospanel/xray/config.json', '/etc/resolv.conf', '/etc/nginx/nginx.conf'):
            self.assertIn(path, protected)
        for denied in ('apt-get', 'iptables', 'ufw', "['caddy'", "['nginx'", "['sysctl'", 'INSTALL_DEPS'):
            self.assertNotIn(denied, installer.REMOTE)

    def test_patch_is_new_identity_and_fixed_new_credential_path(self):
        self.assertEqual(REMOTE['PATCH_ID'], 'systemd-secret-file-tls-v1')
        self.assertEqual(hashlib.sha256(REMOTE['patch_manifest']()).hexdigest(), installer.SECURITY_PATCH_SHA256)
        body = REMOTE['PATCH_CASE']
        self.assertIn('/run/credentials/quantumvpn-mtproto-tls.service/client-secret', body)
        self.assertNotIn('/run/credentials/quantumvpn-mtproto.service/client-secret', body)
        for value in ('O_NOFOLLOW', 'ST_RDONLY', 'S_ISREG', 'info.st_uid == 0', 'info.st_uid == geteuid',
                      'info.st_size != 33', 'got != 33', '== 0400', '== 0440', "f_parse_option ('S')", 'memset (value, 0'):
            self.assertIn(value, body)

    def test_patch_anchors_are_unique_and_cannot_be_reapplied(self):
        sample = ("#include <assert.h>\nvoid f() {\n  case 'S':\n  case 'P':\n}\n"
                  '  parse_option ("mtproto-secret", required_argument, 0, \'S\', "16-byte secret in hex mode");\n')
        patched = REMOTE['patch_source'](sample)
        self.assertEqual(patched.count(REMOTE['PATCH_CASE']), 1)
        self.assertEqual(patched.count(REMOTE['PATCH_OPTION']), 1)
        for invalid in (patched, sample + sample, sample.replace("case 'S'", "case 'Z'")):
            with self.assertRaisesRegex(RuntimeError, 'patch_anchor_mismatch'):
                REMOTE['patch_source'](invalid)

    def test_service_has_no_secret_argv_and_is_bounded_unprivileged(self):
        unit = REMOTE['unit_text']()
        for value in ('User=qvpn-mtproto-tls', 'Group=qvpn-mtproto-tls', 'MemoryMax=384M', 'CPUQuota=50%',
                      'TasksMax=64', 'NoNewPrivileges=true', 'ProtectSystem=strict', 'LimitCORE=0',
                      'LoadCredential=client-secret:/etc/quantumvpn-mtproto-tls/client-secret',
                      '/opt/quantumvpn-mtproto-tls/quantumvpn_mtproto_tls.py --serve'):
            self.assertIn(value, unit)
        self.assertNotIn(' -S ', unit)
        self.assertNotIn('3443', unit)
        self.assertNotIn('quantumvpn-webproxy', unit)
        self.assertNotIn('ExecStart=/bin/sh', unit)

    def test_runtime_three_modules_and_domain_workers_are_recorded(self):
        for value in ("'protocol_sha256':digest(ROOT/'quantumvpn_mtproto_tls_protocol.py')",
                      "'base_module_sha256':digest(ROOT/'quantumvpn_mtproto.py')", "'domain':DOMAIN", "'workers':0",
                      "exclusive(ROOT/'quantumvpn_mtproto_tls_protocol.py',protocol_source.encode()",
                      "exclusive(ROOT/'quantumvpn_mtproto.py',base_module_source.encode()"):
            self.assertIn(value, installer.REMOTE)
        self.assertIn('existing_runtime_changed_review_required', installer.REMOTE)
        self.assertIn("module.get('BASE_MODULE_SHA256')!=BASE_MODULE_SHA256", installer.REMOTE)

    def test_build_source_is_root_owned_only_dep_and_objs_are_user_writable(self):
        body = installer.REMOTE[installer.REMOTE.index('def lock_build_source'):installer.REMOTE.index('def build_pinned_source')]
        self.assertIn('os.chown(source.parent,0,0)', body)
        self.assertIn('os.chown(target,0,0)', body)
        self.assertIn("for name in ('dep','objs')", body)
        self.assertIn('os.chown(target,account.pw_uid,account.pw_gid)', body)
        self.assertIn('source_tree_symlink_refused', body)
        self.assertIn('unexpected_official_build_output_path', body)
        self.assertIn('patched_source_changed_during_build', installer.REMOTE)

    def test_build_children_have_timeout_cpu_memory_and_filesystem_bounds(self):
        calls = Mock(return_value='')
        with patch.dict(REMOTE, {'run': calls}):
            REMOTE['build_pinned_source'](Path('/var/tmp/quantumvpn-mtproto-tls-build-test/source'))
        argv = calls.call_args.args[0]
        for value in ('--property=User=qvpn-mtproto-tls', '--property=MemoryMax=768M', '--property=CPUQuota=50%',
                      '--property=RuntimeMaxSec=300', '--property=KillMode=control-group', '--property=ProtectSystem=strict',
                      '--property=TemporaryFileSystem=/tmp:rw,size=128M,mode=1777,nosuid,nodev',
                      '--property=NoNewPrivileges=yes', '-j1', 'CC=gcc -fcommon', 'COMMIT=' + REMOTE['COMMIT']):
            self.assertIn(value, argv)
        self.assertEqual(calls.call_args.args[1], 360)
        self.assertNotIn('root', argv)
        self.assertNotIn('--property=PrivateTmp=yes', argv)
        self.assertNotIn('--property=TemporaryFileSystem=/var/tmp', argv)

    def test_only_new_service_is_ever_targeted_by_mutating_systemctl(self):
        tree = ast.parse(installer.REMOTE)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run' and node.args:
                command = node.args[0]
                if isinstance(command, ast.List) and command.elts and isinstance(command.elts[0], ast.Constant) and command.elts[0].value == 'systemctl':
                    if command.elts[1].value != 'daemon-reload':
                        self.assertIsInstance(command.elts[-1], ast.Name)
                        self.assertEqual(command.elts[-1].id, 'SERVICE')

    def test_recovery_moves_only_exact_new_paths_to_private_backup(self):
        for value in ('rollback_target_not_managed', 'rollback_identity_changed_manual_review_required',
                      'rollback_unit_changed_manual_review_required', "parent.mkdir(mode=0o700,exist_ok=True)",
                      "Path('/var/lib/quantumvpn-mtproto-tls-failed')", 'path.rename(destination/recovery_names[path])',
                      "target.name.startswith('quantumvpn-mtproto-tls-build-')", "target.parent!=Path('/var/tmp')"):
            self.assertIn(value, installer.REMOTE)
        self.assertNotIn('shutil.rmtree(ROOT)', installer.REMOTE)
        self.assertNotIn('shutil.rmtree(PRIVATE)', installer.REMOTE)


class RuntimeAndReadOnlyTests(unittest.TestCase):
    def test_real_runtime_modules_load_in_memory_and_accept_installer_schema(self):
        tools = Path(__file__).parent
        names = ('quantumvpn_mtproto_tls.py', 'quantumvpn_mtproto_tls_protocol.py', 'quantumvpn_mtproto.py')
        sources = [(tools / name).read_bytes() for name in names]
        module = REMOTE['load_runtime_modules'](*(source.decode() for source in sources))
        self.assertEqual(module['COMMIT'], REMOTE['COMMIT'])
        self.assertEqual(module['PUBLIC_PORT'], REMOTE['PORT'])
        self.assertEqual(module['STATS_PORT'], REMOTE['STATS_PORT'])
        self.assertEqual(module['SECURITY_PATCH_SHA256'], installer.SECURITY_PATCH_SHA256)
        self.assertEqual(module['BASE_MODULE_SHA256'], hashlib.sha256(sources[2]).hexdigest())
        config = {'schema': 1, 'managed_by': 'quantumvpn', 'commit': REMOTE['COMMIT'], 'source': REMOTE['SOURCE'],
                  'server': REMOTE['HOST'], 'domain': REMOTE['DOMAIN'], 'port': REMOTE['PORT'],
                  'stats_port': REMOTE['STATS_PORT'], 'created_at': 1700000000, 'workers': 0,
                  'binary_sha256': 'a' * 64, 'module_sha256': hashlib.sha256(sources[0]).hexdigest(),
                  'protocol_sha256': hashlib.sha256(sources[1]).hexdigest(),
                  'base_module_sha256': hashlib.sha256(sources[2]).hexdigest(),
                  'security_patch': REMOTE['PATCH_ID'], 'patch_sha256': installer.SECURITY_PATCH_SHA256,
                  'source_file_sha256': REMOTE['BASE_SOURCE_SHA256'], 'compiler': 'gcc -fcommon'}
        self.assertEqual(module['_validate_config'](config), config)

    def test_decode_runtime_has_bound_and_digest_guard(self):
        import base64
        value = b'VALUE=1\n'
        encoded = base64.b64encode(value).decode()
        expected = hashlib.sha256(value).hexdigest()
        self.assertEqual(REMOTE['decode_runtime'](encoded, expected), value.decode())
        for raw, digest in ((encoded, '0' * 64), ('', expected), ('not-base64!', expected)):
            with self.subTest(raw=raw), self.assertRaises(Exception):
                REMOTE['decode_runtime'](raw, digest)

    def test_temporary_modules_restore_previous_imports_after_load(self):
        previous_base = SimpleNamespace(original=True)
        previous_protocol = SimpleNamespace(original=True)
        with patch.dict(sys.modules, {'quantumvpn_mtproto': previous_base, 'quantumvpn_mtproto_tls_protocol': previous_protocol}):
            result = REMOTE['load_runtime_modules']('import quantumvpn_mtproto_tls_protocol as p\nRESULT=p.VALUE\n',
                 'import quantumvpn_mtproto as base\nVALUE=base.VALUE+1\n', 'VALUE=7\n')
            self.assertEqual(result['RESULT'], 8)
            self.assertIs(sys.modules['quantumvpn_mtproto'], previous_base)
            self.assertIs(sys.modules['quantumvpn_mtproto_tls_protocol'], previous_protocol)

    def test_temporary_modules_restore_even_if_helper_has_syntax_error(self):
        before = dict((name, sys.modules.get(name)) for name in ('quantumvpn_mtproto', 'quantumvpn_mtproto_tls_protocol'))
        with self.assertRaises(SyntaxError):
            REMOTE['load_runtime_modules']('not valid syntax!!!', 'VALUE=2\n', 'VALUE=1\n')
        for name, value in before.items():
            self.assertIs(sys.modules.get(name), value)

    def test_default_readonly_does_not_download_create_lock_install_or_restart(self):
        helper = {'COMMIT': REMOTE['COMMIT'], 'PUBLIC_PORT': 5443, 'STATS_PORT': 18889,
                  'DOMAIN': REMOTE['DOMAIN'], 'SECURITY_PATCH': REMOTE['PATCH_ID'],
                  'SECURITY_PATCH_SHA256': installer.SECURITY_PATCH_SHA256,
                  'BASE_MODULE_SHA256': REMOTE['BASE_MODULE_SHA256'],
                  'snapshot': Mock(return_value={'installed': False}), 'health_probe': Mock()}
        forbidden = {name: Mock(side_effect=AssertionError(name)) for name in
                     ('install_lock', 'official_data', 'exclusive', 'rollback_created', 'run', 'build_pinned_source')}
        output = io.StringIO()
        with patch.dict(REMOTE, {'APPLY': False, 'load_runtime_modules': Mock(return_value=helper),
             'decode_runtime': Mock(return_value='source'), 'safe_parent': Mock(),
             'protected_identity': Mock(return_value={'same': 'hash'}), 'managed_install': Mock(return_value=False),
             'missing_packages': Mock(return_value=[]), 'require_free_ports': Mock(), **forbidden}), \
             patch.object(REMOTE['os'], 'geteuid', return_value=0, create=True), \
             patch.object(REMOTE['platform'], 'machine', return_value='x86_64'), contextlib.redirect_stdout(output):
            REMOTE['main']()
        self.assertEqual(json.loads(output.getvalue())['mode'], 'read_only')
        for function in forbidden.values():
            function.assert_not_called()
        helper['health_probe'].assert_not_called()

    def test_existing_apply_preserves_owner_stop_without_reenable(self):
        code = installer.REMOTE
        branch = code[code.index('    if existing:\n'):code.index("    if missing:raise RuntimeError")]
        self.assertIn('service_state_preserved', branch)
        self.assertNotIn('systemctl', branch)
        self.assertNotIn('exclusive', branch)

    def test_ports_ipv4_ipv6_and_stats_loopback_are_checked(self):
        for listen in ('0.0.0.0:5443', '[::]:5443', '127.0.0.1:18889', '[::1]:18889'):
            with self.subTest(listen=listen), patch.dict(REMOTE, {'run': Mock(return_value=f'LISTEN 0 128 {listen} 0.0.0.0:*\n')}):
                with self.assertRaisesRegex(RuntimeError, 'requested_port_occupied'):
                    REMOTE['require_free_ports']()
        with patch.dict(REMOTE, {'run': Mock(return_value='LISTEN 0 128 127.0.0.1:18889 0.0.0.0:*\n')}):
            REMOTE['verify_stats_listener']()
        for listen in ('0.0.0.0:18889', '[::]:18889', '[::1]:18889'):
            with patch.dict(REMOTE, {'run': Mock(return_value=f'LISTEN 0 128 {listen} 0.0.0.0:*\n')}):
                with self.assertRaisesRegex(RuntimeError, 'stats_listener_not_exclusively_loopback'):
                    REMOTE['verify_stats_listener']()

    def test_official_download_redirects_do_not_allow_unknown_hosts(self):
        for target in ('http://core.telegram.org/x', 'https://evil.example/x', 'https://core.telegram.org.evil.example/x'):
            with self.assertRaisesRegex(RuntimeError, 'official_download_redirect_refused'):
                REMOTE['OfficialRedirect']().redirect_request(None, None, 302, '', {}, target)

    def test_errors_do_not_report_raw_output_or_secret(self):
        output = io.StringIO()
        with patch.object(REMOTE['subprocess'], 'run', return_value=Mock(returncode=1, stdout='secret-value', stderr='gcc: fatal error: read-only file system /tmp/private')), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError, '^server_command_failed_binary_build$'):
                REMOTE['run'](['make'], stage='binary_build')
        value = json.loads(output.getvalue())
        self.assertEqual(value['status'], 'BuildFailed')
        self.assertTrue(value['build_error_classification']['readonly_fs'])
        self.assertTrue(value['build_error_classification']['tmp_mentioned'])
        self.assertNotIn('secret-value', output.getvalue())
        self.assertNotIn('/tmp/private', output.getvalue())

    def test_only_binary_build_failure_is_classified_other_errors_stay_redacted(self):
        output = io.StringIO()
        with patch.object(REMOTE['subprocess'], 'run', return_value=Mock(returncode=1, stdout='secret', stderr='secret')) as execute, contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError, '^server_command_failed_source_fetch$'):
                REMOTE['run'](['git'], stage='source_fetch')
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(execute.call_args.kwargs['stderr'], REMOTE['subprocess'].DEVNULL)

    def test_classifier_is_bounded_boolean_only_and_detects_allowed_categories(self):
        result = REMOTE['classify_build_error']('gcc: fatal error: /tmp/file: Read-only file system',
                    'Permission denied ENOENT Failed to start transient service unit secret-value')
        self.assertTrue(all(type(value) is bool for value in result.values()))
        self.assertTrue(all(value for key, value in result.items() if key != 'unclassified'))
        self.assertFalse(result['unclassified'])
        self.assertNotIn('secret-value', json.dumps(result))
        self.assertEqual(REMOTE['classify_build_error'](None, None)['unclassified'], True)
        self.assertTrue(REMOTE['classify_build_error']('x' * 1000000 + ' EROFS', '')['readonly_fs'])


if __name__ == '__main__':
    unittest.main()
