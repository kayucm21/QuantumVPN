"""Offline installer guards: no SSH, downloads, builds or real services."""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('web_installer', Path(__file__).with_name('install-webproxy-vds.py'))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
REMOTE = {'RUN_REMOTE': False, 'APPLY': False, 'RELAY_ONLY': False, 'BASE_PATH': ''}
with patch.dict(sys.modules, {'fcntl': Mock(), 'pwd': Mock()}):
    exec(compile(installer.REMOTE, '<web-installer-offline>', 'exec'), REMOTE)


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name, value, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = '/etc/passwd'
            elif kind == tarfile.REGTYPE:
                info.size = len(value)
            tar.addfile(info, io.BytesIO(value) if kind == tarfile.REGTYPE else None)
    return stream.getvalue()


class InstallerContractTests(unittest.TestCase):
    def test_python_syntax_and_pinned_official_sources(self):
        ast.parse(installer.REMOTE)
        self.assertEqual(REMOTE['COMMIT'], 'c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8')
        self.assertEqual(REMOTE['ARCHIVE_SIZE'], 139727)
        self.assertEqual(REMOTE['GO_SIZE'], 70553950)
        self.assertEqual(REMOTE['ARCHIVE_SHA256'], 'a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549')
        self.assertEqual(REMOTE['GO_SHA256'], '63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445')
        self.assertTrue(REMOTE['ARCHIVE_URL'].startswith('https://codeload.github.com/telegramdesktop/tproxy-server/tar.gz/'))
        self.assertEqual(REMOTE['GO_URL'], 'https://dl.google.com/go/go1.27.1.linux-amd64.tar.gz')

    def test_unit_uses_unprivileged_credentials_and_resource_bounds(self):
        unit = REMOTE['unit_text']()
        for expected in ('User=qvpn-webproxy', 'Group=qvpn-webproxy', 'RuntimeDirectoryMode=0700',
                         'MemoryMax=384M', 'CPUQuota=50%', 'TasksMax=64',
                         'ProtectSystem=strict', 'NoNewPrivileges=true', 'LimitCORE=0'):
            self.assertIn(expected, unit)
        for name in ('config.json', 'profiles.json', 'manifest.json', 'token.key'):
            self.assertIn(f'LoadCredential={name}:/etc/quantumvpn-webproxy/{name}', unit)
        self.assertIn('--serve', unit)
        self.assertNotIn('Environment=TPROXY_LEGACY_TOKEN_DRAIN', unit)
        self.assertNotIn('--secret', unit)
        self.assertNotIn('ReadWritePaths=/etc', unit)
        self.assertNotIn('Requires=quantumvpn-mtproto.service', unit)

    def test_config_has_no_public_listener_or_guessed_backend(self):
        config = REMOTE['config']('qweb-0123456789ab')
        self.assertEqual(config['listen'], '127.0.0.1:18082')
        self.assertEqual(config['admin_listen'], '127.0.0.1:18083')
        self.assertEqual(config['public_upstream'], 'http://127.0.0.1:8080')
        self.assertNotIn('public_dir', config)
        self.assertEqual(config['profiles_file'], '/run/credentials/quantumvpn-webproxy.service/profiles.json')
        self.assertEqual(config['token_key_file'], '/run/quantumvpn-webproxy/token.key')
        self.assertIs(config['enable_pprof'], False)
        self.assertEqual(config['limits']['max_pending_global'], 64 * 1024 * 1024)
        self.assertEqual(config['limits']['max_pending_per_session'], 8 * 1024 * 1024)
        self.assertEqual(config['limits']['max_sessions_global'], 32)

    def test_private_prefix_strict_no_path_escape_or_payload(self):
        for value in ('', '/qweb-0123456789ab', 'qweb-0123456789ab/', 'qweb-AAAA0123456789',
                      'qweb-0123456789ab/other', 'qweb-0123456789ab\n', 'qweb-0123',
                      'qweb-../etc/passwd', 'qweb-%2f0123456789ab', 'qweb-' + 'x' * 49, True):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                REMOTE['base_path'](value)
        self.assertEqual(REMOTE['base_path']('qweb-0123456789ab'), 'qweb-0123456789ab')

    def test_existing_plain_secret_single_profile_not_fake_web_link(self):
        profile = REMOTE['profiles']('a' * 32)['profiles']
        self.assertEqual(profile, [{'name': 'quantumvpn', 'secret': 'a' * 32,
                                    'backend': '127.0.0.1:3443', 'carrier_mode': 'https'}])
        for value in ('a' * 31, 'A' * 32, 'dd' + 'a' * 32, 'a' * 32 + '\n', None):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                REMOTE['profiles'](value)

    def test_default_main_returns_before_any_mutation_or_remote_download(self):
        inventory = {'status': 'ReadOnly', 'public_ready': False}
        mutations = {name: Mock(side_effect=AssertionError(name)) for name in
                     ('download', 'load_helper', 'user_identity', 'build', 'exclusive', 'protected_snapshot', 'listeners', 'run')}
        output = io.StringIO()
        with patch.dict(REMOTE, {'APPLY': False, 'read_only_inventory': Mock(return_value=inventory), **mutations}), contextlib.redirect_stdout(output):
            REMOTE['main']()
        self.assertEqual(json.loads(output.getvalue()), inventory)
        for function in mutations.values():
            function.assert_not_called()

    def test_apply_without_relay_only_is_rejected_before_helper_loading(self):
        guard = Mock(side_effect=AssertionError('must not load helper'))
        with patch.dict(REMOTE, {'APPLY': True, 'RELAY_ONLY': False,
                                'read_only_inventory': Mock(return_value={'installed': False}), 'load_helper': guard}):
            with self.assertRaisesRegex(RuntimeError, 'public_front_integration_not_authorized'):
                REMOTE['main']()
        guard.assert_not_called()

    def test_only_fixed_new_service_is_ever_mutated(self):
        tree = ast.parse(installer.REMOTE)
        commands = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run':
                if node.args and isinstance(node.args[0], ast.List):
                    values = [n.value if isinstance(n, ast.Constant) else n.id if isinstance(n, ast.Name) else None
                              for n in node.args[0].elts]
                    commands.append(values)
        for command in commands:
            self.assertNotIn(command[0], ('apt', 'apt-get', 'caddy', 'nginx', 'sh', 'bash', 'curl', 'wget', 'git'))
            if command[0] == 'systemctl' and command[1] != 'daemon-reload':
                self.assertEqual(command[-1], 'SERVICE')
        for denied in ('caddy reload', 'nginx -s', 'install.sh', 'shell=True', 'AutoAddPolicy', 'sftp.put'):
            self.assertNotIn(denied, installer.REMOTE)

    def test_temp_cleanup_and_rollback_are_identity_guarded(self):
        self.assertIn("target.parent==Path('/opt')", installer.REMOTE)
        self.assertIn("target.name.startswith('quantumvpn-webproxy-build-')", installer.REMOTE)
        self.assertIn('(path.stat().st_dev,path.stat().st_ino)==(device,inode)', installer.REMOTE)
        self.assertIn("recovery.mkdir(mode=0o700)", installer.REMOTE)
        self.assertIn('os.rename(path,recovery/path.name)', installer.REMOTE)
        self.assertNotIn('os.unlink(UNIT)', installer.REMOTE)

    def test_build_integrity_and_bounded_private_toolchain(self):
        for expected in ('GO_MOD_SHA256', 'GO_SUM_SHA256', '--setenv=GOTOOLCHAIN=local',
                         '--setenv=GOFLAGS=-mod=readonly', '--setenv=GOSUMDB=sum.golang.org',
                         '--setenv=GOPROXY=https://proxy.golang.org', '--setenv=GOENV=off',
                         '--property=MemoryMax=768M', '--property=RuntimeMaxSec=600',
                         "['test','-p','1','-timeout','120s','./...']", "['mod','verify']"):
            self.assertIn(expected, installer.REMOTE)
        self.assertIn("os.rename(toolchain,ROOT/'toolchain/go')", installer.REMOTE)
        self.assertNotIn('/usr/local/go', installer.REMOTE)


class DownloadAndArchiveTests(unittest.TestCase):
    def test_download_rejects_unknown_source_before_network(self):
        network = Mock(side_effect=AssertionError('network must not be used'))
        with patch.object(REMOTE['urllib'].request, 'build_opener', network):
            for url in ('http://dl.google.com/go/anything', 'https://evil.example/archive', REMOTE['GO_URL']):
                with self.subTest(url=url), self.assertRaises(RuntimeError):
                    REMOTE['download'](url, '0' * 64, 123)
        network.assert_not_called()

    def test_download_exact_length_and_digest_are_required(self):
        raw = b'private test bytes'
        expected = hashlib.sha256(raw).hexdigest()
        for payload in (raw, raw + b'x', raw[:-1], b'X' * len(raw)):
            response = Mock(status=200)
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read = Mock(return_value=payload)
            opener = Mock()
            opener.open.return_value = response
            with patch.dict(REMOTE, {'ARCHIVE_SHA256': expected, 'ARCHIVE_SIZE': len(raw)}), \
                    patch.object(REMOTE['urllib'].request, 'build_opener', return_value=opener):
                if payload == raw:
                    self.assertEqual(REMOTE['download'](REMOTE['ARCHIVE_URL'], expected, len(raw)), raw)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'download_identity_mismatch'):
                        REMOTE['download'](REMOTE['ARCHIVE_URL'], expected, len(raw))

    def test_http_redirect_is_never_followed(self):
        with self.assertRaisesRegex(RuntimeError, 'download_redirect_refused'):
            REMOTE['NoRedirect']().redirect_request(None, None, 302, '', {}, 'https://evil.example/')

    def test_archive_regular_files_are_extracted_without_modes_from_archive(self):
        data = archive([('root/', b'', tarfile.DIRTYPE), ('root/a.txt', b'hello', tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            REMOTE['extract_archive'](data, path, 'root', 10, 100)
            self.assertEqual((path / 'a.txt').read_bytes(), b'hello')

    def test_archive_traversal_links_devices_and_duplicates_are_rejected_before_writes(self):
        cases = [
            [('root/../outside', b'x', tarfile.REGTYPE)],
            [('/root/file', b'x', tarfile.REGTYPE)],
            [('other/file', b'x', tarfile.REGTYPE)],
            [('root/link', b'', tarfile.SYMTYPE)],
            [('root/link', b'', tarfile.LNKTYPE)],
            [('root/device', b'', tarfile.CHRTYPE)],
            [('root/f', b'a', tarfile.REGTYPE), ('root//f', b'b', tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as folder:
                path = Path(folder)
                with self.assertRaises(RuntimeError):
                    REMOTE['extract_archive'](archive(entries), path, 'root', 10, 100)
                self.assertEqual(list(path.iterdir()), [])

    def test_archive_count_and_uncompressed_byte_limits_are_bounded(self):
        data = archive([('root/a', b'12345', tarfile.REGTYPE), ('root/b', b'12345', tarfile.REGTYPE)])
        for count, size in ((1, 100), (10, 9)):
            with tempfile.TemporaryDirectory() as folder, self.assertRaises(RuntimeError):
                REMOTE['extract_archive'](data, Path(folder), 'root', count, size)

    def test_exclusive_never_overwrites_existing_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'token.key'
            REMOTE['exclusive'](path, b'old persistent key')
            with self.assertRaises(FileExistsError):
                REMOTE['exclusive'](path, b'new key')
            self.assertEqual(path.read_bytes(), b'old persistent key')

    def test_run_failure_suppresses_raw_error_details(self):
        result = SimpleNamespace(returncode=1, stdout='SECRET upstream error')
        with patch.object(REMOTE['subprocess'], 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, '^command_failed_go_build$'):
                REMOTE['run'](['/private/go', 'build'], stage='go_build')


if __name__ == '__main__':
    unittest.main()
