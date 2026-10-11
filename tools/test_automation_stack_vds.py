"""Offline safety gates: no SSH/network/service mutation during these tests."""
import importlib.util
import ast
import copy
import gzip
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('automation_install', Path(__file__).with_name('install-automation-stack-vds.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AutomationSafetyTests(unittest.TestCase):
    @staticmethod
    def bundled_lock_fixture():
        specs = module.bundled_parent_specs('openclaw', module.PINS)
        packages = {'': {}}
        for path, spec in specs.items():
            packages[path] = {k: spec[k] for k in ('version', 'resolved', 'integrity')}
        packages['node_modules/npm/node_modules/@gar/promise-retry'] = {'version': '1.0.3', 'inBundle': True}
        return {'lockfileVersion': 3, 'packages': packages}

    def test_actual_bundled_lock_requires_verified_carrier_and_exact_identity(self):
        lock = self.bundled_lock_fixture()
        loader = Mock(return_value={'node_modules/@gar/promise-retry': {'name': '@gar/promise-retry', 'version': '1.0.3'}})
        facts = module.bundled_provenance(lock, 'openclaw', module.PINS, loader)
        loader.assert_called_once_with(module.bundled_parent_specs('openclaw', module.PINS)['node_modules/npm'])
        self.assertEqual(64, len(module.validate_lock(lock, 'openclaw', module.PINS, facts)))
        with self.assertRaisesRegex(module.GuardError, 'unverified_bundled_dependency'):
            module.validate_lock(lock, 'openclaw', module.PINS)
        path = 'node_modules/npm/node_modules/@gar/promise-retry'
        for changed in [{'resolved': 'https://attacker.example/a.tgz'}, {'resolved': 'https://registry.npmjs.org/a/-/a-1.tgz'}, {'integrity': 'sha512-abc'}, {'inBundle': 'true'}]:
            bad = copy.deepcopy(lock); bad['packages'][path].update(changed)
            with self.assertRaisesRegex(module.GuardError, 'unverified_bundled_dependency'):
                module.validate_lock(bad, 'openclaw', module.PINS, facts)
        for changed in [{'version': '9.9.9'}, {'name': 'foreign'}]:
            bad = copy.deepcopy(lock); bad['packages'][path].update(changed)
            with self.assertRaisesRegex(module.GuardError, 'bundled_dependency_provenance_mismatch'):
                module.validate_lock(bad, 'openclaw', module.PINS, facts)
        for changed in [{'parent_integrity': 'sha512-untrusted'}, {'name': 'foreign'}, {'version': '0.0.0'}, {'parent': 'node_modules/foreign'}]:
            bad_facts = copy.deepcopy(facts); bad_facts[path].update(changed)
            with self.assertRaises(module.GuardError):
                module.validate_lock(lock, 'openclaw', module.PINS, bad_facts)

    def test_actual_bundled_provenance_refuses_orphans_changed_parent_and_other_installs(self):
        lock = self.bundled_lock_fixture(); loader = Mock()
        for change in [{'version': '11.20.1'}, {'resolved': 'https://attacker.example/npm.tgz'}, {'integrity': 'sha1-untrusted'}, {'inBundle': True}, {'link': True}]:
            bad = copy.deepcopy(lock); bad['packages']['node_modules/npm'].update(change)
            with self.assertRaisesRegex(module.GuardError, 'bundled_parent_pin_mismatch|unreviewed_bundled_parent'):
                module.bundled_provenance(bad, 'openclaw', module.PINS, loader)
        for bad_name, bad_path in [('n8n', 'node_modules/npm/node_modules/@gar/promise-retry'), ('openclaw', 'node_modules/foreign/node_modules/@gar/promise-retry')]:
            bad = copy.deepcopy(lock); entry = bad['packages'].pop('node_modules/npm/node_modules/@gar/promise-retry'); bad['packages'][bad_path] = entry
            with self.assertRaisesRegex(module.GuardError, 'unreviewed_bundled_parent'):
                module.bundled_provenance(bad, bad_name, module.PINS, loader)
        loader.assert_not_called()

    def test_actual_bundle_archive_stream_checks_digest_paths_and_descriptors(self):
        def archive_bytes(root_name='npm', child_name='@gar/promise-retry', unsafe=None):
            result = io.BytesIO()
            with tarfile.open(fileobj=result, mode='w:gz') as archive:
                contents = {
                    'package/package.json': {'name': root_name, 'version': '11.20.0', 'bundleDependencies': ['@gar/promise-retry']},
                    'package/node_modules/@gar/promise-retry/package.json': {'name': child_name, 'version': '1.0.3'},
                    # Module-format markers are not package roots/provenance.
                    'package/node_modules/@gar/promise-retry/dist/esm/package.json': {'type': 'module'},
                }
                for path, value in contents.items():
                    data = json.dumps(value).encode(); member = tarfile.TarInfo(path); member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                if unsafe:
                    member = tarfile.TarInfo(unsafe)
                    if unsafe.endswith('link'):
                        member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'
                    archive.addfile(member)
            return result.getvalue()
        def spec_for(content):
            return {'name': 'npm', 'version': '11.20.0', 'integrity': 'sha512-' + module.base64.b64encode(module.hashlib.sha512(content).digest()).decode()}
        content = archive_bytes(); spec = spec_for(content)
        self.assertEqual({'node_modules/@gar/promise-retry': {'name': '@gar/promise-retry', 'version': '1.0.3'}}, module.bundle_archive_packages(io.BytesIO(content), spec))
        with self.assertRaisesRegex(module.GuardError, 'bundled_archive_integrity_mismatch'):
            module.bundle_archive_packages(io.BytesIO(content), dict(spec, integrity='sha512-untrusted'))
        for unsafe in ['package/../../escape', '/absolute', 'package/unsafe-link', 'package/node_modules/foo\\escape']:
            bad = archive_bytes(unsafe=unsafe)
            with self.assertRaisesRegex(module.GuardError, 'unsafe_bundled_archive_member'):
                module.bundle_archive_packages(io.BytesIO(bad), spec_for(bad))
        bad = archive_bytes(root_name='foreign')
        with self.assertRaisesRegex(module.GuardError, 'bundled_archive_parent_identity_mismatch'):
            module.bundle_archive_packages(io.BytesIO(bad), spec_for(bad))
        bad = archive_bytes(child_name='foreign')
        with self.assertRaisesRegex(module.GuardError, 'bundled_archive_package_identity_mismatch'):
            module.bundle_archive_packages(io.BytesIO(bad), spec_for(bad))
        with patch('time.monotonic', side_effect=[0, 121]):
            with self.assertRaisesRegex(module.GuardError, 'bundled_archive_read_budget'):
                module.bundle_archive_packages(io.BytesIO(content), spec)

    def test_actual_bundle_loader_refuses_foreign_spec_and_redirect_before_provenance(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'load_bundled_archive')
        urlopen, inspect = Mock(), Mock()
        ns = {'GuardError': module.GuardError, 'PINS': module.PINS, 'bundled_parent_specs': module.bundled_parent_specs,
              'urllib': SimpleNamespace(request=SimpleNamespace(urlopen=urlopen)), 'bundle_archive_packages': inspect}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<bundle-loader>', 'exec'), ns)
        spec = module.bundled_parent_specs('openclaw', module.PINS)['node_modules/npm']
        with self.assertRaisesRegex(module.GuardError, 'unreviewed_bundled_archive_spec'):
            ns['load_bundled_archive'](dict(spec, resolved='https://attacker.example/archive'))
        urlopen.assert_not_called(); inspect.assert_not_called()
        response = Mock(); response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.status = 200; response.geturl.return_value = 'https://attacker.example/archive'; urlopen.return_value = response
        with self.assertRaisesRegex(module.GuardError, 'bundled_archive_redirect_or_status'):
            ns['load_bundled_archive'](spec)
        inspect.assert_not_called()
        response.geturl.return_value = spec['resolved']; inspect.return_value = {'verified': 'fixture'}
        self.assertEqual({'verified': 'fixture'}, ns['load_bundled_archive'](spec))
        inspect.assert_called_once_with(response, spec)

    def test_actual_bundle_checksum_precedes_hidden_gnu_and_pax_payload_parsing(self):
        spec = module.bundled_parent_specs('openclaw', module.PINS)['node_modules/npm']
        for kind in [tarfile.GNUTYPE_LONGNAME, tarfile.XHDTYPE, tarfile.XGLTYPE]:
            # Tiny compressed input advertises a hidden 600 MiB metadata payload.
            # tarfile processes this before yielding a member; never hand it the
            # unverified bytes (and don't allocate the fake payload in this test).
            header = tarfile.TarInfo('././@LongLink')
            header.type = kind; header.size = 600 * 1024 * 1024
            malicious = gzip.compress(header.tobuf(format=tarfile.GNU_FORMAT) + b'\0' * 1024)
            self.assertLess(len(malicious), 1024)
            reader = Mock(wraps=io.BytesIO(malicious))
            with patch('tarfile.open') as parser:
                with self.assertRaisesRegex(module.GuardError, 'bundled_archive_integrity_mismatch'):
                    module.bundle_archive_packages(reader, spec)
                parser.assert_not_called()
            self.assertTrue(reader.read.call_args_list)
            self.assertTrue(all(c.args == (1024 * 1024,) for c in reader.read.call_args_list))

    def test_actual_bundle_compressed_budget_is_disk_spooled_and_never_parsed_on_failure(self):
        spec = module.bundled_parent_specs('openclaw', module.PINS)['node_modules/npm']
        reader = Mock(); reader.read.return_value = b'a' * (1024 * 1024)
        disk = Mock(); disk.__enter__ = Mock(return_value=disk); disk.__exit__ = Mock(return_value=False)
        with patch('tempfile.TemporaryFile', return_value=disk) as temporary, patch('tarfile.open') as parser, patch('time.monotonic', return_value=0):
            with self.assertRaisesRegex(module.GuardError, 'bundled_archive_read_budget'):
                module.bundle_archive_packages(reader, spec)
            temporary.assert_called_once_with(mode='w+b', prefix='qvpn-bundle-audit-')
            self.assertEqual(160, disk.write.call_count)
            self.assertEqual(161, reader.read.call_count)
            parser.assert_not_called(); disk.seek.assert_not_called()

    def test_actual_installed_bundle_identity_and_symlink_gate(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'validate_installed_bundles')
        ns = {'GuardError': module.GuardError, 'PurePosixPath': module.PurePosixPath, 'json': json,
              'package_path_name': module.package_path_name}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<installed-bundles>', 'exec'), ns)
        stage = Path('C:/automation-test/release/qvpn-openclaw-build-fixture').resolve()
        lock = self.bundled_lock_fixture()
        path = 'node_modules/npm/node_modules/@gar/promise-retry'
        facts = {path: {'name': '@gar/promise-retry', 'version': '1.0.3'}}
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'read_text', return_value=json.dumps(facts[path])):
            ns['validate_installed_bundles'](stage, lock, facts)
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaisesRegex(module.GuardError, 'unsafe_installed_bundled_package'):
                ns['validate_installed_bundles'](stage, lock, facts)
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'read_text', return_value=json.dumps({'name': '@gar/promise-retry', 'version': '9.9.9'})):
            with self.assertRaisesRegex(module.GuardError, 'installed_bundled_package_identity_mismatch'):
                ns['validate_installed_bundles'](stage, lock, facts)

    def test_actual_direct_native_builder_argv_paths_and_budget(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'npm_command')
        release = Path('C:/automation-test/release').resolve()
        stage = release / 'qvpn-n8n-build-fixture'
        account = SimpleNamespace(pw_name='qvpn-automation-build')
        ns = {'GuardError': module.GuardError, 'RELEASE': str(release), 'STATE': module.STATE,
              'PRIVATE': module.PRIVATE, 'PROTECTED_PATHS': module.PROTECTED_PATHS, 'Path': Path,
              'os': SimpleNamespace(getpid=lambda: 123),
              'command': Mock(return_value=subprocess.CompletedProcess([], 0, stdout='', stderr=''))}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<native-builder>', 'exec'), ns)
        args = ['rebuild', '--directory=node_modules/isolated-vm', '--release', '--jobs=1']
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False):
            ns['npm_command'](release, stage, account, args, 'n8n-isolated-vm', direct_node_gyp=True)
            argv = ns['command'].call_args.args[0]
            self.assertEqual([str(release / 'node/bin/node'), str(release / 'node/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js'), *args], argv[-6:])
            for expected in ['WorkingDirectory=' + str(stage), 'MemoryMax=1536M', 'MemorySwapMax=0', 'CPUQuota=35%', 'RuntimeMaxSec=1800', '--setenv=MAKEFLAGS=-j1', '--setenv=npm_config_jobs=1']:
                self.assertIn(expected, argv)
            ns['command'].reset_mock()
            for bad_stage, bad_args in [(release / 'foreign', args), (stage, ['rebuild', '--directory=../outside', '--release', '--jobs=1'])]:
                with self.assertRaisesRegex(module.GuardError, 'unexpected_native_build_entrypoint'):
                    ns['npm_command'](release, bad_stage, account, bad_args, 'n8n-isolated-vm', direct_node_gyp=True)
            ns['command'].assert_not_called()

    def test_actual_native_plan_is_serial_and_failure_stops_second_builder(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'build_n8n_native')
        ns = {'npm_command': Mock()}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<native-plan>', 'exec'), ns)
        ns['build_n8n_native']('release', 'owned-stage', 'account', ['--omit=dev'])
        calls = ns['npm_command'].call_args_list
        self.assertEqual(['n8n-sqlite3', 'n8n-isolated-vm'], [c.args[4] for c in calls])
        self.assertIn('--build-from-source', calls[0].args[3])
        self.assertEqual({'direct_node_gyp': True}, calls[1].kwargs)
        self.assertIn('--jobs=1', calls[1].args[3])
        ns['npm_command'].reset_mock(); ns['npm_command'].side_effect = module.GuardError('first_builder_failed')
        with self.assertRaises(module.GuardError):
            ns['build_n8n_native']('release', 'owned-stage', 'account', [])
        self.assertEqual(1, ns['npm_command'].call_count)

    def test_actual_native_versions_match_frozen_dependency_graph(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'validate_native_versions')
        ns = {'GuardError': module.GuardError, 'PurePosixPath': module.PurePosixPath, 'json': json}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<native-versions>', 'exec'), ns)
        lock = {'packages': {'node_modules/isolated-vm': {'version': '7.0.1'}, 'node_modules/n8n/node_modules/sqlite3': {'version': '5.1.7'}}}
        def package_json(path):
            name = path.parent.name
            return json.dumps({'name': name, 'version': '7.0.1' if name == 'isolated-vm' else '5.1.7'})
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'read_text', package_json):
            ns['validate_native_versions'](Path('C:/owned-stage'), lock)
            with self.assertRaisesRegex(module.GuardError, 'native_package_lock_missing'):
                ns['validate_native_versions'](Path('C:/owned-stage'), {'packages': {}})
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'read_text', return_value=json.dumps({'name': 'isolated-vm', 'version': '0.0.0'})):
            with self.assertRaisesRegex(module.GuardError, 'native_package_version_drift'):
                ns['validate_native_versions'](Path('C:/owned-stage'), lock)

    def test_actual_n8n_probe_requires_database_readiness_and_editor(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'service_probe')
        class Response:
            def __init__(self, status): self.status = status
            def __enter__(self): return self
            def __exit__(self, *_): return False
        urlopen = Mock()
        ns = {'GuardError': module.GuardError, 'SERVICES': module.SERVICES, 'PORTS': module.PORTS,
              'is_active': Mock(return_value=True), 'urllib': SimpleNamespace(request=SimpleNamespace(urlopen=urlopen)),
              'command': Mock(return_value=subprocess.CompletedProcess([], 0, stdout='LISTEN 0 128 127.0.0.1:5678 *:*\n'))}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<service-probe>', 'exec'), ns)
        for responses in [[Response(503)], [Response(200), Response(503)]]:
            urlopen.side_effect = responses
            self.assertFalse(ns['service_probe']('n8n'))
            ns['command'].assert_not_called()
        urlopen.reset_mock(); urlopen.side_effect = [Response(200), Response(200)]
        self.assertTrue(ns['service_probe']('n8n'))
        self.assertEqual(['http://127.0.0.1:5678/healthz/readiness', 'http://127.0.0.1:5678/'], [c.args[0] for c in urlopen.call_args_list])

    def test_existing_and_created_users_cannot_be_root_or_shared(self):
        node = next(n for n in ast.parse(module.REMOTE).body if isinstance(n, ast.FunctionDef) and n.name == 'ensure_user')
        home = '/var/lib/quantum-automation/n8n'
        def account(uid=986, gid=980):
            return SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_dir=home, pw_shell='/usr/sbin/nologin')
        ns = {'GuardError': module.GuardError, 'pwd': SimpleNamespace(getpwnam=Mock()),
              'os': SimpleNamespace(getgrouplist=Mock()), 'command': Mock()}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<ensure-user>', 'exec'), ns)
        for uid, gid in [(0, 980), (986, 0)]:
            ns['pwd'].getpwnam.return_value = account(uid, gid)
            ns['os'].getgrouplist.return_value = [gid]
            with self.assertRaisesRegex(module.GuardError, 'root_service_user'):
                ns['ensure_user']('qvpn-n8n', home)
        good = account(); ns['pwd'].getpwnam.return_value = good
        ns['os'].getgrouplist.return_value = [good.pw_gid]
        self.assertIs(good, ns['ensure_user']('qvpn-n8n', home))
        ns['pwd'].getpwnam.side_effect = [KeyError(), account(0, 980)]
        with self.assertRaisesRegex(module.GuardError, 'root_service_user'):
            ns['ensure_user']('qvpn-n8n', home)
        for accounts in [[good, account(986, 979)], [good, account(985, 980)]]:
            with self.assertRaisesRegex(module.GuardError, 'service_accounts_not_distinct'):
                module.validate_service_accounts(accounts)
        module.validate_service_accounts([good, account(985, 979), account(987, 981)])

    def test_actual_safe_lock_rejects_symlink_fifo_owner_mode_and_inode_drift(self):
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0, st_gid=0)
        regular = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0, st_dev=1, st_ino=9)
        def fake_os(info=regular, identity=regular):
            return SimpleNamespace(O_RDONLY=1, O_DIRECTORY=2, O_NOFOLLOW=4, O_NONBLOCK=8, O_CREAT=16, O_RDWR=32,
                                   open=Mock(side_effect=[10, 11]), fstat=Mock(side_effect=[parent, info]),
                                   stat=Mock(return_value=identity), fdopen=Mock(return_value='safe-handle'), close=Mock())
        os_mock = fake_os()
        with patch.object(module, 'os', os_mock):
            self.assertEqual('safe-handle', module.safe_install_lock())
        self.assertEqual(4 | 8 | 16 | 32, os_mock.open.call_args_list[1].args[1])
        os_mock.fdopen.assert_called_once_with(11, 'r+')
        for changed in [dict(st_mode=stat.S_IFIFO | 0o600), dict(st_uid=986), dict(st_gid=980), dict(st_mode=stat.S_IFREG | 0o666)]:
            info = SimpleNamespace(**{**regular.__dict__, **changed})
            with patch.object(module, 'os', fake_os(info)):
                with self.assertRaisesRegex(module.GuardError, 'unsafe_install_lock_file'):
                    module.safe_install_lock()
        os_mock = fake_os(identity=SimpleNamespace(**{**regular.__dict__, 'st_ino': 99}))
        with patch.object(module, 'os', os_mock):
            with self.assertRaisesRegex(module.GuardError, 'unsafe_install_lock_file'):
                module.safe_install_lock()
        os_mock = fake_os(); os_mock.open.side_effect = [10, OSError('symlink ELOOP')]
        with patch.object(module, 'os', os_mock):
            with self.assertRaisesRegex(module.GuardError, 'unsafe_install_lock_open'):
                module.safe_install_lock()

    def test_pins_are_strict(self):
        module.validate_pins(module.PINS)
        for field, value in [('n8n_version', 'latest'), ('node_sha256', 'abc'), ('openclaw_integrity', 'sha1-abc')]:
            pins = dict(module.PINS, **{field: value})
            with self.assertRaises(module.GuardError):
                module.validate_pins(pins)

    def test_lock_requires_exact_package_and_integrities(self):
        name = 'n8n'
        entry = {'version': module.PINS['n8n_version'], 'integrity': module.PINS['n8n_integrity'], 'resolved': 'https://registry.npmjs.org/n8n/-/n8n-' + module.PINS['n8n_version'] + '.tgz'}
        lock = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/n8n': entry}}
        self.assertEqual(64, len(module.validate_lock(lock, name, module.PINS)))
        for changed in [{'resolved': 'http://registry.npmjs.org/n8n/a.tgz'}, {'integrity': 'sha1-untrusted'}, {'version': '0.0.0'}, {'link': True}]:
            bad = copy.deepcopy(lock); bad['packages']['node_modules/n8n'].update(changed)
            with self.assertRaises(module.GuardError):
                module.validate_lock(bad, name, module.PINS)
        bad = copy.deepcopy(lock); bad['packages']['node_modules/a'] = dict(entry, resolved='https://attacker.example/a.tgz')
        with self.assertRaises(module.GuardError):
            module.validate_lock(bad, name, module.PINS)

    def test_node_archive_paths(self):
        prefix = 'node-v' + module.PINS['node_version'] + '-linux-x64'
        member = tarfile.TarInfo(prefix + '/bin/node'); module.validate_node_member(member)
        member = tarfile.TarInfo(prefix + '/bin/npm'); member.type = tarfile.SYMTYPE; member.linkname = '../lib/node_modules/npm/bin/npm-cli.js'
        module.validate_node_member(member)
        for name, target in [(prefix + '/../../etc/passwd', ''), (prefix + '/bin/npm', '/etc/passwd'), (prefix + '/bin/npm', '../../etc/passwd')]:
            bad = tarfile.TarInfo(name)
            if target:
                bad.type = tarfile.SYMTYPE; bad.linkname = target
            with self.assertRaises(module.GuardError):
                module.validate_node_member(bad)

    def test_gateway_closed_and_all_tools_denied(self):
        cfg = module.openclaw_config('a' * 64)
        self.assertEqual('loopback', cfg['gateway']['bind'])
        self.assertEqual('token', cfg['gateway']['auth']['mode'])
        self.assertEqual(['*'], cfg['tools']['deny'])
        self.assertFalse(cfg['tools']['elevated']['enabled'])
        self.assertEqual({}, cfg['channels'])
        self.assertFalse(cfg['browser']['enabled'])
        self.assertFalse(cfg['canvasHost']['enabled'])
        self.assertEqual('http://127.0.0.1:11434', cfg['models']['providers']['ollama']['baseUrl'])
        self.assertGreaterEqual(cfg['models']['providers']['ollama']['models'][0]['contextWindow'], 8000)
        self.assertEqual(['ollama'], cfg['plugins']['allow'])

    def test_n8n_credentials_and_code_not_exposed(self):
        env = module.n8n_environment('b' * 64)
        self.assertEqual('127.0.0.1', env['N8N_LISTEN_ADDRESS'])
        self.assertEqual('true', env['N8N_BLOCK_ENV_ACCESS_IN_NODE'])
        self.assertEqual('false', env['N8N_COMMUNITY_PACKAGES_ENABLED'])
        excluded = json.loads(env['NODES_EXCLUDE'])
        for name in ['code', 'executeCommand', 'readWriteFile', 'ssh']:
            self.assertIn('n8n-nodes-base.' + name, excluded)

    def test_service_isolation_and_budget(self):
        for name, account in module.USERS.items():
            unit = module.service_unit(name)
            self.assertIn('User=' + account, unit)
            for expected in ['ProtectSystem=strict', 'ProtectHome=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=\n', 'PrivateDevices=yes', 'MemorySwapMax=0', 'CPUQuota=25%']:
                self.assertIn(expected, unit)
            self.assertNotIn('User=root', unit)
            self.assertNotIn('docker', unit)
            self.assertNotIn('token=', unit)
            self.assertNotIn('N8N_ENCRYPTION_KEY=', unit)
            for path in ['/var/lib/quantumvpn-operator', '/opt/quantumvpn-operator', '/etc/quantumvpn-operator', '/etc/quantumvpn-dns']:
                self.assertIn('-' + path, unit)
        self.assertIn('Environment=OPENCLAW_CONFIG_READONLY=1', module.service_unit('openclaw'))

    def test_resume_journal_rejects_foreign_paths_pins_and_secrets(self):
        journal = {'schema': 1, 'install_id': module.INSTALL_ID, 'pins': module.PINS,
                   'steps': {}, 'files': {module.RELEASE + '/node/bin/node': 'c' * 64},
                   'credentials': {'key': 'a' * 64, 'token': 'b' * 64}}
        self.assertEqual(journal, module.validate_journal(journal))
        for field, value in [('install_id', 'foreign'), ('pins', {}), ('credentials', {'key': 'short', 'token': 'b' * 64}), ('steps', {'n8n': {'complete': True, 'lock_digest': 'x'}})]:
            bad = copy.deepcopy(journal); bad[field] = value
            with self.assertRaises(module.GuardError):
                module.validate_journal(bad)
        for path in ['/etc/passwd', module.RELEASE + '/../foreign', '/etc/systemd/system/nginx.service']:
            bad = copy.deepcopy(journal); bad['files'][path] = 'd' * 64
            with self.assertRaises(module.GuardError):
                module.validate_journal(bad)

    def test_resume_is_explicit_and_does_not_remove_owned_state(self):
        source = module.remote_script(True, True)
        compile(source, '<resume>', 'exec')
        self.assertIn('remote_main(True, True)', source)
        for expected in ['incomplete_install_requires_explicit_resume', 'resume_requires_owned_journal', 'journal_file_drift', 'completed_journal_step_drift', 'openclaw_pinned_runtime_config_rejected']:
            self.assertIn(expected, source)
        self.assertNotIn('shutil.rmtree(STATE', source)
        self.assertNotIn('shutil.rmtree(PRIVATE', source)
        self.assertNotIn('shutil.rmtree(release', source)
        self.assertIn("dir=release", source)
        self.assertIn("resolved.parent == Path(RELEASE)", source)
        self.assertIn("'--build-from-source'", source)
        self.assertIn("'build-from-source=true\\n'", source)
        self.assertIn('RuntimeMaxSec=1800', source)

    def test_remote_inventory_has_no_implicit_apply(self):
        readonly = module.remote_script(False)
        explicit = module.remote_script(True)
        compile(readonly, '<inventory>', 'exec')
        self.assertIn('remote_main(False)', readonly)
        self.assertIn('remote_main(True)', explicit)
        self.assertNotIn('apt-get', explicit)
        self.assertNotIn('iptables', explicit)
        self.assertNotIn('nft ', explicit)
        self.assertNotIn("systemctl', 'restart'", explicit)
        self.assertIn('RejectPolicy', Path(module.__file__).read_text())

    def test_inference_smoke_is_explicit_authenticated_and_bounded(self):
        source = module.remote_script(False, False, True)
        compile(source, '<smoke>', 'exec')
        self.assertIn('remote_main(False, False, True)', source)
        for expected in ['smoke_requires_healthy_managed_install', 'Authorization', '--session-id', '--timeout', 'RuntimeMaxSec=360', 'openclaw_model_reply_missing_or_failed', 'openclaw_gateway_run_proof_missing', 'openclaw_model_provider_proof_mismatch']:
            self.assertIn(expected, source)
        self.assertNotIn("'--local'", source)
        self.assertNotIn("'--deliver'", source)
        self.assertNotIn("'--token'", source)

    def test_fixed_worker_is_guarded_and_status_is_nonmutating(self):
        job_id = 'a' * 32
        source = module.worker_script(job_id, module.remote_script(True, True))
        compile(source, '<worker>', 'exec')
        for expected in ['installer_lock_busy','owned_build_or_worker_still_active','foreign_worker_root',"'--no-block'",'TimeoutStartSec=10800','RuntimeMaxSec=10800','MemoryMax=320M','StandardOutput=append:', 'independent_of_local_pc']:
            self.assertIn(expected, source)
        status = module.worker_script(job_id)
        self.assertIn('PAYLOAD = None', status)
        self.assertIn('worker_identity_or_source_drift', status)
        for value in ['../escape', 'a' * 31, 'g' * 32, 'A' * 32]:
            with self.assertRaises(ValueError):
                module.worker_script(value)

    def test_actual_worker_dispatch_refuses_failed_systemd_inventory(self):
        source = ast.parse(module.worker_script('a' * 32, module.remote_script(True, True)))
        # Safe-lock behavior is tested separately above. Replace only its
        # syscall boundary; execute the real worker branch, not string checks.
        lock = Mock(); lock.__enter__ = Mock(return_value=Mock()); lock.__exit__ = Mock(return_value=False)
        for node in source.body:
            if isinstance(node, ast.FunctionDef) and node.name == 'safe_install_lock':
                node.body = [ast.Return(value=ast.Name(id='mock_lock', ctx=ast.Load()))]
        source = ast.fix_missing_locations(source)
        fcntl = ModuleType('fcntl'); fcntl.LOCK_EX = 1; fcntl.LOCK_NB = 2; fcntl.flock = Mock()
        failure = subprocess.CompletedProcess([], 1, stdout='', stderr='systemd unavailable')
        with patch.dict(sys.modules, {'fcntl': fcntl}), patch('subprocess.run', return_value=failure) as run, patch('pathlib.Path.mkdir') as mkdir, patch('builtins.print') as output:
            with self.assertRaises(SystemExit) as result:
                exec(compile(source, '<actual-worker>', 'exec'), {'mock_lock': lock})
            self.assertEqual(2, result.exception.code)
            self.assertEqual('owned_worker_inventory_failed', json.loads(output.call_args.args[0])['code'])
            self.assertEqual(1, run.call_count)
            self.assertEqual('list-units', run.call_args.args[0][1])
            mkdir.assert_not_called()


if __name__ == '__main__':
    unittest.main()
