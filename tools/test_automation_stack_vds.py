"""Offline safety gates: no SSH/network/service mutation during these tests."""
import importlib.util
import ast
import copy
import json
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('automation_install', Path(__file__).with_name('install-automation-stack-vds.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AutomationSafetyTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
