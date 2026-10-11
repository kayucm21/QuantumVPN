"""Offline OpenClaw uninstaller guards. No SSH, service or deletion calls."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location('remove_claw', Path(__file__).with_name('remove-openclaw-vds.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RemoveOpenClawTests(unittest.TestCase):
    def setUp(self):
        self.ns = dict(module.migration.base.__dict__)
        self.ns.update(copy=copy, Path=Path, os=Mock(), pwd=Mock(), grp=Mock(), command=Mock(),
                       secrets=Mock(), time=Mock(), fcntl=Mock(), output=Mock(),
                       protected_snapshot=Mock(return_value={}), is_active=Mock(return_value=True))
        for k, v in {'O_RDONLY': 0, 'O_WRONLY': 1, 'O_CREAT': 64, 'O_EXCL': 128,
                     'O_DIRECTORY': 65536, 'O_NOFOLLOW': 131072, 'O_NONBLOCK': 2048}.items():
            setattr(self.ns['os'], k, v)
        for source in (module.migration.MIGRATION, module.UNINSTALL):
            tree = ast.parse(source)
            exec(compile(ast.Module(body=[n for n in tree.body if not isinstance(n, (ast.Import, ast.ImportFrom))], type_ignores=[]), '<guards>', 'exec'), self.ns)

    def fixture(self):
        n = self.ns
        node = {p: ('d' if p.endswith('/node') else 'e') * 64 for p in n['NODE_FILES']}
        other = {n['CLAW_UNIT']: 'c' * 64, n['ACCESS']: 'a' * 64,
                 module.migration.base.STATE + '/openclaw/openclaw.json': 'b' * 64,
                 module.migration.base.RELEASE + '/openclaw/package-lock.json': 'f' * 64}
        docs = {n['MANIFEST']: {'created_utc': '2026-10-11T01:56:28Z', 'protected_snapshot': {},
                               'immutable_files': {**node, **other}},
                n['JOURNAL']: {'files': {**node, **other}, 'credentials': {'token': '9' * 64},
                              'steps': {'node': {'complete': True, 'lock_digest': None}, 'openclaw': {'complete': True, 'lock_digest': 'f' * 64}}}}
        new, node = n['node_only_records'](docs, '1' * 64)
        identity = {'file': {'dev': 1, 'ino': 2, 'uid': 0, 'gid': 0, 'mode': 0o600},
                    'parent': {'dev': 1, 'ino': 3, 'uid': 0, 'gid': 0, 'mode': 0o700}}
        records = (*n['CLAW_RECORDS'], n['CLAW_UNIT'], n['ACCESS'])
        value = {'schema': 1, 'id': n['UNINSTALL_ID'], 'state': 'pending',
                 'old_hashes': {p: '1' * 64 for p in records},
                 'identities': {p: copy.deepcopy(identity) for p in records},
                 'targets': {p: copy.deepcopy(identity) for p in n['CLAW_TARGETS']},
                 'new': {p: base64.b64encode(v).decode() for p, v in new.items()}, 'node_files': node,
                 'removed': {p: 'pending' for p in n['CLAW_TARGETS']},
                 'converted': {p: 'pending' for p in n['CLAW_RECORDS']}, 'account': 'pending',
                 'protected_snapshot': {}, 'protected_active': {}, 'files_before': 200, 'bytes_before': 1024}
        return value, docs, new

    def test_pinned_dependencies_unchanged_and_source_compiles(self):
        self.assertEqual(module.MIGRATION_SHA256, hashlib.sha256(module.migration_path.read_bytes()).hexdigest())
        self.assertEqual(module.migration.BASE_SHA256, hashlib.sha256(module.migration.base_path.read_bytes()).hexdigest())
        for source in (module.remote_script(), module.remote_script(True, True), module.worker_script('a' * 32, module.remote_script(True)), module.worker_script('a' * 32)):
            compile(source, '<remote>', 'exec')

    def test_default_inventory_never_acquires_lock_or_mutates(self):
        value, _, _ = self.fixture(); n = self.ns
        n['Path'] = Mock(return_value=SimpleNamespace(exists=lambda: False, is_symlink=lambda: False))
        n['initial_removal_inventory'] = Mock(return_value=value); n['safe_install_lock'] = Mock()
        n['uninstall_main'](False)
        n['command'].assert_not_called(); n['safe_install_lock'].assert_not_called()
        self.assertFalse(n['output'].call_args.args[0]['mutations'])

    def test_node_only_metadata_has_no_access_token_or_claw_package(self):
        value, _, new = self.fixture(); n = self.ns
        n['validate_removal_intent'](value)
        journal = json.loads(new[n['JOURNAL']]); manifest = json.loads(new[n['MANIFEST']])
        self.assertEqual({}, journal['credentials']); self.assertEqual({'node'}, set(journal['steps']))
        self.assertEqual({}, manifest['dependency_lock_sha256'])
        self.assertEqual(set(n['NODE_FILES']), set(journal['files']))
        self.assertEqual(value['node_files'], manifest['immutable_files'])
        self.assertNotIn('9' * 64, json.dumps(value))
        self.assertNotIn('gateway_token', json.dumps(value))
        self.assertNotIn('qwen', json.dumps(new, default=str).lower())

    def test_missing_shared_node_proof_refuses_record_generation(self):
        _, docs, _ = self.fixture(); n = self.ns
        for document in docs.values():
            for field in ('files', 'immutable_files'):
                document.get(field, {}).pop(n['NODE_FILES'][1], None)
        with self.assertRaisesRegex(module.migration.base.GuardError, 'shared_node_provenance_missing'):
            n['node_only_records'](docs, '1' * 64)

    def test_foreign_scope_identity_or_checkpoint_refused(self):
        value, _, _ = self.fixture(); n = self.ns
        for change in ('scope', 'id', 'digest', 'phase', 'size', 'complete'):
            bad = copy.deepcopy(value)
            if change == 'scope': bad['targets']['/opt'] = {}
            elif change == 'id': bad['id'] = 'foreign'
            elif change == 'digest': bad['node_files'][n['NODE_FILES'][0]] = 'not-a-hash'
            elif change == 'phase': bad['account'] = 'skip'
            elif change == 'size': bad['bytes_before'] = True
            else: bad['state'] = 'done'
            with self.assertRaises(module.migration.base.GuardError): n['validate_removal_intent'](bad)

    def test_unknown_new_records_and_credential_injection_refused(self):
        value, _, new = self.fixture(); n = self.ns
        for change in ('token', 'files', 'history'):
            bad = copy.deepcopy(value)
            p = n['JOURNAL'] if change != 'history' else n['INTENT']
            doc = json.loads(new[p])
            if change == 'token': doc['credentials'] = {'token': 'a' * 64}
            elif change == 'files': doc['files']['/etc/rospanel/config.json'] = 'b' * 64
            else: doc['previous_conversion_sha256'] = 'f' * 64
            bad['new'][p] = base64.b64encode(json.dumps(doc).encode()).decode()
            with self.assertRaises(module.migration.base.GuardError): n['validate_removal_intent'](bad)

    def test_exact_targets_only_never_open_unreviewed_path(self):
        n = self.ns
        for path in ('/', '/opt/quantum-automation', module.migration.base.RELEASE, module.migration.base.STATE, '/var/lib/ollama'):
            with self.assertRaisesRegex(module.migration.base.GuardError, 'unreviewed_openclaw_removal_target'):
                n['claw_target_record'](path)
        n['os'].open.assert_not_called()

    def test_ancestor_symlinks_and_writable_ancestor_refused(self):
        n = self.ns; n['os'].open.side_effect = OSError('symlink')
        with self.assertRaises(OSError): n['open_parent'](module.migration.base.RELEASE + '/openclaw')
        n['os'].open.side_effect = None; n['os'].open.return_value = 8
        n['os'].fstat.return_value = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o777)
        with self.assertRaisesRegex(module.migration.base.GuardError, 'unsafe_migration_ancestor'):
            n['open_parent'](module.migration.base.RELEASE + '/openclaw')

    def test_mount_boundary_refused(self):
        n = self.ns; n['Path'] = Mock(return_value=SimpleNamespace(read_text=lambda: '9 2 1:2 / /opt/owned\\040claw/sub rw - tmpfs tmpfs rw'))
        with self.assertRaisesRegex(module.migration.base.GuardError, 'mounted_removal_subtree'):
            n['assert_no_mounts']('/opt/owned claw')

    def test_recursive_symlinks_unlinked_not_followed(self):
        n = self.ns
        s = SimpleNamespace(st_dev=1, st_ino=4, st_uid=0, st_gid=0, st_mode=stat.S_IFLNK | 0o777, st_size=99)
        n['os'].scandir.return_value = [SimpleNamespace(name='outside', stat=Mock(return_value=s))]
        n['os'].stat.return_value = s
        self.assertEqual((1, 0), n['claw_tree'](8, 1, False, True))
        n['os'].open.assert_not_called(); n['os'].unlink.assert_called_once_with('outside', dir_fd=8)

    def test_foreign_pair_device_and_special_subtree_entries_refused(self):
        n = self.ns
        for diff in ({'st_dev': 2}, {'st_uid': 985, 'st_gid': 979}, {'st_uid': 0, 'st_gid': 981}, {'st_uid': 999}, {'st_mode': stat.S_IFIFO | 0o600}):
            s = SimpleNamespace(st_dev=1, st_ino=4, st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_size=1)
            for k, v in diff.items(): setattr(s, k, v)
            n['os'].scandir.return_value = [SimpleNamespace(name='foreign', stat=Mock(return_value=s))]
            with self.assertRaises(module.migration.base.GuardError): n['claw_tree'](8, 1, False, True)
        n['os'].unlink.assert_not_called()

    def test_state_only_claw_owner_allowed_and_shared_root_file_refused(self):
        n = self.ns
        s = SimpleNamespace(st_dev=1, st_ino=4, st_uid=985, st_gid=979, st_mode=stat.S_IFREG | 0o600, st_size=11)
        n['os'].scandir.return_value = [SimpleNamespace(name='state', stat=Mock(return_value=s))]
        self.assertEqual((1, 11), n['claw_tree'](8, 1, True))
        s.st_uid = 0; s.st_gid = 0
        with self.assertRaisesRegex(module.migration.base.GuardError, 'foreign_openclaw_subtree_entry'):
            n['claw_tree'](8, 1, True, True)
        n['os'].unlink.assert_not_called()

    def test_partial_missing_target_allowed_only_started_or_done(self):
        value, _, new = self.fixture(); n = self.ns
        n['read_fixed'] = lambda p, **kw: (new[p], value['identities'][p])
        n['immutable_digest'] = lambda p: value['node_files'][p]
        value['converted'] = {p: 'started' for p in n['CLAW_RECORDS']}
        n['protected_check'] = Mock()
        n['claw_target_record'] = Mock(side_effect=lambda p, allow_absent, expected_parent: None if allow_absent else (_ for _ in ()).throw(module.migration.base.GuardError('unstarted_openclaw_target_missing')))
        with self.assertRaisesRegex(module.migration.base.GuardError, 'unstarted_openclaw_target_missing'):
            n['removal_checkpoint_check'](value)
        value['removed'] = {p: 'started' for p in n['CLAW_TARGETS']}
        n['removal_checkpoint_check'](value)

    def test_finished_target_recreated_refused(self):
        value, _, new = self.fixture(); n = self.ns
        value['converted'] = {p: 'done' for p in n['CLAW_RECORDS']}; value['removed'] = {p: 'done' for p in n['CLAW_TARGETS']}
        n['read_fixed'] = lambda p, **kw: (new[p], value['identities'][p]); n['immutable_digest'] = lambda p: value['node_files'][p]
        n['claw_target_record'] = lambda p, *args: value['targets'][p]
        with self.assertRaisesRegex(module.migration.base.GuardError, 'openclaw_target_recreated_or_changed'):
            n['removal_checkpoint_check'](value)

    def test_node_drift_blocks_before_target_removal(self):
        value, _, _ = self.fixture(); n = self.ns
        n['immutable_digest'] = Mock(return_value='wrong'); n['claw_target_record'] = Mock()
        with self.assertRaisesRegex(module.migration.base.GuardError, 'shared_node_provenance_drift'):
            n['removal_checkpoint_check'](value)
        n['claw_target_record'].assert_not_called()

    def test_record_changed_or_unjournaled_replacement_refused(self):
        value, _, new = self.fixture(); n = self.ns
        n['immutable_digest'] = lambda p: value['node_files'][p]
        n['read_fixed'] = lambda p, **kw: (new[p], value['identities'][p])
        with self.assertRaisesRegex(module.migration.base.GuardError, 'unjournaled_node_only_replacement'):
            n['removal_checkpoint_check'](value)
        n['read_fixed'] = lambda p, **kw: (b'foreign', value['identities'][p])
        with self.assertRaisesRegex(module.migration.base.GuardError, 'retiring_record_identity_changed'):
            n['removal_checkpoint_check'](value)

    def test_cas_inode_or_digest_mismatch_never_writes(self):
        n = self.ns; value, _, _ = self.fixture(); ident = value['identities'][n['MANIFEST']]
        n['open_parent'] = Mock(return_value=(8, 'manifest.json'))
        n['os'].fstat.return_value = SimpleNamespace(st_dev=1, st_ino=3, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)
        n['read_fixed'] = Mock(return_value=(b'foreign', ident))
        with self.assertRaisesRegex(module.migration.base.GuardError, 'migration_compare_and_swap_failed'):
            n['atomic_cas'](n['MANIFEST'], ident, b'new', '1' * 64)
        n['os'].open.assert_not_called(); n['os'].replace.assert_not_called()

    def test_resumes_atomic_record_replacement_without_second_write(self):
        value, _, new = self.fixture(); n = self.ns
        value['converted'] = {p: 'started' for p in n['CLAW_RECORDS']}
        n['read_fixed'] = lambda p, **kw: (new[p], value['identities'][p])
        n['atomic_cas'] = Mock(); n['save_removal_intent'] = Mock()
        n['retire_claw_records'](value, new)
        n['atomic_cas'].assert_not_called(); self.assertTrue(all(v == 'done' for v in value['converted'].values()))

    def test_unstarted_or_foreign_target_not_deleted(self):
        value, _, _ = self.fixture(); n = self.ns
        for p in ('/', n['CLAW_TARGETS'][0]):
            with self.assertRaisesRegex(module.migration.base.GuardError, 'unreviewed_or_unstarted_openclaw_removal'):
                n['remove_claw_target'](p, value)
        n['os'].unlink.assert_not_called(); n['os'].rmdir.assert_not_called()

    def test_stop_exact_unit_without_model_readiness_requirement(self):
        value, _, _ = self.fixture(); n = self.ns
        n['claw_unit_inventory'] = Mock(side_effect=[{'FragmentPath': n['CLAW_UNIT'], 'DropInPaths': '', 'ActiveState': 'active'},
                                            {'FragmentPath': n['CLAW_UNIT'], 'DropInPaths': '', 'ActiveState': 'inactive'}])
        n['no_account_processes'] = Mock(); n['no_other_owned_workers'] = Mock()
        n['command'].return_value = SimpleNamespace(stdout='', returncode=0)
        n['stop_owned_claw'](value)
        self.assertEqual(['systemctl', 'stop', 'quantum-openclaw.service'], n['command'].call_args_list[0].args[0])
        self.assertEqual(['systemctl', 'disable', 'quantum-openclaw.service'], n['command'].call_args_list[1].args[0])

    def test_foreign_dropin_or_unit_not_stopped(self):
        value, _, _ = self.fixture(); n = self.ns
        for s in ({'FragmentPath': '/etc/foreign.service', 'DropInPaths': ''}, {'FragmentPath': n['CLAW_UNIT'], 'DropInPaths': '/etc/override.conf'}):
            n['claw_unit_inventory'] = Mock(return_value=s)
            with self.assertRaisesRegex(module.migration.base.GuardError, 'foreign_openclaw_unit'): n['stop_owned_claw'](value)
        n['command'].assert_not_called()

    def test_account_only_exact_name_never_recursive_home_remove(self):
        value, _, _ = self.fixture(); n = self.ns
        n['account_identity'] = Mock(); n['no_account_processes'] = Mock(); n['save_removal_intent'] = Mock()
        n['grp'].getgrnam.side_effect = KeyError
        n['remove_claw_account'](value)
        n['command'].assert_called_once_with(['userdel', 'qvpn-openclaw']); self.assertEqual('done', value['account'])

    def test_account_disappearance_needs_started_proof(self):
        value, _, _ = self.fixture(); n = self.ns
        n['pwd'].getpwnam.side_effect = KeyError; n['grp'].getgrnam.side_effect = KeyError; n['save_removal_intent'] = Mock()
        with self.assertRaisesRegex(module.migration.base.GuardError, 'unstarted_openclaw_account_missing'): n['remove_claw_account'](value)
        value['account'] = 'started'; n['remove_claw_account'](value); self.assertEqual('done', value['account'])
        n['command'].assert_not_called()

    def test_existing_user_missing_group_refused(self):
        value, _, _ = self.fixture(); n = self.ns
        n['account_identity'] = Mock(side_effect=KeyError)
        with self.assertRaisesRegex(module.migration.base.GuardError, 'existing_openclaw_user_missing_group'): n['remove_claw_account'](value)
        n['command'].assert_not_called()

    def test_done_account_read_only_never_commands_or_saves(self):
        value, _, _ = self.fixture(); n = self.ns; value['account'] = 'done'
        n['pwd'].getpwnam.side_effect = KeyError; n['grp'].getgrnam.side_effect = KeyError
        n['save_removal_intent'] = Mock()
        n['remove_claw_account'](value)
        n['command'].assert_not_called(); n['save_removal_intent'].assert_not_called()

    def test_completed_read_only_status_does_not_write_intent_or_service(self):
        value, _, _ = self.fixture(); n = self.ns
        value['state'] = 'done'; value['account'] = 'done'
        value['removed'] = {p: 'done' for p in n['CLAW_TARGETS']}
        value['converted'] = {p: 'done' for p in n['CLAW_RECORDS']}
        n['Path'] = Mock(return_value=SimpleNamespace(exists=lambda: True, is_symlink=lambda: False))
        n['read_fixed'] = Mock(return_value=(json.dumps(value).encode(), {}))
        n['removal_checkpoint_check'] = Mock(return_value={})
        n['claw_target_record'] = Mock(return_value=None)
        n['pwd'].getpwnam.side_effect = KeyError; n['grp'].getgrnam.side_effect = KeyError
        n['claw_unit_inventory'] = Mock(return_value={'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'FragmentPath': '', 'DropInPaths': ''})
        n['no_account_processes'] = Mock(); n['save_removal_intent'] = Mock(); n['safe_install_lock'] = Mock()
        n['command'].return_value = SimpleNamespace(stdout='', returncode=0)
        n['uninstall_main'](False)
        n['save_removal_intent'].assert_not_called(); n['safe_install_lock'].assert_not_called()
        n['command'].assert_called_once_with(['ss', '-lntH', 'sport = :18789'])

    def test_missing_unit_only_exact_not_found_inactive_zero_pid_allowed(self):
        n = self.ns
        clean = 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\nMainPID=0\n'
        n['command'].return_value = SimpleNamespace(returncode=1, stdout=clean)
        self.assertEqual('not-found', n['claw_unit_inventory'](True)['LoadState'])
        with self.assertRaises(module.migration.base.GuardError): n['claw_unit_inventory'](False)
        n['command'].return_value.stdout = clean.replace('MainPID=0', 'MainPID=123')
        with self.assertRaises(module.migration.base.GuardError): n['claw_unit_inventory'](True)

    def test_missing_unit_no_properties_or_foreign_dropin_never_assumed_removed(self):
        n = self.ns
        for out in ('', 'LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=/override\nMainPID=0\n'):
            n['command'].return_value = SimpleNamespace(returncode=1, stdout=out)
            with self.assertRaisesRegex(module.migration.base.GuardError, 'openclaw_unit_inventory_failed'):
                n['claw_unit_inventory'](True)

    def test_live_owned_workers_refuse_cleanup(self):
        n = self.ns; n['command'].return_value = SimpleNamespace(returncode=0, stdout='qvpn-automation-build-1 active running command')
        with self.assertRaisesRegex(module.migration.base.GuardError, 'owned_worker_still_running'): n['no_other_owned_workers']()

    def test_worker_scoped_and_bounded_no_shell_or_inference(self):
        script = module.worker_script('a' * 32, module.remote_script(True))
        self.assertIn("ROOT = Path('/run/quantum-openclaw-removal')", script)
        self.assertIn("UNIT = 'qvpn-openclaw-removal-'", script)
        self.assertIn('b"uninstall_main(True"', script)
        self.assertIn('MemoryMax=320M', script); self.assertIn('TimeoutStartSec=1800', script)
        self.assertNotIn('rm -rf', module.UNINSTALL); self.assertNotIn("'journalctl'", module.UNINSTALL)
        self.assertNotIn('model_smoke(', module.UNINSTALL); self.assertNotIn("'start',", module.UNINSTALL)


if __name__ == '__main__':
    unittest.main()
