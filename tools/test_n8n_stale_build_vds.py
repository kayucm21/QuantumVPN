"""Offline exact-path scratch deletion guards; no SSH/lifecycle execution."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import test_openclaw_only_vds as migration_tests

spec=importlib.util.spec_from_file_location('stale',Path(__file__).with_name('remove-n8n-stale-build-vds.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class StaleBuildTests(unittest.TestCase):
    def setUp(self):
        migration_tests.OpenClawOnlyTests.setUp(self)
        tree=ast.parse(module.CLEANUP)
        exec(compile(ast.Module(body=[x for x in tree.body if not isinstance(x,(ast.Import,ast.ImportFrom))],type_ignores=[]),'<scratch>','exec'),self.ns)

    def fixture(self,state='pending'):
        n=self.ns;raw=b'{"schema":2,"state":"ready"}'
        n['read_fixed']=Mock(return_value=(raw,{}))
        return {'schema':1,'id':n['CLEANUP_ID'],'state':state,'path':n['SCRATCH'],
                'target':copy.deepcopy(n['SCRATCH_IDENTITY']),
                'parent':{'dev':64770,'ino':3,'uid':0,'gid':0,'mode':0o755},
                'conversion_sha256':hashlib.sha256(raw).hexdigest(),
                'protected_snapshot':{},'protected_active':{}}

    def test_source_pins_and_payload_compilation(self):
        self.assertEqual(module.MIGRATION_SHA256,hashlib.sha256(module.path.read_bytes()).hexdigest())
        compile(module.remote_script(),'readonly','exec');compile(module.remote_script(True),'apply','exec')
        script=module.worker_script('a'*32,module.remote_script(True));compile(script,'worker','exec')
        for item in ("ROOT = Path('/run/quantum-n8n-scratch-cleanup')","UNIT = 'qvpn-n8n-scratch-cleanup-'",'MemoryMax=320M','MemorySwapMax=0','CPUQuota=20%','IOWeight=10','RuntimeMaxSec=1800','qvpn-n8n-scratch-cleanup-*','cleanup_main(True'):
            self.assertIn(item,script)

    def test_completed_manifest_shared_immutables_gate_is_mandatory(self):
        n=self.ns;n['read_fixed']=Mock(return_value=(b'{}',{}))
        n['validate_completed_intent']=Mock(side_effect=n['GuardError']('not_completed'))
        with self.assertRaisesRegex(n['GuardError'],'not_completed'):n['completed_conversion_gate']()
        n['command'].assert_not_called();n['os'].unlink.assert_not_called()

    def test_tree_only_builder_ownership_and_device(self):
        n=self.ns
        for field,value in (('st_uid',0),('st_gid',0),('st_dev',99),('st_mode',stat.S_IFIFO|0o600)):
            s=SimpleNamespace(st_dev=64770,st_ino=8,st_uid=987,st_gid=981,st_mode=stat.S_IFREG|0o600,st_size=3)
            setattr(s,field,value);n['os'].scandir.return_value=[SimpleNamespace(name='file',stat=Mock(return_value=s))]
            with self.assertRaises(n['GuardError']):n['scratch_tree'](8,True)
        n['os'].unlink.assert_not_called()

    def test_symlink_unlinked_never_traversed(self):
        n=self.ns;s=SimpleNamespace(st_dev=64770,st_ino=8,st_uid=987,st_gid=981,st_mode=stat.S_IFLNK|0o777,st_size=10)
        n['os'].scandir.return_value=[SimpleNamespace(name='link',stat=Mock(return_value=s))];n['os'].stat.return_value=s
        self.assertEqual((1,0),n['scratch_tree'](5,True))
        n['os'].open.assert_not_called();n['os'].unlink.assert_called_once_with('link',dir_fd=5)

    def test_foreign_sibling_path_or_changed_inode_intent_rejected(self):
        value=self.fixture();n=self.ns;n['validate_cleanup_intent'](value)
        for change in ('path','inode','conversion'):
            bad=copy.deepcopy(value)
            if change=='path':bad['path']=module.migration.base.RELEASE+'/other'
            elif change=='inode':bad['target']['ino']+=1
            else:bad['conversion_sha256']='f'*64
            with self.assertRaises(n['GuardError']):n['validate_cleanup_intent'](bad)

    def test_absent_scratch_only_after_durable_started_intent(self):
        n=self.ns;n['open_parent']=Mock(return_value=(8,'fixed'))
        n['os'].fstat.return_value=SimpleNamespace(st_dev=64770,st_ino=3,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o755)
        n['os'].stat.side_effect=FileNotFoundError
        with self.assertRaisesRegex(n['GuardError'],'unstarted_scratch_target_missing'):n['scratch_inventory']()
        self.assertFalse(n['scratch_inventory'](True)['present'])
        value=self.fixture();n['scratch_inventory']=Mock()
        with self.assertRaisesRegex(n['GuardError'],'scratch_removal_requires_started_intent'):n['delete_scratch'](value)

    def test_readonly_never_acquires_lock_or_writes_intent(self):
        n=self.ns;self.fixture();n['completed_conversion_gate']=Mock()
        n['Path']=Mock(return_value=SimpleNamespace(exists=lambda:False,is_symlink=lambda:False))
        n['scratch_inventory']=Mock(return_value={'present':True,'parent':{},'files':2,'bytes':3})
        n['safe_install_lock']=Mock();n['save_cleanup_intent']=Mock()
        n['cleanup_main'](False)
        n['safe_install_lock'].assert_not_called();n['save_cleanup_intent'].assert_not_called()
        self.assertEqual('ScratchInventory',n['output'].call_args[0][0]['status'])

    def test_done_target_recreation_rejected(self):
        n=self.ns;value=self.fixture('done');n['read_fixed'].return_value=(json.dumps(value).encode(),{})
        n['completed_conversion_gate']=Mock();n['validate_cleanup_intent']=Mock(return_value=value)
        n['Path']=Mock(return_value=SimpleNamespace(exists=lambda:True,is_symlink=lambda:False))
        n['scratch_inventory']=Mock(return_value={'present':True,'files':1,'bytes':2,'parent':value['parent']})
        with self.assertRaisesRegex(n['GuardError'],'deleted_scratch_recreated'):n['cleanup_main'](False)
        n['command'].assert_not_called()

    def test_scratch_gate_refuses_active_builder_or_missing_readiness(self):
        n=self.ns;self.fixture();n['validate_completed_intent']=Mock();n['assert_runtime_budget']=Mock();n['account_identity']=Mock()
        n['service_probe'].return_value=False
        with self.assertRaisesRegex(n['GuardError'],'openclaw_not_ready_for_scratch_cleanup'):n['completed_conversion_gate']()
        n['service_probe'].return_value=True;n['no_account_processes']=Mock(side_effect=n['GuardError']('owned_account_process_still_running'))
        with self.assertRaisesRegex(n['GuardError'],'owned_account_process_still_running'):n['completed_conversion_gate']()

    def test_top_extra_file_refused_without_deletion(self):
        n=self.ns;n['open_parent']=Mock(return_value=(8,'fixed'));s=SimpleNamespace(st_dev=64770,st_ino=686169,st_uid=987,st_gid=981,st_mode=stat.S_IFDIR|0o700)
        ps=SimpleNamespace(st_dev=64770,st_ino=3,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o755)
        n['os'].fstat.side_effect=[ps,s];n['os'].stat.return_value=s;n['os'].open.return_value=9
        n['assert_no_mounts']=Mock();n['os'].scandir.return_value=[SimpleNamespace(name='foreign.txt',is_dir=Mock(return_value=False))]
        with self.assertRaisesRegex(n['GuardError'],'unreviewed_scratch_top_entry'):n['scratch_inventory']()
        n['os'].unlink.assert_not_called()

    def test_actual_deletion_uses_only_fd_pinned_exact_scratch_name(self):
        n=self.ns;value=self.fixture('started')
        n['scratch_inventory']=Mock(return_value={'present':True})
        n['no_account_processes']=Mock();n['open_parent']=Mock(return_value=(8,'qvpn-n8n-build-gqoa6z5j'))
        ps=SimpleNamespace(st_dev=64770,st_ino=3,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o755)
        s=SimpleNamespace(st_dev=64770,st_ino=686169,st_uid=987,st_gid=981,st_mode=stat.S_IFDIR|0o700)
        n['os'].fstat.side_effect=[ps,s];n['os'].open.return_value=9;n['os'].stat.return_value=s
        n['scratch_tree']=Mock(return_value=(2,3))
        n['delete_scratch'](value)
        n['open_parent'].assert_called_once_with(n['SCRATCH'])
        n['scratch_tree'].assert_called_once_with(9,True)
        n['os'].rmdir.assert_called_once_with('qvpn-n8n-build-gqoa6z5j',dir_fd=8)
        n['os'].unlink.assert_not_called();n['no_account_processes'].assert_called_once_with(987)

    def test_actual_delete_parent_inode_drift_cannot_unlink(self):
        n=self.ns;value=self.fixture('started');n['scratch_inventory']=Mock(return_value={'present':True})
        n['no_account_processes']=Mock();n['open_parent']=Mock(return_value=(8,'fixed'))
        n['os'].fstat.return_value=SimpleNamespace(st_dev=64770,st_ino=999,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o755)
        with self.assertRaisesRegex(n['GuardError'],'scratch_parent_identity_changed'):n['delete_scratch'](value)
        n['os'].open.assert_not_called();n['os'].rmdir.assert_not_called();n['os'].unlink.assert_not_called()

if __name__=='__main__':unittest.main()
