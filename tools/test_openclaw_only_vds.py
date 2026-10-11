"""Offline migration guards; never opens SSH or runs local systemctl."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('claw_only',Path(__file__).with_name('migrate-openclaw-only-vds.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class OpenClawOnlyTests(unittest.TestCase):
    def setUp(self):
        self.ns=dict(module.base.__dict__)
        self.ns.update(copy=copy,Path=Path,os=Mock(),pwd=Mock(),grp=Mock(),command=Mock(),
                       secrets=Mock(),time=Mock(),fcntl=Mock(),output=Mock(),digest=Mock(),
                       protected_snapshot=Mock(return_value={}),is_active=Mock(return_value=True),
                       service_probe=Mock(return_value=True))
        for key,value in {'O_RDONLY':0,'O_WRONLY':1,'O_CREAT':64,'O_EXCL':128,
                          'O_DIRECTORY':65536,'O_NOFOLLOW':131072,'O_NONBLOCK':2048}.items():
            setattr(self.ns['os'],key,value)
        tree=ast.parse(module.MIGRATION)
        exec(compile(ast.Module(body=[x for x in tree.body if not isinstance(x,(ast.Import,ast.ImportFrom))],type_ignores=[]),'<migration>','exec'),self.ns)

    def fixture(self):
        n=self.ns;token='a'*64
        files={p:'b'*64 for p in n['N8N_IMMUTABLE']}
        files.update({n['CLAW_UNIT']:n['OLD_HASHES'][n['CLAW_UNIT']],n['ACCESS']:'c'*64,
            module.base.RELEASE+'/node/bin/node':'d'*64,
            module.base.RELEASE+'/openclaw/package-lock.json':'e'*64,
            module.base.STATE+'/openclaw/openclaw.json':'f'*64})
        j={'schema':1,'install_id':module.base.INSTALL_ID,'pins':module.base.PINS,
           'credentials':{'token':token,'key':'9'*64},'files':files,
           'steps':{'node':{'complete':True,'lock_digest':None},'n8n':{'complete':True,'lock_digest':'1'*64},'openclaw':{'complete':True,'lock_digest':'2'*64}}}
        m={'install_id':module.base.INSTALL_ID,'pins':module.base.PINS,'immutable_files':{p:v for p,v in files.items() if p!=n['ACCESS']},
           'dependency_lock_sha256':{'n8n':'1'*64,'openclaw':'2'*64},'created_utc':'2026-10-11T01:56:28Z','protected_snapshot':{'old':'kept'}}
        access={'n8n':{'url':'http://localhost:5678/'},'openclaw':{'gateway_token':token,'url':'http://localhost:18789/','model':'ollama/qwen3:0.6b','tools':'disabled'},'private_endpoints':True,'telegram_enabled':False,'ssh_tunnel':'old'}
        old={n['JOURNAL']:json.dumps(j).encode(),n['MANIFEST']:json.dumps(m).encode(),n['ACCESS']:json.dumps(access).encode(),n['CLAW_UNIT']:module.base.service_unit('openclaw').encode()}
        n['OLD_HASHES']={p:hashlib.sha256(v).hexdigest() for p,v in old.items()}
        ident={'file':{'dev':1,'ino':2,'uid':0,'gid':0,'mode':0o600},'parent':{'dev':1,'ino':3,'uid':0,'gid':0,'mode':0o700}}
        value={'schema':1,'id':n['MIGRATION_ID'],'state':'pending','old':{p:base64.b64encode(v).decode() for p,v in old.items()},
            'identities':{p:copy.deepcopy(ident) for p in old},'targets':{p:copy.deepcopy(ident) for p in n['REMOVE']},
            'removed':{p:'pending' for p in n['REMOVE']},'converted':{p:'pending' for p in old},'account':'pending',
            'protected_snapshot':{},'protected_active':{}}
        return value,old,n['replacement_records'](old)

    def test_historical_source_unchanged_and_default_read_only(self):
        self.assertEqual(module.BASE_SHA256,hashlib.sha256(module.base_path.read_bytes()).hexdigest())
        self.ns['migration_inventory']=Mock(return_value={'mode':'read_only'})
        self.ns['safe_install_lock']=Mock()
        self.ns['migrate_main'](False)
        self.ns['safe_install_lock'].assert_not_called();self.ns['command'].assert_not_called()
        self.ns['output'].assert_called_once_with({'mode':'read_only'})

    def test_exact_budget_and_no_respawn_changes_only(self):
        old=module.base.service_unit('openclaw').encode();new=self.ns['new_claw_unit']()
        restored=new.replace(b'MemoryMax=1024M',b'MemoryMax=768M').replace(b'Environment=OPENCLAW_NO_RESPAWN=1\n',b'')
        self.assertEqual(old,restored)
        for item in (b'CPUQuota=25%',b'MemorySwapMax=0',b'--max-old-space-size=384',b'ProtectSystem=strict',b'OPENCLAW_CONFIG_READONLY=1'):
            self.assertIn(item,new)
        self.assertLessEqual(1024,640+768)

    def test_generated_records_preserve_token_node_claw_and_history(self):
        value,old,new=self.fixture();n=self.ns
        j=json.loads(new[n['JOURNAL']]);m=json.loads(new[n['MANIFEST']]);a=json.loads(new[n['ACCESS']])
        self.assertEqual({'token':'a'*64},j['credentials'])
        self.assertEqual({'node','openclaw'},set(j['steps']))
        self.assertEqual({'openclaw':'2'*64},m['dependency_lock_sha256'])
        self.assertEqual({'old':'kept'},m['protected_snapshot'])
        self.assertNotIn('n8n',a);self.assertNotIn('5678',a['ssh_tunnel'])
        self.assertFalse(a['model_verified']);self.assertEqual('a'*64,a['openclaw']['gateway_token'])
        self.assertFalse(set(j['files']) & n['N8N_IMMUTABLE'])
        self.assertFalse(set(m['immutable_files']) & n['N8N_IMMUTABLE'])
        self.assertEqual('d'*64,j['files'][module.base.RELEASE+'/node/bin/node'])

    def test_intent_refuses_foreign_scope_raw_bytes_and_unfinished_complete(self):
        value,old,new=self.fixture();n=self.ns
        self.assertEqual(old,n['validate_intent'](value)[0])
        for change,code in [('old','migration_old_provenance_drift'),('scope','invalid_migration_scope'),('complete','incomplete_migration_marked_complete')]:
            bad=copy.deepcopy(value)
            if change=='old':bad['old'][n['JOURNAL']]=base64.b64encode(b'{}').decode()
            elif change=='scope':bad['targets']['/opt']='foreign'
            else:bad['state']='ready'
            with self.assertRaisesRegex(module.base.GuardError,code):n['validate_intent'](bad)

    def test_pending_missing_only_after_started_and_no_recreated_target(self):
        value,old,new=self.fixture();n=self.ns;n['immutable_pending_check']=Mock()
        n['target_record']=Mock(side_effect=FileNotFoundError)
        with self.assertRaisesRegex(module.base.GuardError,'unstarted_target_missing'):n['validate_current_conversion'](value)
        value['removed']={p:'started' for p in n['REMOVE']}
        n['validate_current_conversion'](value)
        value['removed']={p:'done' for p in n['REMOVE']}
        n['target_record']=lambda p:value['targets'][p]
        with self.assertRaisesRegex(module.base.GuardError,'removal_target_recreated_or_changed'):n['validate_current_conversion'](value)

    def test_unreviewed_removal_path_never_opens(self):
        n=self.ns
        for p in ('/','/opt/quantum-automation',module.base.RELEASE,module.base.STATE+'/openclaw'):
            with self.assertRaisesRegex(module.base.GuardError,'unreviewed_removal_target'):n['remove_target'](p,{},True)
        n['os'].open.assert_not_called()

    def test_recursive_symlink_is_unlinked_never_followed(self):
        n=self.ns;s=SimpleNamespace(st_dev=1,st_ino=4,st_uid=0,st_gid=0,st_mode=stat.S_IFLNK|0o777,st_size=9)
        entry=SimpleNamespace(name='outside-link',stat=Mock(return_value=s))
        n['os'].scandir.return_value=[entry];n['os'].stat.return_value=s
        self.assertEqual((1,0),n['scan_tree'](8,1,True))
        n['os'].open.assert_not_called();n['os'].unlink.assert_called_once_with('outside-link',dir_fd=8)
        entry.stat.assert_called_once_with(follow_symlinks=False)

    def test_recursive_device_foreign_owner_and_special_file_refused(self):
        n=self.ns
        for values in ({'st_dev':2},{'st_uid':999},{'st_gid':999},{'st_mode':stat.S_IFIFO|0o600}):
            s=SimpleNamespace(st_dev=1,st_ino=4,st_uid=0,st_gid=0,st_mode=stat.S_IFREG|0o600,st_size=1)
            for k,v in values.items():setattr(s,k,v)
            n['os'].scandir.return_value=[SimpleNamespace(name='unsafe',stat=Mock(return_value=s))]
            with self.assertRaises(module.base.GuardError):n['scan_tree'](8,1,True)
        n['os'].unlink.assert_not_called()

    def test_mountpoint_refused_with_linux_escape(self):
        n=self.ns;n['Path']=Mock(return_value=SimpleNamespace(read_text=lambda:'9 2 1:2 / /opt/test\\040path/sub rw - tmpfs tmpfs rw'))
        with self.assertRaisesRegex(module.base.GuardError,'mounted_removal_subtree'):n['assert_no_mounts']('/opt/test path')

    def test_cas_wrong_inode_or_digest_never_writes(self):
        n=self.ns;ident={'file':{'dev':1,'ino':2,'uid':0,'gid':0,'mode':0o600},'parent':{'dev':1,'ino':3,'uid':0,'gid':0,'mode':0o700}}
        ps=SimpleNamespace(st_dev=1,st_ino=3,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o700)
        n['open_parent']=Mock(return_value=(8,'manifest.json'));n['os'].fstat.return_value=ps
        n['read_fixed']=Mock(return_value=(b'changed',ident))
        with self.assertRaisesRegex(module.base.GuardError,'migration_compare_and_swap_failed'):n['atomic_cas'](n['MANIFEST'],ident,b'new',hashlib.sha256(b'old').hexdigest())
        n['os'].open.assert_not_called();n['os'].replace.assert_not_called()

    def test_atomic_replacement_crash_is_resumed_without_second_replace(self):
        value,old,new=self.fixture();n=self.ns
        value['converted']={p:'started' for p in old}
        n['read_fixed']=lambda p,**kwargs:(new[p],value['identities'][p])
        n['atomic_cas']=Mock();n['save_intent']=Mock()
        n['convert_records'](value,new)
        n['atomic_cas'].assert_not_called()
        self.assertEqual('converted',value['state']);self.assertTrue(all(v=='done' for v in value['converted'].values()))

    def test_account_removal_fixed_name_without_recursive_home_delete(self):
        value,_,_=self.fixture();n=self.ns
        n['account_identity']=Mock();n['no_account_processes']=Mock();n['save_intent']=Mock()
        n['grp'].getgrnam.side_effect=KeyError
        n['delete_account'](value)
        n['command'].assert_called_once_with(['userdel','qvpn-n8n'])
        self.assertEqual('done',value['account'])

    def test_account_disappearance_requires_durable_started_checkpoint(self):
        value,_,_=self.fixture();n=self.ns;n['pwd'].getpwnam.side_effect=KeyError;n['account_identity']=Mock(side_effect=KeyError);n['save_intent']=Mock();n['grp'].getgrnam.side_effect=KeyError
        with self.assertRaisesRegex(module.base.GuardError,'unstarted_account_missing'):n['delete_account'](value)
        n['command'].assert_not_called()
        value['account']='started';n['delete_account'](value);self.assertEqual('done',value['account'])

    def test_missing_group_with_still_existing_user_cannot_mark_done(self):
        value,_,_=self.fixture();n=self.ns;value['account']='started'
        n['account_identity']=Mock(side_effect=KeyError);n['save_intent']=Mock()
        with self.assertRaisesRegex(module.base.GuardError,'existing_n8n_user_missing_group'):n['delete_account'](value)
        self.assertEqual('started',value['account']);n['command'].assert_not_called();n['save_intent'].assert_not_called()

    def test_completed_compaction_erases_old_key_and_requires_all_checkpoints(self):
        value,_,new=self.fixture();n=self.ns
        with self.assertRaisesRegex(module.base.GuardError,'cannot_compact_incomplete_migration'):n['compact_completed_intent'](value,new)
        value['removed']={p:'done' for p in n['REMOVE']};value['converted']={p:'done' for p in new};value['account']='done';value['state']='ready'
        compact=n['compact_completed_intent'](value,new)
        self.assertEqual(2,compact['schema']);self.assertNotIn('old',compact)
        self.assertNotIn('9'*64,json.dumps(compact));self.assertEqual(n['OLD_HASHES'],compact['old_hashes'])
        self.assertEqual({p:hashlib.sha256(v).hexdigest() for p,v in new.items()},compact['new_hashes'])

    def test_resume_after_unit_deleted_skips_disable_missing_file(self):
        value,_,_=self.fixture();n=self.ns;value['removed'][n['REMOVE'][3]]='done'
        n['unit_state']=Mock(return_value={'FragmentPath':n['REMOVE'][3],'DropInPaths':'','ActiveState':'inactive'})
        n['Path']=Mock(return_value=SimpleNamespace(exists=lambda:False));n['no_account_processes']=Mock()
        n['stop_owned_n8n'](value);n['command'].assert_not_called()

    def test_remote_generated_source_compiles_without_execution(self):
        compile(module.remote_script(),'read-only-payload','exec')
        compile(module.remote_script(True,True),'apply-payload','exec')
        compile(module.worker_script('a'*32,module.remote_script(True)),'worker','exec')

    def test_actual_runtime_caps_unit_owner_and_dropin_gate(self):
        n=self.ns;safe={'FragmentPath':n['CLAW_UNIT'],'DropInPaths':'','ActiveState':'active',
            'MemoryMax':'1073741824','MemorySwapMax':'0','CPUQuotaPerSecUSec':'250ms','MainPID':'123','NRestarts':'0'}
        n['unit_state']=Mock(return_value=safe)
        n['Path']=Mock(return_value=SimpleNamespace(stat=lambda:SimpleNamespace(st_uid=n['CLAW_UID'])))
        self.assertEqual(safe,n['assert_runtime_budget']())
        for key,value in [('MemoryMax','max'),('MemorySwapMax','1'),('CPUQuotaPerSecUSec','500ms'),('DropInPaths','/tmp/foreign.conf'),('FragmentPath','/tmp/foreign.service')]:
            n['unit_state'].return_value={**safe,key:value}
            with self.assertRaisesRegex(module.base.GuardError,'openclaw_runtime_budget_or_unit_drift'):n['assert_runtime_budget']()
        n['unit_state'].return_value=safe
        n['Path']=Mock(return_value=SimpleNamespace(stat=lambda:SimpleNamespace(st_uid=0)))
        with self.assertRaisesRegex(module.base.GuardError,'openclaw_runtime_process_identity_changed'):n['assert_runtime_budget']()

    def test_soak_refuses_restart_and_never_enables_failed_gateway(self):
        n=self.ns;n['time'].monotonic.side_effect=[0,1,2]
        n['assert_runtime_budget']=Mock(side_effect=[{'NRestarts':'0'},{'NRestarts':'1'}])
        with self.assertRaisesRegex(module.base.GuardError,'openclaw_readiness_soak_failed'):n['readiness_soak']()
        n['command'].assert_called_once_with(['systemctl','start','quantum-openclaw.service'])

    def test_private_cas_mode_drift_is_refused_even_if_caller_offers_644(self):
        n=self.ns;path=n['ACCESS'];parent=SimpleNamespace(st_dev=1,st_ino=3,st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o700)
        file=SimpleNamespace(st_dev=1,st_ino=4,st_uid=0,st_gid=0,st_mode=stat.S_IFREG|0o644,st_size=2)
        n['open_parent']=Mock(return_value=(8,'access.json'));n['os'].open.return_value=9
        n['os'].fstat.side_effect=[parent,file];n['os'].stat.return_value=file
        with self.assertRaisesRegex(module.base.GuardError,'unsafe_migration_file'):n['read_fixed'](path,modes=(0o600,0o644))
        n['os'].read.assert_not_called()

    def test_converted_resume_checks_cas_modes_before_any_start(self):
        value,old,new=self.fixture();n=self.ns;value['state']='converted'
        n['validate_current_conversion']=Mock(return_value=(old,new))
        def read(p,**kwargs):
            if p==n['ACCESS']:
                self.assertEqual((0o600,),kwargs['modes'])
                raise module.base.GuardError('unsafe_migration_file')
            return new[p],value['identities'][p]
        n['read_fixed']=read
        with self.assertRaisesRegex(module.base.GuardError,'unsafe_migration_file'):n['assert_converted_inventory'](value)
        n['command'].assert_not_called()

    def test_protected_snapshot_or_active_service_drift_refused(self):
        value,_,_=self.fixture();n=self.ns
        value['protected_active']={'ollama':True};n['is_active'].return_value=False
        with self.assertRaisesRegex(module.base.GuardError,'protected_system_changed_during_migration'):n['protected_check'](value)
        n['is_active'].return_value=True;n['protected_snapshot'].return_value={'changed':True}
        with self.assertRaisesRegex(module.base.GuardError,'protected_system_changed_during_migration'):n['protected_check'](value)

    def test_worker_fixed_identity_bounds_and_no_legacy_main(self):
        script=module.worker_script('a'*32,module.remote_script(True))
        self.assertIn("ROOT = Path('/run/quantum-openclaw-migration')",script)
        self.assertIn("UNIT = 'qvpn-openclaw-migration-'",script)
        for item in ('MemoryMax=320M','MemorySwapMax=0','CPUQuota=20%','IOWeight=10','RuntimeMaxSec=1800','TimeoutStartSec=1800','qvpn-openclaw-migration-*','migrate_main(True'):
            self.assertIn(item,script)
        self.assertNotIn('RuntimeMaxSec=10800',script)
        self.assertNotIn('remote_main(True',module.remote_script(True))

if __name__=='__main__':unittest.main()
