"""Offline checks for bounded, read-only OpenClaw failure diagnosis."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('diagnose_claw',Path(__file__).with_name('diagnose-openclaw-model-vds.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class DiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.n={'json':json,'re':__import__('re'),'datetime':__import__('datetime'),
                'resource':Mock(),'signal':Mock(),'time':Mock(),'select':Mock(),
                'subprocess':Mock(),'os':Mock(),'Path':Mock(),'command':Mock(),
                'GuardError':RuntimeError,'output':Mock(),'MODEL_DIGEST':'expected'}
        tree=ast.parse(module.DIAGNOSIS)
        exec(compile(ast.Module(body=[node for node in tree.body if not isinstance(node,(ast.Import,ast.ImportFrom))],type_ignores=[]),'<diagnosis>','exec'),self.n)

    def journal(self,*messages):
        return b'\n'.join(json.dumps({'MESSAGE':message,'__REALTIME_TIMESTAMP':'1791732420000000'}).encode() for message in messages)

    def test_verifier_pin_and_compiled_script(self):
        self.assertEqual(module.VERIFIER_SHA256,hashlib.sha256(module.verifier_path.read_bytes()).hexdigest())
        compile(module.remote_script(),'<diagnostic>','exec')

    def test_only_readonly_rpc_subset_present(self):
        tree=ast.parse(module.readonly_rpc_source())
        names={node.name for node in tree.body if isinstance(node,ast.FunctionDef)}
        self.assertEqual({'existing_verification_lock','private_claw_config','bounded_metadata'},names)
        for forbidden in ('model_smoke','verify_main','LoopbackWebSocket','await_response','connect_params'):
            self.assertNotIn(forbidden,module.readonly_rpc_source())

    def test_fixed_journal_scope_and_no_mutating_command(self):
        self.assertEqual('2026-10-11 15:27:00 UTC',self.n['JOURNAL_SINCE'])
        tree=ast.parse(module.DIAGNOSIS)
        self.assertNotIn('O_CREAT',module.DIAGNOSIS)
        self.assertNotIn('write_text',module.DIAGNOSIS)
        self.assertNotIn('urlopen',module.DIAGNOSIS)
        for call in [n for n in ast.walk(tree) if isinstance(n,ast.Call)]:
            if isinstance(call.func,ast.Name) and call.func.id=='command':
                if isinstance(call.args[0],ast.Name):self.assertEqual('argv',call.args[0].id)
                else:self.assertEqual(['systemctl','show','quantum-openclaw.service','-p','ControlGroup'],ast.literal_eval(call.args[0]))
        self.assertNotIn("['systemctl','start'",module.DIAGNOSIS)
        self.assertNotIn("['systemctl','stop'",module.DIAGNOSIS)
        self.assertNotIn("['systemctl','restart'",module.DIAGNOSIS)

    def test_fixed_codes_only_never_messages_tokens_paths(self):
        message='private-token secret-prompt /etc/private/key EACCES PermissionError unexpectedException arbitrary_code=SECRET'
        report=self.n['summarize_journal'](self.journal(message))
        self.assertEqual({'EACCES':1},report['allowed_code_counts'])
        self.assertEqual({'PermissionError':1},report['allowed_exception_counts'])
        serialized=json.dumps(report)
        for value in ('private-token','secret-prompt','/etc/private/key','unexpectedException','SECRET'):
            self.assertNotIn(value,serialized)
        self.assertFalse(report['raw_messages_returned'])
        self.assertTrue(report['classification_only'])

    def test_classification_separate_from_cause_claim(self):
        report=self.n['summarize_journal'](self.journal('provider Ollama timed out TimeoutError','ENOENT plugin failed','oom-kill ENOMEM'))
        self.assertEqual(1,report['category_counts']['timeout'])
        self.assertEqual(1,report['category_counts']['missing_file'])
        self.assertEqual(1,report['category_counts']['plugin'])
        self.assertEqual(1,report['category_counts']['oom'])
        self.assertNotIn('cause',report)

    def test_no_false_code_substrings(self):
        report=self.n['summarize_journal'](self.journal('my_EACCES_suffix NotTimeoutErrorElse'))
        self.assertEqual({},report['allowed_code_counts'])
        self.assertEqual({},report['allowed_exception_counts'])

    def test_journal_entry_and_aggregate_bounds(self):
        with self.assertRaisesRegex(RuntimeError,'diagnostic_journal_entry_bound'):
            self.n['summarize_journal'](self.journal(*(['ordinary']*101)))
        with self.assertRaisesRegex(RuntimeError,'diagnostic_journal_output_bound'):
            self.n['summarize_journal'](b'x'*(2*1024**2+1))

    def test_message_processing_bound_and_unknown_fields_dropped(self):
        raw=json.dumps({'MESSAGE':'x'*32769,'SECRET':'do-not-return','__REALTIME_TIMESTAMP':'not-safe'}).encode()
        report=self.n['summarize_journal'](raw)
        self.assertEqual(1,report['truncated_messages'])
        self.assertEqual(1,report['unclassified_entries'])
        self.assertIsNone(report['first_entry_utc'])
        self.assertNotIn('do-not-return',json.dumps(report))

    def test_integer_and_timestamp_allowlists(self):
        for value in (True,-1,'secret','infinity',2**51,None):
            self.assertIsNone(self.n['safe_integer'](value))
        self.assertEqual(1816,self.n['safe_integer']('1816'))
        self.assertEqual('2026-10-11T15:27:00Z',self.n['safe_timestamp']('1791732420000000'))
        self.assertIsNone(self.n['safe_timestamp']('secrets'))

    def test_service_facts_sanitized_but_memory_counters_retained(self):
        self.n['command'].return_value=SimpleNamespace(returncode=0,stdout='ActiveState=active\nSubState=running\nMainPID=123\nNRestarts=4\nMemoryCurrent=500000000\nMemoryPeak=800000000\nMemoryMax=1073741824\nMemorySwapMax=0\nResult=success\nExecMainStatus=0\nPRIVATE=secret\n')
        self.n['Path'].return_value.stat.return_value=SimpleNamespace(st_uid=985)
        facts=self.n['safe_service_facts']('quantum-openclaw.service')
        self.assertEqual(4,facts['restarts']);self.assertEqual(123,facts['main_pid'])
        self.assertEqual(500000000,facts['memory_current_bytes'])
        self.assertEqual(800000000,facts['memory_peak_bytes'])
        self.assertEqual(985,facts['process_uid']);self.assertNotIn('secret',json.dumps(facts))
        args=self.n['command'].call_args.args[0]
        self.assertEqual(['systemctl','show','quantum-openclaw.service'],args[:3])
        with self.assertRaisesRegex(RuntimeError,'diagnostic_unit_scope'):
            self.n['safe_service_facts']('nginx.service')

    def test_unknown_service_values_not_echoed(self):
        self.n['command'].return_value=SimpleNamespace(returncode=0,stdout='ActiveState=token-secret\nSubState=private-path\nResult=private-result\nMainPID=private\n')
        facts=self.n['safe_service_facts']('ollama.service')
        self.assertEqual('unknown',facts['active_state'])
        self.assertIsNone(facts['main_pid']);self.assertNotIn('private',json.dumps(facts))

    def test_loaded_model_metadata_no_unreviewed_names_or_details(self):
        self.n['bounded_metadata']=Mock(side_effect=[
            [{'name':'qwen3:0.6b','model':'qwen3:0.6b','digest':'expected','secret':'token'}],
            [{'name':'qwen3:0.6b','context_length':16384}, {'name':'private-model','details':'secret'}]])
        facts=self.n['metadata_facts']()
        self.assertTrue(facts['expected_model_digest_match'])
        self.assertEqual(1,facts['loaded_expected_count']);self.assertEqual(1,facts['other_loaded_count'])
        self.assertEqual([16384],facts['loaded_context_lengths'])
        self.assertNotIn('private-model',json.dumps(facts));self.assertNotIn('secret',json.dumps(facts))
        self.assertEqual([('tags',),('ps',)],[call.args for call in self.n['bounded_metadata'].call_args_list])

    def test_metadata_failure_keeps_no_exception_message(self):
        self.n['bounded_metadata']=Mock(side_effect=RuntimeError('private-token'))
        facts=self.n['metadata_facts']()
        self.assertFalse(facts['metadata_ready']);self.assertNotIn('private-token',json.dumps(facts))

    def test_bounded_journal_reads_only_child_stdout(self):
        n=self.n;n['time'].monotonic.return_value=0
        process=Mock();process.stdout.fileno.return_value=7;process.wait.return_value=0;process.poll.return_value=0
        n['subprocess'].Popen.return_value=process;n['select'].select.return_value=([7],[],[])
        n['os'].read.side_effect=[self.journal('ordinary'),b'']
        data=n['bounded_journal']()
        self.assertEqual(self.journal('ordinary'),data)
        argv=n['subprocess'].Popen.call_args.args[0]
        self.assertEqual(['journalctl','-u','quantum-openclaw.service','--since','2026-10-11 15:27:00 UTC'],argv[:5])
        self.assertIn('100',argv);process.kill.assert_not_called();process.stdout.close.assert_called_once()

    def test_diagnostic_low_headroom_is_reported_without_inference(self):
        n=self.n;n['INTENT']='intent';n['JOURNAL']='journal';n['RELEASE']='release';n['SOURCE_HASHES']={};n['TIMEOUT_PRIMARY_SOURCE_HASHES']={}
        n['existing_verification_lock']=Mock(return_value=5)
        n['read_fixed']=Mock(return_value=(b'{"schema":2}',{}))
        n['validate_completed_intent']=Mock(return_value={'journal':{'credentials':{'token':'private-token'}}})
        config={'tools':{'deny':['*']}}
        n['private_claw_config']=Mock(return_value=config);n['openclaw_config']=Mock(return_value=config)
        n['safe_service_facts']=Mock(return_value={'active_state':'active'})
        n['service_probe']=Mock(return_value=True)
        n['Path'].return_value.read_text.return_value='MemAvailable: 1859584 kB\n'
        n['metadata_facts']=Mock(return_value={});n['bounded_journal']=Mock(return_value=b'')
        n['owned_file_log_facts']=Mock(return_value={});n['cgroup_facts']=Mock(return_value={})
        n['diagnostic_main']()
        report=n['output'].call_args.args[0]
        self.assertEqual(1816,report['memory_available_mib'])
        self.assertFalse(report['model_smoke_headroom_met']);self.assertFalse(report['inference'])
        self.assertNotIn('private-token',repr(report));n['os'].close.assert_called_once_with(5)

    def test_owned_log_timezone_and_window_filter_no_messages(self):
        entries=[{'time':'2026-10-11T15:26:59Z','message':'EACCES old'},
                 {'_meta':{'date':'2026-10-11T18:28:00.123+03:00'},'message':'private-token timed out TimeoutError'},
                 {'time':'not-time','message':'ENOENT untrusted timestamp'}]
        data=b'\n'.join(json.dumps(entry).encode() for entry in entries)
        report=self.n['summarize_owned_file_log'](data)
        self.assertEqual(1,report['entries_examined']);self.assertEqual(1,report['entries_before_window'])
        self.assertEqual(1,report['entries_without_valid_time'])
        self.assertEqual('2026-10-11T15:28:00Z',report['first_entry_utc'])
        self.assertEqual({'TimeoutError':1},report['allowed_exception_counts'])
        self.assertEqual({},report['allowed_code_counts'])
        self.assertNotIn('private-token',json.dumps(report))

    def test_owned_log_aggregate_and_last_100_limits(self):
        with self.assertRaisesRegex(RuntimeError,'diagnostic_file_log_output_bound'):
            self.n['summarize_owned_file_log'](b'x'*(2*1024**2+1))
        line=json.dumps({'time':'2026-10-11T15:28:00Z','message':'ordinary'}).encode()
        report=self.n['summarize_owned_file_log'](b'\n'.join([line]*101))
        self.assertEqual(100,report['entries_examined']);self.assertEqual(1,report['older_tail_entries_omitted'])

    def test_cgroup_numeric_only_scope_and_no_oom_cause_claim(self):
        data=b'low 0\nhigh 0\nmax 119\noom 0\noom_kill 0\nprivate_key secret\n'
        report=self.n['parse_cgroup_counters'](data,'memory.events')
        self.assertEqual({'low':0,'high':0,'max':119,'oom':0,'oom_kill':0},report)
        self.assertNotIn('cause',report);self.assertNotIn('private',json.dumps(report))
        self.assertEqual({'anon':1,'file':2},self.n['parse_cgroup_counters'](b'anon 1\nfile 2\nother 9\n','memory.stat'))
        self.assertEqual({'nr_throttled':4},self.n['parse_cgroup_counters'](b'nr_throttled 4\nprivate secret\n','cpu.stat'))
        for filename,data in [('secrets',b'oom 0'),('memory.events',b'x'*16385)]:
            with self.assertRaisesRegex(RuntimeError,'diagnostic_cgroup_scope_or_bound'):
                self.n['parse_cgroup_counters'](data,filename)

    def test_owned_log_requires_current_owned_pid_before_proc_access(self):
        self.n['CLAW_UID']=985
        for facts in ({'main_pid':None,'process_uid':985},{'main_pid':123,'process_uid':0}):
            report=self.n['owned_file_log_facts'](facts)
            self.assertFalse(report['available']);self.n['os'].open.assert_not_called()

    def log_reader_fixture(self):
        n=self.n;n['CLAW_UID']=985;n['CLAW_GID']=979;n['STATE']='/var/lib/quantum-automation'
        n['SERVICES']={'openclaw':'quantum-openclaw.service'};n['stat']=__import__('stat')
        for key,value in {'O_RDONLY':0,'O_DIRECTORY':65536,'O_NOFOLLOW':131072,'O_NONBLOCK':2048,'SEEK_SET':0}.items():setattr(n['os'],key,value)
        data=json.dumps({'time':'2026-10-11T15:28:00Z','message':'private-token ETIMEDOUT'}).encode()
        def info(uid,gid,mode,ino,size=0):return SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode,st_ino=ino,st_dev=1,st_size=size)
        stats={11:info(985,979,0o40555,2),12:info(0,0,0o40755,3),13:info(0,0,0o41777,4),14:info(985,979,0o40700,5),15:info(985,979,0o100600,6,len(data))}
        n['os'].open.side_effect=[10,11,12,13,14,15]
        n['os'].fstat.side_effect=lambda fd:stats[fd]
        n['os'].stat.return_value=stats[15]
        n['os'].readlink.return_value=n['STATE']+'/openclaw'
        n['os'].read.return_value=data
        n['unit_state']=Mock(return_value={'MainPID':'123'})
        return stats,data

    def test_owned_log_exact_filename_single_magic_link_and_nofollow(self):
        stats,data=self.log_reader_fixture()
        report=self.n['owned_file_log_facts']({'main_pid':123,'process_uid':985})
        self.assertTrue(report['available']);self.assertEqual({'ETIMEDOUT':1},report['allowed_code_counts'])
        self.assertNotIn('private-token',json.dumps(report))
        calls=self.n['os'].open.call_args_list
        self.assertEqual('root',calls[2].args[0]);self.assertEqual(65536,calls[2].args[1])
        self.assertEqual('openclaw-2026-10-11.log',calls[5].args[0])
        for i,call in enumerate(calls):
            if i!=2:self.assertTrue(call.args[1]&131072)
        self.assertEqual([15,14,13,12,11,10],[call.args[0] for call in self.n['os'].close.call_args_list])

    def test_owned_log_cwd_or_pid_change_refuses_contents(self):
        self.log_reader_fixture();self.n['os'].readlink.return_value='/unrelated'
        report=self.n['owned_file_log_facts']({'main_pid':123,'process_uid':985})
        self.assertFalse(report['available']);self.n['os'].read.assert_not_called()
        self.log_reader_fixture();self.n['unit_state'].return_value={'MainPID':'other'}
        report=self.n['owned_file_log_facts']({'main_pid':123,'process_uid':985})
        self.assertFalse(report['available']);self.n['os'].read.assert_not_called()


    def test_exact_timeout_phrases_distinguish_without_arbitrary_content(self):
        messages=['private-account LLM request timed out.',
                  'Request timed out before a response was generated.',
                  'Opening handshake has timed out',
                  'gateway request timeout for private-method',
                  'preparation timed out private-path']
        report=self.n['summarize_journal'](self.journal(*messages))
        counts=report['timeout_source_phrase_counts']
        self.assertEqual(1,counts['provider_request_timeout'])
        self.assertEqual(1,counts['agent_run_ceiling'])
        self.assertEqual(1,counts['websocket_handshake_timeout'])
        self.assertEqual(1,counts['gateway_request_timeout'])
        self.assertEqual(1,report['generic_timeout_wording_counts']['preparation'])
        self.assertEqual(1,report['timeout_entries_without_known_source_phrase'])
        self.assertFalse(report['timeout_stage_or_run_correlation_proven'])
        for secret in ('private-account','private-method','private-path'):
            self.assertNotIn(secret,json.dumps(report))

    def test_generic_timeout_token_does_not_prove_run_or_preparation(self):
        report=self.n['summarize_journal'](self.journal('status timeout=120'))
        self.assertEqual(1,report['category_counts']['timeout'])
        self.assertEqual(1,report['timeout_entries_without_known_source_phrase'])
        self.assertTrue(all(count==0 for count in report['timeout_source_phrase_counts'].values()))
        self.assertTrue(all(count==0 for count in report['generic_timeout_wording_counts'].values()))
        self.assertFalse(report['timeout_stage_or_run_correlation_proven'])


if __name__=='__main__':unittest.main()
