"""Offline RPC/model verifier checks; no SSH, inference or service execution."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('verify_claw',Path(__file__).with_name('verify-openclaw-model-vds.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ModelVerifierTests(unittest.TestCase):
    def setUp(self):
        self.n={'os':Mock(),'resource':Mock(),'signal':Mock(),'struct':__import__('struct'),
            'uuid':Mock(),'json':json,'Path':Mock(),'command':Mock(),'time':Mock(),
            'socket':Mock(),'base64':__import__('base64'),'hashlib':hashlib,
            'GuardError':RuntimeError,'CLAW_UID':985,'CLAW_GID':979,'output':Mock()}
        tree=ast.parse(module.RPC)
        exec(compile(ast.Module(body=[s for s in tree.body if not isinstance(s,(ast.Import,ast.ImportFrom))],type_ignores=[]),'<rpc>','exec'),self.n)

    def memory(self,available=1920,peak=1408*1024**2,active='active'):
        self.n['Path'].return_value.read_text.return_value='MemAvailable: %s kB\n'%(available*1024)
        self.n['command'].return_value=SimpleNamespace(stdout='ActiveState=%s\nMemoryPeak=%s\nMemoryCurrent=100\n'%(active,peak))

    def test_pinned_sources_and_readonly_default_dispatch(self):
        self.assertEqual(module.MIGRATION_SHA256,hashlib.sha256(module.migration_path.read_bytes()).hexdigest())
        compile(module.remote_script(),'<default>','exec')
        self.n['existing_verification_lock']=Mock(return_value=5)
        self.n['smoke_preflight']=Mock(return_value=('secret',{},{}))
        self.n['model_smoke']=Mock()
        self.n['verify_main']()
        self.n['model_smoke'].assert_not_called()
        self.n['output'].assert_called_once()
        self.assertFalse(self.n['output'].call_args.args[0]['inference'])
        self.assertNotIn('secret',repr(self.n['output'].call_args))
        self.n['os'].close.assert_called_once_with(5)

    def test_explicit_smoke_repeats_all_preflight(self):
        self.n['existing_verification_lock']=Mock(return_value=5)
        self.n['smoke_preflight']=Mock(return_value=('secret',{'MainPID':'4'},{}))
        self.n['model_smoke']=Mock()
        self.n['verify_main'](True)
        self.assertEqual(2,self.n['smoke_preflight'].call_count)
        self.n['model_smoke'].assert_called_once()

    def test_memory_boundary_and_fixed_allowance(self):
        self.memory();result=self.n['memory_gate']()
        self.assertEqual(1920,result['required_mib'])
        self.assertEqual(1408,result['model_peak_allowance_mib'])
        self.memory(available=1919)
        with self.assertRaisesRegex(RuntimeError,'insufficient_model_smoke_memory_headroom'):self.n['memory_gate']()
        for peak in (0,1408*1024**2+1,'[not set]'):
            self.memory(peak=peak)
            with self.assertRaisesRegex(RuntimeError,'ollama_peak_exceeds_reviewed_allowance_or_unavailable'):self.n['memory_gate']()

    def test_connect_shared_token_no_device_or_admin(self):
        params=self.n['connect_params']('private')
        self.assertEqual(4,params['minProtocol']);self.assertEqual(4,params['maxProtocol'])
        self.assertEqual(['operator.write'],params['scopes'])
        self.assertNotIn('device',params);self.assertEqual({'token':'private'},params['auth'])
        self.assertEqual('cli',params['client']['id']);self.assertEqual('cli',params['client']['mode'])

    def test_accepted_is_not_final_and_events_are_not_proof(self):
        ws=Mock();ws.receive.side_effect=[{'type':'event','event':'agent'},
            {'type':'res','id':'request','ok':True,'payload':{'status':'accepted','runId':'run'}},
            {'type':'res','id':'request','ok':True,'payload':{'status':'ok','runId':'run'}}]
        value=self.n['await_response'](ws,'request',True,'run')
        self.assertEqual('ok',value['status']);self.assertEqual(3,ws.receive.call_count)

    def test_authenticated_token_hello_exact_scope_version_method(self):
        hello={'type':'hello-ok','protocol':4,'server':{'version':'2026.9.9'},'auth':{'method':'token','role':'operator','scopes':['operator.write']},'features':{'methods':['agent','agent.wait']}}
        self.n['validate_hello'](hello)
        for field in ('protocol','version','method','scopes','agent'):
            bad=copy.deepcopy(hello)
            if field=='protocol':bad['protocol']=3
            if field=='version':bad['server']['version']='new'
            if field=='method':bad['auth']['method']='none'
            if field=='scopes':bad['auth']['scopes']=['operator.admin']
            if field=='agent':bad['features']['methods']=[]
            with self.assertRaisesRegex(RuntimeError,'gateway_authenticated_hello_required'):self.n['validate_hello'](bad)

    def test_final_correlation_and_rpc_rejection(self):
        for frame,code in [({'type':'res','id':'other','ok':True},'gateway_response_correlation'),
            ({'type':'res','id':'request','ok':False,'error':{'message':'private'}},'gateway_rpc_rejected'),
            ({'type':'res','id':'request','ok':True,'payload':{'status':'accepted','runId':'other'}},'gateway_accepted_run_correlation'),
            ({'type':'res','id':'request','ok':True,'payload':{'status':'ok'}},'gateway_final_without_acceptance')]:
            ws=Mock();ws.receive.return_value=frame
            with self.assertRaisesRegex(RuntimeError,code):self.n['await_response'](ws,'request',True,'run')

    def fixture_final(self):
        return {'runId':'run','status':'ok','summary':'completed','result':{'payloads':[{'text':'OK'}],'meta':{'agentMeta':{'provider':'ollama','model':'qwen3:0.6b','terminalReceipt':{'runId':'run','effective':{'provider':'ollama','model':'qwen3:0.6b'},'successfulToolNames':[]}}}}}

    def test_actual_provider_model_nonempty_response(self):
        value=self.fixture_final();result=self.n['final_proof'](value,'run')
        self.assertEqual({'provider':'ollama','model':'qwen3:0.6b','response_nonempty':True},result)
        for bad in ('provider','model','empty','run','status','error','notice','aborted','stop','meta_error','provider_not_started','summary','timeout_phase','reasoning'):
            value=copy.deepcopy(self.fixture_final())
            if bad in ('provider','model'):value['result']['meta']['agentMeta'][bad]='unapproved'
            if bad=='empty':value['result']['payloads']=[{'text':' '}]
            if bad=='run':value['runId']='other'
            if bad=='status':value['status']='accepted'
            if bad=='error':value['result']['payloads'][0]['isError']=True
            if bad=='notice':value['result']['payloads'][0]['isStatusNotice']=True
            if bad=='aborted':value['result']['meta']['aborted']=True
            if bad=='stop':value['result']['meta']['stopReason']='timeout'
            if bad=='meta_error':value['result']['meta']['error']={'message':'private failure'}
            if bad=='provider_not_started':value['result']['meta']['providerStarted']=False
            if bad=='summary':value['summary']='failed'
            if bad=='timeout_phase':value['result']['meta']['timeoutPhase']='provider'
            if bad=='reasoning':value['result']['payloads'][0]['isReasoning']=True
            with self.assertRaises(RuntimeError):self.n['final_proof'](value,'run')

    def test_no_heavy_cli_service_or_config_mutation_paths(self):
        tree=ast.parse(module.RPC)
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
        for node in calls:
            if isinstance(node.func,ast.Name) and node.func.id=='command':
                argv=ast.literal_eval(node.args[0]);self.assertEqual(['systemctl','show','ollama.service'],argv[:3])
        self.assertNotIn('openclaw.mjs',module.RPC)
        self.assertNotIn('write_text',module.RPC)
        self.assertNotIn('O_CREAT',module.RPC.replace('# No O_CREAT: default preflight cannot create a lock or other file.',''))

    def socket_fixture(self,frames,accept_valid=True):
        n=self.n;n['time'].monotonic.return_value=0
        n['os'].urandom.side_effect=lambda size:b'x'*size
        key=__import__('base64').b64encode(b'x'*16).decode()
        accept=__import__('base64').b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if not accept_valid:accept='unverified'
        header=('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode()
        sock=Mock();sock.recv.side_effect=[header+frames]
        n['socket'].create_connection.return_value=sock
        return sock

    def test_actual_upgrade_leftover_frame_and_masked_client(self):
        payload=json.dumps({'type':'event','event':'connect.challenge','payload':{'nonce':'nonce'}}).encode()
        sock=self.socket_fixture(bytes([0x81,len(payload)])+payload)
        ws=self.n['LoopbackWebSocket'](100)
        self.assertEqual('connect.challenge',ws.receive()['event'])
        ws.send('connect',{'auth':{'token':'private'}},'connect')
        outgoing=sock.sendall.call_args.args[0]
        self.assertTrue(outgoing[1]&0x80)
        self.assertEqual(('127.0.0.1',18789),self.n['socket'].create_connection.call_args.args[0])
        ws.close();sock.close.assert_called_once()

    def test_actual_fragmentation_ping_and_server_mask_refusal(self):
        first=b'{"type":"';second=b'event"}'
        frames=bytes([1,len(first)])+first+b'\x89\x01p'+bytes([0x80,len(second)])+second
        sock=self.socket_fixture(frames);ws=self.n['LoopbackWebSocket'](100)
        self.assertEqual({'type':'event'},ws.receive())
        self.assertEqual(0x8a,sock.sendall.call_args.args[0][0])
        self.socket_fixture(b'\x81\x80');ws=self.n['LoopbackWebSocket'](100)
        with self.assertRaisesRegex(RuntimeError,'websocket_invalid_server_frame'):ws.receive()

    def test_upgrade_and_incoming_payload_bounds(self):
        self.socket_fixture(b'',False)
        with self.assertRaisesRegex(RuntimeError,'websocket_upgrade_not_verified'):self.n['LoopbackWebSocket'](100)
        frames=b'\x81\x7f'+__import__('struct').pack('!Q',262145)
        self.socket_fixture(frames);ws=self.n['LoopbackWebSocket'](100)
        with self.assertRaisesRegex(RuntimeError,'websocket_receive_bound'):ws.receive()

    def test_token_and_error_response_never_copied_to_output(self):
        ws=Mock();ws.receive.return_value={'type':'res','id':'connect','ok':False,'error':{'message':'gateway-token-private'}}
        with self.assertRaisesRegex(RuntimeError,'gateway_rpc_rejected') as caught:self.n['await_response'](ws,'connect')
        self.assertNotIn('private',str(caught.exception));self.n['output'].assert_not_called()

    def test_private_config_real_nofollow_acl_and_inode_reader(self):
        n=self.n;n['STATE']='/var/lib/quantum-automation';n['stat']=__import__('stat')
        for key,value in {'O_RDONLY':0,'O_NOFOLLOW':131072,'O_NONBLOCK':2048}.items():setattr(n['os'],key,value)
        data=b'{"tools":{"deny":["*"]}}'
        def info(uid=985,mode=0o600,ino=3):
            return SimpleNamespace(st_mode=0o100000|mode,st_uid=uid,st_gid=979,st_size=len(data),st_dev=1,st_ino=ino,st_mtime_ns=8,st_ctime_ns=9)
        n['open_parent']=Mock(return_value=(11,'openclaw.json'));n['os'].open.return_value=22
        s=info();n['os'].fstat.side_effect=[s,s];n['os'].stat.return_value=s;n['os'].read.return_value=data
        self.assertEqual({'tools':{'deny':['*']}},n['private_claw_config']())
        self.assertEqual(131072|2048,n['os'].open.call_args.args[1]);self.assertEqual(11,n['os'].open.call_args.kwargs['dir_fd'])
        for s in (info(uid=0),info(mode=0o644)):
            n['os'].fstat.side_effect=[s];n['os'].stat.return_value=s
            with self.assertRaisesRegex(RuntimeError,'unsafe_smoke_config'):n['private_claw_config']()
        s=info();n['os'].fstat.side_effect=[s,info(ino=4)];n['os'].stat.return_value=s
        with self.assertRaisesRegex(RuntimeError,'smoke_config_read_race'):n['private_claw_config']()

    def test_incomplete_conversion_never_reaches_config_or_rpc(self):
        n=self.n;n['INTENT']='/etc/quantum-automation/openclaw-only-migration.json'
        n['read_fixed']=Mock(return_value=(b'{"schema":1,"state":"converted"}',{}))
        n['validate_completed_intent']=Mock(side_effect=RuntimeError('invalid_completed_migration_intent'))
        n['private_claw_config']=Mock();n['model_smoke']=Mock()
        with self.assertRaisesRegex(RuntimeError,'invalid_completed_migration_intent'):n['smoke_preflight']()
        n['private_claw_config'].assert_not_called();n['model_smoke'].assert_not_called()

    def test_exact_tools_deny_policy_before_runtime_or_inference(self):
        n=self.n;n['INTENT']='intent';n['JOURNAL']='journal'
        n['read_fixed']=Mock(return_value=(b'{"schema":2}',{}))
        n['validate_completed_intent']=Mock(return_value={'journal':{'credentials':{'token':'private'}}})
        n['private_claw_config']=Mock(return_value={'tools':{'deny':[]}})
        n['openclaw_config']=Mock(return_value={'tools':{'deny':['*']}})
        n['assert_runtime_budget']=Mock()
        with self.assertRaisesRegex(RuntimeError,'model_smoke_exact_security_policy_drift'):n['smoke_preflight']()
        n['assert_runtime_budget'].assert_not_called()

    def test_terminal_receipt_uses_effective_model_and_no_tool_success(self):
        for bad in ('missing','run','provider','model','tools'):
            value=copy.deepcopy(self.fixture_final());meta=value['result']['meta']['agentMeta']
            if bad=='missing':del meta['terminalReceipt']
            if bad=='run':meta['terminalReceipt']['runId']='other'
            if bad in ('provider','model'):meta['terminalReceipt']['effective'][bad]='other'
            if bad=='tools':meta['terminalReceipt']['successfulToolNames']=['exec']
            with self.assertRaisesRegex(RuntimeError,'model_terminal_receipt_or_tool_evidence'):self.n['final_proof'](value,'run')

if __name__=='__main__':unittest.main()
