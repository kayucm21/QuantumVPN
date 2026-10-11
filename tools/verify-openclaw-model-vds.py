"""Bounded Gateway-only model verification; default is read-only preflight.

--model-smoke is the sole inference opt-in. No OpenClaw CLI, embedded fallback,
service/config mutations or token output. Ready OpenClaw-only conversion required.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

MIGRATION_SHA256 = 'b8eda8c2c6abc9fd9c2cfa68a054054d3ecc76bd6af4897a5a4905640f5151c0'
migration_path = Path(__file__).with_name('migrate-openclaw-only-vds.py')
if hashlib.sha256(migration_path.read_bytes()).hexdigest() != MIGRATION_SHA256:
    raise RuntimeError('reviewed_migration_source_drift')
spec = importlib.util.spec_from_file_location('reviewed_claw_only', migration_path)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

RPC = r'''
import resource,struct,signal,uuid

MODEL_DIGEST='7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435'
MODEL_PEAK_MIB=1408
RESERVE_MIB=384
CLIENT_MIB=128
REQUIRED_MIB=MODEL_PEAK_MIB+RESERVE_MIB+CLIENT_MIB
FRAME_LIMIT=262144
SOURCE_HASHES={
 'call-DmvqNvMY.mjs':'2e3b564bd0e3bef6c553ea1ac8def0bec46d86275e5fd4e91b6d0cfc3572f121',
 'client-B4O1WKhF.mjs':'5434ab96d41c82f8717e0bb5b1046f06d41cac0b3da9a5cbf384e0aaad8cf5cc',
 'method-scopes-C-MKLkWf.mjs':'82c26c6c1453e07cf6637906e7278be570772f16db21863816d9f144e43b4f40',
 'client-info-S_xwnr2o.mjs':'3fcaf44fb6c276a1f16e73056810d9e0a58a228a8ce915b0dd081758dbe09cb9',
 'sessions-Bw59kgfQ.mjs':'044fb9b42bd88b3d6b326b527ff61dc029c47517fcdbd7e75629a98ec4730734',
 'src-D2gvuSyP.mjs':'8f5ed8aa897a9d6a23dcfb597a071d875650a96d6346c63da291308999eaea53',
 'agent-XuZuntjH.mjs':'373c128c874b1f12d9c24d1dba838d2d26a6f71b76bbf27f817ae1bbafef7820',
 'agent-turn-service-W_0N3NA0.mjs':'c373460e63699a72a7b09d10a4ff02711fc36ac66568f91d9efb329101b4839d',
 'ws-connection-CsJ9cE0L.mjs':'b51e1190bd1ca47b2497311e798ee95c2d7acd1e1a410bc6f6c1b1aeb5862f53',
 'embedded-agent-gxn-c3nS.mjs':'5241e89998d2798f0621418c04438adb07b798a0b92537e91718bf116246d808',
}

def existing_verification_lock():
    # No O_CREAT: default preflight cannot create a lock or other file.
    parent=os.open('/run/lock',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fd=None
    try:
        s=os.fstat(parent)
        if not stat.S_ISDIR(s.st_mode) or (s.st_uid,s.st_gid)!=(0,0) or (s.st_mode&0o022 and not s.st_mode&stat.S_ISVTX):raise GuardError('unsafe_existing_lock_parent')
        fd=os.open('quantum-automation-install.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        s=os.fstat(fd);entry=os.stat('quantum-automation-install.lock',dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid)!=(0,0) or stat.S_IMODE(s.st_mode) not in (0o600,0o644) or (s.st_dev,s.st_ino)!=(entry.st_dev,entry.st_ino):raise GuardError('unsafe_existing_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return fd
    except Exception:
        if fd is not None:os.close(fd)
        raise
    finally:os.close(parent)

def private_claw_config():
    path=STATE+'/openclaw/openclaw.json';parent,name=open_parent(path);fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        s=os.fstat(fd);entry=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid)!=(CLAW_UID,CLAW_GID) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>65536 or (s.st_dev,s.st_ino)!=(entry.st_dev,entry.st_ino):raise GuardError('unsafe_smoke_config')
        data=os.read(fd,65537);after=os.fstat(fd);entry=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if len(data)!=s.st_size or (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (s.st_dev,s.st_ino)!=(entry.st_dev,entry.st_ino):raise GuardError('smoke_config_read_race')
        return json.loads(data)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def bounded_metadata(endpoint):
    if endpoint not in ('tags','ps'):raise GuardError('ollama_metadata_scope')
    with urllib.request.urlopen('http://127.0.0.1:11434/api/'+endpoint,timeout=5) as response:data=response.read(FRAME_LIMIT+1)
    if len(data)>FRAME_LIMIT:raise GuardError('ollama_metadata_bound')
    value=json.loads(data)
    if not isinstance(value,dict) or not isinstance(value.get('models'),list):raise GuardError('ollama_metadata_schema')
    return value['models']

def memory_gate():
    r=command(['systemctl','show','ollama.service','-p','ActiveState','-p','MemoryPeak','-p','MemoryCurrent'],timeout=5)
    state=dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
    peak=state.get('MemoryPeak','')
    if state.get('ActiveState')!='active' or not peak.isdigit() or not 0<int(peak)<=MODEL_PEAK_MIB*1024**2:raise GuardError('ollama_peak_exceeds_reviewed_allowance_or_unavailable')
    memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    available=int(memory['MemAvailable'].split()[0])//1024
    if available<REQUIRED_MIB:raise GuardError('insufficient_model_smoke_memory_headroom')
    return {'available_mib':available,'required_mib':REQUIRED_MIB,'model_peak_allowance_mib':MODEL_PEAK_MIB,'observed_ollama_peak_mib':(int(peak)+1024**2-1)//1024**2,'reserve_mib':RESERVE_MIB,'client_limit_mib':CLIENT_MIB}

def smoke_preflight():
    data,_=read_fixed(INTENT);intent=json.loads(data)
    docs=validate_completed_intent(intent)
    token=docs[JOURNAL]['credentials']['token']
    config=private_claw_config()
    if config!=openclaw_config(token):raise GuardError('model_smoke_exact_security_policy_drift')
    if config.get('tools',{}).get('deny')!=['*']:raise GuardError('model_smoke_tools_not_denied')
    account_identity('qvpn-openclaw',CLAW_UID,CLAW_GID,STATE+'/openclaw')
    state=assert_runtime_budget()
    if not service_probe('openclaw'):raise GuardError('model_smoke_gateway_not_loopback_ready')
    package_path=RELEASE+'/openclaw/node_modules/openclaw/package.json'
    package=json.loads(Path(package_path).read_text())
    if package.get('name')!='openclaw' or package.get('version')!='2026.9.9':raise GuardError('model_smoke_version_drift')
    for name,expected in SOURCE_HASHES.items():
        if immutable_digest(RELEASE+'/openclaw/node_modules/openclaw/dist/'+name)!=expected:raise GuardError('model_smoke_rpc_source_drift')
    tags=bounded_metadata('tags')
    matches=[m for m in tags if m.get('name')=='qwen3:0.6b' and m.get('model')=='qwen3:0.6b']
    if len(matches)!=1 or matches[0].get('digest')!=MODEL_DIGEST:raise GuardError('model_smoke_ollama_model_identity_drift')
    loaded=bounded_metadata('ps')
    if any(m.get('name')!='qwen3:0.6b' for m in loaded):raise GuardError('unreviewed_concurrent_ollama_model')
    return token,state,memory_gate()

class LoopbackWebSocket:
    def __init__(self,deadline):
        self.deadline=deadline;self.received=0;self.buffer=b''
        self.sock=socket.create_connection(('127.0.0.1',18789),timeout=5)
        key=base64.b64encode(os.urandom(16)).decode()
        request=('GET / HTTP/1.1\r\nHost: 127.0.0.1:18789\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\nUser-Agent: qvpn-model-verifier/1\r\n\r\n').encode()
        self.sock.sendall(request)
        header=b''
        while b'\r\n\r\n' not in header:
            header+=self.read_socket(4096)
            if len(header)>16384:raise GuardError('websocket_header_bound')
        raw,self.buffer=header.split(b'\r\n\r\n',1)
        lines=raw.decode('ascii').split('\r\n')
        headers={}
        for line in lines[1:]:
            k,v=line.split(':',1);k=k.strip().lower()
            if k in headers:raise GuardError('websocket_duplicate_header')
            headers[k]=v.strip()
        expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if lines[0]!='HTTP/1.1 101 Switching Protocols' or headers.get('upgrade','').lower()!='websocket' or 'upgrade' not in [v.strip() for v in headers.get('connection','').lower().split(',')] or headers.get('sec-websocket-accept')!=expected or 'sec-websocket-extensions' in headers:raise GuardError('websocket_upgrade_not_verified')
    def read_socket(self,n):
        while True:
            left=self.deadline-time.monotonic()
            if left<=0:raise GuardError('model_smoke_wall_timeout')
            self.sock.settimeout(min(5,left))
            try:data=self.sock.recv(n);break
            except socket.timeout:continue
        if not data:raise GuardError('model_smoke_gateway_closed')
        self.received+=len(data)
        if self.received>2*1024**2:raise GuardError('model_smoke_received_bound')
        return data
    def exact(self,n):
        while len(self.buffer)<n:self.buffer+=self.read_socket(n-len(self.buffer))
        value,self.buffer=self.buffer[:n],self.buffer[n:];return value
    def send_frame(self,payload,opcode=1):
        if len(payload)>FRAME_LIMIT or opcode>=8 and len(payload)>125:raise GuardError('websocket_send_bound')
        size=len(payload)
        length=bytes([0x80|size]) if size<126 else bytes([0x80|126])+struct.pack('!H',size) if size<65536 else bytes([0x80|127])+struct.pack('!Q',size)
        mask=os.urandom(4);body=bytes(byte^mask[i%4] for i,byte in enumerate(payload))
        self.sock.sendall(bytes([0x80|opcode])+length+mask+body)
    def send(self,method,params,request_id):
        self.send_frame(json.dumps({'type':'req','id':request_id,'method':method,'params':params},separators=(',',':')).encode())
    def receive(self):
        fragments=b'';fragmented=False
        while True:
            first,second=self.exact(2);fin=bool(first&0x80);opcode=first&15;size=second&127
            if first&0x70 or second&0x80:raise GuardError('websocket_invalid_server_frame')
            if size==126:size=struct.unpack('!H',self.exact(2))[0]
            elif size==127:size=struct.unpack('!Q',self.exact(8))[0]
            if size>FRAME_LIMIT or opcode>=8 and (not fin or size>125):raise GuardError('websocket_receive_bound')
            payload=self.exact(size)
            if opcode==8:raise GuardError('model_smoke_gateway_closed')
            if opcode==9:self.send_frame(payload,10);continue
            if opcode==10:continue
            if opcode==1 and not fragmented:fragmented=not fin
            elif opcode==0 and fragmented:fragmented=not fin
            else:raise GuardError('websocket_unexpected_opcode')
            fragments+=payload
            if len(fragments)>FRAME_LIMIT:raise GuardError('websocket_fragment_bound')
            if fin:
                value=json.loads(fragments.decode('utf-8'))
                if not isinstance(value,dict):raise GuardError('gateway_frame_schema')
                return value
    def close(self):
        self.sock.close()

def connect_params(token):
    return {'minProtocol':4,'maxProtocol':4,'client':{'id':'cli','version':'2026.9.9','platform':'linux','mode':'cli'},'caps':[],'auth':{'token':token},'role':'operator','scopes':['operator.write']}

def validate_hello(hello):
    auth=hello.get('auth',{});server=hello.get('server',{});features=hello.get('features',{})
    if hello.get('type')!='hello-ok' or hello.get('protocol')!=4 or server.get('version')!='2026.9.9' or auth.get('method')!='token' or auth.get('role')!='operator' or auth.get('scopes')!=['operator.write'] or 'agent' not in features.get('methods',[]):raise GuardError('gateway_authenticated_hello_required')

def await_response(ws,request_id,expect_final=False,run_id=None):
    accepted=False
    while True:
        frame=ws.receive()
        if frame.get('type')=='event':continue
        if frame.get('type')!='res' or frame.get('id')!=request_id:raise GuardError('gateway_response_correlation')
        if frame.get('ok') is not True:raise GuardError('gateway_rpc_rejected')
        payload=frame.get('payload')
        if not isinstance(payload,dict):raise GuardError('gateway_response_payload_schema')
        if expect_final and payload.get('status')=='accepted':
            if accepted or payload.get('runId')!=run_id:raise GuardError('gateway_accepted_run_correlation')
            accepted=True;continue
        if expect_final and not accepted:raise GuardError('gateway_final_without_acceptance')
        return payload

def final_proof(payload,run_id):
    # The final response is the correlated agent RPC result, never agent.wait.
    if payload.get('runId')!=run_id or payload.get('status')!='ok' or payload.get('summary')!='completed':raise GuardError('model_final_run_or_status')
    result=payload.get('result')
    if not isinstance(result,dict):raise GuardError('model_final_result_schema')
    result_meta=result.get('meta',{});meta=result_meta.get('agentMeta',{})
    texts=[p.get('text','') for p in result.get('payloads',[]) if isinstance(p,dict) and p.get('isError') is not True and p.get('isStatusNotice') is not True and p.get('isReasoning') is not True]
    if result_meta.get('error') is not None or result_meta.get('aborted') is True or result_meta.get('stopReason') in ('error','toolUse','timeout') or result_meta.get('timeoutPhase') is not None or result_meta.get('providerStarted') is False or meta.get('provider')!='ollama' or meta.get('model')!='qwen3:0.6b' or not any(isinstance(t,str) and t.strip() for t in texts):raise GuardError('model_actual_provider_or_empty_response')
    receipt=meta.get('terminalReceipt',{});effective=receipt.get('effective',{})
    if receipt.get('runId')!=run_id or effective.get('provider')!='ollama' or effective.get('model')!='qwen3:0.6b' or receipt.get('successfulToolNames')!=[]:raise GuardError('model_terminal_receipt_or_tool_evidence')
    return {'provider':'ollama','model':'qwen3:0.6b','response_nonempty':True}

def model_smoke(token,initial,budget):
    # The RPC client runs as the isolated service user, bounded to128MiB AS.
    os.setgroups([]);os.setgid(CLAW_GID);os.setuid(CLAW_UID)
    if (os.getuid(),os.getgid())!=(CLAW_UID,CLAW_GID):raise GuardError('model_client_identity')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_CPU,(60,60))
    signal.alarm(160)
    ws=LoopbackWebSocket(time.monotonic()+150)
    try:
        challenge=ws.receive()
        if challenge.get('type')!='event' or challenge.get('event')!='connect.challenge' or not isinstance(challenge.get('payload',{}).get('nonce'),str) or not challenge['payload']['nonce'].strip():raise GuardError('gateway_challenge_required')
        ws.send('connect',connect_params(token),'connect')
        hello=await_response(ws,'connect')
        validate_hello(hello)
        current=assert_runtime_budget()
        if current.get('MainPID')!=initial.get('MainPID') or current.get('NRestarts')!=initial.get('NRestarts') or not service_probe('openclaw'):raise GuardError('gateway_changed_before_model_request')
        run_id=str(uuid.uuid4());request_id='agent-'+run_id
        budget=memory_gate()  # Last guard immediately before sending any inference.
        ws.send('agent',{'message':'Reply with the single word OK. Do not use tools. /no_think','sessionKey':'agent:main:qvpn-model-smoke-'+run_id,'thinking':'off','deliver':False,'timeout':120,'idempotencyKey':run_id},request_id)
        proof=final_proof(await_response(ws,request_id,True,run_id),run_id)
        current=assert_runtime_budget()
        if current.get('MainPID')!=initial.get('MainPID') or current.get('NRestarts')!=initial.get('NRestarts') or not service_probe('openclaw'):raise GuardError('gateway_changed_during_model_request')
        output({'status':'ModelVerified','model_verified':True,'gateway_only':True,'tools_enabled':False,'inference':True,'client_uid':CLAW_UID,'memory_budget':budget,**proof})
    finally:ws.close();signal.alarm(0)

def verify_main(do_smoke=False):
    resource.setrlimit(resource.RLIMIT_AS,(CLIENT_MIB*1024**2,CLIENT_MIB*1024**2))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    lock=existing_verification_lock()
    try:
        token,state,budget=smoke_preflight()
        if not do_smoke:
            output({'status':'ModelPreflightReady','mode':'read_only','inference':False,'model_verified':False,'gateway_only':True,'tools_enabled':False,'memory_budget':budget});return
        # Re-read all immutable/ACL/runtime gates immediately before privilege drop.
        token,state,budget=smoke_preflight()
        model_smoke(token,state,budget)
    finally:os.close(lock)
'''

def remote_script(model_smoke=False):
    return '\n'.join(['PINS='+repr(migration.base.PINS), migration.base.COMMON,
        migration.base.REMOTE, 'import grp', migration.MIGRATION, RPC,
        f"try:\n verify_main({model_smoke!r})\nexcept GuardError as e:\n output({{'status':'Blocked','code':str(e),'model_verified':False}});raise SystemExit(2)\nexcept Exception as e:\n output({{'status':'Failed','code':type(e).__name__,'model_verified':False}});raise SystemExit(3)"])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-smoke',action='store_true')
    parser.add_argument('--known-hosts',default=str(Path.home()/'.ssh/known_hosts'))
    args=parser.parse_args()
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print(json.dumps({'status':'Blocked','code':'missing_password_environment'}));return 2
    import paramiko
    client=paramiko.SSHClient();client.load_host_keys(args.known_hosts);client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=15)
        incoming,out,err=client.exec_command('python3 -B -',timeout=180)
        incoming.write(remote_script(args.model_smoke));incoming.channel.shutdown_write()
        raw=out.read(16385);error=err.read(4096);status=out.channel.recv_exit_status()
        if error or len(raw)>16384:
            print(json.dumps({'status':'Failed','code':'bounded_remote_report_required','model_verified':False}));return 3
        value=json.loads(raw);print(json.dumps(value,ensure_ascii=False));return status
    except Exception as exc:
        print(json.dumps({'status':'Failed','code':type(exc).__name__,'model_verified':False}));return 3
    finally:client.close()

if __name__=='__main__':sys.exit(main())
