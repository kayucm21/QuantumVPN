"""Guarded additive sandbox for only the existing local llama.cpp service.

Default is read-only. --apply requires the reviewed base-unit SHA256, idle
runtime and unchanged protected files. No model/ExecStart/CPU/RAM/VPN/node/APK
or network-policy edits. Existing IPAddress rules do NOT prove BPF enforcement.
Readiness never uses inference/wake endpoints.

Without a shared inference lock, repeated idle checks cannot exclude a request
arriving after the final check. Apply in an owner-coordinated maintenance window.
"""
from __future__ import annotations

import argparse
import json
import os
import re

REMOTE = r'''
import fcntl,hashlib,json,os,re,secrets,stat,subprocess,tempfile,time
from pathlib import Path
from urllib.request import HTTPRedirectHandler,ProxyHandler,Request,build_opener
SERVICE='quantumvpn-llama.service'
UNIT=Path('/etc/systemd/system/quantumvpn-llama.service')
DIRECTORY=Path('/etc/systemd/system/quantumvpn-llama.service.d')
DROPIN=DIRECTORY/'50-quantumvpn-sandbox.conf'
RECOVERY=Path('/var/lib/quantumvpn-ai-sandbox')
BINARY=Path('/opt/quantumvpn-ai/runtime/llama-server')
MANIFEST=Path('/opt/quantumvpn-ai/runtime-manifest.json')
MODEL=Path('/usr/share/ollama/.ollama/models/blobs/sha256-7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa')
COMMIT='d81235049384534c167caea52b85a694f6103d14'
MODEL_SHA='7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa'
BASE='http://127.0.0.1:11435'
PROTECTED=(UNIT,BINARY,MANIFEST,Path('/etc/systemd/system/rospanel.service'),
           Path('/var/lib/rospanel/xray/config.json'),Path('/etc/nginx/nginx.conf'),
           Path('/etc/nginx/sites-available/quantumvpn-operator'))
BODY=b"""# Managed by Quantum Control: ai-sandbox-v1
[Service]
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
"""
HARDENED={'CapabilityBoundingSet':'','AmbientCapabilities':'','ProtectKernelTunables':'yes',
          'ProtectKernelModules':'yes','ProtectKernelLogs':'yes','ProtectControlGroups':'yes',
          'RestrictSUIDSGID':'yes','RestrictRealtime':'yes','LockPersonality':'yes'}
BASE_PROPERTIES=('User','Group','NoNewPrivileges','ProtectSystem','ProtectHome','PrivateTmp',
                 'CPUQuotaPerSecUSec','MemoryMax','TasksMax','RestrictAddressFamilies')
PROPERTIES=(*BASE_PROPERTIES,*HARDENED,'SystemCallArchitectures','ActiveState','MainPID',
            'FragmentPath','DropInPaths','NeedDaemonReload')
class Refused(Exception):pass
def require(condition,reason):
    if not condition:raise Refused(reason)
def command(argv,timeout=15):
    fixed=(['systemctl','--version'],['systemctl','daemon-reload'],['systemctl','restart',SERVICE],
           ['systemd-analyze','verify',str(UNIT)])
    show=(argv[:3]==['systemctl','show',SERVICE] and argv[3:]==['--property='+key for key in PROPERTIES])
    require(argv in fixed or show,'command_not_allowlisted')
    result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=timeout)
    require(result.returncode==0,'system_command_failed')
    require(len(result.stdout)<=65536,'system_output_too_large')
    return result.stdout
def safe_directory(path,mode=None):
    st=path.lstat()
    require(stat.S_ISDIR(st.st_mode) and not path.is_symlink() and st.st_uid==0 and not st.st_mode&0o022,'unsafe_directory')
    if mode is not None:require(stat.S_IMODE(st.st_mode)==mode,'directory_mode_mismatch')
    return (st.st_dev,st.st_ino)
def file_bytes(path,maximum,required=True):
    try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    except FileNotFoundError:
        require(not required,'required_file_missing')
        return None
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and st.st_size<=maximum,'unsafe_file')
        with os.fdopen(fd,'rb',closefd=False) as stream:value=stream.read(maximum+1)
        require(len(value)<=maximum,'file_too_large')
        after=os.fstat(fd)
        stable=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        require(stable(after)==stable(st),'file_changed_during_read')
        return value
    finally:os.close(fd)
def digest(value):return hashlib.sha256(value).hexdigest()
def identity():
    out={}
    for path in PROTECTED:
        value=file_bytes(path,100*1024*1024,required=path in (UNIT,BINARY,MANIFEST))
        out[str(path)]=digest(value) if value is not None else None
    st=MODEL.lstat()
    require(stat.S_ISREG(st.st_mode) and not MODEL.is_symlink() and st.st_size<=2*1024**3,'unsafe_model_file')
    out['model_stat']=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
    return out
def properties():
    value=command(['systemctl','show',SERVICE,*['--property='+key for key in PROPERTIES]])
    result={}
    for line in value.splitlines():
        key,sep,item=line.partition('=')
        if sep and key in PROPERTIES:
            require(key not in result,'duplicate_service_property')
            result[key]=item
    require(set(result)==set(PROPERTIES),'missing_service_property')
    return result
def verify_base(values):
    expected={'ActiveState':'active','FragmentPath':str(UNIT),'NeedDaemonReload':'no','User':'ollama',
              'Group':'ollama','NoNewPrivileges':'yes','ProtectSystem':'strict','ProtectHome':'yes',
              'PrivateTmp':'yes','MemoryMax':'1468006400','TasksMax':'48'}
    require(all(values.get(k)==v for k,v in expected.items()),'owned_active_runtime_required')
    require(values.get('CPUQuotaPerSecUSec') in ('800ms','800000us'),'resource_limit_mismatch')
    require(set(values.get('DropInPaths','').split()) in (set(),{str(DROPIN)}),'foreign_dropin_refused')
    pid=values.get('MainPID','')
    require(re.fullmatch('[1-9][0-9]{0,9}',pid),'runtime_pid_invalid')
    require((Path('/proc')/pid/'exe').resolve()==BINARY,'running_binary_mismatch')
def verify_install():
    for path in (Path('/etc/systemd/system'),Path('/opt/quantumvpn-ai'),BINARY.parent):safe_directory(path)
    raw=file_bytes(UNIT,16384)
    require(b'--host 127.0.0.1 --port 11435' in raw and b'--offline' in raw and b'--model '+str(MODEL).encode() in raw,'owned_unit_command_mismatch')
    manifest=json.loads(file_bytes(MANIFEST,16384))
    require(manifest.get('managed_by')=='quantum-control' and manifest.get('engine')=='llama.cpp'
            and manifest.get('commit')==COMMIT and manifest.get('model_sha256')==MODEL_SHA
            and manifest.get('binary_sha256')==digest(file_bytes(BINARY,100*1024*1024)),'pinned_runtime_mismatch')
    if DIRECTORY.exists() or DIRECTORY.is_symlink():safe_directory(DIRECTORY)
    previous=file_bytes(DROPIN,16384,False)
    require(previous is None or previous==BODY,'foreign_sandbox_dropin_refused')
    values=properties();verify_base(values)
    return raw,previous,values
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
def local_json(path):
    require(path in ('/health','/props','/slots'),'runtime_endpoint_not_allowlisted')
    request=Request(BASE+path,headers={'Accept':'application/json'})
    with build_opener(ProxyHandler({}),NoRedirect()).open(request,timeout=3) as response:
        require(response.status==200,'runtime_http_status')
        raw=response.read(32769)
    require(len(raw)<=32768,'runtime_response_too_large')
    return json.loads(raw)
def readiness(unit,check_idle=True):
    health,props=local_json('/health'),local_json('/props')
    require(isinstance(health,dict) and health.get('status')=='ok' and isinstance(props,dict),'runtime_not_ready')
    sleeping=props.get('is_sleeping')
    require(type(sleeping) is bool and type(props.get('total_slots')) is int and 1<=props['total_slots']<=8,'runtime_state_unknown')
    if sleeping:return {'ready':True,'sleeping':True,'idle':True,'idle_source':'sleeping_props'}
    if not check_idle or b'--no-slots' in unit:return {'ready':True,'sleeping':False,'idle':False,'idle_source':'slots_disabled'}
    # /slots is not on the upstream no-wake list: never query it when sleeping.
    slots=local_json('/slots')
    require(isinstance(slots,list) and len(slots)==props['total_slots'] and all(isinstance(row,dict) and type(row.get('is_processing')) is bool for row in slots),'slot_state_unknown')
    return {'ready':True,'sleeping':False,'idle':all(not row['is_processing'] for row in slots),'idle_source':'slots'}

def wait_readiness(unit):
    deadline=time.monotonic()+60
    while True:
        try:return readiness(unit,check_idle=False)
        except Exception:
            require(time.monotonic()<deadline,'runtime_readiness_timeout')
            time.sleep(1)
def verify_hardening(values):
    require(all(values.get(key)==value for key,value in HARDENED.items()),'hardening_property_mismatch')
    require(values.get('SystemCallArchitectures') in ('native','x86-64'),'syscall_architecture_mismatch')
    pid=values['MainPID']
    raw=(Path('/proc')/pid/'status').read_text()
    fields={line.partition(':')[0]:line.partition(':')[2].strip() for line in raw.splitlines() if ':' in line}
    require(fields.get('NoNewPrivs')=='1' and fields.get('Seccomp')=='2','process_filter_not_confirmed')
    require(all(re.fullmatch('0{1,16}',fields.get(key,'')) for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),'process_capabilities_not_empty')
def exclusive(path,value,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(value);stream.flush();os.fsync(fd)
    finally:os.close(fd)
def atomic_dropin(value):
    safe_directory(DIRECTORY)
    dirfd=os.open(DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    temp='.qvpn-sandbox-'+secrets.token_hex(8)+'.part'
    fd=None;created=False;linked=False;own=None
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=dirfd);created=True
        os.fchmod(fd,0o644)
        with os.fdopen(fd,'wb') as stream:
            fd=None
            stream.write(value);stream.flush();os.fsync(stream.fileno())
            st=os.fstat(stream.fileno());own=(st.st_dev,st.st_ino)
        # Atomic additive install: unlike replace(), a concurrent target is
        # never overwritten, even when it was absent at preflight.
        os.link(temp,DROPIN.name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
        linked=True
        os.fsync(dirfd)
        # Cleanup remains part of the transaction. If unlink/fsync fails,
        # remove only our installed inode instead of leaving a dropin whose
        # caller has not yet marked the write as successful.
        os.unlink(temp,dir_fd=dirfd);created=False
        os.fsync(dirfd)
        return own
    except Exception:
        if linked:
            st=os.stat(DROPIN.name,dir_fd=dirfd,follow_symlinks=False)
            require((st.st_dev,st.st_ino)==own,'concurrent_dropin_change_manual_recovery_required')
            os.unlink(DROPIN.name,dir_fd=dirfd)
        raise
    finally:
        try:
            if fd is not None:os.close(fd)
            if created:os.unlink(temp,dir_fd=dirfd)
        finally:os.close(dirfd)
def recovery(unit,previous):
    safe_directory(RECOVERY.parent)
    if not RECOVERY.exists():RECOVERY.mkdir(mode=0o700)
    safe_directory(RECOVERY,0o700)
    folder=Path(tempfile.mkdtemp(prefix='sandbox-',dir=RECOVERY));os.chmod(folder,0o700)
    exclusive(folder/'base-unit.before',unit,0o600)
    if previous is not None:exclusive(folder/'dropin.before',previous,0o600)
    exclusive(folder/'identity.json',json.dumps({'schema':1,'unit_sha256':digest(unit),'dropin_existed':previous is not None}).encode(),0o600)
    return folder
def rollback(previous,created_directory,restart_attempted,owned_inode):
    require(file_bytes(DROPIN,16384,False)==BODY,'concurrent_dropin_change_manual_recovery_required')
    # An existing identical managed dropin returns AlreadyHardened and is
    # never replaced. This transaction therefore owns only an additive file.
    require(previous is None,'rollback_existing_file_refused')
    st=DROPIN.lstat()
    require(stat.S_ISREG(st.st_mode) and (st.st_dev,st.st_ino)==owned_inode,'concurrent_dropin_change_manual_recovery_required')
    DROPIN.unlink()
    if created_directory and not any(DIRECTORY.iterdir()):DIRECTORY.rmdir()
    command(['systemctl','daemon-reload'])
    if restart_attempted:command(['systemctl','restart',SERVICE],45)
def main_remote():
    require(os.geteuid()==0,'root_required')
    raw,previous,before_values=verify_install()
    before=identity();state=readiness(raw)
    if previous==BODY:verify_hardening(before_values)
    info={'unit_sha256':digest(raw),'ready':state['ready'],'sleeping':state['sleeping'],
          'idle':state['idle'],'idle_source':state['idle_source'],'already_hardened':previous==BODY,
          'network_bpf_enforcement':'not_verified','network_policy_changed':False}
    if not APPLY:print(json.dumps({'status':'ReadOnly',**info}),flush=True);return
    require(re.fullmatch('[a-f0-9]{64}',EXPECTED_UNIT_SHA256 or '') and digest(raw)==EXPECTED_UNIT_SHA256,'expected_unit_sha256_mismatch')
    if previous==BODY:
        print(json.dumps({'status':'AlreadyHardened',**info}),flush=True);return
    require(state['idle'],'inference_busy_or_idle_unknown')
    version=command(['systemctl','--version']).splitlines()[0]
    match=re.match('systemd ([0-9]{1,3}) ',version+' ')
    require(match and int(match[1])>=247,'systemd_features_not_supported')
    lockfd=os.open('/run/lock/quantumvpn-ai-sandbox.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(lockfd,'r+') as lock:
        st=os.fstat(lock.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'unsafe_lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(identity()==before and file_bytes(DROPIN,16384,False)==previous,'preflight_changed')
        require(readiness(raw)['idle'],'inference_busy_or_idle_unknown')
        folder=recovery(raw,previous)
        created_directory=not DIRECTORY.exists()
        if created_directory:DIRECTORY.mkdir(mode=0o755)
        directory_identity=safe_directory(DIRECTORY)
        written=False;restart_attempted=False;owned_inode=None
        try:
            owned_inode=atomic_dropin(BODY);written=True
            command(['systemd-analyze','verify',str(UNIT)],30)
            require(identity()==before,'protected_files_changed')
            require(readiness(raw)['idle'],'inference_started_before_reload')
            command(['systemctl','daemon-reload'])
            require(readiness(raw)['idle'],'inference_started_before_restart')
            require(file_bytes(DROPIN,16384)==BODY and identity()==before,'pre_restart_state_changed')
            restart_attempted=True
            command(['systemctl','restart',SERVICE],45)
            state=wait_readiness(raw)
            after_values=properties();verify_base(after_values);verify_hardening(after_values)
            require(all(after_values[k]==before_values[k] for k in BASE_PROPERTIES),'existing_service_limits_changed')
            require(identity()==before and file_bytes(DROPIN,16384)==BODY,'postflight_protected_files_changed')
            print(json.dumps({'status':'Hardened','changed':True,'service':SERVICE,'ready':state['ready'],
                              'sleeping':state['sleeping'],'process_caps_empty':True,'seccomp_active':True,
                              'network_bpf_enforcement':'not_verified','network_policy_changed':False,
                              'recovery_path':str(folder),'idle_check_not_atomic_with_callers':True}),flush=True)
        except Exception:
            if written:
                rollback(previous,created_directory,restart_attempted,owned_inode)
                if restart_attempted:
                    wait_readiness(raw);verify_base(properties())
                print(json.dumps({'status':'RolledBack','recovery_path':str(folder),'restarted_only_llama':restart_attempted}),flush=True)
            elif created_directory and safe_directory(DIRECTORY)==directory_identity and not any(DIRECTORY.iterdir()):
                DIRECTORY.rmdir()
            raise
if RUN_REMOTE:
    try:main_remote()
    except Exception as error:
        reason=str(error) if isinstance(error,Refused) else 'unexpected_error'
        print(json.dumps({'status':'Failed','reason':reason}),flush=True)
        raise SystemExit(1)
'''


def main() -> None:
    import paramiko
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--expected-unit-sha256', default='')
    options = parser.parse_args()
    if options.apply and not re.fullmatch('[a-f0-9]{64}', options.expected_unit_sha256):
        parser.error('--apply requires the SHA-256 from a reviewed read-only inventory')
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -B -', timeout=240)
        stdin.write('APPLY=' + repr(options.apply) + '\nEXPECTED_UNIT_SHA256=' + repr(options.expected_unit_sha256)
                    + '\nRUN_REMOTE=True\n' + REMOTE)
        stdin.channel.shutdown_write()
        while True:
            line = stdout.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise SystemExit('Sandbox report exceeded the safe limit')
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read(65536)  # Raw SSH/systemd/HTTP/credential details stay suppressed.
        if stdout.channel.recv_exit_status():
            raise SystemExit('AI sandbox operation failed; raw details suppressed')
    finally:
        client.close()


if __name__ == '__main__':
    main()
