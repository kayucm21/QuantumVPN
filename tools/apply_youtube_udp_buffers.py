"""Guarded server-only UDP buffer repair; read-only unless --apply/--rollback.

Never rewrites RosPanel databases, Xray profiles, credentials or Android rules.
An apply/rollback restarts rospanel to recreate its UDP sockets. The independent
reserve service is untouched. Existing configuration and sysctl values are
verified, saved privately and restored on failure.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid


REMOTE = r'''
import base64,hashlib,json,os,re,socket,subprocess,time,uuid
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path('/var/lib/quantumvpn-operator/performance-backups')
TARGET=Path('/etc/sysctl.d/99-z-quantumvpn-udp-buffers.conf')
CONFIG=Path('/var/lib/rospanel/xray/config.json')
BINARY=Path('/var/lib/rospanel/bin/xray')
ASSETS=Path('/var/lib/rospanel/geo')
HEADER='# QuantumVPN managed UDP buffers; previous state has a private backup.\n'
LIMITS={'net.core.rmem_default':1048576,'net.core.rmem_max':16777216,'net.core.wmem_max':16777216}

def run(args,timeout=15):
    env=dict(os.environ,XRAY_LOCATION_ASSET=str(ASSETS))
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=timeout,cwd=CONFIG.parent,env=env)
    if p.returncode: raise RuntimeError('Server command failed: '+args[0]+' '+args[1]+'; raw output suppressed')
    return p.stdout.strip()

def values(): return {k:int(run(['sysctl','-n',k])) for k in LIMITS}

def desired_values(previous): return {k:max(previous[k],v) for k,v in LIMITS.items()}

def persistent_settings_match(state,settings):
    expected=(HEADER+''.join(k+' = '+str(v)+'\n' for k,v in settings.items())).encode()
    return state is not None and base64.b64decode(state['data_b64'])==expected

def fingerprint():
    return hashlib.sha256(json.dumps(json.loads(CONFIG.read_text()),sort_keys=True,separators=(',',':')).encode()).hexdigest()

def assert_paths():
    if ROOT.is_symlink() or (ROOT.exists() and ROOT.resolve()!=ROOT): raise RuntimeError('Unsafe backup root')
    if TARGET.parent.resolve()!=TARGET.parent or TARGET.is_symlink(): raise RuntimeError('Unsafe sysctl target')
    if not CONFIG.is_file() or not BINARY.is_file() or not (ASSETS/'geosite.dat').is_file(): raise RuntimeError('Expected RosPanel files missing')

def file_state():
    if not TARGET.exists(): return None
    data=TARGET.read_bytes()
    if len(data)>8192 or not data.startswith(HEADER.encode()): raise RuntimeError('Unrecognized existing sysctl file; not overwritten')
    return {'data_b64':base64.b64encode(data).decode(),'mode':TARGET.stat().st_mode & 0o777}

def replace_file(data,mode=0o644):
    temp=TARGET.with_name(TARGET.name+'.tmp-'+uuid.uuid4().hex)
    try:
        fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
        with os.fdopen(fd,'wb') as stream: stream.write(data)
        os.chmod(temp,mode);os.replace(temp,TARGET)
    finally:
        if temp.exists(): temp.unlink()

def restore_file(state):
    if state is None:
        if TARGET.exists():
            if not TARGET.read_bytes().startswith(HEADER.encode()): raise RuntimeError('Sysctl file changed; not deleted')
            TARGET.unlink()
    else: replace_file(base64.b64decode(state['data_b64']),state['mode'])

def set_values(settings):
    for k,v in settings.items(): run(['sysctl','-w',k+'='+str(v)])

def mark_verified(backup,state):
    # Persist completion only AFTER the service/socket restart and health gates.
    temp=backup.with_name(backup.name+'.tmp-'+uuid.uuid4().hex)
    try:
        with os.fdopen(os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as stream:
            json.dump(dict(state,phase='verified'),stream)
        os.replace(temp,backup)
    finally:
        if temp.exists(): temp.unlink()

def restart_and_check():
    run(['systemctl','restart','rospanel'],30)
    until=time.monotonic()+25
    while time.monotonic()<until:
        try:
            if run(['systemctl','is-active','rospanel'])=='active':
                with socket.create_connection(('127.0.0.1',18081),timeout=1): return
        except (OSError,RuntimeError): pass
        time.sleep(1)
    raise RuntimeError('RosPanel local SOCKS health did not recover')

assert_paths()
previous=values();old_file=file_state();before_config=fingerprint()
run([str(BINARY),'run','-test','-config',str(CONFIG)],20)
if run(['systemctl','is-active','rospanel'])!='active': raise RuntimeError('RosPanel is not active')
if MODE=='inspect':
    print(json.dumps({'mode':'read_only','previous':previous,'proposed':desired_values(previous),'sysctl_file_exists':old_file is not None}))
elif MODE=='apply':
    desired=desired_values(previous)
    if desired==previous and persistent_settings_match(old_file,desired):
        print(json.dumps({'status':'AlreadyConfigured','changed':False}))
    else:
        if int(next(r.split()[1] for r in Path('/proc/meminfo').read_text().splitlines() if r.startswith('MemAvailable:')))<1048576:
            raise RuntimeError('Insufficient memory headroom for buffer repair')
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(ROOT,0o700)
        backup=ROOT/('udp-buffer-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+TRANSACTION+'.json')
        state={'schema':1,'phase':'prepared','target':str(TARGET),'previous':previous,'desired':desired,'previous_file':old_file,'config_sha256':before_config}
        with os.fdopen(os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as stream: json.dump(state,stream)
        if values()!=previous or file_state()!=old_file or fingerprint()!=before_config: raise RuntimeError('Preflight state changed')
        try:
            content=HEADER+''.join(k+' = '+str(v)+'\n' for k,v in desired.items())
            replace_file(content.encode());set_values(desired);restart_and_check()
            if values()!=desired or fingerprint()!=before_config: raise RuntimeError('Post-restart configuration mismatch')
            mark_verified(backup,state)
        except Exception:
            restore_file(old_file);set_values(previous);restart_and_check()
            print(json.dumps({'status':'RolledBackAfterFailure','backup_path':str(backup)}),flush=True)
            raise
        print(json.dumps({'status':'Applied','changed':True,'backup_path':str(backup),'values':values(),'rospanel':'active','xray_config_unchanged':True}))
elif MODE=='rollback':
    backup=Path(BACKUP)
    if backup.is_symlink() or backup.parent.resolve()!=ROOT or not re.fullmatch(r'udp-buffer-[0-9TZ]+-[a-f0-9]{32}\.json',backup.name):
        raise RuntimeError('Unsafe rollback target')
    state=json.loads(backup.read_text())
    if state.get('schema')!=1 or state.get('target')!=str(TARGET) or set(state.get('previous',{}))!=set(LIMITS): raise RuntimeError('Invalid rollback state')
    if values()!=state['desired']: raise RuntimeError('Sysctl state changed since apply; rollback refused')
    expected=(HEADER+''.join(k+' = '+str(v)+'\n' for k,v in state['desired'].items())).encode()
    if not TARGET.exists() or TARGET.read_bytes()!=expected: raise RuntimeError('Sysctl file changed since apply')
    restore_file(state['previous_file']);set_values(state['previous']);restart_and_check()
    print(json.dumps({'status':'RolledBack','backup_path':str(backup),'values':values(),'rospanel':'active'}))
else: raise RuntimeError('Unknown repair mode')
'''


POSTCHECK = r'''
# A service restart can interrupt the SSH reply. Confirm ONLY this transaction;
# never retry a mutation, and never infer success just from current sysctls.
import hashlib,json,socket,subprocess
from pathlib import Path
root=Path('/var/lib/quantumvpn-operator/performance-backups')
def require_verified(state):
    if state.get('phase')!='verified': raise RuntimeError('Transaction restart/health completion not confirmed')

rows=list(root.glob('udp-buffer-*-'+TRANSACTION+'.json'))
if len(rows)!=1 or rows[0].is_symlink() or rows[0].parent.resolve()!=root: raise RuntimeError('Transaction backup unavailable')
state=json.loads(rows[0].read_text())
require_verified(state)
target=Path('/etc/sysctl.d/99-z-quantumvpn-udp-buffers.conf')
if state.get('schema')!=1 or state.get('target')!=str(target): raise RuntimeError('Transaction identity mismatch')
header='# QuantumVPN managed UDP buffers; previous state has a private backup.\n'
expected=(header+''.join(k+' = '+str(v)+'\n' for k,v in state['desired'].items())).encode()
if target.is_symlink() or not target.is_file() or target.read_bytes()!=expected: raise RuntimeError('Persistent settings not confirmed')
current={k:int(subprocess.check_output(['sysctl','-n',k],timeout=5).strip()) for k in state['desired']}
if current!=state['desired']: raise RuntimeError('Runtime settings not confirmed')
config=json.loads(Path('/var/lib/rospanel/xray/config.json').read_text())
digest=hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if digest!=state['config_sha256']: raise RuntimeError('VPN configuration changed')
if subprocess.check_output(['systemctl','is-active','rospanel'],timeout=5).strip()!=b'active': raise RuntimeError('Service not active')
with socket.create_connection(('127.0.0.1',18081),timeout=3): pass
print(json.dumps({'status':'AppliedConfirmedAfterReconnect','changed':True,'backup_path':str(rows[0]),'values':current,'rospanel':'active','xray_config_unchanged':True}))
'''


def main() -> None:
    import paramiko

    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--apply',action='store_true')
    mode.add_argument('--rollback',metavar='PRIVATE_BACKUP_PATH')
    options=parser.parse_args()
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password: raise SystemExit('QVPN_VDS_PASSWORD is required in the environment, not arguments.')
    transaction=uuid.uuid4().hex
    def connect():
        session=paramiko.SSHClient()
        session.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
        session.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            session.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=20,auth_timeout=20)
        except Exception:
            session.close()
            raise
        return session
    def invoke(session,source):
        stdin,stdout,stderr=session.exec_command('python3 -',timeout=120)
        stdin.write(source);stdin.channel.shutdown_write()
        rows=[]
        for line in stdout: rows.append(json.loads(line))
        stderr.read()
        return stdout.channel.recv_exit_status(),rows
    client=connect()
    try:
        selected='rollback' if options.rollback else 'apply' if options.apply else 'inspect'
        wrapper='MODE = '+repr(selected)+'\nBACKUP = '+repr(options.rollback)+'\nTRANSACTION = '+repr(transaction)+'\nimport json\ntry:\n    exec('+repr(REMOTE)+')\nexcept Exception as error:\n    print(json.dumps({"status":"Failed","error_type":type(error).__name__,"reason":str(error) if isinstance(error,RuntimeError) else "unexpected failure; details suppressed"}),flush=True)\n    raise SystemExit(1)\n'
        try: code,rows=invoke(client,wrapper)
        except (paramiko.SSHException,EOFError,OSError): code,rows=-1,[]
        if code and not rows and options.apply:
            client.close();client=connect()
            # Read-only reconciliation after an ambiguous transport interruption.
            code,rows=invoke(client,'TRANSACTION = '+repr(transaction)+'\n'+POSTCHECK)
        for row in rows: print(json.dumps(row),flush=True)
        if code: raise RuntimeError('Guarded UDP repair failed; remote stderr suppressed.')
    finally: client.close()


if __name__ == '__main__': main()
