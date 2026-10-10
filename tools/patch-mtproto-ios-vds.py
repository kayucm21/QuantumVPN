"""Guarded native TLS5443 iOS hotfix; default is read-only, --apply is explicit.

Preserves the endpoint, secret, unit, runtime modules and all other services.
Builds a pinned official tree plus two audited patches with limited privileges.
Keeps a durable root-only binary/config rollback; no credentials in output/argv.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

BASELINE_REVISION = '2f1b1f0'
BASELINE_PROTOCOL_SHA256 = 'ff215c9dea0049323a40f3082b88d92f15fad86b809c3f3597057b9457e659c3'


def installer_definitions():
    path = Path(__file__).with_name('install-mtproto-tls-vds.py')
    spec = importlib.util.spec_from_file_location('reviewed_tls_installer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.REMOTE


REMOTE = r'''
BACKUPS=Path('/var/lib/quantumvpn-mtproto-tls-ios-backups')

def emit(value):
    print(json.dumps(value,separators=(',',':')),flush=True)

def atomic_replace(path,data,mode,expected):
    safe_parent(path)
    if path.is_symlink() or not path.is_file() or digest(path)!=expected:
        raise RuntimeError('atomic_target_changed_no_overwrite')
    temporary=path.with_name(path.name+'.ios-'+str(os.getpid())+'.tmp')
    exclusive(temporary,data,mode)
    try:
        if digest(path)!=expected:raise RuntimeError('atomic_target_changed_no_overwrite')
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary.exists():temporary.unlink()

def private_dir(path):
    safe_parent(path)
    if path.is_symlink():raise RuntimeError('backup_directory_symlink_refused')
    path.mkdir(mode=0o700,exist_ok=True)
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise RuntimeError('backup_directory_permissions_refused')

def journal(transaction,value):
    path=transaction/'journal.json'
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    if path.exists():atomic_replace(path,raw,0o600,digest(path))
    else:exclusive(path,raw)

def rollback(transaction,record):
    if record['protected']!=protected_identity():
        raise RuntimeError('rollback_protected_identity_changed_manual_review')
    for name,path,mode in (('binary',ROOT/'mtproto-proxy',0o755),('config',PRIVATE/'config.json',0o600)):
        current=digest(path)
        if current not in (record['old_'+name],record['new_'+name]):
            raise RuntimeError('rollback_foreign_target_manual_review')
        backup=transaction/(name+'.before')
        if backup.is_symlink() or digest(backup)!=record['old_'+name]:
            raise RuntimeError('rollback_backup_identity_refused')
        if current!=record['old_'+name]:
            atomic_replace(path,backup.read_bytes(),mode,current)
    run(['systemctl','restart',SERVICE],30)
    record['phase']='rolled_back';journal(transaction,record)
    emit({'status':'RolledBack','only_tls5443_changed':True,'backup':str(transaction)})

def pending_transactions():
    if not BACKUPS.exists():return []
    private_dir(BACKUPS)
    entries=list(BACKUPS.iterdir())
    if len(entries)>100:raise RuntimeError('backup_count_manual_review_required')
    pending=[]
    for transaction in entries:
        if transaction.is_symlink() or not transaction.is_dir() or not transaction.name.startswith('txn-'):
            raise RuntimeError('unexpected_backup_entry')
        private_dir(transaction)
        path=transaction/'journal.json'
        if not path.exists():raise RuntimeError('incomplete_backup_manual_review_required')
        record=json.loads(path.read_bytes())
        if record.get('patch')!=compat.PATCH_ID:raise RuntimeError('unmanaged_backup_journal')
        if record.get('phase') not in ('verified','rolled_back'):pending.append((transaction,record))
    return pending

def diagnostic_modules(helper_source,baseline_source,base_source):
    runtime=load_runtime_modules(helper_source,baseline_source,base_source)
    diag=types.ModuleType('ios_diagnostic')
    old=sys.modules.get('quantumvpn_mtproto')
    try:
        sys.modules['quantumvpn_mtproto']=runtime['base']
        exec(compile(decode_runtime(DIAGNOSTIC_B64,DIAGNOSTIC_SHA256),'<ios-diagnostic>','exec'),diag.__dict__)
    finally:
        if old is None:sys.modules.pop('quantumvpn_mtproto',None)
        else:sys.modules['quantumvpn_mtproto']=old
    return runtime,diag

def positive_proofs(diag,secret):
    return {profile:diag.probe(secret,client_profile=profile) for profile in
            ('standard',diag.IOS_LEGACY_BROKEN_SNI,diag.IOS_MODERN_SAFARI)}

def negative_proofs(diag,secret):
    # Never transmit a login code/account request. Require original full-HMAC,
    # timestamp, replay cache and explicit-SNI rejection to stay enforced.
    def authenticate(wire):
        deadline=time.monotonic()+3
        try:
            with socket.create_connection(('127.0.0.1',PORT),timeout=1) as conn:
                conn.settimeout(3);conn.sendall(wire)
                diag._authenticate_server(conn,wire,secret,deadline)
            return True
        except (RuntimeError,OSError):return False
    good=diag.build_client_hello(secret,client_profile=diag.IOS_LEGACY_BROKEN_SNI)
    bad=bytearray(good);bad[11]^=1
    old=diag.build_client_hello(secret,client_profile=diag.IOS_LEGACY_BROKEN_SNI,timestamp=int(time.time())-86400*7)
    unknown=diag.build_client_hello(secret,'unknown.example')
    unknown_legacy=diag.build_client_hello(secret,'unknown.example',client_profile=diag.IOS_LEGACY_BROKEN_SNI)
    malformed=bytearray(good);malformed[127]^=128
    # Re-sign the malformed envelope so rejection is not just a bad-HMAC test.
    malformed[11:43]=b'\0'*32
    mac=bytearray(diag.hmac.new(bytes.fromhex(secret),malformed,hashlib.sha256).digest())
    stamp=diag.struct.unpack('<I',mac[28:32])[0]^int(time.time())
    mac[28:32]=diag.struct.pack('<I',stamp);malformed[11:43]=mac
    checks={'wrong_hmac_rejected':not authenticate(bytes(bad)),
            'old_timestamp_rejected':not authenticate(old),
            'unknown_sni_rejected':not authenticate(unknown),
            'unknown_legacy_hostname_rejected':not authenticate(unknown_legacy),
            'malformed_envelope_rejected':not authenticate(bytes(malformed))}
    checks['fresh_hello_accepted']=authenticate(good)
    checks['replayed_hello_rejected']=not authenticate(good)
    return checks

def ios_main():
    if os.geteuid()!=0 or platform.machine() not in ('x86_64','amd64'):
        raise RuntimeError('reviewed_root_x64_host_required')
    lock=install_lock();fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    pending=pending_transactions()
    if pending:
        if not APPLY:raise RuntimeError('pending_transaction_use_apply_to_recover')
        if len(pending)!=1:raise RuntimeError('multiple_pending_transactions_manual_review')
        rollback(*pending[0])
        raise RuntimeError('interrupted_transaction_recovered_retry_after_health_check')
    helper=decode_runtime(MODULE_B64,MODULE_SHA256)
    baseline=decode_runtime(PROTOCOL_B64,PROTOCOL_SHA256)
    base=decode_runtime(BASE_MODULE_B64,BASE_MODULE_SHA256)
    runtime,diag=diagnostic_modules(helper,baseline,base)
    if not managed_install(runtime):raise RuntimeError('managed_tls_install_required')
    config=runtime['_config']();runtime['_verify_runtime'](config)
    if runtime['_service_state']()!='active':raise RuntimeError('active_tls_service_required')
    verify_stats_listener()
    before=protected_identity()
    secret=runtime['_secret']()
    proofs=positive_proofs(diag,secret)
    if not proofs['standard']['ok'] or not proofs[diag.IOS_MODERN_SAFARI]['ok']:
        raise RuntimeError('baseline_protocol_not_confirmed_no_changes')
    existing=config.get('ios_compat',{})
    if existing:
        if existing.get('patch')!=compat.PATCH_ID or existing.get('patch_module_sha256')!=COMPAT_SHA256:
            raise RuntimeError('different_ios_patch_manual_review')
        if not all(p['ok'] for p in proofs.values()):raise RuntimeError('installed_ios_proof_failed')
        negatives=negative_proofs(diag,secret)
        if not all(negatives.values()):raise RuntimeError('installed_authentication_regression')
        emit({'status':'AlreadyPatched','proofs':proofs,'security':negatives,'protected_files_unchanged':before==protected_identity()})
        return
    if not APPLY:
        emit({'status':'Inspected','changed':False,'proofs':proofs,'legacy_ios_reproduced':not proofs[diag.IOS_LEGACY_BROKEN_SNI]['ok']})
        return
    if missing_packages():raise RuntimeError('existing_build_dependencies_required')
    if shutil.disk_usage('/var/tmp').free<600*1024*1024:raise RuntimeError('build_headroom_required')
    account=pwd.getpwnam(USER)
    if account.pw_shell!='/usr/sbin/nologin' or account.pw_dir!='/nonexistent' or not 0<account.pw_uid<1000:
        raise RuntimeError('restricted_build_account_required')
    staging=Path(tempfile.mkdtemp(prefix='quantumvpn-mtproto-tls-build-',dir='/var/tmp'))
    os.chown(staging,account.pw_uid,account.pw_gid)
    transaction=None;record=None
    try:
        emit({'status':'Building','changed':False,'commit':compat.COMMIT})
        source=staging/'source';prefix=['runuser','-u',USER,'--']
        run(prefix+['git','init','-q',str(source)],15,stage='source_init')
        run(prefix+['git','-C',str(source),'remote','add','origin',SOURCE],15,stage='source_remote')
        run(prefix+['git','-C',str(source),'fetch','--depth','1','origin',COMMIT],150,stage='source_fetch')
        run(prefix+['git','-C',str(source),'checkout','--detach','FETCH_HEAD'],20,stage='source_checkout')
        for ref,expected in (('HEAD',compat.COMMIT),('HEAD^{tree}',compat.TREE)):
            if run(prefix+['git','-C',str(source),'rev-parse',ref],5,stage='source_identity').strip()!=expected:
                raise RuntimeError('pinned_source_identity_mismatch')
        run(prefix+['git','-C',str(source),'fsck','--full'],20,stage='source_fsck')
        main_source=(source/'mtproto/mtproto-proxy.c').read_bytes()
        if hashlib.sha256(main_source).hexdigest()!=BASE_SOURCE_SHA256:
            raise RuntimeError('credential_patch_source_identity_required')
        patched_main=patch_source(main_source.decode()).encode()
        original_net=(source/'net/net-tcp-rpc-ext-server.c').read_bytes()
        patched_net=compat.patch_source(original_net)
        if 'l.s_addr = htonl(0x7f000001);' not in (source/'engine/engine-net.c').read_text():
            raise RuntimeError('stats_loopback_invariant_required')
        (source/'mtproto/mtproto-proxy.c').write_bytes(patched_main)
        (source/'net/net-tcp-rpc-ext-server.c').write_bytes(patched_net)
        lock_build_source(source,account);build_pinned_source(source)
        if ((source/'mtproto/mtproto-proxy.c').read_bytes()!=patched_main or
            (source/'net/net-tcp-rpc-ext-server.c').read_bytes()!=patched_net):
            raise RuntimeError('source_changed_during_build')
        binary=source/'objs/bin/mtproto-proxy'
        if binary.is_symlink() or not binary.is_file() or not 1024<=binary.stat().st_size<=100*1024*1024:
            raise RuntimeError('bounded_regular_binary_required')
        candidate=binary.read_bytes();new_binary=hashlib.sha256(candidate).hexdigest()
        new_config=dict(config)
        new_config['binary_sha256']=new_binary
        new_config['ios_compat']={'patch':compat.PATCH_ID,'patch_module_sha256':COMPAT_SHA256,
                                 'commit':compat.COMMIT,'tree':compat.TREE,'net_source_sha256':compat.NET_SOURCE_SHA256,
                                 'patched_net_sha256':hashlib.sha256(patched_net).hexdigest(),'installed_at':int(time.time())}
        raw_config=(json.dumps(new_config,sort_keys=True)+'\n').encode()
        old_binary=digest(ROOT/'mtproto-proxy');old_config=digest(PRIVATE/'config.json')
        if old_binary!=config['binary_sha256'] or runtime['_config']()!=config or before!=protected_identity():
            raise RuntimeError('concurrent_install_change_no_overwrite')
        private_dir(BACKUPS)
        transaction=Path(tempfile.mkdtemp(prefix='txn-',dir=BACKUPS))
        exclusive(transaction/'binary.before',(ROOT/'mtproto-proxy').read_bytes())
        exclusive(transaction/'config.before',(PRIVATE/'config.json').read_bytes())
        exclusive(transaction/'net-tcp-rpc-ext-server.original.c',original_net)
        exclusive(transaction/'net-tcp-rpc-ext-server.patched.c',patched_net)
        exclusive(transaction/'patch.py',decode_runtime(COMPAT_B64,COMPAT_SHA256).encode())
        record={'patch':compat.PATCH_ID,'phase':'prepared','old_binary':old_binary,'new_binary':new_binary,
                'old_config':old_config,'new_config':hashlib.sha256(raw_config).hexdigest(),'protected':before}
        journal(transaction,record)
        emit({'status':'Installing','only_tls5443_restart':True,'backup':str(transaction)})
        atomic_replace(ROOT/'mtproto-proxy',candidate,0o755,old_binary)
        atomic_replace(PRIVATE/'config.json',raw_config,0o600,old_config)
        record['phase']='installed';journal(transaction,record)
        run(['systemctl','restart',SERVICE],30)
        until=time.monotonic()+30
        while time.monotonic()<until:
            if runtime['health_probe']().get('ok'):break
            time.sleep(1)
        runtime['_verify_runtime'](runtime['_config']())
        proofs=positive_proofs(diag,secret);negatives=negative_proofs(diag,secret)
        if not all(p['ok'] for p in proofs.values()):raise RuntimeError('post_patch_protocol_failed')
        if not all(negatives.values()):raise RuntimeError('post_patch_authentication_regression')
        verify_stats_listener()
        if before!=protected_identity():raise RuntimeError('protected_identity_changed')
        record['phase']='verified';journal(transaction,record)
        emit({'status':'Patched','proofs':proofs,'security':negatives,'protected_files_unchanged':True,
              'same_domain_port_secret':True,'snapshot':runtime['snapshot'](),'backup':str(transaction)})
    except BaseException:
        if transaction is not None and record is not None:
            signal.alarm(0);rollback(transaction,record)
        raise
    finally:
        target=staging.resolve()
        if target.parent!=Path('/var/tmp') or not target.name.startswith('quantumvpn-mtproto-tls-build-'):
            raise RuntimeError('unsafe_staging_cleanup_refused')
        shutil.rmtree(target)

try:
    compat=types.ModuleType('ios_compat')
    exec(compile(decode_runtime(COMPAT_B64,COMPAT_SHA256),'<ios-compat>','exec'),compat.__dict__)
    # Include native TLS config inputs and its unchanged helpers in the guard.
    PROTECTED=PROTECTED+(UNIT,PRIVATE/'client-secret',PRIVATE/'proxy-secret',PRIVATE/'proxy-multi.conf',
        ROOT/'quantumvpn_mtproto_tls.py',ROOT/'quantumvpn_mtproto_tls_protocol.py',ROOT/'quantumvpn_mtproto.py',
        ROOT/'security-patch.json',Path('/etc/quantumvpn-dns/config.json'))
    signal.signal(signal.SIGALRM,deadline_expired)
    signal.signal(signal.SIGTERM,deadline_expired)
    signal.signal(signal.SIGHUP,deadline_expired)
    signal.alarm(900)
    ios_main()
except BaseException as error:
    code=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r'[a-z0-9_]{1,100}',str(error)) else 'bounded_operation_failure'
    emit({'status':'Failed','code':code});sys.exit(1)
finally:
    signal.alarm(0)
'''


def program(apply=False):
    here = Path(__file__).parent
    baseline = subprocess.check_output(['git', 'show', BASELINE_REVISION + ':tools/quantumvpn_mtproto_tls_protocol.py'], cwd=here.parent)
    if hashlib.sha256(baseline).hexdigest() != BASELINE_PROTOCOL_SHA256:
        raise RuntimeError('baseline_protocol_identity_required')
    result = 'RUN_REMOTE=False\nAPPLY=' + repr(bool(apply)) + '\n'
    sources = {'MODULE': (here/'quantumvpn_mtproto_tls.py').read_bytes(), 'PROTOCOL': baseline,
               'BASE_MODULE': (here/'quantumvpn_mtproto.py').read_bytes(),
               'COMPAT': (here/'quantumvpn_mtproto_ios_compat.py').read_bytes(),
               'DIAGNOSTIC': (here/'quantumvpn_mtproto_tls_protocol.py').read_bytes()}
    for name, raw in sources.items():
        result += name+'_B64='+repr(base64.b64encode(raw).decode('ascii'))+'\n'
        result += name+'_SHA256='+repr(hashlib.sha256(raw).hexdigest())+'\n'
    return result + installer_definitions() + REMOTE


def main():
    import paramiko
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--verify-public',action='store_true')
    args=parser.parse_args()
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password:raise SystemExit('QVPN_VDS_PASSWORD is required')
    source=program(args.apply)
    client=paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=15,auth_timeout=20)
        stdin,stdout,stderr=client.exec_command('python3 -B -',timeout=1000)
        stdin.write(source);stdin.channel.shutdown_write()
        for line in stdout:print(json.dumps(json.loads(line)),flush=True)
        stderr.read()
        if stdout.channel.recv_exit_status():raise SystemExit('MTProto iOS operation failed; raw details suppressed')
        if args.verify_public:
            import quantumvpn_mtproto_tls_protocol as diag
            with client.open_sftp() as sftp:
                with sftp.open('/etc/quantumvpn-mtproto-tls/client-secret','rb') as stream:
                    secret=stream.read(65).decode('ascii').strip()
            proofs={profile:diag.probe(secret,diag.PUBLIC_HOST,client_profile=profile) for profile in
                    ('standard',diag.IOS_LEGACY_BROKEN_SNI,diag.IOS_MODERN_SAFARI)}
            del secret
            print(json.dumps({'public_proofs':proofs}),flush=True)
            if not all(p['ok'] for p in proofs.values()):raise SystemExit('Public proof failed; no claim of iPhone connectivity')
    finally:client.close()


if __name__=='__main__':main()
