"""Remove one exact, verified private n8n build scratch directory.

Read-only by default. Explicit --apply requires completed OpenClaw-only
conversion and the same exclusive installer lock. No execution of scratch
packages, no glob cleanup, no shared runtime or manifest edits.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

MIGRATION_SHA256='b8eda8c2c6abc9fd9c2cfa68a054054d3ecc76bd6af4897a5a4905640f5151c0'
path=Path(__file__).with_name('migrate-openclaw-only-vds.py')
if hashlib.sha256(path.read_bytes()).hexdigest()!=MIGRATION_SHA256:
    raise RuntimeError('reviewed_migration_source_drift')
spec=importlib.util.spec_from_file_location('claw_migration',path)
migration=importlib.util.module_from_spec(spec);spec.loader.exec_module(migration)

CLEANUP=r'''
CLEANUP_ID='quantum-n8n-scratch-removal-v1'
SCRATCH=RELEASE+'/qvpn-n8n-build-gqoa6z5j'
CLEANUP_INTENT=PRIVATE+'/n8n-stale-build-removal.json'
SCRATCH_IDENTITY={'dev':64770,'ino':686169,'uid':987,'gid':981,'mode':0o700}

def completed_conversion_gate():
    raw,_=read_fixed(INTENT);value=json.loads(raw)
    validate_completed_intent(value)  # No missing files or changed policy exceptions.
    if not service_probe('openclaw'):raise GuardError('openclaw_not_ready_for_scratch_cleanup')
    assert_runtime_budget();no_account_processes(BUILDER_UID)
    account_identity('qvpn-automation-build',BUILDER_UID,BUILDER_GID,'/nonexistent')
    return value

def scratch_tree(fd,delete=False):
    count,size=0,0
    for entry in os.scandir(fd):
        s=entry.stat(follow_symlinks=False)
        if (s.st_dev,s.st_uid,s.st_gid)!=(64770,987,981):raise GuardError('foreign_scratch_entry')
        if stat.S_ISDIR(s.st_mode):
            child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                if info_record(os.fstat(child))!=info_record(s):raise GuardError('scratch_directory_identity_changed')
                n,b=scratch_tree(child,delete);count+=n;size+=b
            finally:os.close(child)
            if delete:
                if info_record(os.stat(entry.name,dir_fd=fd,follow_symlinks=False))!=info_record(s):raise GuardError('scratch_directory_identity_changed')
                os.rmdir(entry.name,dir_fd=fd)
        elif stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode):
            count+=1
            if stat.S_ISREG(s.st_mode):size+=s.st_size
            if delete:
                if info_record(os.stat(entry.name,dir_fd=fd,follow_symlinks=False))!=info_record(s):raise GuardError('scratch_file_identity_changed')
                os.unlink(entry.name,dir_fd=fd)
        else:raise GuardError('special_scratch_entry')
    if delete:os.fsync(fd)
    return count,size

def scratch_inventory(allow_absent=False,expected_parent=None):
    parent,name=open_parent(SCRATCH)
    try:
        ps=info_record(os.fstat(parent))
        if expected_parent is not None and ps!=expected_parent:raise GuardError('scratch_parent_identity_changed')
        try:s=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            if allow_absent:return {'present':False,'parent':ps,'files':0,'bytes':0}
            raise GuardError('unstarted_scratch_target_missing') from None
        if not stat.S_ISDIR(s.st_mode) or info_record(s)!=SCRATCH_IDENTITY or ps['dev']!=64770 or (ps['uid'],ps['gid'],ps['mode'])!=(0,0,0o755):raise GuardError('scratch_target_identity_changed')
        assert_no_mounts(SCRATCH)
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            if info_record(os.fstat(child))!=SCRATCH_IDENTITY:raise GuardError('scratch_target_identity_changed')
            top=list(os.scandir(child))
            if len(top)>1 or (top and (top[0].name!='node_modules' or not top[0].is_dir(follow_symlinks=False))):raise GuardError('unreviewed_scratch_top_entry')
            count,size=scratch_tree(child)
        finally:os.close(child)
        return {'present':True,'parent':ps,'files':count,'bytes':size}
    finally:os.close(parent)

def validate_cleanup_intent(value):
    fields={'schema','id','state','path','target','parent','conversion_sha256','protected_snapshot','protected_active'}
    if not isinstance(value,dict) or set(value)!=fields or value.get('schema')!=1 or value.get('id')!=CLEANUP_ID or value.get('path')!=SCRATCH or value.get('target')!=SCRATCH_IDENTITY or value.get('state') not in ('pending','started','done') or not re.fullmatch('[a-f0-9]{64}',value.get('conversion_sha256','')):
        raise GuardError('foreign_scratch_removal_intent')
    current,_=read_fixed(INTENT)
    if sha(current)!=value['conversion_sha256']:raise GuardError('completed_conversion_identity_changed')
    return value

def save_cleanup_intent(value,create=False):
    validate_cleanup_intent(value)
    parent,name=open_parent(CLEANUP_INTENT)
    try:
        if create:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb') as f:
                os.fchmod(f.fileno(),0o600);f.write(encoded(value));f.flush();os.fsync(f.fileno())
            os.fsync(parent)
        else:
            old,identity=read_fixed(CLEANUP_INTENT)
            atomic_cas(CLEANUP_INTENT,identity,encoded(value),sha(old))
    finally:os.close(parent)

def delete_scratch(value):
    if value['state']!='started':raise GuardError('scratch_removal_requires_started_intent')
    current=scratch_inventory(True,value['parent'])
    if not current['present']:return
    no_account_processes(BUILDER_UID)
    parent,name=open_parent(SCRATCH)
    try:
        if info_record(os.fstat(parent))!=value['parent']:raise GuardError('scratch_parent_identity_changed')
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            if info_record(os.fstat(child))!=SCRATCH_IDENTITY:raise GuardError('scratch_target_identity_changed')
            scratch_tree(child,True)
        finally:os.close(child)
        if info_record(os.stat(name,dir_fd=parent,follow_symlinks=False))!=SCRATCH_IDENTITY:raise GuardError('scratch_target_identity_changed')
        os.rmdir(name,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)

def cleanup_main(do_apply,do_resume=False):
    completed_conversion_gate()
    existing=Path(CLEANUP_INTENT).exists() or Path(CLEANUP_INTENT).is_symlink()
    if existing:
        raw,_=read_fixed(CLEANUP_INTENT);value=validate_cleanup_intent(json.loads(raw))
        inv=scratch_inventory(value['state'] in ('started','done'),value['parent'])
        if value['state']=='done' and inv['present']:raise GuardError('deleted_scratch_recreated')
    else:
        inv=scratch_inventory();raw,_=read_fixed(INTENT)
        value={'schema':1,'id':CLEANUP_ID,'state':'pending','path':SCRATCH,
               'target':SCRATCH_IDENTITY,'parent':inv['parent'],'conversion_sha256':sha(raw),
               'protected_snapshot':protected_snapshot(),'protected_active':{u:is_active(u) for u in PROTECTED_UNITS}}
    if not do_apply:
        output({'status':'ScratchInventory','mode':'read_only','state':value['state'],
                'path':SCRATCH,'files':inv['files'],'bytes':inv['bytes'],'mutations':False});return
    with safe_install_lock() as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        completed_conversion_gate();protected_check(value)
        if existing and not do_resume:raise GuardError('explicit_scratch_resume_required')
        if not existing and do_resume:raise GuardError('no_scratch_removal_to_resume')
        if value['state']=='done':output({'status':'ScratchAlreadyRemoved','path':SCRATCH});return
        if not existing:save_cleanup_intent(value,True)
        value['state']='started';save_cleanup_intent(value)
        delete_scratch(value)
        if scratch_inventory(True,value['parent'])['present']:raise GuardError('scratch_removal_failed')
        completed_conversion_gate();protected_check(value)
        value['state']='done';save_cleanup_intent(value)
        output({'status':'ScratchRemoved','path':SCRATCH,'files_before':inv['files'],'bytes_before':inv['bytes']})
'''

def remote_script(apply=False,resume=False):
    b=migration.base
    return '\n'.join(['PINS='+repr(b.PINS),b.COMMON,b.REMOTE,'import grp',migration.MIGRATION,CLEANUP,
        f"try:\n cleanup_main({apply!r},{resume!r})\nexcept GuardError as e:\n output({{'status':'Blocked','code':str(e)}});raise SystemExit(2)\nexcept Exception as e:\n output({{'status':'Failed','code':type(e).__name__}});raise SystemExit(3)"])

def worker_script(job,payload=None):
    return migration.worker_script(job,payload).replace(
        "EXPECTED_INSTALL_ID = 'quantum-openclaw-only-v2'","EXPECTED_INSTALL_ID = 'quantum-n8n-scratch-removal-v1'").replace(
        "ROOT = Path('/run/quantum-openclaw-migration')","ROOT = Path('/run/quantum-n8n-scratch-cleanup')").replace(
        "UNIT = 'qvpn-openclaw-migration-'","UNIT = 'qvpn-n8n-scratch-cleanup-'").replace(
        'b"migrate_main(True"','b"cleanup_main(True"').replace(
        "'qvpn-openclaw-migration-*'])","'qvpn-openclaw-migration-*','qvpn-n8n-scratch-cleanup-*'])")

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apply',action='store_true');p.add_argument('--resume',action='store_true');p.add_argument('--start-worker',action='store_true');p.add_argument('--worker-status');p.add_argument('--known-hosts',default=str(Path.home()/'.ssh/known_hosts'))
    args=p.parse_args()
    if (args.resume or args.start_worker) and not args.apply:p.error('--resume/--start-worker require --apply')
    if args.worker_status and (args.apply or args.resume or args.start_worker):p.error('--worker-status is read-only and separate')
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password:print(json.dumps({'status':'Blocked','code':'missing_password_environment'}));return 2
    import paramiko
    c=paramiko.SSHClient();c.load_host_keys(args.known_hosts);c.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        c.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=15)
        code=worker_script(args.worker_status) if args.worker_status else worker_script(uuid.uuid4().hex,remote_script(True,args.resume)) if args.start_worker else remote_script(args.apply,args.resume)
        i,o,e=c.exec_command('python3 -B -',timeout=1900);i.write(code);i.channel.shutdown_write()
        for line in o:print(json.dumps(json.loads(line),ensure_ascii=False),flush=True)
        e.read();return o.channel.recv_exit_status()
    except Exception as exc:print(json.dumps({'status':'Failed','code':type(exc).__name__}));return 3
    finally:c.close()

if __name__=='__main__':sys.exit(main())
