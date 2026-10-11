"""Scoped conversion of the verified Quantum stack to OpenClaw only.

Default is read-only. --apply is irreversible: removes only four exact owned
n8n targets and its isolated account, never shared Node or the release parent.
The historical installer remains byte-for-byte unchanged. No model inference,
network changes, arbitrary commands, credentials in output, or live AI tools.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

BASE_SHA256 = '7bdd89762001ef96fc823ade713b097cb6553024762770825a4a34f58217f571'
base_path = Path(__file__).with_name('install-automation-stack-vds.py')
if hashlib.sha256(base_path.read_bytes()).hexdigest() != BASE_SHA256:
    raise RuntimeError('historical_installer_source_drift')
spec = importlib.util.spec_from_file_location('historical_automation', base_path)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

MIGRATION = r'''
import copy

MIGRATION_ID = 'quantum-openclaw-only-v2'
INTENT = PRIVATE + '/openclaw-only-migration.json'
MANIFEST = PRIVATE + '/manifest.json'
JOURNAL = PRIVATE + '/install-journal.json'
ACCESS = PRIVATE + '/access.json'
CLAW_UNIT = '/etc/systemd/system/quantum-openclaw.service'
REMOVE = (RELEASE + '/n8n', STATE + '/n8n', PRIVATE + '/n8n.env',
          '/etc/systemd/system/quantum-n8n.service')
N8N_IMMUTABLE = {REMOVE[2], REMOVE[3], REMOVE[0] + '/package.json',
                 REMOVE[0] + '/package-lock.json', REMOVE[0] + '/node_modules/n8n/package.json'}
OLD_HASHES = {
    MANIFEST: 'f520e3b9c66e2a98db99d0bec7ac1c7c4cbabefc909c7db9fa384e9220d6aab6',
    JOURNAL: '0a572ede0e333660a72ba844c9879089867bf86ca28ba9f25822913ee443739c',
    ACCESS: 'b2499affa53f4eb357bd80d3d5bc84a75c4bda1826f015713e8c376cbeeb86ea',
    CLAW_UNIT: hashlib.sha256(service_unit('openclaw').encode()).hexdigest(),
}
PROTECTED_UNITS = ('nginx', 'rospanel', 'quantumvpn-operator',
                   'quantumvpn-mtproto.service', 'quantumvpn-mtproto-tls.service',
                   'quantumvpn-webproxy.service', 'dnsdist', 'unbound', 'ollama')
N8N_UID, N8N_GID = 986, 980
CLAW_UID, CLAW_GID = 985, 979
BUILDER_UID, BUILDER_GID = 987, 981

def sha(data):
    return hashlib.sha256(data).hexdigest()

def encoded(value):
    return json.dumps(value, sort_keys=True, indent=2).encode()

def new_claw_unit():
    old = service_unit('openclaw')
    if old.count('\nMemoryMax=768M\n') != 1 or old.count('Environment=NODE_OPTIONS=--max-old-space-size=384\n') != 1:
        raise GuardError('unreviewed_old_openclaw_unit')
    return old.replace('\nMemoryMax=768M\n', '\nMemoryMax=1024M\n').replace(
        'Environment=NODE_OPTIONS=--max-old-space-size=384\n',
        'Environment=NODE_OPTIONS=--max-old-space-size=384\nEnvironment=OPENCLAW_NO_RESPAWN=1\n').encode()

def info_record(info):
    return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}

def same_identity(info, record):
    return info_record(info) == record

def open_parent(path):
    # Traverse every ancestor by directory fd: no ancestor symlink, foreign UID,
    # group/world-writable directory, or string-resolved recursive target.
    p = PurePosixPath(path)
    if not p.is_absolute() or str(p) != path or '..' in p.parts:
        raise GuardError('noncanonical_migration_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        prefix=''
        for part in p.parts[1:-1]:
            prefix += '/' + part
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
            s = os.fstat(fd)
            service_parent=prefix in (STATE+'/openclaw',STATE+'/openclaw/workspace')
            uid,gid=(CLAW_UID,CLAW_GID) if service_parent else (0,0)
            if s.st_uid != uid or s.st_gid != gid or stat.S_IMODE(s.st_mode) & 0o022 or ((service_parent or prefix==PRIVATE) and stat.S_IMODE(s.st_mode)!=0o700):
                raise GuardError('unsafe_migration_ancestor')
        return fd, p.name
    except Exception:
        os.close(fd); raise

def immutable_digest(path):
    parent,name=open_parent(path);fd=None
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        s=os.fstat(fd);entry=os.stat(name,dir_fd=parent,follow_symlinks=False)
        uid,gid=(CLAW_UID,CLAW_GID) if path.startswith(STATE+'/openclaw/') else (0,0)
        private_file=path.startswith(STATE+'/openclaw/') or path in (INTENT,MANIFEST,JOURNAL,ACCESS,REMOVE[2])
        if not stat.S_ISREG(s.st_mode) or (s.st_uid,s.st_gid)!=(uid,gid) or stat.S_IMODE(s.st_mode)&0o022 or (private_file and stat.S_IMODE(s.st_mode)!=0o600) or (s.st_dev,s.st_ino)!=(entry.st_dev,entry.st_ino):
            raise GuardError('unsafe_immutable_migration_file')
        h=hashlib.sha256()
        while True:
            chunk=os.read(fd,1024*1024)
            if not chunk:break
            h.update(chunk)
        after=os.fstat(fd);entry=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (entry.st_dev,entry.st_ino)!=(s.st_dev,s.st_ino):
            raise GuardError('immutable_changed_while_reading')
        return h.hexdigest()
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def read_fixed(path, modes=(0o600,), budget=256000):
    parent, name = open_parent(path)
    fd = None
    try:
        ps = os.fstat(parent)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        s = os.fstat(fd); entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        exact_mode=0o644 if path==CLAW_UNIT else 0o600
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or stat.S_IMODE(s.st_mode) not in modes or stat.S_IMODE(s.st_mode)!=exact_mode or s.st_size > budget or (s.st_dev,s.st_ino) != (entry.st_dev,entry.st_ino):
            raise GuardError('unsafe_migration_file')
        data = os.read(fd, budget + 1)
        if len(data) != s.st_size:
            raise GuardError('migration_file_changed_while_reading')
        return data, {'file': info_record(s), 'parent': info_record(ps)}
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

def atomic_cas(path, before, data, old_digest, mode=0o600):
    # Only exact generated replacement; compare digest AND inode immediately
    # before replace. Directory fsync makes each checkpoint crash recoverable.
    parent, name = open_parent(path)
    temp = None
    try:
        if not same_identity(os.fstat(parent), before['parent']):
            raise GuardError('migration_parent_identity_changed')
        current, identity = read_fixed(path, modes=(0o600,0o644))
        if identity != before or sha(current) != old_digest:
            raise GuardError('migration_compare_and_swap_failed')
        temp = '.qvpn-claw-migration-' + secrets.token_hex(16)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode); os.fchown(f.fileno(), 0, 0)
            f.write(data); f.flush(); os.fsync(f.fileno())
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        check, check_id = read_fixed(path, modes=(0o600,0o644))
        if not same_identity(entry, before['file']) or check_id != before or sha(check) != old_digest:
            raise GuardError('migration_compare_and_swap_failed')
        os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
    finally:
        if temp is not None:
            try: os.unlink(temp, dir_fd=parent)
            except FileNotFoundError: pass
        os.close(parent)

def create_intent_file(data):
    parent, name = open_parent(INTENT)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600); f.write(data); f.flush(); os.fsync(f.fileno())
        os.fsync(parent)
    finally: os.close(parent)

def save_intent(value):
    old, identity = read_fixed(INTENT)
    atomic_cas(INTENT, identity, encoded(value), sha(old))

def replacement_records(old):
    m, j = json.loads(old[MANIFEST]), validate_journal(json.loads(old[JOURNAL]))
    if m.get('install_id') != INSTALL_ID or m.get('pins') != PINS or set(j['steps']) != {'node','n8n','openclaw'} or set(m['dependency_lock_sha256']) != {'n8n','openclaw'}:
        raise GuardError('unreviewed_completed_stack')
    if set(m['immutable_files']) & N8N_IMMUTABLE != N8N_IMMUTABLE or old[CLAW_UNIT] != service_unit('openclaw').encode():
        raise GuardError('unreviewed_owned_n8n_or_unit')
    access = json.loads(old[ACCESS]); token = j['credentials']['token']
    if access.get('openclaw',{}).get('gateway_token') != token:
        raise GuardError('access_token_identity_changed')
    access.pop('n8n', None)
    access['ssh_tunnel'] = 'ssh -N -L 127.0.0.1:18789:127.0.0.1:18789 root@150.241.96.191'
    access['model_verified'] = False
    access['n8n_removed'] = True
    pins = {k:v for k,v in PINS.items() if not k.startswith('n8n_')}
    new_m, new_j = copy.deepcopy(m), copy.deepcopy(j)
    for doc in (new_m,new_j): doc['install_id'] = MIGRATION_ID; doc['pins'] = pins
    new_m['dependency_lock_sha256'].pop('n8n')
    new_m['immutable_files'] = {p:v for p,v in m['immutable_files'].items() if p not in N8N_IMMUTABLE}
    new_m['immutable_files'][CLAW_UNIT] = sha(new_claw_unit())
    new_m['conversion'] = {'id': MIGRATION_ID, 'old_manifest_sha256': OLD_HASHES[MANIFEST],
                           'n8n_data_deleted': True, 'model_verified': False}
    new_j['schema'] = 2; new_j['credentials'] = {'token': token}
    new_j['steps'].pop('n8n'); new_j.pop('openclaw_schema_migration',None); new_j.pop('openclaw_budget_migration',None)
    new_j['files'] = {p:v for p,v in j['files'].items() if p not in N8N_IMMUTABLE}
    new_j['files'][CLAW_UNIT] = sha(new_claw_unit()); new_j['files'][ACCESS] = sha(encoded(access))
    return {CLAW_UNIT:new_claw_unit(), ACCESS:encoded(access), JOURNAL:encoded(new_j), MANIFEST:encoded(new_m)}

def unit_state(unit):
    r = command(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','FragmentPath','-p','DropInPaths','-p','MemoryMax','-p','MemorySwapMax','-p','CPUQuotaPerSecUSec','-p','NRestarts','-p','MainPID'],check=False)
    if r.returncode: raise GuardError('migration_unit_inventory_failed')
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)

def no_account_processes(uid):
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            try:
                if p.stat().st_uid == uid: raise GuardError('owned_account_process_still_running')
            except FileNotFoundError: pass

def account_identity(name, uid, gid, home):
    a = pwd.getpwnam(name)
    g = grp.getgrnam(name)
    if (a.pw_uid,a.pw_gid,a.pw_dir,a.pw_shell) != (uid,gid,home,'/usr/sbin/nologin') or g.gr_gid != gid or g.gr_mem or os.getgrouplist(name,gid) != [gid]:
        raise GuardError('owned_account_identity_changed')
    if any(x.pw_gid == gid and x.pw_name != name for x in pwd.getpwall()):
        raise GuardError('owned_group_has_other_users')
    return a

def target_record(path):
    if path not in REMOVE: raise GuardError('unreviewed_removal_target')
    parent,name = open_parent(path)
    try:
        s = os.stat(name,dir_fd=parent,follow_symlinks=False)
        uid,gid,mode = (N8N_UID,N8N_GID,0o700) if path == REMOVE[1] else (0,0,0o755 if path==REMOVE[0] else 0o600)
        expected_type = stat.S_ISDIR if path in REMOVE[:2] else stat.S_ISREG
        if not expected_type(s.st_mode) or (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)) != (uid,gid,mode):
            raise GuardError('unsafe_owned_removal_target')
        if s.st_dev != os.fstat(parent).st_dev: raise GuardError('removal_target_device_changed')
        return {'file':info_record(s),'parent':info_record(os.fstat(parent))}
    finally: os.close(parent)

def assert_no_mounts(path):
    # mountinfo is escaped; decode only the defined octal escapes, not a shell.
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if len(fields) < 5: raise GuardError('invalid_mount_inventory')
        point = re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),fields[4])
        if point == path or point.startswith(path+'/'): raise GuardError('mounted_removal_subtree')

def scan_tree(fd, device, delete=False):
    # One fd-pinned pass, no recursive glob / followed symlinks / RAM file list.
    count, size = 0, 0
    for entry in os.scandir(fd):
        s = entry.stat(follow_symlinks=False)
        if s.st_dev != device or s.st_uid not in (0,N8N_UID,BUILDER_UID) or s.st_gid not in (0,N8N_GID,BUILDER_GID):
            raise GuardError('foreign_removal_subtree_entry')
        if stat.S_ISDIR(s.st_mode):
            child = os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                if info_record(os.fstat(child)) != info_record(s): raise GuardError('removal_subdirectory_identity_changed')
                n,b = scan_tree(child,device,delete); count += n; size += b
            finally: os.close(child)
            if delete:
                current=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                if info_record(current) != info_record(s): raise GuardError('removal_subdirectory_identity_changed')
                os.rmdir(entry.name,dir_fd=fd)
        elif stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode):
            count += 1
            if stat.S_ISREG(s.st_mode): size += s.st_size
            if delete:
                current=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                if info_record(current) != info_record(s): raise GuardError('removal_entry_identity_changed')
                os.unlink(entry.name,dir_fd=fd)
        else: raise GuardError('special_removal_subtree_entry')
    if delete: os.fsync(fd)
    return count,size

def remove_target(path, record, started):
    if path not in REMOVE: raise GuardError('unreviewed_removal_target')
    parent,name = open_parent(path)
    try:
        if not same_identity(os.fstat(parent),record['parent']): raise GuardError('removal_parent_identity_changed')
        try: s=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            if started: return  # Only a durable per-target started intent permits absence.
            raise GuardError('missing_unstarted_removal_target') from None
        if not same_identity(s,record['file']): raise GuardError('removal_target_identity_changed')
        assert_no_mounts(path)
        if path in REMOVE[:2]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            try:
                if not same_identity(os.fstat(child),record['file']): raise GuardError('removal_target_identity_changed')
                scan_tree(child,s.st_dev,False)  # Full safe inventory before the first unlink of this attempt.
                scan_tree(child,s.st_dev,True)
            finally: os.close(child)
            if not same_identity(os.stat(name,dir_fd=parent,follow_symlinks=False),record['file']): raise GuardError('removal_target_identity_changed')
            os.rmdir(name,dir_fd=parent)
        else: os.unlink(name,dir_fd=parent)
        os.fsync(parent)
    finally: os.close(parent)

def immutable_pending_check(value, old, new):
    # Completed historical manifest remains authoritative during deletion.
    # Exceptions are exactly generated CAS targets and started removal targets.
    m=json.loads(old[MANIFEST]); j=validate_journal(json.loads(old[JOURNAL]))
    for path,expected in {**j['files'],**m['immutable_files']}.items():
        removal=next((p for p in REMOVE if path==p or path.startswith(p+'/')),None)
        if removal and value['removed'][removal] in ('started','done'):
            continue
        if path in new and value['converted'][path] in ('started','done'):
            data,_=read_fixed(path,modes=(0o600,0o644))
            if sha(data) not in (sha(old[path]),sha(new[path])): raise GuardError('pending_conversion_content_drift')
        elif immutable_digest(path)!=expected:
            raise GuardError('pending_immutable_file_drift')
    for path in (MANIFEST,JOURNAL,ACCESS,CLAW_UNIT):
        data,_=read_fixed(path,modes=(0o600,0o644))
        allowed=(sha(old[path]),sha(new[path])) if value['converted'][path] in ('started','done') else (sha(old[path]),)
        if sha(data) not in allowed: raise GuardError('pending_record_drift')

def validate_intent(value):
    fields={'schema','id','state','old','identities','targets','removed','converted','account','protected_snapshot','protected_active'}
    if not isinstance(value,dict) or set(value)!=fields or value['schema']!=1 or value['id']!=MIGRATION_ID or value['state'] not in ('pending','converted','ready'):
        raise GuardError('invalid_openclaw_only_intent')
    if set(value['old'])!=set(OLD_HASHES) or set(value['identities'])!=set(OLD_HASHES) or set(value['targets'])!=set(REMOVE) or set(value['removed'])!=set(REMOVE) or set(value['converted'])!=set(OLD_HASHES):
        raise GuardError('invalid_migration_scope')
    if any(x not in ('pending','started','done') for x in [*value['removed'].values(),*value['converted'].values()]) or value['account'] not in ('pending','started','done'):
        raise GuardError('invalid_migration_checkpoint')
    old={p:base64.b64decode(data,validate=True) for p,data in value['old'].items()}
    if any(sha(old[p])!=expected for p,expected in OLD_HASHES.items()): raise GuardError('migration_old_provenance_drift')
    new=replacement_records(old)
    if value['state']!='pending' and (any(x!='done' for x in [*value['removed'].values(),*value['converted'].values()]) or value['account']!='done'):
        raise GuardError('incomplete_migration_marked_complete')
    return old,new

def validate_current_conversion(value):
    old,new=validate_intent(value); immutable_pending_check(value,old,new)
    for path,record in value['targets'].items():
        try: actual=target_record(path)
        except FileNotFoundError:
            if value['removed'][path]=='pending': raise GuardError('unstarted_target_missing') from None
            continue
        if value['removed'][path]=='done' or actual!=record: raise GuardError('removal_target_recreated_or_changed')
    return old,new

def compact_completed_intent(value,new):
    # Erase recovery copies of the old n8n key/records after all irreversible
    # checkpoints are complete. Keep exact new-file hashes as the independent
    # immutable gate; no missing-file exception survives completed conversion.
    if value['state']!='ready' or any(x!='done' for x in [*value['removed'].values(),*value['converted'].values()]) or value['account']!='done':
        raise GuardError('cannot_compact_incomplete_migration')
    return {'schema':2,'id':MIGRATION_ID,'state':'ready',
            'old_hashes':OLD_HASHES,'new_hashes':{p:sha(b) for p,b in new.items()},
            'protected_snapshot':value['protected_snapshot'],'protected_active':value['protected_active'],
            'n8n_removed':True,'model_verified':False}

def validate_completed_intent(value):
    fields={'schema','id','state','old_hashes','new_hashes','protected_snapshot','protected_active','n8n_removed','model_verified'}
    if not isinstance(value,dict) or set(value)!=fields or value['schema']!=2 or value['id']!=MIGRATION_ID or value['state']!='ready' or value['old_hashes']!=OLD_HASHES or value['n8n_removed'] is not True or value['model_verified'] is not False or set(value['new_hashes'])!=set(OLD_HASHES):
        raise GuardError('invalid_completed_migration_intent')
    docs={}
    for path,expected in value['new_hashes'].items():
        if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected): raise GuardError('invalid_completed_migration_digest')
        data,_=read_fixed(path,modes=(0o644,) if path==CLAW_UNIT else (0o600,))
        if sha(data)!=expected: raise GuardError('completed_migration_file_drift')
        docs[path]=json.loads(data) if path!=CLAW_UNIT else data
    m,j,a=docs[MANIFEST],docs[JOURNAL],docs[ACCESS]
    pins={k:v for k,v in PINS.items() if not k.startswith('n8n_')}
    if m.get('install_id')!=MIGRATION_ID or j.get('install_id')!=MIGRATION_ID or m.get('pins')!=pins or j.get('pins')!=pins or j.get('schema')!=2 or set(j.get('credentials',{}))!={'token'} or set(j.get('steps',{}))!={'node','openclaw'} or set(m.get('dependency_lock_sha256',{}))!={'openclaw'} or docs[CLAW_UNIT]!=new_claw_unit() or 'n8n' in a or a.get('openclaw',{}).get('gateway_token')!=j['credentials']['token']:
        raise GuardError('completed_openclaw_only_policy_drift')
    for path,expected in {**j['files'],**m['immutable_files']}.items():
        if path in N8N_IMMUTABLE or path.startswith(REMOVE[0]+'/') or immutable_digest(path)!=expected:
            raise GuardError('completed_openclaw_only_immutable_drift')
    for path in REMOVE:
        parent,name=open_parent(path)
        try:
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:continue
            raise GuardError('completed_n8n_target_recreated')
        finally:os.close(parent)
    for lookup in (pwd.getpwnam,grp.getgrnam):
        try:lookup('qvpn-n8n')
        except KeyError:continue
        raise GuardError('completed_n8n_account_recreated')
    return docs

def protected_check(value):
    if protected_snapshot()!=value['protected_snapshot'] or any(active and not is_active(unit) for unit,active in value['protected_active'].items()):
        raise GuardError('protected_system_changed_during_migration')

def initial_intent_inventory():
    old,identities={},{}
    for path,expected in OLD_HASHES.items():
        data,ident=read_fixed(path,modes=(0o644,) if path==CLAW_UNIT else (0o600,))
        if sha(data)!=expected: raise GuardError('completed_stack_provenance_changed')
        old[path]=data; identities[path]=ident
    replacement_records(old)
    account_identity('qvpn-n8n',N8N_UID,N8N_GID,STATE+'/n8n')
    account_identity('qvpn-openclaw',CLAW_UID,CLAW_GID,STATE+'/openclaw')
    account_identity('qvpn-automation-build',BUILDER_UID,BUILDER_GID,'/nonexistent')
    no_account_processes(BUILDER_UID)
    for name in ('n8n','openclaw'):
        s=unit_state(SERVICES[name])
        if s.get('FragmentPath')!='/etc/systemd/system/'+SERVICES[name] or s.get('DropInPaths')!='': raise GuardError('owned_unit_identity_changed')
        if name=='openclaw' and s.get('ActiveState')!='inactive': raise GuardError('openclaw_must_remain_contained')
    targets={p:target_record(p) for p in REMOVE}
    value={'schema':1,'id':MIGRATION_ID,'state':'pending',
           'old':{p:base64.b64encode(b).decode() for p,b in old.items()},'identities':identities,
           'targets':targets,'removed':{p:'pending' for p in REMOVE},
           'converted':{p:'pending' for p in OLD_HASHES},'account':'pending',
           'protected_snapshot':protected_snapshot(),'protected_active':{u:is_active(u) for u in PROTECTED_UNITS}}
    immutable_pending_check(value,old,replacement_records(old))
    return value

def begin_conversion():
    value=initial_intent_inventory()
    create_intent_file(encoded(value));return value

def stop_owned_n8n(value):
    s=unit_state(SERVICES['n8n'])
    if s.get('FragmentPath') not in ('','/etc/systemd/system/'+SERVICES['n8n']) or s.get('DropInPaths')!='': raise GuardError('foreign_n8n_unit')
    present=Path(REMOVE[3]).exists()
    if not present and value['removed'][REMOVE[3]]=='pending': raise GuardError('unstarted_n8n_unit_missing')
    if s.get('FragmentPath') and present:
        command(['systemctl','stop',SERVICES['n8n']],timeout=45)
        command(['systemctl','disable',SERVICES['n8n']])
    s=unit_state(SERVICES['n8n'])
    if s.get('ActiveState') not in ('inactive','failed'): raise GuardError('n8n_stop_failed')
    no_account_processes(N8N_UID); no_account_processes(BUILDER_UID)

def delete_account(value):
    if value['account']=='done':
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try: lookup('qvpn-n8n')
            except KeyError: continue
            raise GuardError('removed_account_recreated')
        return
    try: pwd.getpwnam('qvpn-n8n')
    except KeyError:
        if value['account']!='started': raise GuardError('unstarted_account_missing') from None
    else:
        try:account_identity('qvpn-n8n',N8N_UID,N8N_GID,STATE+'/n8n')
        except KeyError:raise GuardError('existing_n8n_user_missing_group') from None
        no_account_processes(N8N_UID); value['account']='started'; save_intent(value)
        command(['userdel','qvpn-n8n'])  # NEVER --remove/-r, home was fd-checked above.
    try: group=grp.getgrnam('qvpn-n8n')
    except KeyError: group=None
    if group:
        if group.gr_gid!=N8N_GID or group.gr_mem or any(a.pw_gid==N8N_GID for a in pwd.getpwall()): raise GuardError('n8n_group_identity_changed')
        command(['groupdel','qvpn-n8n'])
    value['account']='done'; save_intent(value)

def convert_records(value,new):
    for path in (CLAW_UNIT,ACCESS,JOURNAL,MANIFEST):
        data,ident=read_fixed(path,modes=(0o600,0o644)); phase=value['converted'][path]
        if sha(data)==sha(new[path]):
            if phase=='pending': raise GuardError('unjournaled_record_replacement')
        else:
            if sha(data)!=OLD_HASHES[path] or ident!=value['identities'][path]: raise GuardError('record_conversion_identity_changed')
            value['converted'][path]='started'; save_intent(value)
            atomic_cas(path,ident,new[path],OLD_HASHES[path],mode=0o644 if path==CLAW_UNIT else 0o600)
        verified,_=read_fixed(path,modes=(0o644,) if path==CLAW_UNIT else (0o600,))
        if sha(verified)!=sha(new[path]): raise GuardError('record_conversion_failed')
        value['converted'][path]='done'; save_intent(value)
    value['state']='converted'; save_intent(value)

def assert_converted_inventory(value):
    old,new=validate_current_conversion(value)
    if value['state'] not in ('converted','ready'): raise GuardError('conversion_not_complete')
    for path in (CLAW_UNIT,ACCESS,JOURNAL,MANIFEST):
        read_fixed(path,modes=(0o644,) if path==CLAW_UNIT else (0o600,))
    m=json.loads(new[MANIFEST]);j=json.loads(new[JOURNAL])
    for path,expected in {**j['files'],**m['immutable_files']}.items():
        if immutable_digest(path)!=expected: raise GuardError('openclaw_only_immutable_drift')
    cfg=json.loads((Path(STATE)/'openclaw/openclaw.json').read_text())
    if cfg!=openclaw_config(j['credentials']['token']): raise GuardError('openclaw_only_security_policy_changed')
    delete_account(value)
    return m

def assert_runtime_budget():
    s=unit_state(SERVICES['openclaw'])
    if s.get('FragmentPath')!=CLAW_UNIT or s.get('DropInPaths')!='' or s.get('ActiveState')!='active' or s.get('MemoryMax')!='1073741824' or s.get('MemorySwapMax')!='0' or s.get('CPUQuotaPerSecUSec')!='250ms':
        raise GuardError('openclaw_runtime_budget_or_unit_drift')
    pid=s.get('MainPID','')
    if not pid.isdigit() or int(pid)<=1 or Path('/proc/'+pid).stat().st_uid!=CLAW_UID:
        raise GuardError('openclaw_runtime_process_identity_changed')
    return s

def readiness_soak():
    # Old loop failed every312–391s: require600s continuous readiness and no
    # restart-counter change, not just systemctl active or one HTTP200.
    command(['systemctl','start',SERVICES['openclaw']])
    deadline=time.monotonic()+300
    while not service_probe('openclaw'):
        if time.monotonic()>deadline: raise GuardError('openclaw_start_readiness_timeout')
        time.sleep(2)
    initial=assert_runtime_budget().get('NRestarts')
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        if not service_probe('openclaw') or assert_runtime_budget().get('NRestarts')!=initial:
            raise GuardError('openclaw_readiness_soak_failed')
        time.sleep(10)
    if not service_probe('openclaw') or assert_runtime_budget().get('NRestarts')!=initial:
        raise GuardError('openclaw_final_readiness_failed')
    command(['systemctl','enable',SERVICES['openclaw']])

def migration_inventory():
    path=Path(INTENT)
    if path.exists() or path.is_symlink():
        data,_=read_fixed(INTENT);value=json.loads(data)
        if value.get('schema')==2:
            validate_completed_intent(value);removed={p:'done' for p in REMOVE}
        else:
            validate_current_conversion(value);removed={p:value['removed'][p] for p in REMOVE}
        status=value['state']
    else:
        status='not_started';removed={p:'present' for p in REMOVE}
        initial_intent_inventory()  # All ownership/immutable gates, no intent file/write.
    memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    return {'status':'Inventory','mode':'read_only','conversion':status,'removed':removed,
            'available_memory_mb':int(memory['MemAvailable'].split()[0])//1024,
            'disk_free_mb':shutil.disk_usage('/').free//1024**2,
            'openclaw_ready':service_probe('openclaw'),'n8n_ready':service_probe('n8n'),
            'model_verified':False,'mutations':False,
            'unverified_n8n_build_leftover_preserved':RELEASE+'/qvpn-n8n-build-gqoa6z5j'}

def migrate_main(do_apply,do_resume=False):
    if not do_apply: output(migration_inventory());return
    with safe_install_lock() as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        memory=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
        if int(memory['MemAvailable'].split()[0])//1024<2000: raise GuardError('insufficient_migration_memory_headroom')
        if Path(INTENT).exists() or Path(INTENT).is_symlink():
            if not do_resume: raise GuardError('explicit_migration_resume_required')
            data,_=read_fixed(INTENT);value=json.loads(data)
            if value.get('schema')==2:
                validate_completed_intent(value)
                output({'status':'AlreadyConverted','openclaw_ready':service_probe('openclaw'),'model_verified':False});return
            old,new=validate_current_conversion(value)
        else:
            if do_resume: raise GuardError('no_owned_migration_to_resume')
            value=begin_conversion();old,new=validate_current_conversion(value)
        protected_check(value)
        if value['state']=='pending':
            if unit_state(SERVICES['openclaw']).get('ActiveState')!='inactive': raise GuardError('conversion_requires_stopped_openclaw')
            stop_owned_n8n(value)
            for path in REMOVE:
                if value['removed'][path]=='done': continue
                validate_current_conversion(value);protected_check(value)
                value['removed'][path]='started';save_intent(value)
                remove_target(path,value['targets'][path],True)
                value['removed'][path]='done';save_intent(value)
                output({'phase':'owned_n8n_target_removed','path':path})
            delete_account(value);convert_records(value,new)
            output({'phase':'openclaw_only_records_converted','memory_max_mb':1024,'model_verified':False})
        assert_converted_inventory(value);protected_check(value)
        try:
            command(['systemd-analyze','verify',CLAW_UNIT],timeout=30)
            command(['systemctl','daemon-reload'])
            readiness_soak();assert_converted_inventory(value);protected_check(value)
        except Exception:
            command(['systemctl','stop',SERVICES['openclaw']],check=False,timeout=45)
            command(['systemctl','disable',SERVICES['openclaw']],check=False)
            raise
        value['state']='ready';save_intent(value)
        save_intent(compact_completed_intent(value,new))
        output({'status':'OpenClawOnlyReady','n8n_removed':True,'model_verified':False,
                'continuous_ready_seconds':600,'tools_enabled':False,'telegram_enabled':False,
                'unverified_n8n_build_leftover_preserved':RELEASE+'/qvpn-n8n-build-gqoa6z5j'})
'''

def remote_script(apply=False, resume=False):
    return '\n'.join(['PINS='+repr(base.PINS),base.COMMON,base.REMOTE,'import grp',MIGRATION,
        f"try:\n migrate_main({apply!r},{resume!r})\nexcept GuardError as e:\n output({{'status':'Blocked','code':str(e)}});raise SystemExit(2)\nexcept Exception as e:\n output({{'status':'Failed','code':type(e).__name__}});raise SystemExit(3)"])

def worker_script(job_id, payload=None):
    if len(job_id)!=32 or any(c not in '0123456789abcdef' for c in job_id): raise ValueError('invalid_worker_id')
    # Reuse only reviewed bootstrap bytes, with fixed isolated job identity,
    # migration payload marker and tighter duration/IO bounds. No command API.
    script=base.worker_script(job_id,payload)
    return script.replace("EXPECTED_INSTALL_ID = 'quantum-automation-native-v1'", "EXPECTED_INSTALL_ID = 'quantum-openclaw-only-v2'").replace(
        "ROOT = Path('/run/quantum-automation-installer')", "ROOT = Path('/run/quantum-openclaw-migration')").replace(
        "UNIT = 'qvpn-automation-install-'", "UNIT = 'qvpn-openclaw-migration-'").replace(
        'b"remote_main(True"', 'b"migrate_main(True"').replace(
        "'qvpn-automation-install-*'])", "'qvpn-automation-install-*','qvpn-openclaw-migration-*'])").replace(
        "'TimeoutStartSec=10800'", "'TimeoutStartSec=1800'").replace(
        "'RuntimeMaxSec=10800'", "'RuntimeMaxSec=1800'").replace(
        "'-p','CPUQuota=20%'", "'-p','CPUQuota=20%','-p','IOWeight=10'")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply',action='store_true');p.add_argument('--resume',action='store_true')
    p.add_argument('--start-worker',action='store_true');p.add_argument('--worker-status')
    p.add_argument('--known-hosts',default=str(Path.home()/'.ssh/known_hosts'))
    args=p.parse_args()
    if (args.resume or args.start_worker) and not args.apply: p.error('--resume/--start-worker require --apply')
    if args.worker_status and (args.apply or args.resume or args.start_worker): p.error('--worker-status is read-only and separate')
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password: print(json.dumps({'status':'Blocked','code':'missing_password_environment'}));return 2
    import paramiko
    c=paramiko.SSHClient();c.load_host_keys(args.known_hosts);c.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        c.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=15)
        code=worker_script(args.worker_status) if args.worker_status else worker_script(uuid.uuid4().hex,remote_script(True,args.resume)) if args.start_worker else remote_script(args.apply,args.resume)
        incoming,out,err=c.exec_command('python3 -B -',timeout=1900);incoming.write(code);incoming.channel.shutdown_write()
        for line in out: print(json.dumps(json.loads(line),ensure_ascii=False),flush=True)
        err.read();return out.channel.recv_exit_status()
    except Exception as exc: print(json.dumps({'status':'Failed','code':type(exc).__name__}));return 3
    finally: c.close()

if __name__=='__main__': sys.exit(main())
