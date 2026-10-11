"""Remove only the proven, isolated OpenClaw installation from the owned VDS.

Read-only inventory by default. --apply stops/disables the exact owned unit,
removes its package/state/access file and isolated account, then retires the
generated metadata to credential-free Node-only proofs. Shared Node, Ollama,
VPN/panels/DNS/proxies, backups and historical audit files are preserved.
No inference, arbitrary logs, shell cleanup, or Android changes are performed.
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

MIGRATION_SHA256 = 'b8eda8c2c6abc9fd9c2cfa68a054054d3ecc76bd6af4897a5a4905640f5151c0'
migration_path = Path(__file__).with_name('migrate-openclaw-only-vds.py')
if hashlib.sha256(migration_path.read_bytes()).hexdigest() != MIGRATION_SHA256:
    raise RuntimeError('reviewed_migration_source_drift')
spec = importlib.util.spec_from_file_location('reviewed_claw_migration', migration_path)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

UNINSTALL = r'''
UNINSTALL_ID = 'quantum-openclaw-removal-v1'
NODE_ONLY_ID = 'quantum-automation-node-only-v1'
UNINSTALL_INTENT = PRIVATE + '/openclaw-removal.json'
CLAW_TARGETS = (CLAW_UNIT, RELEASE + '/openclaw', STATE + '/openclaw', ACCESS)
CLAW_RECORDS = (JOURNAL, MANIFEST, INTENT)
NODE_FILES = (RELEASE + '/node/bin/node', RELEASE + '/node/lib/node_modules/npm/package.json')
PHASES = ('pending', 'started', 'done')

def node_only_records(docs, conversion_hash):
    m, j = docs[MANIFEST], docs[JOURNAL]
    expected_node_pins = {k: v for k, v in PINS.items() if k.startswith('node_')}
    known_node = {p: h for p, h in {**j['files'], **m['immutable_files']}.items() if p in NODE_FILES}
    if set(known_node) != set(NODE_FILES) or j['steps']['node'] != {'complete': True, 'lock_digest': None}:
        raise GuardError('shared_node_provenance_missing')
    common = {'install_id': NODE_ONLY_ID, 'pins': expected_node_pins, 'openclaw_removed': True,
              'n8n_removed': True, 'shared_node_preserved': True}
    manifest = {**common, 'schema': 1, 'dependency_lock_sha256': {}, 'immutable_files': known_node,
                'created_utc': m['created_utc'], 'protected_snapshot': m['protected_snapshot']}
    journal = {**common, 'schema': 3, 'steps': {'node': {'complete': True, 'lock_digest': None}},
               'files': known_node, 'credentials': {}}
    retired = {'schema': 3, 'id': 'quantum-automation-retired-v1', 'state': 'retired',
               'previous_conversion_sha256': conversion_hash, 'openclaw_removed': True,
               'n8n_removed': True, 'shared_node_preserved': True, 'historical_backups_preserved': True}
    return {JOURNAL: encoded(journal), MANIFEST: encoded(manifest), INTENT: encoded(retired)}, known_node

def claw_target_record(path, allow_absent=False, expected_parent=None):
    if path not in CLAW_TARGETS:
        raise GuardError('unreviewed_openclaw_removal_target')
    parent, name = open_parent(path)
    try:
        ps = info_record(os.fstat(parent))
        if expected_parent is not None and ps != expected_parent:
            raise GuardError('openclaw_removal_parent_identity_changed')
        try:
            s = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if allow_absent:
                return None
            raise GuardError('unstarted_openclaw_target_missing') from None
        owner = (CLAW_UID, CLAW_GID, 0o700) if path == STATE + '/openclaw' else (0, 0, 0o755 if path == RELEASE + '/openclaw' else 0o644 if path == CLAW_UNIT else 0o600)
        expected_type = stat.S_ISDIR if path in CLAW_TARGETS[1:3] else stat.S_ISREG
        if not expected_type(s.st_mode) or (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) != owner or s.st_dev != ps['dev']:
            raise GuardError('unsafe_owned_openclaw_target')
        return {'file': info_record(s), 'parent': ps}
    finally:
        os.close(parent)

def claw_tree(fd, device, state_tree, delete=False):
    count, size = 0, 0
    owners = {(CLAW_UID, CLAW_GID)} if state_tree else {(0, 0), (BUILDER_UID, BUILDER_GID)}
    for entry in os.scandir(fd):
        s = entry.stat(follow_symlinks=False)
        if s.st_dev != device or (s.st_uid, s.st_gid) not in owners:
            raise GuardError('foreign_openclaw_subtree_entry')
        if stat.S_ISDIR(s.st_mode):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if info_record(os.fstat(child)) != info_record(s):
                    raise GuardError('openclaw_subdirectory_identity_changed')
                n, b = claw_tree(child, device, state_tree, delete)
                count += n; size += b
            finally:
                os.close(child)
            if delete:
                if info_record(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != info_record(s):
                    raise GuardError('openclaw_subdirectory_identity_changed')
                os.rmdir(entry.name, dir_fd=fd)
        elif stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode):
            count += 1
            if stat.S_ISREG(s.st_mode):
                size += s.st_size
            if delete:
                if info_record(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) != info_record(s):
                    raise GuardError('openclaw_entry_identity_changed')
                os.unlink(entry.name, dir_fd=fd)
        else:
            raise GuardError('special_openclaw_subtree_entry')
    if delete:
        os.fsync(fd)
    return count, size

def claw_tree_inventory(path, record):
    assert_no_mounts(path)
    parent, name = open_parent(path)
    child = None
    try:
        if info_record(os.fstat(parent)) != record['parent']:
            raise GuardError('openclaw_removal_parent_identity_changed')
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        if info_record(os.fstat(child)) != record['file']:
            raise GuardError('openclaw_removal_target_identity_changed')
        return claw_tree(child, record['file']['dev'], path == STATE + '/openclaw')
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)

def no_other_owned_workers():
    r = command(['systemctl', 'list-units', '--type=service', '--state=active,activating,deactivating',
                 '--no-legend', '--plain', 'qvpn-automation-build-*', 'qvpn-automation-install-*',
                 'qvpn-openclaw-migration-*', 'qvpn-n8n-scratch-cleanup-*',
                 'qvpn-openclaw-model-check-*', 'qvpn-openclaw-config-check-*'], check=False)
    if r.returncode:
        raise GuardError('owned_worker_inventory_failed')
    for line in r.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[3] != 'exited':
            raise GuardError('owned_worker_still_running')
    no_account_processes(BUILDER_UID)

def initial_removal_inventory():
    raw, _ = read_fixed(INTENT)
    docs = validate_completed_intent(json.loads(raw))
    account_identity('qvpn-openclaw', CLAW_UID, CLAW_GID, STATE + '/openclaw')
    account_identity('qvpn-automation-build', BUILDER_UID, BUILDER_GID, '/nonexistent')
    no_other_owned_workers()
    s = unit_state(SERVICES['openclaw'])
    if s.get('FragmentPath') != CLAW_UNIT or s.get('DropInPaths') != '':
        raise GuardError('foreign_openclaw_unit')
    config, _ = read_owned_openclaw_config()
    if json.loads(config) != openclaw_config(docs[JOURNAL]['credentials']['token']):
        raise GuardError('openclaw_security_policy_drift')
    new, node = node_only_records(docs, sha(raw))
    old_hashes, identities = {}, {}
    for path in (*CLAW_RECORDS, CLAW_UNIT, ACCESS):
        content, identity = read_fixed(path, modes=(0o644,) if path == CLAW_UNIT else (0o600,))
        old_hashes[path] = sha(content); identities[path] = identity
    targets = {p: claw_target_record(p) for p in CLAW_TARGETS}
    files, size = 0, 0
    for path in CLAW_TARGETS[1:3]:
        n, b = claw_tree_inventory(path, targets[path]); files += n; size += b
    return {'schema': 1, 'id': UNINSTALL_ID, 'state': 'pending',
            'old_hashes': old_hashes, 'identities': identities, 'targets': targets,
            'new': {p: base64.b64encode(v).decode() for p, v in new.items()}, 'node_files': node,
            'removed': {p: 'pending' for p in CLAW_TARGETS},
            'converted': {p: 'pending' for p in CLAW_RECORDS}, 'account': 'pending',
            'protected_snapshot': protected_snapshot(), 'protected_active': {u: is_active(u) for u in PROTECTED_UNITS},
            'files_before': files, 'bytes_before': size}

def validate_removal_intent(value):
    fields = {'schema', 'id', 'state', 'old_hashes', 'identities', 'targets', 'new', 'node_files',
              'removed', 'converted', 'account', 'protected_snapshot', 'protected_active', 'files_before', 'bytes_before'}
    records = set((*CLAW_RECORDS, CLAW_UNIT, ACCESS))
    if not isinstance(value, dict) or set(value) != fields or value.get('schema') != 1 or value.get('id') != UNINSTALL_ID or value.get('state') not in ('pending', 'done'):
        raise GuardError('invalid_openclaw_removal_intent')
    if set(value['old_hashes']) != records or set(value['identities']) != records or set(value['targets']) != set(CLAW_TARGETS) or set(value['removed']) != set(CLAW_TARGETS) or set(value['converted']) != set(CLAW_RECORDS) or set(value['new']) != set(CLAW_RECORDS) or set(value['node_files']) != set(NODE_FILES):
        raise GuardError('invalid_openclaw_removal_scope')
    if any(x not in PHASES for x in [*value['removed'].values(), *value['converted'].values(), value['account']]) or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in [*value['old_hashes'].values(), *value['node_files'].values()]):
        raise GuardError('invalid_openclaw_removal_checkpoint')
    if any(not isinstance(value[k], int) or isinstance(value[k], bool) or value[k] < 0 for k in ('files_before', 'bytes_before')):
        raise GuardError('invalid_openclaw_removal_size')
    new = {p: base64.b64decode(b, validate=True) for p, b in value['new'].items()}
    m, j, history = [json.loads(new[p]) for p in (MANIFEST, JOURNAL, INTENT)]
    pins = {k: v for k, v in PINS.items() if k.startswith('node_')}
    if set(m) != {'install_id', 'pins', 'openclaw_removed', 'n8n_removed', 'shared_node_preserved', 'schema', 'dependency_lock_sha256', 'immutable_files', 'created_utc', 'protected_snapshot'} or set(j) != {'install_id', 'pins', 'openclaw_removed', 'n8n_removed', 'shared_node_preserved', 'schema', 'steps', 'files', 'credentials'}:
        raise GuardError('invalid_node_only_document_fields')
    for doc in (m, j):
        if doc['install_id'] != NODE_ONLY_ID or doc['pins'] != pins or any(doc.get(k) is not True for k in ('openclaw_removed', 'n8n_removed', 'shared_node_preserved')):
            raise GuardError('node_only_document_policy_drift')
    expected_history = {'schema': 3, 'id': 'quantum-automation-retired-v1', 'state': 'retired',
                        'previous_conversion_sha256': value['old_hashes'][INTENT], 'openclaw_removed': True,
                        'n8n_removed': True, 'shared_node_preserved': True, 'historical_backups_preserved': True}
    if m['schema'] != 1 or m['dependency_lock_sha256'] != {} or m['immutable_files'] != value['node_files'] or j['schema'] != 3 or j['steps'] != {'node': {'complete': True, 'lock_digest': None}} or j['files'] != value['node_files'] or j['credentials'] != {} or history != expected_history:
        raise GuardError('invalid_node_only_proof')
    if value['state'] == 'done' and any(p != 'done' for p in [*value['removed'].values(), *value['converted'].values(), value['account']]):
        raise GuardError('incomplete_openclaw_removal_marked_done')
    return new

def save_removal_intent(value, create=False):
    validate_removal_intent(value)
    if create:
        parent, name = open_parent(UNINSTALL_INTENT)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as handle:
                os.fchmod(handle.fileno(), 0o600); handle.write(encoded(value)); handle.flush(); os.fsync(handle.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
    else:
        raw, identity = read_fixed(UNINSTALL_INTENT)
        atomic_cas(UNINSTALL_INTENT, identity, encoded(value), sha(raw))

def removal_checkpoint_check(value):
    new = validate_removal_intent(value)
    for path, expected in value['node_files'].items():
        if immutable_digest(path) != expected:
            raise GuardError('shared_node_provenance_drift')
    for path in CLAW_RECORDS:
        raw, identity = read_fixed(path)
        phase = value['converted'][path]
        if sha(raw) == sha(new[path]):
            if phase == 'pending':
                raise GuardError('unjournaled_node_only_replacement')
        elif sha(raw) != value['old_hashes'][path] or identity != value['identities'][path] or phase == 'done':
            raise GuardError('retiring_record_identity_changed')
    for path, record in value['targets'].items():
        actual = claw_target_record(path, value['removed'][path] != 'pending', record['parent'])
        if actual is None:
            continue
        if value['removed'][path] == 'done' or actual != record:
            raise GuardError('openclaw_target_recreated_or_changed')
        if path in (CLAW_UNIT, ACCESS):
            raw, identity = read_fixed(path, modes=(0o644,) if path == CLAW_UNIT else (0o600,))
            if identity != value['identities'][path] or sha(raw) != value['old_hashes'][path]:
                raise GuardError('openclaw_target_content_drift')
    protected_check(value)
    return new

def claw_unit_inventory(allow_missing=False):
    r = command(['systemctl', 'show', SERVICES['openclaw'], '-p', 'LoadState', '-p', 'ActiveState',
                 '-p', 'SubState', '-p', 'FragmentPath', '-p', 'DropInPaths', '-p', 'MainPID'], check=False)
    values = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
    missing = (values.get('LoadState') == 'not-found' and values.get('ActiveState') == 'inactive'
               and values.get('SubState') == 'dead' and values.get('FragmentPath') == ''
               and values.get('DropInPaths') == '' and values.get('MainPID') == '0')
    if r.returncode and not (allow_missing and missing):
        raise GuardError('openclaw_unit_inventory_failed')
    if values.get('LoadState') == 'not-found' and not (allow_missing and missing):
        raise GuardError('unstarted_openclaw_unit_missing')
    return values

def stop_owned_claw(value):
    s = claw_unit_inventory(value['removed'][CLAW_UNIT] != 'pending')
    if s.get('FragmentPath') not in ('', CLAW_UNIT) or s.get('DropInPaths') != '':
        raise GuardError('foreign_openclaw_unit')
    if value['removed'][CLAW_UNIT] == 'pending' or claw_target_record(CLAW_UNIT, True) is not None:
        command(['systemctl', 'stop', SERVICES['openclaw']], timeout=45)
        command(['systemctl', 'disable', SERVICES['openclaw']])
    s = claw_unit_inventory(value['removed'][CLAW_UNIT] != 'pending')
    if s.get('ActiveState') not in ('inactive', 'failed'):
        raise GuardError('openclaw_stop_failed')
    no_account_processes(CLAW_UID); no_other_owned_workers()
    if command(['ss', '-lntH', 'sport = :18789']).stdout.strip():
        raise GuardError('openclaw_port_still_in_use')

def remove_claw_target(path, value):
    if path not in CLAW_TARGETS or value['removed'][path] != 'started':
        raise GuardError('unreviewed_or_unstarted_openclaw_removal')
    record = value['targets'][path]
    actual = claw_target_record(path, True, record['parent'])
    if actual is None:
        return
    if actual != record:
        raise GuardError('openclaw_removal_target_identity_changed')
    no_account_processes(CLAW_UID); no_account_processes(BUILDER_UID); assert_no_mounts(path)
    parent, name = open_parent(path)
    try:
        if info_record(os.fstat(parent)) != record['parent'] or info_record(os.stat(name, dir_fd=parent, follow_symlinks=False)) != record['file']:
            raise GuardError('openclaw_removal_target_identity_changed')
        if path in CLAW_TARGETS[1:3]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                if info_record(os.fstat(child)) != record['file']:
                    raise GuardError('openclaw_removal_target_identity_changed')
                claw_tree(child, record['file']['dev'], path == STATE + '/openclaw')
                claw_tree(child, record['file']['dev'], path == STATE + '/openclaw', True)
            finally:
                os.close(child)
            if info_record(os.stat(name, dir_fd=parent, follow_symlinks=False)) != record['file']:
                raise GuardError('openclaw_removal_target_identity_changed')
            os.rmdir(name, dir_fd=parent)
        else:
            raw, identity = read_fixed(path, modes=(0o644,) if path == CLAW_UNIT else (0o600,))
            if identity != value['identities'][path] or sha(raw) != value['old_hashes'][path]:
                raise GuardError('openclaw_target_content_drift')
            if info_record(os.stat(name, dir_fd=parent, follow_symlinks=False)) != record['file']:
                raise GuardError('openclaw_removal_target_identity_changed')
            os.unlink(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)

def remove_claw_account(value):
    if value['account'] == 'done':
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup('qvpn-openclaw')
            except KeyError:
                continue
            raise GuardError('removed_openclaw_account_recreated')
        return
    try:
        pwd.getpwnam('qvpn-openclaw')
    except KeyError:
        if value['account'] != 'started':
            raise GuardError('unstarted_openclaw_account_missing') from None
    else:
        try:
            account_identity('qvpn-openclaw', CLAW_UID, CLAW_GID, STATE + '/openclaw')
        except KeyError:
            raise GuardError('existing_openclaw_user_missing_group') from None
        no_account_processes(CLAW_UID)
        value['account'] = 'started'; save_removal_intent(value)
        command(['userdel', 'qvpn-openclaw'])  # Never recursive home deletion.
    try:
        group = grp.getgrnam('qvpn-openclaw')
    except KeyError:
        group = None
    if group is not None:
        if group.gr_gid != CLAW_GID or group.gr_mem or any(a.pw_gid == CLAW_GID for a in pwd.getpwall()):
            raise GuardError('openclaw_group_identity_changed')
        command(['groupdel', 'qvpn-openclaw'])
    value['account'] = 'done'; save_removal_intent(value)

def retire_claw_records(value, new):
    for path in CLAW_RECORDS:
        raw, identity = read_fixed(path)
        if sha(raw) == sha(new[path]):
            if value['converted'][path] == 'pending':
                raise GuardError('unjournaled_node_only_replacement')
        else:
            if sha(raw) != value['old_hashes'][path] or identity != value['identities'][path]:
                raise GuardError('retiring_record_identity_changed')
            value['converted'][path] = 'started'; save_removal_intent(value)
            atomic_cas(path, identity, new[path], value['old_hashes'][path])
        current, _ = read_fixed(path)
        if sha(current) != sha(new[path]):
            raise GuardError('node_only_replacement_failed')
        value['converted'][path] = 'done'; save_removal_intent(value)

def removed_runtime_check(value):
    removal_checkpoint_check(value)
    for path in CLAW_TARGETS:
        if claw_target_record(path, True, value['targets'][path]['parent']) is not None:
            raise GuardError('openclaw_target_still_present')
    remove_claw_account(value)
    s = claw_unit_inventory(True)
    if s.get('LoadState') != 'not-found' or s.get('FragmentPath') or s.get('DropInPaths') or s.get('ActiveState') != 'inactive' or s.get('SubState') != 'dead' or s.get('MainPID') != '0':
        raise GuardError('openclaw_unit_still_loaded')
    no_account_processes(CLAW_UID)
    if command(['ss', '-lntH', 'sport = :18789']).stdout.strip():
        raise GuardError('openclaw_port_still_in_use')

def uninstall_main(do_apply, do_resume=False):
    existing = Path(UNINSTALL_INTENT).exists() or Path(UNINSTALL_INTENT).is_symlink()
    if existing:
        raw, _ = read_fixed(UNINSTALL_INTENT); value = json.loads(raw)
        new = removal_checkpoint_check(value)
    else:
        value = initial_removal_inventory(); new = validate_removal_intent(value)
    if not do_apply:
        if value['state'] == 'done':
            removed_runtime_check(value)
        output({'status': 'OpenClawRemovalInventory', 'mode': 'read_only', 'state': value['state'],
                'files_before': value['files_before'], 'bytes_before': value['bytes_before'],
                'targets': list(CLAW_TARGETS), 'shared_node_preserved': True, 'ollama_preserved': True,
                'historical_backups_and_audits_preserved': True, 'mutations': False})
        return
    with safe_install_lock() as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        no_other_owned_workers()
        if existing and not do_resume:
            raise GuardError('explicit_openclaw_removal_resume_required')
        if not existing and do_resume:
            raise GuardError('no_openclaw_removal_to_resume')
        if value['state'] == 'done':
            removed_runtime_check(value)
            output({'status': 'OpenClawAlreadyRemoved', 'shared_node_preserved': True, 'ollama_preserved': True})
            return
        if not existing:
            # Repeat all live ownership gates after acquiring the exclusive lock.
            current = initial_removal_inventory()
            for k in ('old_hashes', 'identities', 'targets', 'new', 'node_files', 'protected_snapshot', 'protected_active'):
                if current[k] != value[k]:
                    raise GuardError('openclaw_inventory_changed_before_apply')
            save_removal_intent(value, True)
        removal_checkpoint_check(value)
        stop_owned_claw(value)
        for path in CLAW_TARGETS:
            if value['removed'][path] == 'done':
                continue
            removal_checkpoint_check(value)
            value['removed'][path] = 'started'; save_removal_intent(value)
            remove_claw_target(path, value)
            value['removed'][path] = 'done'; save_removal_intent(value)
            output({'phase': 'owned_openclaw_target_removed', 'path': path})
        remove_claw_account(value)
        retire_claw_records(value, new)
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'reset-failed', SERVICES['openclaw']], check=False)
        removed_runtime_check(value)
        value['state'] = 'done'; save_removal_intent(value)
        output({'status': 'OpenClawRemoved', 'files_before': value['files_before'], 'bytes_before': value['bytes_before'],
                'shared_node_preserved': True, 'ollama_preserved': True, 'credentials_retired': True,
                'protected_configuration_unchanged': True, 'historical_backups_and_audits_preserved': True})
'''


def remote_script(apply=False, resume=False):
    b = migration.base
    return '\n'.join(['PINS=' + repr(b.PINS), b.COMMON, b.REMOTE, 'import grp', migration.MIGRATION, UNINSTALL,
        f"try:\n uninstall_main({apply!r},{resume!r})\nexcept GuardError as e:\n output({{'status':'Blocked','code':str(e)}});raise SystemExit(2)\nexcept Exception as e:\n output({{'status':'Failed','code':type(e).__name__}});raise SystemExit(3)"])


def worker_script(job, payload=None):
    script = migration.worker_script(job, payload)
    return script.replace("EXPECTED_INSTALL_ID = 'quantum-openclaw-only-v2'", "EXPECTED_INSTALL_ID = 'quantum-openclaw-removal-v1'").replace(
        "ROOT = Path('/run/quantum-openclaw-migration')", "ROOT = Path('/run/quantum-openclaw-removal')").replace(
        "UNIT = 'qvpn-openclaw-migration-'", "UNIT = 'qvpn-openclaw-removal-'").replace(
        'b"migrate_main(True"', 'b"uninstall_main(True"').replace(
        "'qvpn-openclaw-migration-*'])", "'qvpn-openclaw-migration-*','qvpn-n8n-scratch-cleanup-*','qvpn-openclaw-removal-*'])")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply', action='store_true'); p.add_argument('--resume', action='store_true')
    p.add_argument('--start-worker', action='store_true'); p.add_argument('--worker-status')
    p.add_argument('--known-hosts', default=str(Path.home() / '.ssh/known_hosts'))
    args = p.parse_args()
    if (args.resume or args.start_worker) and not args.apply:
        p.error('--resume/--start-worker require --apply')
    if args.worker_status and (args.apply or args.resume or args.start_worker):
        p.error('--worker-status is read-only and separate')
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print(json.dumps({'status': 'Blocked', 'code': 'missing_password_environment'})); return 2
    import paramiko
    c = paramiko.SSHClient(); c.load_host_keys(args.known_hosts)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        c.connect('150.241.96.191', username='root', password=password, allow_agent=False, look_for_keys=False, timeout=15)
        code = worker_script(args.worker_status) if args.worker_status else worker_script(uuid.uuid4().hex, remote_script(True, args.resume)) if args.start_worker else remote_script(args.apply, args.resume)
        incoming, out, err = c.exec_command('python3 -B -', timeout=1900)
        incoming.write(code); incoming.channel.shutdown_write()
        for line in out:
            print(json.dumps(json.loads(line), ensure_ascii=False), flush=True)
        err.read(); return out.channel.recv_exit_status()
    except Exception as exc:
        print(json.dumps({'status': 'Failed', 'code': type(exc).__name__})); return 3
    finally:
        c.close()


if __name__ == '__main__':
    sys.exit(main())
