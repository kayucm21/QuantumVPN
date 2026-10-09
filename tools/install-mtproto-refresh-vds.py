"""Inspect or explicitly install the guarded daily updater for the owned MTProxy."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path


SOURCE_SHA256 = "b0c60d925092201144c9bc517138715cdd3dc1c169e4d1d7f095b60a409c9697"
REMOTE = r'''
import base64,hashlib,json,os,signal,stat,subprocess,tempfile,time
from pathlib import Path
SCRIPT=Path('/opt/quantumvpn-mtproto/refresh-mtproto-upstream.py')
UNIT_ROOT=Path('/etc/systemd/system')
SERVICE='quantumvpn-mtproto-refresh.service'
TIMER='quantumvpn-mtproto-refresh.timer'
WANTED=UNIT_ROOT/'timers.target.wants'/TIMER

def service_text():
    return """[Unit]
Description=QuantumVPN guarded official Telegram MTProxy upstream refresh
After=network-online.target quantumvpn-mtproto.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 -B /opt/quantumvpn-mtproto/refresh-mtproto-upstream.py --apply
TimeoutStartSec=240
RuntimeMaxSec=240
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_SYS_PTRACE
ReadWritePaths=/etc/quantumvpn-mtproto /var/lib/quantumvpn-operator/mtproto-upstream-backups
UMask=0077
MemoryMax=128M
CPUQuota=25%
Nice=10
LimitCORE=0
StandardOutput=null
StandardError=null
"""

def timer_text():
    return """[Unit]
Description=Daily QuantumVPN official Telegram MTProxy upstream refresh

[Timer]
OnCalendar=*-*-* 02:17:00 UTC
RandomizedDelaySec=300
Persistent=true
Unit=quantumvpn-mtproto-refresh.service

[Install]
WantedBy=timers.target
"""

def command(args,timeout=20,allow_failure=False):
    try:
        value=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,
                             timeout=timeout,check=False)
    except (OSError,subprocess.SubprocessError):
        raise RuntimeError('bounded_install_command_failed') from None
    if value.returncode and not allow_failure:raise RuntimeError('bounded_install_command_failed')
    return value.stdout

def trusted_source():
    source=base64.b64decode(SOURCE_B64,validate=True)
    if hashlib.sha256(source).hexdigest()!=SOURCE_SHA256:raise RuntimeError('refresh_source_identity_mismatch')
    namespace={'__name__':'quantumvpn_mtproto_refresh_install_helpers'}
    exec(compile(source,'<pinned-refresh-source>','exec'),namespace)
    return source,namespace

def artifacts(source):
    return {SCRIPT:source,UNIT_ROOT/SERVICE:service_text().encode(),UNIT_ROOT/TIMER:timer_text().encode()}

def unit_properties(name):
    raw=command(['systemctl','show',name,'--no-pager',
                 '--property=LoadState,FragmentPath,DropInPaths,NeedDaemonReload,ActiveState,UnitFileState'],allow_failure=True)
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)

def verify_existing(expected,module):
    present=[path.exists() or path.is_symlink() for path in expected]
    if any(present) and not all(present):raise RuntimeError('incomplete_existing_refresh_install_refused')
    existing=all(present)
    for path,data in expected.items():
        module['directory'](path.parent,0o755)
        if existing and module['read_file'](path,65536,0o644)!=data:
            raise RuntimeError('unmanaged_refresh_artifact_refused')
    for name in (SERVICE,TIMER):
        state=unit_properties(name)
        if existing:
            if (state.get('LoadState')!='loaded' or state.get('FragmentPath')!=str(UNIT_ROOT/name)
                    or state.get('DropInPaths')!='' or state.get('NeedDaemonReload')!='no'):
                raise RuntimeError('unmanaged_refresh_runtime_unit_refused')
        elif state.get('LoadState')!='not-found' or state.get('FragmentPath') or state.get('DropInPaths'):
            raise RuntimeError('existing_refresh_runtime_unit_refused')
    if WANTED.parent.exists() or WANTED.parent.is_symlink():module['directory'](WANTED.parent,0o755)
    if WANTED.exists() or WANTED.is_symlink():
        if not existing or not WANTED.is_symlink() or WANTED.resolve()!=UNIT_ROOT/TIMER:
            raise RuntimeError('unmanaged_timer_enable_link_refused')
    return existing

def create_file(path,data,module,created):
    module['directory'](path.parent,0o755)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:
        info=os.fstat(stream.fileno())
        module['_metadata'](info,mode=0o600)
        created.append((path,info.st_dev,info.st_ino))
        stream.write(data);stream.flush()
        os.fchmod(stream.fileno(),0o644)
        os.fsync(stream.fileno())
    module['_sync_dir'](path.parent)

def recover_created(created,expected,module,activated):
    if not created:return None
    for path,device,inode in created:
        if path not in expected:raise RuntimeError('recovery_target_refused')
        module['_parents'](path)
        info=path.lstat();module['_metadata'](info)
        if (info.st_dev,info.st_ino)!=(device,inode):raise RuntimeError('recovery_inode_changed_refused')
    if activated:
        if any(module['read_file'](path,65536,0o644)!=expected[path] for path,_,_ in created):
            raise RuntimeError('recovery_unit_identity_changed_refused')
        if (WANTED.exists() or WANTED.is_symlink()) and (not WANTED.is_symlink() or WANTED.resolve()!=UNIT_ROOT/TIMER):
            raise RuntimeError('recovery_timer_enable_link_changed_refused')
        command(['systemctl','disable','--now',TIMER],30)
        command(['systemctl','stop',SERVICE],30)
    module['_private_store']()
    destination=Path(tempfile.mkdtemp(prefix='installer-recovery-'+time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=module['BACKUPS']))
    for path,device,inode in created:
        # Recheck immediately before moving only this attempt's exact inode.
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or (info.st_dev,info.st_ino)!=(device,inode):
            raise RuntimeError('recovery_inode_changed_refused')
        path.rename(destination/path.name)
        (destination/path.name).chmod(0o600)
        module['_sync_dir'](path.parent)
    module['_sync_dir'](destination);module['_sync_dir'](module['BACKUPS'])
    command(['systemctl','daemon-reload'])
    return str(destination)

def refresh_now(module):
    # subprocess receives only fixed paths/flags. Trusted JSON is bounded; raw
    # stderr, process arguments, remote exceptions, and key bytes are suppressed.
    raw=command(['/usr/bin/python3','-B',str(SCRIPT),'--apply'],260)
    if len(raw)>8192:raise RuntimeError('refresh_result_too_large')
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise RuntimeError('refresh_result_invalid') from None
    if not isinstance(value,dict) or value.get('status') not in ('Updated','Unchanged','Recovered'):
        raise RuntimeError('refresh_result_refused')
    return value

def main():
    if os.name!='posix' or os.geteuid()!=0:raise RuntimeError('linux_root_required')
    source,module=trusted_source()
    install=module['owned_install']();module['verify_service']()
    expected=artifacts(source);existing=verify_existing(expected,module)
    if not APPLY:
        print(json.dumps({'status':'ReadOnly','installed':existing,'changed':False,
                          'refresh':module['inspect_or_refresh']()}),flush=True)
        return
    module['proof'](install['module']);module['assert_install'](install)
    module['_private_store']()
    created=[];activated=False
    try:
        if not existing:
            for path,data in expected.items():create_file(path,data,module,created)
            command(['systemd-analyze','verify',str(UNIT_ROOT/SERVICE),str(UNIT_ROOT/TIMER)])
            command(['systemctl','daemon-reload'])
        # Existing owner-disabled/stopped timers remain in their current state.
        result=refresh_now(module)
        module['assert_install'](install);module['verify_service']()
        health=module['proof'](install['module'])
        if not existing:
            activated=True
            command(['systemctl','enable','--now',TIMER],30)
            state=unit_properties(TIMER)
            if state.get('ActiveState')!='active' or state.get('UnitFileState')!='enabled':
                raise RuntimeError('new_timer_activation_not_confirmed')
        print(json.dumps({'status':'AlreadyInstalled' if existing else 'Installed','changed':not existing,
                          'timer_state_preserved':existing,'schedule':'02:17 UTC daily + up to 300 seconds',
                          'refresh':result,'health':health}),flush=True)
    except BaseException:
        try:recovery=recover_created(created,expected,module,activated)
        except BaseException:raise RuntimeError('refresh_install_recovery_incomplete') from None
        if recovery:print(json.dumps({'status':'RolledBack','recovery_path':recovery}),flush=True)
        raise RuntimeError('refresh_install_failed_new_artifacts_recovered' if created else 'refresh_apply_failed') from None

if RUN_REMOTE:
    try:main()
    except Exception as error:
        import re
        code=str(error) if isinstance(error,RuntimeError) and re.fullmatch(r'[a-z_]{1,96}',str(error)) else 'bounded_refresh_install_failed'
        print(json.dumps({'status':'Failed','reason':code}),flush=True)
        raise SystemExit(1) from None
'''


def main():
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args()
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required in the environment")
    source = Path(__file__).with_name("refresh-mtproto-upstream.py").read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise SystemExit("Refresh source identity mismatch")
    client = paramiko.SSHClient()
    client.load_host_keys("C:/Users/Admin/.ssh/known_hosts")
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect("150.241.96.191", username="root", password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command("python3 -B -", timeout=420)
        program = ("APPLY=" + repr(options.apply) + "\nRUN_REMOTE=True\nSOURCE_SHA256=" + repr(SOURCE_SHA256)
                   + "\nSOURCE_B64=" + repr(base64.b64encode(source).decode("ascii")) + "\n" + REMOTE)
        stdin.write(program)
        stdin.channel.shutdown_write()
        for line in stdout:
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise SystemExit("MTProxy refresh installation failed; raw details suppressed")
    finally:
        client.close()


if __name__ == "__main__":
    main()
