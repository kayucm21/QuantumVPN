"""Inspect/install pinned official Telegram MTProxy with a local secret-file patch.

No VPN, nginx, DNS, subscriptions, existing ports or existing keys are replaced.
An existing managed install is verified and reused; unmanaged paths are refused.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path


REMOTE = r'''
import base64,fcntl,hashlib,json,os,platform,pwd,re,shutil,signal,socket,stat,subprocess,tempfile,time,urllib.parse,urllib.request
from pathlib import Path
COMMIT='f36d8af769ffaeac36978d38c2c0f6d1104c2137'
BASE_SOURCE_SHA256='31116c17d5245b8d564d04b252a4d80e24c23f637342e09e33c47b08973defad'
SOURCE='https://github.com/TelegramMessenger/MTProxy.git'
ROOT=Path('/opt/quantumvpn-mtproto')
PRIVATE=Path('/etc/quantumvpn-mtproto')
UNIT=Path('/etc/systemd/system/quantumvpn-mtproto.service')
SERVICE='quantumvpn-mtproto.service'
USER='qvpn-mtproto'
PORT=3443
STATS_PORT=18888
HOST='150.241.96.191'
PACKAGES=('git','ca-certificates','curl','openssl','build-essential','libssl-dev','zlib1g-dev')
PROTECTED=(Path('/etc/nginx/nginx.conf'),Path('/var/lib/rospanel/xray/config.json'),
           Path('/var/lib/rospanel/secrets.key'),Path('/etc/resolv.conf'))

def run(args,timeout=30,env=None,stage=None):
    if stage is None:
        stage=Path(args[0]).name.replace('-','_')
        if stage=='systemctl' and len(args)>1:stage+='_'+args[1].replace('-','_')
    if not re.fullmatch(r'[a-z_]{1,64}',stage):raise RuntimeError('invalid_command_stage')
    try:
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,
                              timeout=timeout,check=False,env=env)
    except subprocess.TimeoutExpired:
        raise RuntimeError('server_command_timeout_'+stage) from None
    if result.returncode: raise RuntimeError('server_command_failed_'+stage)
    return result.stdout

def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for piece in iter(lambda:stream.read(1048576),b''):value.update(piece)
    return value.hexdigest()

def protected_identity():
    return {str(path):digest(path) for path in PROTECTED if path.is_file()}

def ports_in_use(output):
    result=set()
    for line in output.splitlines():
        fields=line.split()
        if len(fields)>=4:
            match=re.search(r':([0-9]{1,5})$',fields[3])
            if match:result.add(int(match.group(1)))
    return result

def require_free_ports():
    used=ports_in_use(run(['ss','-H','-ltn'],5))
    if used.intersection((PORT,STATS_PORT)):raise RuntimeError('requested_port_occupied_no_services_changed')

def verify_stats_listener():
    listeners=[]
    for line in run(['ss','-H','-ltn'],5).splitlines():
        fields=line.split()
        if len(fields)>=4 and fields[3].endswith(':'+str(STATS_PORT)):listeners.append(fields[3])
    if listeners!=['127.0.0.1:'+str(STATS_PORT)]:
        raise RuntimeError('stats_listener_not_exclusively_loopback')

def missing_packages():
    missing=[]
    for package in PACKAGES:
        result=subprocess.run(['dpkg-query','-W','-f='+chr(36)+'{Status}',package],capture_output=True,text=True,timeout=5)
        if result.returncode or result.stdout.strip()!='install ok installed':missing.append(package)
    return missing

def exclusive(path,data,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.chmod(path,mode)

class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlsplit(newurl)
        if parsed.scheme!='https' or parsed.hostname!='core.telegram.org':raise RuntimeError('official_download_redirect_refused')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def official_data(endpoint,maximum):
    if endpoint not in ('getProxySecret','getProxyConfig'):raise RuntimeError('unexpected_official_endpoint')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),OfficialRedirect())
    request=urllib.request.Request('https://core.telegram.org/'+endpoint,headers={'User-Agent':'QuantumVPN-MTProxy-install'})
    with opener.open(request,timeout=20) as response:
        if response.status!=200:raise RuntimeError('official_download_failed')
        data=response.read(maximum+1)
    if not 32<=len(data)<=maximum:raise RuntimeError('official_download_size_refused')
    return data

def unit_text():
    return """[Unit]
Description=QuantumVPN pinned Telegram MTProxy with local secret-file security patch
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=qvpn-mtproto
Group=qvpn-mtproto
WorkingDirectory=/opt/quantumvpn-mtproto
LoadCredential=client-secret:/etc/quantumvpn-mtproto/client-secret
LoadCredential=proxy-secret:/etc/quantumvpn-mtproto/proxy-secret
LoadCredential=proxy-config:/etc/quantumvpn-mtproto/proxy-multi.conf
LoadCredential=runtime-config:/etc/quantumvpn-mtproto/config.json
ExecStart=/usr/bin/python3 /opt/quantumvpn-mtproto/quantumvpn_mtproto.py --serve
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=15
KillMode=control-group
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
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
LimitNOFILE=8192
TasksMax=64
MemoryMax=512M
CPUQuota=75%
Nice=5
StandardOutput=null
StandardError=null
LimitCORE=0

[Install]
WantedBy=multi-user.target
"""

PATCH_ID='systemd-secret-file-v2'
PATCH_CASE="""  case 3000:
    {
      /* QuantumVPN security patch: no client secret in process arguments. */
      if (strcmp (optarg, \"/run/credentials/quantumvpn-mtproto.service/client-secret\")) {
        exit (1);
      }
      int fd = open (optarg, O_RDONLY | O_NOFOLLOW);
      struct stat info;
      struct statvfs filesystem;
      if (fd < 0 || fstat (fd, &info) || !S_ISREG(info.st_mode) ||
          fstatvfs (fd, &filesystem) || !(filesystem.f_flag & ST_RDONLY) ||
          !((info.st_uid == 0 && info.st_gid == 0) ||
            (info.st_uid == geteuid () && info.st_gid == getegid ())) ||
          !((info.st_mode & 0777) == 0400 || (info.st_mode & 0777) == 0440) ||
          info.st_size != 33) {
        if (fd >= 0) { close (fd); }
        exit (1);
      }
      char value[34];
      ssize_t got = read (fd, value, sizeof(value));
      close (fd);
      if (got != 33 || value[32] != '\\n') { exit (1); }
      value[32] = 0;
      for (int i = 0; i < 32; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) { exit (1); }
      }
      char *saved = optarg;
      optarg = value;
      int result = f_parse_option ('S');
      memset (value, 0, sizeof(value));
      optarg = saved;
      return result;
    }
"""
PATCH_OPTION='  parse_option ("secret-file", required_argument, 0, 3000, "read client secret from fixed systemd credential");\n'

def patch_manifest():
    return (json.dumps({'id':PATCH_ID,'include':'#include <fcntl.h>\n#include <sys/stat.h>\n#include <sys/statvfs.h>\n',
                       'case':PATCH_CASE,'option':PATCH_OPTION},sort_keys=True)+'\n').encode()

def patch_source(source):
    anchors=('#include <assert.h>\n',"  case 'S':\n  case 'P':\n",'  parse_option ("mtproto-secret", required_argument, 0, \'S\', "16-byte secret in hex mode");\n')
    if any(source.count(anchor)!=1 for anchor in anchors) or 'case 3000:' in source:
        raise RuntimeError('pinned_source_patch_anchor_mismatch')
    source=source.replace(anchors[0],anchors[0]+'#include <fcntl.h>\n#include <sys/stat.h>\n#include <sys/statvfs.h>\n')
    source=source.replace(anchors[1],PATCH_CASE+anchors[1])
    return source.replace(anchors[2],anchors[2]+PATCH_OPTION)

def rollback_created(created):
    """Recover only this failed attempt's exact newly-created targets; never delete."""
    if not created:return None
    recovery_names={ROOT:'runtime',PRIVATE:'private',UNIT:'quantumvpn-mtproto.service'}
    for path,identity in created:
        if path not in recovery_names:raise RuntimeError('rollback_target_not_managed')
        if not path.exists() or path.is_symlink() or (path.stat().st_dev,path.stat().st_ino)!=identity:
            raise RuntimeError('rollback_identity_changed_manual_review_required')
    if any(path==UNIT for path,_ in created):
        if UNIT.read_text()!=unit_text():raise RuntimeError('rollback_unit_changed_manual_review_required')
        run(['systemctl','disable','--now',SERVICE],30)
    parent=Path('/var/lib/quantumvpn-mtproto-failed')
    if parent.is_symlink():raise RuntimeError('rollback_parent_symlink_refused')
    parent.mkdir(mode=0o700,exist_ok=True)
    if parent.stat().st_uid!=0 or parent.stat().st_mode & 0o077:
        raise RuntimeError('rollback_parent_permissions_refused')
    destination=Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-',time.gmtime()),dir=parent))
    for path,_ in created:
        path.rename(destination/recovery_names[path])
    if any(path==UNIT for path,_ in created):run(['systemctl','daemon-reload'],15)
    return str(destination)

def load_module(source):
    namespace={'__name__':'quantumvpn_mtproto_install_helpers'}
    exec(compile(source,'<quantumvpn-mtproto-module>','exec'),namespace)
    return namespace

def managed_install(module):
    if not any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT)):return False
    for path in (ROOT,PRIVATE,UNIT,ROOT/'mtproto-proxy',ROOT/'quantumvpn_mtproto.py'):
        if path.is_symlink():raise RuntimeError('unsafe_existing_install_path')
    config=module['_config']()
    if digest(ROOT/'mtproto-proxy')!=config['binary_sha256'] or digest(ROOT/'quantumvpn_mtproto.py')!=config['module_sha256']:
        raise RuntimeError('existing_managed_binary_identity_mismatch')
    expected_patch=hashlib.sha256(patch_manifest()).hexdigest()
    if config['patch_sha256']!=expected_patch or digest(ROOT/'security-patch.json')!=expected_patch:
        raise RuntimeError('existing_security_patch_identity_mismatch')
    if digest(ROOT/'mtproto-proxy-base.c')!=config.get('source_file_sha256'):
        raise RuntimeError('existing_base_source_identity_mismatch')
    expected=patch_source((ROOT/'mtproto-proxy-base.c').read_text())
    if (ROOT/'source/mtproto/mtproto-proxy.c').read_text()!=expected:
        raise RuntimeError('existing_patched_source_identity_mismatch')
    if UNIT.read_text()!=unit_text():raise RuntimeError('unmanaged_service_unit_refused')
    module['_secret']()
    return True

def deadline_expired(*unused):raise RuntimeError('installation_deadline')

def main():
    if os.geteuid()!=0:raise RuntimeError('root_required_for_local_service_install')
    if platform.machine() not in ('x86_64','amd64'):raise RuntimeError('official_build_architecture_unsupported')
    module_source=base64.b64decode(MODULE_B64,validate=True).decode('utf-8')
    module=load_module(module_source)
    if module['COMMIT']!=COMMIT or module['PUBLIC_PORT']!=PORT or module['STATS_PORT']!=STATS_PORT:
        raise RuntimeError('module_install_contract_mismatch')
    before=protected_identity()
    existing=managed_install(module)
    missing=missing_packages()
    if not existing:require_free_ports()
    if not APPLY:
        print(json.dumps({'mode':'read_only','installed':existing,'commit':COMMIT,'public_port':PORT,
                          'stats_port':STATS_PORT,'stats_loopback_only':True,'missing_packages':missing,
                          'status':module['snapshot'](),'protected_files_unchanged':before==protected_identity()}),flush=True)
        return
    signal.signal(signal.SIGALRM,deadline_expired);signal.alarm(1200)
    lock=open('/run/lock/quantumvpn-mtproto.install.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if existing:
        # Reinstallation never overrides an owner's deliberate stop/disable.
        probe=module['health_probe']() if module['_service_state']()=='active' else {'ok':None,'status':'service_state_preserved'}
        if probe['ok'] is False:raise RuntimeError('existing_proxy_protocol_not_confirmed')
        if probe['ok'] is True:verify_stats_listener()
        print(json.dumps({'status':'AlreadyInstalled','changed':False,'health':probe,'proxy':module['snapshot'](),
                          'protected_files_unchanged':before==protected_identity()}),flush=True)
        return
    if missing and not INSTALL_DEPS:raise RuntimeError('build_dependencies_missing_use_explicit_install_deps')
    if missing:
        env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
        run(['apt-get','update'],180,env,stage='dependencies_update')
        run(['apt-get','install','-y','--no-install-recommends',*PACKAGES],300,env,stage='dependencies_install')
    try:
        account=pwd.getpwnam(USER)
        if (account.pw_shell!='/usr/sbin/nologin' or account.pw_dir!='/nonexistent'
                or not 0<account.pw_uid<1000 or account.pw_gid<=0):
            raise RuntimeError('existing_service_user_refused')
    except KeyError:
        run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',USER],15)
        account=pwd.getpwnam(USER)
    staging=Path(tempfile.mkdtemp(prefix='quantumvpn-mtproto-build-',dir='/var/tmp'))
    os.chown(staging,account.pw_uid,account.pw_gid)
    created=[]
    try:
        source=staging/'source'
        user_prefix=['runuser','-u',USER,'--']
        run(user_prefix+['git','init','-q',str(source)],15,stage='source_init')
        run(user_prefix+['git','-C',str(source),'remote','add','origin',SOURCE],15,stage='source_remote')
        run(user_prefix+['git','-C',str(source),'fetch','--depth','1','origin',COMMIT],150,stage='source_fetch')
        run(user_prefix+['git','-C',str(source),'checkout','--detach','FETCH_HEAD'],20,stage='source_checkout')
        if run(user_prefix+['git','-C',str(source),'rev-parse','HEAD'],5,stage='source_revision').strip()!=COMMIT:
            raise RuntimeError('official_commit_identity_mismatch')
        if 'l.s_addr = htonl(0x7f000001);' not in (source/'engine/engine-net.c').read_text():
            raise RuntimeError('stats_loopback_invariant_missing')
        base_source=(source/'mtproto/mtproto-proxy.c').read_bytes()
        if hashlib.sha256(base_source).hexdigest()!=BASE_SOURCE_SHA256:
            raise RuntimeError('official_base_source_digest_mismatch')
        patched_source=patch_source(base_source.decode()).encode()
        # The staging tree belongs to this attempt; the exact official base is kept.
        (source/'mtproto/mtproto-proxy.c').write_bytes(patched_source)
        run(user_prefix+['make','-C',str(source),'-j2','CC=gcc -fcommon'],300,stage='binary_build')
        binary=source/'objs/bin/mtproto-proxy'
        if binary.is_symlink() or not binary.is_file() or not 1024<=binary.stat().st_size<=100*1024*1024:
            raise RuntimeError('official_build_output_invalid')
        proxy_secret=official_data('getProxySecret',65536)
        proxy_config=official_data('getProxyConfig',262144)
        require_free_ports()
        if any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT)):
            raise RuntimeError('install_paths_changed_concurrently_no_overwrite')
        ROOT.mkdir(mode=0o755);created.append((ROOT,(ROOT.stat().st_dev,ROOT.stat().st_ino)))
        PRIVATE.mkdir(mode=0o700);created.append((PRIVATE,(PRIVATE.stat().st_dev,PRIVATE.stat().st_ino)))
        exclusive(ROOT/'mtproto-proxy',binary.read_bytes(),0o755)
        exclusive(ROOT/'quantumvpn_mtproto.py',module_source.encode(),0o644)
        # Keep base, patched source and licenses, not temporary build intermediates.
        shutil.copytree(source,ROOT/'source',ignore=shutil.ignore_patterns('.git','objs'))
        exclusive(ROOT/'mtproto-proxy-base.c',base_source,0o644)
        exclusive(ROOT/'security-patch.json',patch_manifest(),0o644)
        config={'schema':1,'managed_by':'quantumvpn','commit':COMMIT,'source':SOURCE,'server':HOST,
                'port':PORT,'stats_port':STATS_PORT,'created_at':int(time.time()),
                'binary_sha256':digest(ROOT/'mtproto-proxy'),'module_sha256':digest(ROOT/'quantumvpn_mtproto.py'),
                'security_patch':PATCH_ID,'patch_sha256':hashlib.sha256(patch_manifest()).hexdigest(),
                'source_file_sha256':hashlib.sha256(base_source).hexdigest(),'compiler':'gcc -fcommon','workers':1}
        exclusive(PRIVATE/'client-secret',(os.urandom(16).hex()+'\n').encode())
        exclusive(PRIVATE/'proxy-secret',proxy_secret)
        exclusive(PRIVATE/'proxy-multi.conf',proxy_config)
        exclusive(PRIVATE/'config.json',(json.dumps(config,sort_keys=True)+'\n').encode())
        exclusive(UNIT,unit_text().encode(),0o644)
        created.append((UNIT,(UNIT.stat().st_dev,UNIT.stat().st_ino)))
        run(['systemd-analyze','verify',str(UNIT)],15,stage='unit_verify')
        run(['systemctl','daemon-reload'],15)
        if module['_service_state']()=='failed':run(['systemctl','reset-failed',SERVICE],10)
        run(['systemctl','enable','--now',SERVICE],30)
        until=time.monotonic()+40
        health={'ok':False}
        while time.monotonic()<until:
            if module['_service_state']()=='failed':
                raise RuntimeError('new_proxy_service_failed_before_protocol_probe')
            health=module['health_probe']()
            if health['ok']:break
            time.sleep(1)
        if not health['ok']:raise RuntimeError('installed_proxy_protocol_not_confirmed')
        verify_stats_listener()
        if before!=protected_identity():raise RuntimeError('protected_files_changed_concurrently_no_overwrite')
        print(json.dumps({'status':'Installed','changed':True,'commit':COMMIT,'security_patch':PATCH_ID,'health':health,
                          'proxy':module['snapshot'](),'protected_files_unchanged':True}),flush=True)
    except Exception:
        signal.alarm(0)  # Recovery has its own bounded commands, not an expired alarm.
        recovery=rollback_created(created)
        if recovery:
            print(json.dumps({'status':'RolledBack','recovery_path':recovery,'only_new_service_changed':True}),flush=True)
        raise
    finally:
        target=staging.resolve()
        if target.parent!=Path('/var/tmp') or not target.name.startswith('quantumvpn-mtproto-build-'):
            raise RuntimeError('unsafe_temporary_cleanup_refused')
        shutil.rmtree(target)

if RUN_REMOTE:
    try:main()
    except Exception as error:
        print(json.dumps({'status':'Failed','error_type':type(error).__name__,
                          'reason':str(error) if isinstance(error,RuntimeError) else 'bounded_install_failed_raw_details_suppressed'}),flush=True)
        raise SystemExit(1)
'''


def main() -> None:
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--install-deps", action="store_true", help="With --apply, install missing official build dependencies")
    parser.add_argument("--verify-public", action="store_true", help="Read-only real nonce proof from this PC to the fixed public endpoint")
    options = parser.parse_args()
    if options.install_deps and not options.apply:
        parser.error("--install-deps requires --apply")
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required in the environment")
    source = Path(__file__).with_name("quantumvpn_mtproto.py").read_bytes()
    client = paramiko.SSHClient()
    client.load_host_keys("C:/Users/Admin/.ssh/known_hosts")
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect("150.241.96.191", username="root", password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command("python3 -", timeout=1250)
        program = ("APPLY=" + repr(options.apply) + "\nINSTALL_DEPS=" + repr(options.install_deps)
                   + "\nMODULE_B64=" + repr(base64.b64encode(source).decode("ascii")) + "\nRUN_REMOTE=True\n" + REMOTE)
        stdin.write(program)
        stdin.channel.shutdown_write()
        for line in stdout:
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read()  # Raw compiler, server and SSH outputs never enter operator reports.
        if stdout.channel.recv_exit_status():
            raise SystemExit("MTProxy operation failed; raw details suppressed")
        if options.verify_public:
            from quantumvpn_mtproto import external_health_probe
            # Transfer directly to process memory, never an artifact, argv or output.
            with client.open_sftp() as sftp:
                with sftp.open("/etc/quantumvpn-mtproto/client-secret", "rb") as secret_file:
                    secret = secret_file.read(65).decode("ascii").strip()
            proof = external_health_probe(secret)
            del secret
            print(json.dumps({"public_protocol_proof": proof}), flush=True)
            if not proof["ok"]:
                raise SystemExit("Public MTProto nonce proof failed; check TCP 3443 and provider firewall")
    finally:
        client.close()


if __name__ == "__main__":
    main()
