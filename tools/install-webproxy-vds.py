"""Privately install a pinned official Telegram WEB relay on the owned VDS.

The default is a read-only inventory. --apply --relay-only installs only a new
loopback relay, never nginx/Caddy/RosPanel, public listeners, VPN or APK settings.
The existing RosPanel TLS front/Xray fallback needs a separately approved front
integration before clients can use this relay. Upstream has no LICENSE: no source/binary is vendored
or published here; verified upstream archives are fetched only on the owner's VDS.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path


REMOTE = r'''
import base64,fcntl,hashlib,http.client,io,json,os,platform,pwd,re,shutil,socket,sqlite3,stat,subprocess,sys,tarfile,tempfile,time,urllib.parse,urllib.request
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
COMMIT='c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8'
ARCHIVE_URL='https://codeload.github.com/telegramdesktop/tproxy-server/tar.gz/'+COMMIT
ARCHIVE_SHA256='a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549'
ARCHIVE_SIZE=139727
GO_URL='https://dl.google.com/go/go1.27.1.linux-amd64.tar.gz'
GO_SHA256='63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445'
GO_SIZE=70553950
GO_VERSION='go1.27.1'
GO_MOD_SHA256='7d3ba1e86605768b4cf7a4a91654e29012677e0892a2c27a8e29432de1802658'
GO_SUM_SHA256='1737d5523b7264df09b253e86e29f96af295a7bd18e0aaa4373c6099317e065f'
ROOT=Path('/opt/quantumvpn-webproxy')
PRIVATE=Path('/etc/quantumvpn-webproxy')
UNIT=Path('/etc/systemd/system/quantumvpn-webproxy.service')
SERVICE='quantumvpn-webproxy.service'
USER='qvpn-webproxy'
PUBLIC_HOST='pecaocek.ignorelist.com'
PUBLIC_UPSTREAM='http://127.0.0.1:8080'
LISTEN='127.0.0.1:18082'
ADMIN='127.0.0.1:18083'
BACKEND='127.0.0.1:3443'
MT_ROOT=Path('/opt/quantumvpn-mtproto')
MT_PRIVATE=Path('/etc/quantumvpn-mtproto')
DATA=Path('/var/lib/quantumvpn-operator')
PROTECTED=(Path('/etc/nginx/nginx.conf'),Path('/etc/nginx/sites-available/quantumvpn-operator'),
 Path('/var/lib/rospanel/xray/config.json'),Path('/var/lib/rospanel/secrets.key'),
 Path('/etc/resolv.conf'),Path('/usr/local/bin/rospanel'),
 DATA/'routing-ed25519.key',MT_PRIVATE/'client-secret',MT_PRIVATE/'config.json',
 MT_ROOT/'mtproto-proxy',MT_ROOT/'quantumvpn_mtproto.py')

def require(value,label):
    if not value:raise RuntimeError(label)

def sha(data):return hashlib.sha256(data).hexdigest()

def read_file(path,maximum,private=False):
    safe_parent(path)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=maximum,'file_type_or_size_refused')
        if private:require(info.st_uid==0 and not info.st_mode&0o077,'private_file_permissions_refused')
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(maximum+1)
        require(len(data)<=maximum,'file_size_refused')
        return data
    finally:os.close(fd)

def digest(path,maximum=512*1024*1024):
    # No secret bytes, paths or digests enter the status report.
    return sha(read_file(path,maximum))

def safe_parent(path):
    require(path.is_absolute(),'absolute_path_required')
    for ancestor in (path.parent,*path.parent.parents):
        require(not ancestor.is_symlink(),'symlink_parent_refused')

def exclusive(path,data,mode=0o600):
    safe_parent(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.chmod(path,mode)

def run(argv,timeout=30,stage='command',env=None,cwd=None):
    require(re.fullmatch(r'[a-z_]{1,64}',stage),'invalid_command_stage')
    try:
        result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              timeout=timeout,check=False,env=env,cwd=cwd,text=True)
    except subprocess.TimeoutExpired:raise RuntimeError('command_timeout_'+stage) from None
    require(result.returncode==0,'command_failed_'+stage)
    return result.stdout

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('download_redirect_refused')

def download(url,expected,size):
    require((url,expected,size) in ((ARCHIVE_URL,ARCHIVE_SHA256,ARCHIVE_SIZE),(GO_URL,GO_SHA256,GO_SIZE)),
            'download_not_allowlisted')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    request=urllib.request.Request(url,headers={'User-Agent':'QuantumVPN-owned-private-install'})
    with opener.open(request,timeout=45) as response:
        require(response.status==200,'download_http_failed')
        data=response.read(size+1)
    require(len(data)==size and sha(data)==expected,'download_identity_mismatch')
    return data

def extract_archive(data,target,root_name,max_members,max_total):
    require(target.is_dir() and not target.is_symlink() and not any(target.iterdir()),'extraction_target_not_empty')
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        members=archive.getmembers()
        require(len(members)<=max_members,'archive_member_limit')
        total=0;names=set()
        for member in members:
            path=PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts and path.parts[0]==root_name,
                    'archive_path_refused')
            name=tuple(path.parts)
            require(name not in names and (member.isdir() or member.isfile()) and not member.issparse(),
                    'archive_type_or_duplicate_refused')
            require(member.size>=0,'archive_size_refused')
            names.add(name);total+=member.size
            require(total<=max_total,'archive_expanded_size_limit')
        for member in members:
            parts=PurePosixPath(member.name).parts[1:]
            if not parts:continue
            destination=target.joinpath(*parts)
            require(destination.is_relative_to(target),'archive_path_refused')
            if member.isdir():destination.mkdir(parents=True,exist_ok=True,mode=0o755)
            else:
                destination.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                value=archive.extractfile(member).read(member.size+1)
                require(len(value)==member.size,'archive_file_size_mismatch')
                exclusive(destination,value,0o755 if member.mode&0o111 else 0o644)

def canonical(data):return (json.dumps(data,sort_keys=True,separators=(',',':'))+'\n').encode()

def base_path(value):
    require(isinstance(value,str) and re.fullmatch(r'qweb-[a-z0-9]{12,48}',value),'base_path_refused')
    return value

def config(path):
    return {'public_hostname':PUBLIC_HOST,'base_path':base_path(path),'listen':LISTEN,'admin_listen':ADMIN,
      'public_upstream':PUBLIC_UPSTREAM,'profiles_file':'/run/credentials/'+SERVICE+'/profiles.json',
      'token_key_file':'/run/quantumvpn-webproxy/token.key','enable_pprof':False,'static_routes':'exact',
      'limits':{'max_header_bytes':16384,'max_body_bytes':2097152,'max_frame_payload':1048576,
        'carrier_batch_bytes':1048576,'max_streams_per_session':32,'max_closed_stream_ids':1024,
        'max_pending_per_session':8388608,'max_pending_global':67108864,
        'max_pending_items_per_session':8192,'max_pending_items_global':65536,
        'max_sessions_per_ip':16,'max_sessions_global':32,'max_streams_global':512,
        'max_backend_dials_in_flight':32,'new_sessions_per_minute':120,'new_sessions_burst':32,
        'new_streams_per_minute':1200,'new_streams_burst':128,'max_bootstraps_per_ip':16,
        'max_bootstraps_global':128,'new_bootstraps_per_minute':240,'new_bootstraps_burst':64,'max_profiles':1},
      'timeouts':{'backend_dial':'5s','long_poll':'25s','reconnect_grace':'2m','bootstrap_lifetime':'2m',
                  'read_header':'10s','idle':'75s','shutdown':'15s'}}

def profiles(secret):
    require(isinstance(secret,str) and re.fullmatch(r'[a-f0-9]{32}',secret),'existing_mt_secret_invalid')
    return {'profiles':[{'name':'quantumvpn','secret':secret,'backend':BACKEND,'carrier_mode':'https'}]}

def unit_text():
    return """[Unit]
Description=QuantumVPN private pinned Telegram WEB relay
After=network-online.target quantumvpn-mtproto.service
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=qvpn-webproxy
Group=qvpn-webproxy
WorkingDirectory=/opt/quantumvpn-webproxy
RuntimeDirectory=quantumvpn-webproxy
RuntimeDirectoryMode=0700
LoadCredential=config.json:/etc/quantumvpn-webproxy/config.json
LoadCredential=profiles.json:/etc/quantumvpn-webproxy/profiles.json
LoadCredential=token.key:/etc/quantumvpn-webproxy/token.key
LoadCredential=manifest.json:/etc/quantumvpn-webproxy/manifest.json
ExecStart=/usr/bin/python3 -B /opt/quantumvpn-webproxy/quantumvpn_webproxy.py --serve
Environment=GOMEMLIMIT=256MiB
Environment=GOMAXPROCS=1
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=20
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
MemoryMax=384M
CPUQuota=50%
Nice=5
StandardOutput=null
StandardError=null
LimitCORE=0

[Install]
WantedBy=multi-user.target
"""

def protected_snapshot():
    files={}
    for path in PROTECTED:
        if path.is_symlink():
            info=path.lstat();files[str(path)]=(info.st_dev,info.st_ino,'symlink:'+os.readlink(path))
        elif path.exists():files[str(path)]=(path.stat().st_dev,path.stat().st_ino,digest(path))
    db=DATA/'operator.db';release=None
    if db.exists():
        require(db.is_file() and not db.is_symlink(),'operator_database_path_refused')
        connection=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True,timeout=10)
        try:
            rows=connection.execute('select key,value from settings').fetchall()
            values={key:value for key,value in rows if key.startswith(('release_','scheduled_','staging_','public_'))
                    or key in ('app_version','app_version_code','min_version_code','maintenance','maintenance_message')}
            release=sha(canonical(values))
        finally:connection.close()
    return files,release

def listeners():
    found={}
    for line in run(['ss','-H','-ltn'],5,'listeners').splitlines():
        fields=line.split()
        if len(fields)>=4 and re.search(r':(?:18082|18083)$',fields[3]):
            found.setdefault(int(fields[3].rsplit(':',1)[1]),[]).append(fields[3])
    return found

def read_only_inventory():
    require(os.geteuid()==0 and platform.system()=='Linux' and platform.machine()=='x86_64','owned_linux_amd64_root_required')
    for path in (ROOT,PRIVATE,UNIT):safe_parent(path)
    mt_config=json.loads(read_file(MT_PRIVATE/'config.json',8192,private=True))
    require(mt_config.get('managed_by')=='quantumvpn' and mt_config.get('port')==3443,'managed_mtproxy_required')
    require(digest(MT_ROOT/'quantumvpn_mtproto.py',512*1024)==mt_config.get('module_sha256'),'mt_helper_identity_mismatch')
    require(digest(MT_ROOT/'mtproto-proxy',100*1024*1024)==mt_config.get('binary_sha256'),'mt_binary_identity_mismatch')
    secret=read_file(MT_PRIVATE/'client-secret',64,private=True).decode('ascii').strip()
    profiles(secret);del secret
    run(['/usr/bin/python3','-B','-c','import cryptography'],5,'crypto_check')
    # TCP readiness is not represented as a successful Telegram handshake.
    for address in (('127.0.0.1',3443),('127.0.0.1',8080)):
        with socket.create_connection(address,timeout=3):pass
    require(shutil.disk_usage('/opt').free>1100*1024*1024,'build_disk_headroom_required')
    mem={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines()}
    require(int(mem.get('MemAvailable','0 kB').split()[0])>=900*1024,'build_memory_headroom_required')
    installed=any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT))
    if not installed:require(not listeners(),'relay_ports_occupied')
    return {'status':'ReadOnly','installed':installed,'front_integration':'pending_separate_review',
            'public_ready':False,'source_commit':COMMIT,'go_version':GO_VERSION,
            'new_listeners':'loopback_only','existing_front_unchanged':True}

def load_helper(source):
    namespace={'__name__':'quantumvpn_webproxy_install_verify','__file__':str(ROOT/'quantumvpn_webproxy.py')}
    exec(compile(source,'<verified-owned-webproxy-helper>','exec'),namespace)
    return namespace

def user_identity():
    try:value=pwd.getpwnam(USER)
    except KeyError:
        run(['useradd','--system','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',USER],15,'new_service_user')
        value=pwd.getpwnam(USER)
    require(value.pw_uid!=0 and value.pw_gid!=0 and value.pw_shell in ('/usr/sbin/nologin','/sbin/nologin')
            and value.pw_dir=='/nonexistent','existing_service_user_refused')
    return value

def own_tree(path,user):
    for parent,dirs,files in os.walk(path,followlinks=False):
        for name in dirs+files:
            child=Path(parent)/name;require(not child.is_symlink(),'build_tree_symlink_refused')
            os.chown(child,user.pw_uid,user.pw_gid)
        os.chown(parent,user.pw_uid,user.pw_gid)

def build(source,toolchain,staging,user):
    require(digest(source/'go.mod',4096)==GO_MOD_SHA256 and digest(source/'go.sum',4096)==GO_SUM_SHA256,'module_lock_identity_mismatch')
    home=staging/'build-home';home.mkdir(mode=0o700)
    own_tree(source,user);own_tree(home,user)
    go=toolchain/'bin/go'
    require(run([str(go),'version'],5,'go_version').strip()=='go version '+GO_VERSION+' linux/amd64','toolchain_identity_mismatch')
    prefix=['systemd-run','--quiet','--wait','--collect','--pipe',
       '--property=User='+USER,'--property=Group='+USER,'--property=WorkingDirectory='+str(source),
       '--property=NoNewPrivileges=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes',
       '--property=PrivateTmp=yes','--property=PrivateDevices=yes','--property=MemoryMax=768M',
       '--property=CPUQuota=50%','--property=TasksMax=128','--property=RuntimeMaxSec=600',
       '--property=LimitCORE=0','--property=ReadWritePaths='+str(source)+' '+str(home),
       '--setenv=HOME='+str(home),'--setenv=GOCACHE='+str(home/'cache'),'--setenv=GOPATH='+str(home/'modules'),
       '--setenv=GOPROXY=https://proxy.golang.org','--setenv=GOSUMDB=sum.golang.org','--setenv=GOTOOLCHAIN=local',
       '--setenv=GOFLAGS=-mod=readonly','--setenv=GOMAXPROCS=1','--setenv=GOMEMLIMIT=512MiB',
       '--setenv=CGO_ENABLED=0','--setenv=GOPRIVATE=','--setenv=GONOSUMDB=','--setenv=GOINSECURE=',
       '--setenv=GONOPROXY=','--setenv=GOENV=off','--setenv=GOTELEMETRY=off',
       '--setenv=GOROOT='+str(toolchain),'--']
    for suffix,stage in ((['mod','download'],'go_download'),(['mod','verify'],'go_verify'),
                         (['test','-p','1','-timeout','120s','./...'],'go_test'),
                         (['build','-p','1','-trimpath','-o','tproxy-server','./cmd/tproxy-server'],'go_build')):
        run(prefix[:-1]+['--unit=qvpn-web-build-'+str(os.getpid())+'-'+stage.replace('_','-'),'--',str(go)]+suffix,620,stage)
    require(digest(source/'go.mod',4096)==GO_MOD_SHA256 and digest(source/'go.sum',4096)==GO_SUM_SHA256,'module_lock_changed')
    binary=source/'tproxy-server'
    require(read_file(binary,50*1024*1024).startswith(b'\x7fELF'),'build_output_not_elf')
    return binary

def remember(created,path):created.append((path,path.stat().st_dev,path.stat().st_ino))

def rollback(created,started):
    if started:
        run(['systemctl','disable','--now',SERVICE],30,'new_service_rollback')
    if not created:return None
    recovery=Path('/etc')/('quantumvpn-webproxy-failed-'+str(time.time_ns()))
    recovery.mkdir(mode=0o700)
    for path,device,inode in reversed(created):
        require(path.exists() and not path.is_symlink() and (path.stat().st_dev,path.stat().st_ino)==(device,inode),
                'rollback_identity_changed_manual_recovery_required')
        os.rename(path,recovery/path.name)
    run(['systemctl','daemon-reload'],15,'rollback_daemon_reload')
    return str(recovery)

def main():
    inventory=read_only_inventory()
    if not APPLY:
        print(json.dumps(inventory),flush=True);return
    require(RELAY_ONLY,'public_front_integration_not_authorized_use_relay_only')
    source=base64.b64decode(MODULE_B64,validate=True)
    require(0<len(source)<512*1024 and sha(source)==HELPER_SHA256,'owned_helper_identity_mismatch')
    helper=load_helper(source)
    if inventory['installed']:
        require(all(path.exists() and not path.is_symlink() for path in (ROOT,PRIVATE,UNIT)),'partial_or_unmanaged_install_refused')
        manifest=json.loads(read_file(PRIVATE/'manifest.json',8192,private=True))
        require(manifest.get('commit')==COMMIT and manifest.get('archive_sha256')==ARCHIVE_SHA256
          and manifest.get('managed_by')=='quantumvpn-webproxy' and manifest.get('helper_sha256')==HELPER_SHA256,
          'existing_install_identity_refused')
        require(digest(ROOT/'quantumvpn_webproxy.py',512*1024)==HELPER_SHA256
          and digest(ROOT/'tproxy-server',50*1024*1024)==manifest.get('binary_sha256')
          and read_file(UNIT,16384)==unit_text().encode(),'existing_install_files_changed')
        require(digest(PRIVATE/'config.json',16384)==manifest.get('config_sha256')
          and digest(PRIVATE/'profiles.json',16384)==manifest.get('profiles_sha256'),
          'existing_private_configuration_changed')
        helper['_configuration']();helper['_profile']()
        if BASE_PATH:require(manifest.get('base_path')==base_path(BASE_PATH),'existing_base_path_changed_no_overwrite')
        # Idempotent inspection never starts/re-enables a stopped owner's service.
        print(json.dumps({'status':'AlreadyInstalled','changed':False,'proxy':helper['snapshot'](),
                          'public_ready':False,'front_integration':'pending_separate_review'}),flush=True);return
    before=protected_snapshot();created=[];started=False
    # /var/tmp is hidden by the build's PrivateTmp mount; keep the private
    # explicit build sandbox under /opt, never a public website directory.
    staging=Path(tempfile.mkdtemp(prefix='quantumvpn-webproxy-build-',dir='/opt'))
    os.chmod(staging,0o711)
    try:
        user=user_identity()
        upstream=staging/'source';upstream.mkdir(mode=0o700)
        toolchain=staging/'go';toolchain.mkdir(mode=0o755)
        source_archive=download(ARCHIVE_URL,ARCHIVE_SHA256,ARCHIVE_SIZE)
        extract_archive(source_archive,upstream,'tproxy-server-'+COMMIT,128,2*1024*1024)
        extract_archive(download(GO_URL,GO_SHA256,GO_SIZE),toolchain,'go',30000,512*1024*1024)
        binary=build(upstream,toolchain,staging,user)
        require(before==protected_snapshot(),'protected_configuration_changed_no_overwrite')
        require(not listeners(),'relay_ports_changed_concurrently')
        require(not any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT)),'install_paths_changed_no_overwrite')
        ROOT.mkdir(mode=0o755);remember(created,ROOT)
        PRIVATE.mkdir(mode=0o700);remember(created,PRIVATE)
        exclusive(ROOT/'tproxy-server',read_file(binary,50*1024*1024),0o755)
        exclusive(ROOT/'quantumvpn_webproxy.py',source,0o644)
        (ROOT/'toolchain').mkdir(mode=0o700)
        os.rename(toolchain,ROOT/'toolchain/go')
        # The pinned archive is retained privately, never served by either panel.
        exclusive(ROOT/'upstream.tar.gz',source_archive)
        path=base_path(BASE_PATH) if BASE_PATH else 'qweb-'+os.urandom(12).hex()
        secret=read_file(MT_PRIVATE/'client-secret',64,private=True).decode('ascii').strip()
        profile_data=canonical(profiles(secret));del secret
        exclusive(PRIVATE/'profiles.json',profile_data)
        del profile_data
        exclusive(PRIVATE/'token.key',os.urandom(32))
        exclusive(PRIVATE/'config.json',canonical(config(path)))
        manifest={'schema':1,'managed_by':'quantumvpn-webproxy','commit':COMMIT,'archive_sha256':ARCHIVE_SHA256,
          'binary_sha256':digest(ROOT/'tproxy-server',50*1024*1024),'helper_sha256':HELPER_SHA256,
          'public_host':PUBLIC_HOST,'public_port':443,'base_path':path,'carrier_mode':'https',
          'listen':LISTEN,'admin_listen':ADMIN,'backend':BACKEND,'public_upstream':PUBLIC_UPSTREAM,
          'go_version':GO_VERSION,'go_archive_sha256':GO_SHA256,'created_at':int(time.time()),
          'unit_sha256':sha(unit_text().encode()),'config_sha256':digest(PRIVATE/'config.json',16384),
          'profiles_sha256':digest(PRIVATE/'profiles.json',16384),'front_integration':'pending_separate_review'}
        exclusive(PRIVATE/'manifest.json',canonical(manifest))
        exclusive(UNIT,unit_text().encode(),0o644);remember(created,UNIT)
        run(['systemd-analyze','verify',str(UNIT)],20,'unit_verify')
        run(['systemctl','daemon-reload'],15,'daemon_reload')
        # Set before enable: a partially successful systemctl must also roll back.
        started=True
        run(['systemctl','enable','--now',SERVICE],40,'new_service_start')
        until=time.monotonic()+30;proof={'ok':False}
        while time.monotonic()<until:
            proof=helper['private_health_probe']()
            if proof.get('ok'):break
            time.sleep(1)
        require(proof.get('ok'),'local_mtproto_nonce_not_confirmed')
        require(listeners()=={18082:[LISTEN],18083:[ADMIN]},'relay_listener_not_exclusively_loopback')
        require(before==protected_snapshot(),'protected_configuration_changed_no_overwrite')
        print(json.dumps({'status':'InstalledRelayOnly','changed':True,'public_ready':False,
          'front_integration':'pending_separate_review','local_protocol_proof':proof,
          'proxy':helper['snapshot'](),'protected_configuration_unchanged':True}),flush=True)
    except Exception:
        recovery=rollback(created,started)
        if recovery:print(json.dumps({'status':'RolledBack','private_recovery_path':recovery,'existing_services_unchanged':True}),flush=True)
        raise
    finally:
        target=staging.resolve()
        require(target.parent==Path('/opt') and target.name.startswith('quantumvpn-webproxy-build-'),
                'temporary_cleanup_path_refused')
        shutil.rmtree(target)

if RUN_REMOTE:
    try:main()
    except Exception as error:
        print(json.dumps({'status':'Failed','reason':str(error) if isinstance(error,RuntimeError)
                         else 'bounded_private_install_failed_raw_details_suppressed'}),flush=True)
        raise SystemExit(1)
'''


def main() -> None:
    import hashlib
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--relay-only', action='store_true', help='Explicitly acknowledge front integration is not installed')
    parser.add_argument('--base-path', default='', help='Optional private prefix qweb- plus 12–48 lowercase letters/digits')
    options = parser.parse_args()
    if options.apply and not options.relay_only:
        parser.error('--apply requires --relay-only; RosPanel/Xray public front is never changed')
    if options.base_path:
        import re
        if not re.fullmatch(r'qweb-[a-z0-9]{12,48}', options.base_path):
            parser.error('invalid private prefix')
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment')
    source = Path(__file__).with_name('quantumvpn_webproxy.py').read_bytes() if options.apply else b''
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -B -', timeout=2700)
        program = ('APPLY=' + repr(options.apply) + '\nRELAY_ONLY=' + repr(options.relay_only)
                   + '\nBASE_PATH=' + repr(options.base_path)
                   + '\nMODULE_B64=' + repr(base64.b64encode(source).decode('ascii'))
                   + '\nHELPER_SHA256=' + repr(hashlib.sha256(source).hexdigest())
                   + '\nRUN_REMOTE=True\n' + REMOTE)
        stdin.write(program)
        stdin.channel.shutdown_write()
        for line in stdout:
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read()  # Raw compiler, SSH and credential-bearing details stay suppressed.
        if stdout.channel.recv_exit_status():
            raise SystemExit('Private WEB relay operation failed; raw details suppressed')
    finally:
        client.close()


if __name__ == '__main__':
    main()
