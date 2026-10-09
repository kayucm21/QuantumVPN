"""Add a pinned native FakeTLS MTProxy on 5443 without replacing existing services.

Default: read-only inventory, no upload, backup, package install or restart.
--apply builds only the new service from the same reviewed official commit and
adds a secret-file patch bound to its own systemd credential. No secret argv,
VPN/DNS/nginx/Caddy changes, WEB proxy changes, or existing MTProxy 3443 changes.
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path


BASE_REMOTE_SHA256 = '2220e68473178a24f4aab9e96ccd12b7447647b47fe60f0ae97d325b5ac334bb'
SECURITY_PATCH_SHA256 = '04762e7126ca87a151ded7be645ded6408060607257e53f2ff8d2b0c9816c473'


def _reviewed_remote() -> str:
    """Derive only from an exact reviewed source; no importing installer side effects."""
    tree = ast.parse(Path(__file__).with_name('install-mtproto-vds.py').read_text(encoding='utf-8'))
    values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'REMOTE' for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    if len(values) != 1 or hashlib.sha256(values[0].encode()).hexdigest() != BASE_REMOTE_SHA256:
        raise RuntimeError('base_installer_changed_review_required')
    remote = values[0]

    def replace(old: str, new: str, count: int = 1) -> None:
        nonlocal remote
        if remote.count(old) != count:
            raise RuntimeError('tls_derivation_anchor_mismatch')
        remote = remote.replace(old, new)

    replace('quantumvpn-mtproto', 'quantumvpn-mtproto-tls', 17)
    replace('qvpn-mtproto', 'qvpn-mtproto-tls', 3)
    replace('quantumvpn_mtproto.py', 'quantumvpn_mtproto_tls.py', 5)
    replace('PORT=3443', 'PORT=5443')
    replace('STATS_PORT=18888', 'STATS_PORT=18889')
    replace("HOST='150.241.96.191'", "HOST='150.241.96.191'\nDOMAIN='pecaocek.ignorelist.com'")
    replace("PATCH_ID='systemd-secret-file-v2'", "PATCH_ID='systemd-secret-file-tls-v1'")
    replace('MemoryMax=512M', 'MemoryMax=384M')
    replace('CPUQuota=75%', 'CPUQuota=50%')
    replace('Description=QuantumVPN pinned Telegram MTProxy with local secret-file security patch',
            'Description=QuantumVPN pinned native Telegram FakeTLS MTProxy')
    replace('ExecStart=/usr/bin/python3 ', 'ExecStart=/usr/bin/python3 -B ')
    replace("           Path('/var/lib/rospanel/secrets.key'),Path('/etc/resolv.conf'))",
            "           Path('/var/lib/rospanel/secrets.key'),Path('/etc/resolv.conf'),\n"
            "           Path('/etc/systemd/system/quantumvpn-mtproto.service'),\n"
            "           Path('/etc/quantumvpn-mtproto/config.json'),Path('/etc/quantumvpn-mtproto/client-secret'),\n"
            "           Path('/opt/quantumvpn-mtproto/mtproto-proxy'),Path('/opt/quantumvpn-mtproto/quantumvpn_mtproto.py'),\n"
            "           Path('/etc/quantumvpn-webproxy/config.json'),Path('/etc/quantumvpn-webproxy/token.key'),\n"
            "           Path('/etc/systemd/system/quantumvpn-webproxy.service'))")
    replace('import base64,fcntl,hashlib,json,os,platform,pwd,re,shutil,signal,socket,stat,subprocess,tempfile,time,urllib.parse,urllib.request',
            'import base64,fcntl,hashlib,json,os,platform,pwd,re,shutil,signal,socket,stat,subprocess,sys,tempfile,time,types,urllib.parse,urllib.request')
    replace('from pathlib import Path\n', 'from pathlib import Path\nsys.dont_write_bytecode=True\n')
    replace('result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,',
            "result=subprocess.run(args,stdout=subprocess.PIPE,\n"
            "                              stderr=subprocess.PIPE if stage=='binary_build' else subprocess.DEVNULL,text=True,")
    replace("    if result.returncode: raise RuntimeError('server_command_failed_'+stage)",
            "    if result.returncode:\n"
            "        if stage=='binary_build':\n"
            "            print(json.dumps({'status':'BuildFailed','build_error_classification':\n"
            "                 classify_build_error(result.stdout,result.stderr)}),flush=True)\n"
            "        raise RuntimeError('server_command_failed_'+stage)")
    replace("    namespace={'__name__':'quantumvpn_mtproto_install_helpers'}\n    exec(compile(source,'<quantumvpn-mtproto-tls-module>','exec'),namespace)\n    return namespace",
            "    namespace={'__name__':'quantumvpn_mtproto_tls_install_helpers','__file__':str(ROOT/'quantumvpn_mtproto_tls.py')}\n"
            "    exec(compile(source,'<quantumvpn-mtproto-tls-module>','exec'),namespace)\n    return namespace")
    replace("    module_source=base64.b64decode(MODULE_B64,validate=True).decode('utf-8')\n    module=load_module(module_source)",
            "    module_source=decode_runtime(MODULE_B64,MODULE_SHA256)\n"
            "    protocol_source=decode_runtime(PROTOCOL_B64,PROTOCOL_SHA256)\n"
            "    base_module_source=decode_runtime(BASE_MODULE_B64,BASE_MODULE_SHA256)\n"
            "    module=load_runtime_modules(module_source,protocol_source,base_module_source)")
    replace("    if module['COMMIT']!=COMMIT or module['PUBLIC_PORT']!=PORT or module['STATS_PORT']!=STATS_PORT:",
            "    if (module['COMMIT']!=COMMIT or module['PUBLIC_PORT']!=PORT or module['STATS_PORT']!=STATS_PORT\n"
            "        or module.get('DOMAIN')!=DOMAIN or module.get('SECURITY_PATCH')!=PATCH_ID\n"
            "        or module.get('SECURITY_PATCH_SHA256')!=EXPECTED_PATCH_SHA256\n"
            "        or module.get('BASE_MODULE_SHA256')!=BASE_MODULE_SHA256):")
    replace("    lock=open('/run/lock/quantumvpn-mtproto-tls.install.lock','a')\n    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)",
            "    lock=install_lock()\n    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)")
    replace("    if missing and not INSTALL_DEPS:raise RuntimeError('build_dependencies_missing_use_explicit_install_deps')\n"
            "    if missing:\n        env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')\n"
            "        run(['apt-get','update'],180,env,stage='dependencies_update')\n"
            "        run(['apt-get','install','-y','--no-install-recommends',*PACKAGES],300,env,stage='dependencies_install')",
            "    if missing:raise RuntimeError('build_dependencies_missing_no_system_packages_changed')\n"
            "    run(['/usr/bin/python3','-B','-c','import cryptography'],5,stage='crypto_check')\n"
            "    if shutil.disk_usage('/var/tmp').free<600*1024*1024:raise RuntimeError('build_disk_headroom_required')")
    replace("        run(user_prefix+['make','-C',str(source),'-j2','CC=gcc -fcommon'],300,stage='binary_build')",
            "        lock_build_source(source,account)\n"
            "        build_pinned_source(source)\n"
            "        if (source/'mtproto/mtproto-proxy.c').read_bytes()!=patched_source:\n"
            "            raise RuntimeError('patched_source_changed_during_build')")
    replace("        require_free_ports()\n        if any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT)):",
            "        if before!=protected_identity():raise RuntimeError('protected_files_changed_concurrently_no_overwrite')\n"
            "        require_free_ports()\n        if any(path.exists() or path.is_symlink() for path in (ROOT,PRIVATE,UNIT)):")
    replace("        exclusive(ROOT/'quantumvpn_mtproto_tls.py',module_source.encode(),0o644)",
            "        exclusive(ROOT/'quantumvpn_mtproto_tls.py',module_source.encode(),0o644)\n"
            "        exclusive(ROOT/'quantumvpn_mtproto_tls_protocol.py',protocol_source.encode(),0o644)\n"
            "        exclusive(ROOT/'quantumvpn_mtproto.py',base_module_source.encode(),0o644)")
    replace("                'binary_sha256':digest(ROOT/'mtproto-proxy'),'module_sha256':digest(ROOT/'quantumvpn_mtproto_tls.py'),",
            "                'binary_sha256':digest(ROOT/'mtproto-proxy'),'module_sha256':digest(ROOT/'quantumvpn_mtproto_tls.py'),\n"
            "                'protocol_sha256':digest(ROOT/'quantumvpn_mtproto_tls_protocol.py'),\n"
            "                'base_module_sha256':digest(ROOT/'quantumvpn_mtproto.py'),'domain':DOMAIN,")
    replace("'compiler':'gcc -fcommon','workers':1", "'compiler':'gcc -fcommon','workers':0")
    replace("ignore=shutil.ignore_patterns('.git','objs')", "ignore=shutil.ignore_patterns('.git','objs','dep')")
    replace("    if digest(ROOT/'mtproto-proxy')!=config['binary_sha256'] or digest(ROOT/'quantumvpn_mtproto_tls.py')!=config['module_sha256']:\n"
            "        raise RuntimeError('existing_managed_binary_identity_mismatch')",
            "    identities={'mtproto-proxy':'binary_sha256','quantumvpn_mtproto_tls.py':'module_sha256',\n"
            "                'quantumvpn_mtproto_tls_protocol.py':'protocol_sha256','quantumvpn_mtproto.py':'base_module_sha256'}\n"
            "    for name,key in identities.items():\n"
            "        if (ROOT/name).is_symlink() or digest(ROOT/name)!=config.get(key):\n"
            "            raise RuntimeError('existing_managed_binary_identity_mismatch')\n"
            "    if config['module_sha256']!=MODULE_SHA256 or config['protocol_sha256']!=PROTOCOL_SHA256 or config['base_module_sha256']!=BASE_MODULE_SHA256:\n"
            "        raise RuntimeError('existing_runtime_changed_review_required')")
    replace("    before=protected_identity()\n    existing=managed_install(module)",
            "    if hashlib.sha256(patch_manifest()).hexdigest()!=EXPECTED_PATCH_SHA256:\n"
            "        raise RuntimeError('tls_patch_identity_mismatch')\n"
            "    for path in (ROOT,PRIVATE,UNIT):safe_parent(path)\n"
            "    before=protected_identity()\n    existing=managed_install(module)")
    replace("if RUN_REMOTE:\n", _REMOTE_HELPERS + "\nif RUN_REMOTE:\n")
    ast.parse(remote)
    return remote


_REMOTE_HELPERS = r'''
def safe_parent(path):
    if not path.is_absolute() or any(parent.is_symlink() for parent in path.parents):
        raise RuntimeError('symlink_or_relative_managed_parent_refused')

def decode_runtime(value,expected):
    raw=base64.b64decode(value,validate=True)
    if not 1<=len(raw)<=512*1024 or not re.fullmatch(r'[a-f0-9]{64}',expected) or hashlib.sha256(raw).hexdigest()!=expected:
        raise RuntimeError('trusted_runtime_source_identity_mismatch')
    return raw.decode('utf-8')

def load_runtime_modules(helper_source,protocol_source,base_source):
    names=('quantumvpn_mtproto','quantumvpn_mtproto_tls_protocol')
    previous={name:sys.modules.get(name) for name in names}
    try:
        for name,source in zip(names,(base_source,protocol_source)):
            module=types.ModuleType(name);module.__file__=str(ROOT/(name+'.py'))
            sys.modules[name]=module
            exec(compile(source,'<trusted-'+name+'>','exec'),module.__dict__)
        return load_module(helper_source)
    finally:
        for name,old in previous.items():
            if old is None:sys.modules.pop(name,None)
            else:sys.modules[name]=old

def install_lock():
    path=Path('/run/lock/quantumvpn-mtproto-tls.install.lock');safe_parent(path)
    fd=os.open(path,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        os.close(fd);raise RuntimeError('install_lock_identity_refused')
    return os.fdopen(fd,'r+')

def lock_build_source(source,account):
    # All checked-in inputs become root-owned/read-only to the build account.
    # The official Makefile writes only dep/ and objs/, which it may own.
    # The account must not rename the root-owned inputs through a writable parent.
    if source.parent.parent!=Path('/var/tmp') or not source.parent.name.startswith('quantumvpn-mtproto-tls-build-'):
        raise RuntimeError('unsafe_build_source_parent')
    os.chown(source.parent,0,0);os.chmod(source.parent,0o755)
    for parent,dirs,files in os.walk(source,followlinks=False):
        for name in dirs+files:
            target=Path(parent)/name
            if target.is_symlink():raise RuntimeError('source_tree_symlink_refused')
            os.chown(target,0,0)
            os.chmod(target,0o755 if target.is_dir() or target.stat().st_mode&0o111 else 0o644)
        os.chown(parent,0,0);os.chmod(parent,0o755)
    for name in ('dep','objs'):
        target=source/name
        if target.exists():raise RuntimeError('unexpected_official_build_output_path')
        target.mkdir(mode=0o755);os.chown(target,account.pw_uid,account.pw_gid)

def build_pinned_source(source):
    # A transient unit owns compiler children and kills the entire group on the
    # hard runtime deadline; it cannot write to checked-in sources or /etc.
    args=['systemd-run','--quiet','--wait','--collect','--pipe',
      '--unit=qvpn-mtproto-tls-build-'+str(os.getpid()),
      '--property=User='+USER,'--property=Group='+USER,
      '--property=WorkingDirectory='+str(source),'--property=NoNewPrivileges=yes',
      '--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateDevices=yes',
      '--property=TemporaryFileSystem=/tmp:rw,size=128M,mode=1777,nosuid,nodev',
      '--property=ReadWritePaths='+str(source/'dep')+' '+str(source/'objs'),
      '--property=MemoryMax=768M','--property=CPUQuota=50%','--property=TasksMax=64',
      '--property=RuntimeMaxSec=300','--property=KillMode=control-group','--property=LimitCORE=0',
      '--setenv=HOME=/nonexistent','--','make','-C',str(source),'-j1','CC=gcc -fcommon','COMMIT='+COMMIT]
    run(args,360,stage='binary_build')

def classify_build_error(stdout,stderr):
    # Never return raw compiler/unit messages, excerpts, paths, argv or secrets.
    # The official pinned build has finite output; classify at most 64KiB.
    pieces=[]
    for value in (stdout,stderr):
        value=value if isinstance(value,str) else ''
        pieces.append(value[:16384]+value[-16384:])
    text='\n'.join(pieces).lower()
    result={
      'readonly_fs':bool(re.search(r'read.only file system|\berofs\b',text)),
      'tmp_mentioned':bool(re.search(r'/tmp(?:/|\b)|\btmpdir\b|temporary file',text)),
      'permission_denied':bool(re.search(r'permission denied|access denied|\beacces\b',text)),
      'compiler_error':bool(re.search(r'(?:gcc|cc1|collect2|\bld\b|fatal).*error|fatal error:',text)),
      'missing_file':bool(re.search(r'no such file|not found|\benoent\b',text)),
      'nativeunit_startfail':bool(re.search(r'failed to (?:start|set unit)|failed at step|unknown (?:property|assignment)|changing to.*directory.*failed',text)),
    }
    result['unclassified']=not any(result.values())
    return result
'''

REMOTE = _reviewed_remote()


def main() -> None:
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--verify-public', action='store_true', help='Read-only genuine FakeTLS/resPQ nonce proof from this PC')
    options = parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment')
    names = ('quantumvpn_mtproto_tls.py', 'quantumvpn_mtproto_tls_protocol.py', 'quantumvpn_mtproto.py')
    sources = [Path(__file__).with_name(name).read_bytes() for name in names]
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -B -', timeout=1250)
        program = 'APPLY=' + repr(options.apply) + '\nRUN_REMOTE=True\nEXPECTED_PATCH_SHA256=' + repr(SECURITY_PATCH_SHA256) + '\n'
        for prefix, source in zip(('MODULE', 'PROTOCOL', 'BASE_MODULE'), sources):
            program += prefix + '_B64=' + repr(base64.b64encode(source).decode('ascii')) + '\n'
            program += prefix + '_SHA256=' + repr(hashlib.sha256(source).hexdigest()) + '\n'
        stdin.write(program + REMOTE)
        stdin.channel.shutdown_write()
        for line in stdout:
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read()  # Never expose raw compiler/server/SSH messages or credentials.
        if stdout.channel.recv_exit_status():
            raise SystemExit('Native FakeTLS operation failed; raw details suppressed')
        if options.verify_public:
            from quantumvpn_mtproto_tls import external_health_probe
            with client.open_sftp() as sftp:
                with sftp.open('/etc/quantumvpn-mtproto-tls/client-secret', 'rb') as stream:
                    secret = stream.read(65).decode('ascii').strip()
            proof = external_health_probe(secret)
            del secret
            print(json.dumps({'public_protocol_proof': proof}), flush=True)
            if not proof.get('ok'):
                raise SystemExit('Public native FakeTLS nonce proof failed; check TCP 5443/provider firewall')
    finally:
        client.close()


if __name__ == '__main__':
    main()
