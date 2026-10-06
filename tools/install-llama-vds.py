"""Install official pinned CPU runtime and source; reuse the existing Qwen GGUF."""
import argparse
import json
import os
import paramiko

REMOTE = r'''
import hashlib,json,os,pwd,shutil,stat,subprocess,tarfile,time,urllib.request
from pathlib import Path
ROOT=Path('/opt/quantumvpn-ai')
TAG='b11429'
COMMIT='d81235049384534c167caea52b85a694f6103d14'
MODEL=Path('/usr/share/ollama/.ollama/models/blobs/sha256-7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa')
MODEL_SHA='7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa'
def run(argv,timeout=180):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise RuntimeError('command failed: '+argv[0]+': '+result.stderr[-700:])
    return result.stdout
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda:stream.read(1048576),b''):h.update(part)
    return h.hexdigest()
def fetch_json(url):
    req=urllib.request.Request(url,headers={'User-Agent':'QuantumControl-local-runtime'})
    with urllib.request.urlopen(req,timeout=30) as response:return json.loads(response.read(4*1024*1024))
release=fetch_json('https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/'+TAG)
assert release['target_commitish']==COMMIT and release['tag_name']==TAG
assets=[x for x in release['assets'] if x['name'].endswith(('.tar.gz','.zip')) and ('ubuntu' in x['name'] or 'linux' in x['name']) and 'x64' in x['name'] and not any(w in x['name'].lower() for w in ('cuda','vulkan','rocm','sycl','openvino'))]
print(json.dumps({'stage':'inventory','tag':TAG,'commit':COMMIT,'assets':[{k:x.get(k) for k in ('name','size','digest','browser_download_url')} for x in assets]}),flush=True)
if not APPLY:raise SystemExit(0)
assert len(assets)==1,'ambiguous CPU artifact'
asset=assets[0]
expected=asset.get('digest','')
assert expected.startswith('sha256:') and len(expected)==71,'missing official checksum'
assert asset['size']<300*1024*1024
assert MODEL.is_file() and not MODEL.is_symlink() and digest(MODEL)==MODEL_SHA
pwd.getpwnam('ollama')
assert not ROOT.is_symlink()
ROOT.mkdir(mode=0o755,exist_ok=True)
manifest=ROOT/'runtime-manifest.json'
if manifest.is_file():
    known=json.loads(manifest.read_text())
    assert known['commit']==COMMIT and known['model_sha256']==MODEL_SHA
    assert digest(ROOT/'runtime'/'llama-server')==known['binary_sha256']
else:
    assert not (ROOT/'runtime').exists(),'unmanaged runtime exists'
    archive=ROOT/'official-runtime.download.part'
    if not archive.exists():
        req=urllib.request.Request(asset['browser_download_url'],headers={'User-Agent':'QuantumControl-local-runtime'})
        with urllib.request.urlopen(req,timeout=90) as response,archive.open('xb') as target:
            total=0
            while True:
                part=response.read(1048576)
                if not part:break
                total+=len(part)
                assert total<=asset['size']
                target.write(part)
    assert not archive.is_symlink()
    assert archive.stat().st_size==asset['size'] and digest(archive)==expected[7:]
    staging=ROOT/'runtime-extract'
    assert not staging.is_symlink()
    assert not staging.exists() or staging.is_dir() and not list(staging.iterdir())
    staging.mkdir(mode=0o755,exist_ok=True)
    assert asset['name'].endswith('.tar.gz'),'expected official tar archive'
    with tarfile.open(archive,'r:gz') as bundle:
        members=bundle.getmembers()
        assert len(members)<1000
        assert sum(x.size for x in members)<700*1024*1024
        for item in members:
            destination=(staging/item.name).resolve()
            assert destination.is_relative_to(staging.resolve())
            assert item.isfile() or item.isdir() or item.issym() or item.islnk(),'no special files'
            if item.issym():assert (destination.parent/item.linkname).resolve().is_relative_to(staging.resolve())
            if item.islnk():assert (staging/item.linkname).resolve().is_relative_to(staging.resolve())
        bundle.extractall(staging,filter='data')
    servers=list(staging.rglob('llama-server'))
    assert len(servers)==1
    source_dir=servers[0].parent
    runtime=ROOT/'runtime'
    runtime.mkdir(mode=0o755)
    for file in source_dir.iterdir():
        if file.is_file() and (file.name=='llama-server' or '.so' in file.name):
            shutil.copy2(file,runtime/file.name)
            (runtime/file.name).chmod(0o755)
    run([str(runtime/'llama-server'),'--version'],timeout=15)
    src=ROOT/'llama.cpp-source'
    assert not src.exists()
    run(['git','clone','--depth','1','--branch','v0.6.0','https://github.com/ggml-org/llama.cpp.git',str(src)],timeout=180)
    assert run(['git','-C',str(src),'rev-parse','HEAD']).strip()==COMMIT
    info={'managed_by':'quantum-control','engine':'llama.cpp','release':TAG,'commit':COMMIT,
          'artifact':asset['name'],'artifact_sha256':expected[7:],'binary_sha256':digest(runtime/'llama-server'),
          'model':'qwen3:0.6b','model_path':str(MODEL),'model_sha256':MODEL_SHA,'created_at':int(time.time())}
    manifest.write_text(json.dumps(info,indent=2)+'\n')
    manifest.chmod(0o644)
    archive.unlink()
    assert staging.resolve().parent==ROOT.resolve() and staging.name=='runtime-extract'
    shutil.rmtree(staging)
unit=Path('/etc/systemd/system/quantumvpn-llama.service')
body="""[Unit]
Description=Quantum Control local Qwen inference (llama.cpp)
After=network.target

[Service]
Type=simple
User=ollama
Group=ollama
WorkingDirectory=/opt/quantumvpn-ai/runtime
Environment=LD_LIBRARY_PATH=/opt/quantumvpn-ai/runtime
ExecStart=/opt/quantumvpn-ai/runtime/llama-server --host 127.0.0.1 --port 11435 --alias quantum-qwen3-0.6b --model /usr/share/ollama/.ollama/models/blobs/sha256-7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa --ctx-size 2048 --threads 1 --threads-batch 1 --parallel 1 --batch-size 128 --ubatch-size 64 --n-predict 400 --no-webui --no-slots --offline --sleep-idle-seconds 120 --reasoning off
Restart=on-failure
RestartSec=10
Nice=10
CPUQuota=80%
MemoryMax=1400M
TasksMax=48
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost
UMask=0077

[Install]
WantedBy=multi-user.target
"""
if unit.exists():assert 'Quantum Control local Qwen inference (llama.cpp)' in unit.read_text()
unit.write_text(body)
unit.chmod(0o644)
run(['systemctl','daemon-reload'])
run(['systemctl','enable','--now','quantumvpn-llama'])
deadline=time.monotonic()+60
while time.monotonic()<deadline:
    try:
        health=fetch_json('http://127.0.0.1:11435/health')
        if health.get('status')=='ok':break
    except Exception:pass
    time.sleep(1)
else:raise RuntimeError('local model did not become healthy; previous Ollama retained')
print(json.dumps({'stage':'ready','health':health,'manifest':json.loads(manifest.read_text()),'service':run(['systemctl','is-active','quantumvpn-llama']).strip()}),flush=True)
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    secret=os.environ.get('QVPN_VDS_PASSWORD')
    if not secret:raise SystemExit('QVPN_VDS_PASSWORD required')
    client=paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=secret,allow_agent=False,look_for_keys=False,timeout=15,auth_timeout=20)
        stdin,stdout,stderr=client.exec_command('python3 -',timeout=600)
        stdin.write('APPLY='+repr(args.apply)+'\n'+REMOTE)
        stdin.channel.shutdown_write()
        for line in stdout:print(line.strip(),flush=True)
        errors=stderr.read().decode()
        if stdout.channel.recv_exit_status():raise RuntimeError('Runtime install failed: '+errors[-1600:])
    finally:client.close()

if __name__=='__main__':main()
