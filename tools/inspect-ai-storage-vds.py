"""Read-only, pinned-host inventory for local inference and disk maintenance."""
import json
import os
import paramiko

REMOTE = r'''
import hashlib,json,os,sqlite3,subprocess,time,urllib.request
from pathlib import Path
out={'time':int(time.time()),'cpu_count':os.cpu_count()}
out['memory']={x.split(':')[0]:int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith(('MemTotal:','MemAvailable:'))}
out['disk']=subprocess.run(['df','-B1','/'],capture_output=True,text=True,timeout=10).stdout
out['architecture']=subprocess.run(['uname','-m'],capture_output=True,text=True,timeout=5).stdout.strip()
out['tools']={x:bool(subprocess.run(['sh','-c','command -v '+x],capture_output=True,timeout=5).stdout.strip()) for x in ('cmake','g++','git','make','curl')}
out['services']={x:subprocess.run(['systemctl','is-active',x],capture_output=True,text=True,timeout=5).stdout.strip() for x in ('quantumvpn-operator','rospanel','ollama','quantumvpn-llama')}
pid=subprocess.run(['systemctl','show','--property=MainPID','--value','ollama'],capture_output=True,text=True,timeout=5).stdout.strip()
if pid.isdigit() and int(pid)>0:
    out['ollama_rss_kib']=next((int(x.split()[1]) for x in (Path('/proc')/pid/'status').read_text().splitlines() if x.startswith('VmRSS:')),None)
    out['ollama_model_dir']=None
    for entry in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
        if entry.startswith(b'OLLAMA_MODELS='):out['ollama_model_dir']=entry.split(b'=',1)[1].decode()
for endpoint in ('tags','ps'):
    try:
        with urllib.request.urlopen('http://127.0.0.1:11434/api/'+endpoint,timeout=5) as response:data=json.loads(response.read(65536))
        out['ollama_'+endpoint]=[{k:r.get(k) for k in ('name','model','size','expires_at')} for r in data.get('models',[]) if isinstance(r,dict)]
    except Exception as error:out['ollama_'+endpoint]={'error':type(error).__name__}
out['model_manifests']=[]
for root in (Path('/usr/share/ollama/.ollama/models'),Path('/root/.ollama/models')):
    manifest=root/'manifests/registry.ollama.ai/library/qwen3/0.6b'
    if manifest.is_file():
        body=json.loads(manifest.read_bytes())
        layers=[]
        for layer in body.get('layers',[]):
            if layer.get('mediaType')=='application/vnd.ollama.image.model':
                file=root/'blobs'/str(layer.get('digest','')).replace(':','-')
                layers.append({'path':str(file),'exists':file.is_file(),'size':file.stat().st_size if file.is_file() else None,'magic':file.open('rb').read(4).decode('ascii','replace') if file.is_file() else None,'digest':layer.get('digest')})
        out['model_manifests'].append({'path':str(manifest),'model_layers':layers})
paths=['/var/lib/quantumvpn-operator','/var/lib/rospanel','/opt','/var/cache','/root','/tmp','/var/log','/var/lib','/usr/local','/srv']
out['directory_sizes']=[]
for path in paths:
    if Path(path).is_dir():
        result=subprocess.run(['du','-x','-B1','-d','2',path],capture_output=True,text=True,timeout=40)
        rows=[]
        for line in result.stdout.splitlines():
            size,_,name=line.partition('\t')
            if size.isdigit():rows.append({'bytes':int(size),'path':name})
        out['directory_sizes'].extend(sorted(rows,key=lambda x:x['bytes'],reverse=True)[:14])
out['temp_candidates']=[]
for folder in (Path('/tmp'),Path('/var/lib/quantumvpn-operator/backups')):
    for item in folder.iterdir():
        if item.is_file() and not item.is_symlink():
            st=item.stat()
            if st.st_size>1024*1024 or item.name.startswith(('.operator-','.rospanel-')):
                out['temp_candidates'].append({'path':str(item),'size':st.st_size,'age_seconds':int(time.time()-st.st_mtime)})
out['temp_candidates']=sorted(out['temp_candidates'],key=lambda x:x['size'],reverse=True)[:30]
db=sqlite3.connect('file:/var/lib/quantumvpn-operator/operator.db?mode=ro',uri=True)
settings=dict(db.execute('select key,value from settings'))
out['settings']={k:settings.get(k) for k in ('ai_model','ai_advisor_enabled','ai_interval_seconds','ai_alerts_enabled','telegram_backups_enabled','latency_targets','node_drain','node_quarantine','load_balancer_enabled','load_balancer_last_target','app_version','release_schedule_enabled')}
out['node_registry']=settings.get('node_map_config')
out['latency_probe_targets']=settings.get('latency_probe_targets')
out['inbound_metadata']=[]
for file in (Path('/var/lib/rospanel/xray/config.json'),Path('/var/lib/quantumvpn-operator/reserve-trojan.json')):
    if file.is_file():
        content=json.loads(file.read_bytes())
        out['inbound_metadata'].extend({'source':str(file),'protocol':item.get('protocol') or item.get('type'),'port':item.get('port') or item.get('listen_port'),'tag':item.get('tag')} for item in content.get('inbounds',[]) if isinstance(item,dict))
out['reserve_service']=subprocess.run(['systemctl','is-active','quantumvpn-reserve-trojan'],capture_output=True,text=True,timeout=5).stdout.strip()
out['apk_duplicate_metadata']=[]
for abi in ('arm64-v8a','armeabi-v7a'):
    temporary=Path('/tmp')/('QuantumVPN-5.10.12-debug-'+abi+'.apk')
    permanent=Path('/var/www/quantumvpn/downloads/5.10.12')/('QuantumVPN-5.10.12-operator-debug-'+abi+'.apk')
    out['apk_duplicate_metadata'].append({'temporary':str(temporary),'permanent':str(permanent),'permanent_exists':permanent.is_file(),'same_size':temporary.is_file() and permanent.is_file() and temporary.stat().st_size==permanent.stat().st_size})
out['db_quick_check']=db.execute('pragma quick_check').fetchone()[0]
out['source_hashes']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/opt/quantumvpn-operator').glob('*.py') if p.is_file()}
db.close()
print(json.dumps(out))
'''

def main():
    secret = os.environ.get('QVPN_VDS_PASSWORD')
    if not secret:
        raise SystemExit('QVPN_VDS_PASSWORD required')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=secret,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=300)
        stdin.write(REMOTE)
        stdin.channel.shutdown_write()
        raw = stdout.read().decode()
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise RuntimeError('Read-only AI/storage inventory failed')
        print(json.dumps(json.loads(raw), ensure_ascii=False))
    finally:
        client.close()

if __name__ == '__main__':
    main()
