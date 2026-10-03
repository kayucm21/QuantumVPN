"""Read-only deployment inventory. Never prints credentials or client records."""
import hashlib
import json
import os
import paramiko

SOURCE = r'''
import hashlib,json,sqlite3,subprocess
from pathlib import Path
from contextlib import closing
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value','quantumvpn-operator']).decode().strip()
env={}
for entry in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
    if b'=' in entry:
        key,value=entry.split(b'=',1)
        if key.startswith(b'QV_'): env[key.decode()]=value.decode()
database=Path(env.get('QV_DATA_DIR','/var/lib/quantumvpn-operator'))/'operator.db'
keys=('app_version','app_version_code','release_schedule_enabled','release_publish_at','scheduled_app_version',
      'scheduled_app_version_code','scheduled_expected_app_version','scheduled_expected_app_version_code',
      'scheduled_release_metadata_sha256','update_notifications_enabled','public_download_enabled')
with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True)) as db:
    settings=dict(db.execute('select key,value from settings'))
    public={k:settings.get(k) for k in keys}
    integrity=db.execute('pragma quick_check').fetchone()[0]
hashes={}
for name in ('app.py','quantumvpn_aurora.py','assets/quantumvpn-world.svg'):
    path=Path('/opt/quantumvpn-operator')/name
    hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
nginx=[]
for folder in ('/etc/nginx/sites-enabled','/etc/nginx/conf.d'):
    for path in Path(folder).glob('*'):
        if path.is_file():
            rows=path.read_text(errors='replace').splitlines()
            for i,row in enumerate(rows):
                if 'location' in row and 'downloads' in row:
                    nginx.append({'file':str(path),'line':i+1,'block':rows[i:i+10]})
current=Path(env.get('QV_DOWNLOAD_ROOT','/var/www/quantumvpn/downloads'))/settings.get('app_version','')/'release-metadata.json'
metadata=json.loads(current.read_text())
print(json.dumps({'settings':public,'sqlite':integrity,'source_hashes':hashes,
    'current_identity':{k:metadata.get(k) for k in ('version_name','version_code','application_id','signer_sha256')},
    'nginx_downloads':nginx,'service_active':subprocess.check_output(['systemctl','is-active','quantumvpn-operator']).decode().strip()},sort_keys=True))
'''

if __name__ == '__main__':
    client=paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=os.environ['QVPN_VDS_PASSWORD'],
                       allow_agent=False,look_for_keys=False,timeout=20,auth_timeout=20)
        stdin,out,err=client.exec_command('python3 -',timeout=35)
        stdin.write(SOURCE);stdin.channel.shutdown_write()
        result=out.read().decode();err.read()
        if out.channel.recv_exit_status(): raise RuntimeError('Read-only release inventory failed')
        print(result.strip())
    finally:
        client.close()
