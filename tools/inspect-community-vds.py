"""Pinned, read-only release/panel inventory; never prints credentials or players."""
import json
import os

REMOTE = r'''
import hashlib,json,sqlite3,subprocess,sys
from pathlib import Path
from contextlib import closing
root=Path('/opt/quantumvpn-operator')
names=('app.py','quantumvpn_aurora.py','quantumvpn_control_quality.py','quantumvpn_resources.py','quantumvpn_durak.py','quantumvpn_community.py','quantumvpn_control_next.py','assets/quantumvpn-world.svg')
out={'python':sys.version.split()[0],'sources':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() if (root/name).is_file() else None for name in names}}
with closing(sqlite3.connect('file:/var/lib/quantumvpn-operator/operator.db?mode=ro',uri=True)) as db:
    settings=dict(db.execute('select key,value from settings'))
    out['release']={k:settings.get(k) for k in ('app_version','app_version_code','release_schedule_enabled','scheduled_app_version','release_publish_at')}
    out['card_states']=dict(db.execute('select state,count(*) from card_tables group by state'))
    out['integrity']=db.execute('pragma quick_check').fetchone()[0]
    out['admin_count']=db.execute('select count(*) from admin_users').fetchone()[0]
    out['wallet_count']=db.execute('select count(*) from card_wallets').fetchone()[0]
for service in ('quantumvpn-operator','rospanel','nginx','quantumvpn-reserve-trojan'):
    p=subprocess.run(['systemctl','is-active',service],capture_output=True,text=True,timeout=5)
    out[service]=p.stdout.strip()
try:
    if (root/'deps').is_dir():sys.path.insert(0,str(root/'deps'))
    import webauthn
    out['webauthn_available']=True
except ImportError:out['webauthn_available']=False
out['dependency_directory']=(root/'deps').is_dir()
print(json.dumps(out))
'''


def main():
    import paramiko
    password=os.environ.get('QVPN_VDS_PASSWORD')
    if not password:raise SystemExit('QVPN_VDS_PASSWORD environment required')
    client=paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=password,allow_agent=False,look_for_keys=False,timeout=20,auth_timeout=20)
        stdin,stdout,stderr=client.exec_command('python3 -',timeout=45)
        stdin.write(REMOTE);stdin.channel.shutdown_write()
        raw=stdout.read().decode();stderr.read()
        if stdout.channel.recv_exit_status():raise RuntimeError('Read-only inventory failed; remote details suppressed')
        print(json.dumps(json.loads(raw),ensure_ascii=False))
    finally:client.close()


if __name__=='__main__':main()
