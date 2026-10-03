"""Stage verified local APKs; --promote publishes the VDS version/notification signal.

Credentials come only from QVPN_VDS_PASSWORD. Old APKs and client keys are preserved.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
import paramiko

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def remote(client, script):
    stdin, stdout, stderr = client.exec_command("python3 -", timeout=60)
    stdin.write(script); stdin.channel.shutdown_write()
    out, err = stdout.read().decode(), stderr.read().decode()
    if stdout.channel.recv_exit_status():
        raise RuntimeError("VDS operation failed: " + err[-1000:])
    print(out.strip())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--host", required=True)
    parser.add_argument("--promote", action="store_true")
    parser.add_argument("--notes", help="Release-specific user-visible changelog (no credentials)")
    args = parser.parse_args()
    assert re.fullmatch(r"\d+\.\d+\.\d+", args.version)
    folder = ROOT / "artifacts" / args.version
    metadata = json.loads((folder / "release-metadata.json").read_text())
    assert metadata["version_name"] == args.version
    assert metadata["application_id"] == "com.quantumvpn.debug"
    assert {a["abi"] for a in metadata["artifacts"]} == {"arm64-v8a", "armeabi-v7a"}
    names = ["release-metadata.json", "build-info.json"]
    for artifact in metadata["artifacts"]:
        name = artifact["apk_file"]
        assert Path(name).name == name
        path = folder / name
        assert path.stat().st_size == artifact["apk_size"] and digest(path) == artifact["apk_sha256"]
        names.extend([name, name + ".sha256"])
    files = {name: digest(folder / name) for name in names}
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.host, username="root", password=password, timeout=20,
                   auth_timeout=20, banner_timeout=20, allow_agent=False, look_for_keys=False)
    try:
        remote_root = "/var/www/quantumvpn/downloads/" + args.version
        upload = ".upload-" + uuid.uuid4().hex
        remote(client, f"from pathlib import Path\nPath({remote_root!r}).mkdir(parents=True,exist_ok=True)\n")
        with client.open_sftp() as sftp:
            for name in names:
                sftp.put(str(folder / name), remote_root + "/" + upload + "-" + name)
        remote(client, f"""import hashlib,json,os
from pathlib import Path
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
root=Path({remote_root!r}); files=json.loads({json.dumps(files)!r})
for name,expected in files.items():
    assert digest(root/({upload!r}+'-'+name))==expected, 'Upload checksum mismatch'
    if (root/name).exists():
        assert digest(root/name)==expected, 'Refusing to replace a different published artifact'
for name in files:
    os.replace(root/({upload!r}+'-'+name),root/name); os.chmod(root/name,0o644)
print(json.dumps({{'staged':{args.version!r},'verified_files':len(files)}}))
""")
        if not args.promote:
            return
        note = args.notes or f"QuantumVPN {args.version}: Aurora 2026, мятно-синий интерфейс, общий фон и своя фотография, доступность, поиск серверов, меньше фоновой нагрузки и улучшенная загрузка обновлений."
        # Metadata and device banners become visible in one transaction.
        remote(client, f"""import json,os,shlex,sqlite3,sys,time
from pathlib import Path
for line in Path('/etc/quantumvpn-operator.env').read_text().splitlines():
    if '=' not in line or line.lstrip().startswith('#'): continue
    key,value=line.split('=',1)
    os.environ[key.strip()]=' '.join(shlex.split(value))
sys.path.insert(0,'/opt/quantumvpn-operator')
import app
db=app.conn(); s=app.settings(db); version={args.version!r}; code={metadata['version_code']}
assert not app.scheduled_release_missing_abis(version), 'Missing ABI APK'
assert int(s.get('app_version_code','0'))<=code, 'Refusing a downgrade'
if s.get('app_version')==version and int(s.get('app_version_code','0'))==code:
    print(json.dumps({{'already_promoted':version}})); sys.exit(0)
backup=Path('/var/lib/quantumvpn-operator/release-backups'); backup.mkdir(mode=0o700,exist_ok=True)
now=int(time.time()); backup_file=backup/('operator-before-'+version+'-'+str(now)+'.db')
with sqlite3.connect(str(backup_file)) as target: db.backup(target)
os.chmod(backup_file,0o600)
db.execute('begin immediate')
s=app.settings(db)
banner='Доступно обновление QuantumVPN '+version+'. Откройте уведомление для установки.'
values={{'app_version':version,'app_version_code':str(code),'app_changelog':{note!r},
 'min_version_code':'0','rollout_percent':'100','release_schedule_enabled':'0',
 'update_notifications_enabled':'1','announce':banner,'announce_en':'QuantumVPN '+version+' is available.',
 'announce_until':'0','force_update_message':'Доступно обновление QuantumVPN '+version+'.',
 'config_revision':str(int(s.get('config_revision','1'))+1)}}
for key,value in values.items(): db.execute('insert or replace into settings(key,value) values (?,?)',(key,value))
devices=db.execute("select distinct device from events where kind='policy' and ts>? and device!='' limit 5000",(now-365*86400,)).fetchall()
for (device,) in devices:
    db.execute('insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) on conflict(device) do update set force_banner=excluded.force_banner,updated_at=excluded.updated_at',(device,banner,0,version+'-release',now))
db.execute('insert into events values (?,?,?,?,?)',(now,'release_promoted','operator','',json.dumps({{'version':version,'version_code':code,'source':'verified-local-build'}})))
db.commit(); app.release_info.cache_clear()
app.telegram_send(app.settings(db),'[Quantum Control] QuantumVPN '+version+' опубликован. Охват: 100%. Уведомления включены.'); db.close()
print(json.dumps({{'promoted':version,'version_code':code,'notification_signal':True,'known_device_banners':len(devices),'backup':str(backup_file)}}))
""")
    finally:
        client.close()

if __name__ == "__main__":
    main()
