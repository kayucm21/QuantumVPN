"""Atomic operator-module deployment with source/SQLite backup and service rollback.

Never uploads keys, changes VPN configuration, or deletes old releases/client data.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import uuid

import paramiko

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OLD = "59179c01e73ae74f75fae6a1d39dc5c45ce7740364d76b8c134cb5306ce6a037"


def run(client, script):
    stdin, out, err = client.exec_command("python3 -", timeout=60)
    stdin.write(script)
    stdin.channel.shutdown_write()
    text, errors = out.read().decode(), err.read().decode()
    if out.channel.recv_exit_status():
        raise RuntimeError("Panel operation failed: " + errors[-1200:])
    print(text.strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required")
    files = {"app.py": ROOT / "tools/quantumvpn_operator_panel.py", "quantumvpn_resources.py": ROOT / "tools/quantumvpn_resources.py"}
    digests = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.host, username="root", password=password, timeout=15, allow_agent=False, look_for_keys=False)
    stage = ".resources-upload-" + uuid.uuid4().hex
    try:
        run(client, f"""import hashlib,subprocess
from pathlib import Path
p=Path('/opt/quantumvpn-operator/app.py')
assert hashlib.sha256(p.read_bytes()).hexdigest() in ({EXPECTED_OLD!r},{digests['app.py']!r}), 'Live source has unexpected edits; stop'
subprocess.run(['python3','-c','import PIL,cryptography'],check=True)
print('Runtime dependencies and live source verified')
""")
        with client.open_sftp() as sftp:
            for name, path in files.items():
                sftp.put(str(path), "/opt/quantumvpn-operator/" + stage + "-" + name)
        run(client, f"""import hashlib,json,os,py_compile,shlex,shutil,sqlite3,subprocess,sys,time
from pathlib import Path
root=Path('/opt/quantumvpn-operator'); expected=json.loads({json.dumps(digests)!r}); prefix={stage!r}
for name,digest in expected.items():
    staged=root/(prefix+'-'+name)
    assert hashlib.sha256(staged.read_bytes()).hexdigest()==digest, 'Staged hash mismatch'
    py_compile.compile(str(staged),doraise=True)
backup=Path('/var/lib/quantumvpn-operator/source-backups')/('resources-'+str(time.time_ns()))
backup.mkdir(parents=True,mode=0o700)
for name in expected:
    if (root/name).exists(): shutil.copy2(root/name,backup/name)
with sqlite3.connect('/var/lib/quantumvpn-operator/operator.db') as live, sqlite3.connect(str(backup/'operator.db')) as saved:
    live.backup(saved)
os.chmod(backup/'operator.db',0o600)
for name in reversed(list(expected)):
    os.replace(root/(prefix+'-'+name),root/name); os.chmod(root/name,0o600)
try:
    subprocess.run(['systemctl','restart','quantumvpn-operator'],check=True)
    for attempt in range(10):
        if subprocess.run(['systemctl','is-active','--quiet','quantumvpn-operator']).returncode==0: break
        time.sleep(0.5)
    subprocess.run(['systemctl','is-active','--quiet','quantumvpn-operator'],check=True)
    for line in Path('/etc/quantumvpn-operator.env').read_text().splitlines():
        if '=' not in line or line.lstrip().startswith('#'): continue
        key,value=line.split('=',1); os.environ[key.strip()]=' '.join(shlex.split(value))
    sys.path.insert(0,str(root)); import app
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    import base64
    key=app.routing_signing_key()
    assert base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode().rstrip('=')=='lNDNapSDNgBvv0cKnsdMvQMTIIUPx_6fKnf2QoY0v7g', 'Pinned key mismatch'
    db=app.conn(); app.resources.schema(db)
    if not db.execute('select count(*) from resource_bundles').fetchone()[0]:
        app.resources.action(db,app.ROOT,{{'action':['save'],'accent':['#58F4CE'],'welcome':['Больше свободы. Ближе к людям.'],'note':['Начальная проверенная ревизия']}},{{}},'release-deploy')
        app.resources.action(db,app.ROOT,{{'action':['production'],'revision':['1']}},{{}},'release-deploy')
        db.commit()
    envelope=app.resources.client_manifest(db,'release-probe',501101099,lambda:key)
    data=app.resources.canonical(envelope['payload']).encode()
    key.public_key().verify(base64.urlsafe_b64decode(envelope['signature']+'=='),data)
    db.close()
    print(json.dumps({{'panel_build':app.PANEL_BUILD,'backup':str(backup),'resources_signature':'verified','sequence':envelope['payload']['sequence']}}))
except BaseException:
    # Keep SQLite data/key material; restore only our backed-up source.
    for name in expected:
        if (backup/name).exists(): shutil.copy2(backup/name,root/name)
    subprocess.run(['systemctl','restart','quantumvpn-operator'])
    raise
""")
    finally:
        client.close()


if __name__ == "__main__":
    main()
