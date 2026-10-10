"""Verify and privately stage local APKs, then optionally schedule or promote.

No release is public by default. --schedule-at requires an explicit Moscow
whole-hour ISO-8601 timestamp and keeps the current app version unchanged. SSH
trust is pinned in known_hosts; credentials are read only from the process env.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ABIS = ("arm64-v8a", "armeabi-v7a")
PACKAGE = "com.quantumvpn.debug"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
MOSCOW = timezone(timedelta(hours=3))


def require(ok, label):
    if not ok:
        raise ValueError(label)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parse_schedule(value, *, now=None):
    """An explicit future whole hour at UTC+03:00; never infer a date/timezone."""
    require(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):00:00\+03:00", value)),
            "--schedule-at must be YYYY-MM-DDTHH:00:00+03:00 (Moscow)")
    instant = datetime.fromisoformat(value)
    require(instant.utcoffset() == MOSCOW.utcoffset(None), "Moscow timezone required")
    stamp = int(instant.timestamp())
    current = int(time.time()) if now is None else int(now)
    require(stamp >= current + 300, "Publication must be at least five minutes in the future")
    return stamp


def properties(path):
    """Read Gradle Java properties without treating escaped SDK paths literally.

    Java escaping is not Python ``unicode_escape``: existing Unicode must stay
    intact, unknown escapes drop only the slash, and Windows backslashes must
    be escaped. Support the usual separators, comments and continued lines.
    """
    def decode(value):
        result, position = [], 0
        escapes = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}
        while position < len(value):
            char = value[position]
            position += 1
            if char != "\\":
                result.append(char)
                continue
            if position == len(value):
                # A final continuation marker at EOF has no following line.
                break
            escaped = value[position]
            position += 1
            if escaped == "u":
                digits = value[position:position + 4]
                require(bool(re.fullmatch(r"[0-9a-fA-F]{4}", digits)),
                        "Malformed Java properties Unicode escape")
                result.append(chr(int(digits, 16)))
                position += 4
            else:
                result.append(escapes.get(escaped, escaped))
        return "".join(result)

    logical_lines, pending = [], None
    for raw in re.split(r"\r\n|\n|\r", Path(path).read_text(encoding="utf-8")):
        line = raw.lstrip(" \t\f")
        if pending is None and (not line or line.startswith(("#", "!"))):
            continue
        line = (pending or "") + line
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2:
            pending = line[:-1]
        else:
            logical_lines.append(line)
            pending = None
    if pending is not None:
        logical_lines.append(pending)

    result = {}
    for line in logical_lines:
        end, escaped = 0, False
        while end < len(line):
            char = line[end]
            if not escaped and char in "=: \t\f":
                break
            escaped = not escaped if char == "\\" else False
            end += 1
        start = end
        if start < len(line) and line[start] in " \t\f":
            while start < len(line) and line[start] in " \t\f":
                start += 1
        if start < len(line) and line[start] in "=:":
            start += 1
        while start < len(line) and line[start] in " \t\f":
            start += 1
        result[decode(line[:end])] = decode(line[start:])
    return result


def verify_apk(path, artifact, metadata, tool_dir, runner=subprocess.check_output):
    """Recheck APK identity/signature instead of trusting editable JSON alone."""
    badging = runner([str(tool_dir / "aapt2.exe"), "dump", "badging", str(path)],
                     text=True, encoding="utf-8")
    package = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging)
    require(package is not None and package.groups() ==
            (PACKAGE, str(metadata["version_code"]), metadata["version_name"]),
            "APK package/version mismatch")
    certs = runner([str(tool_dir / "apksigner.bat"), "verify", "--print-certs", str(path)],
                   text=True, encoding="utf-8")
    signers = re.findall(r"certificate SHA-256 digest: ([0-9a-fA-F]{64})", certs)
    require(len(signers) == 1 and signers[0].lower() == metadata["signer_sha256"],
            "APK signer mismatch")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        native = {name.split("/")[1] for name in names
                  if name.startswith("lib/") and name.endswith(".so")}
        require(native == {artifact["abi"]}, "APK ABI mismatch")
        require(f"lib/{artifact['abi']}/libbox.so" in names, "APK core library missing")


def verified_local_release(version, expected_signer, *, root=ROOT, checker=verify_apk,
                           expected_publish_at=None):
    require(bool(VERSION.fullmatch(version)), "Invalid version")
    require(bool(SHA256.fullmatch(expected_signer)), "Invalid expected signer SHA-256")
    folder = root / "artifacts" / version
    require(folder.is_dir() and not folder.is_symlink(), "Release folder missing or symlinked")
    metadata = json.loads((folder / "release-metadata.json").read_text(encoding="utf-8"))
    require(metadata.get("schema") == 2, "Updater metadata schema must be 2")
    require(metadata.get("version_name") == version, "Metadata version mismatch")
    require(type(metadata.get("version_code")) is int and 0 < metadata["version_code"] < 2147483647,
            "Invalid Android versionCode")
    require(metadata.get("application_id") == PACKAGE, "Metadata package mismatch")
    require(metadata.get("signer_sha256") == expected_signer, "Metadata signer mismatch")
    artifacts = metadata.get("artifacts", [])
    require(isinstance(artifacts, list) and len(artifacts) == 2 and
            {a.get("abi") for a in artifacts} == set(ABIS), "Both distinct ABI APKs are required")
    tools = (Path(properties(root / "local.properties")["sdk.dir"]) / "build-tools" /
             properties(root / "core.properties")["ANDROID_BUILD_TOOLS"])
    names = ["release-metadata.json", "build-info.json"]
    for artifact in artifacts:
        name = f"QuantumVPN-{version}-operator-debug-{artifact['abi']}.apk"
        require(artifact.get("apk_file") == name, "Unexpected APK file name")
        path = folder / name
        require(path.is_file() and not path.is_symlink(), "APK missing or symlinked")
        require(type(artifact.get("apk_size")) is int and artifact["apk_size"] > 0 and
                path.stat().st_size == artifact["apk_size"], "APK size mismatch")
        require(bool(SHA256.fullmatch(artifact.get("apk_sha256", ""))) and
                digest(path) == artifact["apk_sha256"], "APK SHA-256 mismatch")
        checksum = folder / (name + ".sha256")
        require(checksum.is_file() and not checksum.is_symlink(), "APK checksum asset missing")
        require(checksum.read_text(encoding="ascii").strip() ==
                artifact["apk_sha256"] + "  " + name, "Checksum asset mismatch")
        checker(path, artifact, metadata, tools)
        names.extend([name, name + ".sha256"])
    build = json.loads((folder / "build-info.json").read_text(encoding="utf-8"))
    require(build.get("version_name") == version and build.get("version_code") == metadata["version_code"]
            and build.get("artifacts") == artifacts and build.get("local_build") is True,
            "Build metadata mismatch")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", build.get("git_commit", ""))), "Build commit missing")
    if expected_publish_at is not None:
        require(type(expected_publish_at) is int and expected_publish_at > 0,
                "Invalid verified publication epoch")
        require(type(build.get("publish_at_epoch")) is int and
                build["publish_at_epoch"] == expected_publish_at,
                "Publication time differs from verified build schedule")
    for name in names:
        require((folder / name).is_file() and not (folder / name).is_symlink(), "Artifact symlink rejected")
    return folder, metadata, {name: digest(folder / name) for name in names}


# Kept self-contained for remote execution and local SQLite/filesystem tests.
REMOTE_SOURCE = r'''
import hashlib, json, os, shutil, sqlite3, stat, subprocess, sys, time, uuid
from contextlib import closing
from pathlib import Path

def require(ok, label):
    if not ok: raise ValueError(label)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def runtime_environment():
    result=subprocess.run(['systemctl','show','--property=MainPID','--value','quantumvpn-operator'],
                          capture_output=True, timeout=15, check=True)
    pid=result.stdout.strip().decode()
    require(pid.isdigit() and int(pid)>0, 'Operator service not running')
    values={}
    for item in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
        if b'=' in item:
            key,value=item.split(b'=',1)
            if key.startswith(b'QV_'): values[key.decode()]=value.decode()
    return values

def paths(config):
    env=runtime_environment()
    data=Path(env.get('QV_DATA_DIR','/var/lib/quantumvpn-operator'))
    downloads=Path(env.get('QV_DOWNLOAD_ROOT','/var/www/quantumvpn/downloads'))
    require(data.is_absolute() and data.is_dir() and not data.is_symlink(), 'Unsafe data root')
    require(downloads.is_absolute() and downloads.is_dir() and not downloads.is_symlink(), 'Unsafe download root')
    database=data/'operator.db'
    require(database.is_file() and not database.is_symlink(), 'Operator database missing or symlinked')
    return data, downloads, database, env

def current_settings(database):
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=30)) as db:
        require(db.execute('pragma quick_check').fetchone()[0]=='ok','SQLite integrity failure')
        return dict(db.execute('select key,value from settings'))

def check_baseline(config, settings):
    require(settings.get('app_version')==config['expected_version'] and
            int(settings.get('app_version_code','0'))==config['expected_code'], 'Production version CAS failed')
    require(config['metadata']['version_code']>config['expected_code'], 'Release versionCode must strictly increase')
    if settings.get('release_schedule_enabled')=='1':
        require(settings.get('scheduled_app_version')==config['version'] and
                int(settings.get('scheduled_app_version_code','0'))==config['metadata']['version_code'] and
                settings.get('scheduled_release_metadata_sha256')==config['files']['release-metadata.json'] and
                int(settings.get('release_publish_at','0'))==config['publish_at'], 'Another release is scheduled')
    if config['publish_at']:
        require(config['publish_at']>=int(time.time())+300,'Schedule is no longer safely in the future')

def preflight(config):
    require(os.geteuid()==0,'Root required')
    data,downloads,database,env=paths(config)
    settings=current_settings(database)
    check_baseline(config,settings)
    current=downloads/config['expected_version']/'release-metadata.json'
    require(current.is_file() and not current.is_symlink(),'Current release signer metadata missing')
    previous=json.loads(current.read_text())
    require(previous.get('application_id')==config['metadata']['application_id'] and
            previous.get('version_name')==config['expected_version'] and
            previous.get('version_code')==config['expected_code'] and
            previous.get('signer_sha256')==config['metadata']['signer_sha256'], 'Production signer/package mismatch')
    if config['publish_at']:
        # The new scheduler must verify CAS and artifact hashes at publication.
        source=Path('/opt/quantumvpn-operator/app.py').read_text()
        require('scheduled_release_metadata_sha256' in source and
                'scheduled_expected_app_version_code' in source, 'Deploy guarded scheduler before scheduling APK')
    return data,downloads,database,env

def prepare(config):
    data,downloads,database,env=preflight(config)
    staging=data/'release-staging'
    require(not staging.is_symlink(),'Staging root symlink rejected')
    staging.mkdir(mode=0o700,exist_ok=True)
    target=staging/config['upload_id']
    require(not target.exists(),'Staging ID already exists')
    target.mkdir(mode=0o700)
    return {'staging':str(target),'production_unchanged':True}

def inspect_release(config):
    data,downloads,database,env=preflight(config)
    return {'verified_preflight':True,'production_version':config['expected_version'],
            'production_version_code':config['expected_code'],'new_version':config['version'],
            'new_version_code':config['metadata']['version_code'],'mode':config['mode'],
            'publish_at':config['publish_at'],'production_unchanged':True,'remote_mutations':False}

def verify_files(folder,config):
    require(folder.is_dir() and not folder.is_symlink(),'Staged release missing')
    require({p.name for p in folder.iterdir()}==set(config['files']), 'Unexpected staged artifact')
    for name,expected in config['files'].items():
        path=folder/name
        require(path.is_file() and not path.is_symlink() and digest(path)==expected,'Artifact checksum mismatch: '+name)
    require(json.loads((folder/'release-metadata.json').read_text())==config['metadata'],'Uploaded metadata mismatch')

def backup_database(database,data,version):
    folder=data/'release-backups'
    require(not folder.is_symlink(),'Backup folder symlink rejected')
    folder.mkdir(mode=0o700,exist_ok=True)
    os.chmod(folder,0o700)
    target=folder/('operator-before-'+version+'-'+uuid.uuid4().hex+'.db')
    descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=30)) as source:
        with closing(sqlite3.connect(str(target))) as destination:
            source.backup(destination)
            require(destination.execute('pragma quick_check').fetchone()[0]=='ok','Backup integrity failure')
    return str(target)

def public_copy(staged,downloads,config):
    target=downloads/config['version']
    if target.exists():
        verify_files(target,config)
        return target
    pending=downloads/('.stage-'+config['upload_id'])
    require(not pending.exists(),'Public staging ID collision')
    pending.mkdir(mode=0o700)
    try:
        for name in config['files']:
            shutil.copyfile(staged/name,pending/name)
            os.chmod(pending/name,0o644)
        verify_files(pending,config)
        os.chmod(pending,0o755)
        require(not target.exists(),'Release folder appeared concurrently')
        os.rename(pending,target)
    finally:
        if pending.exists():
            for name in config['files']:
                path=pending/name
                if path.is_file() and not path.is_symlink(): path.unlink()
            pending.rmdir()
    return target

def cleanup_private(staged,config):
    # Delete only this invocation's exact checksum-verified private upload.
    # Public release folders, database backups and prior uploads are untouched.
    try:
        verify_files(staged,config)
        for name in config['files']: (staged/name).unlink()
        staged.rmdir()
        return False
    except (OSError,ValueError):
        return True

def schedule(config,database,data):
    backup=backup_database(database,data,config['version'])
    now=int(time.time())
    with closing(sqlite3.connect(str(database),timeout=30)) as db:
        db.execute('begin immediate')
        settings=dict(db.execute('select key,value from settings'))
        check_baseline(config,settings)
        values={
            'release_schedule_enabled':'1', 'release_publish_at':str(config['publish_at']),
            'scheduled_app_version':config['version'],
            'scheduled_app_version_code':str(config['metadata']['version_code']),
            'scheduled_rollout_percent':'100', 'scheduled_app_changelog':config['notes'][:1000],
            'scheduled_min_version_code':'0', 'update_notifications_enabled':'1',
            'scheduled_expected_app_version':config['expected_version'],
            'scheduled_expected_app_version_code':str(config['expected_code']),
            'scheduled_release_metadata_sha256':config['files']['release-metadata.json'],
            'scheduled_release_backup':backup,
        }
        for key,value in values.items():
            db.execute('insert or replace into settings(key,value) values (?,?)',(key,value))
        db.execute('insert into events values (?,?,?,?,?)',
            (now,'release_scheduled','operator','',json.dumps({'version':config['version'],
             'version_code':config['metadata']['version_code'],'publish_at':config['publish_at'],
             'timezone':'Europe/Moscow','source':'verified-local-build'})))
        db.commit()
    return backup

def promote(config,database,data,env):
    # Reuse the operator's redacted, deduplicated inbox event in the same
    # transaction as the release settings and device banners.
    sys.path.insert(0,'/opt/quantumvpn-operator')
    import quantumvpn_community as community
    backup=backup_database(database,data,config['version'])
    now=int(time.time()); banner='Доступно обновление QuantumVPN '+config['version']+'. Откройте уведомление для установки.'
    with closing(sqlite3.connect(str(database),timeout=30)) as db:
        db.execute('begin immediate')
        settings=dict(db.execute('select key,value from settings'))
        check_baseline(config,settings)
        values={'app_version':config['version'],'app_version_code':str(config['metadata']['version_code']),
            'app_changelog':config['notes'][:1000],'min_version_code':'0','rollout_percent':'100',
            'release_schedule_enabled':'0','update_notifications_enabled':'1','announce':banner,
            'announce_en':'QuantumVPN '+config['version']+' is available.','announce_until':'0',
            'force_update_message':banner,'config_revision':str(int(settings.get('config_revision','1'))+1)}
        for key,value in values.items(): db.execute('insert or replace into settings(key,value) values (?,?)',(key,value))
        community.append_event(db,'release','Обновление QuantumVPN '+config['version'],
                               values['app_changelog'],'release:'+str(config['metadata']['version_code']),now=now)
        devices=db.execute("select distinct device from events where kind='policy' and ts>? and device!='' limit 5000",
                           (now-365*86400,)).fetchall()
        for (device,) in devices:
            db.execute('insert into device_flags(device,force_banner,request_diagnostic,note,updated_at) values (?,?,?,?,?) '
             'on conflict(device) do update set force_banner=excluded.force_banner,updated_at=excluded.updated_at',
             (device,banner,0,config['version']+'-release',now))
        db.execute('insert into events values (?,?,?,?,?)',(now,'release_promoted','operator','',
            json.dumps({'version':config['version'],'version_code':config['metadata']['version_code'],
                        'source':'verified-local-build'})))
        db.commit()
    try:
        os.environ.update(env); sys.path.insert(0,'/opt/quantumvpn-operator')
        import app
        with closing(sqlite3.connect(str(database))) as db:
            notice_settings=dict(db.execute('select key,value from settings'))
        app.telegram_send(notice_settings,'[Quantum Control] QuantumVPN '+config['version']+' опубликован.')
    except Exception: pass
    return backup,len(devices)

def finalize(config):
    data,downloads,database,env=preflight(config)
    staged=data/'release-staging'/config['upload_id']
    verify_files(staged,config)
    if config['mode']=='stage':
        return {'staged':config['version'],'private_path':str(staged),'verified_files':len(config['files']),
                'production_unchanged':True,'notification_signal':False}
    if config['mode']=='schedule':
        # Commit the embargo before introducing a predictable public URL.
        # On a copy failure the guarded worker defers rather than publishing a partial matrix.
        backup=schedule(config,database,data)
        public_copy(staged,downloads,config)
        require(current_settings(database).get('app_version')==config['expected_version'],
                'Production changed while scheduling')
        return {'scheduled':config['version'],'version_code':config['metadata']['version_code'],
                'publish_at':config['publish_at'],'timezone':'Europe/Moscow','backup':backup,
                'production_unchanged':True,'notification_signal':False,'notifications_enabled':True,
                'private_staging_retained':cleanup_private(staged,config)}
    public_copy(staged,downloads,config)
    backup,count=promote(config,database,data,env)
    return {'promoted':config['version'],'version_code':config['metadata']['version_code'],
            'notification_signal':True,'known_device_banners':count,'backup':backup,
            'private_staging_retained':cleanup_private(staged,config)}
'''


def remote(client, action, config):
    script = "import json\nCONFIG=json.loads(" + repr(json.dumps(config)) + ")\n"
    script += REMOTE_SOURCE + "\nprint(json.dumps(" + action + "(CONFIG)))\n"
    stdin, stdout, stderr = client.exec_command("python3 -", timeout=180)
    stdin.write(script)
    stdin.channel.shutdown_write()
    output, error = stdout.read().decode(), stderr.read().decode()
    if stdout.channel.recv_exit_status():
        raise RuntimeError("VDS verification failed: " + error[-1500:])
    lines = output.strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def main():
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    parser.add_argument("--expected-current-version", required=True)
    parser.add_argument("--expected-current-code", required=True, type=int)
    parser.add_argument("--expected-signer-sha256", required=True)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--promote", action="store_true", help="Explicit immediate publication")
    actions.add_argument("--schedule-at", help="YYYY-MM-DDTHH:00:00+03:00 (explicit Moscow date/hour)")
    parser.add_argument("--notes", default="QuantumVPN 2.0: новый интерфейс, удобные кнопки, оформление и доступность.")
    parser.add_argument("--check-only", action="store_true", help="Read-only remote preflight; do not upload or change settings")
    args = parser.parse_args()
    require(bool(VERSION.fullmatch(args.expected_current_version)), "Invalid expected current version")
    require(0 < args.expected_current_code < 2147483647, "Invalid expected current code")
    publish_at = parse_schedule(args.schedule_at) if args.schedule_at else 0
    folder, metadata, files = verified_local_release(
        args.version, args.expected_signer_sha256,
        expected_publish_at=publish_at if args.schedule_at else None)
    require(metadata["version_code"] > args.expected_current_code, "Release versionCode must strictly increase")
    require(args.version != args.expected_current_version, "Release versionName must change")
    require(args.known_hosts.is_file(), "Pinned known_hosts file required")
    password = os.environ.get("QVPN_VDS_PASSWORD")
    require(bool(password), "QVPN_VDS_PASSWORD is required")
    config = {"version": args.version, "metadata": metadata, "files": files,
              "expected_version": args.expected_current_version, "expected_code": args.expected_current_code,
              "mode": "schedule" if publish_at else ("promote" if args.promote else "stage"),
              "publish_at": publish_at, "notes": args.notes, "upload_id": uuid.uuid4().hex}
    client = paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(args.host, port=args.port, username="root", password=password, timeout=20,
                       auth_timeout=20, banner_timeout=20, allow_agent=False, look_for_keys=False)
        if args.check_only:
            print(json.dumps(remote(client, "inspect_release", config), ensure_ascii=False))
            return
        prepared = remote(client, "prepare", config)
        stage = prepared["staging"]
        with client.open_sftp() as sftp:
            for name in files:
                target = stage + "/" + name
                sftp.put(str(folder / name), target)
                sftp.chmod(target, 0o600)
        print(json.dumps(remote(client, "finalize", config), ensure_ascii=False))
    finally:
        client.close()


if __name__ == "__main__":
    main()
