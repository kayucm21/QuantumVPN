from pathlib import Path
import os
import sys
import time
import paramiko

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

password = os.environ.get("QVPN_VDS_PASSWORD")
if not password:
    raise SystemExit("QVPN_VDS_PASSWORD is required")

root = Path(__file__).resolve().parents[1]
version = "5.10.4"
remote_root = "/var/www/quantumvpn/downloads/5.10.4"

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(
    "150.241.96.191",
    username="root",
    password=password,
    timeout=60,
    banner_timeout=90,
    auth_timeout=60,
    look_for_keys=False,
    allow_agent=False,
)
transport = client.get_transport()
if transport:
    transport.set_keepalive(15)

artifact_dir = root / "artifacts" / version
files = {
    artifact_dir / f"QuantumVPN-{version}-operator-debug-arm64-v8a.apk": f"/tmp/QuantumVPN-{version}-operator-debug-arm64-v8a.apk",
    artifact_dir / f"QuantumVPN-{version}-operator-debug-armeabi-v7a.apk": f"/tmp/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk",
    artifact_dir / f"QuantumVPN-{version}-operator-debug-arm64-v8a.apk.sha256": f"/tmp/QuantumVPN-{version}-operator-debug-arm64-v8a.apk.sha256",
    artifact_dir / f"QuantumVPN-{version}-operator-debug-armeabi-v7a.apk.sha256": f"/tmp/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk.sha256",
    artifact_dir / "release-metadata.json": "/tmp/release-metadata.json",
    artifact_dir / "build-info.txt": "/tmp/build-info.txt",
    artifact_dir / "RELEASE_NOTES.md": "/tmp/RELEASE_NOTES.md",
    root / "tools" / "quantumvpn_operator_panel.py": "/tmp/quantumvpn_operator_panel.py",
}

with client.open_sftp() as sftp:
    for local, remote in files.items():
        if not local.is_file():
            raise SystemExit(f"missing artifact: {local}")
        print(f"upload {local.name}", flush=True)
        sftp.put(str(local), remote)

remote_python = r'''import json, sqlite3, time
version = "5.10.4"
code = "129"
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
note = "QuantumVPN 5.10.4: главный экран открывается сразу, нижняя навигация исправлена, уведомление доступно без расписания."
values = {
    "app_version": version,
    "app_version_code": code,
    "min_version_code": "0",
    "app_changelog": note,
    "update_notifications_enabled": "1",
    "release_schedule_enabled": "0",
    "release_publish_at": "0",
    "scheduled_app_version": "",
    "scheduled_app_version_code": "0",
    "scheduled_min_version_code": "0",
    "scheduled_app_changelog": "",
    "announce": "Доступно обновление QuantumVPN 5.10.4. Откройте уведомление, чтобы установить исправленную версию.",
    "announce_en": "QuantumVPN 5.10.4 is available. Open the notification to install the fixed version.",
    "announce_until": "0",
    "force_update_message": "Доступно обновление QuantumVPN 5.10.4.",
}
for key, value in values.items():
    db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))
db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "release_promoted", "operator", "", json.dumps({"version": version, "version_code": int(code), "scheduled": False}, ensure_ascii=False)))
db.commit()
db.close()
print("release_promoted_immediately", flush=True)
'''

commands = [
    f"install -d -m 755 {remote_root}",
    "install -m 644 /tmp/QuantumVPN-5.10.4-operator-debug-arm64-v8a.apk /var/www/quantumvpn/downloads/5.10.4/QuantumVPN-5.10.4-operator-debug-arm64-v8a.apk",
    "install -m 644 /tmp/QuantumVPN-5.10.4-operator-debug-armeabi-v7a.apk /var/www/quantumvpn/downloads/5.10.4/QuantumVPN-5.10.4-operator-debug-armeabi-v7a.apk",
    "install -m 644 /tmp/QuantumVPN-5.10.4-operator-debug-arm64-v8a.apk.sha256 /var/www/quantumvpn/downloads/5.10.4/QuantumVPN-5.10.4-operator-debug-arm64-v8a.apk.sha256",
    "install -m 644 /tmp/QuantumVPN-5.10.4-operator-debug-armeabi-v7a.apk.sha256 /var/www/quantumvpn/downloads/5.10.4/QuantumVPN-5.10.4-operator-debug-armeabi-v7a.apk.sha256",
    "install -m 644 /tmp/release-metadata.json /var/www/quantumvpn/downloads/5.10.4/release-metadata.json",
    "install -m 644 /tmp/build-info.txt /var/www/quantumvpn/downloads/5.10.4/build-info.txt",
    "install -m 644 /tmp/RELEASE_NOTES.md /var/www/quantumvpn/downloads/5.10.4/RELEASE_NOTES.md",
    "chmod -R a+rX /var/www/quantumvpn/downloads/5.10.4",
    "test -f /opt/quantumvpn-operator/app.py && cp -p /opt/quantumvpn-operator/app.py /opt/quantumvpn-operator/app.py.before-5.10.4 || true",
    "install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py",
    "python3 -m py_compile /opt/quantumvpn-operator/app.py",
    "systemctl restart quantumvpn-operator",
    "systemctl is-active --quiet quantumvpn-operator",
]

for command in commands:
    _, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code_exit = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.strip(), flush=True)
    if err.strip():
        print(f"stderr: {err.strip()[-2000:]}", flush=True)
    if code_exit != 0:
        raise SystemExit(f"remote command failed ({code_exit}): {command}")

encoded = remote_python.encode("utf-8").hex()
_, stdout, stderr = client.exec_command(f"echo {encoded} | xxd -r -p | python3", timeout=120)
print(stdout.read().decode("utf-8", "replace"), flush=True)
err = stderr.read().decode("utf-8", "replace")
code_exit = stdout.channel.recv_exit_status()
if err.strip():
    print(f"stderr: {err.strip()[-2000:]}", flush=True)
if code_exit != 0:
    raise SystemExit("release settings update failed")

checks = [
    "curl -sk https://127.0.0.1:8443/api/client/update?abi=arm64-v8a&current_version_code=128",
    "curl -sk https://127.0.0.1:8443/api/client/update?abi=armeabi-v7a&current_version_code=128",
    "curl -sk https://127.0.0.1:8443/api/client/policy?version_code=128",
]
for command in checks:
    _, stdout, stderr = client.exec_command(command, timeout=60)
    print(stdout.read().decode("utf-8", "replace"), flush=True)
    err = stderr.read().decode("utf-8", "replace")
    if err.strip():
        print(f"verify stderr: {err.strip()[-2000:]}", flush=True)

client.close()
print("DEPLOYED 5.10.4 immediate notification, no schedule", flush=True)


