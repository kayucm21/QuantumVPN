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
version = "5.9.2"

def connect():
    for attempt in range(6):
        try:
            print(f"connect {attempt + 1}", flush=True)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect("150.241.96.191", username="root", password=password, timeout=60, banner_timeout=90, auth_timeout=60, look_for_keys=False, allow_agent=False)
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(15)
            return client
        except Exception as exc:
            print(type(exc).__name__, str(exc), flush=True)
            time.sleep(5)
    raise SystemExit("ssh failed")

client = connect()
files = {
    root / f"artifacts/{version}/QuantumVPN-{version}-operator-debug-arm64-v8a.apk": f"/tmp/QuantumVPN-{version}-operator-debug-arm64-v8a.apk",
    root / f"artifacts/{version}/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk": f"/tmp/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk",
    root / f"artifacts/{version}/QuantumVPN-{version}-operator-debug-arm64-v8a.apk.sha256": f"/tmp/QuantumVPN-{version}-operator-debug-arm64-v8a.apk.sha256",
    root / f"artifacts/{version}/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk.sha256": f"/tmp/QuantumVPN-{version}-operator-debug-armeabi-v7a.apk.sha256",
    root / f"artifacts/{version}/release-metadata.json": "/tmp/release-metadata.json",
    root / f"artifacts/{version}/build-info.txt": "/tmp/build-info.txt",
    root / f"artifacts/{version}/RELEASE_NOTES.md": "/tmp/RELEASE_NOTES.md",
    root / f"artifacts/{version}/update.html": "/tmp/update.html",
    root / "tools/quantumvpn_operator_panel.py": "/tmp/quantumvpn_operator_panel.py",
    # The reusable local script keeps the historical filename; its internal
    # version is updated alongside the APK release.
    root / "tools/deploy-operator-5.9.0.sh": f"/tmp/deploy-operator-{version}.sh",
    root / "tools/setup-nginx-downloads.sh": "/tmp/setup-nginx-downloads.sh",
}
with client.open_sftp() as sftp:
    for local, remote in files.items():
        print("upload", local.name, flush=True)
        sftp.put(str(local), remote)

command = f"chmod +x /tmp/deploy-operator-{version}.sh /tmp/setup-nginx-downloads.sh && bash /tmp/deploy-operator-{version}.sh"
_, stdout, stderr = client.exec_command(command, timeout=420)
print(stdout.read().decode("utf-8", "replace"))
error = stderr.read().decode("utf-8", "replace")
if error.strip():
    print("STDERR", error[-4000:])
code = stdout.channel.recv_exit_status()
_, verify, verify_err = client.exec_command("curl -sk https://127.0.0.1:8443/api/client/update?abi=arm64-v8a&current_version_code=0; echo", timeout=60)
print(verify.read().decode("utf-8", "replace"))
verify_error = verify_err.read().decode("utf-8", "replace")
if verify_error.strip():
    print("VERIFY_STDERR", verify_error[-2000:])
client.close()
print("DONE", code, flush=True)
raise SystemExit(code)
