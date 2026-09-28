from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import paramiko


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.10.7"
VERSION_CODE = 132
HOST = "150.241.96.191"
REMOTE_ROOT = f"/var/www/quantumvpn/downloads/{VERSION}"


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_artifacts() -> Path:
    destination = ROOT / "artifacts" / VERSION
    destination.mkdir(parents=True, exist_ok=True)
    sources = {
        "arm64-v8a": ROOT / "build" / f"quantumvpn-{VERSION}-arm64-staging.apk",
        "armeabi-v7a": ROOT / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
    }
    items: list[dict[str, object]] = []
    for abi, source in sources.items():
        if not source.is_file():
            raise SystemExit(f"missing built APK: {source}")
        target = destination / f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk"
        target.write_bytes(source.read_bytes())
        digest = checksum(target)
        (destination / f"{target.name}.sha256").write_text(f"{digest}  {target.name}\n", encoding="utf-8")
        items.append({"abi": abi, "apk_file": target.name, "apk_sha256": digest, "apk_size": target.stat().st_size})
    metadata = {
        "schema": 2,
        "version_name": VERSION,
        "version_code": VERSION_CODE,
        "application_id": "com.quantumvpn.debug",
        "signing_certificate_sha256": "4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d",
        "artifacts": items,
    }
    (destination / "release-metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "build-info.txt").write_text(
        f"version={VERSION}\nversionCode={VERSION_CODE}\nfeatures=raised-system-nav-clearance,startup-update-gate,verified-system-download,arm64-v8a,armeabi-v7a\n",
        encoding="utf-8",
    )
    (destination / "RELEASE_NOTES.md").write_text(
        f"# QuantumVPN {VERSION}\n\n"
        "- Нижняя навигация поднята над системными кнопками Android фиксированным безопасным отступом.\n"
        "- Стартовый экран остаётся видимым при проверке, загрузке и проверке новой версии APK.\n"
        "- Перед открытием системной установки автоматически проверяются SHA-256, пакет, версия и подпись APK.\n",
        encoding="utf-8",
    )
    return destination


def run_remote(client: paramiko.SSHClient, command: str) -> str:
    _, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if code:
        raise SystemExit(f"remote command failed ({code}): {err[-1000:]}")
    return out


def deploy(destination: Path) -> None:
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise SystemExit("QVPN_VDS_PASSWORD is required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username="root", password=password, timeout=60, banner_timeout=90, auth_timeout=60, look_for_keys=False, allow_agent=False)
    try:
        files = [*destination.iterdir(), ROOT / "tools" / "quantumvpn_operator_panel.py"]
        with client.open_sftp() as sftp:
            for file in files:
                remote = f"/tmp/{file.name}"
                print(f"upload {file.name}", flush=True)
                sftp.put(str(file), remote)
        for command in (
            f"install -d -m 755 {REMOTE_ROOT}",
            f"install -m 644 /tmp/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk {REMOTE_ROOT}/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk",
            f"install -m 644 /tmp/QuantumVPN-{VERSION}-operator-debug-armeabi-v7a.apk {REMOTE_ROOT}/QuantumVPN-{VERSION}-operator-debug-armeabi-v7a.apk",
            f"install -m 644 /tmp/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk.sha256 {REMOTE_ROOT}/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk.sha256",
            f"install -m 644 /tmp/QuantumVPN-{VERSION}-operator-debug-armeabi-v7a.apk.sha256 {REMOTE_ROOT}/QuantumVPN-{VERSION}-operator-debug-armeabi-v7a.apk.sha256",
            f"install -m 644 /tmp/release-metadata.json {REMOTE_ROOT}/release-metadata.json",
            f"install -m 644 /tmp/build-info.txt {REMOTE_ROOT}/build-info.txt",
            f"install -m 644 /tmp/RELEASE_NOTES.md {REMOTE_ROOT}/RELEASE_NOTES.md",
            f"chmod -R a+rX {REMOTE_ROOT}",
            "install -m 750 /tmp/quantumvpn_operator_panel.py /opt/quantumvpn-operator/app.py",
            "python3 -m py_compile /opt/quantumvpn-operator/app.py",
            "systemctl restart quantumvpn-operator",
            "systemctl is-active --quiet quantumvpn-operator",
        ):
            run_remote(client, command)
        update = f'''import json, sqlite3, time
db = sqlite3.connect("/var/lib/quantumvpn-operator/operator.db")
values = {{
    "app_version": "{VERSION}", "app_version_code": "{VERSION_CODE}", "min_version_code": "0",
    "app_changelog": "QuantumVPN {VERSION}: нижняя навигация поднята над системными кнопками, а загрузка обновления остаётся на стартовом экране до системной установки.",
    "update_notifications_enabled": "1", "release_schedule_enabled": "0", "release_publish_at": "0",
    "scheduled_app_version": "", "scheduled_app_version_code": "0", "scheduled_min_version_code": "0", "scheduled_app_changelog": "",
    "announce": "Доступно обновление QuantumVPN {VERSION}. Исправлены отступ нижних кнопок и загрузка обновления при запуске — откройте уведомление для установки.",
    "announce_en": "QuantumVPN {VERSION} is available.", "announce_until": "0",
    "force_update_message": "Доступно обновление QuantumVPN {VERSION}.",
}}
for key, value in values.items(): db.execute("insert or replace into settings(key,value) values (?,?)", (key, value))
db.execute("insert into events values (?,?,?,?,?)", (int(time.time()), "release_promoted", "operator", "", json.dumps({{"version": "{VERSION}", "version_code": {VERSION_CODE}, "scheduled": False}})))
db.commit(); db.close()
'''
        run_remote(client, f"echo {update.encode('utf-8').hex()} | xxd -r -p | python3")
        for abi in ("arm64-v8a", "armeabi-v7a"):
            print(run_remote(client, f"curl -sk 'https://127.0.0.1:8443/api/client/update?abi={abi}&current_version_code=131'"), flush=True)
    finally:
        client.close()


if __name__ == "__main__":
    deploy(package_artifacts())
    print(f"DEPLOYED {VERSION}", flush=True)
