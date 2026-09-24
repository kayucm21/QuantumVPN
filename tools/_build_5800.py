import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

src_root = Path(__file__).resolve().parents[1]
dst = Path(r"C:\qvpn")
os.makedirs(r"C:\gradle-home-qvpn", exist_ok=True)
os.environ["GRADLE_USER_HOME"] = r"C:\gradle-home-qvpn"
os.environ.pop("GRADLE_OPTS", None)

version = "5.8.0"
code = 114
art = src_root / "artifacts" / version
art.mkdir(parents=True, exist_ok=True)

sync = [
    "app/src/main/java/com/quantumvpn/ui/QuantumVpnAppV2.kt",
    "app/src/main/java/com/quantumvpn/vpn/WifiAutoConnectCoordinator.kt",
    "app/src/main/res/xml/vpn_toggle_widget_info.xml",
    "app/src/main/res/xml/vpn_wide_widget_info.xml",
    "app/src/main/java/com/quantumvpn/updates/SystemApkUpdateInstaller.kt",
    "app/src/main/java/com/quantumvpn/MainActivity.kt",
    "app/src/main/java/com/quantumvpn/QuantumVpnApplication.kt",
    "app-updater/src/main/java/com/quantumvpn/updates/UpdateController.kt",
    "app-updater/src/main/java/com/quantumvpn/updates/PanelHttpsClient.kt",
    "gradle.properties",
    "tools/quantumvpn_operator_panel.py",
    "tools/setup-nginx-downloads.sh",
    "tools/deploy-operator-5.8.0.sh",
]
for rel in sync:
    source = src_root / rel
    if not source.is_file():
        print("missing", rel)
        sys.exit(2)
    target = dst / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

gradlew = str(dst / "gradlew.bat")
subprocess.run([gradlew, "--stop"], cwd=dst, check=False)
previous = src_root / "artifacts" / "5.7.14" / "release-metadata.json"
old = json.loads(previous.read_text(encoding="utf-8")) if previous.is_file() else {}

items = []
for abi in ("arm64-v8a", "armeabi-v7a"):
    print("=== building", abi, flush=True)
    result = subprocess.run(
        [gradlew, ":app:assembleDebug", f"-PzapretAbi={abi}", "--no-daemon", "--max-workers=1"],
        cwd=dst,
    )
    if result.returncode:
        raise SystemExit(result.returncode)
    name = f"QuantumVPN-{version}-operator-debug-{abi}.apk"
    target = art / name
    shutil.copy2(dst / "app/build/outputs/apk/debug/app-debug.apk", target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (art / f"{name}.sha256").write_text(f"{digest}  {name}\n", encoding="utf-8")
    items.append({"abi": abi, "apk_file": name, "apk_sha256": digest, "apk_size": target.stat().st_size})
    print(abi, digest, target.stat().st_size, flush=True)

metadata = {
    "schema": 2,
    "version_name": version,
    "version_code": code,
    "application_id": "com.quantumvpn.debug",
    "signing_certificate_sha256": old.get("signing_certificate_sha256", "4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d"),
    "core_tag": old.get("core_tag", "v1.13.18-extended-2.6.5"),
    "core_commit": old.get("core_commit", "e8f6936480b7fa9738911e3e7fc2ec0d8a634a88"),
    "artifacts": items,
}
(art / "release-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
(art / "build-info.txt").write_text("version=5.8.0\nversionCode=114\nfeatures=smart-connect,network-handoff,notification-center,aurora-glass,widget,health-monitor\n", encoding="utf-8")
(art / "RELEASE_NOTES.md").write_text(
    "# QuantumVPN 5.8.0\n\n"
    "- Smart Connect combines latency and reliability.\n"
    "- Automatic Wi‑Fi/LTE handoff restarts the active session after a validated network change.\n"
    "- Notification Center shows maintenance, announcements and release status.\n"
    "- Aurora Glass theme now exposes Android Dynamic Color.\n"
    "- Home-screen widgets refresh periodically and on every VPN state change.\n"
    "- Operator panel stores a rolling server/service health history.\n",
    encoding="utf-8",
)
print("ARTIFACTS_OK", art, flush=True)
