"""Verify and preserve each locally built ABI APK; emit updater-compatible metadata.

Run once immediately after each ABI build. It never publishes or promotes a release.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def props(path):
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line and not line.startswith("#"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--abi", choices=("arm64-v8a", "armeabi-v7a"), required=True)
    args = parser.parse_args()
    build = props(ROOT / "gradle.properties")
    core = props(ROOT / "core.properties")
    version, code = build["zapretVersionName"], int(build["zapretVersionCode"])
    sdk = Path(props(ROOT / "local.properties")["sdk.dir"])
    tools = sdk / "build-tools" / core["ANDROID_BUILD_TOOLS"]
    apk = ROOT / "app/build/outputs/apk/debug/app-debug.apk"
    badging = subprocess.check_output([str(tools / "aapt2.exe"), "dump", "badging", str(apk)], text=True, encoding="utf-8")
    package = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging)
    assert package and package.groups() == ("com.quantumvpn.debug", str(code), version), "APK identity mismatch"
    signer_text = subprocess.check_output([str(tools / "apksigner.bat"), "verify", "--print-certs", str(apk)], text=True)
    signer = re.search(r"certificate SHA-256 digest: ([0-9a-f]+)", signer_text).group(1)
    with zipfile.ZipFile(apk) as archive:
        abis = {name.split("/")[1] for name in archive.namelist() if name.startswith("lib/") and name.endswith(".so")}
        assert abis == {args.abi}, f"Unexpected native ABI set: {abis}"
        assert f"lib/{args.abi}/libbox.so" in archive.namelist()
    destination = ROOT / "artifacts" / version
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / f"QuantumVPN-{version}-operator-debug-{args.abi}.apk"
    shutil.copy2(apk, target)
    with target.open("rb") as apk_file:
        digest = hashlib.file_digest(apk_file, "sha256").hexdigest()
    (destination / (target.name + ".sha256")).write_text(f"{digest}  {target.name}\n", encoding="ascii")
    metadata_file = destination / "release-metadata.json"
    metadata = json.loads(metadata_file.read_text()) if metadata_file.exists() else {
        "schema": 2, "version_name": version, "version_code": code,
        "application_id": "com.quantumvpn.debug", "core_tag": core["CORE_TAG"],
        "core_commit": core["CORE_COMMIT"], "core_patch_sha256": core["CORE_PATCH_SHA256"],
        "signer_sha256": signer, "artifacts": [],
    }
    assert metadata["version_code"] == code and metadata["signer_sha256"] == signer
    metadata["artifacts"] = [row for row in metadata["artifacts"] if row["abi"] != args.abi] + [
        {"abi": args.abi, "apk_file": target.name, "apk_sha256": digest, "apk_size": target.stat().st_size}]
    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    (destination / "build-info.json").write_text(json.dumps({
        "version_name": version, "version_code": code, "git_commit": commit,
        "dirty_at_build": bool(subprocess.check_output(["git", "diff", "HEAD", "--", "app", "app-updater", "gradle.properties"], cwd=ROOT)),
        "core_commit": core["CORE_COMMIT"], "local_build": True,
        "physical_device_verification": "pending", "artifacts": metadata["artifacts"],
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {version} / {code} / {args.abi}; signer {signer}; SHA-256 {digest}")

if __name__ == "__main__":
    main()
