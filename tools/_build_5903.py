from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.9.3"
VERSION_CODE = 118
ARTIFACTS = ROOT / "artifacts" / VERSION
APK_DIR = ROOT / "app" / "build" / "outputs" / "apk" / "debug"
ARM64_STAGING = ROOT / "build" / "quantumvpn-5.9.3-arm64-staging.apk"


def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    items = []
    for abi in ("arm64-v8a", "armeabi-v7a"):
        # The Gradle ABI build is run immediately before this packaging step.
        target = ARTIFACTS / f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk"
        source = ARM64_STAGING if abi == "arm64-v8a" else (APK_DIR / "app-debug.apk")
        if not source.is_file():
            raise SystemExit(f"missing built APK: {source}")
        shutil.copy2(source, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        (ARTIFACTS / f"{target.name}.sha256").write_text(
            f"{digest}  {target.name}\n", encoding="utf-8"
        )
        items.append({"abi": abi, "apk_file": target.name, "apk_sha256": digest, "apk_size": target.stat().st_size})
    metadata = {
        "schema": 2,
        "version_name": VERSION,
        "version_code": VERSION_CODE,
        "application_id": "com.quantumvpn.debug",
        "signing_certificate_sha256": "4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d",
        "core_tag": "v1.13.18-extended-2.6.5",
        "core_commit": "e8f6936480b7fa9738911e3e7fc2ec0d8a634a88",
        "artifacts": items,
    }
    (ARTIFACTS / "release-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (ARTIFACTS / "build-info.txt").write_text(
        "version=5.9.3\nversionCode=118\n"
        "features=remote-branding,live-health,privacy-controls,adblock,kill-switch,"
        "scheduled-release-21-msk,arm64-v8a,armeabi-v7a\n",
        encoding="utf-8",
    )
    (ARTIFACTS / "RELEASE_NOTES.md").write_text(
        "# QuantumVPN 5.9.3\n\n"
        "- Добавлено удалённое оформление из панели без пересборки APK.\n"
        "- Добавлены настройки DNS-фильтра и Kill Switch в новом интерфейсе.\n"
        "- Сохранены живой пинг, мониторинг нод, диагностика с согласием и обновления по расписанию 21:00 МСК.\n"
        "- Убран отдельный режим экономии батареи из нового интерфейса.\n",
        encoding="utf-8",
    )
    (ARTIFACTS / "update.html").write_text(
        "<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>QuantumVPN 5.9.3</title><style>body{font-family:system-ui;background:#06121d;color:#effcff;padding:24px}.card{max-width:560px;margin:8vh auto;padding:28px;border:1px solid #1d5570;border-radius:24px;background:#0b2032}.btn{display:block;text-align:center;padding:15px;border-radius:999px;background:#3de7ff;color:#041018;font-weight:800;text-decoration:none;margin-top:20px}.muted{color:#9eb6c9}</style>"
        "<div class='card'><h1>QuantumVPN 5.9.3</h1><p class='muted'>Удалённое оформление · живой мониторинг · безопасные обновления.</p>"
        "<a class='btn' href='/downloads/5.9.3/QuantumVPN-5.9.3-operator-debug-arm64-v8a.apk'>Скачать ARM64</a>"
        "<p><a class='muted' href='/downloads/5.9.3/QuantumVPN-5.9.3-operator-debug-armeabi-v7a.apk'>Скачать ARMv7</a></p></div>",
        encoding="utf-8",
    )
    print(ARTIFACTS)


if __name__ == "__main__":
    main()
