from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "5.10.3"
VERSION_CODE = 128
ARTIFACTS = ROOT / "artifacts" / VERSION


def package(abi: str, source: Path) -> dict[str, object]:
    target = ARTIFACTS / f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk"
    target.write_bytes(source.read_bytes())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (ARTIFACTS / f"{target.name}.sha256").write_text(f"{digest}  {target.name}\n", encoding="utf-8")
    return {"abi": abi, "apk_file": target.name, "apk_sha256": digest, "apk_size": target.stat().st_size}


def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    apk = ROOT / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
    arm64 = ROOT / "build" / f"quantumvpn-{VERSION}-arm64-staging.apk"
    if not apk.is_file() or not arm64.is_file():
        raise SystemExit("both ABI APKs must be built before packaging")
    items = [package("arm64-v8a", arm64), package("armeabi-v7a", apk)]
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
    (ARTIFACTS / "release-metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ARTIFACTS / "build-info.txt").write_text(
        "version=5.10.3\nversionCode=128\nfeatures=aurora-glass,clamped-navigation-inset,background-updater,arm64-v8a,armeabi-v7a\n",
        encoding="utf-8",
    )
    (ARTIFACTS / "RELEASE_NOTES.md").write_text(
        "# QuantumVPN 5.10.3\n\n"
        "- Исправлен завышенный нижний отступ навигации на некоторых Android-устройствах.\n"
        "- Кнопки «Главная», «Серверы», «Статистика» и «Настройки» закреплены рядом с системной панелью.\n"
        "- Обновление доступно сразу, без расписания.\n",
        encoding="utf-8",
    )
    print(ARTIFACTS)


if __name__ == "__main__":
    main()
