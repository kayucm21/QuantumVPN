#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$PROJECT_ROOT/app/src/main/AndroidManifest.xml"

[[ -f "$PROJECT_ROOT/settings.gradle.kts" ]]
[[ -f "$PROJECT_ROOT/app/build.gradle.kts" ]]
[[ -f "$MANIFEST" ]]
[[ -f "$PROJECT_ROOT/NOTICE" ]]
[[ -f "$PROJECT_ROOT/THIRD_PARTY_NOTICES.md" ]]
[[ -f "$PROJECT_ROOT/gradle/verification-metadata.xml" ]]
[[ -f "$PROJECT_ROOT/app/src/main/res/raw/sing_box_extended_license.txt" ]]
[[ -f "$PROJECT_ROOT/app/src/main/res/raw/sing_geoip_license.txt" ]]
[[ -f "$PROJECT_ROOT/audit/core/rule_set_performance_test.go" ]]
[[ -f "$PROJECT_ROOT/scripts/core-patchset.sh" ]]
source "$PROJECT_ROOT/core.properties"
source "$PROJECT_ROOT/scripts/core-patchset.sh"
verify_core_patchset "$PROJECT_ROOT"
[[ -f "$PROJECT_ROOT/scripts/gate8-performance-summary.jq" ]]

RELEASE_WORKFLOW="$PROJECT_ROOT/.github/workflows/release.yml"
grep -Fq 'workflow_dispatch:' "$RELEASE_WORKFLOW"
grep -Fq 'final_gate_approved:' "$RELEASE_WORKFLOW"
# shellcheck disable=SC2016
grep -Fq 'ZAPRET_EXPECTED_SIGNER_SHA256: ${{ secrets.ANDROID_SIGNING_CERT_SHA256 }}' "$RELEASE_WORKFLOW"
grep -Fq 'scripts/verify-gate8-performance.sh' "$RELEASE_WORKFLOW"
if grep -Eq '^[[:space:]]+push:' "$RELEASE_WORKFLOW"; then
    echo "Release publication must require manual final-gate attestation" >&2
    exit 1
fi

cmp -s "$PROJECT_ROOT/LICENSE" "$PROJECT_ROOT/app/src/main/res/raw/license_gpl_3.txt"
cmp -s "$PROJECT_ROOT/NOTICE" "$PROJECT_ROOT/app/src/main/res/raw/notice.txt"
cmp -s "$PROJECT_ROOT/THIRD_PARTY_NOTICES.md" "$PROJECT_ROOT/app/src/main/res/raw/third_party_notices.txt"

WRAPPER_PROPERTIES="$PROJECT_ROOT/gradle/wrapper/gradle-wrapper.properties"
grep -Fqx 'distributionUrl=https\://services.gradle.org/distributions/gradle-9.4.1-bin.zip' "$WRAPPER_PROPERTIES"
grep -Fqx 'distributionSha256Sum=2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb' "$WRAPPER_PROPERTIES"
printf '%s  %s\n' \
    '55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c' \
    "$PROJECT_ROOT/gradle/wrapper/gradle-wrapper.jar" \
    | sha256sum -c - >/dev/null

INVALID_ACTIONS="$(
    sed -n 's/^[[:space:]]*uses:[[:space:]]*//p' "$PROJECT_ROOT"/.github/workflows/*.yml \
        | grep -Ev '@[0-9a-f]{40}([[:space:]]+#.*)?$' || true
)"
if [[ -n "$INVALID_ACTIONS" ]]; then
    echo "GitHub Actions must be pinned to full commit SHAs:" >&2
    printf '%s\n' "$INVALID_ACTIONS" >&2
    exit 1
fi

mapfile -t ANDROID_MODULES < <(
    find "$PROJECT_ROOT" -mindepth 2 -maxdepth 2 -name build.gradle.kts -printf '%h\n' \
        | sed "s|$PROJECT_ROOT/||" \
        | sort
)
EXPECTED_ANDROID_MODULES=(app app-updater network-bootstrap wireguard-import)
if [[ "${ANDROID_MODULES[*]}" != "${EXPECTED_ANDROID_MODULES[*]}" ]]; then
    echo "Unexpected Android module set: ${ANDROID_MODULES[*]:-none}" >&2
    exit 1
fi
if [[ "$(grep -l 'com.android.application' "$PROJECT_ROOT"/*/build.gradle.kts | wc -l)" -ne 1 ]] ||
    ! grep -Fq 'com.android.application' "$PROJECT_ROOT/app/build.gradle.kts"; then
    echo "Exactly app must be the Android application module" >&2
    exit 1
fi

if grep -Eq 'android:process=' "$MANIFEST"; then
    echo "Manifest must keep a single Android process" >&2
    exit 1
fi

if grep -R -E 'import android\.util\.Log|\bLog\.[vdiewtf]\(|printStackTrace\(|System\.(out|err)' \
    "$PROJECT_ROOT/app/src/main/java" "$PROJECT_ROOT/app-updater/src/main/java"; then
    echo "Production source must not write credentials or runtime details to Logcat/stdout" >&2
    exit 1
fi
if grep -R -F 'addPrimaryClipChangedListener' \
    "$PROJECT_ROOT/app/src/main/java" "$PROJECT_ROOT/app-updater/src/main/java"; then
    echo "Application clipboard listeners/history are forbidden; approved explicit copies are checked separately" >&2
    exit 1
fi
# Extended-product owners are explicit; new owners/calls still fail review.
python3 "$PROJECT_ROOT/scripts/verify-runtime-surfaces.py" "$PROJECT_ROOT"
python3 "$PROJECT_ROOT/scripts/test_verify_runtime_surfaces.py"

python3 - "$MANIFEST" "$PROJECT_ROOT/app/src/main/res/xml/diagnostic_file_paths.xml" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

android = "{http://schemas.android.com/apk/res/android}"
manifest_path, paths_path = map(Path, sys.argv[1:])
root = ET.parse(manifest_path).getroot()
application = root.find("application")
if application is None:
    raise SystemExit("Manifest has no application")
if application.get(android + "usesCleartextTraffic") != "false":
    raise SystemExit("Application must explicitly reject platform cleartext traffic")
source_permissions = {node.get(android + "name") for node in root.findall("uses-permission")}
expected_source_permissions = {
    "android.permission.WAKE_LOCK",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.USE_BIOMETRIC",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.QUERY_ALL_PACKAGES",
}
if source_permissions != expected_source_permissions:
    raise SystemExit(
        f"Source manifest permission allowlist mismatch: "
        f"{sorted(source_permissions ^ expected_source_permissions)}"
    )
profileable = application.findall("profileable")
if len(profileable) != 1 or profileable[0].get(android + "shell") != "true":
    raise SystemExit("Release-gate profiling requires exactly one shell-profileable declaration")

vpn_services = [
    node for node in application.findall("service")
    if node.get(android + "permission") == "android.permission.BIND_VPN_SERVICE"
]
if len(vpn_services) != 1:
    raise SystemExit(f"Expected exactly one VPN service, found {len(vpn_services)}")
vpn_service = vpn_services[0]
if vpn_service.get(android + "exported") != "false":
    raise SystemExit("VPN service must not be exported")
always_on_metadata = [
    node for node in vpn_service.findall("meta-data")
    if node.get(android + "name") == "android.net.VpnService.SUPPORTS_ALWAYS_ON"
]
if len(always_on_metadata) != 1 or always_on_metadata[0].get(android + "value") != "true":
    raise SystemExit("Current VPN service must explicitly declare its reviewed Always-on capability")

# The manifest capability is not a claim of Lockdown/per-app compatibility.
# Current system-policy checks must remain in the connection preflight.
source_root = manifest_path.parents[2] / "src/main/java/com/quantumvpn"
system_policy = (source_root / "vpn/VpnSystemPolicy.kt").read_text(encoding="utf-8")
vpn_source = (source_root / "vpn/QuantumVpnService.kt").read_text(encoding="utf-8")
if not all(value in system_policy for value in ("lockdown ->", "alwaysOn ->", "blockingMessage")) or "blockingMessage" not in vpn_source:
    raise SystemExit("Always-on/Lockdown must retain the explicit unsupported-policy preflight")

private_receivers = {
    ".vpn.VpnScheduleAlarmReceiver", ".vpn.SubscriptionRefreshReceiver",
    ".vpn.UpdateCheckReceiver", ".vpn.SubscriptionRefreshBootReceiver",
    ".vpn.VpnCommandReceiver", ".updates.UpdateInstallResultReceiver",
}
for name in private_receivers:
    nodes = [node for node in application.findall("receiver") if node.get(android + "name") == name]
    if len(nodes) != 1 or nodes[0].get(android + "exported") != "false":
        raise SystemExit(f"Internal schedule/update/command receiver must not be exported: {name}")

providers = [
    node for node in application.findall("provider")
    if node.get(android + "name") == "androidx.core.content.FileProvider"
]
if len(providers) != 1:
    raise SystemExit(f"Expected one FileProvider, found {len(providers)}")
provider = providers[0]
expected = {
    android + "authorities": "${applicationId}.fileprovider",
    android + "exported": "false",
    android + "grantUriPermissions": "true",
}
for attribute, value in expected.items():
    if provider.get(attribute) != value:
        raise SystemExit(f"Unsafe FileProvider attribute {attribute}: {provider.get(attribute)!r}")
metadata = provider.findall("meta-data")
if len(metadata) != 1 or metadata[0].get(android + "resource") != "@xml/diagnostic_file_paths":
    raise SystemExit("FileProvider must reference only diagnostic_file_paths")

paths = ET.parse(paths_path).getroot()
children = list(paths)
entries = {(child.tag, child.get("name"), child.get("path")) for child in children}
expected_paths = {
    ("cache-path", "diagnostics", "diagnostics/"),
    ("cache-path", "updates", "updates/"),
    ("cache-path", "updates-system", "updates-system/"),
    ("cache-path", "backups", "backups/"),
    ("external-files-path", "external_downloads", "Download/"),
}
if entries != expected_paths or len(children) != len(expected_paths):
    raise SystemExit(f"FileProvider paths differ from bounded cache paths: {entries!r}")
PY

python3 - "$PROJECT_ROOT" <<'PY'
from pathlib import Path
import hashlib
import re
import sys

root = Path(sys.argv[1])
docs = [root / name for name in (
    "ARCHITECTURE.md",
    "DNS_ARCHITECTURE.md",
    "ROUTING_ARCHITECTURE.md",
    "IMPORT_FORMATS.md",
    "IMPLEMENTATION_PLAN.md",
    "README.md",
    "SIGNING.md",
    "GATE8_RESULTS.md",
    "THIRD_PARTY_NOTICES.md",
)]
all_text = "\n".join(path.read_text(encoding="utf-8") for path in docs)
fixture_root = root / "testdata"
manifest = {}
for line in (fixture_root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, relative = line.split(maxsplit=1)
    manifest[relative] = digest
fixtures = sorted(fixture_root.rglob("*.json"))
fixture_names = {path.relative_to(fixture_root).as_posix() for path in fixtures}
if fixture_names != set(manifest):
    raise SystemExit("Fixture set differs from testdata/SHA256SUMS")
for fixture in fixtures:
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    relative = fixture.relative_to(fixture_root).as_posix()
    if manifest[relative] != digest:
        raise SystemExit(f"Fixture hash mismatch: {fixture}: {digest}")
    if digest not in all_text:
        raise SystemExit(f"Fixture hash is not documented: {fixture}: {digest}")
for doc in docs:
    text = doc.read_text(encoding="utf-8")
    if len(re.findall(r"^```", text, re.MULTILINE)) % 2:
        raise SystemExit(f"Unbalanced Markdown fences: {doc}")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        local = target.split("#", 1)[0]
        if local and not (doc.parent / local).exists():
            raise SystemExit(f"Broken local link in {doc}: {target}")
print("Markdown, local links and fixture hashes are valid.")
PY

python3 - "$PROJECT_ROOT" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
surfaces = {
    "README": (root / "README.md").read_text(encoding="utf-8"),
    "release notes generator": (root / "scripts/create-release-bundle.sh").read_text(encoding="utf-8"),
}
required = (
    "Известные ограничения MVP",
    "arm64-v8a",
    "Always-on/Lockdown",
    "shared UID",
    "DoH, DoT",
    "FakeIP",
    "Domain-only block",
    "Clash YAML",
    "Hysteria v1",
    "silent install",
    "plaintext DNS fallback",
)
for surface, text in surfaces.items():
    missing = [value for value in required if value not in text]
    if missing:
        raise SystemExit(f"{surface} omits known limitations: {missing!r}")
ui_root = root / "app/src/main/java/com/quantumvpn/ui"
settings = (ui_root / "SettingsScreen.kt").read_text(encoding="utf-8")
current_ui = (ui_root / "QuantumVpnAppV2.kt").read_text(encoding="utf-8")
disclosures = {
    "legacy settings": (settings, ("Always-on/Lockdown:", "LocalFaq.items", "LocalThreatModel.paragraphs")),
    "current settings/home": (current_ui, (
        "Аварийная защита", "может ограничить доступ к сети",
        "системный Private DNS Android не изменяется",
        "Пароли, ссылки подписок и содержимое трафика не отправляются",
        "Это текущий трафик приложения, не предел скорости VPN",
    )),
}
for surface, (text, values) in disclosures.items():
    missing = [value for value in values if value not in text]
    if missing:
        raise SystemExit(f"{surface} omits current risk disclosures: {missing!r}")
print("Release-document limitations and current UI risk disclosures verified.")
PY

python3 - "$PROJECT_ROOT" "$CORE_COMMIT" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1])
asset_root = root / "app/src/main/assets/rule-sets"
manifest = json.loads((asset_root / "manifest.json").read_text(encoding="utf-8"))
if manifest.get("generated_with_core") != sys.argv[2]:
    raise SystemExit("Rule-set manifest core revision mismatch")
expected = {"zapret-ru-domains", "zapret-ru-ip"}
entries = manifest.get("sets", [])
if {entry["tag"] for entry in entries} != expected:
    raise SystemExit("Unexpected packaged rule-set tag set")
for entry in entries:
    path = asset_root / entry["file"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry["sha256"]:
        raise SystemExit(f"Rule-set asset hash mismatch: {path}: {digest}")
print("Packaged rule-set manifest and hashes are valid.")
PY

# Native Windows jq cannot open a non-ASCII absolute filter path reliably.
# Resolve the ASCII relative filter inside the already-validated project root.
PERFORMANCE_POLICY="scripts/gate8-performance-summary.jq"
POLICY_RESULT="$(
    cd "$PROJECT_ROOT"
    printf '%s\n' \
        '{"scenario":"stack_current_mixed","cpu_ticks":100,"elapsed_nanos":1000000000,"pss_kb":100,"rss_kb":100,"tun_bytes":100,"throughput_mbps":100}' \
        '{"scenario":"stack_system","cpu_ticks":104,"elapsed_nanos":1040000000,"pss_kb":104,"rss_kb":104,"tun_bytes":104,"throughput_mbps":104}' \
        '{"scenario":"mtu_default_9000","cpu_ticks":100,"elapsed_nanos":1000000000,"pss_kb":100,"rss_kb":100,"tun_bytes":100,"throughput_mbps":100}' \
        '{"scenario":"mtu_1500","cpu_ticks":106,"elapsed_nanos":1060000000,"pss_kb":106,"rss_kb":106,"tun_bytes":106,"throughput_mbps":106}' \
        | jq -s --argjson threshold 5 -f "$PERFORMANCE_POLICY"
)"
BELOW_THRESHOLD_DECISION="$(
    jq -r '.comparisons[] | select(.name == "mixed_vs_system") | .decision' <<<"$POLICY_RESULT"
)"
ABOVE_THRESHOLD_DECISION="$(
    jq -r '.comparisons[] | select(.name == "mtu_default_vs_1500") | .decision' <<<"$POLICY_RESULT"
)"
if [[ "$BELOW_THRESHOLD_DECISION" != "NO_CHANGE_BELOW_5_PERCENT_OR_NO_SIGNAL" ]]; then
    echo "Performance policy accepted a sub-5% change" >&2
    exit 1
fi
if [[ "$ABOVE_THRESHOLD_DECISION" != "PHYSICAL_CONFIRMATION_REQUIRED" ]]; then
    echo "Performance policy ignored a >=5% change" >&2
    exit 1
fi
echo "Performance significance policy verified."

echo "Project structure verified."
