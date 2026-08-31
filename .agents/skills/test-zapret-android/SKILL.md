---
name: test-zapret-android
description: Test and diagnose QuantumVPN Android APKs on real devices and emulators, including VPN, TUN, per-app routing, DNS, network changes, crashes, hangs, performance, and release-device gates. Use when reproducing an Android-only problem, collecting ADB/logcat/dumpsys evidence, extracting the app's redacted diagnostic JSON, or deciding which existing device verification script to run.
---

# Test Zapret Android

Use device evidence to separate Android VPN behavior from sing-box/libbox behavior. Never mark a physical-device gate complete from JVM tests, fixtures, an emulator, or schema validation alone.

## Establish the test target

1. Read `AGENTS.md` and the relevant section of `IMPLEMENTATION_PLAN.md`, `DNS_ARCHITECTURE.md`, `ROUTING_ARCHITECTURE.md`, or `GATE8_RESULTS.md`.
2. Record the APK version, Git commit, core revision, ABI, device model, API level, network transport, DNS mode, Private DNS mode, profile/outbound type, and reproduction time.
3. Prefer the latest debug APK built from the commit under investigation for diagnosis. Use a release APK again before closing release-only behavior.
4. Use these package IDs:
   - debug: `com.quantumvpn.debug`
   - release: `com.quantumvpn`
5. Treat the user's device as remote unless `adb devices -l` in the current environment proves otherwise. Give host-side commands for the user's OS and ask for the resulting artifacts.

Debug builds permit `run-as` and contain test-only probes. Release builds must reject `run-as`; use the Android Sharesheet to export diagnostics from release builds.

## Run repository verification first

Run only the checks relevant to the change, then widen verification in proportion to risk:

```bash
./scripts/verify-project.sh
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug -PzapretAbi=arm64-v8a
./gradlew :app:assembleDebug -PzapretAbi=armeabi-v7a
```

Use existing device scripts instead of recreating their logic:

- `scripts/verify-process-recreation.sh`: debug device process/core/TUN recreation.
- `scripts/verify-release-device.sh`: release install, upgrade, downgrade, signature, and cold-start checks. It uninstalls the release package; run only on an authorized test device after protecting user data.
- `scripts/verify-gate8-stress.sh`: destructive Wi-Fi/cellular stress intended only for a disposable AVD.
- `scripts/verify-gate8-performance.sh`: extended performance and power evidence; inspect its prerequisites and mutations before running.
- `scripts/verify-release-candidate.sh`: host-side APK/revision/ABI/manifest verification.
- `scripts/collect-video-evidence-windows.cmd`: non-destructive physical-device capture for a stuttering video session. It records process/thread CPU, a scheduler trace, memory, interface counters, connectivity, unfiltered logcat and the explicitly exported app diagnostic.
- `scripts/collect-stable-gate-windows.cmd`: non-destructive four-phase release-package
  capture for stable `0.2.1`: VPN-off idle, VPN-on idle, selected-app video and
  Wi-Fi/mobile switching. It records objective CPU, PSS, traces, battery counters,
  interfaces, connectivity and logcat without using `run-as`.

Do not run a script that installs, uninstalls, clears, or changes device networking unless that mutation is within the user's requested test scope.

For every future multi-step Windows evidence workflow, create or update a checked-in
`.cmd` or `.ps1` file and give the user only the short download/run commands. Never
ask the user to paste a multi-line workflow into interactive `cmd.exe`. Individual
one-line inspection commands remain acceptable. Package the script as a ZIP, publish
that ZIP as an asset of the current GitHub test prerelease, and give its normal
browser download link as the primary delivery method. A checked-in GitHub file link
and `curl.exe` command are secondary fallbacks only. Do not rely on
`Invoke-WebRequest` or `raw.githubusercontent.com`: older Windows PowerShell, network
filters and TLS interception can reset those connections.

For the Windows video capture, download
[`Zapret-KVN-video-evidence-collector.zip`](https://github.com/youtubediscord/QuantumVPN-android/releases/download/v0.2.1-test.26/Zapret-KVN-video-evidence-collector.zip)
from the Test 26 GitHub Release in a browser, extract the script next to `adb.exe`
and run the file. The script pauses before the measured 35-second playback window
and again for the explicit diagnostic export. Use the following only as a fallback:

```bat
cd /d D:\bin\platform-tools
curl.exe --http1.1 -L --retry 3 -o collect-video-evidence-windows.cmd "https://github.com/youtubediscord/QuantumVPN-android/raw/refs/heads/main/scripts/collect-video-evidence-windows.cmd"
collect-video-evidence-windows.cmd
```

Browser fallback:
[`collect-video-evidence-windows.cmd`](https://github.com/youtubediscord/QuantumVPN-android/blob/main/scripts/collect-video-evidence-windows.cmd)
→ **Download raw file**. If the ZIP link must move to a newer test release, verify
the release asset exists before giving the new URL. Never return to a pasted
multi-line workflow.

For stable `0.2.1` physical measurements, download
[`Zapret-KVN-stable-gate-collector.zip`](https://github.com/youtubediscord/QuantumVPN-android/releases/download/v0.2.1-beta.30/Zapret-KVN-stable-gate-collector.zip)
in a browser, extract it next to `adb.exe`, and run
`collect-stable-gate-windows.cmd`. Run it once per profile/outbound under test. The
release package is not debuggable, so a redacted in-app diagnostic remains a
separate Sharesheet export and is only required when a VPN/DNS phase fails.

## Capture a reproduction through ADB

Run `adb` on the host computer, not at an Android `device:/ $` prompt. Avoid a PID filter for VPN/DNS diagnosis: useful events belong to `ConnectivityService`, `DnsManager`, `netd/resolv`, and other system processes.

For Windows CMD:

```bat
cd /d D:\bin\platform-tools
adb.exe devices -l
adb.exe shell pm list packages | findstr /i zapretkvn
adb.exe logcat -c
adb.exe logcat -b main -b system -b crash -v threadtime > "%USERPROFILE%\Desktop\zapret-kvn-logcat.txt"
```

Start the final command before reproducing. Use only the app needed for the reproduction, wait until success or the visible error, then stop logcat with `Ctrl+C`.

Use this full two-phase Windows CMD capture by default for a VPN/TUN/DNS failure.
Run it from the Windows prompt, never from `device:/ $`; type `exit` first if the
prompt is an Android shell:

```bat
cd /d D:\bin\platform-tools
set "ZAPRET_PKG=com.quantumvpn.debug"
set "ZAPRET_EVIDENCE=%USERPROFILE%\Desktop\zapret-evidence"
if not exist "%ZAPRET_EVIDENCE%" mkdir "%ZAPRET_EVIDENCE%"
adb.exe devices -l > "%ZAPRET_EVIDENCE%\devices.txt" 2>&1
adb.exe shell pm list packages | findstr /i zapretkvn > "%ZAPRET_EVIDENCE%\packages.txt"
adb.exe shell getprop ro.build.version.release > "%ZAPRET_EVIDENCE%\android-release.txt"
adb.exe shell getprop ro.build.version.sdk > "%ZAPRET_EVIDENCE%\android-api.txt"
adb.exe shell getprop ro.product.cpu.abi > "%ZAPRET_EVIDENCE%\android-abi.txt"
adb.exe logcat -c
adb.exe logcat -b main -b system -b crash -v threadtime > "%ZAPRET_EVIDENCE%\zapret-logcat.txt"
```

While the last command is running, reproduce exactly once, wait for the visible
result, then open `Настройки → Диагностика` and press `Экспортировать диагностику`
without force-stopping or restarting the app. Once the Sharesheet appears, return
to CMD and press `Ctrl+C`. Then run:

```bat
adb.exe shell dumpsys -l > "%ZAPRET_EVIDENCE%\dumpsys-services.txt" 2>&1
adb.exe shell dumpsys connectivity > "%ZAPRET_EVIDENCE%\connectivity.txt" 2>&1
adb.exe shell dumpsys netd > "%ZAPRET_EVIDENCE%\netd.txt" 2>&1
adb.exe shell settings get global private_dns_mode > "%ZAPRET_EVIDENCE%\private-dns-mode.txt" 2>&1
adb.exe shell settings get global private_dns_specifier > "%ZAPRET_EVIDENCE%\private-dns-specifier.txt" 2>&1
adb.exe shell run-as %ZAPRET_PKG% ls -l cache/diagnostics > "%ZAPRET_EVIDENCE%\diagnostic-files.txt" 2>&1
adb.exe exec-out run-as %ZAPRET_PKG% cat cache/diagnostics/zapret-kvn-diagnostic.json > "%ZAPRET_EVIDENCE%\zapret-kvn-diagnostic.json"
powershell.exe -NoProfile -Command "Compress-Archive -Path $env:ZAPRET_EVIDENCE\* -DestinationPath $env:USERPROFILE\Desktop\zapret-evidence.zip -Force"
```

Treat the unfiltered logcat and redacted app diagnostic as complementary evidence:
logcat proves Android `VpnService`, `ConnectivityService`, `netd/resolv`, interface,
DNS and teardown behavior; the diagnostic contains the bounded libbox `CommandLog`,
effective runtime overlay and stage timings. Always request both from the same
attempt before changing VPN/TUN/DNS implementation.

For Bash:

```bash
adb devices -l
adb shell pm list packages | grep -i zapretkvn
adb logcat -c
adb logcat -b main -b system -b crash -v threadtime > zapret-kvn-logcat.txt
```

Do not force-stop or relaunch the app between the failure and diagnostic export: current connection attempts and startup core logs are held in process memory.

## Extract the app diagnostic

The normal logcat does not contain the bounded libbox `CommandLog`. Obtain it from the app's redacted diagnostic JSON.

After reproducing, open `Настройки → Диагностика` and press `Экспортировать диагностику` near the top once. The appearance of the Sharesheet is enough to create the cache file. Without pressing the button, no report file exists. In Test 9 and older, scroll to the very bottom and press the former `Создать и передать diagnostic JSON` button.

Pull it from an installed debug build in Windows CMD:

```bat
adb.exe shell run-as com.quantumvpn.debug ls -l cache/diagnostics
adb.exe exec-out run-as com.quantumvpn.debug cat cache/diagnostics/zapret-kvn-diagnostic.json > "%USERPROFILE%\Desktop\zapret-kvn-diagnostic.json"
```

Or in Bash:

```bash
adb shell run-as com.quantumvpn.debug ls -l cache/diagnostics
adb exec-out run-as com.quantumvpn.debug \
  cat cache/diagnostics/zapret-kvn-diagnostic.json > zapret-kvn-diagnostic.json
```

If `run-as` reports that the package is not debuggable, verify the installed package. For a real release build, use the Sharesheet instead. The temporary export is deleted at the next application startup, so copy it before restarting.

Before treating an attachment as app evidence, verify that it is JSON and contains the Zapret schema. A Telegram MTP/MTProxy text log renamed to `.json` is not an app diagnostic:

```bash
jq -e '.report_version >= 2 and (.app | type == "object")' zapret-kvn-diagnostic.json
```

Reports v3 additionally contain the core patch SHA-256, granular core/TUN/DNS/HTTPS
stage timings, priority core-log categories, received/coalesced/dropped counters,
runtime resource counters and one prior Android process-exit reason on API 30+.
`dropped_lines` means routine in-memory evidence exceeded a fixed quota; runtime logs
are still never persisted or copied to Logcat. Confirm that relevant handshake/TUN/error
records survived before requesting a larger external logcat capture.

## Capture Android network state

List available services before calling a vendor-dependent `dumpsys` target:

```bat
adb.exe shell dumpsys -l | findstr /i "connectivity dns netd vpn"
```

Capture only services actually listed:

```bat
adb.exe shell dumpsys connectivity > "%USERPROFILE%\Desktop\zapret-kvn-connectivity.txt" 2>&1
adb.exe shell dumpsys netd > "%USERPROFILE%\Desktop\zapret-kvn-netd.txt" 2>&1
adb.exe shell settings get global private_dns_mode
adb.exe shell settings get global private_dns_specifier
adb.exe shell getprop ro.build.version.release
adb.exe shell getprop ro.build.version.sdk
adb.exe shell getprop ro.product.cpu.abi
```

`dnsresolver` is not exposed as a separate dumpsys service on every Android build, including some GrapheneOS builds. `Can't find service: dnsresolver` and an empty redirected file mean “unavailable,” not “DNS is broken.” Do not treat an empty dump as evidence.

Never change Private DNS or other system settings merely to collect diagnostics. Change them only as an explicit test-matrix step and restore the original value.

## Capture hangs and crashes

While the unfiltered logcat capture is running, request a Java thread dump for a visible hang from Windows CMD:

```bat
for /f %P in ('adb.exe shell pidof -s com.quantumvpn.debug') do adb.exe shell kill -3 %P
```

Use `%%P` instead of `%P` inside a `.bat` file. Then wait a few seconds before stopping logcat.

For a crash, retain the full reproduction log and additionally save:

```bat
adb.exe logcat -d -b crash -v threadtime > "%USERPROFILE%\Desktop\zapret-kvn-crash.txt"
```

If the process crashed, relaunch once and export the diagnostic; `previous_crash` should contain the app's persisted redacted crash record. Use `adb bugreport` only as a last resort because it is large and privacy-sensitive.

## Require evidence by problem type

For VPN/DNS/TUN failures, require:

- unfiltered timestamped logcat covering start through stop/error;
- redacted `zapret-kvn-diagnostic.json` from the same process session;
- exact visible error and approximate timestamp;
- APK version, device/API/ABI, network transport, DNS mode, Private DNS mode, and outbound type;
- available connectivity/netd dumps only when they add relevant state.

For intermittent failures, collect at least one success and one failure from the same APK/device/network. Preserve attempt history before the app restarts.

For the Android WireGuard roaming fix, record both `core.revision` and
`core.patch_sha256`. Compare Test 13 with Test 12 using the same profile, DNS mode,
MTU, device and network; the patch is implemented but its causal effect is not proven
until the physical A/B succeeds.

For userspace WireGuard, also inspect `wireguard_client_bind_detour_count`, peer
count, local address families, default IPv4/IPv6 AllowedIPs, effective Android TUN
MTU and inner endpoint MTU. The pinned core defaults an unspecified Android TUN to
9000. In the normal QuantumVPN mode a userspace WireGuard profile must instead report
`tun_mtu=min(1500, minimum endpoint MTU)`; an endpoint without MTU receives 1280.
The Android WireGuard patch uses the protected sing-box dialer directly and must not
add a synthetic outbound detour. A handshake response proves only the outer UDP/key
path, not usable inner TCP/UDP traffic. If small DNS succeeds but HTTPS stalls, verify
the actual TUN MTU in unfiltered `ConnectivityService`/`Vpn` logcat before changing DNS.

For routing/per-app failures, also record the selected package, include/exclude mode, whether the control app was selected, and IPv4/IPv6/TCP/UDP/QUIC result without including credentials.

## Interpret the layers separately

- Android owns package admission, `VpnService.Builder`, TUN addresses/routes/DNS, the underlying network, and teardown.
- sing-box/libbox owns packet processing after TUN admission, DNS hijack, managed DNS transports, route rules, and outbounds.
- An established `tun0` does not prove that internal DNS or the proxy outbound works.
- Android network `VALIDATED` does not replace the app's DNS and HTTPS health checks.
- Automatic/opportunistic Private DNS may attempt DoT against the internal DNS address. In the current implementation, the managed health probe independently sends raw DNS on port 53; do not confuse the two timelines.
- Closing TUN immediately after a failed startup health check is expected fail-closed behavior, not automatically a core crash or server restart.

Build a timestamped sequence before proposing a fix. State which layer is proven healthy, which layer failed, and which conclusion remains an inference.

## Protect diagnostic data

Prefer the app diagnostic because it is redacted. Raw logcat or dumpsys can contain SSID, BSSID, MAC/IP addresses, package names, endpoints, and device state. Do not commit raw user artifacts, publish them in GitHub Releases, or paste unrelated lines into public issues. Keep credentials and raw profiles out of all reports.
