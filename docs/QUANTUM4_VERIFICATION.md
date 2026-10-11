# Quantum 4.0 foundation / QuantumVPN 5.12.0

Verified on 10–11 October 2026. This is the first staged delivery, not completion
of the entire 100-feature roadmap.

## Android host gate

- Source commit: `5811e829a8e0c462042f00412088fa1083ad62d4`, clean Android sources on `main`.
- 24 updater and 232 app JVM tests passed. Instrumentation sources compiled;
  no instrumentation tests were executed on a device.
- Both local ARM APKs were built serially using JDK 21 and the checked-in
  Windows build helper. Its 56 offline guard assertions passed.
- Package: `com.quantumvpn.debug`; version `5.12.0`; code `501200099`.
- Existing certificate SHA-256:
  `4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d`.
- Embedded core and existing signing key unchanged; each APK includes
  `libbox.so` and its other native libraries for only the intended ABI.

| ABI | Bytes | SHA-256 |
| --- | ---: | --- |
| arm64-v8a | 140391412 | `acdeeb791ad8daee6dddb5ee9a887c8eb6378f2a6209ccfedb18d2693224b9e7` |
| armeabi-v7a | 130846720 | `16f76c5d1abe12da70b9e44ce1c5ea9c62479fae9c0368b3b8785bc3bcaeadf5` |

Physical upgrade, manufacturer installer behavior, VPN speed, real battery
use and screen/layout checks remain **pending**. The owner chose verification
without a connected phone. The first upgrade from 5.11.4 still uses that older
version's installer and needs Android confirmation. Future self-updates may
also require confirmation under Android's policy.

## VDS release transaction

- Both APKs, per-APK checksums and matching schema-2/build metadata uploaded
  and verified on the existing VDS.
- Schedule committed for **11 October 2026, 07:00 Moscow / 04:00 UTC**,
  epoch `1791691200`; notifications enabled, not sent early.
- The existing server worker checks the captured 5.11.4 / 501104099 baseline,
  matching signature metadata, complete ABI matrix and pinned file hashes.
  It polls every 20 seconds, so publication can follow the requested instant
  by up to one polling interval, subject to the integrity checks.
- After staging, both external ABI APIs still reported 5.11.4 / 501104099;
  their HTTPS downloads returned 200 with correct sizes. Both scheduled
  5.12.0 download HEAD requests returned 404 (embargo active).
- No desktop process is needed for VDS publication. A publication signal is
  not proof that every phone received an Android notification or installed.
- A read-only check at 00:46 UTC on 11 October confirmed the same captured
  baseline, enabled schedule and notification setting. The current public
  version remained 5.11.4; its ARM downloads were available over HTTPS.

## Supplementary panel

- Deployed build: `4.0.0-foundation.1`.
- 153 scoped panel/catalog/quality/HTTP/deployment/network-verifier tests
  passed; two optional passkey tests skipped.
- Five navigation groups, published-rule explanations, and saved-candidate
  conflict preview implemented; previous links, CSRF and form return paths
  retained. Preview checked at 1280×720 and 390 px.
- Source deployment verification confirmed unchanged panel settings,
  signing material and public app API. Network checks also confirmed the
  existing main panel, Xray, native MTProto and diagnostic WARP paths;
  this does not establish the client's latency or video throughput.
- Roadmap status: three scoped verified features, five partial, 92 planned.
  See the authenticated Product → Quantum 4.0 ledger for the exact scope.

## Separate remaining gates

GitHub CI runs for the two foundation commits and their previous baseline all
failed at Android SDK setup, before Gradle: the pinned action's default requested
Google's removed `tools` package. Both CI and Release workflows now explicitly
request `platform-tools` while retaining the action's reviewed commit SHA. The
workflows remain enabled. This configuration correction is not a completed remote
build or device gate; it does not modify the locally verified APK artifacts.
The next CI run passed SDK setup and exposed a second pre-existing issue:
`ci-build.sh` and its nested shell entry points were recorded without execute
permission. Git executable modes are now retained for `gradlew` and tracked
`scripts/*.sh`; their file contents are unchanged.

The latest `26253d5` CI run still failed before Gradle. A read-only local
verification identified two further pre-existing gate mismatches: the root
NOTICE retained old branding while the compiled resource already used
QuantumVPN, and the manifest requests `WAKE_LOCK` and
`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, forbidden by the verifier's original
policy. Only the stale root NOTICE branding was synchronized; the compiled
resource, Android permission list and staged APKs were not changed. The
permission/performance checks were not weakened. A successful remote CI
build is still pending and must not be inferred from the local APK checks.

The n8n/OpenClaw installation has its own guarded installer and health/model
checks. Its outcome is not inferred from the Android or panel test results.
The first native build reached its resource-bounded timeout without promotion.
The durable resume worker then completed n8n's serial native build and its
checkpoint under the same resource limits. It stopped before installing
OpenClaw: the original dependency guard rejected 146 `inBundle` records without
per-child download URLs. A local-only audit of the actual 561-entry lock
confirmed those 146 records against the exact SHA-512-pinned parent archives;
no non-bundled dependency required a foreign source. A narrow provenance guard
now requires exact carrier, package path, name and version, and retains the
prohibition on arbitrary download sources. Compressed archives are bounded and
SHA-512-verified in a private disk file before parsing any tar metadata; this
also covers hidden GNU/PAX header allocation regressions. Its 25 offline tests
passed, and the release packaging/publisher checks passed 88 offline assertions.
This is not yet proof of service readiness or a successful model response.
GitHub publication is separate from the VDS production schedule and must not
make a Beta-updater release available before its authorized deadline.

No credentials, proxy secrets or device diagnostics are included in this report.
