# Quantum 4.0 foundation / QuantumVPN 5.12.0

Verified on 10 October 2026. This is the first staged delivery, not completion
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
- Embedded core and existing signing key unchanged; each APK contains only
  its intended ABI and `libbox.so`.

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

The n8n/OpenClaw installation has its own guarded installer and health/model
checks. Its outcome is not inferred from the Android or panel test results.
GitHub publication is separate from the VDS production schedule and must not
make a Beta-updater release available before its authorized deadline.

No credentials, proxy secrets or device diagnostics are included in this report.
