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
- Under the current repository workflow, a separate GitHub prerelease draft
  `v5.12.0` was prepared from the same exact build commit with six verified
  assets (two APKs, two SHA-256 files, release metadata and build provenance).
  It remains a draft, not a public Beta update. The guarded publisher returned
  `NotDue` without mutation; public publication remains forbidden before the
  same 07:00 Moscow deadline and requires both production ABI APIs to agree.
- After the deadline, read-only inspection at 10:16 UTC confirmed that the
  existing VDS worker had promoted 5.12.0 / 501200099 and disabled the completed
  schedule. SQLite integrity and package/signature identity checks passed.
  Both legacy and updater APIs for both ARM ABIs returned the new version;
  all four HTTPS APK HEAD checks returned 200 with the expected byte sizes.
  The guarded GitHub publisher then returned `Published` for the separate
  prerelease after checking both production ABI metadata, exact APK hashes,
  all six mirrored assets, and the same unchanged source commit. No phone
  notification delivery or completed installation is inferred from this.

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
- Roadmap status: four scoped verified features, five partial, 91 planned.
  See the authenticated Product → Quantum 4.0 ledger for the exact scope.
- On 11 October, item #38 adds a settings-loss warning to the explicit editable
  POST-form allowlist, including externally associated routing fields. Three
  local tests passed, with 34 real headless-Chrome assertions covering reset,
  invalid/cancelled submits, bfcache, multiple dirty forms, delayed native POST,
  dynamic fields, new tabs and downloads. Values remain in memory only; no
  browser storage, network request or field-value notification is added. Native
  browser warnings are not guaranteed on mobile application termination.
  Existing HTTP tests passed 9/9 and roadmap/UI tests 10/10. The source-only CAS
  deployment passed with public APIs, settings and signing identity unchanged;
  its source rollback snapshot is `aurora-5958b12083d940369f674fb1580c4017`.
  Post-deployment production network checks passed for both panels, both ARM
  update APIs/downloads and MTProto. APK version and release time were untouched.
- The post-publication Network-center verifier now pins the deployed 5.12.0
  identity rather than the previous 5.11.4 baseline. All 17 offline verifier
  tests passed; the independent live check passed for both panels, routing
  catalog/forms, both ABI APIs/downloads, MTProto and diagnostic WARP.

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

The `26253d5` CI run still failed before Gradle. A read-only local
verification identified two further pre-existing gate mismatches: the root
NOTICE retained old branding while the compiled resource already used
QuantumVPN, and the manifest requests `WAKE_LOCK` and
`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, forbidden by the verifier's original
policy. Only the stale root NOTICE branding was synchronized; the compiled
resource, Android permission list and staged APKs were not changed. The
permission/performance checks were not weakened. A successful remote CI
build is still pending and must not be inferred from the local APK checks.
The subsequent `e6f7914` CI run also completed with a failure; the existing
permission-policy discrepancy was not bypassed to obtain a green check.

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
The next resume passed bundle verification and `npm ci`, then stopped before
postinstall because npm 11.20 rejects project-scoped `--allow-scripts` CLI
configuration (`EALLOWSCRIPTS`). The reviewed correction declares only the exact
`openclaw@2026.9.9` manifest policy, rebuilds that unique top-level target and
disables bundled-dependency rebuild traversal. All 28 tests passed, including
an opt-in compatibility test against the SHA-512-verified npm source with
execution mocked. A default offline run skips only that external-source audit.
This is not yet proof of service readiness or a successful model response.
The next worker completed the exact selected OpenClaw postinstall and recorded
the package checkpoint. It stopped before starting services because the actual
pinned validator rejected three retired configuration fields. Their replacement
memory/canvas controls and built-in redaction behavior were independently read
from the promoted runtime source. An exact-token, old/new-digest migration now
permits recovery only for that owned incomplete installation with both services
stopped. Configuration validation requires both exit status zero and JSON
`valid: true`. All 34 offline/audited-source tests passed; a completed service
start and authenticated Gateway model response remain separate live gates.
That resume passed configuration validation but stopped at its live health
gate. The kernel identified `CONSTRAINT_MEMCG` in the new OpenClaw unit, not
global host memory exhaustion; fail-closed cleanup stopped both new services.
About 2.8 GiB remained available, and independent production verification
still passed for both VPN panels, current ARM API/downloads and MTProto.
The reviewed recovery increases only OpenClaw's service cap from 576 to
768 MiB, retains n8n's 640 MiB, both 25% CPU limits, zero swap and existing
heap limits, and requires at least 2000 MiB available before installation.
An exact owned-unit digest migration preserves stopped/incomplete-install
guards; service starts are serialized with bounded readiness windows and a
final simultaneous health check. This change is not itself live health proof.
All 43 offline/audited-source installer tests passed for the resource recovery;
the generated exact legacy unit SHA-256 matched the stopped VDS unit.
The single approved recovery worker `ad472fa4bfff4b6a9e61ec0ec5d69ee8`
then completed with exit status zero. An independent read-only inventory
validated the immutable installation manifest and both active managed services.
n8n database readiness/editor and OpenClaw UI returned HTTP 200, with listeners
restricted to loopback; protected configuration remained unchanged. This is
service readiness, not evidence of a successful model answer. Around 1.7 GiB
remained available after cold start. The heavier CLI model smoke was withheld:
the existing Ollama model-loading peak plus its CLI allowance exceeded that
headroom. No existing Ollama, VPN, panel or proxy service was stopped, and no
additional runtime limits were raised to force a successful test.
The later post-publication handoff gate detected an important regression: n8n remained
database/editor-ready with zero restarts, but OpenClaw no longer passed HTTP
readiness. It had restarted 73 times. A bounded read-only kernel/exit audit
identified repeated `CONSTRAINT_MEMCG` kills in its own 768 MiB cgroup
(approximately 697 MiB anonymous RSS), not V8 heap exceptions or host-wide
OOM. Its initial installation/readiness result is therefore historical, not
proof of ongoing stability. Only this newly installed Gateway service was
authorized for stop/disable containment; no new memory limits or model
inference were authorized. OpenClaw is not a completed live AI integration,
and its interface/model access must remain marked unavailable/pending until
the resource regression is fixed and repeated health/inference gates pass.
Containment was then confirmed: the exact owned OpenClaw unit was stopped and
disabled, while n8n remained active. Independent read-only inventory still
validated the immutable manifest, reported the Gateway port free and about
2041 MiB available, and the post-containment production network check passed.
No protected service was stopped. A later historical snapshot comparison
noticed a change in the MTProto configuration directory, so the earlier
installation-time unchanged-tree result must not be generalized to all later
runtime configuration. Current MTProto readiness was separately verified;
the installer manifest/baseline was not rewritten to conceal that difference.
GitHub publication is separate from the VDS production schedule and must not
make a Beta-updater release available before its authorized deadline.

## OpenClaw-only conversion, 11 October 2026

The owner requested full removal of the owned n8n installation. The reviewed
worker `0ca7d186b6dd4707ab74ba991e1c4096` finished successfully at 11:33 UTC:
the n8n release, state, environment, service unit and isolated account/group
were removed, and the exact owned installation records were converted. The
completed root-private audit is schema2 with recovery secrets erased. Previous
backup archives, shared Node, Ollama, VPN, DNS and panels were not deletion
targets. Deleted n8n working data can only be recovered from a prior backup.

OpenClaw passed 600 continuous seconds of HTTP/loopback readiness with no
restart during the soak, its isolated UID, 1024 MiB maximum, CPU25% and zero
swap. Its 384 MiB heap, read-only configuration, disabled updates and tool
deny-all policy remain in place. This addresses the earlier owned-cgroup
regression, but does not prove unlimited uptime, model quality, Telegram
integration or autonomous node administration. A fresh read-only inventory
at 15:20 UTC still passed the completed conversion and HTTP readiness; it
reported 1994 MiB available RAM and 29242 MiB free disk.

The separately reviewed exact-path cleanup of the owned partial n8n build
directory was dispatched as worker `6f298fc8bd9d4664bccb09816f9c4464` at 15:20
UTC. Its preflight found 68066 files / 217052937 bytes. At 15:28 UTC the worker
had exited successfully with `ScratchRemoved`; an independent read-only
inventory confirmed state `done`, zero files/bytes and target absence. No
shared runtime or backup archive was removed. The migration tests passed
23/23 and cleanup tests 12/12. The original installer tests passed with one
external-source opt-in audit skipped (43 tests discovered).

The lightweight Gateway-only model verifier passed 17 offline tests. Its
default is read-only preflight; explicit inference requires completed schema2,
exact private ACL/config/runtime/source/model identity, at least 1920 MiB
available RAM and the reviewed Ollama peak allowance. It runs as the isolated
service UID without tools, heavy CLI or embedded fallback and requires a
correlated successful final reply plus actual Ollama/Qwen terminal receipt.
Read-only preflight passed at 15:28 UTC with 2097 MiB available RAM and an
observed Ollama peak of 1383 MiB. One explicit no-tools Gateway inference
then failed with the sanitized code `gateway_rpc_rejected`; no successful model
reply is claimed. The Gateway remained HTTP-ready. At 15:32 UTC only 1816 MiB
was available, so another inference was refused by the unchanged 1920 MiB
headroom guard. Read-only failure diagnosis is the next gate; no model unload,
service restart or resource/security limit increase was used to force a pass.

Read-only diagnosis at 15:48 UTC found the same Gateway PID, zero restarts,
1961 MiB available RAM, no loaded Ollama model and 30 owned file-log records
with six timeout keyword hits. Its then-current cgroup had zero OOM/kill
counts. Those hits were not correlated to the test and are not a root cause.
At 15:52 a later read-only preflight failed Gateway HTTP readiness. At 15:53
the Gateway had auto-restarted (new PID, NRestarts=1), its PrivateTmp log and
cgroup counters had reset, and HTTP readiness was still false during startup.
The earlier 600-second soak does not establish stable inference operation.
No second inference was sent. The installed agent remains unverified.
The same HTTP-readiness refusal recurred at 15:59 UTC after the automatic
restart. A safe RPC rejection diagnostic now preserves only fixed stage/code/
status enums and category booleans (19 offline tests). The read-only failure
helper passed 23 tests, with no raw log messages, tokens, inference, unloads
or service changes. Further manager-journal diagnosis was not executed: the
delegated diagnostic turn was rejected by the service safety guard, and no
alternate execution path was used for that blocked action. Neither this
incomplete diagnosis nor current reset counters justify a root-cause claim or
increased resource limits. OpenClaw installation is not functionally complete.

Independent production checks at 11:34, 15:24 and 16:01 UTC passed both panels, routing forms
and catalog, both ARM update APIs/download HEADs, MTProto upstreams and the
diagnostic WARP IPv4/IPv6 path. They are server-side checks, not client latency,
video throughput or proof of subscriber WARP routing. APK identity, signing
and publication time remain unchanged.

No credentials, proxy secrets or device diagnostics are included in this report.
