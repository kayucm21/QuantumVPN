# QuantumVPN 5.11.4 — Aurora

Android update requested for immediate publication after verification, not a
midnight schedule. Package `com.quantumvpn.debug`, code `501104099`; existing
distribution signature and pinned VPN core are unchanged. Both local ARM APKs
must be verified independently before promotion.

## Changes

- Q wordmark, compact home, actual VPN status, distinct games action, and the
  existing cached Aurora background. No decorative infinite power-ring loop.
- Welcome/name flow without phone, email or a new account. Name/completion are
  saved atomically; the name is editable in Settings and only sent to the game
  when joining. Visible-home workers stay stopped during onboarding.
- Startup keeps real update bytes/speed/remaining time and signed-rule checks.
  Server readiness resets synchronously when probe targets change. System bars
  stay readable on the dark welcome/name screens.
- Server-authoritative Durak: both players ready before deal, legal defense
  selection plus explicit confirmation, guarded double clicks/revisions,
  no playable actions while waiting or disconnected, fresh shuffled game on
  re-entry after finishing, normal take/discard/draw-to-six rules.
- Device-bound game ticket has an encrypted Android Keystore resume with a
  bounded expiry. Access codes are never persisted. Polling stops off-screen,
  in background, or at match end; failures back off and stale rooms cannot
  replace the current game.
- Immediate VDS promotion now writes the redacted, deduplicated release inbox
  event in the same transaction as the release/version and device banners.

## Verification boundaries

The candidate passed 232 JVM tests, 125 focused Python tests, 84 offline release
assertions and all 38 focused UI/Keystore tests on the dedicated API 26 x86_64
AVD. The first SwiftShader run stalled during the fourth test; the full rerun
with the explicit `swangle` renderer completed in 35.895 seconds. This isolates
an emulator/capture compatibility issue without claiming a proven root cause.
The pulled home, startup and compact-settings UI fixtures were visually reviewed.
Both ARM APKs passed package/version, signature, SHA-256 and native ABI checks.

The legacy full-project checker stops on an existing NOTICE branding mismatch;
it is not recorded as a passed full-project or remote-CI gate. APK source is
commit `1f1f050e3ef7e36cb6542af34ebe0d4f9658c4b4`; subsequent changes only affect
the review launcher and documentation, not application sources or binaries.

JVM, Python and disposable emulator checks do not prove physical-device VPN
throughput, battery consumption, modern Android vendor behavior or universal
notification delivery. No zero-bug or zero-battery claim is made. No physical
phone was connected for this release; its gate remains pending in build-info.

Raw ADB/diagnostic evidence stays local. The collector ZIP contains scripts
only. No subscriber data, credentials, game access code or signing key is a
release asset. Existing VDS backups, APK releases, assets and tags are retained.

The VDS updater remains primary; users do not need to leave their PC running.
Per-device receipt occurs on the next allowed client refresh and depends on
network availability, Android notification permission and background limits.

Local constrained-host build uses the existing ASCII junction to this same
checkout, Java 17, in-process Kotlin, one worker and a 1200 MB heap. Build and
emulator are run sequentially to avoid starving the host.
