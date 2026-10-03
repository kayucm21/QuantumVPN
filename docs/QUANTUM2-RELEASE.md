# QuantumVPN 2.0 interface / Android 5.11.2

Native version: **5.11.2**, versionCode **501102099**. The operator package remains
`com.quantumvpn.debug`, with the existing signing certificate. "2.0" names the
interface; it is not an Android version downgrade.

## Implemented

- Cyan Q/shield mark and real bundled aurora / Earth wallpapers.
- Compact home, real connection action, server selector, measured ping and
  truthful DNS / signed-rules status, purple game entry.
- All / Favorites / Reserve server filters, persisted favorites, protocol
  filter, search and the existing connection guards.
- Today / Week statistics from recorded traffic, not mock values.
- Four settings groups: Connection, Notifications, Appearance, Help.
- Local photo picker, aurora / city backgrounds, finite touch bubbles and
  reduced-motion support. The bell opens the notification center.
- Server-authoritative card table and turns. Device-bound game ticket, display
  name and accepted requests survive leaving the game tab in the same process.
- Startup checks update state, signed rules / cache fallback and available
  server endpoints. Changing measured pings does not restart endpoint checks.
  APK progress uses real bytes, speed and ETA; an unresolved update or install
  handoff cannot open Home prematurely.
- Navigation reserves the actual Android system-button inset once.

## Explicit limitations

The reference image is a visual concept. Its sample cities, pings, friends and
balances are not manufactured in production. Private-room creation, friend
invitations and a friend directory need server APIs and are not implemented in
this release. Existing access-code admission and matchmaking remain available.
Game admission secrets are never saved in an Android Bundle or photo cache.

No physical handset is connected for this release. UI fixtures / emulator tests
do not attest real VPN, DNS, cellular roaming or all-device performance. Native
VPN/TUN/DNS behavior and Android Private DNS settings were not changed here.

## Verification

- JVM: 251 tests passed in app, updater, network bootstrap and WireGuard import.
- Python panel / scheduler / control quality / Aurora: 75 tests passed.
- Full instrumentation Kotlin compilation passed, but Dr.Web quarantined a
  DEX in the full instrumentation bundle as `Android.MobiDash.32.origin`.
  Security settings were not changed. Focused UI fixtures are built with
  `-PquantumUiReviewOnly=true`; default / CI tests still include every source.
- Final API 26 / x86_64 UI run: **16/16 passed**, 22.214 seconds, with an empty
  crash buffer. Six independent fixture screenshots were captured and visually
  reviewed; the final search/filter/disabled-button contrast was corrected.
  Evidence remains local in `artifacts/quantum2-review-26/tests-20261004-023323`
  and `capture-20261004-023527/quantum2-review`. It contains no subscription or
  real subscriber data. The earlier API 35 run was aborted by a system crash;
  it is not a passed modern-Android gate.
- The focused manifest excludes the unrelated test VPN/provider components
  whose classes are intentionally absent. The ordinary manifest is unchanged.

On a constrained Windows host use Java 17, one worker, in-process Kotlin and
`-Dorg.gradle.jvmargs=-Xmx1536m -XX:+UseSerialGC -Dfile.encoding=UTF-8`.
A Latin-path junction to the same checkout avoids Java 17 native argument-file
decoding of the Cyrillic project path for JVM tests. It is not a second checkout.
The disposable AVD workflow is `scripts/quantum2-review-avd.ps1`:
Boot, RunTests, Capture, Stop. It never installs on an arbitrary physical phone.
The release includes that helper and `scripts/QUANTUM2-UI-REVIEW.md` in
`QuantumVPN-5.11.2-ui-review.zip`, without SDK binaries or raw diagnostics.

## Release timing

Authorized target: **2026-10-04 00:00 Europe/Moscow** = **2026-10-03 21:00 UTC**
= **2026-10-04 05:00 Asia/Irkutsk**, epoch **1791061200**.
VDS publication checks both ABI files, checksums, manifest and current-version
CAS. Pending downloads are embargoed by canonical path, including symlink and
dot-segment regressions. The worker runs every 20 seconds; publication is at the
deadline or the first subsequent successful tick, not a real-time guarantee.

Preparing a GitHub draft is separate from scheduling the VDS. A draft must not
be published early. Notification signals are enabled at publication; delivery
on each phone depends on policy refresh, permissions and Android restrictions.
Do not equate a publication event with confirmed delivery to every device.

Both ARM APKs were built from clean source commit
`65528a509eb91e1b7917f1ad2bfd01ef457bbcee`. Their package, certificate, native ABI,
manifest version, size and SHA-256 were rechecked before upload. VDS scheduling
was confirmed with a private SQLite backup and unchanged production 5.11.1;
the verified application channel is HTTPS on port 8443. Both pending APK HEAD
requests on that channel return 404 before publication. The separate port 443
TLS handshake fails from this Windows host and is not marked verified here.
The GitHub draft's APK digests and all metadata/checksum contents match locally;
the publication script returned `NotDue`, with no write, even with `-Publish`.

## Image assets and final prompt set

Mode: built-in image generation, not the CLI/API fallback. Final assets live in
the repository, not only the image-generation folder:

- `app/src/main/res/drawable-nodpi/quantum2_aurora.png`: vertical dark navy
  mountain-and-lake scene, cyan / teal aurora and its reflection, silhouetted
  pine forest, tranquil night sky, usable dark space behind foreground mobile
  controls; no text, UI, phone frame, logo or watermark.
- `app/src/main/res/drawable-nodpi/quantum2_earth.png`: vertical deep-space
  background, luminous cyan Earth horizon in the lower half, subtle stars and
  atmospheric rim, dark upper area for the welcome and Q-shield; no text, UI,
  phone frame, logo or watermark.

Both are cached at sampled resolution for the mobile backdrop. All labels,
buttons, statistics and progress indicators are native Compose elements.
