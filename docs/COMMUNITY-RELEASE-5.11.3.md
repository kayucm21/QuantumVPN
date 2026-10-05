# QuantumVPN 5.11.3 / Quantum Control 2.1

Android package `com.quantumvpn.debug`, versionCode `501103099`.
Authorized release: **6 October 2026, 00:00 Moscow**
(`2026-10-05T21:00:00Z`, 05:00 Asia/Irkutsk). Neither the GitHub draft
nor the VDS download paths may become public before that instant.

## Android

- Support conversations are in Settings → Help. A subscriber-bound credential
  is obtained only from the accepted managed subscription. Credentials live in
  no-backup app storage; diagnostic attachment is voluntary and redacted again
  by the server.
- The home bell opens a persistent notification inbox for releases,
  maintenance, recovery and support replies. Old cached entries remain readable
  offline. Local and server release events share a stable version-code key.
- Quality sharing is explicitly opt-in. It reports bounded connection/ping
  measurements, protocol, network type and an opaque node identifier, not
  visited domains, VPN links or keys. Unknown ping is not a measured zero.
- Update evidence distinguishes notification, completed download, installer
  handoff and first launch. Installer handoff does not prove installation.
- No native VPN, TUN, system DNS, routing engine or core ABI implementation
  changed in this release. Existing updater cache cleanup is retained.

## Durak

The server validates all moves. Both players must confirm readiness; waiting
players cannot attack, defend or take. A defense selects a specific uncovered
attack. Only legal cards are clickable. "Беру" takes the entire table, including
already defended pairs. "Отбой" moves completed pairs into the discard pile.
At bout end the attacker draws first and the defender last, up to six cards
each while cards remain. The trump card is drawn last.

The attack limit is frozen at bout start; the winner is determined only after
a completed bout. All 36 cards remain accounted for. Revisions reject stale
clicks, action IDs deduplicate accepted retries, and wallet operations and the
game update commit atomically. The virtual stake is charged once and the pot
is settled once; a draw refunds both stakes. Q-coins are not redeemable money.

Valid older deals migrate without resetting hands or balances. Malformed
stored deals are read-only/unavailable and direct the players to support;
their persisted game and virtual pot are retained for operator review rather
than inventing a winner or refund.

## Operator panel

- Client quality and release delivery metrics are grouped in existing sections.
  Small quality groups are suppressed; server-local probes are not labeled as
  client ping.
- Regression-triggered rollout pause is opt-in and only pauses future APK
  issuance. It requires at least 20 distinct fresh first-launch reports and
  >=30% adverse quality evidence from that cohort. It does not stop VPN
  sessions or alter the release date, native configuration or version.
- Typed node/routing/release configuration uses a 10-minute preview, explicit
  confirmation and compare-and-swap guards. Rollback creates another preview,
  and routing revisions remain monotonic. Keys and arbitrary commands cannot
  be inserted through these forms.
- Support replies require operator permission, exact public HTTPS Origin and
  session-bound CSRF. HTML is escaped and diagnostics allowlisted.
- Passkeys use pinned WebAuthn 3.0.1, verified exact Origin/RP, user verification,
  expiring browser-bound single-use challenges and signature-counter checks.
  Enrollment requires the current password and enabled TOTP. Existing password
  and TOTP recovery remain available; no administrator key is enrolled by the
  deployment itself.

## Verification and operational boundaries

- 205 Python unit/real loopback HTTP tests cover the final path-parser
  regressions and a complete
  two-player HTTP match, draw/payout retry protection, wallet rollback,
  subscriber credential isolation, support CSRF, real P256/CBOR virtual
  authenticator cryptography, preview CAS/rollback and release embargo.
- 56 offline PowerShell publication assertions passed, with no credentials,
  network requests or external mutations in these tests.
- All four Android JVM test suites passed: 230 app, 17 updater, 3 bootstrap,
  4 WireGuard import tests (254 total, no failures).
  API 26 x86_64 emulator UI suite: **27/27**. Screenshots and ADB meminfo/crash
  evidence are under `artifacts/quantum2-review-26/capture-20261005-212121`;
  crash buffer was empty. The test fixtures disable community network requests.
- No physical Android device was attached. Real OEM/network/background
  notification delivery and physical VPN performance are **not verified** by
  emulator screen tests. The WebAuthn tests are cryptographic virtual-device
  tests, not registration of an actual administrator's hardware key.
- Local ARM64 and ARMv7 artifacts must each pass package/version, native ABI,
  signer and SHA-256 checks before staging. Build metadata records the exact
  source commit, UI verification and pending physical-device verification.
- Source deployment has private source/SQLite backups and source-only guarded
  rollback. It never restores a live game/wallet database, changes RosPanel
  credentials/subscriptions or restarts active VPN engines.
- Panel `2.1.0-community.1` was deployed and verified on the VDS. Public release
  APIs, configuration and signing identity stayed unchanged. Both production
  ABI APIs continued to return `5.11.2 / 501102099` before scheduling; the active
  game and two wallets remained in the database. HTTPS login GET and existing
  download HEAD checks passed. Deployment backup:
  `/var/lib/quantumvpn-operator/aurora-source-backups/aurora-76bc70c0795e4dcd9637c198b751b419`.
- A scheduled VDS worker publishes only after the UTC deadline and rechecks
  both artifacts. A separate one-time chat check publishes the verified GitHub
  prerelease only after the same deadline and after both production ABI APIs
  agree, then checks HTTPS download HEADs. Local scheduled verification requires
  the PC and Codex app to remain running.
