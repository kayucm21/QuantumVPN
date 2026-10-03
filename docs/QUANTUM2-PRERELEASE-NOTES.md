# QuantumVPN 5.11.2 — Quantum 2.0 interface

Scheduled operator publication: **4 October 2026, 00:00 Moscow**
(`2026-10-03T21:00:00Z`). The GitHub prerelease remains a draft until that deadline
and the production update APIs confirm both verified ABI packages.

## Changes

- Cyan Q/shield branding, bundled aurora and Earth backgrounds, compact home.
- Connect, server selector and game actions remain above bottom navigation.
- Favorites / Reserve filters, server search and measured-ping display.
- Recorded Today / Week statistics, without illustrative traffic or ping values.
- Four settings groups, gallery background, touch effects and reduced motion.
- Startup checks rules and server endpoints; the update download shows measured
  bytes, speed and ETA and cannot be skipped by a stale ready flag.
- Card-game admission ticket and accepted actions survive switching tabs within
  the same app process. Game state and virtual balances remain server-authoritative.

Private rooms, friend invitations and friend-directory APIs are **not included**.
Existing access-code admission and matchmaking remain available. The interface
follows the approved concept; sample data and unimplemented actions are not faked.
No change to Android Private DNS or native VPN/TUN/DNS behavior is included here.

## Build and verification

Native versionName **5.11.2**, versionCode **501102099**, package
**com.quantumvpn.debug**; both APKs use the installed operator certificate.
Choose exactly one APK for your device: **arm64-v8a** or **armeabi-v7a**.

`release-metadata.json` and `build-info.json` record the source commit, pinned core,
signature and per-ABI hashes/sizes. Each APK also has a separate SHA-256 asset.
UI emulator checks do not close physical handset, OEM, VPN or battery gates;
physical-device verification remains pending. See the repository's
`docs/QUANTUM2-RELEASE.md` for the actual test results and visual asset provenance.

`QuantumVPN-5.11.2-ui-review.zip` contains only the checked-in disposable Windows
AVD helper and README. It is a developer review workflow, not a phone installer.
It contains no credentials or diagnostic recordings. GitHub Actions remains an
independent verification/build path; these APKs were built locally.
