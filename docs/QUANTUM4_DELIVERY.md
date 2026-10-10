# Quantum 4.0: staged delivery, not a 100-feature completion claim

The owner's approved scope is the 100 numbered features in
`tools/quantumvpn_four_catalog.py`. The authenticated Product → Quantum 4.0
view is a bounded, searchable delivery ledger; adding a row is not implementing
that feature. A feature may be marked verified only with a note defining the
tested scope. Partial work must remain partial.

## First candidate: QuantumVPN 5.12.0

- Both ARM test APKs keep the existing package/signing key and embedded core.
- The update transaction checks package identity, signing lineage, version,
  checksum and available storage before handing verified bytes to Android.
- PackageInstaller sessions can request unattended self-updating on Android 12+
  under the platform's conditions. The app must still support Android requesting
  user confirmation. This is not an OS restriction bypass, an Accessibility
  auto-clicker, device-owner enrollment or a root installer.
- Downloading, waiting for confirmation, installing, failure and cancellation
  are distinct states. Installation is not proved by opening the installer.
- An installed-package readback is needed before reporting success. Obsolete
  APK/partial cache files are removed after handoff/cancellation/failure/startup.

Reference: [Android PackageInstaller user-action contract](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int)).

The existing version must be upgraded once to obtain this installer integration.
Subsequent installs may still require confirmation depending on Android version,
target SDK and device policy. No claim is made about Sberbank's implementation.

## Schedule

The requested slot is **11 October 2026, 07:00 Moscow**, or **04:00 UTC**
(12:00 Asia/Irkutsk). An explicit date and UTC+03:00 offset must be supplied.
The VDS worker owns publication; the desktop need not stay on after staging.
The schedule is not confirmed until verified APKs, checksums, metadata and the
server-side compare-and-swap release transaction have passed. Do not publish
early or mark a failed staging attempt scheduled.

## Panel foundation

- Five navigation groups retain existing deep links and form return targets.
- Route explanations report published-policy matches, priority and conflicts.
  They do not claim a measured client ping or execute target scans.
- The development ledger is authenticated and read-only; it does not change
  active routes, users, subscriptions, DNS or releases.

## Automation foundation

n8n and OpenClaw are isolated, loopback-only services. Access uses an SSH tunnel;
they do not receive root credentials, existing bot polling tokens or permission
to mutate VPN configuration. Installing an agent runtime does not train a new
model, prove frontier-model intelligence or implement autonomous administration.
See [automation stack](quantum4-automation-stack.md) for versions, resource
limits, licensing and handoff procedures.

## Verification boundary

The owner chose to proceed without connecting a physical Android device.
Host tests, instrumentation compilation and APK verification do not prove
system installer behavior, smoothness, battery consumption or actual VPN speed
on the owner's phone. Device gates must remain pending, not converted into
success based on a fixture. No promise of 0% battery use, 100% absence of bugs
or immunity from filtering/DDoS is made.

Do not place SSH passwords, gateway tokens, raw client profiles or exported
device diagnostics in this document, Git, release notes or public artifacts.
