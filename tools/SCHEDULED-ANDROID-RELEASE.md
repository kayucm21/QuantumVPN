# Verified local Android publication at Moscow midnight

This workflow changes only release settings. Client subscriptions, routing
signing keys, old APK directories and old GitHub Releases/tags are retained.

1. Build and package **both** `arm64-v8a` and `armeabi-v7a` locally with
   `package-android-local.py`. The native incremental version stays `5.11.2`;
   "QuantumVPN 2.0" is the interface name, not a downgrade to Android version 2.0.
   Both packages must have the same application ID and signing certificate as
   the installed production APK. The versionCode must strictly increase.
2. Run relevant native/UI/device tests. Record the actual evidence in
   `build-info.json`; do not label an untested physical device as verified.
3. Deploy and verify the guarded `promote_scheduled_release` implementation
   before scheduling. Legacy schedules without a pinned release manifest and
   captured production baseline are retained, but publication fails closed.
4. Read the current production version/code and check the last verified local
   metadata signer. The following command is for production `5.11.1` /
   `501101099`; **do not reuse its CAS baseline if production has changed**.

```powershell
py -3.14 tools/deploy-local-apk-release.py 5.11.2 `
  --host 150.241.96.191 `
  --known-hosts C:/Users/Admin/.ssh/known_hosts `
  --expected-current-version 5.11.1 `
  --expected-current-code 501101099 `
  --expected-signer-sha256 4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d `
  --schedule-at 2026-10-04T00:00:00+03:00 `
  --check-only
```

The timestamp is `2026-10-03 21:00:00 UTC`, not Irkutsk midnight. Only an
explicit `YYYY-MM-DDT00:00:00+03:00` at least five minutes in the future is
accepted. Credentials are supplied in the temporary process variable
`QVPN_VDS_PASSWORD`; do not put passwords/tokens in a file, command output or
release metadata. The chosen Python runtime needs `paramiko` installed.

5. Execute the same command without `--check-only` only after verification.
   It re-verifies APK package/version/signature, per-APK checksum assets and
   metadata, connects using pinned host keys, uploads into a private staging
   directory, and reserves a checked SQLite backup before changing settings.
   It enables update notifications, records the schedule/CAS/manifest digest,
   then exposes the complete verified ABI matrix atomically behind the download
   embargo. It **does not** change the current version or send an early update
   signal. Without `--schedule-at` or `--promote`, only private staging occurs.
6. Check the live `release_schedule_enabled`, `release_publish_at`, pending
   version/code and manifest digest. The running operator worker checks due
   releases every 20 seconds. Publication therefore occurs at midnight or on
   the first subsequent worker tick, not with a subsecond real-time guarantee.
   Download URLs remain embargoed if a due publication fails integrity/CAS
   checks. Version metadata, download-button version, banners and the release
   event become visible in one SQLite transaction after verification.
7. Verify both ABI update APIs and HTTPS downloads after publication. A banner
   signal proves publication, **not** that every handset has already received a
   push. Devices learn the release on their next policy/update refresh; Android
   notification permission and OS background restrictions still apply.

## GitHub prerelease timing

Prepare a **draft prerelease** with tag `v5.11.2`, both APKs, matching
`release-metadata.json`, `build-info.json` and each `*.apk.sha256` asset. The tag
without `v` must exactly match APK and metadata versionName. Keep GitHub Actions
enabled independently; the local release need not wait for remote builds.

Publishing the prerelease early makes it visible to the application's Beta
updater immediately. For a strict midnight release, keep it draft until the
Moscow schedule fires, then publish the draft via an explicitly configured
scheduler/operator action. The VDS APK scheduler **does not publish a GitHub
draft** and this deployment utility does not accept GitHub credentials. Do not
claim GitHub timing is configured until its separate action has been tested.

Run scheduler regressions without SSH or real builds:

```powershell
py -3.14 -m unittest discover -s tools -p test_scheduled_apk_release.py -v
```
