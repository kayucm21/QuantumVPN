# Local AI and factual backup reports: production verification

Verified on 2026-10-06, approximately 15:00–15:06 Moscow time.

## Installed and active

- Operator panel build: `2.2.0-operations.1` on the existing VDS.
- Official llama.cpp `v0.6.0 / b11429`, commit
  `d81235049384534c167caea52b85a694f6103d14`, with pinned release and model hashes.
- Existing Qwen3 0.6B GGUF reused read-only; no cloud API or duplicate model download.
- Real structured inference passed: 581 prompt tokens, 145 completion tokens.
- `ai_engine=llama.cpp`, advisor enabled and measured registered-node controller enabled.
- Current registered node is healthy; zero automatic topology changes were needed.
- Idle unload verified: service remains ready, `sleeping=true`, `resident=false`.
  Process RSS dropped from about 1073 MiB loaded to about 161 MiB idle.
- Main panel, additional panel, Xray, reserve Trojan, and local inference services active.

## Reports and backups

- A new encrypted configuration backup, 1,478,338 bytes, was actually delivered
  to the existing authorized Telegram chat.
- Its factual full status report was delivered as a reply to the archive message.
- The report correctly includes current successful delivery, Moscow timestamps,
  actual CPU/RAM/disk measurements, runtime/model identity, release state,
  and existing private read-only commands.
- Hourly backups use the same delivery hook; changing AI phrasing alone no longer
  produces Telegram messages. Problem/recovery alerts use observed-state fingerprints.
- No token, password, subscription URI, raw client identity, or model prose is
  included in the status report.

## Preservation and cleanup

- Public APK remains `5.11.3`, code `501103099`; neither APK was rebuilt or changed.
- Both ABI update APIs return 200; both HTTPS APK HEAD requests return 200.
- Routing revision remains 7 and signing identity is unchanged. Database quick check: `ok`.
- Source deployment creates a rollback snapshot, compares hashes and configuration,
  and verifies signed public APIs before accepting the replacement.
- The first restart verification timed out on a cold update API and source files
  were rolled back automatically. Cleanup startup was delayed and cold checksum
  probes bounded at 30 seconds; the subsequent deployments passed all baselines.
- Removed only the old ARM64 and ARMv7 temporary APK duplicates in `/tmp`,
  262,722,794 bytes combined (about 251 MiB), after matching permanent-file SHA-256.
  The permanent downloads remain available, so the removed copies are recoverable.
- The full migration backup was retained. Measured disk usage after the work: 40.67%.
- Plain backup ZIPs are not auto-deleted even when a `.zip.enc` counterpart exists:
  that alone cannot prove its integrity. Published APKs and encrypted backups are
  not temporary cleanup candidates.

## Android scope and limits

- APK already uses sing-box/libbox, not Xray-core, and supports Trojan import and TLS.
- The existing reserve Trojan endpoint passed TLS certificate/hostname verification.
- No Android device was connected, so no end-to-end phone VPN test is claimed.
- Current Android policy parser ignores panel recommendation/quarantine fields.
  This controller manages the panel only; automatic phone failover requires a
  separate client change and device verification.
- New physical VPN servers require real infrastructure and cannot be fabricated
  by the model. Server-side TCP checks do not measure client speed or prove TSPU.

## Local regression gates

- Full tools suite: 373 tests passed before the final conservative ZIP-retention change.
- Final relevant suite: 72 tests passed, including corrupt encrypted counterpart
  retention, backup/report delivery, measured failover/rollback, adapter boundaries,
  Telegram report limits and deployment scope/rollback.
- Main branch only; no APK release or release tag created by this work.

See [controller and deployment design](LLAMA-NODE-AUTOPILOT.md).
