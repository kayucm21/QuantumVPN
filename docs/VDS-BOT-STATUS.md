# Quantum Control Bot on VDS

Updated 5 October 2026. Operator build: `2.1.1-bot.1`.

The existing `@Bepakovac_bot` now accepts commands in the configured owner's
private chat. No new bot token, external AI subscription or channel credentials
were introduced. APKs remain in VDS storage. The owner cancelled the local
GitHub publication task, so the PC and Codex may be switched off.

## Commands and real measurements

- `/status`: aggregate AI, VDS, release, delivery and backup status.
- `/ai_status`, `/check_updates`, `/backups`: the same complete status view,
  including their respective sections.
- `/get_stable`: the currently public VDS APK links for ARM64 and ARMv7;
  respects maintenance, download closure and the scheduled release embargo.
- `/get_dev`: explains that no separate public Dev release is configured.
- `/start`, `/help`: read-only command help.

The report shows CPU utilization sampled from `/proc/stat`, RAM usage from
`MemAvailable`, actual filesystem usage, allowlisted service state, and server
probe aggregates. Probe latency is explicitly not described as client ping.

The real installed model is local `qwen3:0.6b`. Installed catalogue presence and
loaded/resident model state are separate; unavailable inventory is unknown,
not zero or proof of absence. Model memory, active analysis, 30-day analysis
counts/success rate and the last analysis are evidence-based. The bot does not
invent Gemini availability, conversations, API key rotation or MTProto channels.
The existing AI remains an advisor; these commands add no infrastructure-write
authority or arbitrary shell execution.

Release delivery counts distinguish notification received, download complete,
installer handoff and app launch. They are distinct-device self-reports, not a
claim that Telegram reached every subscriber or that installer handoff means
installation. Hourly encrypted backup delivery uses the existing enabled worker;
the report shows the actual last delivery result and stored backup metadata.

## Security and operational boundaries

- Only the exact configured positive private chat ID and matching non-bot sender
  may issue commands. Groups, forwards, edited updates and foreign users are
  ignored. Qualified commands require the username verified through `getMe`.
- A single Linux process lock owns polling. The receiver refuses an existing
  webhook or a competing-poller conflict; it never deletes a webhook.
- Telegram requests are method-allowlisted, size-bounded and do not follow
  redirects. Token-bearing URLs and raw remote exceptions are not logged.
- Persisted cursors prevent duplicate replies across restarts. At-most-once
  replies mean a failed send is not replayed; the owner can request status again.
- Five-second spacing and a 30-reply/five-minute cap limit command traffic.
  Status output contains no subscriptions, account IDs, passwords or API keys.
- Deployment uses pinned SSH host trust, old-source hash guards, private source
  and SQLite backups, and source-only rollback. Only the operator service is
  restarted. VPN engines, RosPanel subscriptions, signing keys and APKs are
  not modified by this update.

## Verification

- All **259** Python unit and real loopback HTTP tests passed, including **46**
  bot status/receiver tests and **16** deployment-helper tests.
- Independent read-only review found no serious owner-auth, secret-output,
  release-embargo or polling-concurrency issue. Its model-catalogue unavailable
  finding was fixed and covered by failure/success-path regression tests.
- Live Telegram `getMe` authenticated `Bepakovac_bot`; no webhook was configured.
  All eight private-chat menu commands were registered. The persisted receiver
  heartbeat was fresh, and Telegram accepted the owner confirmation message.
- SQLite integrity remained `ok`; operator, RosPanel and existing services stayed
  active. Both production ABI APIs still returned `5.11.2 / 501102099`, with
  VDS download URLs; current APK HEADs returned 200 and scheduled APK HEADs 404.
- The scheduled release remains **6 October 2026, 00:00 Moscow**
  (`2026-10-05T21:00:00Z`, epoch `1791234000`), version `5.11.3`.
  No early publication occurred. The server's release worker, not a local PC
  task, owns the release and its notification.
- First deployment backup:
  `/var/lib/quantumvpn-operator/aurora-source-backups/aurora-e1fa648047fd42bc96e0b38beb3086da`.
- Final verified deployment (including the unavailable-catalogue fix):
  `/var/lib/quantumvpn-operator/aurora-source-backups/aurora-8a2679b85d7e4d9b99c7cbf52fe8c3e9`.

No physical Android/device tests or APK rebuilds were performed for this bot-only
update. Incoming human `/status` interaction is not claimed as a live test:
authorization and reply behavior were tested offline, while polling, menu and
outgoing confirmation were verified against the real bot.
