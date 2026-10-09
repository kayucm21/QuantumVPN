# Quantum Control bot operations · 2.3.0-pulse.6

Scope: VDS bot, registered-node advisor and proxy observations only. Android
5.11.4 / 501104099, APK artifacts, signing keys, client proxy secrets and release
schedule are unchanged. This is not model training, GPT equivalence or guaranteed
protection against blocking or upstream link saturation.

## Monitoring and authority

- Resource/service/factual incident worker: 60 seconds, three spaced valid
  samples for new incidents and recovery. Missing telemetry retains an open
  incident, never implies recovery. State and fingerprint acknowledge delivery
  only after Telegram succeeds; failed/cooldown candidates remain retryable.
- Registered-node measurements retain the existing 30-second cadence. Proxy
  nonce observations have a 300-second TTL. Reading a cached result does not
  increment confirmation: the three confirmations need three distinct probes.
- Qwen3 0.6B runs locally through llama.cpp. Existing analysis interval is
  900 seconds; no inference under high measured CPU/RAM. Static knowledge adds
  DNS/TCP/TLS distinctions, registered-reserve checks, backup validation and
  MTProto/client-path distinctions; it does not alter model weights.
- Model output is a typed proposal, never shell code. Existing executor admits
  only registered nodes with fresh repeated evidence, manual restrictions,
  cooldown, post-change verification and compare-and-swap rollback. Millisecond
  IP/key/port rotation is not enabled. It would disrupt sessions, not fix physics.
- Only confirmed factual transitions go to Telegram; rewritten model prose and
  raw exceptions/targets no longer create independent alert streams.

## Telegram proxy evidence

Read-only bounded protocol probes cover MTProto 3443, native FakeTLS 5443 and
public HTTPS WEB Proxy 443. Readiness requires a matching Telegram nonce and
upstream/runtime readiness, not merely an open TCP listener. Private stats,
relay and admin ports are inspected for loopback-only binds.

On the tested PC, padded MTProto confirmed 3/3 requests in 137–143 ms.
FakeTLS initially showed transient 6.96–8.64 second requests; repeated stage
tests confirmed 249–259 ms. All three server probes passed after deployment.
These results do **not** prove the user's ISP/carrier path works without VPN,
successful account authorization, throughput, or a TSPU cause. A carrier-specific
issue on 3443 remains unresolved; existing FakeTLS/WEB links are alternative
transports, not an automatic change of the user's Telegram settings.

## Encrypted backup and reports

Each hourly/manual copy is AES-256-GCM with a fresh random nonce; the external
decryption key is not embedded or sent to Telegram. Before delivery the worker
authenticates/decrypts the archive, checks ZIP integrity and restores SQLite
files in an isolated temporary directory for integrity/schema checks. A failed
verification stops delivery of that archive. Current copy verified two databases
and all listed restoration-critical key files, with zero missing components.

The encrypted file contains panel databases and restoration-critical keys, not
a full bootable server image or all APK/source/service environment files. Tests
are explicitly not a full service start. The archive caption includes the test
result and the structured status is sent as a reply to that same file.

Owned aged intermediate cleanup remains hourly, constrained by existing managed
paths/retention and verified duplicate rules. No broad directory deletion or
live database/key removal is introduced.

## Deployment and verification

Source-only guarded deploy backup:
`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-b36e2ef38bb8459392415594707bf08c`.
Deployer verified unchanged stable configuration, public APK APIs and signing
identity. Both ABI updater/legacy APIs and HTTPS HEAD downloads returned 200;
all six network views and owner proxy links passed authentication/CSRF/form and
secret-exposure checks. One actual analysis completed successfully; Telegram
confirmed delivery of one verified encrypted archive and its report.

`tools/harden-ai-sandbox-vds.py` is additive, pinned and read-only by default;
apply only while the installed llama service is confirmed idle. It preserves
model, command line, CPU/RAM limits and network policy, and restarts only llama.
Its rollback removes only the exact managed additive drop-in. Filesystem/kernel
protections and empty process capability sets do not prevent ISP censorship.
Existing network-policy declarations are not proof of BPF enforcement.

Sandbox applied and verified: empty process capability sets, non-root model
runtime and seccomp active. Recovery snapshot:
`/var/lib/quantumvpn-ai-sandbox/sandbox-ny_h0es2`.
Only llama was restarted, while confirmed idle; model/resources/network policy
and protected VPN/panel configuration files retained their identities.

Verification commands:

```powershell
python -m unittest tools.test_bot_operations tools.test_fact_delivery tools.test_bot_status tools.test_bot_reports tools.test_proxy_monitor tools.test_ai_knowledge tools.test_llama_autopilot tools.test_operations_reports tools.test_ai_sandbox_vds tools.test_verify_bot_operations
python tools/verify-bot-operations-vds.py --probe
python tools/verify-network-pulse.py --require-mtproto
```

SSH credentials must be supplied in a temporary `QVPN_VDS_PASSWORD` process
environment, with pinned known_hosts and RejectPolicy; never log credentials.
`--send-backup` and `--analyze` are explicit real owner actions, not dry-run checks.

Final source/report patch rollback snapshot:
`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-875b4a32f01742198183f13388663c2e`.
