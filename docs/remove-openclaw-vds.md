# Scoped OpenClaw removal

The owner requested complete removal of the active OpenClaw installation on
2026-10-12. `tools/remove-openclaw-vds.py` defaults to read-only inventory and
requires the existing pinned SSH host key plus a transient password environment.
Do not put credentials in source, shell arguments, output or committed files.

## Exact scope

The removal targets are:

- `/etc/systemd/system/quantum-openclaw.service`;
- `/opt/quantum-automation/releases/q4-20261010/openclaw`;
- `/var/lib/quantum-automation/openclaw`, including its configuration and sessions;
- `/etc/quantum-automation/access.json`;
- the isolated `qvpn-openclaw` user/group, UID 985 / GID 979.

The shared Node.js release, build account, existing Ollama/Qwen service/model,
VPN, both panels, DNS, Telegram proxies, subscriptions and APK releases are not
removal targets. Historical installation/diagnostic records and backup archives
are preserved. Recovery of deleted working state requires a previous backup.
Old source helpers are historical provenance, not authorization to reinstall.

The existing manifest/journal become credential-free Node-only proofs. The old
completed conversion record becomes a neutral retired audit. The removal intent
stores hashes and generated Node-only metadata, never recovery copies of a live
Gateway token. The server access file and runtime configuration are removed.

## Guards and resumability

Before a first mutation, the completed installation provenance, fixed paths,
unit bytes, UID/GID pairs, config policy and shared Node file digests are checked.
Every ancestor is traversed using no-follow directory descriptors. Recursion
rejects mounts, different devices, foreign owners and special files; internal
dependency symlinks are unlinked rather than followed. Target/parent inode
identities are checked again immediately before removal.

An exclusive installer lock and owned-worker/process checks prevent concurrent
installer writes. Only the exact OpenClaw unit is stopped/disabled. Its
PrivateTmp lifetime is managed by systemd. No arbitrary command API, model
inference, manager-journal diagnostics, firewall or network changes are used.

Durable per-target checkpoints and fsync precede deletion. Only started/done
targets may be absent during an explicit resume. Generated records use atomic
compare-and-swap replacements. Post-removal requires absent targets/account,
`LoadState=not-found`, inactive/dead unit with PID 0, no OpenClaw processes and
no listener on 18789. Protected configuration hashes and previously active
services must remain unchanged.

Available modes (supply the password transiently outside these arguments):

```text
python -B tools/remove-openclaw-vds.py
python -B tools/remove-openclaw-vds.py --apply --start-worker
python -B tools/remove-openclaw-vds.py --worker-status <owned-job-id>
python -B tools/remove-openclaw-vds.py --apply --resume --start-worker
```

The fixed worker has a 1800-second deadline, 320 MiB memory maximum, no swap,
CPU quota 20% and IOWeight 10. It operates independently of the local PC/SSH
connection. Resume only after inspecting the previous worker and confirming
that it no longer runs; never dispatch competing removals.

30 offline tests cover scope rejection, no-follow traversal, mount/owner guards,
CAS/refused drift, partial recovery, credential-free metadata, exact account
removal, missing-unit detection and completed read-only mode without writes.
Existing installer/migration/scratch suites remain unchanged.

## Production verification

The fixed worker `8e0704e0729448b18efa7be794a7f2e8` completed with
`OpenClawRemoved`, exit status 0, active/exited and protected configuration
unchanged. A fresh read-only inventory at 2026-10-11 16:28 UTC (2026-10-12 in
Asia/Irkutsk) independently confirmed state `done`, absent targets/account/unit,
no PID or listener on 18789 and preserved shared Node/Ollama. Its pre-deletion
scope had 42,018 files / 685,047,474 logical bytes; that is a logical file-size
count, not an exact physical disk-space measurement.

The fresh read-only network verification also passed: both panels active, six
authenticated views HTTP 200 with valid CSRF and no nested forms/credential
exposure, both ABI release APIs and verified HTTPS APK HEADs available, MTProto
active with 19 ready upstreams. APK remains 5.12.0 / 501200099. WARP diagnostic
IPv4/IPv6 HTTPS probes passed; these VDS checks do not prove phone performance or
subscriber route selection. No application release or update time changed.

All 30 removal tests pass. The combined unchanged installer/migration/scratch
and new removal suites ran 108 tests: 107 passed, one external opt-in test skipped.

The old private Windows `access.json` is a historical handoff and is not part of
the active server installation. Its earlier guarded rewrite was denied by local
tool policy; that action is not retried through an alternate execution path.
Its README must mark the retired service/token unusable after removal. Existing
owner-only Windows ACLs are not broadened.
