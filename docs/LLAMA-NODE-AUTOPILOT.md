# Local llama.cpp node operator

`llama.cpp` runs model inference; Qwen3 0.6B supplies the existing local model
weights. The integration adds typed structured analysis and automatic control
of already registered nodes. It cannot create a physical server or replace a
failed single-server installation with a fabricated reserve.

## Pinned runtime input

Official source: <https://github.com/ggml-org/llama.cpp>.
Installed official stable release on 2026-10-06: `v0.6.0` / `b11429`, commit
`d81235049384534c167caea52b85a694f6103d14`. Source checkout:
`/opt/quantumvpn-ai/llama.cpp-source`.
The verified official CPU binary artifact SHA-256 is
`f6d25dde8f51133143d1453da4fd5f73b145127177612a283bf7995957af3392`.
Keep the immutable version, release artifact checksum and GGUF checksum in the
deployment manifest; do not resolve mutable `master` during deployment.

The inspected server already has this model file:

`/usr/share/ollama/.ollama/models/blobs/sha256-7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa`

Expected SHA-256: `7f4030143c1c477224c5434f8272c662a8b042079a0a584f0a27a1684fe2e1fa`.
Expected size: 522640096 bytes; GGUF magic. Reuse the verified file read-only,
with filesystem access for the unprivileged runtime, instead of downloading or
duplicating model weights. The source build needs CMake, make and a C++ compiler.

```sh
cmake -B build -S . -DGGML_NATIVE=OFF -DGGML_CUDA=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON
cmake --build build --target llama-server -j 1
```

Retain runtime shared libraries from `build/bin` together with the executable.
Disable optional remote download dependencies where required by the pinned
version/build environment. Test `llama-server --version` before activation.

## Runtime limits

Use a dedicated non-root systemd service on loopback. Installed 2-CPU/4-GB
server limits: `Nice=10`, `CPUQuota=80%`, `MemoryMax=1400M`, one inference slot,
read-only model/source directories and `NoNewPrivileges=yes`. Limit journal
retention and do not log prompts. Suggested executable arguments:

```sh
llama-server --host 127.0.0.1 --port 11435 --alias quantum-qwen3-0.6b \
  -m /verified/read-only/model.gguf --ctx-size 2048 --threads 1 \
  --threads-batch 1 --parallel 1 --batch-size 128 --ubatch-size 64 \
  --n-predict 400 --no-webui --no-slots --offline --sleep-idle-seconds 120 --reasoning off \
  --chat-template-kwargs '{"enable_thinking":false}'
```

Do not enable `--tools`, `--agent`, MCP, POST `/props`, local media access or
external binding. Run scheduled inference no more often than once per ten
minutes. `quantumvpn_llama.analyze` enforces one concurrent request, 400 output
tokens, 90-second request timeout, 24-KiB request and 32-KiB response budgets.
Measured CPU/RAM >=85% skips inference. The deterministic network controller
continues independently. Idle sleep unloads model/KV memory; `/health` and
`/props` do not wake it.

Official API and options:
<https://github.com/ggml-org/llama.cpp/blob/d81235049384534c167caea52b85a694f6103d14/tools/server/README.md>.
Build instructions:
<https://github.com/ggml-org/llama.cpp/blob/d81235049384534c167caea52b85a694f6103d14/docs/build.md>.

## Panel hooks

Import the two sibling modules as `llama` and `autopilot`. Production settings
keep `ai_model=qwen3:0.6b` and use `ai_engine=llama.cpp`; the adapter sends runtime
alias `quantum-qwen3-0.6b` to the local service. Set
`ai_autopilot_enabled=1` only for the user-authorized automatic operating mode;
`0` stops new automatic actions. There is no cloud API key.

```python
registered = parse_node_map_config(settings["node_map_config"])
guard = network_guard_snapshot(db)
plan = autopilot.plan_actions(guard, registered, settings, now=now)
analysis = llama.analyze(ai_operations_snapshot(db, settings),
                        allowed_actions=plan["allowed_actions"])
result = autopilot.execute(db, guard, registered, now=now,
                          proposals=analysis["analysis"]["recommendations"])
db.commit()
```

Also call `autopilot.execute` immediately after fresh network monitor collection,
even when local inference is unavailable. Avoid running the older independent
automatic quarantine controller simultaneously: it has its own ownership and
could exclude the sole configured server. Keep manual drains/forbidden nodes
enabled; the autopilot respects them.

Display `llama.local_status()` readiness, active inference and sleeping/resident
flags accurately. It queries only fixed `127.0.0.1:11435` endpoints without
using ambient HTTP proxies or following redirects. Report runtime `llama.cpp`
and model `Qwen3 0.6B` separately. Plain three-line `advice` is returned for
display; Telegram formatting should escape/format it deliberately. Model prose
must not replace recorded action results or the actual backup delivery status.

## Automatic operations

Freshness is at most five minutes. A TCP stage needs at least three consecutive
failure/regression checks before exclusion. A reserve needs at least three
successful checks and no measured degraded DNS/TLS stages. Only registered
identities are eligible; public diagnostic targets never become VPN nodes.

The controller can:

- Temporarily quarantine a repeatedly degraded registered node when another
  proven healthy node is available.
- Recover an automatically quarantined node owned by this controller after
  repeated healthy checks; leave manual/other-controller exclusions intact.
- Set the panel's recommended registered reserve when the selected node is
  unavailable. Preserve a healthy current selection to avoid switching on small
  latency changes.
- Roll back its own settings if the new selection repeatedly fails and the
  previous selection is freshly healthy. Confirm success after three distinct
  post-change checks, with a 15-minute normal action cooldown.

Allowed mutable settings are `node_quarantine`, `nodes_recommended`,
`load_balancer_last_target`, `load_balancer_last_decision`, plus durable
`ai_autopilot_state`. A SQLite savepoint makes settings and audit atomic within
the caller's transaction. Pending changes record before/after values; any
manual modification cancels the old rollback. It never issues commands,
restarts tunnels, rewrites subscriptions, changes TLS/keys or touches admin
access. A single failed node without a real reserve is reported and monitored.

TCP availability does not measure client speed or prove TSPU involvement.
Automatic node actions use measured facts regardless of the model's wording;
unknown or fabricated model node/action values are rejected. New server
provisioning requires an actual provider/API/account and is outside these hooks.

## Current Android integration limit

The current APK's `ClientPolicy` and `ClientPolicyRepository.parsePolicy` do not
read `nodes_recommended`, `nodes_forbidden`, `nodes_quarantined`, `nodes_draining`
or `load_balancer`. These fields are published by the panel, but the installed
APK ignores them. The changes therefore provide real panel management and
auditable node settings; they do not automatically change the selected server,
apply node exclusions or fail over an existing phone connection. Supporting
that behavior requires a separate client integration and verified Android
release. Do not describe panel/VDS checks as improved measured phone latency,
throughput or proof of YouTube quality.

## Encrypted backup and factual report delivery

`create_backup_archive()` takes consistent SQLite snapshots of the operator and
main panel, plus available restoration-critical signing/session keys, and
returns an AES-GCM encrypted `.zip.enc` archive. The external decryption key and
environment secrets are not embedded. Plain temporary archives/databases are
removed after encryption or handled by the failure path. Encrypted local
backups follow the existing seven-day retention policy.

`send_backup_report(db, settings, archive, kind="hourly")` first delivers the
encrypted archive with a short factual caption, records its delivery receipt,
then replies to that Telegram document with the full status report. It records
separate `archive_sent` and `report_sent` results in `backup_report_delivery`.
The report uses measured resources, service status, persisted actions and
actual delivery records rather than generated model prose. A failed delivery
must remain a recorded failure; a successfully created file does not prove
Telegram received it. `hourly_backup_worker` calls this hook each wall-clock
hour when delivery is enabled; manual backup delivery uses the same hook.

## Owned temporary cleanup

`quantumvpn_maintenance.cleanup_managed` inspects direct files in validated
absolute backup, download and `/tmp` directories. It refuses symlinks and does
not recursively delete directories. Its precise eligible names are:

- Backup `.operator-<timestamp>.db` and `.rospanel-<timestamp>.db` intermediates
  older than 24 hours.
- Recognized temporary QuantumVPN ARM APKs in `/tmp`, older than 48 hours and
  at most 256 MiB, only when the permanent version/ABI download is a regular
  byte-identical file verified by SHA-256.

Plain backup ZIPs are retained for investigation even with an encrypted
counterpart: its existence cannot prove authenticated, equivalent contents.
Normal encryption already removes the plain intermediate after atomic save.
Published APKs and encrypted backup files are not cleanup candidates. Before
unlinking, the hook rechecks inode, size, modification time and containing
directory. It records reclaimed bytes and reasons, so a 41% disk figure is not
treated as proof of garbage or a promise of a particular reclaimed size.
`maintenance_worker` runs this bounded cleanup hourly and records material
removals; manual maintenance uses the same criteria.

## Verification

`tools/test_llama_autopilot.py` covers local transport/schema and secret
filtering, single inference/resource limits, missing tools, measured failover,
last-node availability protection, manual limits, ownership-preserving recovery,
rollback/cooldown, three distinct post-change checks, atomic audit and outer
transaction rollback. Run:

```sh
PYTHONPATH=tools python -m unittest tools.test_llama_autopilot -v
```

Runtime deployment remains a separate step: inspect the real service health,
run one real schema-constrained request, confirm sleep/RAM behavior and public
panel/VPN checks before selecting the runtime in production settings.
