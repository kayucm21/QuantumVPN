# Quantum 4.0 automation stack: private native services

This deployment installs n8n and OpenClaw for the owner's internal administration,
not a public multi-tenant automation hosting product. It does not replace the
existing Quantum bot and grants neither process root access or panel credentials.

## Reviewed upstreams and version pins

Reviewed on 2026-10-10:

- Node.js **24.21.0**, official `node-v24.21.0-linux-x64.tar.xz`, SHA-256
  `fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`.
  [Official checksums](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt).
- n8n **2.42.6**, published npm package with fixed SHA-512 integrity from the
  [version metadata](https://registry.npmjs.org/n8n/2.42.6).
- OpenClaw **2026.9.9**, published npm package with fixed SHA-512 integrity from
  the [version metadata](https://registry.npmjs.org/openclaw/2026.9.9).

Dependency resolution is followed by validating each registry HTTPS URL and
SHA-512 integrity in the generated lock. Installation uses `npm ci` against this
unchanged lock. The dependency lock hash is retained in the private manifest.
This pins the resulting dependency graph after resolution; the graph is not
pre-reviewed in the repository and its first resolution is not reproducible
across time. npm lifecycle execution is restricted to required native n8n
modules (sqlite3/isolated-vm are forced to build from source, without unpinned
native prebuild downloads) and the official OpenClaw package postinstall, under a separate
unprivileged resource-bounded build account. No `curl | sh` or unpinned `latest`
installation is used.

OpenClaw's published npm dependency graph contains bundled packages: they
normally have `inBundle: true` but no separate `resolved` or `integrity` fields.
Only two exact reviewed carriers are supported: the pinned OpenClaw archive
above and npm **11.20.0**, official
`https://registry.npmjs.org/npm/-/npm-11.20.0.tgz`, SHA-512
`dF3EDFwbYN+N5RUip+ZYDe0NeURK5BgqKOcvT1iNtUYhTMTl0FwWhBuXrS7KtXyduqyTMS5aaQaregnHDAxNgw==`.
For each carrier, bounded compressed input (160 MiB / 120 seconds, 1 MiB reads)
is first spooled to a private disk-backed `TemporaryFile` and verified against
its exact SHA-512. **Only then is any gzip/tar metadata parsed.** This ordering
also prevents unverified GNU LongName/PAX headers from causing large hidden
payload allocations before member validation. No tar member is extracted or
executed; safe paths/types, 20,000 members, 512 MiB declared payload and 2 MiB
package descriptor limits are still checked on the verified archive.

Each bundled lock entry must match a real package root's exact path, name and
version inside the verified carrier. Arbitrary carriers, orphan bundles, bundles
with their own URL/integrity, external URLs and mismatches are rejected. Installed
bundled package descriptors are checked again after `npm ci` and postinstall.
On 2026-10-11, an isolated local package-lock-only audit (no lifecycle or `npm ci`)
resolved 561 lock entries, including 146 bundled entries. Both exact carrier
archives independently provided all 146 matching descriptor facts. Its canonical
lock SHA-256 was
`29e91d637fdc1b5189a3658f7a8b9c50b9f3ec057b0d20bfcf07eed26df21ca4`.
This is dependency/provenance evidence, not a successful VDS installation claim.

The [n8n npm method](https://docs.n8n.io/hosting/installation/npm/) remains
available for the pinned 2.x version; the documentation announces deprecation
from n8n 3.0. This deployment deliberately does not introduce a Docker daemon or
modify Docker firewall chains on the live VPN host.

## Licensing and realistic costs

n8n uses a [Sustainable Use License](https://github.com/n8n-io/n8n/blob/n8n%402.42.6/LICENSE.md)
for internal business/personal use, not an unrestricted OSI open-source license.
Enterprise features have separate terms. The community deployment does not
mean unlimited CPU, storage, workflow concurrency, third-party API quotas or
free model-provider calls. Do not offer this installation as paid public n8n
hosting without reviewing applicable licensing.

OpenClaw's core uses the [MIT license](https://github.com/openclaw/openclaw/blob/v2026.9.9/LICENSE).
It is an agent runtime, not a new trained model. Initial chat inference uses the
existing local Qwen3 0.6B model: no external model API key is required, but this
small model is not equivalent to a frontier GPT model.

## Installation and isolation

`tools/install-automation-stack-vds.py` defaults to read-only inventory. Explicit
`--apply` is required. SSH requires `QVPN_VDS_PASSWORD` supplied transiently and
an already pinned host key; unknown hosts are rejected.
Existing service accounts must have nonzero distinct UID/GID values and no
supplementary groups. The installer pins `/run/lock` by a no-follow directory
descriptor and opens the root-owned lock with no-follow/nonblocking flags,
rejecting symlinks, FIFOs, writable-by-others modes and inode drift. It retains
the existing root-owned `0644` lock inode (or creates `0600`); the traditional
root-owned sticky parent prevents replacement by another UID.

For durable dispatch use `--apply --start-worker` (or additionally `--resume`
after inspecting an incomplete owned installation). The bootstrap refuses a
held installation lock or any running/starting owned build/installer unit before
dispatch (a completed `active/exited` oneshot is retained for inspection).
Only the fixed reviewed installer source is uploaded, with its SHA-256 and job
identity under root-only `/run/quantum-automation-installer/<job-id>`. A bounded
named systemd worker runs independently of the SSH connection/PC; it is not a
general root command API or an AI tool. Query `--worker-status <job-id>` for
read-only identity-checked status. Private detailed diagnostics are not echoed.
The runtime `/run` job records do not survive reboot; the persistent installation
journal does, and permits a reviewed explicit resume after the old unit is gone.

Owned paths:

- `/opt/quantum-automation/releases/q4-20261010` — immutable runtime/packages.
- `/var/lib/quantum-automation/n8n` — n8n user state.
- `/var/lib/quantum-automation/openclaw` — isolated agent state/workspace.
- `/etc/quantum-automation` — root-private environment, manifest and access handoff.
- `quantum-n8n.service`, `quantum-openclaw.service` — new isolated services only.

Services run as `qvpn-n8n` / `qvpn-openclaw`, with no extra groups, capabilities,
sudo, Docker socket or host command tools. Systemd makes the system read-only,
hides protected panel/proxy state, and permits writes only in the corresponding
service state directory. Each service has CPU, process and memory limits;
combined memory maxima are 1216 MiB, with no swap. Native dependency builds have
a separate 1536 MiB / 35% CPU limit and never overlap.
Each native dependency build has an explicit 1800-second maximum. Build jobs
are restricted to one. The isolated-vm upstream install script hardcodes `-j4`
then `-jmax`; environment-only jobs=1 does not override that script. Therefore
its compilation invokes the node-gyp CLI bundled inside the checksum-pinned
Node archive directly with `--jobs=1`; package files/scripts are not modified.
SQLite3 is separately rebuilt from source. Node headers
come from the official Node HTTPS distribution and node-gyp checksum checks.

One installation-only runtime exception was approved on 2026-10-10 for
`qvpn-automation-build-955461-n8n-native.service`: after proving its exact
unprivileged account/PID/held installer lock, both existing panels active, two
CPUs and 1.41 idle-core equivalents over three seconds, its CPU quota was
changed **35% → 55%** with `systemctl set-property --runtime` (exit code 0).
The same PID, 1536 MiB memory limit, zero swap and 1800-second deadline were
verified unchanged. No VPN, panel, model or other unit received this change;
the default future build quota remains 35%.
That attempt reached the explicit 1800-second timeout with 20/27 isolated-vm
objects compiled, before package promotion. The parent exited, lock was free,
and no owned build/service remained active before the single-job resume path
was allowed. Package caches/stages belonging to the failed build were cleaned
by its existing scoped finalizer; protected panel state was not removed.

Both editors bind only to loopback. No firewall, DNS, nginx, VPN, proxy secret,
subscription or Android build changes are performed. There are no public
webhook endpoints in this initial private deployment. n8n code, host shell,
file and SSH nodes are excluded; environment access and community packages are
disabled. OpenClaw starts with **all model tools denied**, browser/canvas,
discovery, periodic heartbeat and Telegram channels disabled. The existing bot
token is not reused or taken over. Tools may later be added only as a reviewed
allowlist and isolated execution contract, not by granting unrestricted root.

## Access

Create an SSH tunnel from a trusted computer:

```powershell
ssh -N -L 127.0.0.1:5678:127.0.0.1:5678 -L 127.0.0.1:18789:127.0.0.1:18789 root@150.241.96.191
```

Then open `http://localhost:5678/` for n8n or `http://localhost:18789/` for
OpenClaw. The SSH tunnel protects transport; these URLs do not expose public
HTTP ports. Use localhost, not a public VDS IP. Complete n8n's first-run owner
setup with the owner's chosen email/password. There is no invented preconfigured
email account and no existing panel password reuse.

OpenClaw requires the generated gateway token from
`/etc/quantum-automation/access.json` (root-only `0600` under a `0700` directory).
The token is not printed by the installer, placed in shell arguments or committed.
An access document can be delivered separately through an authorized private
file handoff. It is not a public URL to share with users.

## Verification and failure behavior

Offline tests verify version/digest pinning, dependency lock rejection, safe
Node archive extraction, loopback binding, tool denials and service isolation.
The remote application requires free ports, enough available memory/disk and
build prerequisites. Existing foreign paths/users/units are refused.

Before installation, protected configuration hashes and active services are
recorded. After start, HTTP checks require n8n's database-connected/migrated
`/healthz/readiness` plus editor `GET /`, and OpenClaw's UI. Loopback-only listeners and
protected configuration are checked before enabling boot startup. On failure,
newly created services are stopped/disabled; owned state and private diagnostic
logs are retained rather than deleted. A failed incomplete installation is not
silently overwritten on retry: inspect the fixed secret-free failure code, then
use `--apply --resume` only for the reviewed owned installation. A root-private
`install-journal.json` pins the installation identity, versions, completed
dependency locks, exact file digests and configuration write intents. Drift,
foreign paths and unjournaled existing files are refused; no state directories
are recursively deleted to make a retry pass. An interruption between runtime
promotion and recording its completed checkpoint still requires inspection.
Read-only inventory verifies the managed immutable manifest and rejects drift.

Before either service starts, the pinned OpenClaw runtime validates its own
configuration in a resource-bounded unprivileged process. Managed configuration
is read-only to the runtime. The selected 16,384-token model context exceeds
the actual pinned 2026.9.9 context guard's 4,000-token hard floor and 8,000-token
warning floor. This is a schema/runtime compatibility check, not evidence of
model quality or a successful inference. The separate explicit `--model-smoke`
command checks both health endpoints, authenticated Gateway runtime settings,
then runs one bounded no-tools local-model reply through the Gateway (not an
embedded fallback). Gateway credentials are read from managed state, never
placed in arguments or printed. Full diagnostics stay root-private; only the
successful Gateway run-ID proof (the ID itself is not echoed), nonempty-response,
exact Ollama/Qwen provider/model
and timing facts are returned. The integrity-verified pinned
`agent-via-gateway-MB8SBICx.mjs` was inspected: its non-local dispatch rethrows
Gateway errors rather than falling back to embedded inference. This test
creates one owned chat session and diagnostic file but sends no Telegram reply.

This installer proves service availability, isolation and health; it does not
prove a working Telegram integration, automated node administration or model
answer quality. Those require separate configured credentials, scoped workflow
reviews, functional tests and approval gates.

Security references:
[n8n node exclusions](https://docs.n8n.io/hosting/securing/blocking-nodes/),
[n8n environment/security controls](https://docs.n8n.io/hosting/configuration/environment-variables/security/),
[OpenClaw hardened baseline](https://docs.openclaw.ai/gateway/security/hardened-baseline),
[OpenClaw tool policy](https://docs.openclaw.ai/gateway/config-tools/tool-policy),
[OpenClaw Ollama configuration](https://docs.openclaw.ai/providers/ollama/configuration).
