# Quantum Pulse / Network center

Panel build: `2.3.0-pulse.1`. This is a panel-only change; Android version,
release schedule, APK artifacts, subscriptions and existing VPN keys are not
changed by its deployment.

## Operator workflow

Open `/operator?tab=network`. The consolidated section has six views:
overview, nodes, DNS, routes, AI and Telegram MTProto. Existing detailed URLs
remain available. Cards use registered nodes and actual server measurements;
server TCP RTT is not a user's phone ping or a VPN throughput measurement.

The route laboratory accepts one public IP or IDNA domain, without resolving
it or probing arbitrary targets. It explains signed APK-rule precedence and
server Xray first-match behavior separately. Its server scenario is explicitly
`vless-in / TCP / 443`, not an observed subscriber session. Geosite, GeoIP,
regular expressions or missing/truncated context remain unknown rather than
being reported as a successful bypass. Domain/CIDR conflicts are bounded;
CIDR checks use an interval sweep rather than a full cross product.

DNS and route controls reuse the existing draft, staging, preview, confirmation,
signed publication and revision rollback handlers. Saving a draft does not
publish it. Return links preserve the Network view and policy source. Missing
drafts or staging revisions visibly fall back to production.

## Bounded automation

The model remains a local adviser. Typed, measured node automation is separate
from model prose and only changes existing panel recommendations/quarantine.
It neither allocates IPs nor provisions imaginary regional nodes, executes
model-generated commands or switches active VPN sessions.

Default policy: observe every 60 seconds, at least three consecutive checks,
900 seconds between changes. Allowed intervals are 60–3600 seconds,
cooldowns 300–86400 seconds, and 3–10 checks. Healthy current nodes, stale
reports, lack of a proven reserve and manual overrides prevent unnecessary
changes. Settings/topology compare-and-swap and post-change checks protect
pending rollback. Freeze/restore controls are explicit operator actions.

The action journal records a checked plan before changes, the applied decision,
reason, typed measurements, before/after and rollback scope. Node aliases,
numbers and fixed text are used; arbitrary logs, model prose, credentials and
targets are not copied to the journal or its Telegram message.

Real WARP IPv4/IPv6 is supported by the existing userspace egress. A `104.*`
address is IPv4; there is no fake routable IPv6 or millisecond IP rotation.
The fixed SOCKS diagnostic proves WARP egress health only, not subscriber
first-match routing, universal access, or a guaranteed 50 ms phone ping.

## Own Telegram proxy

The installer uses official Telegram MTProxy source pinned to commit
`f36d8af769ffaeac36978d38c2c0f6d1104c2137`, with a narrowly scoped local
`--secret-file` patch. Source and patch hashes are retained in install metadata.
The patch prevents a client secret appearing in process arguments. It is not
an unmodified upstream binary or a fake API.

Runtime: `/opt/quantumvpn-mtproto`; private configuration:
`/etc/quantumvpn-mtproto`; service: `quantumvpn-mtproto.service`.
The dedicated unprivileged service listens on public TCP 3443; stats listen
only on `127.0.0.1:18888`. systemd supplies read-only credentials and applies
filesystem, privilege and resource restrictions. Plain private files require
root ownership and mode 0600. systemd credential reads also validate their
read-only mount and exact root/service ownership and 0400/0440 modes.

Ordinary panel GET/status/journal responses do not contain a proxy secret.
An authenticated owner explicitly requests connection links through a
CSRF-protected POST, with no-store/no-referrer responses. Start, stop and
restart are fixed service commands and require an additional confirmation.
Operator/viewer roles cannot reveal the secret or control the proxy.

Health verification performs an obfuscated padded MTProto `req_pq_multi`
request and verifies the nonce in Telegram's `resPQ` response. This is stronger
than an open TCP port, but is not a full Telegram account/RSA-login test.
The proxy supports Telegram only; it does not route other applications.
Automatic daily refresh of upstream Telegram configuration is not included.

## Verification and deployment

Local contracts cover roles, strict public Origin and session-bound CSRF,
duplicate/body limits, typed AI writes, immutable APK/release settings, draft
navigation, publication confirmation, journal redaction, MTProto permissions,
protocol parsing and deployment rollback. Optional Passkey tests may be skipped
when their dependency is unavailable.

`tools/deploy-aurora-panel.py --with-local-ai --with-pulse` verifies previous
source hashes, creates a private source/database snapshot, and checks production
API metadata plus protected configuration. Apply restarts only the additional
panel. Failure restores source, not a stale live database snapshot.

`tools/install-mtproto-vds.py` defaults to read-only inspection. Apply refuses
busy ports/unmanaged paths and reuses a verified managed install. A failed new
install is stopped and moved into a private recovery directory; it does not
remove existing VPN configuration, nginx, DNS, subscriptions or credentials.

`tools/verify-network-pulse.py --require-mtproto` is a read-only post-deployment
gate. SSH uses pinned known_hosts. Its short-lived owner cookie stays on the
VDS; no cookie, HTML, config or credential is printed. It checks all six views,
both ARM production API variants and HTTPS download HEAD responses, both WARP
IP families and MTProto readiness. Diagnostic output is allowlist-redacted.

### Verified deployment

On VDS `150.241.96.191`, build `2.3.0-pulse.1` was applied and the live
read-only gate passed. Private source/database snapshot:
`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-6046d05b7ff44322b0294da2873bd3e3`.
Protected configuration, public API metadata and signing identity were unchanged.

Both panels are active. All six Network views return 200 with no-store,
credential-free ordinary pages and CSRF on writable forms. The laboratory
renders Instagram-domain and public-IPv6 results with its stated scenario.
Both ARM legacy/updater APIs still return `5.11.4 / 501104099`; TLS-verified
APK HEAD responses are 200 and match declared sizes.

MTProto installation passed a local nonce proof at 16 ms and a public proof
from the PC at 132 ms (single protocol checks, not throughput promises).
The live gate reports an active proxy, 19 ready upstream targets and
loopback-only statistics. Existing protected VPN/nginx/DNS files were unchanged.
WARP IPv4 and IPv6 fixed diagnostic TLS traces both return 200 with `warp=on`.

257 focused automatic tests passed, with two optional Passkey dependency skips.
The separate legacy operator/routing suite also passed. A large valid DNS form
above 256 KiB saves all 2,000 rules; routing bodies are read fully within a
4 MiB limit rather than silently truncated. Oversize, duplicate singleton and
missing Network action requests are rejected without settings mutations.
Policy source survives local tab switches and preview cancellation.

Two failed new proxy attempts were stopped and retained privately for recovery,
not left as running competing services. Temporary diagnostic units/files were
removed; user VPN data was not removed. No Android build/publication was done.
