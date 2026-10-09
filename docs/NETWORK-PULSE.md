# Quantum Pulse / Network center

Panel build: `2.3.0-pulse.3`. This is a panel-only change; Android version,
release schedule, APK artifacts, subscriptions and existing VPN keys are not
changed by its deployment.

## Operator workflow

Open `/operator?tab=network`. The consolidated section has six views:
overview, nodes, DNS, routes, AI and Telegram. Existing detailed URLs
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

### Search and selected target checks

Overview, DNS and routes expose the existing owned target catalog in a modal.
Search and IPv4/IPv6 filters use bounded SQL over existing catalog rows, not a
network-wide scan. Domains, subdomains, public addresses and CIDRs retain their
source provenance; CIDRs are not expanded into hosts. Pages contain at most 50
records and a check contains at most 24 selected public hosts. Each selected
result shows actual resolved IPv4/IPv6, TCP/443 and its timestamp in Moscow time.
This is a point-in-time VDS connection measurement, not phone ICMP ping, proof
of application login or an arbitrary port scan. Unknowns stay unknown.

The Network forms preserve strict Origin/CSRF, one live scanner/dialog ID set,
session-bound scan evidence and draft-only confirmation. Viewer accounts can
search but cannot probe or apply recommendations. The check always uses the
current routing draft (production fallback if none); it does not automatically
publish rules or add a third-party service IP as a VPN node.

Detector404 was inspected through its public documentation only. Its API uses
an account Bearer token; its terms prohibit automated requests without
permission. No API requests, scraping, scheduled importer or database copy
were performed. An authorized export/integration requires appropriate access
and permission. The documented monitored service URLs are not a promise of
every Internet IPv4, IPv6 address or subdomain.

Sources: https://detector404.ru/doc/api and https://detector404.ru/doc/legal.

## Bounded automation

The model remains a local adviser. Typed, measured node automation is separate
from model prose and only changes existing panel recommendations/quarantine.
It neither allocates IPs nor provisions imaginary regional nodes, executes
model-generated commands or switches active VPN sessions.

The local llama adapter retains strict output validation. Generation now
restricts recommendation objects to exact allowed node/action pairs (empty
array when no actions are eligible), rather than allowing invented pairs and
only rejecting them afterwards. Failures retain their existing category plus
an allowlisted diagnostic reason, never raw model text or exception output.
The bot formats that reason and explicitly separates an AI-analysis error from
a confirmed VPN outage. Successful runs clear the previous reason; unchanged
issues remain quiet. Limits remain 400 output tokens, 90 seconds, one analysis
at a time and resource-pressure deferral.

The reported historical failure was stored as `invalid_response`; its actual
model text was not retained. Runtime crash, OOM and output truncation were not
proven. Three bounded, read-only aggregate replays accepted the old contract,
so the new enum reason is necessary to diagnose any recurrence precisely.

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

### Connection links and Telegram WEB Proxy

The Telegram view contains separate MTProto and WEB cards. Owner-only reveal
uses the existing strict Origin, session CSRF and bounded POST endpoint. With
JavaScript it stays in the current view; without JavaScript a separate no-store
page exposes the same controls. Links are validated as an exact matching native
Telegram/t.me pair before HTML rendering. Each link can be copied, opened or
visually hidden. Clipboard writes require a button click; clipboard content is
never read, and links are never saved in browser storage or audit payloads.
Hiding a revealed key is not revocation.

WEB means Telegram's official `telegramdesktop/tproxy-server`, pinned at
`c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8`, not an open HTTP/SOCKS browser
proxy. The private installer is read-only by default. Its explicit
`--apply --relay-only` mode creates only a new bounded loopback service; it does
not take public ports, replace a web server, change VPN settings or run the
upstream installer. No upstream source or binary is vendored or published.
The pinned upstream repository has no LICENSE file; review licensing before
redistribution.

The owned production port 443 belongs to RosPanel's TLS front. It forwards TLS
to Xray's VLESS inner listener; ordinary HTTPS falls back to RosPanel on 8080.
The `Server: Caddy` response is a decoy banner, not a standalone Caddy server
with a configuration API. Consequently an nginx location on the panel's
loopback/8443 listener alone cannot activate WEB on public 443. This deployment
does not change the main front, Xray configuration or active VPN sessions.
The WEB card remains **not connected** until a separately approved persistent
HTTPS-prefix integration is installed and verified. Do not present a prepared
UI or a loopback process as a working public proxy.

The WEB helper verifies public TLS, the authentic bridge/session contract and
Telegram's matching resPQ nonce through the actual carrier, closes its disposable
session, and records only typed results. Public connection links require a
successful public proof within five minutes; a local probe cannot enable them.
Service controls invalidate the proof. Clients need Telegram with WEB support;
universal Android/iOS compatibility and a minimum stable Android version are not
claimed. The protocol is not a full Telegram account authorization test.

Primary upstream contracts:
https://github.com/telegramdesktop/tproxy-server and its pinned `PROTOCOL.md`
and `BASE_PATH.md` (native and HTTPS link formats, fixed HTTPS port, base-path
co-hosting and preservation of bridge security headers).

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

On 9 October 2026 the owner-approved WEB Proxy activation on HTTPS 443 passed
genuine public Telegram nonce proofs over HTTP/1.1 and HTTP/2. The owned
`tools/activate-webproxy-front.py` defaults to read-only inventory; apply requires
four observed protected SHA-256 values, a verified private relay, native gateway
tests, unchanged public-root responses and protected configuration. It installs
only a loopback client-IP-preserving gateway, exact RosPanel-cgroup fallback NAT
and owned lifecycle units/drop-ins. No main/VPN restart was needed. Details and
private snapshot location: `docs/TELEGRAM-PROXY-20261009.md`. Production APK,
credentials, subscriptions and DNS remain unchanged.

On 8 October 2026, `2.3.0-pulse.2` passed the guarded source-only deployment
and the extended live verification on `150.241.96.191`. Private source/database
snapshot:
`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-2edd859326004b4bae610c69233c902c`.
Configuration, release metadata and signing identity remained unchanged.
The final focused offline suite passed 326 tests, including authenticated HTTP
round-trips, draft-only scan confirmation, typed AI reason persistence, schema
validation, JavaScript interaction, redaction and deployment/verifier gates.

All six Network views returned 200/no-store without nested forms; overview,
DNS and routes each have exactly one live scanner/dialog set. The catalog
contained 2,894 deduplicated records: 2,885 domain records and 9 IPv4 host
records; no standalone IPv6 host record was present at that snapshot. The
IPv6 filter returned zero honestly, not invented addresses; IPv6 checks and
user-imported public IPv6 targets are supported. YouTube search matched 169
records, paginated 50 at a time. No Detector404 feed was imported.

The new in-memory adapter source was also exercised against the installed
llama runtime before deployment: empty allowed-actions grammar was accepted,
with 123 completion tokens in 44.3 seconds. This was one read-only aggregate
inference, not a fabricated database success or a speed measurement.

Both panels and MTProto remained active (19 ready upstream targets). Both
ARM legacy/updater APIs and TLS-verified APK HEAD probes still returned
`5.11.4 / 501104099`; fixed WARP diagnostic traces remained healthy for IPv4
and IPv6. These checks do not promise universal bypass or 50 ms client ping.

#### Previous pulse.1 deployment

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
