# Telegram proxy UI and connection verification — 9 October 2026

Panel-only build `2.3.0-pulse.3` was applied on the owned VDS
`150.241.96.191`. The source-only deployment reported unchanged protected
configuration, public release API and signing identity. Recovery snapshot:

`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-42e90a1afa304868bea83098443b1eb7`.

387 focused offline tests passed. Coverage includes authenticated HTTP
round-trips, strict Origin/CSRF and owner-only proxy actions, native/HTTPS link
validation, static clipboard/copy/open/hide controls, fake-carrier WEB protocol
tests, credential/runtime permissions, archive extraction and scoped deployment.

The extended live read-only gate passed all six Network views, both ARM
legacy/updater APIs and TLS-verified APK HEAD requests. Production APK remains
`5.11.4 / 501104099`; byte sizes remain 140374940 (arm64) and 130830248 (armv7).
Main and additional panels remain active, with no nested Network forms or
ordinary-page proxy credentials. Fixed diagnostic WARP IPv4/IPv6 traces remain
healthy; these do not prove subscriber routing or user performance.

A separate live owner-only reveal POST passed through the actual nginx/TLS
listener on 8443 with public Host, Origin and session CSRF. It returned JSON
containing the validated MTProto controls, no-store/no-referrer/noindex headers,
and no redirect away from the current view. The short-lived cookie, response
HTML and proxy secret stayed on the VDS and were not printed. This action
created only the normal boolean owner-reveal audit, not service/configuration
changes. Clipboard interaction is covered by offline JavaScript tests; no claim
of exercising the user's Telegram account or browser clipboard is made.

## Slow MTProto connection report

The reported long connection was not reproduced at this snapshot:

- Three PC-to-public-IP genuine Telegram nonce proofs: 148, 147 and 162 ms.
- Three VDS loopback proofs: 101, 13 and 13 ms.
- Separate fixed Telegram DC 1–5 proofs through the owned public 3443 listener:
  172, 16, 123, 13 and 154 ms; every resPQ nonce matched.
- MTProxy active; 19 ready upstream targets, zero proxy errors/restarts;
  84 open file descriptors against an 8192 limit, approximately 10.9 MB RAM.

The DC check used a transient in-memory fixed-DC adaptation of the
checksum-verified owned helper. No installed file, client, service or VPN
configuration was changed. These are point-in-time protocol measurements,
not Telegram account authorization, the affected phone's connection time,
message delivery latency, bandwidth or proof about filtering. Client platform,
Telegram version, approximate delay and first-vs-repeated connection behavior
are still required to identify the affected path. No speculative sysctl/MTU,
proxy port or process restart was applied.

## WEB activated after explicit approval

On 9 October 2026 the owner explicitly approved activation on HTTPS 443,
including a brief VLESS/TLS reconnect if necessary. Activation succeeded without
restarting the main/VPN service. RosPanel binary, Xray configuration, nginx,
VPN credentials, subscriptions, release metadata and signing keys were unchanged.
RosPanel's existing TLS front still reaches Xray's inner VLESS listener; only
its cgroup's new HTTP fallback connections to `127.0.0.1:8080` are routed through
the owned loopback HTTP/1.1 + h2c gateway on 18084. That gateway routes the fixed
WEB prefix to the private official relay on 18082, and all ordinary paths back
to the same main panel on 8080. PROXY v1 addresses are preserved for the main
panel and used as the relay's single trusted loopback forwarding address.

Private configuration/database snapshot:
`/var/lib/quantumvpn-operator/web-front-backups/front-e5091cebe4ce47579c74c83790efc282`.
Owned front/route systemd units and main/relay Wants drop-ins provide persistent
ordering and remove only the fingerprinted owned nft table on shutdown. Existing
main configuration files and public listeners were not replaced. Persistence is
configured and unit-verified; no reboot or main-service restart was performed.

Verification:

- Seven native Go tests passed, including HTTP/1.1, HTTP/2, fragmented PROXY v1,
  IPv4/IPv6 source serialization, spoofed forwarding-header replacement and
  malformed/encoded private-namespace isolation.
- Public root HTTP/1.1 and HTTP/2 responses matched their before-activation hashes.
- Private genuine Telegram nonce proof: 179 ms; public HTTPS/HTTP/1.1 proof:
  111 ms. Both disposable probe sessions were closed.
- A separate real public HTTP/2 carrier proof passed all five requests and
  matched Telegram's nonce (439 ms including per-request curl setup). Headers,
  capability URLs and bearer tokens stayed in memory/stdin, not argv or logs.
- Actual owner POSTs through verified TLS on 8443 passed: WEB probe returned the
  expected 303 to the same Network view, WEB reveal returned 200/no-store with
  native/HTTPS links and copy/open/hide controls. These short-lived credentials
  and link response were not printed. The live panel now has a fresh proof.
- The complete Network read-only gate passed again: both panels, MTProto with
  19 ready targets, all six views, both ARM APIs and TLS-verified APK HEADs.
  APK remains `5.11.4 / 501104099`, with unchanged artifact sizes.

The first relay-only attempt stopped at the health gate because urllib added a
form Content-Type to an empty downlink POST. The bodyless transport is fixed and
covered with real urllib header preparation, not only a fake carrier. Its
rollback also exposed identical runtime/private basenames; rollback destinations
are now distinct, identity-guarded and regression-tested. The verified built
runtime was recovered without rebuilding or changing the proxy secret. The
remaining private recovery directory is retained, not published or deleted.
The final focused suite passed 223 tests, including 13 front guards.

The private decoded namespace (including encoded and naked paths) is reserved
for the relay's credential gate, without rewriting the original URI. Malformed
authenticated links cannot bypass that gate and reach the main panel's logs.
This minimal source/binary update was native-tested and applied with exact
identity checks and a private backup:
`/var/lib/quantumvpn-operator/web-front-backups/namespace-a184b31079724e00baab9f059f39781c`.
Only the owned gateway was restarted; its dependent route recovered and the
main/VPN service uptime was unchanged. A first immediate dependent-status
check encountered a startup race and safely restored the prior gateway;
the successful retry waited for route readiness before its public proof
(92 ms). No stale route fingerprint was observed. Both public-root hashes and
protected configuration remained unchanged.

Owner connection controls are in Network → Telegram → WEB Proxy. A fresh
public proof is required before revealing links; repeat “Проверить HTTPS и
Telegram” when that proof expires. Opening a link configures only a compatible
Telegram client; this does not automatically change the user's Telegram
settings. No Telegram account authorization, phone latency or throughput test
is claimed by the server nonce checks.

Official source contract: https://github.com/telegramdesktop/tproxy-server,
pinned at `c8adb8b7c6b7fc46c12ae3acb68be9070c26a8e8`; archive SHA-256
`a78b48f536180143dd7005785ca397310c36ee0b132e19949a45d64f586ab549`.
No upstream source/binary is redistributed. Compatible Telegram WEB clients are
required; all Android/iOS versions are not guaranteed to support the transport.

## Google AI Studio key-listing error

`Failed to list API keys: permission denied` does not establish a VPN outage or
that a paid subscription is missing. Official AI Studio documentation requires
project lookup, `apikeys.keys.list`, `serviceusage.services.get` and the Generative
Language API to be enabled. Additional Google security, terms, region and
project-abuse checks can also deny access. Existing keys should not be deleted
or rotated merely to diagnose listing failure.

Check the same Google account and existing project in Google Cloud Credentials;
if Cloud can list keys but AI Studio cannot, check the selected account and
import the existing project. Pro benefits do not grant project IAM permissions
or override Google's security/region requirements. Exact cause for this user's
account is not proven without its project/account access evidence.

Primary references:
https://ai.google.dev/gemini-api/docs/troubleshoot-ai-studio,
https://ai.google.dev/gemini-api/docs/api-key,
https://ai.google.dev/gemini-api/docs/google-ai-plans.
