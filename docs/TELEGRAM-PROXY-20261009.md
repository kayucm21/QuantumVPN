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

## WEB activation pending

The WEB UI/backend and private relay installer are prepared, not publicly
activated. Read-only installer inventory returned `installed=false`,
`public_ready=false`, `front_integration=pending_separate_review`. No upstream
installer, new runtime, public listener, DNS change or main/VPN restart was run.

RosPanel's public TLS front forwards to Xray's VLESS inner listener; its HTTP
fallback reaches RosPanel on 8080. `Server: Caddy` is a decoy banner, not a
standalone Caddy configuration API. Activating a HTTPS relay prefix on 443
requires a reviewed persistent front/fallback integration and may briefly
reconnect VLESS/TLS subscribers. User approval for this intervention is pending.
Connection links stay disabled until a fresh genuine public TLS/carrier/Telegram
proof passes. A prepared card or loopback process is not a working public proxy.

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
