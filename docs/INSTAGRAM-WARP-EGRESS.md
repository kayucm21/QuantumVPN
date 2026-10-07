# Instagram / WARP IPv6 egress

Server-only repair for the existing RosPanel installation; Android 5.11.4 and
its distribution metadata are unchanged. A fabricated IPv6 address is not a
route. Existing userspace WARP provides real dual-stack egress over an IPv4
host; this does not create an incoming IPv6 address or a new DNS AAAA record.

## Persistent change

`tools/apply_instagram_warp.py` appends Instagram/Meta CDN domain suffixes to
`settings.routing_config.warp_domains` and public global-unicast `2000::/3` to
`warp_ips`. The existing `warp-out` balancer remains unchanged. API, private
addresses, metadata and ad-block rules retain their earlier precedence. Native
networking, WARP keys/endpoints, domain strategy, DNS, clients, subscriptions,
inbounds, APKs and the independent reserve service are not edited.

The helper defaults to read-only inspection. `--apply` validates a separate
candidate with the installed Xray before CAS-updating only the routing column
and revision, then restarts RosPanel and compares the complete generated config
with the expected change. SQLite online backup and config/state copies stay in
a private `0700` VDS transaction directory, with files `0600`. Failure restores
only this routing setting, never the whole database or newly created users.
Concurrent routing/revision changes abort rather than overwrite. An ambiguous
SSH response is reconciled read-only, not retried as another mutation. RosPanel
itself increments the revision once while generating Xray at startup. That
single increment is adopted only when the exact desired routing and all other
settings match the private pre-change SQLite snapshot. `--verify-committed`
finishes health verification/marking after a lost response without reapplying
settings or restarting services.

SSH credentials are supplied only through process environment
`QVPN_VDS_PASSWORD`; host keys must already be pinned in `known_hosts`. Do not
copy raw database/config backups into public release assets.

## Evidence limits

The existing diagnostic SOCKS inbound has its own WARP rule. HTTPS probes prove
WARP IPv4/IPv6 health and Instagram web reachability, not that a subscriber's
new domain rule matched. The persisted/generated rule comparison independently
checks the subscriber routing change and unchanged protected sections.

Instagram login/feed/media on the user's phone still requires a real-device
test. A local per-app bypass or the Android ad-block category "Social" can
exclude/block Instagram before traffic reaches the server. Server routing cannot
undo those device settings. Do not call an anonymous API-root 400/404 response
a successful Instagram-account test. No physical-device gate is closed here.

## Verification

Applied 2026-10-07 12:06 UTC; verified after reconnect at revision **203**. The
transaction is retained privately on VDS under
`routing-backups/instagram-20261007T120614Z-b9e9aabb73184b989be13a1a6bcce8c8`.
Only routing, revision and update timestamp differ from the settings backup;
the complete generated Xray configuration equals the expected two-array change.
Both panels remain active and the independent reserve service is unchanged.

Filtered checks: IPv4 and IPv6 Cloudflare trace return HTTP 200 with verified
TLS and `warp=on`; Instagram web returns HTTP 200, including a separate HTTPS
test connected to a numeric Meta IPv6 destination; YouTube control returns
HTTP 204. These are server egress checks, not phone throughput or login/feed
verification. No account identifiers, subscriber tokens or private keys are
included in this record. Android version remains 5.11.4.
