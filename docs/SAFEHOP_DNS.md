# Safehop DNS

Safehop is an independent recursive DNS service on the owned VDS
`150.241.96.191`. This document describes the installation implemented by
`tools/install-safehop-dns-vds.py` and its two configuration generators.
As of 10 October 2026, Unbound `1.19.2`, signed PowerDNS dnsdist `2.1.2` and the
four owned resolver/frontend/route units are installed and active. The separate
ZeroSSL certificate for `safehop.crabdance.com` expires on 8 January 2027.
The HTTP/2 backend correction and ingress refresh have passed the trusted local
DoH POST gate; protected-file hashes remain unchanged. The Safehop-only
certificate hook has also passed a live execution check. External-network
reachability remains unresolved, while all server-side endpoint and
authenticated VLESS/Vision regression gates below have passed. An installer
`Activated` result is not, by itself, an external-network DNS or VPN proof.

## Client endpoints

| Transport | Endpoint |
| --- | --- |
| DNS over HTTPS | `https://safehop.crabdance.com/dns-query` on TCP 443 |
| DNS over TLS / Android Private DNS hostname | `safehop.crabdance.com` on TCP 853 |
| Ordinary DNS | `150.241.96.191` on UDP/TCP 53 |

These are the configured endpoints, not a claim that all transports work on
every network. The current physical Windows Ethernet test cannot reach ordinary
DNS on 53 or complete Safehop TLS on 443/853, as described below. Earlier port-53
success did not establish physical-route reachability because Happ VPN may have
carried that traffic.

The domain's A record must point only to the verified assigned IPv4. No public
IPv6 is assigned at this installation snapshot; no IPv6 listener or AAAA record
is claimed. The generators accept IPv6 only after an explicit global address
has been verified on the host. Changing an Android DNS setting is a separate
client action; this installation does not change the app or device settings.

## Shared ingress and unchanged VPN path

The installed RosPanel source was inspected at commit
`ac36089a772aee7b7a0e4b0b48687820747882f6`. Its native TCP 443 front forwards
PROXY v1 followed by untouched TLS into Xray on `127.0.0.1:18443`; Xray performs
the existing VPN TLS termination. The installer requires the existing inbound's
`acceptProxyProtocol` and `rejectUnknownSni` settings to be true.

The new front is a separate unprivileged nginx instance, with its own service
and configuration. Its SNI preread selects a backend without terminating VPN
TLS, and its outgoing PROXY v1 preserves the network client's address.
See the [nginx preread documentation](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
and [stream proxy documentation](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html).

```text
Public TCP 443 -> owned DNAT -> 150.241.96.191:18556, Safehop nginx stream
  Safehop SNI -> PROXY v1 + TLS -> 127.0.0.1:18555, Safehop HTTPS
                -> HTTP/2 h2c + replaced client-IP header -> dnsdist 127.0.0.1:18554
                -> Unbound 127.0.0.1:18553
  Other SNI   -> PROXY v1 + unchanged TLS -> existing Xray 127.0.0.1:18443
                -> existing VLESS or existing HTTP fallback / WEB gateway

Public UDP/TCP 53 and TCP 853 -> dnsdist -> Unbound 127.0.0.1:18553
Public TCP 80 -> owned DNAT -> 150.241.96.191:18557
  Safehop Host -> exact HTTP-01 challenge webroot; other paths rejected
  Other Host   -> existing RosPanel HTTP 80, retaining Host and ACME paths
```

The owned nft table is `inet quantumvpn_safehop_dns`. The current generator has
PREROUTING and OUTPUT DNAT for exactly `150.241.96.191` TCP 80/443, allowing both
external ingress and traffic from the VDS/Xray to its own public endpoint to use
the front. Loopback backend addresses and unrelated destinations are excluded.
Auxiliary ingress is accepted only when the post-DNAT address/port and conntrack
original destination/port match the intended 80-to-18557 or 443-to-18556 mapping.
Direct public access to 18554–18557 has been verified rejected. The DNS backend
and HTTPS terminator bind only loopback. No global nft flush is used;
replacements are atomic and require the previous owned table fingerprint. The
deployment refresh has activated OUTPUT routing and preserved protected hashes.
[nftables reference](https://www.netfilter.org/projects/nftables/manpage.html).

Safehop HTTPS requires its own Host, a canonical `/dns-query` request and a
valid GET/POST envelope. Encoded aliases and unrelated paths do not fall back
to a panel. The loopback HTTPS listener requires PROXY v1, trusts only its
loopback sender, and replaces rather than appends `X-Forwarded-For` before
dnsdist. [nginx real-IP reference](https://nginx.org/en/docs/http/ngx_http_realip_module.html).

The installed dnsdist nghttp2 backend on 18554 accepts HTTP/2 rather than the
initial HTTP/1 upstream request. The deployed front uses nginx `grpc_pass` as an
HTTP/2 h2c transport for ordinary DNS messages, retaining its method/URI/body
guards and replacing the trusted source header. `nginx -t` and the refresh's
certificate-verified HTTP/1 client DoH POST returned HTTP 200; the backend leg is
HTTP/2, not an actual gRPC DNS API.
[dnsdist HTTP/2 backend guidance](https://www.dnsdist.org/guides/dns-over-https.html#http-1-support),
[nginx gRPC transport module](https://nginx.org/en/docs/http/ngx_http_grpc_module.html).

The existing RosPanel binary, Xray configuration, native VPN certificate/key,
main nginx configuration and sites, RosPanel secrets and host resolver are
protected by observed SHA-256 identities. This deployment does not rewrite
VPN clients, subscriptions or the main database, and does not build, update or
publish an APK. Existing panel/download TLS on 8443 and the previous WEB gateway
remain separate. Stream idle timeout is explicitly 24 hours.

## Resolver policy and bounded public DNS risk

Unbound performs recursion without forwarders, validates DNSSEC using a writable
RFC 5011 root trust anchor, minimises query names and rejects private-address
answers under the configured rebinding policy. Invalid DNSSEC is not accepted
by honouring a client's CD flag. DNS queries/replies are not logged; nginx access
and request-bearing error logs and dnsdist ring query/response history are
disabled. [Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html),
[dnsdist configuration reference](https://www.dnsdist.org/reference/config.html).

Public port 53 is an open recursive service. UDP source spoofing and reflection
risk remain even with limits; encrypted DNS should be the normal client choice.
The configured bounds include 500 DNS queries/second globally, 100/second per
IPv4 client with a burst of 150, rejection of ANY/AXFR/IXFR and non-query opcodes,
1232-byte UDP responses, bounded TCP concurrency and bounded service memory/CPU.
These reduce abuse and resource use; they do not make the public resolver
immune to attack or guarantee availability under a flood.

dnsdist's native DoH handler rejects AXFR/IXFR with `NOTIMP` before the configured
Lua refusal rule can run. These transfers remain unsupported. Only DoH AXFR/IXFR
accepts an empty-answer `NOTIMP` or `REFUSED` rejection in the verifier; ANY and
the other DNS/DoT refusal checks still require `REFUSED`.
[dnsdist 2.1.2 native DoH handling](https://github.com/PowerDNS/pdns/blob/dnsdist-2.1.2/pdns/dnsdistdist/dnsdist.cc#L1697-L1702).

## Operator workflow

Run the repository CLI from the workspace on the authorized Windows host, with
`QVPN_VDS_PASSWORD` already supplied in its short-lived environment. SSH uses
the existing pinned `C:/Users/Admin/.ssh/known_hosts` entry. Do not place the
password in command arguments, this document or an artifact.

Inventory, inspection and verification:

```powershell
python -B tools/install-safehop-dns-vds.py --mode inventory
python -B tools/install-safehop-dns-vds.py --mode inspect
python -B tools/install-safehop-dns-vds.py --mode verify
```

`inventory` is the default mode and returns protected hashes plus the required
host/inbound checks. `inspect` requires an installation manifest and reports
bounded unit/journal/listener information. `verify` checks the owned nft identity,
protected files, UDP/TCP 53, certificate-verified DoT, a trusted DoH POST to the
public-address endpoint and rejection of `dnssec-failed.org` by the recursive
backend. It requires all seven relevant services to be active: the four owned
units plus existing `rospanel`, `nginx` and `quantumvpn-operator`.
Inspection/verification acquire the installer lock but do not change services
or routing. The DoH check originates on the VDS; it is not an external-client
reachability proof.

For a first installation, retain and review the inventory, then pass only its
exact `protected_hashes` object to bootstrap. This PowerShell 7 sequence shows
the argument handling; bootstrap and activate are deployment actions:

```powershell
$safehopInventory = python -B tools/install-safehop-dns-vds.py --mode inventory | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Safehop inventory failed' }
$safehopExpected = $safehopInventory.protected_hashes | ConvertTo-Json -Compress
python -B tools/install-safehop-dns-vds.py --mode bootstrap --expected-json $safehopExpected
if ($LASTEXITCODE -ne 0) { throw 'Inspect the failed Safehop bootstrap before continuing' }
python -B tools/install-safehop-dns-vds.py --mode activate
if ($LASTEXITCODE -ne 0) { throw 'Inspect the failed Safehop activation before continuing' }
python -B tools/install-safehop-dns-vds.py --mode verify
```

Bootstrap installs signed DNS packages, prepares dedicated accounts/state,
initialises the DNSSEC trust anchor, starts the private resolver and HTTP-only
challenge front, and obtains a separate Safehop certificate. It leaves public
443 on the original native path. Activation validates native configurations,
checks DNS/DoT, reloads the Safehop front and atomically enables its HTTPS DNAT.
It requires a certificate-verified public-address DoH POST before recording the
installation as active; its output still marks external gates pending. The main
VPN service is not restarted. A failed bootstrap stops only its new
front/resolver and removes only its matching owned table; retained state can be
inspected before the guarded supported retry. Do not delete retained state or
alter the manifest to bypass a failure gate.

For an already active owned installation, `refresh` applies the current front
configuration and nft rules, performs a trusted local DoH POST, and restores the
previous front/rules on failure. It is a deployment action, not an inventory
command. The current backend/OUTPUT refresh has passed this local gate:

```powershell
python -B tools/install-safehop-dns-vds.py --mode refresh
```

All 88 offline checks passed, including the five temporary VLESS probe tests and
the installer verification/failing-refresh regression cases. After the scoped
native DoH transfer-denial expectation was corrected, all 38/38 VDS
public-endpoint checks passed. Certificate-verified frontend HTTP/2 DoH GET and
POST both returned HTTP 200. The existing WEB MTProto public-443 Telegram nonce
proof passed after OUTPUT routing, in 413 ms.

A temporary authenticated VLESS/Vision client using the unchanged existing Xray
binary/configuration and certificate-verified legacy SNI fetched
`https://example.com/` through public TCP 443: HTTP 200, 577 response-body bytes,
204 ms. Its client configuration and existing Vision UUID were supplied in
memory through stdin, its logs were discarded, and only its owned temporary
process was stopped afterward. The existing server configuration remained
unchanged. The bounded helper is `tools/quantumvpn_safehop_vless_probe.py`; it
runs on the already authorized VDS with `--server-name` set to the verified
legacy VPN TLS hostname, reads an existing client locally, and needs no external
client credentials or new persistent client configuration. The helper itself
does not SSH, install files or change services.

These endpoint, WEB and Vision proofs were VDS-originated through OUTPUT, not
physical external-client reachability or external-source-address proofs.

Acceptance from an external network still requires UDP/TCP DNS and DoT, DoH over HTTP/1
and HTTP/2, malformed-path/header tests, auxiliary-port rejection, the existing
WEB Telegram nonce proof, unchanged panel/download checks, and an authenticated
VLESS 443 connection with client-source evidence. With the new OUTPUT rules,
VDS-local connections can exercise the selected front, but they do not prove
external PREROUTING ingress or preservation of an external client's address.
The existing `verify-network-pulse.py --require-mtproto` checks panels, updater
APIs/APK HEADs and diagnostic WARP egress; it does not authenticate VLESS.
`verify-panel-domain-links.py` additionally performs owner probe/reveal POSTs
and commits boolean audit entries.

Bounded Windows tests selected physical Ethernet interface 7 per socket without
changing global routes or VPN state. The latest rerun timed out for all ordinary
UDP-53 queries, received OS errors for TCP-53 queries, and failed all Safehop TLS
handshakes. Existing certificate-verified panel/download endpoints on 8443/8444
returned HTTP 200, and direct 18554–18557 access was refused. Earlier port-53
success apparently used Happ VPN and is not evidence of direct Ethernet DNS.

An earlier Safehop TLS attempt received an `access denied` alert, while the
correlated VDS AF_PACKET capture saw no corresponding ClientHello. This is
consistent with filtering or interception before the VDS on the tested route,
but neither identifies an intermediary nor establishes an ISP or TSPU cause.
Reachability outside this physical route remains unknown.

A final correlated ordinary-DNS check fixed the Ethernet-7 UDP source port to
23430. During the seven-second VDS AF_PACKET capture there were zero matching
query or reply packets, and the PC request timed out. The test did not change PC
routes or disconnect its VPN. It establishes non-arrival for this bounded test,
not where or why the traffic was filtered.

No result here asserts a real Android device test, a particular ISP/mobile
network's reachability, subscriber routing, throughput or phone latency. Review
the reported service booleans as well as the CLI exit status. Installer `verify`
includes VDS-originated DoH, not an external-client probe or temporary
authenticated VLESS check. The broader 38-case endpoint suite and Vision helper
remain separate probes.

## Certificate renewal and recovery

The installed Safehop certificate is issued by ZeroSSL and expires on
`2027-01-08`. Let's Encrypt issuance encountered the shared registered-domain
rate limit; the installation reused the owner's existing registered ZeroSSL EC
account. Its original account key, existing VPN certificate/key and main
configuration were not changed. No new main certificate/SAN was introduced.
[Let's Encrypt rate-limit reference](https://letsencrypt.org/docs/rate-limits/).

Certbot stores the separate Safehop lineage at
`/etc/letsencrypt/live/safehop.crabdance.com` despite its ZeroSSL issuer. HTTP-01
uses `/var/lib/quantumvpn-safehop-dns/acme-webroot`. The Safehop renewal
configuration's exact `renew_hook` value is
`/usr/bin/python3 -B /usr/local/lib/quantumvpn-safehop-renew.py` (the field is
`renew_hook`, not `deploy_hook`). Live hook execution passed, `certbot.timer` is
active, and the original account key remains unchanged. This verifies the
installed renewal/reload path, not a future CA issuance outcome.

The hook is scoped to that Safehop lineage. It ignores other renewed lineages,
validates the Safehop hostname, validity and matching key, copies only the
Safehop certificate/key into its dedicated TLS directory, reloads the Safehop
nginx instance and restarts an already-active Safehop dnsdist instance. It
restores prior copies on failure. Native VPN TLS is not renewed, replaced or
restarted by this hook; DoT/DoH clients may reconnect during their own frontend
renewal. [HTTP-01 challenge mechanics](https://letsencrypt.org/docs/challenge-types/),
[Certbot renewal and deploy hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

The persistent route unit is `quantumvpn-safehop-route.service`; it follows
`quantumvpn-safehop-front.service` and removes only a fingerprint-matching owned
nft table on stop. To restore the original native public 80/443 ingress on the
VDS:

```sh
sudo systemctl stop quantumvpn-safehop-front.service
```

Existing proxied streams may need to reconnect. New connections return to the
original RosPanel/Xray path. Its verified `rejectUnknownSni=true` rejects the
Safehop hostname at TLS before a DoH request can reach the ordinary panel; no
panel fallback for that hostname is claimed after recovery. This stop leaves
ordinary DNS and DoT running; to withdraw those listeners as well:

```sh
sudo systemctl stop quantumvpn-safehop-dnsdist.service quantumvpn-safehop-unbound.service
```

For a reviewed temporary ingress stop, restart the front followed by the route
unit to restore the recorded active rules:

```sh
sudo systemctl start quantumvpn-safehop-front.service quantumvpn-safehop-route.service
```

A stop does not disable enabled services for a future boot. If a changed table
fingerprint prevents automatic removal/restoration, inspect and reconcile the
specific owned state rather than flushing nftables. Retain the manifest,
certificate lineage and installation files for recovery; this workflow does
not delete any GitHub release, remote asset or tag.
