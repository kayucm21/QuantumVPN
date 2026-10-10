"""Pure configuration data for the independent Safehop recursive DNS service.

No file, process, network, package, firewall or service changes occur here.  The
installer must create the dedicated accounts, provision a DNSSEC root trust
anchor and a valid certificate, and validate each config with its target binary.
The Lua configuration uses the common dnsdist 1.8.3/current-2.x API subset; older
syntax compatibility is not an endorsement of an unpatched public deployment.
"""
from __future__ import annotations

import ipaddress


DOMAIN = "safehop.crabdance.com"
PUBLIC_IPV4 = "150.241.96.191"
CONFIG_DIRECTORY = "/etc/quantumvpn-safehop-dns"
STATE_DIRECTORY = "/var/lib/quantumvpn-safehop-dns"
UNBOUND_USER = "quantumvpn-safehop-unbound"
DNSDIST_USER = "quantumvpn-safehop-dnsdist"
UNBOUND_SERVICE = "quantumvpn-safehop-unbound.service"
DNSDIST_SERVICE = "quantumvpn-safehop-dnsdist.service"
UNBOUND_CONFIG = CONFIG_DIRECTORY + "/unbound.conf"
DNSDIST_CONFIG = CONFIG_DIRECTORY + "/dnsdist.conf"
ROOT_KEY = STATE_DIRECTORY + "/unbound/root.key"
FULLCHAIN = STATE_DIRECTORY + "/tls/fullchain.pem"
PRIVATE_KEY = STATE_DIRECTORY + "/tls/privkey.pem"
UNBOUND_PORT = 18553
INTERNAL_DOH_PORT = 18554
GLOBAL_QPS = 500
CLIENT_QPS = 100
CLIENT_BURST = 150
CLIENT_EXPIRATION_SECONDS = 60
CLIENT_CLEANUP_SECONDS = 30

SOURCE_URLS = (
    "https://www.dnsdist.org/reference/config.html",
    "https://www.dnsdist.org/reference/selectors.html",
    "https://www.dnsdist.org/reference/tuning.html",
    "https://www.dnsdist.org/rules-actions.html",
    "https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html",
    "https://github.com/PowerDNS/pdns/blob/dnsdist-1.8.3/pdns/dnsdistdist/docs/reference/config.rst",
    "https://github.com/NLnetLabs/unbound/blob/release-1.19.2/doc/example.conf.in",
)

SYNTAX_CAVEATS = (
    "Use a supported, patched dnsdist package; validate Lua with dnsdist --check-config.",
    "The dnsdist binary must include DNS-over-HTTPS and OpenSSL support.",
    "DoH uses nil certificate/key arguments for plain HTTP on loopback only; not tls=false.",
    "The HTTPS gateway must replace X-Forwarded-For with the actual client address.",
    "MaxQPSRule matches traffic below its limit; NotRule is required to drop excess traffic.",
    "No broad private-domain exception is made for the shared crabdance.com zone.",
    "The installer must initialize the writable RFC 5011 root.key before starting Unbound.",
    "MemoryDenyWriteExecute is omitted for dnsdist because its LuaJIT build may require JIT memory.",
)


def verified_ipv6(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> str | None:
    """Accept only an explicit globally routable address with verified assignment.

    The flag is the installer's assertion based on host evidence, not a network
    probe.  Zone identifiers, networks, wildcards and IPv4-mapped addresses are
    rejected even when the caller asserts verification.
    """
    if type(public_ipv6_verified) is not bool:
        raise ValueError("IPv6 verification must be a boolean")
    if public_ipv6 is None:
        if public_ipv6_verified:
            raise ValueError("IPv6 verification requires an explicit address")
        return None
    if not isinstance(public_ipv6, str) or not public_ipv6 or "%" in public_ipv6:
        raise ValueError("IPv6 must be an explicit global address without a scope")
    try:
        value = ipaddress.IPv6Address(public_ipv6)
    except ipaddress.AddressValueError as error:
        raise ValueError("IPv6 must be an explicit global address") from error
    if (not public_ipv6_verified or not value.is_global or value.is_multicast
            or value.is_unspecified or value.ipv4_mapped is not None):
        raise ValueError("IPv6 must be globally routable and verified on the host")
    return str(value)


def unbound_config(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> str:
    ipv6 = verified_ipv6(public_ipv6, public_ipv6_verified=public_ipv6_verified)
    return f'''# Managed by QuantumVPN Safehop DNS; recursive resolver, no forwarders.
server:
    interface: 127.0.0.1@{UNBOUND_PORT}
    interface-automatic: no
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    access-control: 127.0.0.1/32 allow
    do-ip4: yes
    do-ip6: {"yes" if ipv6 else "no"}
    do-udp: yes
    do-tcp: yes
    do-daemonize: no
    username: "{UNBOUND_USER}"
    chroot: ""
    directory: "{STATE_DIRECTORY}/unbound"
    pidfile: ""
    auto-trust-anchor-file: "{ROOT_KEY}"
    module-config: "validator iterator"
    num-threads: 2
    msg-cache-size: 64m
    rrset-cache-size: 128m
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    key-cache-size: 4m
    neg-cache-size: 4m
    infra-cache-numhosts: 10000
    num-queries-per-thread: 256
    outgoing-range: 512
    outgoing-num-tcp: 16
    incoming-num-tcp: 64
    edns-buffer-size: 1232
    max-udp-size: 1232
    minimal-responses: yes
    qname-minimisation: yes
    qname-minimisation-strict: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    aggressive-nsec: yes
    val-permissive-mode: no
    ignore-cd-flag: yes
    prefetch: yes
    prefetch-key: yes
    cache-min-ttl: 0
    cache-max-ttl: 86400
    serve-expired: no
    hide-identity: yes
    hide-version: yes
    do-not-query-localhost: yes
    private-address: 0.0.0.0/8
    private-address: 10.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: 127.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: ::/128
    private-address: ::1/128
    private-address: ::ffff:0:0/96
    private-address: fc00::/7
    private-address: fe80::/10
    # DNS query/answer data must never be written to logs.
    verbosity: 0
    log-queries: no
    log-replies: no
    log-servfail: no
    log-local-actions: no
    use-syslog: yes
    statistics-interval: 0
    extended-statistics: no
remote-control:
    control-enable: no
'''


def dnsdist_config(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> str:
    ipv6 = verified_ipv6(public_ipv6, public_ipv6_verified=public_ipv6_verified)
    addresses = [PUBLIC_IPV4] + ([ipv6] if ipv6 else [])
    ordinary = []
    tls = []
    for index, address in enumerate(addresses):
        host = f"[{address}]" if ":" in address else address
        ordinary.append(
            f'{"setLocal" if index == 0 else "addLocal"}("{host}:53", '
            '{maxConcurrentTCPConnections=128, maxInFlight=16, tcpListenQueueSize=128})'
        )
        tls.append(
            f'addTLSLocal("{host}:853", "{FULLCHAIN}", "{PRIVATE_KEY}", '
            '{provider="openssl", minTLSVersion="tls1.2", '
            'maxConcurrentTCPConnections=128, maxInFlight=16, tcpListenQueueSize=128, '
            'sessionTimeout=300, numberOfStoredSessions=512, releaseBuffers=true, '
            'enableRenegotiation=false})'
        )
    return '\n'.join([
        '-- Managed by QuantumVPN Safehop DNS. No console, API, packet cache or query logs.',
        'setACL({"0.0.0.0/0", "::/0"})',
        'setVerbose(false)',
        'setRingBuffersOptions({recordQueries=false, recordResponses=false})',
        'setMaxTCPClientThreads(2)',
        'setMaxTCPConnectionsPerClient(8)',
        'setMaxTCPConnectionDuration(60)',
        'setMaxTCPQueriesPerConnection(1000)',
        'setMaxTCPQueuedConnections(128)',
        'setTCPRecvTimeout(10)',
        'setTCPSendTimeout(10)',
        'setMaxUDPOutstanding(512)',
        'setUDPTimeout(2)',
        *ordinary,
        *tls,
        '-- Only a local HTTPS gateway may reach this plain-HTTP listener.',
        '-- That gateway must replace, never append or pass through, X-Forwarded-For.',
        f'addDOHLocal("127.0.0.1:{INTERNAL_DOH_PORT}", nil, nil, {{"/dns-query"}}, '
        '{trustForwardedForHeader=true, exactPathMatching=true, keepIncomingHeaders=false, '
        'maxConcurrentTCPConnections=128, tcpListenQueueSize=128, idleTimeout=10, serverTokens=""})',
        f'newServer({{address="127.0.0.1:{UNBOUND_PORT}", name="safehop-recursive", '
        'checkName=".", checkType="NS", mustResolve=true, '
        'maxConcurrentTCPConnections=32, useClientSubnet=false})',
        '-- Apply the global token bucket before allocating per-client limiter state.',
        f'addAction(NotRule(MaxQPSRule({GLOBAL_QPS})), DropAction())',
        f'addAction(MaxQPSIPRule({CLIENT_QPS}, 32, 64, {CLIENT_BURST}, '
        f'{CLIENT_EXPIRATION_SECONDS}, {CLIENT_CLEANUP_SECONDS}, 1, 4), DropAction())',
        '-- Transport-independent policy, including TCP, DoT and proxied DoH.',
        'addAction(OrRule({QTypeRule(DNSQType.ANY), QTypeRule(DNSQType.AXFR), '
        'QTypeRule(DNSQType.IXFR)}), RCodeAction(DNSRCode.REFUSED))',
        'addAction(NotRule(OpcodeRule(DNSOpcode.Query)), RCodeAction(DNSRCode.REFUSED))',
        '',
    ])


def _service_common(user: str, *, ipv6: bool, memory_high: str, memory_max: str) -> str:
    return f'''User={user}
Group={user}
UMask=0077
RuntimeDirectory={user}
RuntimeDirectoryMode=0700
CacheDirectory={user}
CacheDirectoryMode=0700
WorkingDirectory=/var/cache/{user}
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX AF_INET{" AF_INET6" if ipv6 else ""}
SystemCallArchitectures=native
LimitNOFILE=4096
LimitCORE=0
TasksMax=32
MemoryHigh={memory_high}
MemoryMax={memory_max}
CPUQuota=150%
Nice=5
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
StandardOutput=journal
StandardError=journal
'''


def unbound_service(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> str:
    ipv6 = verified_ipv6(public_ipv6, public_ipv6_verified=public_ipv6_verified)
    # glibc getifaddrs uses a netlink socket even with a fixed IPv4 interface.
    common = _service_common(UNBOUND_USER, ipv6=bool(ipv6), memory_high="320M", memory_max="384M").replace(
        "RestrictAddressFamilies=AF_UNIX AF_INET", "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET")
    return f'''[Unit]
Description=QuantumVPN Safehop recursive DNSSEC resolver
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/sbin/unbound -d -c {UNBOUND_CONFIG}
StateDirectory=quantumvpn-safehop-dns/unbound
StateDirectoryMode=0700
CapabilityBoundingSet=
AmbientCapabilities=
MemoryDenyWriteExecute=true
{common}
[Install]
WantedBy=multi-user.target
'''


def dnsdist_service(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> str:
    ipv6 = verified_ipv6(public_ipv6, public_ipv6_verified=public_ipv6_verified)
    return f'''[Unit]
Description=QuantumVPN Safehop DNS, DNS-over-TLS and internal DNS-over-HTTP frontend
After=network-online.target {UNBOUND_SERVICE}
Wants=network-online.target
Requires={UNBOUND_SERVICE}
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/bin/dnsdist --supervised --disable-syslog -C {DNSDIST_CONFIG}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
{_service_common(DNSDIST_USER, ipv6=bool(ipv6), memory_high="128M", memory_max="192M")}
[Install]
WantedBy=multi-user.target
'''


def generated_files(public_ipv6: str | None = None, *, public_ipv6_verified: bool = False) -> dict[str, str]:
    """Return proposed file contents only, without writing or installing them."""
    kwargs = {"public_ipv6": public_ipv6, "public_ipv6_verified": public_ipv6_verified}
    return {
        UNBOUND_CONFIG: unbound_config(**kwargs),
        DNSDIST_CONFIG: dnsdist_config(**kwargs),
        "/etc/systemd/system/" + UNBOUND_SERVICE: unbound_service(**kwargs),
        "/etc/systemd/system/" + DNSDIST_SERVICE: dnsdist_service(**kwargs),
    }
