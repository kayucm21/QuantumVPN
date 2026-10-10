"""Pure deployment data for the independent Safehop shared HTTPS front.

This module performs no I/O, process execution or network operations.  The
installer must verify the existing Xray loopback TLS listener accepts PROXY v1,
validate nginx/nft syntax, and switch the owned nft table atomically.  These
configurations target Ubuntu nginx 1.24 with libnginx-mod-stream and realip.
"""
from __future__ import annotations

import hashlib
import json


DOMAIN = "safehop.crabdance.com"
DOMAIN_PATTERN = DOMAIN.replace(".", r"\.")
PUBLIC_IPV4 = "150.241.96.191"
CONFIG_DIRECTORY = "/etc/quantumvpn-safehop-dns"
STATE_DIRECTORY = "/var/lib/quantumvpn-safehop-dns"
FRONT_USER = "quantumvpn-safehop-front"
FRONT_GROUP = "quantumvpn-safehop-tls"
FRONT_SERVICE = FRONT_USER + ".service"
RUNTIME_DIRECTORY = "/run/" + FRONT_USER
PREFIX = "/var/cache/" + FRONT_USER
NGINX_CONFIG = CONFIG_DIRECTORY + "/nginx-front.conf"
NFTABLES_CONFIG = CONFIG_DIRECTORY + "/front.nft"
ACME_WEBROOT = STATE_DIRECTORY + "/acme-webroot"
FULLCHAIN = STATE_DIRECTORY + "/tls/fullchain.pem"
PRIVATE_KEY = STATE_DIRECTORY + "/tls/privkey.pem"
DOH_PORT = 18554
DOH_TLS_PORT = 18555
STREAM_PORT = 18556
HTTP_PORT = 18557
XRAY_TLS_PORT = 18443
NFT_TABLE = "quantumvpn_safehop_dns"
NFT_OWNER = "quantumvpn-safehop-front:v1"
STREAM_MODULE = "/usr/lib/nginx/modules/ngx_stream_module.so"

SOURCE_URLS = (
    "https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html",
    "https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html",
    "https://nginx.org/en/docs/http/ngx_http_realip_module.html",
    "https://nginx.org/en/docs/http/ngx_http_map_module.html",
    "https://nginx.org/en/docs/http/ngx_http_core_module.html",
    "https://nginx.org/en/docs/http/ngx_http_grpc_module.html",
    "https://www.dnsdist.org/guides/dns-over-https.html",
    "https://www.netfilter.org/projects/nftables/manpage.html",
)

# Quotes in nginx maps are required around regexes containing braces.
# The lookahead caps the encoded message; groups exclude length == 1 mod 4.
GET_REQUEST_PATTERN = (
    r"^GET:/dns-query\?dns=(?=[A-Za-z0-9_-]{16,2048}$)"
    r"(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$"
)
ACME_REQUEST_PATTERN = (
    r"^(?:GET|HEAD):/\.well-known/acme-challenge/[A-Za-z0-9_-]{22,128}$"
)
POST_LENGTH_PATTERN = (
    r"^POST:(?:1[2-9]|[2-9][0-9]|[1-9][0-9]{2}|[1-3][0-9]{3}|"
    r"40[0-8][0-9]|409[0-6])$"
)

# ngx_http_grpc has no equivalent to proxy_pass_request_headers off. Suppress
# known credentials, identity/trace metadata and alternate client-IP headers;
# dnsdist independently uses keepIncomingHeaders=false for unknown custom ones.
DOH_DROPPED_REQUEST_HEADERS = (
    "Cookie", "Authorization", "Proxy-Authorization", "Forwarded",
    "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Protocol",
    "X-Forwarded-Server", "X-Original-Forwarded-For", "X-Original-For",
    "X-Original-Host", "X-Original-URL", "X-Rewrite-URL", "Client-IP",
    "X-Client-IP", "X-Cluster-Client-IP", "True-Client-IP", "CF-Connecting-IP",
    "Fastly-Client-IP", "X-Envoy-External-Address", "X-Envoy-Original-Dst-Host",
    "X-Envoy-Original-Path", "User-Agent", "Referer", "Origin",
    "Accept-Language", "Accept-Encoding", "Traceparent", "Tracestate", "Baggage",
    "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding",
    "TE", "Trailer", "Upgrade", "Expect",
)


def _main_config(*, stream: bool) -> str:
    module = f"load_module {STREAM_MODULE};\n" if stream else ""
    return f'''# Managed by QuantumVPN Safehop front; standalone nginx instance.
{module}daemon off;
master_process on;
worker_processes 2;
pid {RUNTIME_DIRECTORY}/nginx.pid;
# Request paths, DNS data and hostnames must not enter error/access logs.
error_log /dev/null crit;
events {{
    worker_connections 2048;
    multi_accept off;
}}
'''


def _http_common() -> str:
    return f'''    server_tokens off;
    access_log off;
    log_not_found off;
    client_body_temp_path {PREFIX}/client-body 1 2;
    proxy_temp_path {PREFIX}/proxy 1 2;
    fastcgi_temp_path {PREFIX}/fastcgi 1 2;
    uwsgi_temp_path {PREFIX}/uwsgi 1 2;
    scgi_temp_path {PREFIX}/scgi 1 2;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 15s;
    keepalive_timeout 15s;
    keepalive_requests 100;
    client_header_buffer_size 1k;
    large_client_header_buffers 2 4k;
    client_max_body_size 16m;
    reset_timedout_connection on;
    limit_req_zone $binary_remote_addr zone=safehop_http_client:1m rate=20r/s;
    limit_conn_zone $binary_remote_addr zone=safehop_http_connections:1m;
    limit_req_status 429;
    limit_conn_status 429;
    map $http_host $safehop_http_host {{
        default 0;
        "~*^{DOMAIN_PATTERN}(:80)?$" 1;
    }}
    map "$request_method:$request_uri" $safehop_acme_request {{
        default 0;
        "~{ACME_REQUEST_PATTERN}" 1;
    }}
    map "$request_method:$http_content_length:$http_transfer_encoding" $safehop_acme_body {{
        default 0;
        "GET::" 1;
        "GET:0:" 1;
        "HEAD::" 1;
        "HEAD:0:" 1;
    }}
'''


def _http_servers() -> str:
    return f'''    server {{
        listen {PUBLIC_IPV4}:{HTTP_PORT} default_server;
        server_name _;
        limit_req zone=safehop_http_client burst=40 nodelay;
        limit_conn safehop_http_connections 16;
        location / {{
            proxy_pass http://127.0.0.1:80;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Forwarded "";
            proxy_set_header X-Forwarded-Host "";
            proxy_set_header X-Forwarded-Proto http;
            proxy_set_header X-Forwarded-Port 80;
            proxy_set_header Connection "";
            proxy_connect_timeout 3s;
            proxy_read_timeout 30s;
            proxy_send_timeout 30s;
            proxy_buffers 4 8k;
            proxy_max_temp_file_size 0;
        }}
    }}
    server {{
        listen {PUBLIC_IPV4}:{HTTP_PORT};
        server_name {DOMAIN};
        client_max_body_size 1;
        limit_req zone=safehop_http_client burst=20 nodelay;
        limit_conn safehop_http_connections 8;
        if ($safehop_http_host = 0) {{ return 404; }}
        if ($safehop_acme_request = 0) {{ return 404; }}
        if ($safehop_acme_body = 0) {{ return 400; }}
        location ~ "^/\\.well-known/acme-challenge/[A-Za-z0-9_-]{{22,128}}$" {{
            root {ACME_WEBROOT};
            default_type text/plain;
            disable_symlinks on;
            try_files $uri =404;
        }}
        location / {{ return 404; }}
    }}
'''


def bootstrap_config() -> str:
    """HTTP-01 bootstrap; no certificate dependency or interception of TLS."""
    return _main_config(stream=False) + "http {\n" + _http_common() + _http_servers() + "}\n"


def nginx_config(*, loopback_probe: bool = False) -> str:
    """Final SNI passthrough, canonical DoH and isolated HTTP-01 handling.

    The optional loopback listener exercises the same ClientHello routing from
    the host without exposing an additional public port or trusting client
    PROXY headers. It generates PROXY v1 from the local socket peer as usual.
    """
    if type(loopback_probe) is not bool:
        raise ValueError("loopback_probe must be a boolean")
    probe_listen = f"        listen 127.0.0.1:{STREAM_PORT};\n" if loopback_probe else ""
    stream = f'''stream {{
    access_log off;
    map $ssl_preread_server_name $safehop_tls_upstream {{
        {DOMAIN} 127.0.0.1:{DOH_TLS_PORT};
        default 127.0.0.1:{XRAY_TLS_PORT};
    }}
    limit_conn_zone $binary_remote_addr zone=safehop_tls_connections:1m;
    server {{
        listen {PUBLIC_IPV4}:{STREAM_PORT};
{probe_listen}        ssl_preread on;
        preread_timeout 10s;
        preread_buffer_size 16k;
        limit_conn safehop_tls_connections 1500;
        proxy_pass $safehop_tls_upstream;
        # PROXY v1 carries the network peer IP, never an HTTP client header.
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 24h;
        proxy_buffer_size 16k;
        proxy_socket_keepalive on;
    }}
}}
'''
    maps = f'''    limit_req_zone $binary_remote_addr zone=safehop_doh_client:2m rate=100r/s;
    limit_req_zone $server_name zone=safehop_doh_global:64k rate=500r/s;
    map $http_host $safehop_doh_host {{
        default 0;
        "~*^{DOMAIN_PATTERN}(:443)?$" 1;
    }}
    map $request_method $safehop_doh_method {{
        default 0;
        GET 1;
        POST 1;
    }}
    map "$request_method:$request_uri" $safehop_doh_request {{
        default 0;
        "~{GET_REQUEST_PATTERN}" 1;
        "POST:/dns-query" 1;
    }}
    map "$request_method:$http_content_type" $safehop_doh_type {{
        default 0;
        ~^GET: 1;
        "~*^POST:application/dns-message$" 1;
    }}
    map "$request_method:$http_content_length" $safehop_doh_length {{
        default 0;
        "GET:" 1;
        "GET:0" 1;
        # Chunked/H2 POST without Content-Length is bounded while nginx reads it.
        "POST:" 1;
        "~{POST_LENGTH_PATTERN}" 1;
    }}
    map "$request_method:$http_transfer_encoding" $safehop_doh_encoding {{
        default 0;
        "GET:" 1;
        ~^POST: 1;
    }}
'''
    dropped_headers = "".join(f'            grpc_set_header {header} "";\n'
                              for header in DOH_DROPPED_REQUEST_HEADERS)
    doh = f'''    server {{
        # nginx 1.24 uses the listen http2 parameter, not the newer http2 directive.
        listen 127.0.0.1:{DOH_TLS_PORT} ssl http2 proxy_protocol default_server;
        server_name {DOMAIN};
        ssl_certificate {FULLCHAIN};
        ssl_certificate_key {PRIVATE_KEY};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:safehop_tls_sessions:1m;
        ssl_session_timeout 5m;
        ssl_session_tickets off;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        real_ip_recursive off;
        client_max_body_size 4096;
        client_body_buffer_size 8k;
        limit_conn safehop_http_connections 8;
        if ($safehop_doh_host = 0) {{ return 404; }}
        location = /dns-query {{
            if ($safehop_doh_method = 0) {{ return 405; }}
            # Match the raw URI: encoded paths, extra args and aliases fail closed.
            if ($safehop_doh_request = 0) {{ return 400; }}
            if ($safehop_doh_type = 0) {{ return 415; }}
            if ($safehop_doh_length = 0) {{ return 400; }}
            if ($safehop_doh_encoding = 0) {{ return 400; }}
            limit_req zone=safehop_doh_global burst=100 nodelay;
            limit_req zone=safehop_doh_client burst=150 nodelay;
            # dnsdist 2.1+ nghttp2 accepts only HTTP/2, including plain loopback.
            grpc_pass grpc://127.0.0.1:{DOH_PORT};
            grpc_set_header Host {DOMAIN};
            grpc_set_header Content-Type application/dns-message;
            grpc_set_header Accept application/dns-message;
            grpc_set_header Content-Length $content_length;
            grpc_set_header X-Forwarded-For $remote_addr;
            grpc_set_header X-Forwarded-Proto https;
            grpc_set_header X-Forwarded-Port 443;
{dropped_headers}            grpc_connect_timeout 3s;
            grpc_read_timeout 10s;
            grpc_send_timeout 10s;
            grpc_buffer_size 8k;
            grpc_next_upstream off;
            grpc_socket_keepalive on;
            grpc_hide_header Set-Cookie;
            grpc_hide_header X-Powered-By;
            grpc_ignore_headers X-Accel-Redirect X-Accel-Charset;
            add_header Cache-Control "no-store" always;
        }}
        location / {{ return 404; }}
    }}
'''
    return _main_config(stream=True) + stream + "http {\n" + _http_common() + maps + _http_servers() + doh + "}\n"


def front_service() -> str:
    return f'''[Unit]
Description=QuantumVPN Safehop shared HTTPS and HTTP-01 front
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User={FRONT_USER}
Group={FRONT_GROUP}
UMask=0077
RuntimeDirectory={FRONT_USER}
RuntimeDirectoryMode=0700
CacheDirectory={FRONT_USER}
CacheDirectoryMode=0700
WorkingDirectory={PREFIX}
ExecStartPre=/usr/sbin/nginx -t -p {PREFIX}/ -c {NGINX_CONFIG}
ExecStart=/usr/sbin/nginx -p {PREFIX}/ -c {NGINX_CONFIG}
ExecReload=/usr/sbin/nginx -s reload -p {PREFIX}/ -c {NGINX_CONFIG}
KillSignal=SIGQUIT
TimeoutStopSec=15s
Restart=on-failure
RestartSec=5s
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths={CONFIG_DIRECTORY} {STATE_DIRECTORY}/tls {ACME_WEBROOT}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX AF_INET
SystemCallArchitectures=native
LimitNOFILE=8192
LimitCORE=0
TasksMax=16
MemoryHigh=96M
MemoryMax=128M
CPUQuota=150%
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''


def nftables_rules(*, bootstrap: bool = False) -> str:
    """Create only the owned table; never flush global rules or existing tables.

    This is a create transaction.  Replacing an existing, verified owned table
    requires the installer to prepend exactly `delete table inet <NFT_TABLE>`
    to this data in the same atomic nft transaction.
    """
    if type(bootstrap) is not bool:
        raise ValueError("bootstrap must be a boolean")
    redirects = []
    output_redirects = []
    permits = []
    for source, target, name in ((80, HTTP_PORT, "http"), (443, STREAM_PORT, "https")):
        if source == 443 and bootstrap:
            continue
        # Explicit DNAT keeps the exact address nginx binds, even if another
        # address happens to be primary on the incoming interface.
        redirects.append(
            f'        ip daddr {PUBLIC_IPV4} tcp dport {source} '
            f'dnat ip to {PUBLIC_IPV4}:{target} comment "{NFT_OWNER}:redirect-{name}"\n'
        )
        # Local Xray/host connections to the same public endpoint bypass
        # PREROUTING. Only this exact public address and endpoint are redirected.
        output_redirects.append(
            f'        ip daddr {PUBLIC_IPV4} tcp dport {source} '
            f'dnat ip to {PUBLIC_IPV4}:{target} comment "{NFT_OWNER}:redirect-output-{name}"\n'
        )
        permits.append(
            f'        ip daddr {PUBLIC_IPV4} tcp dport {target} ct status dnat '
            f'ct original ip daddr {PUBLIC_IPV4} ct original proto-dst {source} '
            f'accept comment "{NFT_OWNER}:allow-dnat-{name}"\n'
        )
    return f'''# Managed QuantumVPN table only. Exact own-address endpoints; no global flush.
table inet {NFT_TABLE} {{
    comment "{NFT_OWNER}"
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        comment "{NFT_OWNER}:prerouting"
{"".join(redirects)}    }}
    chain output {{
        type nat hook output priority dstnat; policy accept;
        comment "{NFT_OWNER}:output"
{"".join(output_redirects)}    }}
    chain input {{
        type filter hook input priority -5; policy accept;
        comment "{NFT_OWNER}:input"
{"".join(permits)}        ip daddr {PUBLIC_IPV4} tcp dport {{ {DOH_PORT}, {DOH_TLS_PORT} }} reject with tcp reset comment "{NFT_OWNER}:reject-internal-doh"
        ip daddr {PUBLIC_IPV4} tcp dport {{ {STREAM_PORT}, {HTTP_PORT} }} reject with tcp reset comment "{NFT_OWNER}:reject-direct"
    }}
}}
'''


def nft_table_data(*, bootstrap: bool = False) -> dict:
    """Expected semantic JSON from `nft -j list table inet <NFT_TABLE>`."""
    if type(bootstrap) is not bool:
        raise ValueError("bootstrap must be a boolean")
    records = [{"table": {"family": "inet", "name": NFT_TABLE, "comment": NFT_OWNER}}]
    for name, kind, priority in (("prerouting", "nat", -100), ("output", "nat", -100), ("input", "filter", -5)):
        records.append({"chain": {"family": "inet", "table": NFT_TABLE, "name": name,
                                   "type": kind, "hook": name, "prio": priority,
                                   "policy": "accept", "comment": NFT_OWNER + ":" + name}})
    def match(left: dict, right, op: str = "==") -> dict:
        return {"match": {"op": op, "left": left, "right": right}}
    ip = match({"payload": {"protocol": "ip", "field": "daddr"}}, PUBLIC_IPV4)
    def rule(chain: str, expressions: list, name: str) -> dict:
        return {"rule": {"family": "inet", "table": NFT_TABLE, "chain": chain,
                          "expr": expressions, "comment": NFT_OWNER + ":" + name}}
    for chain in ("prerouting", "output"):
        for source, target, name in ((80, HTTP_PORT, "http"), (443, STREAM_PORT, "https")):
            if source == 443 and bootstrap:
                continue
            port = match({"payload": {"protocol": "tcp", "field": "dport"}}, source)
            comment = ("redirect-output-" if chain == "output" else "redirect-") + name
            records.append(rule(chain, [ip, port, {"dnat": {"addr": PUBLIC_IPV4, "family": "ip", "port": target}}], comment))
    dnat = match({"ct": {"key": "status"}}, "dnat", "in")
    original_ip = match({"ct": {"key": "daddr", "family": "ip", "dir": "original"}}, PUBLIC_IPV4)
    for source, target, name in ((80, HTTP_PORT, "http"), (443, STREAM_PORT, "https")):
        if source == 443 and bootstrap:
            continue
        port = match({"payload": {"protocol": "tcp", "field": "dport"}}, target)
        original_port = match({"ct": {"key": "proto-dst", "dir": "original"}}, source)
        records.append(rule("input", [ip, port, dnat, original_ip, original_port, {"accept": None}], "allow-dnat-" + name))
    internal_ports = match({"payload": {"protocol": "tcp", "field": "dport"}}, {"set": [DOH_PORT, DOH_TLS_PORT]})
    records.append(rule("input", [ip, internal_ports, {"reject": {"type": "tcp reset"}}], "reject-internal-doh"))
    ports = match({"payload": {"protocol": "tcp", "field": "dport"}}, {"set": [STREAM_PORT, HTTP_PORT]})
    records.append(rule("input", [ip, ports, {"reject": {"type": "tcp reset"}}], "reject-direct"))
    return {"nftables": records}


def _normalized_nft_records(data: dict | str) -> list:
    if isinstance(data, str):
        data = json.loads(data)
    if not isinstance(data, dict) or set(data) != {"nftables"} or not isinstance(data["nftables"], list):
        raise ValueError("Expected an nft JSON ruleset object")
    records = []
    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items() if key != "handle"}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value
    for record in data["nftables"]:
        if not isinstance(record, dict) or len(record) != 1:
            raise ValueError("Invalid nft JSON record")
        if "metainfo" in record:
            continue
        kind = next(iter(record))
        value = record[kind]
        if kind not in ("table", "chain", "rule") or not isinstance(value, dict):
            raise ValueError("Unexpected object in owned nft table")
        if value.get("family") != "inet" or value.get("name" if kind == "table" else "table") != NFT_TABLE:
            raise ValueError("Foreign table in nft JSON")
        records.append(normalize(record))
    # nft groups rules immediately after each chain, whereas generated records
    # are grouped by kind. Keep rule order within each chain significant.
    tables = [record for record in records if "table" in record]
    chains = sorted((record for record in records if "chain" in record), key=lambda record: record["chain"]["name"])
    rules = sorted((record for record in records if "rule" in record), key=lambda record: record["rule"]["chain"])
    return tables + chains + rules


def nft_table_fingerprint(data: dict | str) -> str:
    """Fingerprint semantic contents; runtime handles/metainfo are excluded."""
    canonical = json.dumps(_normalized_nft_records(data), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def owned_nft_table(data: dict | str, *, bootstrap: bool | None = None) -> bool:
    """Fail closed if an existing table differs from either exact managed form."""
    if bootstrap is not None and type(bootstrap) is not bool:
        raise ValueError("bootstrap must be a boolean or None")
    try:
        actual = nft_table_fingerprint(data)
    except (ValueError, TypeError, KeyError):
        return False
    modes = (False, True) if bootstrap is None else (bootstrap,)
    return any(actual == nft_table_fingerprint(nft_table_data(bootstrap=mode)) for mode in modes)


def generated_files(*, bootstrap: bool = False, loopback_probe: bool = False) -> dict[str, str]:
    if type(bootstrap) is not bool:
        raise ValueError("bootstrap must be a boolean")
    if type(loopback_probe) is not bool:
        raise ValueError("loopback_probe must be a boolean")
    if bootstrap and loopback_probe:
        raise ValueError("The loopback TLS probe requires the final TLS configuration")
    return {
        NGINX_CONFIG: bootstrap_config() if bootstrap else nginx_config(loopback_probe=loopback_probe),
        NFTABLES_CONFIG: nftables_rules(bootstrap=bootstrap),
        "/etc/systemd/system/" + FRONT_SERVICE: front_service(),
    }
