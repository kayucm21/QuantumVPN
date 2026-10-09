"""Read-only, credential-redacted post-deployment Network-center verification.

SSH uses the existing pinned known_hosts entry and QVPN_VDS_PASSWORD only. A
120-second owner cookie is created and used entirely inside the server process;
no cookie, session key, HTML, database rows, config or proxy secret leaves SSH.
The fixed diagnostic SOCKS probe proves WARP egress health, not subscriber route
selection or phone performance. No POST, upload, service control or app import.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import paramiko

HOST = "150.241.96.191"
PUBLIC = "https://pecaocek.ignorelist.com:8443"
EXPECTED_VERSION = "5.11.4"
EXPECTED_CODE = 501104099
EXPECTED_BUILD = "2.3.0-pulse.5"
ABIS = ("arm64-v8a", "armeabi-v7a")
MAX_JSON = 131072
VIEWS = ("overview", "nodes", "dns", "routes", "ai", "mtproto")
SCANNER_VIEWS = ("overview", "dns", "routes")
SCANNER_IDS = ("routing-scan-form", "routing-scan-apply", "routing-scan-dialog", "routing-catalog-dialog")
CATALOG_PROBES = ("ipv4", "ipv6", "domain", "seed_search")
SAFE_REMOTE_ERRORS = {
    "command_failed", "command_output_bound", "operator_pid", "environment_bound", "public_origin",
    "private_file_permissions", "private_file_bound", "data_directory", "database_file", "enabled_owner",
    "session_key_length", "loopback_bind", "operator_port", "response_bound", "page_credential_exposure",
    "route_lab_scope", "mtproto_module_missing", "mtproto_status_shape", "mtproto_service_shape",
    "mtproto_not_ready", "warp_metrics", "warp_tls_status", "warp_family", "panel_services",
    "verification_runtime_failure",
} | {f"page_{kind}_{view}" for view in VIEWS for kind in ("status", "build", "marker", "cache", "csrf", "forms", "scanner_ids")} | {
    f"catalog_{kind}_{name}" for name in CATALOG_PROBES for kind in ("status", "cache", "bound", "shape", "target", "family", "search")} | {
    f"api_{kind}_{abi}_{name}" for abi in ABIS for name in ("legacy", "updater") for kind in ("status", "release")}


REMOTE_SOURCE = r'''
import base64, hashlib, hmac, http.client, ipaddress, json, os, re, secrets
from contextlib import closing
from html.parser import HTMLParser
from pathlib import Path
import socket, sqlite3, ssl, stat, subprocess, sys, time
from urllib.parse import urlencode, urlsplit

sys.dont_write_bytecode = True
PUBLIC = 'https://pecaocek.ignorelist.com:8443'
BUILD = '2.3.0-pulse.5'
VERSION = '5.11.4'
VERSION_CODE = 501104099
VIEWS = ('overview', 'nodes', 'dns', 'routes', 'ai', 'mtproto')
SCANNER_VIEWS = ('overview', 'dns', 'routes')
SCANNER_IDS = ('routing-scan-form', 'routing-scan-apply', 'routing-scan-dialog', 'routing-catalog-dialog')

class CheckFailed(Exception):
    pass

def require(value, label):
    if not value:
        raise CheckFailed(label)

def command(argv, timeout=8, maximum=131072):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'command_failed')
    require(len(result.stdout) <= maximum and len(result.stderr) <= maximum, 'command_output_bound')
    return result.stdout

def service_state(service):
    result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, timeout=4)
    state = result.stdout.decode('ascii', errors='replace').strip()
    return state if state in ('active', 'inactive', 'failed', 'activating', 'deactivating') else 'unknown'

def environment():
    pid = command(['systemctl', 'show', '--property=MainPID', '--value', 'quantumvpn-operator'], timeout=4).strip()
    require(re.fullmatch(rb'[1-9][0-9]{0,9}', pid), 'operator_pid')
    raw = (Path('/proc') / pid.decode('ascii') / 'environ').read_bytes()
    require(len(raw) <= 1048576, 'environment_bound')
    values = {}
    for entry in raw.split(b'\0'):
        if b'=' in entry:
            key, value = entry.split(b'=', 1)
            if key.startswith(b'QV_'):
                values[key.decode('ascii')] = value.decode('utf-8', 'strict')
    require(values.get('QV_PUBLIC_BASE', PUBLIC).rstrip('/') == PUBLIC, 'public_origin')
    return values

def private_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                'private_file_permissions')
        require(info.st_size <= maximum, 'private_file_bound')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = stream.read(maximum + 1)
        require(len(value) <= maximum, 'private_file_bound')
        return value
    finally:
        os.close(fd)

def owner_cookie(env):
    data = Path(env.get('QV_DATA_DIR', '/var/lib/quantumvpn-operator'))
    require(data.is_absolute() and data.is_dir() and not data.is_symlink(), 'data_directory')
    database = data / 'operator.db'
    require(database.is_file() and not database.is_symlink(), 'database_file')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.execute('pragma query_only=on')
        owner = db.execute("select username from admin_users where role='owner' and enabled=1 order by username limit 1").fetchone()
    require(owner and isinstance(owner[0], str) and 1 <= len(owner[0]) <= 128, 'enabled_owner')
    key = private_bytes(data / 'session.secret', 64)
    require(len(key) == 32, 'session_key_length')
    encode = lambda value: base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')
    payload = {'u': owner[0], 'exp': int(time.time()) + 120, 'n': secrets.token_hex(16)}
    body = encode(json.dumps(payload, separators=(',', ':')).encode())
    signature = encode(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return 'qv_session=' + body + '.' + signature

class LoopbackHTTPS(http.client.HTTPSConnection):
    """Verify the public certificate/SNI while connecting only to local TLS."""
    def __init__(self, address, port, timeout):
        super().__init__(urlsplit(PUBLIC).hostname, port, timeout=timeout, context=ssl.create_default_context())
        self.loopback_address = address

    def connect(self):
        sock = socket.create_connection((self.loopback_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

def request(env, path, cookie=None, timeout=10):
    bind = env.get('QV_BIND', '0.0.0.0')
    require(bind in ('0.0.0.0', '127.0.0.1', '::', '::1', 'localhost'), 'loopback_bind')
    address = '::1' if bind in ('::', '::1') else '127.0.0.1'
    port = int(env.get('QV_PORT', '8765'))
    require(1 <= port <= 65535, 'operator_port')
    terminated = env.get('QV_TLS_TERMINATED', '').strip() in ('1', 'true', 'yes')
    local_tls = bool(env.get('QV_TLS_CERT') and env.get('QV_TLS_KEY') and not terminated)
    connection = LoopbackHTTPS(address, port, timeout) if local_tls else http.client.HTTPConnection(address, port, timeout=timeout)
    headers = {'Host': urlsplit(PUBLIC).netloc, 'User-Agent': 'QuantumVPN-Network-ReadOnly-Probe'}
    if cookie:
        headers['Cookie'] = cookie
    try:
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        require(len(body) <= 4 * 1024 * 1024, 'response_bound')
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()

class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.current = None
        self.forms = []
        self.stack = []
        self.nested_forms = 0
        self.ids = {}
        self.network_views = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        identifier = attrs.get('id')
        if identifier:
            self.ids.setdefault(identifier, []).append(tag)
        if 'data-network-view' in attrs:
            self.network_views.append(attrs['data-network-view'])
        if tag == 'form':
            if self.stack:
                self.nested_forms += 1
            self.current = {'action': attrs.get('action', ''), 'csrf': False, 'network_return': False}
            self.stack.append(self.current)
        elif tag == 'input' and self.current is not None:
            if attrs.get('name') == 'csrf' and len(attrs.get('value', '')) >= 32:
                self.current['csrf'] = True
            if attrs.get('name') == 'return_tab' and attrs.get('value') == 'network':
                self.current['network_return'] = True

    def handle_endtag(self, tag):
        if tag == 'form' and self.stack:
            self.forms.append(self.stack.pop())
            self.current = self.stack[-1] if self.stack else None

def page_check(env, cookie, view, target=''):
    query = {'tab': 'network', 'network_view': view}
    if target:
        query['network_target'] = target
    status, headers, body = request(env, '/operator?' + urlencode(query), cookie)
    require(status == 200, 'page_status_' + view)
    require(('QuantumControl/' + BUILD) in headers.get('Server', ''), 'page_build_' + view)
    require(b'secret=' not in body and cookie.encode() not in body, 'page_credential_exposure')
    require('no-store' in headers.get('Cache-Control', ''), 'page_cache_' + view)
    forms = Forms()
    forms.feed(body.decode('utf-8', 'strict'))
    require(b'NETWORK CENTER' in body and view in forms.network_views, 'page_marker_' + view)
    require(not forms.nested_forms and not forms.stack, 'page_forms_' + view)
    scanner_ids = {identifier: len(forms.ids.get(identifier, [])) for identifier in SCANNER_IDS}
    if view in SCANNER_VIEWS:
        expected = dict(zip(SCANNER_IDS, ('form', 'form', 'dialog', 'dialog')))
        require(all(forms.ids.get(identifier) == [tag] for identifier, tag in expected.items()), 'page_scanner_ids_' + view)
    selected = [form for form in forms.forms if form['action'].startswith('/operator/network/') or form['network_return']]
    require((selected or view == 'nodes') and all(form['csrf'] for form in selected), 'page_csrf_' + view)
    if target:
        require(target.encode() in body and 'Серверный сценарий VLESS/TCP 443, не личная сессия'.encode() in body,
                'route_lab_scope')
    return {'status': 200, 'network_marker': True, 'build_matched': True,
            'credential_free': True, 'csrf_forms': len(selected), 'lab_scenario': bool(target),
            'scanner_ids': scanner_ids, 'nested_forms': forms.nested_forms}

def catalog_check(env, cookie, name):
    # The only catalog probes are bounded, authenticated GETs against this
    # server. No catalog entry is resolved/probed or placed into a draft.
    probes = {'ipv4': ('ipv4', '', 4), 'ipv6': ('ipv6', '', 6),
              'domain': ('domain', '', None), 'seed_search': ('domain', 'youtube', None)}
    require(name in probes, 'catalog_shape_domain')
    kind, query, family = probes[name]
    path = '/operator/routing/catalog?' + urlencode({'kind': kind, 'q': query, 'offset': 0, 'limit': 50})
    status, headers, body = request(env, path, cookie)
    require(status == 200, 'catalog_status_' + name)
    require('no-store' in headers.get('Cache-Control', ''), 'catalog_cache_' + name)
    require(len(body) <= 131072, 'catalog_bound_' + name)
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        raise CheckFailed('catalog_shape_' + name) from None
    require(isinstance(value, dict), 'catalog_shape_' + name)
    total, matched, offset, limit, max_scan = (value.get(key) for key in ('total', 'matched', 'offset', 'limit', 'max_scan'))
    items = value.get('items')
    require(all(type(count) is int for count in (total, matched, offset, limit, max_scan))
            and 0 <= matched <= total <= 100000 and offset == 0 and limit == 50 and max_scan == 24
            and value.get('kind') == kind and value.get('query') == query
            and isinstance(items, list) and len(items) == min(50, matched), 'catalog_shape_' + name)
    seen = set()
    for item in items:
        require(isinstance(item, dict), 'catalog_target_' + name)
        target = item.get('target')
        require(isinstance(target, str) and 1 <= len(target) <= 253 and target not in seen
                and item.get('kind') == ('ip' if family else 'domain') and item.get('selectable') is True,
                'catalog_target_' + name)
        seen.add(target)
        if family:
            try:
                address = ipaddress.ip_address(target)
            except ValueError:
                raise CheckFailed('catalog_family_' + name) from None
            require('%' not in target and str(address) == target
                    and type(item.get('ip_version')) is int and item['ip_version'] == family == address.version
                    and address.is_global and not address.is_multicast and not address.is_reserved
                    and not address.is_unspecified and not address.is_loopback and not address.is_link_local,
                    'catalog_family_' + name)
        else:
            require(item.get('ip_version') is None and '.' in target and ':' not in target and '/' not in target,
                    'catalog_family_' + name)
        if query:
            require(query in target.lower(), 'catalog_search_' + name)
    if query:
        require(matched > 0, 'catalog_search_' + name)
    return {'status': 200, 'total': total, 'matched': matched, 'returned': len(items),
            'limit': 50, 'max_scan': 24, 'ip_family': family}

def mtproto_status(required):
    script = Path('/opt/quantumvpn-operator/quantumvpn_mtproto.py')
    require(script.is_file() and not script.is_symlink(), 'mtproto_module_missing')
    value = json.loads(command(['python3', '-B', str(script)], timeout=12))
    require(isinstance(value, dict) and type(value.get('installed')) is bool, 'mtproto_status_shape')
    state = value.get('service')
    require(state in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'unknown'), 'mtproto_service_shape')
    result = {'installed': value['installed'], 'service': state,
              'stats_loopback_only': value.get('stats_loopback_only') is True,
              'secret_available': value.get('secret_available') is True,
              'upstream_ready': value.get('upstream_ready') if type(value.get('upstream_ready')) is bool else None}
    stats = value.get('stats') if isinstance(value.get('stats'), dict) else {}
    ready = stats.get('total_ready_targets')
    result['ready_targets'] = ready if type(ready) is int and 0 <= ready <= 1000000 else None
    if required:
        require(result['installed'] and state == 'active' and result['stats_loopback_only']
                and result['secret_available'] and result['upstream_ready'] is True, 'mtproto_not_ready')
    return result

def warp_trace(family):
    url = 'https://1.1.1.1/cdn-cgi/trace' if family == 4 else 'https://[2606:4700:4700::1111]/cdn-cgi/trace'
    args = ['curl', '--silent', '--show-error', '--noproxy', '', '--socks5-hostname', '127.0.0.1:18081',
            '--proto', '=https', '--connect-timeout', '4', '--max-time', '12', '--max-filesize', '8192',
            '--write-out', '\n%{json}', url]
    raw = command(args, timeout=16, maximum=32768).decode('utf-8', 'strict')
    body, separator, metrics = raw.rpartition('\n')
    require(separator, 'warp_metrics')
    info = json.loads(metrics)
    fields = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    require(info.get('ssl_verify_result') == 0 and info.get('http_code') == 200, 'warp_tls_status')
    require(fields.get('warp') == 'on' and ipaddress.ip_address(fields.get('ip', '')).version == family, 'warp_family')
    return {'status': 200, 'tls_verified': True, 'warp': True, 'ip_family': family}

def verify(config):
    services = {name: service_state(name) for name in ('quantumvpn-operator', 'rospanel')}
    require(all(state == 'active' for state in services.values()), 'panel_services')
    env = environment()
    cookie = owner_cookie(env)
    pages = {view: page_check(env, cookie, view) for view in VIEWS}
    routes = {'instagram_domain': page_check(env, cookie, 'routes', 'instagram.com'),
              'public_ipv6': page_check(env, cookie, 'routes', '2001:4860:4860::8888')}
    catalog = {name: catalog_check(env, cookie, name) for name in ('ipv4', 'ipv6', 'domain', 'seed_search')}
    apis = {}
    for abi in ('arm64-v8a', 'armeabi-v7a'):
        apis[abi] = {}
        for name, path in (('legacy', '/api/app/version'), ('updater', '/api/client/update')):
            status, headers, raw = request(env, path + '?abi=' + abi + '&current_version_code=0', timeout=30)
            require(status == 200, 'api_status_' + abi + '_' + name)
            value = json.loads(raw)
            require(value.get('version') == VERSION and value.get('version_code') == VERSION_CODE, 'api_release_' + abi + '_' + name)
            apis[abi][name] = {'status': 200, 'version': VERSION, 'version_code': VERSION_CODE}
    return {'ok': True, 'mode': 'read-only', 'panel_build': BUILD, 'services': services,
            'pages': pages, 'route_lab': routes, 'catalog': catalog, 'local_apis': apis,
            'mtproto': mtproto_status(config.get('require_mtproto') is True),
            'warp': {'scope': 'unconditional-diagnostic-SOCKS-not-subscriber-routing',
                     'ipv4': warp_trace(4), 'ipv6': warp_trace(6)}}

try:
    result = verify(CONFIG)
except CheckFailed as error:
    result = {'ok': False, 'error': str(error)}
except Exception:
    result = {'ok': False, 'error': 'verification_runtime_failure'}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
raise SystemExit(0 if result['ok'] else 1)
'''


class CheckFailed(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def artifact_url(value: object, abi: str) -> str:
    """Reject redirects/alternate origins before any external download request."""
    if not isinstance(value, str) or abi not in ABIS:
        raise CheckFailed("artifact_url_shape")
    parsed = urlsplit(value)
    expected = f"/downloads/{EXPECTED_VERSION}/QuantumVPN-{EXPECTED_VERSION}-operator-debug-{abi}.apk"
    if (parsed.scheme != "https" or parsed.netloc != urlsplit(PUBLIC).netloc or parsed.path != expected
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise CheckFailed("artifact_url_scope")
    return value


def external_verification() -> dict:
    # Default HTTPS certificate/hostname verification; no ambient proxy or
    # redirect can send these fixed probes to another endpoint.
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    result = {}
    for abi in ABIS:
        result[abi] = {}
        for name, path in (("legacy", "/api/app/version"), ("updater", "/api/client/update")):
            request = Request(PUBLIC + path + "?abi=" + abi + "&current_version_code=0",
                              headers={"User-Agent": "QuantumVPN-Network-ReadOnly-Probe"})
            with opener.open(request, timeout=30) as response:
                raw = response.read(MAX_JSON + 1)
                if response.status != 200 or len(raw) > MAX_JSON:
                    raise CheckFailed("external_api_status")
            info = json.loads(raw)
            if info.get("version") != EXPECTED_VERSION or info.get("version_code") != EXPECTED_CODE:
                raise CheckFailed("external_api_release")
            url = artifact_url(info.get("url"), abi)
            size = info.get("size")
            if type(size) is not int or size <= 0 or not re.fullmatch(r"[0-9a-f]{64}", info.get("sha256", "")):
                raise CheckFailed("external_artifact_metadata")
            with opener.open(Request(url, method="HEAD", headers={"User-Agent": "QuantumVPN-Network-ReadOnly-Probe"}), timeout=20) as response:
                if response.status != 200 or response.headers.get("Content-Length") != str(size):
                    raise CheckFailed("external_head_status")
            result[abi][name] = {"status": 200, "version": EXPECTED_VERSION, "version_code": EXPECTED_CODE,
                                 "head_status": 200, "bytes": size, "tls_verified": True}
    return result


def remote_verification(client, require_mtproto=False) -> dict:
    script = "CONFIG = " + repr({"require_mtproto": require_mtproto is True}) + "\n" + REMOTE_SOURCE
    stdin, stdout, stderr = client.exec_command("python3 -B -", timeout=240)
    stdin.write(script)
    stdin.channel.shutdown_write()
    output = stdout.read(MAX_JSON + 1)
    # Never print server stderr or raw stdout: they could contain private data.
    stderr.read(MAX_JSON + 1)
    status = stdout.channel.recv_exit_status()
    if len(output) > MAX_JSON:
        raise CheckFailed("remote_result_bound")
    try:
        value = json.loads(output)
    except (ValueError, TypeError):
        raise CheckFailed("remote_result_unstructured") from None
    if not isinstance(value, dict):
        raise CheckFailed("remote_result_shape")
    if status or value.get("ok") is not True:
        label = value.get("error")
        if not isinstance(label, str) or label not in SAFE_REMOTE_ERRORS:
            label = "remote_verification_failed"
        raise CheckFailed(label)
    return redact_result(value)


def redact_result(value: dict) -> dict:
    """Validate every output leaf and drop any unexpected nested private field."""
    if set(value) != {"ok", "mode", "panel_build", "services", "pages", "route_lab", "catalog", "local_apis", "mtproto", "warp"}:
        raise CheckFailed("remote_result_fields")
    if value.get("mode") != "read-only" or value.get("panel_build") != EXPECTED_BUILD or value.get("ok") is not True:
        raise CheckFailed("remote_result_identity")

    def boolean(raw, key, nullable=False):
        item = raw.get(key)
        if type(item) is bool or nullable and item is None:
            return item
        raise CheckFailed("remote_result_shape")

    def integer(raw, key, minimum, maximum, nullable=False):
        item = raw.get(key)
        if nullable and item is None:
            return None
        if type(item) is int and minimum <= item <= maximum:
            return item
        raise CheckFailed("remote_result_shape")

    def page(raw, view):
        if not isinstance(raw, dict) or raw.get("status") != 200:
            raise CheckFailed("remote_result_page")
        identifiers = raw.get("scanner_ids")
        if not isinstance(identifiers, dict):
            raise CheckFailed("remote_result_page")
        counts = {identifier: integer(identifiers, identifier, 0, 100) for identifier in SCANNER_IDS}
        if view in SCANNER_VIEWS and any(count != 1 for count in counts.values()):
            raise CheckFailed("remote_result_page")
        return {"status": 200, **{key: boolean(raw, key) for key in (
            "network_marker", "build_matched", "credential_free", "lab_scenario")},
                "csrf_forms": integer(raw, "csrf_forms", 0, 100), "scanner_ids": counts,
                "nested_forms": integer(raw, "nested_forms", 0, 0)}

    try:
        services = {name: value["services"][name] for name in ("quantumvpn-operator", "rospanel")}
        if any(state != "active" for state in services.values()):
            raise CheckFailed("remote_result_services")
        pages = {view: page(value["pages"][view], view) for view in VIEWS}
        route_lab = {kind: page(value["route_lab"][kind], "routes") for kind in ("instagram_domain", "public_ipv6")}
        catalog = {}
        for name in CATALOG_PROBES:
            raw = value["catalog"][name]
            family = 4 if name == "ipv4" else (6 if name == "ipv6" else None)
            total = integer(raw, "total", 0, 100000)
            matched = integer(raw, "matched", 0, total)
            returned = integer(raw, "returned", 0, 50)
            if (raw.get("status") != 200 or raw.get("ip_family") != family or
                    family is not None and type(raw.get("ip_family")) is not int or
                    returned != min(50, matched) or name == "seed_search" and matched == 0):
                raise CheckFailed("remote_result_catalog")
            catalog[name] = {"status": 200, "total": total, "matched": matched, "returned": returned,
                             "limit": integer(raw, "limit", 50, 50), "max_scan": integer(raw, "max_scan", 24, 24),
                             "ip_family": family}
        apis = {}
        for abi in ABIS:
            apis[abi] = {}
            for name in ("legacy", "updater"):
                raw = value["local_apis"][abi][name]
                if (raw.get("status") != 200 or raw.get("version") != EXPECTED_VERSION
                        or raw.get("version_code") != EXPECTED_CODE):
                    raise CheckFailed("remote_result_api")
                apis[abi][name] = {"status": 200, "version": EXPECTED_VERSION, "version_code": EXPECTED_CODE}
        raw = value["mtproto"]
        if raw.get("service") not in ("active", "inactive", "failed", "activating", "deactivating", "unknown"):
            raise CheckFailed("remote_result_proxy")
        proxy = {"service": raw["service"], **{key: boolean(raw, key) for key in (
            "installed", "stats_loopback_only", "secret_available")},
                 "upstream_ready": boolean(raw, "upstream_ready", nullable=True),
                 "ready_targets": integer(raw, "ready_targets", 0, 1000000, nullable=True)}
        raw = value["warp"]
        scope = "unconditional-diagnostic-SOCKS-not-subscriber-routing"
        if raw.get("scope") != scope:
            raise CheckFailed("remote_result_warp_scope")
        warp = {"scope": scope}
        for name, family in (("ipv4", 4), ("ipv6", 6)):
            trace = raw[name]
            if (trace.get("status") != 200 or trace.get("ip_family") != family
                    or trace.get("warp") is not True or trace.get("tls_verified") is not True):
                raise CheckFailed("remote_result_warp")
            warp[name] = {"status": 200, "tls_verified": True, "warp": True, "ip_family": family}
    except (KeyError, TypeError, AttributeError):
        raise CheckFailed("remote_result_shape") from None
    return {"ok": True, "mode": "read-only", "panel_build": EXPECTED_BUILD, "services": services,
            "pages": pages, "route_lab": route_lab, "catalog": catalog, "local_apis": apis, "mtproto": proxy, "warp": warp}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    result.add_argument("--require-mtproto", action="store_true", help="Require the installed proxy to be active with ready Telegram upstreams")
    return result


def main() -> int:
    args = parser().parse_args()
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password:
        raise CheckFailed("password_environment_missing")
    if not args.known_hosts.is_file():
        raise CheckFailed("pinned_known_hosts_missing")
    client = paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(HOST, port=22, username="root", password=password, timeout=15,
                       auth_timeout=20, banner_timeout=20, allow_agent=False, look_for_keys=False)
        result = remote_verification(client, args.require_mtproto)
    finally:
        client.close()
    result["external_apis"] = external_verification()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailed as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")))
        raise SystemExit(1)
    except Exception:
        print(json.dumps({"ok": False, "error": "verification_runtime_failure"}, separators=(",", ":")))
        raise SystemExit(1)
