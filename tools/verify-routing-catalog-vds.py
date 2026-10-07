"""Read-only post-deployment routing catalogue/API verification over pinned SSH.

Only existing administrator Basic Auth from the running service is used. GET
handlers may index known catalogue entries normally; this tool performs no POST,
probe scan, policy publication, app import, credential minting or file upload.
Output contains check labels/counts only, never response bodies or credentials.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

import paramiko


REMOTE_VERIFY = r'''
import base64, http.client, ipaddress, json, signal, ssl, time
from pathlib import Path
from urllib.parse import urlencode

_helpers = {'__name__': 'catalog_verification_helpers'}
exec(DEPLOY_SOURCE, _helpers)

def _get(env, path, authorization=None):
    require = _helpers['require']
    bind = env.get('QV_BIND', '0.0.0.0')
    require(bind in ('0.0.0.0','127.0.0.1','::','::1','localhost'), 'loopback_not_bound')
    host = '::1' if bind in ('::','::1') else '127.0.0.1'
    port = int(env.get('QV_PORT', '8765'))
    terminated = env.get('QV_TLS_TERMINATED', '').strip() in ('1','true','yes')
    tls = bool(env.get('QV_TLS_CERT') and env.get('QV_TLS_KEY') and not terminated)
    if tls:
        # Loopback is authenticated by the pinned SSH host, just as deployment.
        connection = http.client.HTTPSConnection(host,port,timeout=7,context=ssl._create_unverified_context())
    else:
        connection = http.client.HTTPConnection(host,port,timeout=7)
    headers = {'User-Agent':'QuantumVPN-Catalog-Verification'}
    if authorization is not None:
        headers['Authorization'] = authorization
    try:
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        require(len(body) <= 4 * 1024 * 1024, 'catalog_response_size')
        return response.status, {key.lower():value for key,value in response.getheaders()}, body
    finally:
        connection.close()

def verify():
    require = _helpers['require']
    env = _helpers['environment']()
    user, password = env.get('QV_ADMIN_USER'), env.get('QV_ADMIN_PASSWORD')
    require(isinstance(user,str) and bool(user) and isinstance(password,str) and bool(password), 'service_basic_credentials_missing')
    authorization = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
    data = Path(env.get('QV_DATA_DIR','/var/lib/quantumvpn-operator'))
    before = _helpers['db_snapshot'](data)
    signing_before = _helpers['key_snapshot'](data)
    public_before = _helpers['public_snapshot'](env,signing_before[1])

    status, headers, body = _get(env,'/operator/health',authorization)
    require(status == 200, 'operator_health_http')
    health = json.loads(body)
    require(health.get('operator_api') == 'ok' and health.get('panel_build') == EXPECTED_BUILD, 'operator_build')
    status, headers, body = _get(env,'/operator?tab=routing',authorization)
    require(status == 200 and b'routing-catalog-dialog' in body and b'data-catalog-open' in body, 'routing_catalog_markup')

    def catalog(**parameters):
        path = '/operator/routing/catalog' + ('?' + urlencode(parameters) if parameters else '')
        status, headers, body = _get(env,path,authorization)
        require(status == 200, 'catalog_http')
        require('no-store' in headers.get('cache-control','').lower(), 'catalog_cache_control')
        require(headers.get('content-type','').lower().startswith('application/json'), 'catalog_content_type')
        value = json.loads(body)
        require(isinstance(value,dict) and isinstance(value.get('items'),list), 'catalog_structure')
        require(type(value.get('total')) is int and type(value.get('matched')) is int, 'catalog_counts')
        require(0 <= len(value['items']) <= 50 and value['matched'] <= value['total'], 'catalog_page_bounds')
        targets = [item.get('target') for item in value['items'] if isinstance(item,dict)]
        require(len(targets) == len(value['items']) and all(isinstance(target,str) for target in targets)
                and len(targets) == len(set(targets)), 'catalog_page_duplicate')
        return value

    first = catalog()
    require(first['total'] >= MINIMUM_TARGETS and len(first['items']) == 50, 'catalog_seed_count')
    second = catalog(offset=50,limit=50)
    require(second['total'] == first['total'] and second.get('offset') == 50 and len(second['items']) == 50, 'catalog_second_page')
    require(not {item['target'] for item in first['items']} & {item['target'] for item in second['items']}, 'catalog_page_overlap')
    youtube = catalog(q='youtube',kind='domain')
    require(youtube['matched'] > 0 and all('youtube' in item['target'].lower() or any('youtube' in address.lower() for address in item.get('addresses',[]) if isinstance(address,str))
                                        for item in youtube['items']), 'catalog_youtube_search')
    ips = catalog(kind='ip',limit=1)
    address = ips['items'][0]['target'] if ips['items'] else '1.1.1.1'
    require(ipaddress.ip_address(address).is_global, 'catalog_public_ip')
    ip_result = catalog(q=address,kind='ip')
    require(not ips['items'] or any(item['target'] == address for item in ip_result['items']), 'catalog_ip_search')
    status, headers, body = _get(env,'/operator/routing/catalog')
    require(status == 401, 'catalog_noauth_status')
    status, headers, body = _get(env,'/operator/routing/catalog?kind=invalid',authorization)
    require(status == 400, 'catalog_invalid_kind_status')
    require('no-store' in headers.get('cache-control','').lower(), 'catalog_invalid_kind_cache')

    public_after = _helpers['public_snapshot'](env,signing_before[1])
    require(public_after == public_before, 'public_api_changed')
    require(_helpers['key_snapshot'](data) == signing_before, 'signing_identity_changed')
    require(_helpers['db_snapshot'](data) == before, 'public_settings_changed')
    return {'ok':True,'panel_build':health['panel_build'],'catalog_total':first['total'],
            'page_size':len(first['items']),'second_page_size':len(second['items']),
            'youtube_matches':youtube['matched'],'ip_matches':ip_result['matched'],
            'noauth_status':401,'invalid_kind_status':400,'cache_control':'no-store',
            'configuration':'unchanged','public_api':'unchanged','signing_identity':'unchanged'}

def _catalog_main():
    def expired(signum, frame):
        _helpers['require'](False,'catalog_verification_deadline')
    signal.signal(signal.SIGALRM,expired)
    signal.alarm(45)
    try:
        print(json.dumps(verify(),sort_keys=True))
    except BaseException as error:
        label = str(error) if isinstance(error,_helpers['CheckFailed']) else type(error).__name__
        # All CheckFailed labels originate from fixed local checks. No HTTP
        # response, environment value or authentication header is printed.
        print(json.dumps({'ok':False,'error':label},sort_keys=True))
        raise SystemExit(1)
    finally:
        signal.alarm(0)
'''


def deploy_source() -> str:
    spec = importlib.util.spec_from_file_location("catalog_deployer", Path(__file__).with_name("deploy-aurora-panel.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.REMOTE_SOURCE


def script(expected_build: str, minimum_targets: int) -> str:
    return ("DEPLOY_SOURCE=" + repr(deploy_source()) + "\nEXPECTED_BUILD=" + repr(expected_build)
            + "\nMINIMUM_TARGETS=" + repr(minimum_targets) + "\n" + REMOTE_VERIFY
            + "\nif __name__ == '__main__':\n    _catalog_main()\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    parser.add_argument("--expected-build", default="2.2.1-routing.1")
    parser.add_argument("--minimum-targets", type=int, default=2884)
    args = parser.parse_args()
    password = os.environ.get("QVPN_VDS_PASSWORD")
    if not password or not args.known_hosts.is_file() or not 1 <= args.port <= 65535 or not 100 <= args.minimum_targets <= 100_000:
        raise ValueError("verification_configuration_invalid")
    client = paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(args.host,port=args.port,username=args.user,password=password,
                       timeout=12,auth_timeout=15,banner_timeout=15,allow_agent=False,look_for_keys=False)
        stdin, stdout, stderr = client.exec_command("python3 -",timeout=55)
        stdin.write(script(args.expected_build,args.minimum_targets))
        stdin.channel.shutdown_write()
        output = stdout.read(32 * 1024 + 1)
        stderr.read(16 * 1024)
        status = stdout.channel.recv_exit_status()
        if len(output) > 32 * 1024:
            raise RuntimeError("verification_response_size")
        result = json.loads(output)
        if not isinstance(result,dict) or status or result.get("ok") is not True:
            # Remote failure labels are fixed; never echo arbitrary response.
            error = result.get("error","") if isinstance(result,dict) else ""
            if not isinstance(error,str) or not error or len(error) > 120 or any(not (c.isascii() and (c.isalnum() or c in "_.-")) for c in error):
                error = "remote_verification_failed"
            print(json.dumps({"ok":False,"error":error},sort_keys=True))
            return 1
        print(json.dumps(result,sort_keys=True))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError,OSError,RuntimeError,paramiko.SSHException) as error:
        print(json.dumps({"ok":False,"error":type(error).__name__},sort_keys=True))
        raise SystemExit(1)
