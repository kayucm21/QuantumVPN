"""Explicit owner link/health verification; never prints secrets or controls services.

The only POSTs are three link revelations and the WEB health proof needed before
revelation. Authentication, CSRF and connection links stay inside VDS memory.
Uses the same pinned SSH/TLS checks as verify-network-pulse.py.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys

import paramiko


PROBE_SOURCE = r'''
from urllib.parse import parse_qs

class LinkFields(HTMLParser):
    def __init__(self):
        super().__init__(); self.csrf = []; self.fields = {}; self.current = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name') == 'csrf':
            self.csrf.append(attrs.get('value', ''))
        if tag == 'textarea':
            self.current = attrs.get('id'); self.fields[self.current] = ''
    def handle_data(self, value):
        if self.current is not None:
            self.fields[self.current] += value
    def handle_endtag(self, tag):
        if tag == 'textarea': self.current = None

def post(env, cookie, action, csrf):
    # Exact host, path and Origin; no HTTP redirects or external destination.
    port = int(env.get('QV_PORT', '8765'))
    bind = env.get('QV_BIND', '127.0.0.1')
    require(bind in ('0.0.0.0','127.0.0.1','::','::1','localhost'), 'loopback_bind')
    address = '::1' if bind in ('::','::1') else '127.0.0.1'
    terminated = env.get('QV_TLS_TERMINATED', '').strip() in ('1','true','yes')
    tls = bool(env.get('QV_TLS_CERT') and env.get('QV_TLS_KEY') and not terminated)
    connection = LoopbackHTTPS(address, port, 40) if tls else http.client.HTTPConnection(address, port, timeout=40)
    try:
        connection.request('POST', '/operator/network/mtproto', urlencode({'action':action,'csrf':csrf}),
            {'Host':urlsplit(PUBLIC).netloc, 'Origin':PUBLIC, 'Sec-Fetch-Site':'same-origin',
             'Cookie':cookie, 'Content-Type':'application/x-www-form-urlencoded',
             'Accept':'application/json', 'X-QV-Request':'1'})
        response = connection.getresponse(); raw = response.read(131073)
        require(len(raw) <= 131072, 'response_bound')
        return response.status, dict(response.getheaders()), raw
    finally:
        connection.close()

def panel_links_check():
    env = environment(); cookie = owner_cookie(env)
    status, headers, raw = request(env, '/operator?tab=network&network_view=mtproto', cookie)
    require(status == 200 and ('QuantumControl/'+BUILD) in headers.get('Server',''), 'page_status_mtproto')
    fields = LinkFields(); fields.feed(raw.decode('utf-8'))
    tokens = {value for value in fields.csrf if len(value) >= 32}
    require(len(tokens) == 1, 'page_csrf_mtproto'); token = tokens.pop()
    status, headers, raw = post(env, cookie, 'web_probe', token)
    require(status == 303, 'web_probe_failed')
    results = {}
    for kind, action, port in (('mtproto','links',3443),('tls','tls_links',5443),('web','web_links',443)):
        status, headers, raw = post(env, cookie, action, token)
        require(status == 200 and 'no-store' in headers.get('Cache-Control',''), 'link_response_failed')
        value = json.loads(raw); require(isinstance(value,dict) and isinstance(value.get('html'),str), 'link_shape_failed')
        markup = LinkFields(); markup.feed(value['html'])
        pair = []
        for variant in ('telegram','https'):
            link = markup.fields.get('proxy-'+kind+'-'+variant+'-link','')
            parsed = urlsplit(link); query = parse_qs(parsed.query, strict_parsing=True)
            require(parsed.scheme == ('tg' if variant == 'telegram' else 'https'), 'link_shape_failed')
            expected = 'webproxy' if kind == 'web' else 'proxy'
            require((parsed.netloc,parsed.path) == ((expected,'') if variant == 'telegram' else ('t.me','/'+expected)), 'link_shape_failed')
            require(set(query) == ({'server','secret'} if kind == 'web' else {'server','secret','port'})
                    and all(len(values) == 1 for values in query.values()), 'link_shape_failed')
            server = query['server'][0]
            require(bool(re.fullmatch(r'pecaocek\.ignorelist\.com/[a-z0-9_-]{8,64}',server)) if kind == 'web' else server == 'pecaocek.ignorelist.com', 'domain_link_failed')
            require(kind == 'web' or query['port'] == [str(port)], 'domain_port_failed')
            secret = query['secret'][0]
            require(bool(re.fullmatch(r'dd[a-f0-9]{32}',secret)) if kind == 'mtproto' else
                    bool(re.fullmatch(r'ee[a-f0-9]{32}'+b'pecaocek.ignorelist.com'.hex(),secret)) if kind == 'tls' else
                    bool(re.fullmatch(r'[A-Za-z0-9_-]{23}',secret)), 'link_shape_failed')
            if kind == 'web':
                decoded = base64.urlsafe_b64decode(secret+'=')
                require(len(decoded) == 17 and decoded[0] == 0x70
                        and base64.urlsafe_b64encode(decoded).decode().rstrip('=') == secret, 'link_shape_failed')
            pair.append(query)
        require(pair[0] == pair[1], 'link_shape_failed')
        require('data-proxy-copy=' in value['html'] and 'Открыть Telegram' in value['html'], 'link_controls_failed')
        results[kind] = {'domain':True,'port':port,'no_store':True,'matching_pair':True,'copy_open_controls':True}
    status, headers, raw = request(env, '/operator?tab=quality', cookie)
    require(status == 200 and 'Качество клиентов'.encode() in raw and 'Проверка восстановления'.encode() in raw, 'quality_page_failed')
    markup = Forms(); markup.feed(raw.decode('utf-8'))
    require(not markup.nested_forms and not markup.stack, 'quality_page_failed')
    return {'ok':True, 'build':BUILD, 'proxy_links':results, 'quality_page':{'status':200,'nested_forms':0}, 'scope':'owner-link-posts-and-web-health-only'}

try:
    result = panel_links_check()
except CheckFailed as error:
    allowed = {'loopback_bind','response_bound','page_status_mtproto','page_csrf_mtproto','web_probe_failed','link_response_failed','link_shape_failed','domain_link_failed','domain_port_failed','link_controls_failed','quality_page_failed'}
    result = {'ok':False,'error':str(error) if str(error) in allowed else 'verification_failed'}
except Exception:
    result = {'ok':False,'error':'verification_failed'}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
raise SystemExit(0 if result['ok'] else 1)
'''


def main():
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print('{"ok":false,"error":"password_environment_required"}'); return 1
    path = Path(__file__).with_name('verify-network-pulse.py')
    spec = importlib.util.spec_from_file_location('pulse_verifier', path)
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    prefix = verifier.REMOTE_SOURCE.split('\ntry:\n    result = verify(CONFIG)', 1)[0]
    client = paramiko.SSHClient(); client.load_host_keys(str(Path.home()/'.ssh'/'known_hosts'))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(verifier.HOST, username='root', password=password, allow_agent=False, look_for_keys=False, timeout=15)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=160)
        stdin.write(prefix + '\n' + PROBE_SOURCE); stdin.channel.shutdown_write()
        raw = stdout.read(16385); status = stdout.channel.recv_exit_status()
        if len(raw) > 16384: raise ValueError
        result = json.loads(raw)
        # Output only constants/booleans from the verified result, never a remote field.
        if status or result != {'ok':True, 'build':verifier.EXPECTED_BUILD,
                'proxy_links':{kind:{'domain':True,'port':port,'no_store':True,'matching_pair':True,'copy_open_controls':True}
                               for kind,port in (('mtproto',3443),('tls',5443),('web',443))},
                'quality_page':{'status':200,'nested_forms':0}, 'scope':'owner-link-posts-and-web-health-only'}:
            print('{"ok":false,"error":"verification_failed"}'); return 1
        print(json.dumps(result, sort_keys=True)); return 0
    except Exception:
        print('{"ok":false,"error":"verification_failed"}'); return 1
    finally:
        client.close()


if __name__ == '__main__':
    sys.exit(main())
