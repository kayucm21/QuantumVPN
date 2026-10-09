"""Bounded verification of bot operations; optional explicit owner test actions.

Default reads status only. --probe checks the three owned proxy transports;
--send-backup creates/delivers one verified encrypted copy; --analyze requests
one normal panel analysis. Never prints cookies, URLs, model prose or secrets.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

import paramiko

REMOTE = r'''
class CSRF(HTMLParser):
    def __init__(self):super().__init__();self.tokens=set()
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='input' and a.get('name')=='csrf' and len(a.get('value',''))>=32:self.tokens.add(a['value'])

def owner_action(env,cookie,action,csrf):
    require(action in {'backup_now','run_ai_analysis'},'action_scope')
    bind=env.get('QV_BIND','127.0.0.1')
    require(bind in ('0.0.0.0','127.0.0.1','::','::1','localhost'),'loopback_bind')
    address='::1' if bind in ('::','::1') else '127.0.0.1'
    port=int(env.get('QV_PORT','8765'))
    terminated=env.get('QV_TLS_TERMINATED','').strip() in ('1','true','yes')
    tls=bool(env.get('QV_TLS_CERT') and env.get('QV_TLS_KEY') and not terminated)
    connection=LoopbackHTTPS(address,port,45) if tls else http.client.HTTPConnection(address,port,timeout=45)
    try:
        connection.request('POST','/operator/actions',urlencode({'action':action,'csrf':csrf,'return_tab':'ai'}),
            {'Host':urlsplit(PUBLIC).netloc,'Origin':PUBLIC,'Sec-Fetch-Site':'same-origin',
             'Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded'})
        response=connection.getresponse();response.read(131073)
        require(response.status==303,'owner_action_rejected')
    finally:connection.close()

def verify_bot(config):
    env=environment();cookie=owner_cookie(env)
    status,headers,body=request(env,'/operator?tab=ai',cookie)
    require(status==200 and ('QuantumControl/'+BUILD) in headers.get('Server',''),'build')
    parser=CSRF();parser.feed(body.decode('utf-8'));require(len(parser.tokens)==1,'csrf')
    csrf=next(iter(parser.tokens))
    data=Path(env.get('QV_DATA_DIR','/var/lib/quantumvpn-operator'))
    path=data/'operator.db'
    def read_settings():
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
            return dict(db.execute('select key,value from settings'))
    result={'ok':True,'build':BUILD,'apk_unchanged':False,'proxy_scope':'server_to_telegram_not_client',
            'client_without_vpn_tested':False,'blocker_cause_proven':False}
    before=read_settings()
    require(before.get('app_version')=='5.11.4' and before.get('app_version_code')=='501104099','release')
    sys.path.insert(0,'/opt/quantumvpn-operator')
    import quantumvpn_ai_knowledge as knowledge
    result['knowledge_installed']=knowledge.KNOWLEDGE_VERSION=='2026-10-09.1'
    pid=command(['systemctl','show','--property=MainPID','--value','quantumvpn-llama'],timeout=4).decode().strip()
    require(pid.isdigit() and int(pid)>0,'ai_isolation')
    fields={line.partition(':')[0]:line.partition(':')[2].strip() for line in (Path('/proc')/pid/'status').read_text().splitlines() if ':' in line}
    uid=fields.get('Uid','').split()
    result['ai_isolation']={'non_root':len(uid)==4 and all(v.isdecimal() and int(v)>0 for v in uid),
                            'no_new_privileges':fields.get('NoNewPrivs')=='1','seccomp':fields.get('Seccomp')=='2',
                            'capabilities_empty':all(fields.get(k)=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))}
    require(all(result['ai_isolation'].values()),'ai_isolation')
    if config['probe']:
        import quantumvpn_proxy_monitor as monitor
        states=monitor.refresh()
        result['proxies']={name:{'ready':state.get('ready') is True,
                                'protocol_confirmed':state.get('stage')=='telegram',
                                'isolation_verified':state.get('isolation_verified') is True}
                           for name,state in states.items() if name in {'mtproto','native_tls','web'}}
    started=int(time.time())
    if config['send_backup']:
        owner_action(env,cookie,'backup_now',csrf)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
            row=db.execute("select detail from events where kind='backup_report_delivery' and ts>=? order by ts desc limit 1",(started,)).fetchone()
        require(row is not None,'backup_receipt_missing')
        delivery=json.loads(row[0]);require(delivery.get('kind')=='manual','backup_receipt_scope')
        backup=json.loads(read_settings().get('quality_backup') or '{}')
        require(backup.get('ok') is True and type(backup.get('checked_at')) is int and backup['checked_at']>=started,'backup_verification')
        result['backup']={'verified':True,'databases':len(backup.get('databases',[])),
                          'missing_components':len(backup.get('missing',[])),
                          'archive_sent':delivery.get('archive_sent') is True,'report_sent':delivery.get('report_sent') is True}
        require(result['backup']['archive_sent'] and result['backup']['report_sent'],'backup_delivery')
    if config['analyze']:
        analysis_start=int(time.time())
        owner_action(env,cookie,'run_ai_analysis',csrf)
        deadline=time.monotonic()+110
        while True:
            current=read_settings()
            if int(current.get('ai_last_run','0'))>=analysis_start:break
            require(time.monotonic()<deadline,'analysis_timeout');time.sleep(2)
        result['analysis']={'ready':current.get('ai_last_status')=='готов',
                            'local':current.get('ai_engine')=='llama.cpp' and current.get('ai_model')=='qwen3:0.6b',
                            'error_reason':current.get('ai_last_error_reason') if current.get('ai_last_error_reason') in {'output_truncated','request_size','transport','response_json','content_json','analysis_shape'} else 'none_or_other'}
        require(result['analysis']['ready'] and result['analysis']['local'],'analysis_not_ready')
    after=read_settings()
    require(all(before.get(k)==after.get(k) for k in ('app_version','app_version_code','release_schedule_enabled','release_publish_at')),'release_changed')
    result['apk_unchanged']=True
    return result
try:
    result=verify_bot(CONFIG)
except CheckFailed as error:
    allowed={'action_scope','owner_action_rejected','build','csrf','release','backup_receipt_missing',
             'backup_receipt_scope','backup_verification','backup_delivery','analysis_timeout','analysis_not_ready','release_changed','ai_isolation'}
    result={'ok':False,'error':str(error) if str(error) in allowed else 'verification_failed'}
except Exception:
    result={'ok':False,'error':'verification_failed'}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
raise SystemExit(0 if result['ok'] else 1)
'''


def safe_result(value):
    """Strict output schema: a forged SSH stdout cannot print credentials."""
    errors = {'action_scope','owner_action_rejected','build','csrf','release','backup_receipt_missing',
              'backup_receipt_scope','backup_verification','backup_delivery','analysis_timeout','analysis_not_ready',
              'release_changed','ai_isolation','verification_failed'}
    if isinstance(value, dict) and value.get('ok') is False:
        return {'ok': False, 'error': value.get('error') if value.get('error') in errors else 'verification_failed'}
    required = {'ok','build','apk_unchanged','proxy_scope','client_without_vpn_tested','blocker_cause_proven','knowledge_installed'}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {'proxies','backup','analysis','ai_isolation'}:
        raise ValueError('shape')
    expected = {'ok': True,'build':'2.3.0-pulse.6','apk_unchanged':True,
                'proxy_scope':'server_to_telegram_not_client','client_without_vpn_tested':False,
                'blocker_cause_proven':False,'knowledge_installed':True}
    if any(type(value[k]) is not type(v) or value[k] != v for k,v in expected.items()):
        raise ValueError('fact')
    result = dict(expected)
    if 'ai_isolation' in value:
        isolation = value['ai_isolation']
        if (not isinstance(isolation, dict) or set(isolation) != {'non_root','no_new_privileges','seccomp','capabilities_empty'}
                or any(type(x) is not bool for x in isolation.values())):
            raise ValueError('isolation_fact')
        result['ai_isolation'] = dict(isolation)
    if 'proxies' in value:
        proxies = value['proxies']
        fields = {'ready','protocol_confirmed','isolation_verified'}
        if not isinstance(proxies, dict) or set(proxies) != {'mtproto','native_tls','web'}:
            raise ValueError('proxies')
        for item in proxies.values():
            if not isinstance(item, dict) or set(item) != fields or any(type(x) is not bool for x in item.values()):
                raise ValueError('proxy_fact')
        result['proxies'] = {k: dict(v) for k,v in proxies.items()}
    if 'backup' in value:
        backup = value['backup']
        if (not isinstance(backup, dict) or set(backup) != {'verified','databases','missing_components','archive_sent','report_sent'}
                or any(type(backup[k]) is not bool for k in ('verified','archive_sent','report_sent'))
                or type(backup['databases']) is not int or not 1 <= backup['databases'] <= 2
                or type(backup['missing_components']) is not int or not 0 <= backup['missing_components'] <= 6):
            raise ValueError('backup_fact')
        result['backup'] = dict(backup)
    if 'analysis' in value:
        analysis = value['analysis']
        reasons = {'output_truncated','request_size','transport','response_json','content_json','analysis_shape','none_or_other'}
        if (not isinstance(analysis, dict) or set(analysis) != {'ready','local','error_reason'}
                or type(analysis['ready']) is not bool or type(analysis['local']) is not bool
                or not isinstance(analysis['error_reason'], str) or analysis['error_reason'] not in reasons):
            raise ValueError('analysis_fact')
        result['analysis'] = dict(analysis)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--send-backup', action='store_true')
    parser.add_argument('--analyze', action='store_true')
    args = parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print('{"ok":false,"error":"password_environment_required"}'); return 1
    spec = importlib.util.spec_from_file_location('pulse_verifier', Path(__file__).with_name('verify-network-pulse.py'))
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    prefix = verifier.REMOTE_SOURCE.split('\ntry:\n    result = verify(CONFIG)', 1)[0]
    config = {'probe': args.probe, 'send_backup': args.send_backup, 'analyze': args.analyze}
    client = paramiko.SSHClient(); client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(verifier.HOST, username='root', password=password, look_for_keys=False, allow_agent=False, timeout=15)
        stdin, stdout, stderr = client.exec_command('python3 -B -', timeout=180)
        stdin.write('CONFIG=' + repr(config) + '\n' + prefix + '\n' + REMOTE)
        stdin.channel.shutdown_write()
        raw = stdout.read(4097); stderr.read(65536); status = stdout.channel.recv_exit_status()
        if len(raw) > 4096:
            raise ValueError('response_bound')
        result = safe_result(json.loads(raw))
        print(json.dumps(result, sort_keys=True))
        return 1 if status or result.get('ok') is not True else 0
    except Exception:
        print('{"ok":false,"error":"verification_failed"}'); return 1
    finally:
        client.close()


if __name__ == '__main__':
    sys.exit(main())
