"""Telegram/Qwen inventory; only --notify sends a fixed owner confirmation."""
import argparse
import json
import os

REMOTE = r'''
import hashlib,json,os,sqlite3,subprocess,sys
from contextlib import closing
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
opener=build_opener(NoRedirect)
def request(url,payload=None):
    req=Request(url,data=None if payload is None else json.dumps(payload).encode(),headers={'Content-Type':'application/json','Accept':'application/json'})
    with opener.open(req,timeout=8) as response:
        raw=response.read(65537)
        if len(raw)>65536:raise ValueError('oversize')
        return json.loads(raw)
root=Path('/opt/quantumvpn-operator')
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value','quantumvpn-operator'],timeout=10).decode().strip()
assert pid.isdigit() and int(pid)>0
env={}
for entry in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
    if b'=' in entry:
        key,value=entry.split(b'=',1)
        if key.startswith(b'QV_'):env[key.decode()]=value.decode()
with closing(sqlite3.connect('file:/var/lib/quantumvpn-operator/operator.db?mode=ro',uri=True)) as db:
    settings=dict(db.execute('select key,value from settings'))
    out={'integrity':db.execute('pragma quick_check').fetchone()[0],
         'settings':{key:settings.get(key) for key in ('app_version','app_version_code','release_schedule_enabled','scheduled_app_version','release_publish_at','ai_model','ai_advisor_enabled','ai_interval_seconds','telegram_alerts_enabled','telegram_backups_enabled')},
         'ai_observations':db.execute('select count(*) from ai_observations').fetchone()[0]}
    if db.execute("select 1 from sqlite_master where name='bot_receiver_state'").fetchone():
        out['receiver_last_poll']=db.execute('select max(updated_at) from bot_receiver_state').fetchone()[0]
        out['server_time']=int(__import__('time').time())
token=(env.get('QV_TELEGRAM_BOT_TOKEN') or settings.get('telegram_bot_token') or '').strip()
chat=(settings.get('telegram_chat_id') or '').strip()
out['bot']={'configured':bool(token and chat),'private_chat_configured':chat.isdigit() and int(chat)>0,'token_source':'environment' if env.get('QV_TELEGRAM_BOT_TOKEN') else 'database' if token else 'none'}
if token:
    for method in ('getMe','getWebhookInfo'):
        try:
            payload=request('https://api.telegram.org/bot'+token+'/'+method,{})
            result=payload.get('result') or {}
            if method=='getMe':out['bot'].update({'authenticated':payload.get('ok') is True,'username':result.get('username')})
            else:out['bot'].update({'webhook_configured':bool(result.get('url')),'pending_updates':result.get('pending_update_count')})
        except Exception as error:out['bot'][method+'_error']=type(error).__name__
    if chat.isdigit() and int(chat)>0:
        try:
            result=request('https://api.telegram.org/bot'+token+'/getMyCommands',{'scope':{'type':'chat','chat_id':int(chat)}})
            out['bot']['commands']=[row.get('command') for row in (result.get('result') or []) if isinstance(row,dict)]
        except Exception as error:out['bot']['menu_error']=type(error).__name__
        if NOTIFY:
            try:
                result=request('https://api.telegram.org/bot'+token+'/sendMessage',{'chat_id':chat,'text':'✅ Quantum Control Bot обновлён.\n/status — статус VDS, Qwen, APK и копий\n/ai_status — модель и анализы\n/check_updates — версия и время выпуска\n/get_stable — опубликованный APK\n/backups — резервные копии\n/help — все команды\n\nQuantumVPN 5.11.3 загружена на VDS. Выпуск: 6 октября, 00:00 МСК. ПК и Codex оставлять включёнными не нужно; публикация через GitHub отменена.'})
                out['bot']['confirmation_sent']=result.get('ok') is True
            except Exception as error:out['bot']['confirmation_error']=type(error).__name__
for route in ('tags','ps'):
    try:
        payload=request('http://127.0.0.1:11434/api/'+route)
        out['ollama_'+route]=[{'name':item.get('name'),'size':item.get('size'),'size_vram':item.get('size_vram')} for item in (payload.get('models') or []) if isinstance(item,dict)][:12]
    except Exception as error:out['ollama_'+route+'_error']=type(error).__name__
out['sources']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() if (root/name).is_file() else None for name in ('app.py','quantumvpn_bot_status.py')}
units=subprocess.check_output(['systemctl','list-units','--all','--type=service','--plain','--no-legend'],timeout=10).decode()
out['bot_related_services']=[line.split()[0] for line in units.splitlines() if line.split() and any(term in line.split()[0].lower() for term in ('telegram','bot','ollama'))]
print(json.dumps(out))
'''

def main():
    import paramiko
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--notify', action='store_true', help='Send one fixed update confirmation to the configured private owner chat')
    args = parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD environment required')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=20, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=60)
        stdin.write('NOTIFY=' + repr(args.notify) + '\n' + REMOTE)
        stdin.channel.shutdown_write()
        raw = stdout.read().decode()
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise RuntimeError('Read-only bot inventory failed; details suppressed')
        print(json.dumps(json.loads(raw), ensure_ascii=False))
    finally:
        client.close()

if __name__ == '__main__':
    main()
