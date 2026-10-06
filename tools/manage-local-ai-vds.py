"""Pinned activation/verification for the reviewed local node controller."""
import argparse
import json
import os
import paramiko

REMOTE = r'''
import hashlib,http.client,json,os,socket,sqlite3,ssl,subprocess,sys,time
from pathlib import Path
from urllib.parse import urlsplit
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value','quantumvpn-operator'],timeout=10).decode().strip()
assert pid.isdigit() and int(pid)>0
for entry in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
    if b'=' in entry:
        key,value=entry.split(b'=',1)
        if key.startswith(b'QV_'):os.environ[key.decode()]=value.decode()
root=Path(os.environ.get('QV_DATA_DIR','/var/lib/quantumvpn-operator'))
out={'now':int(time.time()),'services':{name:subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=5).stdout.strip() for name in ('quantumvpn-operator','rospanel','quantumvpn-reserve-trojan','quantumvpn-llama','ollama')}}
file=Path(os.environ.get('QV_RESERVE_PROFILE_URI_FILE','/etc/quantumvpn-reserve/trojan-uri'))
if file.is_file():
    uri=urlsplit(file.read_text().strip())
    out['reserve_profile']={'scheme':uri.scheme,'host':uri.hostname,'port':uri.port,'configured':bool(uri.password or uri.username)}
if MODE=='status':
    db=sqlite3.connect('file:'+str(root/'operator.db')+'?mode=ro',uri=True)
    s=dict(db.execute('select key,value from settings'))
    out['settings']={k:s.get(k) for k in ('ai_engine','ai_model','ai_advisor_enabled','ai_autopilot_enabled','ai_autopilot_last_status','ai_autopilot_last_action','ai_last_status','ai_last_error','ai_last_run','app_version','routing_revision','config_revision','release_schedule_enabled')}
    out['cleanup']=[]
    for row in db.execute("select ts,detail from audit where action='temporary_cleanup' order by ts desc limit 1"):
        out['cleanup'].append({'ts':row[0],'result':json.loads(row[1])})
    out['backup_report']=[]
    for row in db.execute("select ts,detail from events where kind='backup_report_delivery' order by ts desc limit 1"):
        out['backup_report'].append({'ts':row[0],'result':json.loads(row[1])})
    out['db_integrity']=db.execute('pragma quick_check').fetchone()[0]
    db.close()
    out['source_sha256']=hashlib.sha256(Path('/opt/quantumvpn-operator/app.py').read_bytes()).hexdigest()
    out['temporary_apks']={abi:Path('/tmp/QuantumVPN-5.10.12-debug-'+abi+'.apk').exists() for abi in ('arm64-v8a','armeabi-v7a')}
    out['migration_backup_retained']=Path('/root/quantumvpn-backup-20260930-193543').is_dir()
    out['process_memory_bytes']={}
    for name in ('quantumvpn-llama','ollama'):
        process=subprocess.check_output(['systemctl','show','--property=MainPID','--value',name],timeout=5).decode().strip()
        if process.isdigit() and int(process)>0:
            out['process_memory_bytes'][name]=next((int(line.split()[1])*1024 for line in (Path('/proc')/process/'status').read_text().splitlines() if line.startswith('VmRSS:')),None)
    memory={line.split(':')[0]:int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
    out['memory_used_percent']=round(100*(memory['MemTotal']-memory['MemAvailable'])/memory['MemTotal'],1)
    if out.get('reserve_profile',{}).get('scheme')=='trojan':
        host,port=out['reserve_profile']['host'],out['reserve_profile']['port']
        try:
            with socket.create_connection((host,port),timeout=5) as connection:
                with ssl.create_default_context().wrap_socket(connection,server_hostname=host):
                    out['reserve_tls_verified']=True
        except Exception:out['reserve_tls_verified']=False
    sys.path.insert(0,'/opt/quantumvpn-operator')
    if Path('/opt/quantumvpn-operator/quantumvpn_llama.py').is_file():
        import quantumvpn_llama as llama
        out['local_model']=llama.local_status()
    else:
        from urllib.request import build_opener,ProxyHandler
        with build_opener(ProxyHandler({})).open('http://127.0.0.1:11435/props',timeout=3) as response:
            props=json.loads(response.read(32768))
        out['local_model']={'sleeping':props.get('is_sleeping')}
    tls=bool(os.environ.get('QV_TLS_CERT') and os.environ.get('QV_TLS_KEY') and os.environ.get('QV_TLS_TERMINATED','') not in ('1','true','yes'))
    out['api_checks']=[]
    for abi in ('arm64-v8a','armeabi-v7a'):
        connection=http.client.HTTPSConnection('127.0.0.1',int(os.environ.get('QV_PORT','8765')),timeout=30,context=ssl._create_unverified_context()) if tls else http.client.HTTPConnection('127.0.0.1',int(os.environ.get('QV_PORT','8765')),timeout=30)
        start=time.monotonic()
        try:
            connection.request('GET','/api/client/update?abi='+abi+'&current_version_code=0')
            response=connection.getresponse()
            payload=json.loads(response.read(65536))
            out['api_checks'].append({'abi':abi,'status':response.status,'elapsed_ms':round((time.monotonic()-start)*1000),'version':payload.get('version'),'version_code':payload.get('version_code')})
        except Exception as error:
            out['api_checks'].append({'abi':abi,'error':type(error).__name__,'elapsed_ms':round((time.monotonic()-start)*1000)})
        finally:connection.close()
else:
    sys.path.insert(0,'/opt/quantumvpn-operator')
    import app as panel
    assert panel.PANEL_BUILD=='2.2.0-operations.1'
    db=panel.conn()
    s=panel.settings(db)
    if MODE=='activate':
        assert panel.llama.local_status().get('ready') is True
        snapshot=panel.ai_operations_snapshot(db,s)
        prospective={**s,'ai_autopilot_enabled':'1'}
        planned=panel.autopilot.plan_actions(panel.network_guard_snapshot(db),panel.parse_node_map_config(s.get('node_map_config','')),prospective,now=int(time.time()))
        probe=panel.llama.analyze(snapshot,allowed_actions=planned['allowed_actions'])
        assert probe.get('analysis') and probe.get('runtime')=='llama.cpp'
        before={k:s.get(k) for k in ('ai_engine','ai_model','ai_autopilot_enabled','ai_advisor_enabled')}
        values={'ai_engine':'llama.cpp','ai_model':panel.QWEN_DEFAULT_MODEL,'ai_autopilot_enabled':'1','ai_advisor_enabled':'1'}
        panel.set_settings(db,values)
        panel.audit(db,'deployment','127.0.0.1','local_ai_activation',{'before':before,'after':values,'engine_probe':'passed'})
        db.commit()
        out['activation']={'verified':True,'engine':'llama.cpp','model':panel.QWEN_DEFAULT_MODEL,'autopilot':True,'usage':probe.get('usage')}
        out['analysis']=probe['analysis']
        # Store the validated first result without an unnecessary second model call.
        panel.set_settings(db,{'ai_last_run':str(int(time.time())),'ai_last_status':'готов','ai_last_advice':probe['advice'],'ai_last_error':''})
        db.execute('insert into ai_observations(ts,trigger,status,advice,telegram_sent,before_json) values (?,?,?,?,?,?)',(int(time.time()),'llama_activation','готов',probe['advice'],0,json.dumps(probe['snapshot'])))
        db.commit()
        out['autopilot_status']=panel.run_autopilot_step(db,panel.settings(db))['status']
        db.commit()
    elif MODE=='report':
        # This is a separate process: do not mistake its unstarted poller for
        # the live service. Use the same-bot persisted successful poll evidence.
        token=panel.telegram_bot_token(s)
        scope=hashlib.sha256((token+'\n'+s.get('telegram_chat_id','').strip()).encode()).hexdigest()
        last=db.execute('select updated_at from bot_receiver_state where scope=?',(scope,)).fetchone()
        webhook=panel.telegram_bot_api(s,'getWebhookInfo')
        if isinstance(webhook,dict) and webhook.get('url'):
            panel.bot_runtime_state('webhook',True)
        elif isinstance(webhook,dict) and last and 0<=int(time.time())-last[0]<=60:
            panel.bot_runtime_state('polling',False)
        else:
            panel.bot_runtime_state('unavailable',False if isinstance(webhook,dict) else None)
        archive=panel.create_backup_archive()
        out['delivery']=panel.send_backup_report(db,s,archive,kind='manual',actor='deployment')
        assert out['delivery']['archive_sent'] and out['delivery']['report_sent'],'backup/report delivery failed'
        out['archive_bytes']=Path(archive).stat().st_size
        out['status_text']=panel.bot_status.format_status(panel.operations_status_snapshot(db,panel.settings(db)))
    elif MODE=='cleanup':
        result=panel.maintenance.cleanup_managed(panel.ROOT,panel.DOWNLOAD_ROOT,apply=True)
        panel.audit(db,'maintenance','127.0.0.1','temporary_cleanup',result)
        db.commit()
        out['cleanup']=result
    db.close()
usage=__import__('shutil').disk_usage(str(root))
out['disk']={'used_bytes':usage.used,'total_bytes':usage.total,'used_percent':round(usage.used*100/usage.total,2)}
print(json.dumps(out,ensure_ascii=False))
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=('status','activate','report','cleanup'))
    args=parser.parse_args()
    secret=os.environ.get('QVPN_VDS_PASSWORD')
    if not secret:raise SystemExit('QVPN_VDS_PASSWORD required')
    client=paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191',username='root',password=secret,allow_agent=False,look_for_keys=False,timeout=15,auth_timeout=20)
        stdin,stdout,stderr=client.exec_command('python3 -',timeout=180)
        stdin.write('MODE='+repr(args.mode)+'\n'+REMOTE)
        stdin.channel.shutdown_write()
        output=stdout.read().decode()
        errors=stderr.read().decode()
        if stdout.channel.recv_exit_status():
            # Never print raw server exceptions; they can include remote headers.
            raise RuntimeError('Local AI operation failed; inspect the sanitized operator error status')
        print(json.dumps(json.loads(output),ensure_ascii=False))
    finally:client.close()

if __name__=='__main__':main()
