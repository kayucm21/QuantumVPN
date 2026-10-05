"""Pinned read-only network/provider inventory. No credentials or client logs."""
import json
import os
import paramiko

REMOTE = r'''
import hashlib,json,sqlite3,subprocess,time
from contextlib import closing
from pathlib import Path
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value','quantumvpn-operator'],timeout=10).decode().strip()
assert pid.isdigit() and int(pid)>0
env={}
for entry in (Path('/proc')/pid/'environ').read_bytes().split(b'\0'):
    if b'=' in entry:
        key,value=entry.split(b'=',1)
        if key in (b'QV_GEMINI_API_KEY',b'GEMINI_API_KEY',b'GOOGLE_API_KEY'):env[key.decode()]=bool(value.strip())
out={'gemini_key_configured':any(env.values()),'time':int(time.time())}
for key in ('net.ipv4.tcp_congestion_control','net.core.default_qdisc','net.ipv4.tcp_available_congestion_control'):
    result=subprocess.run(['sysctl','-n',key],capture_output=True,text=True,timeout=5)
    out[key]=result.stdout.strip() if result.returncode==0 else 'unavailable'
with closing(sqlite3.connect('file:/var/lib/quantumvpn-operator/operator.db?mode=ro',uri=True)) as db:
    settings=dict(db.execute('select key,value from settings'))
    out['settings']={key:settings.get(key) for key in ('ai_model','latency_state','latency_probe_interval','load_balancer_enabled','load_balancer_strategy','load_balancer_max_latency_ms','app_version','scheduled_app_version','release_publish_at')}
    out['node_map_configured']=bool((settings.get('node_map_config') or '').strip())
    rows=db.execute("select target,count(*),sum(ok),avg(case when ok=1 then latency_ms end),max(ts) from server_health where ts>? and target like 'latency:%' group by target limit 30",(int(time.time())-3600,)).fetchall()
    out['probe_hour']=[{'target':row[0],'checks':row[1],'success':row[2],'mean_ms':row[3],'last':row[4]} for row in rows]
    if db.execute("select 1 from sqlite_master where name='network_guard_state'").fetchone():
        report=db.execute('select report_json,updated_at from network_guard_state where id=1').fetchone()
        if report:
            body=json.loads(report[0])
            out['network_guard']={key:body.get(key) for key in ('status','coverage','cause','throughput','recommended_target')}
            out['network_guard']['updated_at']=report[1]
            out['network_guard']['node_count']=len(body.get('nodes') or [])
    out['routing_revision']=settings.get('routing_revision')
out['source_hashes']={name:hashlib.sha256((Path('/opt/quantumvpn-operator')/name).read_bytes()).hexdigest() if (Path('/opt/quantumvpn-operator')/name).is_file() else None for name in ('app.py','quantumvpn_gemini.py','quantumvpn_network_guard.py','quantumvpn_bot_status.py','quantumvpn_control_next.py')}
out['load_average']=Path('/proc/loadavg').read_text().split()[:3]
out['meminfo']={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
print(json.dumps(out))
'''


def main():
    secret = os.environ.get('QVPN_VDS_PASSWORD')
    if not secret:
        raise SystemExit('QVPN_VDS_PASSWORD required')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=secret, allow_agent=False,
                       look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=40)
        stdin.write(REMOTE)
        stdin.channel.shutdown_write()
        raw = stdout.read().decode()
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise RuntimeError('Read-only network inventory failed')
        print(json.dumps(json.loads(raw), ensure_ascii=False))
    finally:
        client.close()


if __name__ == '__main__':
    main()
