"""Read-only, redacted SSH evidence. Password via stdin or QVPN_VDS_PASSWORD."""
import argparse
import json
import os
from pathlib import Path
import sys

import paramiko

REMOTE = r'''
import json, pathlib, subprocess, time
def run(args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=12)
        return {'status':p.returncode,'output':p.stdout[:12000]}
    except Exception as exc:return {'error':type(exc).__name__}
out={'captured_at':int(time.time())}
out['system']=run(['uname','-srmo'])
out['resources']=run(['free','-m'])
out['load']=pathlib.Path('/proc/loadavg').read_text().strip()
out['cpu']=run(['ps','-eo','comm,pcpu,pmem','--sort=-pcpu'])
out['disk']=run(['df','-h','/'])
out['tcp']=run(['sysctl','net.ipv4.tcp_congestion_control','net.core.default_qdisc','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem'])
out['qdisc']=run(['tc','-s','qdisc','show'])
out['connections']=run(['ss','-s'])
out['listeners']=run(['ss','-lntup'])
out['services']=run(['systemctl','list-units','--type=service','--state=running','--no-pager','--no-legend'])
out['interfaces']=run(['ip','-s','link'])
out['directories']={p:[c.name for c in pathlib.Path(p).iterdir()][:60] for p in ('/opt','/etc/xray','/etc/sing-box','/opt/quantumvpn-operator') if pathlib.Path(p).is_dir()}
out['configs']=[]
for name in ('/etc/xray/config.json','/usr/local/etc/xray/config.json','/etc/sing-box/config.json','/opt/rospanel/xray_config.json'):
    p=pathlib.Path(name)
    if not p.is_file():continue
    try:
        config=json.loads(p.read_text())
        result={'path':name,'inbounds':[],'outbounds':[]}
        for inbound in config.get('inbounds',[]):
            stream=inbound.get('streamSettings',{})
            result['inbounds'].append({'protocol':inbound.get('protocol') or inbound.get('type'),'port':inbound.get('port') or inbound.get('listen_port'),'network':stream.get('network'),'security':stream.get('security'),'sockopt':stream.get('sockopt'),'limits':{k:inbound.get(k) for k in ('up_mbps','down_mbps','ignore_client_bandwidth') if k in inbound}})
        for outbound in config.get('outbounds',[]):
            settings=outbound.get('settings',{})
            result['outbounds'].append({'protocol':outbound.get('protocol') or outbound.get('type'),'fragment':settings.get('fragment'),'limits':{k:outbound.get(k) for k in ('up_mbps','down_mbps') if k in outbound}})
        out['configs'].append(result)
    except Exception as exc:out['configs'].append({'path':name,'error':type(exc).__name__})
print(json.dumps(out,ensure_ascii=False))
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', default='root')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--known-hosts', type=Path, default=Path.home()/'.ssh'/'known_hosts')
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    password = sys.stdin.readline().rstrip('\r\n') if args.password_stdin else os.environ.get('QVPN_VDS_PASSWORD')
    if not password:raise SystemExit('SSH password required via stdin or environment')
    client=paramiko.SSHClient()
    client.load_host_keys(str(args.known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(args.host,port=args.port,username=args.user,password=password,timeout=15,auth_timeout=15,look_for_keys=False,allow_agent=False)
        password=None
        stdin,stdout,stderr=client.exec_command('python3 -',timeout=50)
        stdin.write(REMOTE)
        stdin.channel.shutdown_write()
        payload=stdout.read(100000).decode('utf-8')
        if stdout.channel.recv_exit_status()!=0:raise RuntimeError('Remote evidence capture failed')
        print(json.dumps(json.loads(payload),ensure_ascii=False,indent=2))
    except Exception as exc:
        print(json.dumps({'error':type(exc).__name__,'host':args.host}),file=sys.stderr)
        raise SystemExit(1)
    finally:client.close()

if __name__=='__main__':main()
