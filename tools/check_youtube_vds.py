"""Bounded read-only VDS performance evidence, without clients/keys/raw logs.

Uses the existing SSH host pin and QVPN_VDS_PASSWORD in memory. HTTP bodies are
discarded; these probes test server egress, not Android VPN/video throughput.
Cloudflare API: https://github.com/cloudflare/speedtest
"""
from __future__ import annotations

import argparse
import json
import os

REMOTE = r'''
import concurrent.futures,json,os,re,subprocess,time
from pathlib import Path
from datetime import datetime,timezone

def command(args, timeout=15):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,text=True)
        return p.returncode,p.stdout[:524288]
    except (OSError,subprocess.TimeoutExpired): return -1,''

def proc_stat():
    values=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    return values

def counters():
    result={}
    lines=Path('/proc/net/snmp').read_text().splitlines()
    for i in range(0,len(lines)-1,2):
        names=lines[i].split(); values=lines[i+1].split()
        if names[0]!=values[0]: continue
        section=names[0].rstrip(':')
        wanted={'Tcp':{'OutSegs','RetransSegs','InErrs','EstabResets'},
                'Udp':{'InDatagrams','OutDatagrams','InErrors','RcvbufErrors','SndbufErrors'}}.get(section,set())
        result[section]={k:int(v) for k,v in zip(names[1:],values[1:]) if k in wanted}
    return result

def interfaces():
    result={}
    for row in Path('/proc/net/dev').read_text().splitlines()[2:]:
        name,raw=row.split(':',1);name=name.strip()
        if name=='lo': continue
        numbers=list(map(int,raw.split()))
        result[name]={'rx_bytes':numbers[0],'rx_errors':numbers[2],'rx_drops':numbers[3],
                      'tx_bytes':numbers[8],'tx_errors':numbers[10],'tx_drops':numbers[11]}
    return result

def snapshot():
    a=proc_stat(); start=time.monotonic();before=counters();nic_before=interfaces()
    time.sleep(2)
    b=proc_stat();seconds=time.monotonic()-start;after=counters();nic_after=interfaces()
    delta=[y-x for x,y in zip(a,b)];total=max(1,sum(delta))
    mem={r.split(':')[0]:int(r.split()[1]) for r in Path('/proc/meminfo').read_text().splitlines() if r.split()[1].isdigit()}
    code,processes=command(['ps','-eo','comm,pcpu,pmem,rss','--sort=-pcpu'])
    processes=[r.split() for r in processes.splitlines()[1:11]]
    net={}
    for name,values in nic_after.items():
        base=nic_before.get(name,values)
        net[name]={k:values[k]-base[k] for k in values}
        net[name]['rx_mbps']=round(net[name]['rx_bytes']*8/seconds/1e6,3)
        net[name]['tx_mbps']=round(net[name]['tx_bytes']*8/seconds/1e6,3)
    net_delta={section:{k:values[k]-before.get(section,{}).get(k,values[k]) for k in values} for section,values in after.items()}
    return {'sample_seconds':round(seconds,2),'cpu_busy_percent':round(100*(total-delta[3]-delta[4])/total,2),
            'cpu_steal_percent':round(100*delta[7]/total,2),'cpu_iowait_percent':round(100*delta[4]/total,2),
            'cores':os.cpu_count(),'load':list(os.getloadavg()),'memory_total_kib':mem.get('MemTotal'),
            'memory_available_kib':mem.get('MemAvailable'),'processes_comm_cpu_mem_rss':processes,
            'interface_deltas':net,'transport_deltas':net_delta}

def numeric_config():
    output={}
    path=Path('/var/lib/rospanel/xray/config.json')
    if path.is_file():
        cfg=json.loads(path.read_text())
        output['xray']={'log_level':cfg.get('log',{}).get('loglevel'),
            'inbounds':[{'protocol':v.get('protocol'),'port':v.get('port'),'network':v.get('streamSettings',{}).get('network'),
                'security':v.get('streamSettings',{}).get('security'),
                'sockopt':{k:w for k,w in v.get('streamSettings',{}).get('sockopt',{}).items() if k in {'tcpFastOpen','tcpCongestion','tcpKeepAliveIdle','tcpKeepAliveInterval','tcpWindowClamp','tcpMptcp'}}}
                for v in cfg.get('inbounds',[])],
            'outbound_protocols':[{'tag':v.get('tag'),'protocol':v.get('protocol'),
                'mtu':v.get('settings',{}).get('mtu'),
                'reserved_present':bool(v.get('settings',{}).get('reserved'))} for v in cfg.get('outbounds',[])],
            'local_socks':[{'port':v.get('port'),'listen':v.get('listen'),
                'auth':v.get('settings',{}).get('auth','noauth')} for v in cfg.get('inbounds',[]) if v.get('protocol')=='socks'],
            'balancers':[{'tag':v.get('tag'),'selector':v.get('selector'),
                'strategy':v.get('strategy',{}).get('type'),'fallback_tag':v.get('fallbackTag')}
                for v in cfg.get('routing',{}).get('balancers',[])],
            'observatory':{k:cfg.get('observatory',{}).get(k) for k in ('subjectSelector','probeInterval','enableConcurrency')},
            'routing_rules':len(cfg.get('routing',{}).get('rules',[])),
            'youtube_rules':[{'type':v.get('type'),'network':v.get('network'),'outbound_tag':v.get('outboundTag'),'balancer_tag':v.get('balancerTag'),
                             'domains':[d for d in v.get('domain',[]) if any(w in d for w in ('youtube','googlevideo','ytimg'))]}
                             for v in cfg.get('routing',{}).get('rules',[]) if any(any(w in d for w in ('youtube','googlevideo','ytimg')) for d in v.get('domain',[]))]}
    return output

def socket_metrics():
    _,text=command(['ss','-tin'])
    rows=[]
    for line in text.splitlines():
        if not line.startswith((' ','\t')): continue
        item={}
        for key in ('rtt','cwnd','retrans','bytes_retrans','delivery_rate','pacing_rate'):
            match=re.search(r'\b'+key+r'(?::|\s+)([^\s]+)',line)
            if match: item[key]=match.group(1)
        if item: rows.append(item)
    return {'tcp_metric_samples':rows[:30],'tcp_metric_count':len(rows)}

def egress(socks=False):
    probes=[]
    targets=[('youtube204','https://www.youtube.com/generate_204',65536),
             ('google204','https://www.gstatic.com/generate_204',65536),
             ('cloudflare8m','https://speed.cloudflare.com/__down?bytes=8388608',8388608),
             ('google8m','https://dl.google.com/android/repository/platform-tools-latest-linux.zip',8388608)]
    for family in (('remote',) if socks else ('4','6')):
        for label,url,limit in targets:
            for repeat in range(3):
                args=['curl','--silent','--show-error','--proto','=https','--tlsv1.2',
                      '--connect-timeout','5','--max-time','12','--max-filesize',str(limit),
                      '--output','/dev/null','--write-out','%{json}',url]
                if socks: args += ['--socks5-hostname','127.0.0.1:18081']
                else: args += ['-'+family]
                if label=='google8m': args += ['--http1.1','--range','0-8388607']
                code,text=command(args,15)
                try: result=json.loads(text)
                except ValueError: result={}
                expected_status=206 if label=='google8m' else 200 if label=='cloudflare8m' else 204
                complete=code==0 and result.get('http_code')==expected_status and (result.get('size_download')==8388608 if label.endswith('8m') else True)
                probes.append({'target':label,'family':family,'path':'xray-local-socks' if socks else 'server-direct','repeat':repeat+1,'curl_exit':code,'valid_probe':complete,
                    **{k:result.get(k) for k in ('http_code','http_version','time_namelookup','time_connect','time_appconnect','time_starttransfer','time_total','size_download','speed_download')},
                    'mbps':round(result.get('speed_download',0)*8/1e6,3) if complete and label.endswith('8m') else None})
    return probes

def require_local_socks(entries):
    if not any(v.get('port')==18081 and v.get('listen')=='127.0.0.1' and v.get('auth')=='noauth' for v in entries):
        raise RuntimeError('Expected loopback-only no-auth SOCKS diagnostic endpoint absent')

result={'utc':datetime.now(timezone.utc).isoformat(),'server_only_not_android_video':True}
result['before']=snapshot()
result['network_sysctl']={}
for key in ('net.ipv4.tcp_congestion_control','net.core.default_qdisc','net.ipv4.tcp_available_congestion_control',
            'net.ipv4.tcp_mtu_probing','net.core.rmem_default','net.core.rmem_max','net.core.wmem_default','net.core.wmem_max','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem',
            'net.core.netdev_max_backlog','net.ipv4.tcp_slow_start_after_idle'):
    code,value=command(['sysctl','-n',key]);result['network_sysctl'][key]=value.strip() if code==0 else None
_,qdisc=command(['tc','-s','qdisc','show']);result['qdisc']=qdisc
result.update(numeric_config());result.update(socket_metrics())
if PROXY:
    entries=result.get('xray',{}).get('local_socks',[])
    require_local_socks(entries)
probe_before=counters()
with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    future=pool.submit(egress,PROXY)
    print(json.dumps({'snapshot':result}),flush=True)
    result['egress_probes']=future.result()
probe_after=counters()
result['probe_transport_deltas']={section:{k:values[k]-probe_before.get(section,{}).get(k,values[k]) for k in values} for section,values in probe_after.items()}
result['after']=snapshot()
print(json.dumps({'final':result}),flush=True)
'''


def main() -> None:
    import paramiko
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy',action='store_true',help='Test the existing loopback-only Xray SOCKS endpoint without changing it')
    options=parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required; do not pass it on the command line.')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=20, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=320)
        stdin.write('PROXY = '+repr(options.proxy)+'\n'+REMOTE)
        stdin.channel.shutdown_write()
        for line in stdout:
            # Only our structured, filtered evidence can be emitted.
            json.loads(line)
            print(line.rstrip(), flush=True)
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise RuntimeError('Remote read-only performance capture failed; raw stderr suppressed.')
    finally:
        client.close()


if __name__ == '__main__':
    main()
