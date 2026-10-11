#!/usr/bin/env python3
"""Read only the fixed installed OpenClaw RPC sources and Ollama metadata.

No config/token reads, inference, model load, service actions or remote writes.
The SSH password must be supplied in QVPN_VDS_PASSWORD by the caller.
"""
import argparse
import json
import os
from pathlib import Path

REMOTE = r'''
import hashlib,json,os,stat,urllib.request
from pathlib import Path
ROOT=Path('/opt/quantum-automation/releases/q4-20261010/openclaw/node_modules/openclaw')
def read_source(path):
    if path.parent not in (ROOT,ROOT/'dist'):raise RuntimeError('source_scope')
    for ancestor in reversed(path.parents):
        info=os.lstat(ancestor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('source_parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>5000000:raise RuntimeError('source_file')
        data=b''
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            data+=chunk
        after=os.fstat(fd)
        if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('source_race')
        return data
    finally:os.close(fd)
def excerpt(name,ranges):
    data=read_source(ROOT/'dist'/name);lines=data.decode().splitlines()
    return {'path':str(ROOT/'dist'/name),'sha256':hashlib.sha256(data).hexdigest(),
            'excerpts':[{'first_line':start,'text':'\n'.join('%d: %s'%(i+1,lines[i]) for i in range(start-1,min(end,len(lines))))} for start,end in ranges]}
def around(name,terms,before=8,after=35):
    data=read_source(ROOT/'dist'/name);lines=data.decode().splitlines();ranges=[]
    for i,line in enumerate(lines):
        if any(term in line for term in terms):
            start=max(1,i+1-before);end=min(len(lines),i+1+after)
            if ranges and start<=ranges[-1][1]+1:ranges[-1]=(ranges[-1][0],max(end,ranges[-1][1]))
            else:ranges.append((start,end))
    if len(ranges)>35:raise RuntimeError('too_many_source_hits')
    return excerpt(name,ranges) if ranges else None
package=json.loads(read_source(ROOT/'package.json'))
if package.get('name')!='openclaw' or package.get('version')!='2026.9.9':raise RuntimeError('pinned_version_mismatch')
result={'package':{'name':package['name'],'version':package['version']},'sources':[]}
if SECTION=='connect':
    result['sources']=[excerpt('call-DmvqNvMY.mjs',[(1,180)]),excerpt('client-B4O1WKhF.mjs',[(1,130),(260,405),(660,800),(1020,1340)]),excerpt('agent-via-gateway-MB8SBICx.mjs',[(610,690)]),around('method-scopes-C-MKLkWf.mjs',['agent.wait','agent'])]
elif SECTION=='agent':
    result['sources']=[excerpt('agent-XuZuntjH.mjs',[(1,85)])]
    terms=['AgentParamsSchema =','AgentWaitParamsSchema =','ConnectParamsSchema =','HelloOkSchema =','function createAgentTurnService(', 'agentRunHandler =','const GATEWAY_CLIENT_NAMES']
    for path in sorted((ROOT/'dist').glob('*.mjs')):
        if path.stat().st_size>5000000:continue
        found=around(path.name,terms,5,100)
        if found:result['sources'].append(found)
    if len(result['sources'])>20:raise RuntimeError('source_scan_output_bound')
elif SECTION=='final':
    result['sources']=[excerpt('client-info-S_xwnr2o.mjs',[(1,40)]),excerpt('agent-turn-service-W_0N3NA0.mjs',[(2860,3038)]),around('agent-turn-service-W_0N3NA0.mjs',['emitFinal','agentMeta','payloads:','prepareWaitForTurn','status: "accepted"'],10,65)]
elif SECTION=='provider':
    for path in sorted((ROOT/'dist').glob('*.mjs')):
        if path.stat().st_size>5000000:continue
        found=around(path.name,['agentMeta: {','const agentMeta =','let agentMeta ='],8,45)
        if found:result['sources'].append(found)
    if len(result['sources'])>30:raise RuntimeError('source_scan_output_bound')
elif SECTION=='schema':
    terms=['AgentParamsSchema','AgentWaitParamsSchema','agent.wait','connect.challenge','ConnectParamsSchema','AgentEventSchema']
    for path in sorted((ROOT/'dist').glob('*.mjs')):
        if not any(tag in path.name for tag in ('schema','protocol','gateway','server','connect','agent')):continue
        found=around(path.name,terms,8,40)
        if found:result['sources'].append(found)
    if len(result['sources'])>30:raise RuntimeError('source_scan_output_bound')
elif SECTION=='ollama':
    def metadata(endpoint):
        with urllib.request.urlopen('http://127.0.0.1:11434/api/'+endpoint,timeout=5) as response:
            raw=response.read(262145)
        if len(raw)>262144:raise RuntimeError('metadata_limit')
        value=json.loads(raw)
        return [{k:model[k] for k in ('name','model','size','digest','details','expires_at','size_vram','context_length') if k in model} for model in value.get('models',[])]
    result['ollama']={'tags':metadata('tags'),'ps':metadata('ps')}
else:raise RuntimeError('section_scope')
print(json.dumps(result,ensure_ascii=False))
'''

def remote_script(section):
    if section not in ('connect', 'schema', 'agent', 'final', 'provider', 'ollama'):
        raise ValueError('section_scope')
    return 'SECTION=' + repr(section) + '\n' + REMOTE

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--section', choices=['connect', 'schema', 'agent', 'final', 'provider', 'ollama'], default='connect')
    parser.add_argument('--known-hosts', default=str(Path.home() / '.ssh/known_hosts'))
    parser.add_argument('--output', type=Path, help='Save generated source-only research JSON without printing excerpts')
    args = parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        print(json.dumps({'error': 'ephemeral_password_required'}))
        return 2
    import paramiko
    client = paramiko.SSHClient()
    client.load_host_keys(args.known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=60)
        stdin.write(remote_script(args.section)); stdin.channel.shutdown_write()
        raw = stdout.read(500000)
        error = stderr.read(4000)
        status = stdout.channel.recv_exit_status()
        if status != 0 or error or len(raw) >= 500000:
            codes=('source_scope','source_parent','source_file','source_race','too_many_source_hits','pinned_version_mismatch','source_scan_output_bound','metadata_limit','section_scope')
            code=next((c for c in codes if error.rstrip().endswith(('RuntimeError: '+c).encode())), 'source_read_exception')
            print(json.dumps({'error': 'read_only_research_failed', 'exit': status,'code':code}))
            return 1
        value = json.loads(raw)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
            print(json.dumps({'ok': True, 'source_research_artifact': str(args.output), 'section': args.section}))
            return 0
        print(json.dumps(value, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({'error': 'ssh_or_source_read_failed', 'kind': type(exc).__name__}))
        return 1
    finally:
        client.close()

if __name__ == '__main__':
    raise SystemExit(main())
