"""Guarded RosPanel Instagram/public IPv6 egress repair (inspect by default).

Only appends routing_config.warp_domains / warp_ips. Keeps WARP credentials,
inbounds, DNS, subscriptions and Android unchanged. Requires an existing healthy
dual-stack WARP and a pinned SSH host key. Private backups are retained on VDS.
"""
from __future__ import annotations

import argparse
import os
import uuid


REMOTE = r'''
import copy,hashlib,ipaddress,json,os,re,socket,sqlite3,subprocess,time
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path('/var/lib/quantumvpn-operator/routing-backups')
DB=Path('/var/lib/rospanel/rospanel.db')
CONFIG=Path('/var/lib/rospanel/xray/config.json')
BINARY=Path('/var/lib/rospanel/bin/xray')
ASSETS=Path('/var/lib/rospanel/geo')
DOMAINS=('instagram.com','cdninstagram.com','facebook.com','facebook.net',
         'fbcdn.net','fbsbx.com','ig.me')
IPV6='2000::/3'  # Public global unicast only; never bypass private-address blocks.

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def extend(values,extras):
    if not isinstance(values,list) or any(not isinstance(x,str) for x in values):
        raise RuntimeError('Unexpected routing list schema')
    result=list(values)
    for item in extras:
        if item not in result: result.append(item)
    return result

def proposed(raw):
    obj=json.loads(raw)
    if not isinstance(obj,dict): raise RuntimeError('Unexpected routing object')
    obj['warp_domains']=extend(obj.get('warp_domains'),DOMAINS)
    obj['warp_ips']=extend(obj.get('warp_ips'),(IPV6,))
    return obj

def generated_candidate(cfg,old,new):
    candidate=copy.deepcopy(cfg)
    rules=candidate.get('routing',{}).get('rules',[])
    normalize=lambda items: [x if ':' in x else 'domain:'+x for x in items]
    for key,stored in (('domain','warp_domains'),('ip','warp_ips')):
        before=normalize(old[stored]) if key=='domain' else old[stored]
        after=normalize(new[stored]) if key=='domain' else new[stored]
        matches=[(i,r) for i,r in enumerate(rules) if r.get('balancerTag')=='warp-out'
                 and r.get(key)==before and not r.get('inboundTag')]
        if len(matches)!=1: raise RuntimeError('Persistent/generated WARP rules differ')
        index,rule=matches[0]
        # Preserve existing API/SSRF/reject precedence, not just the rule count.
        guards=[i for i,r in enumerate(rules) if r.get('outboundTag') in ('api','block')]
        if not guards or index<=max(guards): raise RuntimeError('Unexpected WARP rule ordering')
        rule[key]=after
    return candidate

def read_settings(connection,require_health=True):
    row=connection.execute('SELECT routing_config,config_revision,warp_enabled,last_config_error FROM settings WHERE id=1').fetchone()
    if not row: raise RuntimeError('RosPanel settings missing')
    if require_health and (not row[2] or row[3]): raise RuntimeError('RosPanel WARP not enabled/healthy')
    return row[0],row[1]

def db_connect():
    mode='rw' if MODE in ('apply','rollback') else 'ro'
    return sqlite3.connect('file:'+str(DB)+'?mode='+mode,uri=True,timeout=10)

def config(): return json.loads(CONFIG.read_text())

def service(name):
    p=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=5)
    return p.stdout.strip()

def run(args,timeout=20):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,
                     timeout=timeout,cwd=CONFIG.parent,env=dict(os.environ,XRAY_LOCATION_ASSET=str(ASSETS)))
    if p.returncode: raise RuntimeError('Server command failed; raw output suppressed: '+Path(args[0]).name)
    return p.stdout

def assert_paths():
    for path in (DB,CONFIG,BINARY,ASSETS/'geosite.dat'):
        if not path.is_file() or path.is_symlink(): raise RuntimeError('Expected regular server file missing')
    if ROOT.is_symlink() or ROOT.parent.resolve()!=ROOT.parent:
        raise RuntimeError('Unsafe backup root')
    if ROOT.exists() and ROOT.resolve()!=ROOT: raise RuntimeError('Unsafe backup root')

def private_json(path,obj):
    temp=path.with_name(path.name+'.tmp-'+TRANSACTION)
    try:
        with os.fdopen(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
            json.dump(obj,f);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if temp.exists(): temp.unlink()

def validate_config(cfg,directory):
    path=directory/'candidate.json'
    private_json(path,cfg)
    try: run([str(BINARY),'run','-test','-config',str(path)],25)
    finally: path.unlink()  # Exact private temporary file, not a user/config file.

def require_warp(cfg):
    warp=next((o for o in cfg.get('outbounds',[]) if o.get('tag')=='warp'),None)
    if not warp or warp.get('protocol')!='wireguard': raise RuntimeError('Existing WARP outbound missing')
    settings=warp.get('settings',{})
    families={ipaddress.ip_interface(a).version for a in settings.get('address',[])}
    peers=settings.get('peers',[])
    if families!={4,6} or not any('::/0' in p.get('allowedIPs',[]) for p in peers):
        raise RuntimeError('Existing WARP is not dual stack')
    balancer=next((b for b in cfg.get('routing',{}).get('balancers',[]) if b.get('tag')=='warp-out'),None)
    if not balancer or balancer.get('fallbackTag')!='warp' or 'warp' not in balancer.get('selector',[]):
        raise RuntimeError('Unexpected WARP balancer')
    selected=[o for o in cfg.get('outbounds',[]) if any(o.get('tag','').startswith(prefix)
              for prefix in balancer['selector'])]
    for outbound in selected:
        settings=outbound.get('settings',{})
        families={ipaddress.ip_interface(a).version for a in settings.get('address',[])}
        if outbound.get('protocol')!='wireguard' or families!={4,6} or not any(
                '0.0.0.0/0' in p.get('allowedIPs',[]) and '::/0' in p.get('allowedIPs',[])
                for p in settings.get('peers',[])):
            raise RuntimeError('Selected WARP peer is not dual stack')

def https(url,trace=False,connect_to=None):
    args=['curl','--silent','--show-error','--noproxy','','--socks5-hostname','127.0.0.1:18081',
          '--proto','=https','--connect-timeout','4','--max-time','12','--max-filesize','8192',
          '--write-out','\n%{json}']
    if not trace: args.append('--head')
    if connect_to: args.extend(['--connect-to',connect_to])
    p=subprocess.run(args+[url],capture_output=True,text=True,timeout=16)
    if p.returncode: raise RuntimeError('HTTPS WARP probe failed; response suppressed')
    body,_,metrics=p.stdout.rpartition('\n')
    info=json.loads(metrics)
    if info.get('ssl_verify_result')!=0 or not 200<=int(info.get('http_code',0))<400:
        raise RuntimeError('HTTPS certificate/status probe failed')
    result={'status':info['http_code'],'tls_verified':True,'seconds':round(info['time_total'],3)}
    if trace:
        data=dict(line.split('=',1) for line in body.splitlines() if '=' in line)
        if data.get('warp')!='on': raise RuntimeError('Probe is not using WARP')
        result.update(ip_family=ipaddress.ip_address(data['ip']).version,warp=True)
    return result

def probes():
    return {
      'warp_ipv4':https('https://1.1.1.1/cdn-cgi/trace',trace=True),
      'warp_ipv6':https('https://[2606:4700:4700::1111]/cdn-cgi/trace',trace=True),
      'instagram_web':https('https://www.instagram.com/'),
      'youtube_control':https('https://www.youtube.com/generate_204'),
    }

def restart_and_check():
    run(['systemctl','restart','rospanel'],30)
    until=time.monotonic()+25
    while time.monotonic()<until:
        try:
            if service('rospanel')=='active':
                with socket.create_connection(('127.0.0.1',18081),timeout=1): return
        except (OSError,RuntimeError): pass
        time.sleep(1)
    raise RuntimeError('RosPanel/SOCKS did not recover after restart')

def cas(connection,old,revision,new):
    connection.execute('BEGIN IMMEDIATE')
    try:
        count=connection.execute('UPDATE settings SET routing_config=?, config_revision=config_revision+1, updated_at=? '
          'WHERE id=1 AND routing_config=? AND config_revision=?',(new,int(time.time()),old,revision)).rowcount
        if count!=1: raise RuntimeError('Routing/revision changed concurrently; update refused')
        connection.commit()
    except BaseException:
        connection.rollback();raise

def settings_identity(connection):
    columns=[row[1] for row in connection.execute('PRAGMA table_info(settings)')]
    row=connection.execute('SELECT * FROM settings WHERE id=1').fetchone()
    if row is None: raise RuntimeError('Settings snapshot missing')
    excluded={'routing_config','config_revision','updated_at','last_config_error'}
    return digest({key:value for key,value in zip(columns,row) if key not in excluded})

def adopt_generated_revision(state,connection,directory):
    # RosPanel increments config_revision once when generating Xray at startup.
    # Accept only that single increment, with this exact routing string and all
    # other settings unchanged against our private online SQLite snapshot.
    raw,revision=read_settings(connection,require_health=False)
    expected=state['desired_revision']
    committed=state['previous_revision']+1
    allowed=(expected,) if state.get('generator_revision_increment') else (committed,committed+1)
    if expected not in (committed,committed+1) or raw!=state['desired_raw'] or revision not in allowed:
        raise RuntimeError('Unexpected routing/generator revision; no overwrite')
    backup=directory/'rospanel.db'
    if backup.is_symlink() or not backup.is_file(): raise RuntimeError('Private settings snapshot missing')
    with sqlite3.connect('file:'+str(backup)+'?mode=ro',uri=True) as old:
        if settings_identity(connection)!=settings_identity(old):
            raise RuntimeError('Other panel settings changed; generator revision not adopted')
    if revision!=expected:
        state['generator_revision_increment']=1
        state['desired_revision']=revision
        private_json(directory/'state.json',state)

def confirm(state,connection):
    raw,revision=read_settings(connection)
    if raw!=state['desired_raw'] or revision!=state['desired_revision']:
        raise RuntimeError('Persistent routing changed since this transaction')
    if digest(config())!=state['desired_config_sha256']:
        raise RuntimeError('Generated config differs; protected VPN sections not confirmed')
    if service('rospanel')!='active' or service('quantumvpn-operator')!='active':
        raise RuntimeError('Panel service health failed')
    if service('reserve-trojan')!=state['reserve_state']:
        raise RuntimeError('Independent reserve service state changed')
    return probes()

def rollback(state,connection):
    # Never restore a whole database: new users, traffic, sessions must survive.
    raw,revision=read_settings(connection,require_health=False)
    if raw!=state['desired_raw'] or revision!=state['desired_revision']:
        raise RuntimeError('Concurrent routing update; rollback refused')
    cas(connection,raw,revision,state['previous_raw'])
    restart_and_check()
    current,_=read_settings(connection,require_health=False)
    if current!=state['previous_raw']: raise RuntimeError('Routing rollback not confirmed')
    if digest(config())!=state['previous_config_sha256']:
        raise RuntimeError('Rollback config differs; concurrent client changes are not overwritten')
    if service('quantumvpn-operator')!='active': raise RuntimeError('Operator unhealthy after rollback')
    probes()

def load_state(path):
    if path.is_symlink() or path.parent.resolve()!=ROOT or not re.fullmatch(r'instagram-[0-9TZ]+-[a-f0-9]{32}',path.name):
        raise RuntimeError('Unsafe transaction directory')
    state_file=path/'state.json'
    if state_file.is_symlink(): raise RuntimeError('Unsafe transaction state')
    state=json.loads(state_file.read_text())
    if state.get('schema')!=1 or state.get('target')!=str(DB): raise RuntimeError('Wrong transaction identity')
    return state

def main():
    assert_paths()
    with db_connect() as connection:
        if MODE in ('rollback','reconcile','verify_committed'):
            directory=Path(BACKUP)
            state=load_state(directory)
            if MODE=='verify_committed':
                if state.get('phase')!='committed': raise RuntimeError('Only a committed transaction can be verified')
                adopt_generated_revision(state,connection,directory)
                checks=confirm(state,connection)
                state['phase']='verified';private_json(directory/'state.json',state)
                print(json.dumps({'status':'AppliedVerifiedAfterReconnect','backup_path':str(directory),
                  'revision':state['desired_revision'],'protected_config_unchanged':True,'checks':checks}))
            elif MODE=='reconcile':
                if state.get('phase')!='verified': raise RuntimeError('Transaction completion not confirmed; no retry')
                checks=confirm(state,connection)
                print(json.dumps({'status':'AppliedConfirmedAfterReconnect','backup_path':str(directory),'checks':checks}))
            else:
                if state.get('phase')!='verified': raise RuntimeError('Only verified transactions can be manually rolled back')
                rollback(state,connection);state['phase']='rolled_back';private_json(directory/'state.json',state)
                print(json.dumps({'status':'RolledBack','backup_path':str(directory)}))
            return
        raw,revision=read_settings(connection)
        old=json.loads(raw);desired=proposed(raw);cfg=config();require_warp(cfg)
        if service('rospanel')!='active' or service('quantumvpn-operator')!='active':
            raise RuntimeError('Panels not active before repair')
        candidate=generated_candidate(cfg,old,desired)
        run([str(BINARY),'run','-test','-config',str(CONFIG)],25)
        before_probes=probes()
        if MODE=='inspect':
            print(json.dumps({'mode':'read_only','revision':revision,'domains_to_add':[x for x in DOMAINS if x not in old['warp_domains']],
              'public_ipv6_to_add':IPV6 not in old['warp_ips'],'checks':before_probes}))
            return
        if desired==old:
            print(json.dumps({'status':'AlreadyConfigured','changed':False,'checks':before_probes}));return
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(ROOT,0o700)
        directory=ROOT/('instagram-'+STAMP+'-'+TRANSACTION)
        directory.mkdir(mode=0o700)
        backup_db=directory/'rospanel.db'
        # SQLite online backup, not a live filesystem copy of DB/WAL.
        fd=os.open(backup_db,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
        deadline=time.monotonic()+45
        def backup_progress(status,remaining,total):
            if time.monotonic()>deadline: raise RuntimeError('Private backup deadline exceeded; no mutation')
        with sqlite3.connect(backup_db) as dest:
            connection.backup(dest,pages=256,progress=backup_progress,sleep=0.05)
            if dest.execute('PRAGMA quick_check').fetchone()!=('ok',):
                raise RuntimeError('Private SQLite backup integrity failed; no mutation')
        private_json(directory/'previous-xray.json',cfg)
        desired_raw=json.dumps(desired,separators=(',',':'),ensure_ascii=False)
        state={'schema':1,'target':str(DB),'phase':'prepared','previous_raw':raw,'previous_revision':revision,
          'desired_raw':desired_raw,'desired_revision':revision+1,'previous_config_sha256':digest(cfg),
          'desired_config_sha256':digest(candidate),'reserve_state':service('reserve-trojan')}
        private_json(directory/'state.json',state)
        validate_config(candidate,directory)
        if digest(config())!=state['previous_config_sha256']:
            raise RuntimeError('Live config changed during preflight; no settings changed')
        cas(connection,raw,revision,desired_raw)
        try:
            state['phase']='committed';private_json(directory/'state.json',state)
            restart_and_check()
            adopt_generated_revision(state,connection,directory)
            checks=confirm(state,connection)
            state['phase']='verified';private_json(directory/'state.json',state)
        except Exception:
            adopt_generated_revision(state,connection,directory)
            rollback(state,connection)
            state['phase']='rolled_back';private_json(directory/'state.json',state)
            print(json.dumps({'status':'RolledBackAfterFailure','backup_path':str(directory)}),flush=True)
            raise
        print(json.dumps({'status':'Applied','changed':True,'backup_path':str(directory),'revision':state['desired_revision'],
          'protected_config_unchanged':True,'checks':checks}))

if RUN_REMOTE:
    try: main()
    except Exception as error:
        print(json.dumps({'status':'Failed','error_type':type(error).__name__,
          'reason':str(error) if isinstance(error,RuntimeError) else 'unexpected failure; raw details suppressed'}),flush=True)
        raise SystemExit(1)
'''


def main() -> None:
    import datetime
    import json
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--rollback', metavar='PRIVATE_TRANSACTION_DIRECTORY')
    modes.add_argument('--verify-committed', metavar='PRIVATE_TRANSACTION_DIRECTORY',
                       help='Verify and mark a committed transaction; never reapplies or restarts')
    options = parser.parse_args()
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment, not arguments.')
    transaction = uuid.uuid4().hex
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    directory = '/var/lib/quantumvpn-operator/routing-backups/instagram-' + stamp + '-' + transaction

    def connect():
        client = paramiko.SSHClient()
        client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect('150.241.96.191', username='root', password=password,
                           allow_agent=False, look_for_keys=False, timeout=20, auth_timeout=20)
        except Exception:
            client.close()
            raise
        return client

    def invoke(client, mode, backup=None):
        source = ('MODE=' + repr(mode) + '\nBACKUP=' + repr(backup) + '\nTRANSACTION=' + repr(transaction)
                  + '\nSTAMP=' + repr(stamp) + '\nRUN_REMOTE=True\n' + REMOTE)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=240)
        stdin.write(source)
        stdin.channel.shutdown_write()
        rows = [json.loads(line) for line in stdout]
        stderr.read()  # Never expose raw settings/config/command errors.
        return stdout.channel.recv_exit_status(), rows

    client = connect()
    try:
        try:
            selected = ('rollback' if options.rollback else 'verify_committed' if options.verify_committed
                        else 'apply' if options.apply else 'inspect')
            code, rows = invoke(client, selected, options.rollback or options.verify_committed)
        except (paramiko.SSHException, EOFError, OSError):
            code, rows = -1, []
        if code and not rows and options.apply:
            client.close()
            client = connect()
            # An ambiguous SSH response is reconciled read-only, never reapplied.
            code, rows = invoke(client, 'reconcile', directory)
        for row in rows:
            print(json.dumps(row), flush=True)
        if code:
            raise SystemExit('Guarded Instagram/WARP repair failed; raw stderr suppressed.')
    finally:
        client.close()


if __name__ == '__main__':
    main()
