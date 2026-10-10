"""Owned Safehop DNS deployment. Read-only by default; no APK or VPN rewrites.

Uses signed distro/PowerDNS packages, a separate ACME certificate and nginx
SNI passthrough into the unchanged PROXY-aware Xray inbound. SSH credentials
are accepted only from the short-lived QVPN_VDS_PASSWORD environment variable.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

import paramiko


REMOTE = r"""
import base64,fcntl,hashlib,ipaddress,json,os,pwd,grp,re,socket,sqlite3,ssl,stat,struct,subprocess,time,traceback,types,urllib.request
from pathlib import Path
ROOT=Path('/var/lib/quantumvpn-safehop-dns')
CFG=Path('/etc/quantumvpn-safehop-dns')
MANIFEST=ROOT/'installation.json'
FRONT_UNIT='quantumvpn-safehop-front.service'
ROUTE_UNIT='quantumvpn-safehop-route.service'
DOMAIN='safehop.crabdance.com'
PUBLIC='150.241.96.191'
TABLE=('inet','quantumvpn_safehop_dns')
KEY_FINGERPRINT='9FAAA5577E8FCF62093D036C1B0C6205FD380FBB'
PROTECTED=('/usr/local/bin/rospanel','/var/lib/rospanel/xray/config.json','/var/lib/rospanel/certs/cert.pem','/var/lib/rospanel/certs/key.pem','/etc/systemd/system/rospanel.service','/etc/nginx/nginx.conf','/etc/nginx/sites-available/quantumvpn-operator','/etc/nginx/sites-available/rospanel-admin','/var/lib/rospanel/secrets.key','/etc/resolv.conf')

def require(ok,code):
 if not ok:raise RuntimeError(code)
def sha(data):return hashlib.sha256(data).hexdigest()
def run(args,timeout=30,ok=True,input=None):
 p=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l',LC_ALL='C'))
 if ok and p.returncode:
  # Only reviewed DNS tooling diagnostics; never display environment or private keys.
  safe=('nginx','dnsdist','unbound-checkconf','nft','systemd-analyze','apt-get','certbot')
  if Path(args[0]).name in safe:
   lines=(p.stderr or p.stdout)[-2400:]
   print(json.dumps({'diagnostic':Path(args[0]).name,'message':lines}),flush=True)
  raise RuntimeError('command_failed_'+Path(args[0]).name.replace('-','_'))
 return p
def read(path,maximum=16777216):
 path=Path(path);require(not path.is_symlink() and path.is_file(),'regular_file_required')
 i=path.stat();require(i.st_uid==0 and not i.st_mode&0o022 and i.st_size<=maximum,'protected_file_refused')
 return path.read_bytes()
def mkdir(path,mode=0o700,user=0,group=0):
 path=Path(path);require(not path.is_symlink(),'directory_symlink_refused')
 if not path.exists():path.mkdir(mode=mode,parents=True)
 require(path.is_dir(),'directory_required');os.chmod(path,mode);os.chown(path,user,group)
def write(path,data,mode=0o600,group=0):
 path=Path(path);data=data.encode() if isinstance(data,str) else data
 require(not path.is_symlink(),'write_symlink_refused')
 if path.exists():require(path.is_file() and path.stat().st_uid==0,'write_owner_refused')
 temp=path.with_name(path.name+'.safehop-tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  os.fchown(fd,0,group)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  os.replace(temp,path)
 finally:
  if temp.exists():temp.unlink()
def protected():
 result={p:sha(read(p,268435456 if p=='/usr/local/bin/rospanel' else 16777216)) for p in PROTECTED if p!='/etc/resolv.conf'}
 resolved=Path('/etc/resolv.conf').resolve();require(str(resolved)=='/run/systemd/resolve/stub-resolv.conf','unexpected_host_resolver_path')
 require(resolved.is_file() and not resolved.stat().st_mode&0o022,'host_resolver_permissions')
 result['/etc/resolv.conf']=sha(resolved.read_bytes());return result
def source(encoded,expected,name):
 data=base64.b64decode(encoded,validate=True);require(sha(data)==expected,'local_source_identity_failed')
 m=types.ModuleType(name);exec(compile(data,name,'exec'),m.__dict__);return m
def service(unit):return run(['systemctl','is-active',unit],ok=False).stdout.strip()=='active'
def ports():
 raw=run(['ss','-H','-lntup']).stdout
 return [int(x) for x in re.findall(r'(?:\]|\*|[0-9.]+):(\d+)\s',raw)]
def table():
 p=run(['nft','-j','list','table',*TABLE],ok=False)
 return json.loads(p.stdout) if p.returncode==0 else None
def identity(value):
 def clean(x):
  if isinstance(x,dict):return {k:clean(v) for k,v in x.items() if k not in ('handle','metainfo','packets','bytes')}
  if isinstance(x,list):return [clean(v) for v in x if not isinstance(v,dict) or 'metainfo' not in v]
  return x
 return sha(json.dumps(clean(value),sort_keys=True,separators=(',',':')).encode())
def save(state):write(MANIFEST,json.dumps(state,sort_keys=True,indent=2)+'\n')
def state():return json.loads(read(MANIFEST))
def switch_rules(rules,s):
 existing=table()
 if existing:require(identity(existing)==s.get('nft_fingerprint'),'foreign_or_changed_nft_table')
 command=('delete table '+ ' '.join(TABLE)+'\n' if existing else '')+rules
 run(['nft','--check','-f','-'],input=command)
 run(['nft','-f','-'],input=command)
 s['nft_fingerprint']=identity(table());s['nft_rules']=rules;save(s)
def stop_rules(s):
 existing=table()
 if existing:
  require(identity(existing)==s.get('nft_fingerprint'),'changed_nft_table_no_delete')
  run(['nft','delete','table',*TABLE])
def account(name,group=None):
 try:g=grp.getgrnam(group or name)
 except KeyError:
  run(['groupadd','--system',group or name]);g=grp.getgrnam(group or name)
 try:u=pwd.getpwnam(name);require(u.pw_shell in ('/usr/sbin/nologin','/bin/false'),'foreign_account_refused')
 except KeyError:
  run(['useradd','--system','--gid',g.gr_name,'--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name]);u=pwd.getpwnam(name)
 return u,g
def query(host,port,name='example.com',tcp=True,tls=False):
 wire=struct.pack('!6H',27183,0x0100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
 if tcp:
  c=socket.create_connection((host,port),timeout=12)
  if tls:c=ssl.create_default_context().wrap_socket(c,server_hostname=DOMAIN)
  c.sendall(struct.pack('!H',len(wire))+wire)
  def exact(n):
   b=b''
   while len(b)<n:
    part=c.recv(n-len(b));require(bool(part),'dns_truncated');b+=part
   return b
  raw=exact(struct.unpack('!H',exact(2))[0]);c.close()
 else:
  c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.settimeout(12);c.sendto(wire,(host,port));raw,_=c.recvfrom(4096);c.close()
 require(len(raw)>=12 and struct.unpack('!H',raw[:2])[0]==27183,'dns_response_identity')
 flags=struct.unpack('!H',raw[2:4])[0];rcode=flags&15
 require(flags&0x8000 and rcode==(2 if name=='dnssec-failed.org' else 0),'dns_resolution_or_dnssec_failed')
 return {'ok':True,'rcode':rcode,'answers':struct.unpack('!H',raw[6:8])[0],'authenticated_data':bool(flags&0x20)}
def ready_query(*args,**kwargs):
 for attempt in range(10):
  try:return query(*args,**kwargs)
  except (ConnectionRefusedError,TimeoutError):
   if attempt==9:raise
   time.sleep(.5)
def inventory():
 require(os.geteuid()==0,'root_required')
 require('VERSION_ID="24.04"' in Path('/etc/os-release').read_text(),'ubuntu_24_04_required')
 c=json.loads(read('/var/lib/rospanel/xray/config.json'));v=[x for x in c.get('inbounds',[]) if x.get('tag')=='vless-in']
 require(len(v)==1 and v[0].get('listen')=='127.0.0.1' and v[0].get('port')==18443,'unexpected_vless_inbound')
 require(v[0].get('streamSettings',{}).get('sockopt',{}).get('acceptProxyProtocol') is True,'proxy_protocol_required')
 require(v[0].get('streamSettings',{}).get('tlsSettings',{}).get('rejectUnknownSni') is True,'unknown_sni_must_fail_closed')
 addresses=json.loads(run(['ip','-j','address']).stdout)
 global_ips=[a['local'] for x in addresses for a in x.get('addr_info',[]) if a.get('scope')=='global' and ipaddress.ip_address(a['local']).is_global]
 require(PUBLIC in global_ips,'public_ipv4_assignment_required')
 require({x[4][0] for x in socket.getaddrinfo(DOMAIN,443,socket.AF_INET)}=={PUBLIC},'dns_A_record_mismatch')
 require(service('rospanel') and service('nginx') and service('quantumvpn-operator'),'existing_services_not_ready')
 return {'status':'ReadOnly','domain':DOMAIN,'ipv4':PUBLIC,'public_ipv6':[x for x in global_ips if ':' in x],'installed':MANIFEST.exists(),'protected_hashes':protected(),'proxy_protocol':True,'old_safehop_sni_rejected':True}
def packages(s):
 # Never let a package postinst open a default wildcard DNS listener.
 require(not run(['dpkg-query','-W','-f=${Status}','unbound'],ok=False).stdout.strip(),'preexisting_unbound_requires_manual_review')
 require(not run(['dpkg-query','-W','-f=${Status}','dnsdist'],ok=False).stdout.strip(),'preexisting_dnsdist_requires_manual_review')
 masks=[]
 for unit in ('unbound.service','unbound-resolvconf.service','dnsdist.service'):
  p=Path('/run/systemd/system')/unit;require(not p.exists() and not p.is_symlink(),'preexisting_runtime_mask')
  os.symlink('/dev/null',p);masks.append(p)
 run(['systemctl','daemon-reload'])
 try:
  key=urllib.request.urlopen('https://repo.powerdns.com/FD380FBB-pub.asc',timeout=30).read(131073);require(len(key)<131072,'repository_key_bound')
  kp=Path('/etc/apt/keyrings/quantumvpn-safehop-dns.asc');mkdir(kp.parent,0o755);require(not kp.exists(),'repository_key_exists');write(kp,key,0o644)
  k=run(['gpg','--batch','--with-colons','--show-keys',str(kp)]).stdout
  require(KEY_FINGERPRINT in re.findall(r'^fpr:::::::::([0-9A-F]+):',k,re.M),'repository_signing_key_mismatch')
  sp=Path('/etc/apt/sources.list.d/quantumvpn-safehop-dns.list');pp=Path('/etc/apt/preferences.d/quantumvpn-safehop-dns')
  require(not sp.exists() and not pp.exists(),'repository_configuration_exists')
  write(sp,'deb [signed-by='+str(kp)+'] https://repo.powerdns.com/ubuntu noble-dnsdist-21 main\n',0o644)
  write(pp,'Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n',0o644)
  s['apt_owned']=[str(kp),str(sp),str(pp)];save(s)
  run(['apt-get','update'],180)
  policy=run(['apt-cache','policy','dnsdist']).stdout
  candidate=re.search(r'Candidate: 2\.1\.(\d+)-1pdns\.ubuntu24\.04',policy)
  require(candidate and int(candidate.group(1))>=2 and 'noble-dnsdist-21' in policy,'supported_signed_dnsdist_candidate_required')
  run(['apt-get','install','--yes','--no-install-recommends','dnsdist','unbound','unbound-anchor','certbot','knot-dnsutils'],240)
  feature=run(['dnsdist','--version']).stdout
  require('dns-over-https' in feature and 'dns-over-tls' in feature,'encrypted_dns_features_missing')
  s['dnsdist_version']=feature.splitlines()[0];save(s)
  run(['systemctl','disable','unbound.service','dnsdist.service'])
  s['packages_ready']=True;save(s)
 finally:
  for p in masks:
   if p.is_symlink() and os.readlink(p)=='/dev/null':p.unlink()
  run(['systemctl','daemon-reload'])
def existing_zerossl_account(s):
 # Reuse only the owner's registered account; onlyReturnExisting cannot create one.
 # Never overwrite the RosPanel account key, EAB settings, database or certificate.
 from acme import client as ac, messages
 import josepy as jose
 from certbot._internal import account as accounts
 from certbot import configuration
 import argparse
 server='https://acme.zerossl.com/v2/DV90'
 path=Path('/var/lib/rospanel/acme/zerossl_account.key');data=read(path,16384);original=sha(data)
 key=jose.JWK.load(data)
 require(isinstance(key,jose.JWKEC),'expected_existing_ec_account')
 net=ac.ClientNetwork(key,alg=jose.ES256,user_agent='QuantumVPN-Safehop-ACME/1.0',timeout=30)
 client=ac.ClientV2(ac.ClientV2.get_directory(server,net),net)
 registration=client.query_registration(messages.RegistrationResource(body=messages.Registration(),uri=''))
 require(str(registration.body.status)=='valid','existing_acme_account_invalid')
 account=accounts.Account(registration,key)
 directory=Path('/etc/letsencrypt/accounts/acme.zerossl.com/v2/DV90')
 config=configuration.NamespaceConfig(argparse.Namespace(config_dir='/etc/letsencrypt',work_dir='/var/lib/letsencrypt',logs_dir='/var/log/letsencrypt',server=server,strict_permissions=True,http01_port=80,https_port=443,domains=None))
 storage=accounts.AccountFileStorage(config)
 if (directory/account.id).exists():
  prior=storage.load(account.id);require(prior.key==key,'certbot_account_identity_changed')
 else:storage.save(account,client)
 require(sha(read(path,16384))==original,'main_acme_key_changed')
 s['acme_provider']='zerossl';s['acme_account']=account.id;save(s)
 return ['--server',server,'--account',account.id]
def certificate(s):
 provider=existing_zerossl_account(s) if Path('/var/lib/rospanel/acme/zerossl_account.key').is_file() else []
 run(['certbot','certonly','--webroot','--webroot-path',str(ROOT/'acme-webroot'),'--cert-name',DOMAIN,'--domain',DOMAIN,'--non-interactive','--agree-tos','--register-unsafely-without-email','--no-eff-email','--deploy-hook','/usr/bin/python3 -B /usr/local/lib/quantumvpn-safehop-renew.py',*provider],180)
 live=Path('/etc/letsencrypt/live')/DOMAIN
 cert=(live/'fullchain.pem').read_bytes();key=(live/'privkey.pem').read_bytes()
 require(len(cert)<32768 and len(key)<16384,'certificate_size_refused')
 decoded=ssl._ssl._test_decode_cert(str(live/'cert.pem'));require(('DNS',DOMAIN) in decoded.get('subjectAltName',()),'certificate_host_mismatch')
 require(ssl.cert_time_to_seconds(decoded['notAfter'])>time.time()+30*86400,'certificate_expiry_too_short')
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(live/'fullchain.pem'),str(live/'privkey.pem'))
 group=grp.getgrnam('quantumvpn-safehop-tls').gr_gid
 write(ROOT/'tls/fullchain.pem',cert,0o640,group);write(ROOT/'tls/privkey.pem',key,0o640,group)
 s['certificate_not_after']=decoded['notAfter'];s['certificate_sha256']=sha(cert);save(s)
def bootstrap():
 current=inventory();require(current['protected_hashes']==EXPECTED,'protected_identity_changed')
 resuming=MANIFEST.exists()
 if resuming:
  s=state();require(s.get('managed_by')=='quantumvpn-safehop-dns' and s['protected_hashes']==EXPECTED and s['stage']=='bootstrap_failed' and s.get('packages_ready'),'safehop_resume_requires_review')
  require(not table(),'resume_with_live_route_refused')
 else:
  require(not table() and not ROOT.exists() and not CFG.exists(),'safehop_already_present_inspect_required')
  for name in (dns.UNBOUND_USER,dns.DNSDIST_USER,front.FRONT_USER):
   try:pwd.getpwnam(name);raise RuntimeError('preexisting_safehop_account')
   except KeyError:pass
  for path in list(dns.generated_files())+[front.NGINX_CONFIG,'/etc/systemd/system/'+FRONT_UNIT,'/etc/systemd/system/'+ROUTE_UNIT,'/usr/local/lib/quantumvpn-safehop-route.py','/usr/local/lib/quantumvpn-safehop-renew.py']:
   require(not Path(path).exists() and not Path(path).is_symlink(),'preexisting_safehop_file')
 require(all(x not in ports() for x in (853,18553,18554,18555,18556,18557)),'safehop_port_conflict')
 require(not re.search(r'(?:\*|0\.0\.0\.0|150\.241\.96\.191|\[::\]):53\s',run(['ss','-H','-lntu']).stdout),'public_dns_port_conflict')
 mkdir(ROOT,0o711);mkdir(CFG,0o755);mkdir(ROOT/'acme-webroot',0o755);mkdir(ROOT/'acme-webroot/.well-known',0o755);mkdir(ROOT/'acme-webroot/.well-known/acme-challenge',0o755)
 if not resuming:s={'schema':1,'managed_by':'quantumvpn-safehop-dns','stage':'preparing','created_at':int(time.time()),'protected_hashes':EXPECTED,'files':{},'nft_fingerprint':None}
 save(s)
 try:
  if not resuming:packages(s)
  fu,fg=account('quantumvpn-safehop-front','quantumvpn-safehop-tls');u,g=account(dns.UNBOUND_USER);account(dns.DNSDIST_USER)
  run(['usermod','--append','--groups','quantumvpn-safehop-tls',dns.DNSDIST_USER])
  mkdir(ROOT/'tls',0o750,0,grp.getgrnam('quantumvpn-safehop-tls').gr_gid)
  mkdir(ROOT/'unbound',0o700,u.pw_uid,g.gr_gid)
  mkdir(front.PREFIX,0o700,fu.pw_uid,fg.gr_gid);mkdir(front.RUNTIME_DIRECTORY,0o700,fu.pw_uid,fg.gr_gid)
  for name in ('client-body','proxy','fastcgi','uwsgi','scgi'):mkdir(Path(front.PREFIX)/name,0o700,fu.pw_uid,fg.gr_gid)
  for path,content in dns.generated_files().items():
   if path.endswith(dns.DNSDIST_SERVICE):content=content.replace('Group='+dns.DNSDIST_USER+'\n','Group='+dns.DNSDIST_USER+'\nSupplementaryGroups=quantumvpn-safehop-tls\n')
   write(path,content,0o644);s['files'][path]=sha(content.encode())
  # The package's own profile is extended only for this new dedicated state/config.
  ap=Path('/etc/apparmor.d/local/usr.sbin.unbound');require(resuming or not ap.exists() or all(not line.strip() or line.lstrip().startswith(b'#') for line in read(ap).splitlines()),'preexisting_unbound_apparmor_local')
  if Path('/etc/apparmor.d/usr.sbin.unbound').exists():
   write(ap,'# QuantumVPN Safehop DNS\n/etc/quantumvpn-safehop-dns/unbound.conf r,\n/var/lib/quantumvpn-safehop-dns/unbound/ r,\nowner /var/lib/quantumvpn-safehop-dns/unbound/** rwk,\n',0o644)
   run(['apparmor_parser','--replace','/etc/apparmor.d/usr.sbin.unbound'])
  run(['unbound-anchor','-a',str(ROOT/'unbound/root.key')],60,ok=False)
  require((ROOT/'unbound/root.key').is_file() and (ROOT/'unbound/root.key').stat().st_size>100,'dnssec_root_anchor_missing')
  os.chown(ROOT/'unbound/root.key',u.pw_uid,g.gr_gid);os.chmod(ROOT/'unbound/root.key',0o600)
  run(['unbound-checkconf',dns.UNBOUND_CONFIG])
  write(front.NGINX_CONFIG,front.bootstrap_config(),0o644)
  write('/etc/systemd/system/'+FRONT_UNIT,front.front_service(),0o644)
  write('/usr/local/lib/quantumvpn-safehop-route.py',ROUTE_SOURCE,0o700)
  write('/usr/local/lib/quantumvpn-safehop-renew.py',RENEW_SOURCE,0o700)
  write('/etc/systemd/system/'+ROUTE_UNIT,ROUTE_SERVICE,0o644)
  # nginx -t touches its pid file; never let a root test create a root-owned pid.
  run(['runuser','--user',front.FRONT_USER,'--','nginx','-t','-p',front.PREFIX,'-c',front.NGINX_CONFIG])
  run(['systemd-analyze','verify','/etc/systemd/system/'+FRONT_UNIT,'/etc/systemd/system/'+dns.UNBOUND_SERVICE,'/etc/systemd/system/'+dns.DNSDIST_SERVICE,'/etc/systemd/system/'+ROUTE_UNIT])
  save(s);run(['systemctl','daemon-reload']);run(['systemctl','start',dns.UNBOUND_SERVICE]);ready_query('127.0.0.1',18553)
  run(['systemctl','start',FRONT_UNIT]);switch_rules(front.nftables_rules(bootstrap=True),s)
  require(protected()==EXPECTED,'protected_identity_changed_after_bootstrap')
  certificate(s);s['stage']='certificate_ready';save(s)
  print(json.dumps({'status':'CertificateReady','domain':DOMAIN,'dnssec_resolver':True,'dnsdist_version':s['dnsdist_version'],'certificate_not_after':s['certificate_not_after'],'protected_unchanged':True}))
 except Exception:
  s['stage']='bootstrap_failed';save(s);stop_rules(s);run(['systemctl','stop',FRONT_UNIT,dns.UNBOUND_SERVICE],ok=False)
  raise
def activate():
 s=state();require(s['stage']=='certificate_ready','certificate_ready_required')
 require(protected()==s['protected_hashes'],'protected_identity_changed')
 run(['dnsdist','--check-config','-C',dns.DNSDIST_CONFIG])
 run(['systemctl','start',dns.DNSDIST_SERVICE]);ready_query(PUBLIC,53);query(PUBLIC,53,tcp=False);query(PUBLIC,853,tls=True);query('127.0.0.1',18553,'dnssec-failed.org')
 old_config=read(front.NGINX_CONFIG);old_rules=s['nft_rules']
 try:
  write(front.NGINX_CONFIG,front.nginx_config(),0o644)
  run(['nginx','-t','-p',front.PREFIX,'-c',front.NGINX_CONFIG]);run(['systemctl','reload',FRONT_UNIT])
  switch_rules(front.nftables_rules(),s)
  doh_probe()
  require(protected()==s['protected_hashes'],'protected_identity_changed_after_activation')
  s['stage']='active';save(s)
  run(['systemctl','enable',dns.UNBOUND_SERVICE,dns.DNSDIST_SERVICE,FRONT_UNIT,ROUTE_UNIT]);run(['systemctl','start',ROUTE_UNIT])
 except Exception:
  switch_rules(old_rules,s);write(front.NGINX_CONFIG,old_config,0o644)
  run(['systemctl','reload',FRONT_UNIT],ok=False);run(['systemctl','stop',dns.DNSDIST_SERVICE],ok=False)
  s['stage']='certificate_ready';save(s)
  raise
 print(json.dumps({'status':'Activated','domain':DOMAIN,'ipv4':PUBLIC,'doh':'https://'+DOMAIN+'/dns-query','dot':DOMAIN,'dnssec_invalid_rejected':True,'protected_unchanged':True,'main_restarted':False,'external_gates_pending':True}))
def verify():
 s=state();require(protected()==s['protected_hashes'],'protected_identity_changed')
 require(table() and identity(table())==s['nft_fingerprint'],'nft_identity_failed')
 services={x:service(x) for x in [FRONT_UNIT,ROUTE_UNIT,dns.UNBOUND_SERVICE,dns.DNSDIST_SERVICE,'rospanel','nginx','quantumvpn-operator']}
 require(s['stage']=='active' and all(services.values()),'active_services_required')
 print(json.dumps({'status':s['stage'],'domain':DOMAIN,'services':services,'ordinary_udp':query(PUBLIC,53,tcp=False),'ordinary_tcp':query(PUBLIC,53),'dot':query(PUBLIC,853,tls=True),'doh':doh_probe(),'dnssec_invalid':query('127.0.0.1',18553,'dnssec-failed.org'),'protected_unchanged':True,'certificate_not_after':s.get('certificate_not_after')}))
def doh_probe():
 wire=struct.pack('!6H',27183,0x0100,1,0,0,0)+b'\x07example\x03com\0'+struct.pack('!HH',1,1)
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
 req=urllib.request.Request('https://'+DOMAIN+'/dns-query',data=wire,headers={'Content-Type':'application/dns-message','Accept':'application/dns-message'})
 with opener.open(req,timeout=15) as response:
  raw=response.read(4097);require(response.status==200 and response.headers.get_content_type()=='application/dns-message','doh_http_contract')
 require(12<=len(raw)<=4096 and struct.unpack('!H',raw[:2])[0]==27183 and raw[3]&15==0 and struct.unpack('!H',raw[6:8])[0]>0,'doh_wire_contract')
 return {'ok':True,'trusted_tls':True,'http_status':200}
def refresh():
 s=state();require(s['stage']=='active' and protected()==s['protected_hashes'],'active_owned_installation_required')
 old_config=read(front.NGINX_CONFIG);old_rules=s['nft_rules']
 try:
  write(front.NGINX_CONFIG,front.nginx_config(),0o644)
  run(['nginx','-t','-p',front.PREFIX,'-c',front.NGINX_CONFIG]);run(['systemctl','reload',FRONT_UNIT])
  switch_rules(front.nftables_rules(),s)
  proof=doh_probe();require(protected()==s['protected_hashes'],'protected_identity_changed')
  s['front_config_sha256']=sha(read(front.NGINX_CONFIG));save(s)
  print(json.dumps({'status':'Refreshed','doh':proof,'protected_unchanged':True,'main_restarted':False}))
 except Exception:
  switch_rules(old_rules,s);write(front.NGINX_CONFIG,old_config,0o644);run(['systemctl','reload',FRONT_UNIT],ok=False)
  raise
def inspect():
 s=state();units=[FRONT_UNIT,ROUTE_UNIT,dns.UNBOUND_SERVICE,dns.DNSDIST_SERVICE]
 print(json.dumps({'status':s['stage'],'packages_ready':s.get('packages_ready'), 'protected_unchanged':protected()==s['protected_hashes'],'units':{u:run(['systemctl','show',u,'-p','ActiveState','-p','SubState','-p','Result','-p','ExecMainStatus'],ok=False).stdout for u in units},'journal':run(['journalctl','--no-pager','--since','10 minutes ago','-n','25',*sum((['-u',u] for u in units),[])],ok=False).stdout,'listeners':[line for line in run(['ss','-H','-lntup']).stdout.splitlines() if re.search(r':(?:53|853|1855[3-7])\s',line)]}))
dns=source(DNS_B64,DNS_SHA,'safehop_dns_configuration')
front=source(FRONT_B64,FRONT_SHA,'safehop_front_configuration')
ROUTE_SERVICE='''[Unit]\nDescription=QuantumVPN Safehop owned public ingress route\nAfter=network-online.target quantumvpn-safehop-front.service\nRequires=quantumvpn-safehop-front.service\nBindsTo=quantumvpn-safehop-front.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 -B /usr/local/lib/quantumvpn-safehop-route.py start\nExecStop=/usr/bin/python3 -B /usr/local/lib/quantumvpn-safehop-route.py stop\n[Install]\nWantedBy=multi-user.target\n'''
ROUTE_SOURCE=r'''import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path('/var/lib/quantumvpn-safehop-dns');p=ROOT/'installation.json'
def run(args,**kwargs):
 r=subprocess.run(args,capture_output=True,text=True,timeout=15,**kwargs)
 if r.returncode:raise SystemExit('owned_route_command_failed')
 return r.stdout
def fingerprint(value):
 def clean(x):
  if isinstance(x,dict):return {k:clean(v) for k,v in x.items() if k not in ('handle','metainfo','packets','bytes')}
  if isinstance(x,list):return [clean(v) for v in x if not isinstance(v,dict) or 'metainfo' not in v]
  return x
 return hashlib.sha256(json.dumps(clean(value),sort_keys=True,separators=(',',':')).encode()).hexdigest()
s=json.loads(p.read_text());assert s['managed_by']=='quantumvpn-safehop-dns' and s['schema']==1
r=subprocess.run(['nft','-j','list','table','inet','quantumvpn_safehop_dns'],capture_output=True,text=True,timeout=15)
if r.returncode==0:
 assert fingerprint(json.loads(r.stdout))==s['nft_fingerprint'],'foreign_route_no_change'
 if sys.argv[1]=='stop':run(['nft','delete','table','inet','quantumvpn_safehop_dns'])
elif sys.argv[1]=='start':
 assert s['stage']=='active' and '\ntable inet quantumvpn_safehop_dns {' in '\n'+s['nft_rules'], 'owned_rules_required'
 run(['nft','--check','-f','-'],input=s['nft_rules']);run(['nft','-f','-'],input=s['nft_rules'])
 assert fingerprint(json.loads(run(['nft','-j','list','table','inet','quantumvpn_safehop_dns'])))==s['nft_fingerprint'],'restored_route_identity'
'''
RENEW_SOURCE=r'''import grp,json,os,ssl,subprocess,time
from pathlib import Path
domain='safehop.crabdance.com';root=Path('/var/lib/quantumvpn-safehop-dns');live=Path('/etc/letsencrypt/live')/domain
# Certbot also renews other certificates: this hook must never touch them.
lineage=os.environ.get('RENEWED_LINEAGE')
if lineage and Path(lineage)!=live:raise SystemExit(0)
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=25)
 if p.returncode:raise RuntimeError('safehop_certificate_reload_failed')
def active(unit):return subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0
def write(path,data):
 tmp=path.with_name(path.name+'.renew-tmp');fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o640)
 try:
  os.fchown(fd,0,grp.getgrnam('quantumvpn-safehop-tls').gr_gid)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()
decoded=ssl._ssl._test_decode_cert(str(live/'cert.pem'))
assert ('DNS',domain) in decoded.get('subjectAltName',()) and ssl.cert_time_to_seconds(decoded['notAfter'])>time.time()+86400
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(str(live/'fullchain.pem'),str(live/'privkey.pem'))
cert=(live/'fullchain.pem').read_bytes();key=(live/'privkey.pem').read_bytes();assert len(cert)<32768 and len(key)<16384
paths=[root/'tls/fullchain.pem',root/'tls/privkey.pem'];old=[p.read_bytes() if p.exists() else None for p in paths]
dns_was_active=active('quantumvpn-safehop-dnsdist.service')
try:
 for p,data in zip(paths,[cert,key]):write(p,data)
 run(['nginx','-t','-p','/var/cache/quantumvpn-safehop-front','-c','/etc/quantumvpn-safehop-dns/nginx-front.conf'])
 if active('quantumvpn-safehop-front.service'):run(['systemctl','reload','quantumvpn-safehop-front.service'])
 if dns_was_active:
  run(['dnsdist','--check-config','-C','/etc/quantumvpn-safehop-dns/dnsdist.conf']);run(['systemctl','restart','quantumvpn-safehop-dnsdist.service'])
except Exception:
 for p,data in zip(paths,old):
  if data is not None:write(p,data)
 if active('quantumvpn-safehop-front.service'):run(['systemctl','reload','quantumvpn-safehop-front.service'])
 if dns_was_active:run(['systemctl','restart','quantumvpn-safehop-dnsdist.service'])
 raise
print('Safehop certificate installed; unrelated VPN services were not restarted.')
'''
try:
 if MODE=='inventory':print(json.dumps(inventory()))
 else:
  lock=os.open('/run/quantumvpn-safehop-dns.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  {'bootstrap':bootstrap,'activate':activate,'verify':verify,'inspect':inspect,'refresh':refresh}[MODE]()
except Exception as e:
 print(json.dumps({'status':'Failed','error':str(e) if isinstance(e,RuntimeError) and re.fullmatch('[a-z0-9_]+',str(e)) else type(e).__name__,'location':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(e.__traceback__)[-3:]]}));raise SystemExit(1)
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('inventory', 'bootstrap', 'activate', 'verify', 'inspect', 'refresh'), default='inventory')
    parser.add_argument('--expected-json', help='Exact protected hashes from read-only inventory JSON')
    args = parser.parse_args()
    expected = json.loads(args.expected_json) if args.expected_json else {}
    if args.mode == 'bootstrap' and not expected:
        parser.error('--mode bootstrap requires --expected-json')
    base = Path(__file__).parent
    values = {}
    for name, file in [('DNS', 'quantumvpn_safehop_dns.py'), ('FRONT', 'quantumvpn_safehop_front.py')]:
        data = (base / file).read_bytes()
        values[name+'_B64'] = base64.b64encode(data).decode()
        values[name+'_SHA'] = hashlib.sha256(data).hexdigest()
    source = '\n'.join(key+'='+repr(value) for key, value in dict(values, MODE=args.mode, EXPECTED=expected).items()) + '\n' + REMOTE
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=750)
        stdin.write(source); stdin.channel.shutdown_write()
        raw = stdout.read().decode(); stderr.read()
        entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
        for entry in entries[:-1]:print(json.dumps(entry, ensure_ascii=False))
        result = entries[-1]
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if stdout.channel.recv_exit_status():
            raise SystemExit(1)
    finally:
        client.close()


if __name__ == '__main__':
    main()
