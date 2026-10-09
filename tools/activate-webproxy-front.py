"""Activate the owned WEB relay without replacing RosPanel, nginx or Xray config.

Default: read-only inventory. --apply requires the observed protected hashes.
A new loopback HTTP/1 + h2c gateway preserves PROXY-protocol client addresses.
Only RosPanel's cgroup TCP fallbacks to 127.0.0.1:8080 are DNATed to it. No
public listener, VPN credentials, database, subscription or APK is changed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path


GATEWAY_GO = r'''
package main

import (
 "bufio"
 "context"
 "encoding/json"
 "errors"
 "io"
 "log"
 "net"
 "net/http"
 "net/http/httputil"
 "net/netip"
 "net/url"
 "os"
 "os/signal"
 "regexp"
 "strconv"
 "strings"
 "sync"
 "syscall"
 "time"
)

const listenAddr = "127.0.0.1:18084"
const siteAddr = "127.0.0.1:8080"
const relayAddr = "127.0.0.1:18082"
const publicHost = "pecaocek.ignorelist.com"
type clientKey struct{}
var prefixPattern = regexp.MustCompile(`^qweb-[a-z0-9]{12,48}$`)
type configuration struct { Schema int `json:"schema"`; BasePath string `json:"base_path"`; PublicHost string `json:"public_host"` }

func parseProxy(line string) (*net.TCPAddr, error) {
 if len(line) > 108 || !strings.HasSuffix(line,"\r\n") { return nil,errors.New("proxy_header_refused") }
 fields:=strings.Split(strings.TrimSuffix(line,"\r\n")," ")
 if len(fields)!=6 || fields[0]!="PROXY" || (fields[1]!="TCP4" && fields[1]!="TCP6") { return nil,errors.New("proxy_header_refused") }
 src,e:=netip.ParseAddr(fields[2]);if e!=nil || src.String()!=fields[2] || src.IsUnspecified() || src.IsMulticast() { return nil,errors.New("proxy_source_refused") }
 dst,e:=netip.ParseAddr(fields[3]);if e!=nil || dst.String()!=fields[3] { return nil,errors.New("proxy_destination_refused") }
 if (fields[1]=="TCP4" && (!src.Is4() || !dst.Is4())) || (fields[1]=="TCP6" && (!src.Is6() || !dst.Is6())) { return nil,errors.New("proxy_family_refused") }
 port,e:=strconv.Atoi(fields[4]);if e!=nil || port<1 || port>65535 || strconv.Itoa(port)!=fields[4] { return nil,errors.New("proxy_port_refused") }
 dport,e:=strconv.Atoi(fields[5]);if e!=nil || dport<1 || dport>65535 || strconv.Itoa(dport)!=fields[5] { return nil,errors.New("proxy_port_refused") }
 return &net.TCPAddr{IP:net.ParseIP(src.Unmap().String()),Port:port},nil
}

type proxyConn struct { net.Conn; reader *bufio.Reader; client *net.TCPAddr; release func(); once sync.Once }
func (c *proxyConn) Read(p []byte)(int,error) { return c.reader.Read(p) }
func (c *proxyConn) RemoteAddr()net.Addr { return c.client }
func (c *proxyConn) Close()error { e:=c.Conn.Close();c.once.Do(c.release);return e }
type proxyListener struct { net.Listener; slots chan struct{} }
func (l *proxyListener) Accept()(net.Conn,error) {
 for {
  c,e:=l.Listener.Accept();if e!=nil{return nil,e}
  peer,ok:=c.RemoteAddr().(*net.TCPAddr);if !ok || !peer.IP.Equal(net.IPv4(127,0,0,1)){c.Close();continue}
  select {case l.slots<-struct{}{}:default:c.Close();continue}
  release:=func(){<-l.slots}
  c.SetReadDeadline(time.Now().Add(3*time.Second));r:=bufio.NewReaderSize(c,4096)
  // Read at most the PROXY v1 maximum; never consume/execute HTTP or query data.
  var line strings.Builder
  for line.Len()<=108 { b,e:=r.ReadByte();if e!=nil{break};line.WriteByte(b);if b=='\n'{break} }
  client,e:=parseProxy(line.String());if e!=nil{c.Close();release();continue}
  c.SetReadDeadline(time.Time{});return &proxyConn{Conn:c,reader:r,client:client,release:release},nil
 }
}

func source(r *http.Request)(*net.TCPAddr,error) {
 a,e:=netip.ParseAddrPort(r.RemoteAddr);if e!=nil || a.Port()<1{return nil,errors.New("client_address_refused")};return &net.TCPAddr{IP:net.ParseIP(a.Addr().Unmap().String()),Port:int(a.Port())},nil
}

func proxyHeader(client *net.TCPAddr)(string,error) {
 if client==nil || client.IP==nil || client.Port<1 || client.Port>65535{return "",errors.New("original_client_required")}
 family,destination:="TCP4","127.0.0.1";if client.IP.To4()==nil{family,destination="TCP6","::1"}
 return "PROXY "+family+" "+client.IP.String()+" "+destination+" "+strconv.Itoa(client.Port)+" 8080\r\n",nil
}
func siteDial(ctx context.Context,network,address string)(net.Conn,error) {
 if network!="tcp" || address!=siteAddr { return nil,errors.New("fixed_site_destination_required") }
 client,ok:=ctx.Value(clientKey{}).(*net.TCPAddr);if !ok || client.IP==nil || client.Port<1 || client.Port>65535 { return nil,errors.New("original_client_required") }
 c,e:=(&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second}).DialContext(ctx,"tcp",siteAddr);if e!=nil{return nil,e}
 header,e:=proxyHeader(client);if e!=nil{c.Close();return nil,e}
 c.SetWriteDeadline(time.Now().Add(5*time.Second));n,e:=io.WriteString(c,header);c.SetWriteDeadline(time.Time{})
 if e!=nil || n!=len(header){c.Close();if e==nil{e=io.ErrShortWrite};return nil,e};return c,nil
}

func newProxy(target string,site bool)*httputil.ReverseProxy {
 u,_:=url.Parse("http://"+target)
 t:=&http.Transport{Proxy:nil,ForceAttemptHTTP2:false,DisableKeepAlives:site,MaxIdleConns:16,MaxIdleConnsPerHost:16,MaxConnsPerHost:64,IdleConnTimeout:90*time.Second,ResponseHeaderTimeout:60*time.Second,MaxResponseHeaderBytes:32768}
 if site { t.DialContext=siteDial } else { t.DialContext=(&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second}).DialContext }
 return &httputil.ReverseProxy{Transport:t,FlushInterval:-1,ErrorLog:log.New(io.Discard,"",0),Rewrite:func(p *httputil.ProxyRequest){
  p.SetURL(u);p.Out.Host=p.In.Host
  // Never trust client-supplied forwarding chains. The sole source is PROXY v1.
  for _,k:=range []string{"Forwarded","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Port","X-Real-IP","X-QV-Front-Client-IP","X-QV-Front-Client-Port"}{p.Out.Header.Del(k)}
  client,e:=source(p.In);if e==nil{p.Out.Header.Set("X-Forwarded-For",client.IP.String());p.Out.Header.Set("X-Real-IP",client.IP.String())}
  p.Out.Header.Set("X-Forwarded-Proto","https")
 },ErrorHandler:func(w http.ResponseWriter,r *http.Request,e error){http.Error(w,"Service unavailable",http.StatusServiceUnavailable)}}
}

func gatewayHandler(prefix string,site,relay http.Handler)http.Handler {
 requests:=make(chan struct{},128)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  select{case requests<-struct{}{}:defer func(){<-requests}();default:http.Error(w,"Service unavailable",503);return}
  a,e:=source(r);if e!=nil{http.Error(w,"Bad request",400);return};r=r.WithContext(context.WithValue(r.Context(),clientKey{},a))
  // Reserve the decoded namespace, including its naked form. Keep the original
  // URI intact: the relay's credential gate rejects authenticated noncanonical
  // paths before they can be delegated to the public application's logs.
  base:="/"+prefix
  if r.URL.Path==base || strings.HasPrefix(r.URL.Path,base+"/"){r.Body=http.MaxBytesReader(w,r.Body,2*1024*1024);relay.ServeHTTP(w,r)}else{site.ServeHTTP(w,r)}
 })
}

func main(){
 // A systemd readonly credential is the only supported production config path.
 d:=os.Getenv("CREDENTIALS_DIRECTORY");if d!="/run/credentials/quantumvpn-webproxy-front.service" {os.Exit(1)}
 f,e:=os.Open(d+"/front.json");if e!=nil{os.Exit(1)};info,e:=f.Stat();if e!=nil || !info.Mode().IsRegular() || info.Size()>4096{f.Close();os.Exit(1)}
 var cfg configuration;dec:=json.NewDecoder(io.LimitReader(f,4097));dec.DisallowUnknownFields();e=dec.Decode(&cfg);var extra any;tail:=dec.Decode(&extra);f.Close()
 if e!=nil || tail!=io.EOF || cfg.Schema!=1 || cfg.PublicHost!=publicHost || !prefixPattern.MatchString(cfg.BasePath){os.Exit(1)}
 ln,e:=net.Listen("tcp",listenAddr);if e!=nil{os.Exit(1)}
 protocols:=new(http.Protocols);protocols.SetHTTP1(true);protocols.SetUnencryptedHTTP2(true)
 s:=&http.Server{Handler:gatewayHandler(cfg.BasePath,newProxy(siteAddr,true),newProxy(relayAddr,false)),Protocols:protocols,HTTP2:&http.HTTP2Config{MaxConcurrentStreams:32},ReadHeaderTimeout:10*time.Second,IdleTimeout:90*time.Second,MaxHeaderBytes:16384,ErrorLog:log.New(io.Discard,"",0)}
 done:=make(chan os.Signal,1);signal.Notify(done,syscall.SIGTERM,syscall.SIGINT)
 go func(){<-done;ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel();s.Shutdown(ctx)}()
 if address:=os.Getenv("NOTIFY_SOCKET");address!=""{a:=&net.UnixAddr{Name:address,Net:"unixgram"};c,e:=net.DialUnix("unixgram",nil,a);if e!=nil{os.Exit(1)};_,e=c.Write([]byte("READY=1"));c.Close();if e!=nil{os.Exit(1)}}
 if e=s.Serve(&proxyListener{Listener:ln,slots:make(chan struct{},64)});e!=nil && e!=http.ErrServerClosed{os.Exit(1)}
}
'''

GATEWAY_TEST_GO = r'''
package main
import("bufio";"context";"fmt";"io";"net";"net/http";"net/http/httptest";"strings";"testing";"time")
func TestProxyParsing(t *testing.T){
 for _,v:=range []string{"PROXY TCP4 198.51.100.7 127.0.0.1 45678 443\r\n","PROXY TCP6 2001:db8::7 ::1 45678 443\r\n"}{if _,e:=parseProxy(v);e!=nil{t.Fatal(e)}}
 for _,v:=range []string{"GET / HTTP/1.1\r\n","PROXY UNKNOWN\r\n","PROXY TCP4 0.0.0.0 127.0.0.1 1 443\r\n","PROXY TCP4 198.51.100.7 127.0.0.1 0 443\r\n","PROXY TCP6 198.51.100.7 ::1 1 443\r\n","PROXY TCP4 198.51.100.7 127.0.0.1 01 443\r\n","PROXY  TCP4 198.51.100.7 127.0.0.1 1 443\r\n","PROXY TCP4 198.51.100.7 127.0.0.1 1 443\n",strings.Repeat("x",109)+"\r\n"}{if _,e:=parseProxy(v);e==nil{t.Fatalf("accepted invalid header")}}
}
func TestFragmentationAndIPv6Address(t *testing.T){
 ln,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)};defer ln.Close();wrapped:=&proxyListener{Listener:ln,slots:make(chan struct{},1)}
 done:=make(chan string,1);go func(){c,e:=wrapped.Accept();if e!=nil{done<-"error";return};defer c.Close();b:=make([]byte,3);io.ReadFull(c,b);done<-c.RemoteAddr().String()+" "+string(b)}()
 c,e:=net.Dial("tcp",ln.Addr().String());if e!=nil{t.Fatal(e)};defer c.Close()
 for _,s:=range []string{"PRO","XY TCP6 2001:db8::7 ::1 45678 443\r","\nGET"}{io.WriteString(c,s)}
 select{case value:=<-done:if value!="[2001:db8::7]:45678 GET"{t.Fatal(value)};case <-time.After(time.Second):t.Fatal("fragmentation stalled")}
}
func TestForwardingDoesNotAppendSpoofedChains(t *testing.T){
 seen:=make(chan string,1);backend:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){seen<-r.Header.Get("X-Forwarded-For")+"|"+r.Header.Get("Forwarded")+"|"+r.Host+"|"+r.URL.RequestURI();io.WriteString(w,"ok")}));defer backend.Close()
 p:=newProxy(strings.TrimPrefix(backend.URL,"http://"),false);r:=httptest.NewRequest("POST","http://pecaocek.ignorelist.com/qweb-0123456789ab/api/v1/session?bridge=not-logged",strings.NewReader("data"));r.RemoteAddr="198.51.100.7:12345";r.Header.Set("X-Forwarded-For","1.2.3.4, 5.6.7.8");r.Header.Set("Forwarded","for=1.2.3.4")
 p.ServeHTTP(httptest.NewRecorder(),r);if s:=<-seen;s!="198.51.100.7||pecaocek.ignorelist.com|/qweb-0123456789ab/api/v1/session?bridge=not-logged"{t.Fatal("header/path/host changed")}
}
func TestSiteDialRefusesUserDestinationAndMissingClient(t *testing.T){
 for _,a:=range []string{"example.com:443","127.0.0.1:10085",siteAddr}{if c,e:=siteDial(context.Background(),"tcp",a);e==nil{c.Close();t.Fatal("unsafe dial")}}
}
func TestReservedNamespaceKeepsMalformedCredentialsAwayFromSite(t *testing.T){
 const prefix="qweb-0123456789ab"
 for _,path:=range []string{"/qweb-0123456789ab/","/%71web-0123456789ab/","/qweb-0123456789ab%2Fapi/v1/session","/qweb-0123456789ab","/%71web-0123456789ab","/qweb-0123456789ab/api%2Fv1/session"}{
  siteCalls,relayCalls:=0,0;want:=path+"?bridge=not-logged"
  site:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){siteCalls++})
  relay:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){relayCalls++;if r.URL.RequestURI()!=want || r.Header.Get("Authorization")!="Bearer not-logged"{t.Fatal("credential URI changed")}})
  r:=httptest.NewRequest("POST","http://pecaocek.ignorelist.com"+want,strings.NewReader("data"));r.RemoteAddr="198.51.100.7:12345";r.Header.Set("Authorization","Bearer not-logged")
  gatewayHandler(prefix,site,relay).ServeHTTP(httptest.NewRecorder(),r)
  if siteCalls!=0 || relayCalls!=1{t.Fatal("reserved credential path delegated to site")}
 }
 for _,path:=range []string{"/","/api/v1/session","/qweb-0123456789ab-other/","/other/%71web-0123456789ab/"}{
  siteCalls,relayCalls:=0,0
  site:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){siteCalls++})
  relay:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){relayCalls++})
  r:=httptest.NewRequest("GET","http://pecaocek.ignorelist.com"+path,nil);r.RemoteAddr="198.51.100.7:12345"
  gatewayHandler(prefix,site,relay).ServeHTTP(httptest.NewRecorder(),r)
  if siteCalls!=1 || relayCalls!=0{t.Fatal("unrelated site namespace stolen")}
 }
}
func TestHTTP1AndH2CWithProxyClient(t *testing.T){
 ln,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)}
 protocols:=new(http.Protocols);protocols.SetHTTP1(true);protocols.SetUnencryptedHTTP2(true)
 server:=&http.Server{Protocols:protocols,Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){fmt.Fprintf(w,"%s|%s",r.Proto,r.RemoteAddr)})};go server.Serve(&proxyListener{Listener:ln,slots:make(chan struct{},8)});defer server.Close()
 dial:=func(ctx context.Context,n,a string)(net.Conn,error){c,e:=(&net.Dialer{}).DialContext(ctx,n,a);if e==nil{_,e=io.WriteString(c,"PROXY TCP4 198.51.100.7 127.0.0.1 45678 443\r\n")};return c,e}
 for _,h2:=range []bool{false,true}{p:=new(http.Protocols);p.SetHTTP1(!h2);p.SetUnencryptedHTTP2(h2);transport:=&http.Transport{Protocols:p,DialContext:dial};client:=&http.Client{Transport:transport,Timeout:3*time.Second};response,e:=client.Get("http://"+ln.Addr().String()+"/");if e!=nil{t.Fatal(e)};b,_:=io.ReadAll(response.Body);response.Body.Close();transport.CloseIdleConnections();want:="HTTP/1.1|198.51.100.7:45678";if h2{want="HTTP/2.0|198.51.100.7:45678"};if string(b)!=want{t.Fatal(string(b))}}
}
// The same serializer the production DialContext uses is checked against a
// strict mock PROXY receiver; neither IPv6 nor port may be lost.
func TestProxySerialization(t *testing.T){
 for _,value:=range []string{"198.51.100.7:12345","[2001:db8::7]:54321"}{a,e:=net.ResolveTCPAddr("tcp",value);if e!=nil{t.Fatal(e)};line,e:=proxyHeader(a);if e!=nil{t.Fatal(e)};r:=bufio.NewReader(strings.NewReader(line));raw,_:=r.ReadString('\n');got,e:=parseProxy(raw);if e!=nil || got.String()!=value{t.Fatal("source address lost")}}
}
'''

ROUTE_RUNTIME = r'''
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
PRIVATE=Path('/etc/quantumvpn-webproxy')
STATE=Path('/var/lib/quantumvpn-webproxy-front/state.json')
TABLE='quantumvpn_web_front'
def require(v,e):
 if not v:raise RuntimeError(e)
def read(p,n):
 require(not p.is_symlink() and not any(x.is_symlink() for x in p.parents),'unsafe_route_path')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  i=os.fstat(fd);require(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022 and i.st_size<=n,'unsafe_route_file')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
  require(len(b)<=n,'route_file_bound');return b
 finally:os.close(fd)
def run(args,input=None):
 p=subprocess.run(args,input=input,capture_output=True,text=True,timeout=10)
 return p.returncode,p.stdout
def normalized(v):
 if isinstance(v,list):return [normalized(x) for x in v if not isinstance(x,dict) or 'metainfo' not in x]
 if isinstance(v,dict):return {k:normalized(x) for k,x in v.items() if k not in ('handle','packets','bytes')}
 return v
def fingerprint(v):return hashlib.sha256(json.dumps(normalized(v),sort_keys=True,separators=(',',':')).encode()).hexdigest()
def table():
 rc,out=run(['nft','-j','list','table','ip',TABLE])
 if rc:
  rc,out=run(['nft','-j','list','tables']);require(rc==0,'nft_inventory_failed')
  require(not any(x.get('table',{}).get('family')=='ip' and x.get('table',{}).get('name')==TABLE for x in json.loads(out)['nftables']),'nft_table_unreadable')
  return None
 value=json.loads(out);require(len(value.get('nftables',[]))<=8,'foreign_route_table');return value
def state():
 if not STATE.exists():return None
 v=json.loads(read(STATE,4096));require(v.get('schema')==1 and v.get('managed_by')=='quantumvpn-web-front','foreign_route_state');return v
def save(v):
 require(STATE.parent.is_dir() and not STATE.parent.is_symlink(),'unsafe_route_state_directory')
 temp=STATE.with_name('state.pending');fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'w') as f:json.dump(v,f,sort_keys=True);f.flush();os.fsync(f.fileno())
  os.replace(temp,STATE)
 finally:
  if temp.exists():temp.unlink()
def rules(marker):
 return ('table ip '+TABLE+' {\n chain output {\n type nat hook output priority -90; policy accept;\n '
  'ip daddr 127.0.0.1 tcp dport 8080 socket cgroupv2 level 2 "system.slice/rospanel.service" '
  'counter dnat to 127.0.0.1:18084 comment "'+marker+'"\n }\n}\n')
def main(action):
 require(os.geteuid()==0 and action in ('start','stop'),'fixed_route_action_required')
 manifest=json.loads(read(PRIVATE/'front-manifest.json',16384))
 require(manifest.get('managed_by')=='quantumvpn-web-front' and manifest.get('schema')==1,'foreign_front_manifest')
 marker=manifest.get('marker','');require(len(marker)==32 and all(x in '0123456789abcdef' for x in marker),'invalid_route_marker')
 require(hashlib.sha256(read(Path('/opt/quantumvpn-webproxy/front-route.py'),65536)).hexdigest()==manifest['route_sha256'],'route_helper_identity_changed')
 current=table();saved=state()
 if current is not None:
  require(saved is not None and saved.get('active') is True and saved.get('marker')==marker and fingerprint(current)==saved.get('fingerprint'),'foreign_or_changed_route_table')
 if action=='stop':
  if current is not None:require(run(['nft','delete','table','ip',TABLE])[0]==0,'route_stop_failed')
  save({'schema':1,'managed_by':'quantumvpn-web-front','active':False,'marker':marker});return
 require(Path('/sys/fs/cgroup/system.slice/rospanel.service').is_dir(),'main_cgroup_missing')
 require(run(['systemctl','is-active','rospanel.service'])[0]==0 and run(['systemctl','is-active','quantumvpn-webproxy-front.service'])[0]==0,'front_not_ready')
 value=rules(marker);batch=('delete table ip '+TABLE+'\n' if current is not None else '')+value
 require(run(['nft','--check','--file','-'],batch)[0]==0,'precise_cgroup_route_not_supported')
 require(run(['nft','--file','-'],batch)[0]==0,'route_apply_failed')
 after=table();require(after is not None,'route_not_installed');identity=fingerprint(after)
 try:save({'schema':1,'managed_by':'quantumvpn-web-front','active':True,'marker':marker,'fingerprint':identity})
 except Exception:
  if table() is not None and fingerprint(table())==identity:run(['nft','delete','table','ip',TABLE])
  raise
if __name__=='__main__':
 try:main(sys.argv[1] if len(sys.argv)==2 else '')
 except Exception:raise SystemExit(1)
'''


REMOTE = r"""
import base64,fcntl,hashlib,http.client,json,os,platform,re,shutil,socket,sqlite3,stat,subprocess,sys,tempfile,time,types,urllib.request,uuid
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path('/opt/quantumvpn-webproxy');PRIVATE=Path('/etc/quantumvpn-webproxy');DATA=Path('/var/lib/quantumvpn-operator')
FRONT='quantumvpn-webproxy-front.service';ROUTE='quantumvpn-webproxy-route.service'
TABLE='quantumvpn_web_front';STATE=Path('/var/lib/quantumvpn-webproxy-front')
DROPIN=Path('/etc/systemd/system/rospanel.service.d/60-quantumvpn-webproxy-front.conf')
RELAY_DROPIN=Path('/etc/systemd/system/quantumvpn-webproxy.service.d/60-quantumvpn-webproxy-front.conf')
PROTECTED=(Path('/usr/local/bin/rospanel'),Path('/etc/nginx/nginx.conf'),Path('/var/lib/rospanel/xray/config.json'),Path('/etc/systemd/system/rospanel.service'),Path('/etc/nginx/sites-available/quantumvpn-operator'),Path('/etc/nginx/sites-available/rospanel-admin'),Path('/var/lib/rospanel/secrets.key'),DATA/'routing-ed25519.key',PRIVATE/'config.json',PRIVATE/'profiles.json',PRIVATE/'token.key',PRIVATE/'manifest.json',ROOT/'tproxy-server',ROOT/'quantumvpn_webproxy.py',Path('/etc/systemd/system/quantumvpn-webproxy.service'))
NEW=(ROOT/'front',ROOT/'front.go',ROOT/'front-route.py',PRIVATE/'front.json',PRIVATE/'front-manifest.json',Path('/etc/systemd/system')/FRONT,Path('/etc/systemd/system')/ROUTE,DROPIN,RELAY_DROPIN)
def require(v,e):
 if not v:raise RuntimeError(e)
def sha(b):return hashlib.sha256(b).hexdigest()
def safe_parent(p):
 require(p.is_absolute() and not any(x.is_symlink() for x in p.parents),'unsafe_absolute_parent')
def read(p,n=512*1024*1024):
 safe_parent(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  i=os.fstat(fd);require(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022 and 0<=i.st_size<=n,'unsafe_protected_file')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
  require(len(b)<=n,'protected_file_bound');return b
 finally:os.close(fd)
def exclusive(p,b,mode=0o600):
 safe_parent(p);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 os.chmod(p,mode)
def run(args,timeout=15,input=None,env=None,cwd=None):
 try:p=subprocess.run(args,input=input,capture_output=True,text=True,timeout=timeout,env=env,cwd=cwd)
 except subprocess.TimeoutExpired:raise RuntimeError('bounded_command_timeout') from None
 require(p.returncode==0,'bounded_command_failed');return p.stdout
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def stage(name):print(json.dumps({'status':'Progress','stage':name}),flush=True)
def record(path):
 i=path.stat();return (path,i.st_dev,i.st_ino,stat.S_IMODE(i.st_mode),None if path.is_dir() else sha(read(path)))
def check_created(items,marker):
 for path,device,inode,mode,digest in items:
  require(path.exists() and not path.is_symlink(),'rollback_target_missing_or_symlink_manual_recovery_required')
  i=path.stat();require((i.st_dev,i.st_ino,stat.S_IMODE(i.st_mode),i.st_uid)==(device,inode,mode,0),'rollback_target_identity_changed_manual_recovery_required')
  if digest is not None:require(sha(read(path))==digest,'rollback_target_content_changed_manual_recovery_required')
  else:
   require(path==STATE,'unknown_created_directory')
   children=list(path.iterdir());require(all(p.name=='state.json' for p in children),'unexpected_state_directory_contents')
   for p in children:
    value=json.loads(read(p,4096));require(value.get('schema')==1 and value.get('managed_by')=='quantumvpn-web-front' and value.get('marker')==marker,'rollback_state_identity_changed_manual_recovery_required')
def cache_files(cache,user):
 require(cache.is_dir() and not cache.is_symlink() and cache.stat().st_uid==user.pw_uid and stat.S_IMODE(cache.stat().st_mode)==0o700,'owned_build_cache_required')
 result={};total=0
 for parent,dirs,files in os.walk(cache,followlinks=False):
  for name in dirs+files:
   p=Path(parent)/name;i=p.lstat();require(not stat.S_ISLNK(i.st_mode) and i.st_uid==user.pw_uid and not i.st_mode&0o022,'cache_identity_or_permissions_refused')
   if name in files:
    require(stat.S_ISREG(i.st_mode) and i.st_nlink==1,'cache_file_type_refused');total+=i.st_size
    require(len(result)<60000 and total<900*1024*1024,'bounded_cache_size_required')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
     with os.fdopen(fd,'rb',closefd=False) as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    finally:os.close(fd)
    result[p.relative_to(cache).as_posix()]=digest
 return result
def cache_index(cache,user):
 return canonical({'schema':1,'managed_by':'quantumvpn-front-build','go_version':'go1.27.1','uid':user.pw_uid,'files':cache_files(cache,user)})
def protected():
 files={str(p):sha(read(p)) for p in PROTECTED if p.exists()}
 c=sqlite3.connect('file:/var/lib/rospanel/rospanel.db?mode=ro',uri=True)
 try:
  c.row_factory=sqlite3.Row;s=dict(c.execute('select * from settings where id=1').fetchone())
  for k in ('updated_at','last_config_error','config_revision','blacklist_synced_at','blacklist_error','auto_update_last_at','auto_update_last'):s.pop(k,None)
  rows=[dict(x) for x in c.execute('select * from inbounds order by id')]
  clients=[tuple(x) for x in c.execute('select id,uuid,password,sub_token,enabled,data_limit,expire_at from users order by id')]
  files['main_db_settings_inbounds_clients']=sha(canonical([s,rows,clients]))
 finally:c.close()
 c=sqlite3.connect((DATA/'operator.db').as_uri()+'?mode=ro',uri=True)
 try:
  values={k:v for k,v in c.execute('select key,value from settings') if k.startswith(('release_','scheduled_','staging_','public_')) or k in ('app_version','app_version_code','min_version_code','maintenance','maintenance_message')}
  files['operator_release']=sha(canonical(values))
 finally:c.close()
 return files
def helper():
 manifest=json.loads(read(PRIVATE/'manifest.json',16384));source=read(ROOT/'quantumvpn_webproxy.py',512*1024)
 require(manifest.get('managed_by')=='quantumvpn-webproxy' and sha(source)==manifest.get('helper_sha256'),'relay_identity_required')
 m=types.ModuleType('owned_web_front_probe');m.__file__=str(ROOT/'quantumvpn_webproxy.py');exec(compile(source,m.__file__,'exec'),m.__dict__)
 m._configuration();return m
def inventory():
 require(os.geteuid()==0 and platform.machine()=='x86_64','owned_linux_amd64_root_required')
 for p in NEW:safe_parent(p)
 values=protected();installed=any(p.exists() or p.is_symlink() for p in NEW)
 main=run(['systemctl','show','rospanel.service','--property=ControlGroup','--value']).strip()
 require(main=='/system.slice/rospanel.service','unexpected_main_cgroup')
 require(run(['systemctl','is-active','rospanel.service']).strip()=='active','main_service_required')
 require(Path('/sys/fs/cgroup/system.slice/rospanel.service').is_dir(),'unified_cgroup_required')
 configuration=json.loads(read(Path('/var/lib/rospanel/xray/config.json'),8*1024*1024));v=[x for x in configuration.get('inbounds',[]) if x.get('tag')=='vless-in']
 require(len(v)==1 and v[0].get('listen')=='127.0.0.1' and v[0].get('port')==18443 and v[0].get('settings',{}).get('fallbacks')==[{'dest':'127.0.0.1:8080','xver':1}],'unexpected_vless_fallback')
 return {'status':'ReadOnly','installed':installed,'public_ready':False,'protected_hashes':{str(p):values[str(p)] for p in PROTECTED[:4]},'gateway':'loopback_only','scope':'exact_main_cgroup_fallback_only'},values
def front_unit():
 return '''[Unit]
Description=QuantumVPN owned WEB HTTP gateway preserving client addresses
After=rospanel.service quantumvpn-webproxy.service
Requires=quantumvpn-webproxy.service
BindsTo=rospanel.service quantumvpn-webproxy.service
PartOf=rospanel.service quantumvpn-webproxy.service
Wants=quantumvpn-webproxy-route.service
[Service]
Type=notify
NotifyAccess=main
DynamicUser=yes
LoadCredential=front.json:/etc/quantumvpn-webproxy/front.json
ExecStart=/opt/quantumvpn-webproxy/front
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
TimeoutStartSec=20
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
LimitNOFILE=2048
TasksMax=96
MemoryMax=128M
CPUQuota=50%
Environment=GOMEMLIMIT=96MiB
Environment=GOMAXPROCS=1
StandardOutput=null
StandardError=null
LimitCORE=0
[Install]
WantedBy=multi-user.target
'''
def route_unit():
 return '''[Unit]
Description=QuantumVPN exact RosPanel cgroup WEB fallback route
After=rospanel.service quantumvpn-webproxy-front.service
Requires=quantumvpn-webproxy-front.service
BindsTo=rospanel.service quantumvpn-webproxy-front.service
PartOf=rospanel.service quantumvpn-webproxy-front.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -B /opt/quantumvpn-webproxy/front-route.py start
ExecStop=/usr/bin/python3 -B /opt/quantumvpn-webproxy/front-route.py stop
TimeoutStartSec=20
TimeoutStopSec=20
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/quantumvpn-webproxy-front
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
UMask=0077
MemoryMax=64M
TasksMax=16
StandardOutput=null
StandardError=null
LimitCORE=0
'''
def public_site(h2=False):
 # Never capture an authenticated path, query or cookie. Root/decoy only.
 args=['curl','--silent','--show-error','--max-time','12','--connect-timeout','5','--noproxy','*','--http2' if h2 else '--http1.1','--write-out','\n%{http_code} %{http_version}','https://pecaocek.ignorelist.com/']
 value=run(args,15);body,trailer=value.rsplit('\n',1);code,version=trailer.split()
 require(code=='200' and version==('2' if h2 else '1.1'),'public_http_contract_failed')
 return {'status':int(code),'version':version,'body_sha256':sha(body.encode())}
def main():
 inv,before=inventory()
 if not APPLY:print(json.dumps(inv),flush=True);return
 require(EXPECTED=={str(p):before[str(p)] for p in PROTECTED[:4]},'protected_preflight_hash_changed')
 require(not inv['installed'],'existing_or_partial_front_refused')
 require(not STATE.exists() and not STATE.is_symlink(),'existing_route_state_refused')
 m=helper();proof=m.private_health_probe();require(proof.get('ok') and proof.get('telegram_nonce_confirmed'),'private_relay_nonce_required')
 manifest,_=m._configuration();prefix=manifest['base_path'];require(re.fullmatch('qweb-[a-z0-9]{12,48}',prefix),'managed_prefix_required')
 for port in (18084,):
  try:c=socket.create_connection(('127.0.0.1',port),1)
  except ConnectionRefusedError:continue
  else:c.close();raise RuntimeError('new_gateway_port_occupied')
 runtime=base64.b64decode(ROUTE_B64,validate=True);go=base64.b64decode(GO_B64,validate=True);tests=base64.b64decode(TEST_B64,validate=True)
 require(sha(runtime)==ROUTE_SHA and sha(go)==GO_SHA and sha(tests)==TEST_SHA,'source_identity_failed')
 route=types.ModuleType('front_route_preflight');exec(compile(runtime,'<owned-front-route>','exec'),route.__dict__)
 require(route.table() is None,'foreign_existing_nft_table')
 marker=uuid.uuid4().hex;run(['nft','--check','--file','-'],input=route.rules(marker))
 site_before=public_site();site_h2_before=public_site(True)
 require(site_before['body_sha256']==site_h2_before['body_sha256'],'baseline_http_versions_differ')
 goexe=ROOT/'toolchain/go/bin/go';require(goexe.is_file() and not goexe.is_symlink(),'private_toolchain_required')
 require(run([str(goexe),'version']).strip()=='go version go1.27.1 linux/amd64','private_toolchain_identity_required')
 relay_manifest=json.loads(read(PRIVATE/'manifest.json',16384))
 require(relay_manifest.get('go_archive_sha256')=='63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445','private_toolchain_manifest_identity_required')
 toolchain_parent=ROOT/'toolchain';parent_info=toolchain_parent.stat()
 require(not toolchain_parent.is_symlink() and parent_info.st_uid==0 and stat.S_IMODE(parent_info.st_mode) in (0o700,0o755),'private_toolchain_parent_refused')
 # This directory contains only the public checksum-pinned Go toolchain. Never
 # make /etc credentials, the retained upstream archive or token files public.
 mode_changed=stat.S_IMODE(parent_info.st_mode)==0o700
 if mode_changed:os.chmod(toolchain_parent,0o755)
 staging=Path(tempfile.mkdtemp(prefix='quantumvpn-front-build-',dir='/opt'));os.chmod(staging,0o711)
 staging_info=staging.stat();created=[];started=False;success=False
 try:
  source=staging/'source';source.mkdir(mode=0o755);home=staging/'home';home.mkdir(mode=0o700)
  exclusive(source/'front.go',go,0o644);exclusive(source/'front_test.go',tests,0o644)
  import pwd
  user=pwd.getpwnam('qvpn-webproxy')
  require(user.pw_uid!=0 and user.pw_gid!=0,'unprivileged_build_user_required')
  for p in (source,home,*source.iterdir()):os.chown(p,user.pw_uid,user.pw_gid)
  cache=ROOT/'toolchain/cache';index=ROOT/'toolchain/front-cache-index.json';safe_parent(cache)
  if cache.exists() or cache.is_symlink():require(index.exists() and read(index,8*1024*1024)==cache_index(cache,user),'verified_cache_index_required')
  else:
   require(not index.exists() and not index.is_symlink(),'cache_index_without_cache_refused');cache.mkdir(mode=0o700);os.chown(cache,user.pw_uid,user.pw_gid);exclusive(index,cache_index(cache,user))
  old_index=read(index,8*1024*1024)
  prefix_cmd=['systemd-run','--quiet','--wait','--collect','--pipe','--property=User=qvpn-webproxy','--property=Group=qvpn-webproxy','--property=WorkingDirectory='+str(source),'--property=NoNewPrivileges=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=PrivateDevices=yes','--property=MemoryMax=768M','--property=CPUQuota=100%','--property=TasksMax=128','--property=RuntimeMaxSec=600','--property=ReadWritePaths='+str(source)+' '+str(home)+' '+str(cache),'--setenv=HOME='+str(home),'--setenv=GOCACHE='+str(cache),'--setenv=GOTOOLCHAIN=local','--setenv=GO111MODULE=off','--setenv=GOPROXY=off','--setenv=GOSUMDB=off','--setenv=GOMAXPROCS=1','--setenv=GOMEMLIMIT=512MiB','--setenv=CGO_ENABLED=0','--setenv=GOENV=off','--setenv=GOWORK=off','--setenv=GOTELEMETRY=off','--setenv=GOROOT='+str(ROOT/'toolchain/go'),'--']
  stage('BuildingAndTestingOwnedGateway')
  # Both invocations share an owned cache. Every retained byte is checked against
  # a root-only index before reuse; the daemon cannot write it through its strict
  # filesystem sandbox. No cloud dependency or unverified legacy cache is used.
  try:
   run(prefix_cmd+[str(goexe),'test','-p','1','-timeout','120s'],620)
   stage('NativeHttp1Http2AndClientAddressTestsPassed')
   run(prefix_cmd+[str(goexe),'build','-p','1','-trimpath','-o','front'],620)
  finally:
   require(read(index,8*1024*1024)==old_index,'cache_index_changed_concurrently');pending=index.with_name('front-cache-index.pending');exclusive(pending,cache_index(cache,user));os.replace(pending,index)
  stage('OwnedGatewayBuilt')
  binary=(source/'front').read_bytes();require(binary.startswith(b'\x7fELF') and len(binary)<25*1024*1024,'owned_front_binary_invalid')
  require(before==protected(),'protected_configuration_changed_before_apply')
  require(not any(p.exists() or p.is_symlink() for p in NEW) and not STATE.exists(),'front_targets_changed_before_apply')
  backup=DATA/'web-front-backups'/('front-'+uuid.uuid4().hex);backup.mkdir(parents=True,mode=0o700)
  for n,p in enumerate(PROTECTED):
   if p.exists():exclusive(backup/('protected-'+str(n)),read(p))
  db=sqlite3.connect('file:/var/lib/rospanel/rospanel.db?mode=ro',uri=True);dbbak=sqlite3.connect(backup/'rospanel.db')
  try:db.backup(dbbak)
  finally:db.close();dbbak.close();os.chmod(backup/'rospanel.db',0o600)
  exclusive(backup/'inventory.json',canonical({'protected_hashes':before,'public_root':site_before,'source_sha256':GO_SHA}))
  STATE.mkdir(mode=0o700);created.append(record(STATE))
  for p in (DROPIN,RELAY_DROPIN):
   if not p.parent.exists():p.parent.mkdir(mode=0o755)
  front_manifest={'schema':1,'managed_by':'quantumvpn-web-front','marker':marker,'source_sha256':GO_SHA,'test_sha256':TEST_SHA,'binary_sha256':sha(binary),'route_sha256':ROUTE_SHA,'base_path':manifest['base_path'],'installed_at':int(time.time()),'backup_path':str(backup)}
  files={ROOT/'front':(binary,0o755),ROOT/'front.go':(go,0o644),ROOT/'front-route.py':(runtime,0o644),PRIVATE/'front.json':(canonical({'schema':1,'public_host':'pecaocek.ignorelist.com','base_path':manifest['base_path']}),0o600),PRIVATE/'front-manifest.json':(canonical(front_manifest),0o600),Path('/etc/systemd/system')/FRONT:(front_unit().encode(),0o644),Path('/etc/systemd/system')/ROUTE:(route_unit().encode(),0o644),DROPIN:(b'[Unit]\nWants=quantumvpn-webproxy-front.service\n',0o644),RELAY_DROPIN:(b'[Unit]\nWants=quantumvpn-webproxy-front.service\n',0o644)}
  for p,(data,mode) in files.items():exclusive(p,data,mode);created.append(record(p))
  run(['systemd-analyze','verify',str(Path('/etc/systemd/system')/FRONT),str(Path('/etc/systemd/system')/ROUTE)],20)
  run(['systemctl','daemon-reload']);started=True;stage('StartingLoopbackGatewayAndExactFallbackRoute');run(['systemctl','enable','--now',FRONT],40)
  until=time.monotonic()+20
  while time.monotonic()<until:
   try:c=socket.create_connection(('127.0.0.1',18084),1);c.close();break
   except OSError:time.sleep(0.2)
  else:raise RuntimeError('owned_gateway_not_listening')
  run(['systemctl','start',ROUTE],25)
  require(run(['systemctl','is-active',ROUTE]).strip()=='active','route_not_active')
  site_after=public_site();site_h2_after=public_site(True)
  require(site_after==site_before and site_h2_after==site_h2_before,'public_site_changed_rollback_required')
  stage('VerifyingPublicHttpsCarrierAndUnchangedSite')
  proof=m.health_probe();require(proof.get('ok') and proof.get('tls_confirmed') and proof.get('telegram_nonce_confirmed'),'public_web_nonce_not_confirmed')
  require(before==protected(),'protected_configuration_changed_after_apply')
  success=True;print(json.dumps({'status':'Activated','public_ready':True,'http1_preserved':True,'http2_preserved':True,'protocol_proof':proof,'protected_configuration_unchanged':True,'backup_path':str(backup),'main_restart_required':False}),flush=True)
 except Exception:
  check_created(created,marker)
  if started:
   run(['systemctl','stop',ROUTE],25);run(['systemctl','disable','--now',FRONT],30)
  if created:
   check_created(created,marker)
   recovery=PRIVATE/('front-failed-'+uuid.uuid4().hex);recovery.mkdir(mode=0o700)
   for index,(p,device,inode,mode,digest) in enumerate(reversed(created)):
    os.rename(p,recovery/(str(index)+'-'+p.name))
   run(['systemctl','daemon-reload'])
   print(json.dumps({'status':'RolledBack','private_recovery_path':str(recovery),'main_unchanged':before==protected()}),flush=True)
  raise
 finally:
  target=staging.resolve();current=staging.lstat();require(target==staging and (current.st_dev,current.st_ino)==(staging_info.st_dev,staging_info.st_ino) and target.parent==Path('/opt') and target.name.startswith('quantumvpn-front-build-'),'build_cleanup_target_refused');shutil.rmtree(target)
  if mode_changed and not success:
   current=toolchain_parent.lstat();require((current.st_dev,current.st_ino,current.st_uid,stat.S_IMODE(current.st_mode))==(parent_info.st_dev,parent_info.st_ino,0,0o755),'toolchain_parent_changed_manual_recovery_required');os.chmod(toolchain_parent,0o700)
if RUN_REMOTE:
 try:main()
 except Exception as e:
  print(json.dumps({'status':'Failed','reason':str(e) if isinstance(e,RuntimeError) else 'bounded_front_operation_failed_details_suppressed'}),flush=True);raise SystemExit(1)
"""


def main() -> None:
    import paramiko

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    for name in ('rospanel', 'nginx', 'xray', 'rospanel-unit'):
        parser.add_argument('--expected-' + name + '-sha256', default='')
    options = parser.parse_args()
    expected = {path: getattr(options, field) for path, field in (
        ('/usr/local/bin/rospanel', 'expected_rospanel_sha256'),
        ('/etc/nginx/nginx.conf', 'expected_nginx_sha256'),
        ('/var/lib/rospanel/xray/config.json', 'expected_xray_sha256'),
        ('/etc/systemd/system/rospanel.service', 'expected_rospanel_unit_sha256'))}
    if options.apply:
        import re
        if any(not re.fullmatch('[a-f0-9]{64}', value) for value in expected.values()):
            parser.error('--apply requires all four observed protected SHA-256 hashes')
    password = os.environ.get('QVPN_VDS_PASSWORD')
    if not password:
        raise SystemExit('QVPN_VDS_PASSWORD is required in the environment')
    client = paramiko.SSHClient()
    client.load_host_keys('C:/Users/Admin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    sources = {'GO': GATEWAY_GO, 'TEST': GATEWAY_TEST_GO, 'ROUTE': ROUTE_RUNTIME}
    program = 'APPLY=' + repr(options.apply) + '\nEXPECTED=' + repr(expected) + '\nRUN_REMOTE=True\n'
    for name, source in sources.items():
        value = source.encode()
        program += name + '_B64=' + repr(base64.b64encode(value).decode()) + '\n'
        program += name + '_SHA=' + repr(hashlib.sha256(value).hexdigest()) + '\n'
    program += REMOTE
    try:
        client.connect('150.241.96.191', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
        client.get_transport().set_keepalive(20)
        stdin, stdout, stderr = client.exec_command('python3 -B -', timeout=1500)
        stdin.write(program)
        stdin.channel.shutdown_write()
        for line in stdout:
            print(json.dumps(json.loads(line)), flush=True)
        stderr.read()
        if stdout.channel.recv_exit_status():
            raise SystemExit('WEB front operation failed; raw details suppressed')
    finally:
        client.close()


if __name__ == '__main__':
    main()
