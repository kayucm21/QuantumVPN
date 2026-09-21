#!/usr/bin/env python3
"""Small self-contained QuantumVPN operator panel (stdlib only)."""
import base64, datetime, hashlib, html, json, os, sqlite3, ssl, time, shutil, threading
from urllib.parse import urlsplit, parse_qs
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

ROOT = os.environ.get("QV_DATA_DIR", "/var/lib/quantumvpn-operator")
DB = os.path.join(ROOT, "operator.db")
USER = os.environ["QV_ADMIN_USER"]
PASSWORD = os.environ["QV_ADMIN_PASSWORD"]
UPSTREAM = os.environ["QV_SUBSCRIPTION_UPSTREAM"]
ROSPANEL_DB = os.environ.get("QV_ROSPANEL_DB", "/var/lib/rospanel/rospanel.db")

VERSION = "5.6.16"
VERSION_CODE = 97
DOWNLOAD_ROOT = os.environ.get("QV_DOWNLOAD_ROOT", "/var/www/quantumvpn/downloads")
PUBLIC_BASE = "https://tepacom.o190.com:8443"
_DB_INIT_LOCK = threading.Lock()
_DB_READY = False
_LAST_EVENT_CLEANUP = 0

@lru_cache(maxsize=8)
def release_info(abi, size, mtime):
    name = f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk"
    digest = hashlib.sha256()
    with open(os.path.join(DOWNLOAD_ROOT, VERSION, name), "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"version": VERSION, "version_code": VERSION_CODE, "url": f"{PUBLIC_BASE}/downloads/{VERSION}/{name}", "sha256": digest.hexdigest(), "size": size, "note": "Aurora 2026: оценка качества серверов, центр состояния, история и приватность, защита публичного Wi-Fi, управляемый выпуск и расписание техработ."}

def conn():
    global _DB_READY, _LAST_EVENT_CLEANUP
    os.makedirs(ROOT, exist_ok=True)
    db = sqlite3.connect(DB)
    now = int(time.time())
    with _DB_INIT_LOCK:
        if not _DB_READY:
            db.execute("create table if not exists settings (key text primary key, value text not null)")
            db.execute("create table if not exists events (ts integer, kind text, device text, ip text, detail text)")
            db.execute("create table if not exists protocols (name text primary key, enabled integer not null default 1)")
            defaults = {
                "maintenance":"0",
                "maintenance_message":"Ведутся технические работы. После завершения работ мы возобновим сервис.",
                "maintenance_schedule_enabled":"0",
                "maintenance_start":"0",
                "maintenance_end":"0",
                "announce":"",
                "subscription_main_enabled":"1",
                "update_notifications_enabled":"1",
                "rollout_percent":"100",
                "feature_vpn_connect":"1",
                "feature_adblock":"1",
                "feature_auto_connect":"1",
                "feature_auto_failover":"1",
                "config_revision":"1",
            }
            for key, value in defaults.items():
                db.execute("insert or ignore into settings values (?,?)", (key,value))
            db.execute(
                "update settings set value=? where key='maintenance_message' and value=?",
                ("Ведутся технические работы. После завершения работ мы возобновим сервис.", "Технические работы. Извините за неудобства."),
            )
            _DB_READY = True
        if now - _LAST_EVENT_CLEANUP >= 3600:
            db.execute("delete from events where ts < ?", (now - 14*86400,))
            _LAST_EVENT_CLEANUP = now
        db.commit()
    return db

def settings(db): return dict(db.execute("select key,value from settings"))
def enabled(s, key, default=True): return s.get(key, "1" if default else "0") == "1"
def effective_maintenance(s, now=None):
    now = int(time.time()) if now is None else int(now)
    manual = enabled(s, "maintenance", False)
    scheduled = enabled(s, "maintenance_schedule_enabled", False)
    start = int(s.get("maintenance_start", "0") or 0)
    end = int(s.get("maintenance_end", "0") or 0)
    return manual or (scheduled and start > 0 and end > start and start <= now < end)
def datetime_value(raw):
    try:
        epoch = int(raw or 0)
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M") if epoch > 0 else ""
    except Exception:
        return ""
def parse_datetime_value(raw):
    value = (raw or "").strip()
    if not value: return 0
    return int(datetime.datetime.fromisoformat(value).timestamp())
def client_bucket(raw):
    try: return max(0, min(99, int(raw)))
    except Exception: return None
def auth(header):
    try:
        return base64.b64decode(header.split()[1]).decode() == f"{USER}:{PASSWORD}"
    except Exception: return False
def device_id(raw): return hashlib.sha256(raw.encode()).hexdigest()[:16] if raw else "anonymous"
def subscription_lines():
    with urlopen(Request(UPSTREAM,headers={"User-Agent":"QuantumVPN-API"}),timeout=15) as r: raw=r.read(4*1024*1024)
    text=raw.decode("utf-8","replace").strip()
    if "://" not in text:
        try: text=base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8","replace")
        except Exception: pass
    return [x.strip() for x in text.splitlines() if "://" in x]
def protocol(line): return line.split("://",1)[0].lower()
def rospanel_users():
    """Read RosPanel status only; subscriber changes stay in RosPanel itself."""
    try:
        db = sqlite3.connect(f"file:{ROSPANEL_DB}?mode=ro", uri=True, timeout=2)
        rows = db.execute("select name,enabled,status,used_up,used_down,expire_at,last_seen from users order by name limit 200").fetchall()
        db.close()
        return rows
    except Exception:
        return []

def render_panel(s, rows, users, protocols):
    checked=lambda key: "checked" if s.get(key)=="1" else ""
    events="".join(f"<tr><td>{time.strftime('%d.%m %H:%M',time.localtime(x[0]))}</td><td>{html.escape(x[1])}</td><td>{html.escape(x[2])}</td><td>{html.escape(x[3])}</td><td>{html.escape(x[4][:500])}</td></tr>" for x in rows) or "<tr><td colspan=4>Событий пока нет</td></tr>"
    subscribers="".join(f"<tr><td>{html.escape(str(name))}</td><td class={'ok' if enabled else 'off'}>{'активен' if enabled else 'отключён'}</td><td>{html.escape(str(status or '—'))}</td><td>{((up or 0)+(down or 0))/1024/1024:.1f} MB</td><td>{'—' if not expires else time.strftime('%d.%m.%Y',time.localtime(expires))}</td></tr>" for name,enabled,status,up,down,expires,last in users) or "<tr><td colspan=5>RosPanel недоступен</td></tr>"
    toggles="".join(f"<label><input type=checkbox name=p_{html.escape(name)} {'checked' if enabled else ''}> {html.escape(name.upper())}</label>" for name,enabled in protocols) or "<p class=muted>Протоколы появятся после синхронизации.</p>"
    rollout = max(1, min(100, int(s.get("rollout_percent", "100") or 100)))
    maintenance_now = effective_maintenance(s)
    return f'''<!doctype html><html lang=ru><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Quantum Control</title><style>
    :root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 10% 0,#103b47,#050b16 55%);color:#eaf7ff;font:15px system-ui}}main{{max-width:1220px;margin:auto;padding:28px 18px 64px}}.hero,.card{{background:#0a192ae8;border:1px solid #21546a;border-radius:22px;padding:22px;margin:16px 0;box-shadow:0 16px 40px #0004}}.hero{{background:linear-gradient(135deg,#0d3140,#091222)}}h1{{margin:5px 0;font-size:32px}}h2{{margin:0 0 14px}}.accent,.ok{{color:#38efab}}.off{{color:#ff9aa7}}.muted{{color:#9ab0bf}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}}.grid .card{{margin:0}}label{{display:block;margin:12px 0}}textarea,input{{width:100%;background:#07121f;color:#eaf7ff;border:1px solid #285368;border-radius:10px;padding:10px}}input[type=checkbox]{{width:auto;accent-color:#38efab}}button,a.button{{display:inline-block;background:linear-gradient(135deg,#31dda0,#3298ef);color:#041019;border:0;border-radius:11px;padding:11px 14px;font-weight:800;text-decoration:none;cursor:pointer}}.actions{{display:flex;gap:10px;flex-wrap:wrap}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:10px 6px;border-bottom:1px solid #1d3546;text-align:left}}@media(max-width:600px){{main{{padding:18px 12px}}h1{{font-size:26px}}table{{font-size:11px}}}}</style><main>
    <section class=hero><div class=accent>QUANTUM CONTROL · ROSPANEL</div><h1>Управление приложением</h1><p class=muted>Политики, подписка, протоколы, версии APK, журналы и статус пользователей.</p></section>
    <section class=grid><form class=card method=post action=/operator/policy><input type=hidden name=section value=service><h2>Сервис</h2><p class={'off' if maintenance_now else 'ok'}>{'Сейчас идут технические работы' if maintenance_now else 'Сервис работает'}</p><label><input type=checkbox name=maintenance {checked('maintenance')}> Включить работы немедленно</label><label><input type=checkbox name=maintenance_schedule_enabled {checked('maintenance_schedule_enabled')}> Использовать расписание</label><label>Начало (время VDS)<input type=datetime-local name=maintenance_start value='{datetime_value(s.get('maintenance_start'))}'></label><label>Окончание (время VDS)<input type=datetime-local name=maintenance_end value='{datetime_value(s.get('maintenance_end'))}'></label><label>Сообщение<textarea name=maintenance_message id=maintenance-text>{html.escape(s.get('maintenance_message',''))}</textarea></label><p class=muted>Предпросмотр:</p><div id=maintenance-preview class=card></div><label><input type=checkbox checked disabled> Оповещать всех о новых версиях (всегда включено)</label><label>Объявление<textarea name=announce>{html.escape(s.get('announce',''))}</textarea></label><button>Сохранить</button></form><form class=card method=post action=/operator/policy><input type=hidden name=section value=subscription><h2>Встроенная подписка</h2><p class=ok>Подключена к RosPanel</p><label><input type=checkbox name=subscription_main_enabled {checked('subscription_main_enabled')}> Выдавать конфигурацию приложению</label><button>Применить</button></form><form class=card method=post action=/operator/protocols><h2>Протоколы</h2>{toggles}<button>Сохранить</button></form></section>
    <section class=grid><form class=card method=post action=/operator/policy><input type=hidden name=section value=release><h2>Выпуск APK {VERSION}</h2><label>Получатели обновления: <strong>{rollout}%</strong><input type=range min=1 max=100 name=rollout_percent value={rollout} oninput="this.previousElementSibling.textContent=this.value+'%'"></label><p class=muted>Устройства распределяются стабильно. Увеличивайте 10% → 50% → 100% после проверки.</p><button>Сохранить выпуск</button><div class=actions style='margin-top:14px'><a class=button href='/downloads/{VERSION}/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk'>ARM64</a><a class=button href='/downloads/{VERSION}/QuantumVPN-{VERSION}-operator-debug-armeabi-v7a.apk'>ARMv7</a></div></form><form class=card method=post action=/operator/policy><input type=hidden name=section value=features><h2>Безопасные удалённые настройки</h2><p class=muted>Меняют только заранее встроенные функции. Исполняемый код удалённо не загружается.</p><label><input type=checkbox name=feature_vpn_connect {checked('feature_vpn_connect')}> Подключение VPN</label><label><input type=checkbox name=feature_adblock {checked('feature_adblock')}> DNS-фильтрация</label><label><input type=checkbox name=feature_auto_connect {checked('feature_auto_connect')}> Автозащита сети</label><label><input type=checkbox name=feature_auto_failover {checked('feature_auto_failover')}> Автосмена сервера</label><p class=muted>Ревизия конфигурации: {html.escape(s.get('config_revision','1'))}</p><button>Применить конфигурацию</button></form><section class=card><h2>Добровольная диагностика</h2><p class=muted>Логи поступают только после согласия пользователя.</p><a class=button href=/operator/logs.txt>Скачать TXT-логи</a></section></section>
    <section class=card><h2>Пользователи RosPanel</h2><p class=muted>Управление тарифами и пользователями остаётся в защищённой RosPanel.</p><table><tr><th>Пользователь</th><th>Доступ</th><th>Статус</th><th>Трафик</th><th>Срок</th></tr>{subscribers}</table></section><section class=card><h2>События приложения</h2><table><tr><th>Время</th><th>Событие</th><th>Устройство</th><th>IP</th><th>Изменения</th></tr>{events}</table></section><section class=card><h2>Статус API</h2><a class=button href=/operator/health>Проверить доступность</a><p class=muted>Доступность VPN-сервера проверяется пингом в приложении.</p></section></main><script>const input=document.getElementById('maintenance-text');const preview=document.getElementById('maintenance-preview');function showPreview(){{preview.textContent=input.value;}}input.addEventListener('input',showPreview);showPreview();</script></html>'''

class App(BaseHTTPRequestHandler):
    server_version = "QuantumVPN-Operator"
    def connection_db(self):
        db = conn()
        if not hasattr(self, "_dbs"): self._dbs = []
        self._dbs.append(db)
        return db
    def finish(self):
        try:
            super().finish()
        finally:
            for db in getattr(self, "_dbs", []): db.close()
    def log_message(self, *_): pass
    def reply(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode(); self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def admin(self):
        if auth(self.headers.get("Authorization", "")): return True
        self.send_response(401); self.send_header("WWW-Authenticate",'Basic realm="QuantumVPN Operator"'); self.end_headers(); return False
    def client(self):
        ip = self.client_address[0]
        dev = device_id(self.headers.get("x-hwid", ""))
        return dev, ip
    def do_GET(self):
        db=self.connection_db(); s=settings(db)
        path = urlsplit(self.path).path
        if path == "/api/app/version":
            abi = parse_qs(urlsplit(self.path).query).get("abi", ["arm64-v8a"])[0]
            if abi not in ("arm64-v8a", "armeabi-v7a"): return self.reply(404, '{"error":"unsupported_abi"}')
            file = os.path.join(DOWNLOAD_ROOT, VERSION, f"QuantumVPN-{VERSION}-operator-debug-{abi}.apk")
            if not os.path.isfile(file): return self.reply(503, '{"error":"release_not_ready"}')
            stat = os.stat(file)
            info = dict(release_info(abi, stat.st_size, stat.st_mtime_ns))
            query = parse_qs(urlsplit(self.path).query)
            bucket = client_bucket(query.get("bucket", [None])[0])
            rollout = max(1, min(100, int(s.get("rollout_percent", "100") or 100)))
            eligible = bucket is None or bucket < rollout
            if not eligible:
                info["version"] = query.get("current_version", [VERSION])[0][:32] or VERSION
                try: info["version_code"] = max(1, int(query.get("current_version_code", [VERSION_CODE])[0]))
                except Exception: info["version_code"] = VERSION_CODE
                info["note"] = f"Постепенный выпуск {rollout}%: устройство пока остаётся на текущей версии."
            info["rollout_percent"] = rollout
            info["rollout_eligible"] = eligible
            return self.reply(200, json.dumps(info))
        if path.startswith("/downloads/"): return self.download_file(path)
        if path == "/operator/health":
            if not self.admin(): return
            status = {"operator_api": "ok", "release": VERSION, "visible_users": len(rospanel_users())}
            try:
                url = urlsplit(UPSTREAM)
                started = time.monotonic()
                with urlopen(f"{url.scheme}://{url.netloc}/", timeout=5) as response:
                    status["upstream_http"] = response.status
                status["latency_ms"] = round((time.monotonic()-started)*1000)
            except Exception:
                status["upstream"] = "probe_failed"
            return self.reply(200, json.dumps(status))
        if self.path.startswith("/api/client/policy"):
            dev,ip=self.client(); now=int(time.time())
            last=db.execute("select max(ts) from events where kind='policy' and device=?",(dev,)).fetchone()[0] or 0
            if now-last >= 600:
                db.execute("insert into events values (?,?,?,?,?)",(now,"policy",dev,ip,self.headers.get("x-device-model","Android")[:120])); db.commit()
            maintenance = effective_maintenance(s, now)
            result={"platform":"android","maintenance":maintenance,"maintenance_message":s["maintenance_message"],"maintenance_start":int(s.get("maintenance_start","0") or 0),"maintenance_end":int(s.get("maintenance_end","0") or 0),"announce":s["announce"],"latest_version":VERSION,"version_code":VERSION_CODE,"update_url":f"{PUBLIC_BASE}/downloads/{VERSION}/QuantumVPN-{VERSION}-operator-debug-arm64-v8a.apk","update_notifications":True,"config_revision":int(s.get("config_revision","1") or 1),"features":{"vpn_connect":enabled(s,"feature_vpn_connect") and not maintenance,"import_json":False,"adblock":enabled(s,"feature_adblock"),"auto_connect":enabled(s,"feature_auto_connect"),"auto_failover":enabled(s,"feature_auto_failover")}}
            return self.reply(200,json.dumps(result))
        if self.path == "/api/v1/subscription":
            if s["subscription_main_enabled"] != "1": return self.reply(503,"Subscription temporarily unavailable","text/plain; charset=utf-8")
            try:
                # RosPanel may bind the subscription to x-hwid. Redirecting keeps
                # the Android client's legitimate device headers intact instead of
                # fetching the protected subscription server-side.
                self.send_response(307); self.send_header("Location", UPSTREAM); self.send_header("Cache-Control", "no-store"); self.end_headers()
            except Exception: self.reply(502,"Subscription upstream unavailable","text/plain; charset=utf-8")
            return
        if self.path == "/operator":
            if not self.admin(): return
            rows=db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 100").fetchall()
            protocols=db.execute("select name,enabled from protocols order by name").fetchall()
            return self.reply(200,render_panel(s, rows, rospanel_users(), protocols),"text/html; charset=utf-8")
        if self.path == "/operator/logs.txt":
            if not self.admin(): return
            rows=db.execute("select ts,kind,device,ip,detail from events order by ts desc limit 500").fetchall()
            body="\n\n".join(f"[{time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(ts))}] {kind}\nDevice: {device}\nIP: {ip}\n{detail}" for ts,kind,device,ip,detail in rows)
            return self.reply(200,body or "No logs", "text/plain; charset=utf-8")
        self.reply(404,"Not found","text/plain")
    def download_file(self, path, head=False):
        root = os.path.realpath(DOWNLOAD_ROOT) + os.sep
        target = os.path.realpath(os.path.join(DOWNLOAD_ROOT, path.removeprefix("/downloads/")))
        if not target.startswith(root) or not os.path.isfile(target): return self.reply(404, "Not found", "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Content-Length", str(os.path.getsize(target)))
        self.send_header("Content-Disposition", "attachment")
        self.end_headers()
        if not head:
            with open(target, "rb") as source: shutil.copyfileobj(source, self.wfile, 64 * 1024)
    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path.startswith("/downloads/"): return self.download_file(path, True)
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path == "/api/client/diagnostic":
            try:
                size=min(int(self.headers.get("Content-Length","0")), 16_384)
                raw=self.rfile.read(size).decode("utf-8")
                payload=json.loads(raw)
                if payload.get("consent") is not True: return self.reply(400,'{"error":"consent_required"}')
                dev,ip=self.client(); detail=("last_error="+str(payload.get("last_error", ""))+"\\n"+str(payload.get("logs", "")))[:12_500]
                db=self.connection_db(); db.execute("insert into events values (?,?,?,?,?)",(int(time.time()),"voluntary_diagnostic",dev,ip,detail)); db.commit()
                return self.reply(201,'{"ok":true}')
            except Exception: return self.reply(400,'{"error":"invalid_report"}')
        if self.path.startswith("/operator/") and self.headers.get("Origin") not in (None, PUBLIC_BASE): return self.reply(403, "Invalid origin")
        if self.path == "/operator/protocols":
            if not self.admin(): return
            raw=self.rfile.read(int(self.headers.get("Content-Length","0"))).decode(); from urllib.parse import parse_qs; form=parse_qs(raw); db=self.connection_db()
            for name,_ in db.execute("select name,enabled from protocols"):
                db.execute("update protocols set enabled=? where name=?",(1 if "p_"+name in form else 0,name))
            db.commit(); self.send_response(303); self.send_header("Location","/operator"); self.end_headers(); return
        if self.path != "/operator/policy" or not self.admin(): return
        raw=self.rfile.read(int(self.headers.get("Content-Length","0"))).decode(); from urllib.parse import parse_qs; form=parse_qs(raw)
        db=self.connection_db(); current=settings(db)
        section = form.get("section", [""])[0]
        if section == "service":
            try:
                start = parse_datetime_value(form.get("maintenance_start", [""])[0])
                end = parse_datetime_value(form.get("maintenance_end", [""])[0])
            except Exception:
                return self.reply(400, '{"error":"invalid_maintenance_time"}')
            if "maintenance_schedule_enabled" in form and (start <= 0 or end <= start):
                return self.reply(400, '{"error":"maintenance_end_must_follow_start"}')
            values={"maintenance":"1" if "maintenance" in form else "0", "maintenance_schedule_enabled":"1" if "maintenance_schedule_enabled" in form else "0", "maintenance_start":str(start), "maintenance_end":str(end), "maintenance_message":form.get("maintenance_message", [""])[0][:400], "announce":form.get("announce", [""])[0][:400]}
        elif section == "subscription":
            values={"subscription_main_enabled":"1" if "subscription_main_enabled" in form else "0"}
        elif section == "release":
            try: rollout = max(1, min(100, int(form.get("rollout_percent", ["100"])[0])))
            except Exception: return self.reply(400, '{"error":"invalid_rollout"}')
            values={"rollout_percent":str(rollout)}
        elif section == "features":
            values={key:"1" if key in form else "0" for key in ("feature_vpn_connect","feature_adblock","feature_auto_connect","feature_auto_failover")}
        else: return self.reply(400, '{"error":"unknown_section"}')
        if section in ("service", "features") and any(current.get(k) != v for k,v in values.items()):
            values["config_revision"] = str(int(current.get("config_revision", "1") or 1) + 1)
        changes = {k: {"before": current.get(k), "after": v} for k,v in values.items() if current.get(k) != v}
        for k,v in values.items(): db.execute("insert or replace into settings values (?,?)",(k,v))
        db.execute("insert into events values (?,?,?,?,?)",(int(time.time()),"admin",USER,self.client_address[0],json.dumps(changes, ensure_ascii=False))); db.commit(); self.send_response(303); self.send_header("Location","/operator"); self.end_headers()

if __name__ == "__main__":
    port = int(os.environ.get("QV_PORT", "8765"))
    server = ThreadingHTTPServer(("0.0.0.0", port), App)
    cert, key = os.environ.get("QV_TLS_CERT"), os.environ.get("QV_TLS_KEY")
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
