#!/usr/bin/env python3
"""Measured, credential-free VDS console, embedded or served behind TLS.

The console reads the local node only. Its diagnostics connect only to loopback
ports admitted by the local Xray config; no request supplies a command, address,
configuration path, service name or credentials. It never changes firewall,
ports or live VPN configuration. A config entry is not proof of external access.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_PORTS = 48
PROTOCOLS = frozenset({"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "dokodemo-door", "wireguard", "hysteria", "hysteria2", "tuic"})
TRANSPORTS = frozenset({"tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "h2", "quic", "kcp", "hysteria"})
SECURITY = frozenset({"none", "tls", "reality"})
_LOCK = threading.Lock()
_SAMPLE = None
_CACHE = None
_CACHE_AT = 0.0


def _number(value, maximum=10**18):
    return value if type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value) else None


def _read(path, limit=65536):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(limit + 1)
        return raw.decode("utf-8") if len(raw) <= limit else ""
    except (OSError, UnicodeError):
        return ""


def _command(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=False)
        return result.stdout[:65536].decode("utf-8", "replace") if result.returncode == 0 and len(result.stdout) <= 65536 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def configured_ports(path=None):
    """Only enums, integers and listener scope survive the private config."""
    path = path or os.environ.get("QV_NODE_XRAY_CONFIG", "/var/lib/rospanel/xray/config.json")
    try:
        config = json.loads(_read(path, MAX_CONFIG_BYTES))
    except (ValueError, TypeError):
        return {"available": False, "ports": [], "truncated": False}
    inbounds = config.get("inbounds") if isinstance(config, dict) else None
    if not isinstance(inbounds, list):
        return {"available": False, "ports": [], "truncated": False}
    ports = []
    for inbound in inbounds[:MAX_PORTS]:
        if not isinstance(inbound, dict) or not isinstance(inbound.get("protocol"), str) or inbound["protocol"] not in PROTOCOLS:
            continue
        port = inbound.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            continue
        stream = inbound.get("streamSettings")
        stream = stream if isinstance(stream, dict) else {}
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")
        listen = inbound.get("listen", "0.0.0.0")
        try:
            address = ipaddress.ip_address(listen)
            scope = "loopback" if address.is_loopback else "network"
            probe_host = "::1" if address.version == 6 else "127.0.0.1"
            probe_allowed = address.is_unspecified or address.is_loopback
        except (ValueError, TypeError):
            scope, probe_host, probe_allowed = "unknown", "127.0.0.1", False
        ports.append({"protocol": inbound["protocol"], "port": port,
                      "transport": network if isinstance(network, str) and network in TRANSPORTS else "unknown",
                      "security": security if isinstance(security, str) and security in SECURITY else "unknown",
                      "scope": scope, "probe_host": probe_host, "probe_allowed": probe_allowed,
                      "tcp_expected": isinstance(network, str) and network not in {"quic", "kcp"} and inbound["protocol"] not in {"wireguard", "hysteria", "hysteria2", "tuic"}})
    return {"available": True, "ports": ports, "truncated": len(inbounds) > MAX_PORTS}


def listening_ports(raw):
    """Parse ss -H -lntu, dropping peer/local addresses and process strings."""
    rows = {}
    for line in raw.splitlines()[:4096]:
        parts = line.split()
        if len(parts) < 5 or parts[0] not in {"tcp", "udp"}:
            continue
        local = parts[4]
        host, _, port = local.rpartition(":")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            continue
        host = host.strip("[]")
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False if host == "*" else None
        key = (parts[0], int(port))
        row = rows.setdefault(key, {"network": parts[0], "port": int(port), "network_listener": False})
        if loopback is False:
            row["network_listener"] = True
    return sorted(rows.values(), key=lambda row: (row["port"], row["network"]))[:128]


def traffic_counters(raw):
    receive = transmit = interfaces = 0
    for line in raw.splitlines()[:128]:
        name, sep, fields = line.partition(":")
        if not sep or name.strip() == "lo":
            continue
        values = fields.split()
        if len(values) >= 16 and values[0].isdigit() and values[8].isdigit():
            receive += int(values[0])
            transmit += int(values[8])
            interfaces += 1
    return {"rx_bytes": receive, "tx_bytes": transmit, "interfaces": interfaces} if interfaces else None


def traffic_rate(previous, current, elapsed):
    if not previous or not current or not 0.5 <= elapsed <= 120 or previous["interfaces"] != current["interfaces"]:
        return {"rx_mbps": None, "tx_mbps": None}
    result = {}
    for key, source in (("rx_mbps", "rx_bytes"), ("tx_mbps", "tx_bytes")):
        delta = current[source] - previous[source]
        result[key] = round(delta * 8 / elapsed / 1_000_000, 2) if 0 <= delta <= 10**15 else None
    return result


def qdisc_summary(raw):
    try:
        rows = json.loads(raw)
    except (TypeError, ValueError):
        return {"available": False, "kinds": [], "rate_caps_bps": []}
    if not isinstance(rows, list):
        return {"available": False, "kinds": [], "rate_caps_bps": []}
    kinds, caps, complete = set(), set(), len(rows) <= 128
    for row in rows[:128]:
        if not isinstance(row, dict):
            continue
        kind = row.get("kind")
        if isinstance(kind, str) and kind in {"fq", "fq_codel", "cake", "tbf", "htb", "hfsc", "netem", "pfifo", "pfifo_fast", "mq", "noqueue", "clsact", "ingress"}:
            kinds.add(kind)
        else:
            complete = False
        # HFSC has service curves, not one numeric upper rate. Do not claim
        # that an unsupported curve or unknown kind excludes shaping.
        if kind == "hfsc":
            complete = False
        options = row.get("options") if isinstance(row.get("options"), dict) else {}
        names = ("ceil",) if kind == "htb" else ("bandwidth",) if kind == "cake" else ("rate",) if kind in ("tbf", "netem") else ()
        for name in names:
            value = _number(options.get(name), 10**12)
            if value is not None and value > 0:
                # iproute2 lib/json_print.c print_color_rate: JSON uses bytes/s.
                # HTB's rate is a guarantee; ceil is its upper bound.
                caps.add(round(value * 8))
            elif name in options and value is None:
                complete = False
    return {"available": complete, "kinds": sorted(kinds), "rate_caps_bps": sorted(caps)}


def snapshot(*, probe=False):
    """Collect local evidence. Missing/denied sources stay unknown."""
    global _SAMPLE
    now, monotonic = int(time.time()), time.monotonic()
    counts = traffic_counters(_read("/proc/net/dev"))
    with _LOCK:
        previous = _SAMPLE
        rate = traffic_rate(previous[1], counts, monotonic - previous[0]) if previous else {"rx_mbps": None, "tx_mbps": None}
        if counts:
            _SAMPLE = (monotonic, counts)
    memory = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        token = value.strip().split(" ")[0]
        if token.isdigit():
            memory[key] = int(token)
    total, available = memory.get("MemTotal"), memory.get("MemAvailable")
    memory_pct = round((total - available) / total * 100, 1) if total and available is not None and 0 <= available <= total else None
    load = _read("/proc/loadavg").split()
    try:
        load_pct = round(float(load[0]) / max(1, os.cpu_count() or 1) * 100, 1)
    except (ValueError, IndexError):
        load_pct = None
    try:
        disk = shutil.disk_usage("/")
        disk_pct = round(disk.used / disk.total * 100, 1) if disk.total else None
    except OSError:
        disk_pct = None
    raw_listeners = _command(["ss", "-H", "-lntu"])
    listeners = listening_ports(raw_listeners)
    configured = configured_ports()
    reserve = configured_ports(os.environ.get("QV_NODE_RESERVE_CONFIG", "/etc/quantumvpn-reserve/xray.json"))
    configured["available"] = configured["available"] or reserve["available"]
    configured["ports"] = (configured["ports"] + reserve["ports"])[:MAX_PORTS]
    configured["truncated"] = configured["truncated"] or reserve["truncated"]
    ports = []
    for row in configured["ports"]:
        family = "tcp" if row["tcp_expected"] else "udp"
        matches = [item for item in listeners if item["port"] == row["port"] and item["network"] == family]
        public = {key: row[key] for key in ("protocol", "port", "transport", "security", "scope")}
        public.update(network=family, listening=bool(matches) if raw_listeners else None,
                      network_listener=any(item["network_listener"] for item in matches) if raw_listeners else None,
                      loopback_probe=None, latency_ms=None)
        if probe and row["tcp_expected"] and row["probe_allowed"]:
            started = time.monotonic()
            try:
                with socket.create_connection((row["probe_host"], row["port"]), timeout=0.15):
                    public.update(loopback_probe=True, latency_ms=round((time.monotonic() - started) * 1000, 1))
            except OSError:
                public["loopback_probe"] = False
        ports.append(public)
    algorithm = _read("/proc/sys/net/ipv4/tcp_congestion_control", 128).strip()
    algorithm = algorithm if algorithm in {"bbr", "bbr2", "bbr3", "cubic", "reno", "vegas", "westwood", "htcp", "dctcp"} else "unknown"
    qdisc = qdisc_summary(_command(["tc", "-j", "qdisc", "show"]))
    classes = qdisc_summary(_command(["tc", "-j", "class", "show"]))
    qdisc["available"] = qdisc["available"] and classes["available"]
    qdisc["rate_caps_bps"] = sorted(set(qdisc["rate_caps_bps"] + classes["rate_caps_bps"]))
    try:
        address = ipaddress.ip_address(os.environ.get("QV_NODE_PUBLIC_ADDRESS", ""))
        public_address = str(address) if address.is_global else None
    except ValueError:
        public_address = None
    findings = []
    if qdisc["rate_caps_bps"]:
        findings.append("rate_limit_observed")
    if any(row["listening"] is False for row in ports):
        findings.append("configured_port_not_listening")
    if probe and any(row["loopback_probe"] is False for row in ports):
        findings.append("local_tcp_failed")
    if not configured["available"]:
        findings.append("xray_config_unavailable")
    return {"schema": 1, "generated_at": now, "scope": "local_server", "public_address": public_address,
            "resources": {"load_1m_pct": load_pct, "memory_used_pct": memory_pct, "disk_used_pct": disk_pct},
            "traffic": {**rate, "sample_scope": "all_non_loopback_interfaces", "vpn_throughput_measured": False},
            "tcp": {"congestion_control": algorithm, "qdisc": qdisc},
            "config_available": configured["available"], "ports_truncated": configured["truncated"], "ports": ports,
            "listeners_available": bool(raw_listeners), "listener_count": len(listeners) if raw_listeners else None,
            "diagnostic": {"probed": probe, "findings": findings, "external_reachability": "not_measured"}}


def cached_snapshot():
    global _CACHE, _CACHE_AT
    with _LOCK:
        cached, age = _CACHE, time.monotonic() - _CACHE_AT
    if cached is not None and age < 5:
        return cached
    value = snapshot()
    with _LOCK:
        _CACHE, _CACHE_AT = value, time.monotonic()
    return value


def render(value, *, csrf="", api_base="/operator/server", embedded=False, can_probe=True):
    """HTML is static code; all live data is serialized safely and displayed as text."""
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c").replace("&", "\\u0026")
    probe = '<button id=node-diagnose>Проверить порты</button>' if can_probe else ''
    management = '<a href="/operator?tab=service">Управление протоколами →</a><a href="/operator?tab=network">Маршруты и ИИ →</a>' if embedded else ''
    return '''<!doctype html><html lang=ru><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=referrer content=same-origin><title>Quantum Node · управление VDS</title>
<style>
:root{color-scheme:light;--navy:#0c1c34;--ink:#162a45;--muted:#6a7d94;--blue:#2769ea;--line:#dfe7f1}*{box-sizing:border-box}body{margin:0;background:#f3f6fb;color:var(--ink);font:15px/1.6 system-ui,sans-serif}button,a{font:inherit}a{color:var(--blue);text-decoration:none}button{border:0;border-radius:11px;background:var(--blue);color:white;padding:10px 16px;cursor:pointer;font-weight:600}button:disabled{opacity:.55;cursor:wait}button:focus-visible,a:focus-visible{outline:3px solid #86b4ff;outline-offset:3px}.shell{max-width:1330px;margin:auto;padding:32px}.top{display:flex;justify-content:space-between;align-items:center;gap:20px}.brand{font-size:20px;font-weight:800;letter-spacing:-.7px}.brand small{font-size:11px;letter-spacing:2px;margin-left:12px;color:var(--muted)}.top nav{display:flex;gap:20px;flex-wrap:wrap}.hero{background:var(--navy);border-radius:24px;color:#eef5ff;padding:32px;margin:28px 0 22px;display:grid;grid-template-columns:1.4fr 1fr;gap:30px;background-image:radial-gradient(ellipse at 95% 0,#214c85,transparent 60%)}.eyebrow{font-size:11px;letter-spacing:2px;color:#82afff;text-transform:uppercase}.hero h1{font-size:34px;line-height:1.15;letter-spacing:-1px;margin:12px 0}.hero p{color:#a7bad2;max-width:650px}.node-id{overflow-wrap:anywhere;font:22px ui-monospace,monospace;margin:10px 0 20px}.hero-actions{display:flex;gap:10px;flex-wrap:wrap}.hero-actions .secondary{background:#233c5b}.hero-aside{border-left:1px solid #344b68;padding-left:28px;display:flex;justify-content:center;flex-direction:column}.hero-aside strong{font-size:18px}.status-dot{display:inline-block;border-radius:50%;width:8px;height:8px;background:#6fc7b7;margin-right:9px}.subtle{font-size:12px;color:var(--muted)}.hero .subtle{color:#a7bad2}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.card{min-width:0;background:white;border:1px solid var(--line);border-radius:17px;padding:22px}.metric .value{font-size:30px;font-weight:750;letter-spacing:-.7px;margin:10px 0 2px}.metric-label{font-size:12px;color:var(--muted)}.grid{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(0,1fr);gap:20px;margin-top:22px}h2{font-size:18px;margin:0 0 15px;letter-spacing:-.3px}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;font-size:11px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:9px 10px}td{border-bottom:1px solid #edf1f7;padding:13px 10px;white-space:nowrap}.pill{border-radius:6px;padding:3px 8px;background:#edf3ff;color:#3164b5;font-size:11px;display:inline-block}.pill.bad{background:#fff0ed;color:#bb5039}.pill.good{background:#eaf7f2;color:#258061}.kv{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid #edf1f7;padding:11px 0;font-size:13px}.kv span{color:var(--muted)}.callout{background:#f0f5ff;border-radius:10px;padding:14px;font-size:12px;color:#4c6485;margin-top:20px}.checks{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-top:20px}.check{background:#f8faff;border:1px solid var(--line);border-radius:12px;padding:16px;font-size:13px}.check strong{display:block;margin-bottom:5px}.footer{display:flex;justify-content:space-between;gap:20px;margin:26px 0 8px;color:var(--muted);font-size:11px}#node-result{white-space:pre-wrap;margin-top:16px;color:#c7dbff;font-size:13px}.error{color:#d65848!important}@media(max-width:900px){.shell{padding:18px}.hero,.grid{grid-template-columns:1fr}.hero-aside{border-left:0;border-top:1px solid #344b68;padding:20px 0 0}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.checks{grid-template-columns:1fr}.hero h1{font-size:29px}}@media(max-width:480px){.shell{padding:12px}.top{align-items:flex-start;flex-direction:column}.hero{padding:23px}.metrics{gap:10px}.card{padding:16px}.metric .value{font-size:25px}.footer{flex-direction:column;gap:5px}}
</style></head><body><main class=shell><header class=top><div class=brand>Quantum<span style="color:#2769ea"> Node</span><small>CONTROL</small></div><nav>''' + management + '''</nav></header>
<section class=hero><div><div class=eyebrow>Инфраструктура / локальная нода</div><h1>Видеть причину.<br>Проверять результат.</h1><p>Протоколы, открытые порты, ресурсы и трафик вашего VDS — по фактическим данным системы.</p><div class=hero-actions><button id=node-refresh>Обновить данные</button>''' + probe + '''<button class=secondary id=node-export>Скачать отчёт</button></div><div id=node-result role=status aria-live=polite></div></div><div class=hero-aside><strong><span class=status-dot></span>Снимок состояния сервера</strong><div class=node-id id=node-address>—</div><div id=node-time class=subtle></div><p class=subtle>Каждый показатель относится к этому серверу. Доступность с телефона проверяется отдельно.</p></div></section>
<section class=metrics aria-label="Ресурсы и трафик"><article class="card metric"><div class=metric-label>Нагрузка / 1 минута</div><div class=value id=node-load>—</div><div class=subtle>В пересчёте на ядра CPU</div></article><article class="card metric"><div class=metric-label>Память</div><div class=value id=node-memory>—</div><div class=subtle>Использовано RAM</div></article><article class="card metric"><div class=metric-label>Трафик приём / передача</div><div class=value id=node-traffic style="font-size:23px">—</div><div class=subtle>Мбит/с · все сетевые интерфейсы</div></article><article class="card metric"><div class=metric-label>Диск</div><div class=value id=node-disk>—</div><div class=subtle>Использовано хранилища</div></article></section>
<section class=grid><article class=card><h2>Протоколы и порты</h2><p class=subtle>Сопоставление Xray-конфигурации с слушающими сокетами Linux. Проверка TCP выполняется через loopback.</p><div class=table-wrap><table><thead><tr><th>Протокол</th><th>Порт</th><th>Транспорт</th><th>Защита</th><th>Слушает</th><th>TCP</th></tr></thead><tbody id=node-ports></tbody></table></div><p id=node-config class=subtle></p></article><article class=card><h2>Пропускная способность</h2><div class=kv><span>TCP congestion</span><strong id=node-congestion>—</strong></div><div class=kv><span>Очереди Linux</span><strong id=node-queues>—</strong></div><div class=kv><span>Лимиты tc</span><strong id=node-caps>—</strong></div><div class=kv><span>Слушающие порты</span><strong id=node-listeners>—</strong></div><div class=callout>Speedtest на VDS показывает канал сервера. Скорость VPN зависит от пути телефона, Wi‑Fi/LTE, транспорта, MTU и нагрузки. Отсутствие лимита tc не доказывает отсутствие ограничения у провайдера.</div></article></section>
<section class="card" style="margin-top:22px"><h2>Проверка медленного видео</h2><div class=checks><article class=check><strong>01 · Один телефон и сеть</strong>Сравните прямую загрузку и VPN подряд, без смены Wi‑Fi/LTE. Сохраните добровольную диагностику приложения.</article><article class=check><strong>02 · Один сервер, разные пути</strong>Проверьте каждый профиль отдельно. Порт слушает — это ещё не успешное шифрованное соединение с телефона.</article><article class=check><strong>03 · Повторные замеры</strong>Сравните скорость, потери, повторные передачи и загрузку CPU до и после изменения. Снижение RTT не доказывает рост скорости.</article></div></section><footer class=footer><span>Quantum Node · измерения Linux / Xray</span><span>Настройки, ключи и профили подключения в отчёт не входят.</span></footer></main>
<script type=application/json id=node-initial>''' + payload + '''</script><script>
(()=>{'use strict';const base=''' + json.dumps(api_base) + ''',csrf=''' + json.dumps(csrf) + ''';let current=JSON.parse(document.getElementById('node-initial').textContent);const el=id=>document.getElementById('node-'+id),number=v=>typeof v==='number'&&Number.isFinite(v),pct=v=>number(v)?v+'%':'—';function badge(value){const span=document.createElement('span');span.className='pill '+(value===true?'good':value===false?'bad':'');span.textContent=value===true?'Да':value===false?'Нет':'—';return span}function display(value){current=value;el('address').textContent=value.public_address||'Адрес не задан';el('time').textContent='Проверено: '+new Date(value.generated_at*1000).toLocaleString('ru-RU');el('load').textContent=pct(value.resources.load_1m_pct);el('memory').textContent=pct(value.resources.memory_used_pct);el('disk').textContent=pct(value.resources.disk_used_pct);el('traffic').textContent=[value.traffic.rx_mbps,value.traffic.tx_mbps].map(v=>number(v)?v:'—').join(' / ');el('congestion').textContent=value.tcp.congestion_control==='unknown'?'Нет данных':value.tcp.congestion_control;el('queues').textContent=value.tcp.qdisc.kinds.join(', ')||'Нет данных';el('caps').textContent=value.tcp.qdisc.rate_caps_bps.length?value.tcp.qdisc.rate_caps_bps.map(v=>(v/1000000).toFixed(1)+' Мбит/с').join(', '):value.tcp.qdisc.available?'Не обнаружены':'Нет данных';el('listeners').textContent=value.listener_count??'—';el('ports').replaceChildren();for(const row of value.ports){const tr=document.createElement('tr');for(const name of ['protocol','port','transport','security']){const td=document.createElement('td');td.textContent=row[name];tr.append(td)}for(const key of ['listening','loopback_probe']){const td=document.createElement('td');td.append(badge(row[key]));if(key==='loopback_probe'&&number(row.latency_ms))td.append(' '+row.latency_ms+' мс');tr.append(td)}el('ports').append(tr)}el('config').textContent=!value.config_available?'Конфигурация Xray недоступна: протоколы не подтверждены.':!value.ports.length?'В конфигурации нет поддерживаемых входящих портов.':value.ports_truncated?'Показаны первые 48 записей конфигурации.':'Внешняя доступность и скорость VPN этим снимком не измеряются.'}
async function request(diagnose){const buttons=[el('refresh'),el('diagnose')].filter(Boolean);buttons.forEach(button=>button.disabled=true);el('result').classList.remove('error');el('result').textContent=diagnose?'Проверяем локальные TCP-порты…':'Обновляем измерения…';try{const response=await fetch(base+(diagnose?'/diagnostics':'/status'),{method:diagnose?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:diagnose?{'Content-Type':'application/x-www-form-urlencoded'}:{},body:diagnose?new URLSearchParams({csrf}):undefined});if(!response.ok)throw Error(response.status===401||response.status===403?'Сессия истекла или нет прав. Обновите страницу.':response.status===429?'Проверка недавно выполнялась. Подождите минуту.':'Сервер временно недоступен');display(await response.json());el('result').textContent=diagnose?'Проверка завершена. Результаты TCP показаны в таблице.':'Снимок обновлён.'}catch(error){el('result').classList.add('error');el('result').textContent=error.message}finally{buttons.forEach(button=>button.disabled=false)}}el('refresh').addEventListener('click',()=>request(false));if(el('diagnose'))el('diagnose').addEventListener('click',()=>request(true));el('export').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='quantum-node-'+current.generated_at+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});display(current);})();
</script></body></html>'''


