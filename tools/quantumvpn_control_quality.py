"""Read-only control-plane evidence. Never returns subscription credentials."""
from __future__ import annotations

import base64
import hashlib
import html
import io
import ipaddress
import json
import math
import os
import re
import sqlite3
import tempfile
import time
import zipfile
from contextlib import closing
from urllib.parse import urlsplit

MAX_BYTES = 4 * 1024 * 1024
CLIENT_QUALITY_LIMIT = 2000
CLIENT_QUALITY_MIN_DEVICES = 5
CLIENT_QUALITY_PROTOCOLS = {"vless", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "amneziawg", "shadowsocks", "unknown"}
CLIENT_QUALITY_NETWORKS = {"wifi", "mobile", "ethernet", "unknown"}
APK_LINK_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "olcrtc", "olconnect"}
ADS_SUFFIXES = (
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "pagead2.googlesyndication.com", "scorecardresearch.com", "adsrvr.org", "adnxs.com",
    "facebook.net", "hotjar.com", "clarity.ms", "moatads.com", "taboola.com", "outbrain.com",
    "criteo.com", "pubmatic.com", "openx.net", "rubiconproject.com",
)


def subscription_evidence(raw: bytes) -> dict:
    """Describe payload shape, not names, endpoints, keys or share-link contents."""
    if len(raw) > MAX_BYTES:
        raise ValueError("Подписка больше 4 МБ")
    text = raw.decode("utf-8", "replace").lstrip("\ufeff").strip()
    encoding = "text"
    if not text.startswith(("{", "[Interface]", "[Peer]", "[")) and "://" not in text:
        try:
            compact = re.sub(r"\s+", "", text)
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode("utf-8")
            if "://" in decoded or decoded.lstrip().startswith(("{", "[")):
                text, encoding = decoded.strip(), "base64"
        except (ValueError, UnicodeError):
            pass
    schemes = {}
    for scheme in re.findall(r"(?im)^\s*([a-z0-9+.-]+)://", text):
        schemes[scheme.lower()] = schemes.get(scheme.lower(), 0) + 1
    conf = bool(re.search(r"(?im)^\s*\[Interface\]\s*$", text))
    if conf:
        schemes["amneziawg" if re.search(r"(?im)^\s*(jc|jmin|s[1-4]|h[1-4]|i[1-5])\s*=", text) else "wireguard"] = 1
        encoding += " / conf"
    elif text.startswith(("{", "[")):
        try:
            root = json.loads(text)
            # Only sing-box endpoint/outbound type fields are protocol evidence.
            if isinstance(root, dict):
                for item in root.get("outbounds", []) + root.get("endpoints", []):
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("type") or "")[:32].lower()
                    if name in {"direct", "block", "selector", "urltest", "dns", ""}:
                        continue
                    if name == "wireguard" and item.get("amnezia"):
                        name = "amneziawg"
                    schemes[name] = schemes.get(name, 0) + 1
                encoding += " / sing-box JSON"
            else:
                encoding += " / JSON array (требуется конвертация)"
        except (ValueError, TypeError):
            encoding += " / некорректный JSON"
    supported = APK_LINK_SCHEMES if "JSON" not in encoding and not conf else APK_LINK_SCHEMES | {"wireguard", "amneziawg", "shadowsocks", "socks"}
    return {
        "checked_at": int(time.time()), "bytes": len(raw), "encoding": encoding,
        "protocols": schemes, "unsupported_schemes": sorted(set(schemes) - supported),
        "sha256": hashlib.sha256(raw).hexdigest(), "has_awg": "amneziawg" in schemes,
        "warning": "Проверена структура выдачи; соединение и ключи проверяются на устройстве.",
    }


def explain_route(payload: dict, target: str) -> dict:
    """Mirror published APK policy precedence without fetching target URLs."""
    target = target.strip()[:1024]
    if not target:
        raise ValueError("Введите домен или IP")
    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("Укажите HTTP(S) URL без учётных данных")
        host = parsed.hostname or ""
    else:
        host = target.strip("[]")
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        host = str(address)
    except ValueError:
        address = None
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Некорректный домен") from exc
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
            raise ValueError("Некорректный домен или IP")
    result = {"target": host, "revision": payload.get("revision"), "dns": payload.get("dns", {}), "checked_at": int(time.time())}
    if not payload.get("enabled", True):
        return {**result, "direction": "Профиль устройства", "reason": "Панельная маршрутизация отключена; используются правила сохранённого профиля."}
    rules = payload.get("rules", {})
    def suffix(values):
        return next((s for s in values if host == s or host.endswith("." + s)), None)
    def cidr(values):
        return next((s for s in values if address and address in ipaddress.ip_network(s)), None)
    block = suffix(rules.get("block_domains", [])) if not address else None
    ads = suffix(ADS_SUFFIXES) if not address and payload.get("adblock", {}).get("enabled") else None
    if block or ads:
        return {**result, "direction": "Блокировка", "reason": "Приоритет block / DNS reject", "matched": block or ads}
    direct = suffix(rules.get("direct_domains", [])) if not address else cidr(rules.get("direct_cidrs", []))
    if direct:
        return {**result, "direction": "Напрямую", "reason": "Явное правило direct", "matched": direct}
    # Android's generated LAN bypass precedes explicit proxy rules.
    # sing-box ip_is_private matches non-public addresses, including CGNAT.
    if address and (not address.is_global or address.is_multicast):
        return {**result, "direction": "Напрямую", "reason": "Локальная сеть / служебный адрес"}
    proxy = suffix(rules.get("proxy_domains", [])) if not address else cidr(rules.get("proxy_cidrs", []))
    if payload.get("profile") == "balanced":
        return {**result, "direction": "Зависит от RU-списка APK", "matched": proxy or "RU / по умолчанию", "reason": "APK проверяет локальные RU domain/IP списки перед proxy: совпадение → напрямую, иначе → VPN. RU-списки и оставшиеся правила профиля не проверялись панелью."}
    if proxy:
        return {**result, "direction": "Через выбранный VPN", "reason": "Явное правило proxy", "matched": proxy}
    return {**result, "direction": "Через выбранный VPN", "reason": "Маршрут по умолчанию; локальные сети исключены"}


def dependency_evidence(path: str) -> dict:
    out = {"available": False, "nodes": [], "protocols": [], "users": 0, "awg_enabled": False}
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)) as db:
            db.row_factory = sqlite3.Row
            s = dict(db.execute("select host, master_label, awg_enabled, awg_port from settings limit 1").fetchone())
            out.update(available=True, awg_enabled=bool(s["awg_enabled"]), awg_port=s["awg_port"])
            out["users"] = db.execute("select count(*) from users where enabled=1").fetchone()[0]
            out["nodes"] = [{"id": 0, "label": s["master_label"] or "Основной сервер", "host": s["host"], "enabled": True, "last_seen": 0}]
            for r in db.execute("select id,name,host,enabled,last_seen,awg_enabled from nodes where deleted_at is null or deleted_at=0 order by id limit 80"):
                out["nodes"].append({"id": r["id"], "label": r["name"], "host": r["host"], "enabled": bool(r["enabled"]), "last_seen": r["last_seen"] or 0})
                if r["awg_enabled"]:
                    out["protocols"].append({"node": r["id"], "label": "AmneziaWG", "protocol": "amneziawg", "port": None, "enabled": bool(r["enabled"])})
            for r in db.execute("select server_id,name,protocol,port,enabled from inbounds order by sort,id limit 120"):
                out["protocols"].append({"node": r["server_id"] or 0, "label": r["name"], "protocol": r["protocol"], "port": r["port"], "enabled": bool(r["enabled"])})
            if s["awg_enabled"]:
                out["protocols"].append({"node": 0, "label": "AmneziaWG", "protocol": "amneziawg", "port": s["awg_port"], "enabled": True})
    except (sqlite3.Error, TypeError, OSError):
        out["error"] = "Основная панель недоступна или её схема не поддерживается"
    return out


def validate_backup(ciphertext: bytes, key: bytes, aes_class) -> dict:
    """Restore only into a private temporary directory; never overwrite live DBs."""
    if aes_class is None:
        raise ValueError("Не установлен модуль шифрования")
    if len(ciphertext) > 128 * 1024 * 1024 or len(ciphertext) < 33 or ciphertext[:5] != b"QVBK1":
        raise ValueError("Некорректный зашифрованный архив")
    plain = aes_class(key).decrypt(ciphertext[5:17], ciphertext[17:], b"QuantumControl backup v1")
    databases, files = [], []
    with zipfile.ZipFile(io.BytesIO(plain)) as bundle, tempfile.TemporaryDirectory(prefix="qv-restore-check-") as folder:
        members = bundle.infolist()
        if len(members) > 48 or sum(x.file_size for x in members) > 128 * 1024 * 1024:
            raise ValueError("Архив превышает допустимый размер")
        names = [x.filename for x in members]
        if len(names) != len(set(names)) or "operator.db" not in names or "backup-info.json" not in names:
            raise ValueError("В архиве отсутствует обязательная база или метаданные")
        if bundle.testzip() is not None:
            raise ValueError("Повреждена контрольная сумма ZIP")
        json.loads(bundle.read("backup-info.json"))
        for name in ("operator.db", "rospanel.db"):
            if name not in names:
                continue
            dest = os.path.join(folder, name)
            with open(dest, "xb") as stream:
                stream.write(bundle.read(name))
            os.chmod(dest, 0o600)
            with closing(sqlite3.connect(f"file:{dest}?mode=ro", uri=True)) as db:
                if db.execute("pragma integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Не пройдена проверка SQLite")
                tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
                required = {"settings", "events", "device_flags"} if name == "operator.db" else {"users", "settings", "inbounds"}
                if not required <= tables:
                    raise ValueError("База не содержит обязательные таблицы")
                db.execute("select * from settings limit 1").fetchone()
            databases.append(name)
        for name in ("session.secret", "routing-ed25519.key", "rospanel/secrets.key", "rospanel/certs/cert.pem", "rospanel/certs/key.pem"):
            if name in names and bundle.read(name):
                files.append(name)
    missing = [name for name in ("rospanel.db", "session.secret", "routing-ed25519.key", "rospanel/secrets.key", "rospanel/certs/cert.pem", "rospanel/certs/key.pem") if name not in databases + files]
    return {"checked_at": int(time.time()), "ok": True, "databases": databases, "key_files": files, "missing": missing,
            "note": "AES-GCM, ZIP и восстановление SQLite проверены в отдельном временном каталоге. Для полного запуска нужны серверные файлы, окружение сервиса и внешний ключ расшифровки."}


def client_quality_summary(db, now=None) -> dict:
    """Read-only, bounded cohorts; repeated reports do not give a device extra weight.

    This view deliberately does not reuse the release guard's raw reports or
    version cohorts. It uses one latest report per device/node/protocol/network
    and exposes no device IDs. A full window is not guaranteed at the cap.
    """
    moment = int(time.time() if now is None else now)
    result = {"available": False, "window_start": moment - 86400, "window_end": moment,
              "reports_considered": 0, "devices": 0, "device_group_samples": 0,
              "groups": [], "suppressed_groups": 0, "missing_ping_samples": 0,
              "limit": CLIENT_QUALITY_LIMIT, "limit_reached": False,
              "min_devices": CLIENT_QUALITY_MIN_DEVICES, "sampling": "latest_per_device_group",
              "recommendations_available": False}
    try:
        rows = db.execute(
            "select device,ts,node_key,protocol,network,ping_ms,success from community_quality "
            "where ts>=? and ts<=? order by ts desc,id desc limit ?",
            (moment - 86400, moment, CLIENT_QUALITY_LIMIT)).fetchall()
    except sqlite3.Error:
        return result
    result.update(available=True, reports_considered=len(rows), limit_reached=len(rows) == CLIENT_QUALITY_LIMIT)
    latest = {}
    for device, ts, node, protocol, network, ping, success in rows:
        if not isinstance(device, str) or not device or len(device) > 128:
            continue
        node = node if isinstance(node, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", node) else ""
        protocol = protocol if protocol in CLIENT_QUALITY_PROTOCOLS else "unknown"
        network = network if network in CLIENT_QUALITY_NETWORKS else "unknown"
        latest.setdefault((device, node, protocol, network), (ping, success == 1))
    groups = {}
    for (device, node, protocol, network), (ping, success) in latest.items():
        try:
            ping = float(ping) if success and not isinstance(ping, bool) else 0
            measured = math.isfinite(ping) and 0 < ping <= 60000
        except (ValueError, TypeError, OverflowError):
            measured = False
        result["missing_ping_samples"] += int(not measured)
        group = groups.setdefault((node, protocol, network), {"devices": 0, "successes": 0, "pings": []})
        group["devices"] += 1
        group["successes"] += int(success)
        if measured:
            group["pings"].append(ping)
    result.update(devices=len({key[0] for key in latest}), device_group_samples=len(latest))
    for (node, protocol, network), group in groups.items():
        if group["devices"] < CLIENT_QUALITY_MIN_DEVICES:
            result["suppressed_groups"] += 1
            continue
        pings = sorted(group["pings"])
        # A cohort of five must not expose a single valid personal measurement.
        enough_pings = len(pings) >= CLIENT_QUALITY_MIN_DEVICES
        percentile = lambda fraction: round(pings[math.ceil(len(pings) * fraction) - 1], 1) if enough_pings else None
        result["groups"].append({"node": node, "protocol": protocol, "network": network,
                                 "devices": group["devices"], "ping_devices": len(pings),
                                 "success_percent": round(100 * group["successes"] / group["devices"], 1),
                                 "ping_p50_ms": percentile(.5), "ping_p95_ms": percentile(.95)})
    result["groups"].sort(key=lambda row: (-row["devices"], row["node"], row["protocol"], row["network"]))
    return result


def render_client_quality(summary: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    groups = summary.get("groups", [])
    minimum = CLIENT_QUALITY_MIN_DEVICES
    if not summary.get("available"):
        status = "Добровольные отчёты пока недоступны. Серверные проверки не подставляются вместо клиентских замеров."
    elif not summary.get("reports_considered"):
        status = "За последние 24 часа добровольные замеры не поступили. Это не означает неисправность VPN."
    elif not groups:
        status = f"Недостаточно добровольных данных: нужно минимум {minimum} разных устройств в группе."
    else:
        status = f"{int(summary['devices'])} устройств · {int(summary['reports_considered'])} отчётов · {len(groups)} групп."
    networks = {"wifi": "Wi-Fi", "mobile": "Мобильная", "ethernet": "Ethernet", "unknown": "Не сообщена"}
    latency = lambda value: esc(value) if value is not None else "—"
    rows = "".join(
        f"<tr><td>{esc(row['node'] or 'Не сообщена')}</td><td>{esc(row['protocol'].upper())}</td>"
        f"<td>{esc(networks.get(row['network'], 'Не сообщена'))}</td><td>{int(row['devices'])}</td>"
        f"<td>{esc(row['success_percent'])}%</td><td>{int(row['ping_devices'])}</td>"
        f"<td>{latency(row['ping_p50_ms'])}</td><td>{latency(row['ping_p95_ms'])}</td></tr>"
        for row in groups[:40])
    table = ("<div class=quality-table><table><thead><tr><th>Нода (ключ)</th><th>Протокол</th><th>Сеть</th>"
             "<th>Устройств</th><th>Подключения OK</th><th>Замеров ping</th><th>P50, мс</th><th>P95, мс</th>"
             f"</tr></thead><tbody>{rows}</tbody></table></div>") if rows else ""
    limit_note = (f"<p class=warn>Достигнут лимит {CLIENT_QUALITY_LIMIT} последних отчётов: выборка может не охватывать все 24 часа.</p>"
                  if summary.get("limit_reached") else "")
    remaining = f"<p class=muted>Показаны первые 40 из {len(groups)} групп.</p>" if len(groups) > 40 else ""
    return f"""<details class=card style='margin-top:12px'><summary>Качество клиентов · {len(groups)} групп · 24 часа</summary>
    <p class=muted>{esc(status)}</p>{limit_note}{table}{remaining}
    <p class=muted>Один последний отчёт на устройство и группу нода / протокол / сеть. Редкие группы скрыты: {int(summary.get('suppressed_groups', 0))}.
    Ping не измерен или подключение неуспешно в {int(summary.get('missing_ping_samples', 0))} записях этой выборки.
    P50 — медиана, P95 — порог для 95% замеров; показаны только успешные положительные замеры минимум {minimum} устройств.</p>
    <p class=muted>Это добровольные самоотчёты APK, а не ping с VDS. IP и идентификаторы устройств не показываются.
    Ключ ноды не доказывает её географию. Выборка не измеряет скорость и не доказывает ТСПУ; для автоматической рекомендации сервера данных недостаточно.</p></details>"""


def quality_snapshot(db, s: dict, rospanel_db: str) -> dict:
    def saved(key):
        try:
            return json.loads(s.get(key) or "{}")
        except (ValueError, TypeError):
            return {}
    moment = int(time.time())
    since = moment - 86400
    health = [dict(r) for r in db.execute(
        "select target,count(*) samples,sum(ok) successes,round(avg(case when ok=1 then latency_ms end),1) latency_ms,max(ts) checked_at "
        "from server_health where ts>=? group by target order by target limit 80", (since,))]
    clients = [dict(r) for r in db.execute("select device,version_code,policy_at,update_at,download_at,install_at,notification_permission from delivery_evidence order by policy_at desc limit 200")]
    installed = db.execute("select count(*) from delivery_evidence where version_code>=? and version_code>0", (int(s.get("app_version_code") or 0),)).fetchone()[0]
    client_count = db.execute("select count(*) from delivery_evidence").fetchone()[0]
    ai = [dict(r) for r in db.execute("select id,ts,trigger,status,advice,telegram_sent,before_json from ai_observations order by id desc limit 24")]
    return {"subscription": saved("quality_subscription"), "route": saved("quality_route"),
            "backup": saved("quality_backup"), "dependencies": dependency_evidence(rospanel_db), "health": health,
            "clients": clients, "client_count": client_count, "installed": installed, "ai": ai, "version": s.get("app_version", ""),
            "version_code": int(s.get("app_version_code") or 0), "client_quality": client_quality_summary(db, moment)}


def render_quality(snapshot: dict, s: dict) -> str:
    esc = lambda x: html.escape(str(x), quote=True)
    stamp = lambda x: time.strftime("%d.%m %H:%M", time.gmtime(int(x or 0) + 10800)) + " МСК" if x else "нет данных"
    sub, route, backup, deps = (snapshot[k] for k in ("subscription", "route", "backup", "dependencies"))
    protocols = sub.get("protocols", {})
    sub_rows = "".join(f"<tr><td>{esc(k.upper())}</td><td>{int(v)}</td><td>{'Нужна поддержка схемы' if k in sub.get('unsupported_schemes',[]) else 'Формат распознан'}</td></tr>" for k,v in sorted(protocols.items())) or "<tr><td colspan=3>Ожидается ответ подписки</td></tr>"
    protocol_tiles = " ".join(f"<span class=badge>{esc(k.upper())} · {int(v)}</span>" for k,v in list(sorted(protocols.items()))[:6]) or "<span class=muted>Ожидается ответ подписки</span>"
    awg_note = "<p class=warn>AWG включён в основной панели, но последняя проверенная выдача его не содержит.</p>" if deps.get("awg_enabled") and sub and not sub.get("has_awg") else ""
    health_rows = "".join(f"<tr><td>{esc(r['target'])}</td><td>{int(r['successes'])}/{int(r['samples'])}</td><td>{round(100*int(r['successes'])/max(1,int(r['samples'])),1)}%</td><td>{esc(str(r['latency_ms']) + ' мс' if r['latency_ms'] and (r['target'].startswith('latency:') or r['target'] == 'subscription_upstream') else 'не измерялось')}</td><td>{esc(stamp(r['checked_at']))}</td></tr>" for r in snapshot["health"]) or "<tr><td colspan=5>Автоматические измерения ещё не поступили</td></tr>"
    clients = snapshot["clients"]
    client_rows = "".join(f"<tr><td>{esc(r['device'])}</td><td>{int(r['version_code']) or 'не сообщён'}</td><td>{esc(stamp(r['policy_at']))}</td><td>{esc(stamp(r['update_at']))}</td><td>{esc(stamp(r['download_at']))}</td><td>{esc(r['notification_permission'])}</td></tr>" for r in clients[:12]) or "<tr><td colspan=6>Ожидаются запросы устройств</td></tr>"
    ai_rows = "".join(f"<tr><td>{esc(stamp(r['ts']))}</td><td>{esc(r['status'])}<br><small>{esc(r['trigger'])}</small></td><td>{esc(r['advice'])}<details><summary>Снимок измерений</summary><pre>{esc(r['before_json'])}</pre></details></td><td>{'API принял' if r['telegram_sent'] else 'Нет'}</td></tr>" for r in snapshot["ai"]) or "<tr><td colspan=4>Новых запусков модели пока нет</td></tr>"
    dependencies = []
    for node in deps.get("nodes", []):
        items = [x for x in deps.get("protocols", []) if x["node"] == node["id"]]
        badges = " ".join(f"<span class='badge {'ok' if x['enabled'] else 'off'}'>{esc(x['protocol'])} : {int(x['port']) if x['port'] else 'неизвестно'}</span>" for x in items) or "<span class=muted>Протоколы не настроены</span>"
        dependencies.append(f"<article class=card><b>{esc(node['label'])}</b><p class=muted>{esc(node['host'])} · {'Включён' if node['enabled'] else 'Отключён'}</p>{badges}<p>→ Общая выдача подписки → {int(deps.get('users',0))} активных пользователей</p><small>Статус включения взят из базы; доступность — в таблице измерений.</small></article>")
    dep_html = "".join(dependencies) or "<p class=muted>Нет данных основной панели</p>"
    route_result = f"<div class=flash><b>{esc(route.get('target',''))} → {esc(route.get('direction',''))}</b><details><summary>Почему выбран этот маршрут?</summary><p>{esc(route.get('reason',''))}</p><small>Правило: {esc(route.get('matched','по умолчанию'))} · опубликовано r{esc(route.get('revision','—'))}</small></details></div>" if route else ""
    backup_result = f"<p class={'ok' if backup.get('ok') else 'off'}>{'Проверка восстановления пройдена' if backup.get('ok') else 'Проверка не пройдена'}</p><p>{esc(backup.get('note',''))}</p><p class=muted>Проверено: {esc(', '.join(backup.get('databases',[]) + backup.get('key_files',[])) or '—')}</p><p class=warn>Отсутствует в архиве: {esc(', '.join(backup.get('missing',[])) or 'нет обязательных пропусков')}</p><small>{esc(stamp(backup.get('checked_at')))}</small>" if backup else "<p class=muted>Восстановление ещё не проверялось</p>"
    client_quality_html = render_client_quality(snapshot.get("client_quality", {}))
    return f"""<style>.quality-page details.card{{margin-top:10px}}.quality-page summary{{cursor:pointer;font-weight:650}}.quality-page .quality-table{{max-height:240px;overflow:auto}}.quality-page pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-height:160px;overflow:auto}}.quality-page table{{min-width:0}}.quality-page td{{overflow-wrap:anywhere}}.quality-page .grid{{align-items:start}}.quality-page .stat{{padding:9px;font-size:12px}}.quality-page .stat b{{margin-top:2px;font-size:21px}}.quality-page .card{{padding:12px}}.quality-page h2{{font-size:16px;margin:0 0 8px}}.quality-page p{{margin:8px 0;font-size:12px}}.quality-page form{{display:flex;align-items:flex-end;gap:8px}}.quality-page form label{{flex:1;min-width:0;margin:0}}.quality-page form button{{flex-shrink:0;padding:9px 12px}}.quality-page .flash{{margin-top:8px;padding:10px;font-size:12px}}.quality-page .quality-details{{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}}.panel-shell:has(.quality-page) .tabs>a{{min-height:35px;padding:8px 12px}}@media(max-width:900px){{.quality-page table{{min-width:650px}}.quality-page .quality-details{{grid-template-columns:1fr}}.quality-page form{{flex-wrap:wrap}}}}</style><section class=quality-page><div class=reference-kpis>
    <div class=stat>Протоколы в выдаче<b>{len(protocols) if sub else '—'}</b><small>{esc(stamp(sub.get('checked_at')))}</small></div>
    <div class=stat>Устройства с телеметрией<b>{snapshot['client_count']}</b><small>Сообщили текущую версию: {snapshot['installed']}</small></div>
    <div class=stat>Маршрутизация<b>r{esc(s.get('routing_revision','1'))}</b><small>Проверяется опубликованная политика</small></div>
    <div class=stat>Проверка backup<b>{('Частично' if backup.get('missing') else 'OK') if backup.get('ok') else 'Ожидает'}</b><small>{esc(stamp(backup.get('checked_at')))}</small></div></div>
    <div class=grid style='margin-top:12px'>
    <section class=card><div class=section-head><h2>Подписка глазами APK</h2><form method=post action=/operator/actions><input type=hidden name=return_tab value=quality><button name=action value=inspect_subscription>Проверить</button></form></div>
    <p class=muted>Последний ответ одной подписки. Ссылки и ключи скрыты.</p>{awg_note}<div class=quality-protocols>{protocol_tiles}</div><details style='margin-top:10px'><summary>Формат и совместимость</summary><div class=quality-table><table><thead><tr><th>Протокол</th><th>Серверов</th><th>Формат</th></tr></thead><tbody>{sub_rows}</tbody></table></div><small>{esc(' · '.join(str(sub[k]) for k in ('source','encoding','warning') if sub.get(k)))}</small><pre>SHA-256: {esc(sub.get('sha256','нет данных'))}</pre></details></section>
    <section class=card><h2>Почему выбран этот маршрут?</h2><form method=post action=/operator/actions><input type=hidden name=return_tab value=quality><label>Домен, IP или URL<input name=route_target maxlength=1024 required placeholder='youtube.com' value='{esc(route.get('target',''))}'></label><button name=action value=explain_route>Проверить правило</button></form>{route_result}<p class=muted>DNS: {esc(s.get('routing_dns_resolver') or s.get('routing_dns_mode','vpn_only'))}. Введённый URL не открывается и не сканируется.</p></section>
    </div>{client_quality_html}<details class=card style='margin-top:12px'><summary>Состояние сервисов и нод · {len(snapshot['health'])} целей · последние 24 часа</summary><div class=quality-table><table><thead><tr><th>Цель</th><th>Успешные проверки</th><th>Доступность</th><th>Задержка ответа</th><th>Последний замер</th></tr></thead><tbody>{health_rows}</tbody></table></div><p class=muted>Это проверки с VDS. Потери пакетов и скорость конкретного VPN-протокола требуют отдельного измерения и здесь не вычисляются из TCP-пинга. <a href='/operator?tab=quality'>Обновить показатели →</a></p></details><div class=quality-details>
    <details class=card><summary>Карта зависимостей: ноды → протоколы → подписки</summary><div class=grid style='margin-top:12px'>{dep_html}</div><p class=muted>Панельная маршрутизация r{esc(s.get('routing_revision','1'))} и DNS применяются в APK к выбранному профилю. Индивидуальные ограничения основной панели могут изменить набор серверов пользователя.</p></details>
    <details class=card><summary>Обновления и уведомления · {esc(snapshot['version'])}</summary><div class=quality-table><table><thead><tr><th>Устройство</th><th>versionCode</th><th>Запрос политики</th><th>Проверка обновления</th><th>Загрузка</th><th>Разрешение уведомлений</th></tr></thead><tbody>{client_rows}</tbody></table></div><p class=muted>Версия — сообщение клиента, не независимая проверка установки. Запрос политики не доказывает показ уведомления. Старые APK не сообщают разрешение и установку: для них отображается «неизвестно».</p></details>
    <details class=card><summary>Qwen: рекомендации и наблюдения</summary><div class=quality-table><table><thead><tr><th>Время</th><th>Результат</th><th>Рекомендация</th><th>Telegram</th></tr></thead><tbody>{ai_rows}</tbody></table></div><p class=muted>Модель анализирует агрегированные измерения. Выполнение команд ей не предоставляется. Снимки измерений сохранены с каждым новым анализом.</p><a href='/operator?tab=ai'>Настройки Qwen →</a></details>
    <details class=card><summary>Проверка восстановления резервной копии</summary><form method=post action=/operator/actions style='margin-top:12px'><input type=hidden name=return_tab value=quality><button name=action value=verify_backup>Проверить последнюю копию</button></form>{backup_result}</details></div></section>"""
