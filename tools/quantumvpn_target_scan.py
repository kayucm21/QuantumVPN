"""Operator target-scan presentation. No probing, persistence or policy writes."""
from __future__ import annotations

import html
import ipaddress
from datetime import datetime, timedelta, timezone


def _ip_label(value) -> str:
    """Derive address family from actual numeric evidence, not a claimed flag."""
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return "IP: тип неизвестен"
    return f"IPv{address.version}"


def _checked_label(value) -> str:
    if type(value) is not int or value <= 0:
        return "Время замера не указано"
    try:
        return datetime.fromtimestamp(value, timezone(timedelta(hours=3))).strftime("%d.%m.%Y %H:%M:%S МСК")
    except (ValueError, OverflowError, OSError):
        return "Время замера не указано"


def scan_dialog(findings: list[dict], token: str, csrf: str, *, auto_open: bool = False,
                can_write: bool = True, reserve_available: bool = False, limit: int = 24) -> str:
    escape = lambda value: html.escape(str(value), quote=True)
    limit = min(24, max(1, limit)) if type(limit) is int else 24
    labels = {"proxy": "Через VPN", "direct": "Напрямую", "block": "Блок-лист", "observe": "Решение оператора"}
    statuses = {"ok": "Доступна", "timeout": "TCP/443 не ответил", "unresolved": "Нет публичного DNS-адреса",
                "budget": "Истёк лимит времени"}
    rows, checked_times, any_ready = [], [], False
    for index, item in enumerate(findings[:limit]):
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        target = str(item.get("target") or "")[:253]
        latency = item.get("latency_ms")
        measured_target = type(latency) is int and 0 < latency <= 60_000
        latency_label = f"{latency} мс" if measured_target else "Не измерена"
        ready = kind in ("domain", "ip") and item.get("status") == "ok" and measured_target and bool(token) and can_write
        any_ready = any_ready or ready
        checked_at = item.get("checked_at")
        checked_label = _checked_label(checked_at)
        if checked_label != "Время замера не указано":
            checked_times.append(checked_at)
        recommendation = item.get("recommendation")
        default_direction = recommendation if recommendation in {"proxy", "direct", "block"} else "proxy"
        directions = ("proxy", "direct", "block") if kind == "domain" else ("proxy", "direct")
        options = "".join(f'<option value="{direction}" {"selected" if direction == default_direction else ""}>{labels[direction]}</option>'
                          for direction in directions)
        samples = []
        addresses = item.get("addresses")
        for sample in addresses[:3] if isinstance(addresses, list) else []:
            if not isinstance(sample, dict):
                continue
            measured = sample.get("latency_ms")
            address = str(sample.get("address") or "")[:253]
            samples.append(escape(address) + " · " +
                           (f"{measured} мс" if type(measured) is int and 0 < measured <= 60_000 else "нет TCP-ответа") +
                           f'<small>{escape(_ip_label(address))} · TCP/443 с VDS · {escape(checked_label)}</small>')
        target_label = ("Домен / поддомен" if kind == "domain" else
                        ("Публичный " + _ip_label(target) if kind == "ip" else "Диапазон, не отдельный сервер"))
        backup = ("При сбое VPN проверить профиль «Резерв TLS» в APK; его путь здесь не измерялся."
                  if reserve_available else "Резерв TLS не настроен или выключен; запасной путь не измерялся.")
        rows.append(
            '<tr><td><label class="scan-pick">'
            f'<input type="checkbox" name="scan_selected" value="{index}" aria-label="Выбрать {escape(target)}" {"" if ready else "disabled"}>'
            f'<span><b>{escape(target)}</b><small>{escape(target_label)}</small></span></label></td>'
            f'<td><span class="{"ok" if ready else "warn"}">{escape(statuses.get(item.get("status"), "Нет данных"))}</span>'
            f'<small>TCP/443 с VDS: {escape(latency_label)}</small><small>Замер: {escape(checked_label)}</small></td>'
            f'<td class="scan-addresses">{"<br>".join(samples) or "Адрес не получен"}</td>'
            f'<td><b>{escape(labels.get(recommendation, labels["observe"]))}</b><small>{escape(item.get("reason") or "")}</small>'
            f'<small class="scan-backup">{escape(backup)}</small></td>'
            f'<td><label>В черновик<select name="scan_direction_{index}" aria-label="Направление для {escape(target)}" {"" if ready else "disabled"}>{options}</select></label></td></tr>'
        )
    checked = max(checked_times, default=0)
    table = ("".join(rows) or '<tr><td colspan="5">Введите конкретные цели и запустите проверку.</td></tr>')
    ready = any_ready
    return f'''<dialog id="routing-scan-dialog" class="routing-scan-dialog" aria-labelledby="routing-scan-title" data-auto-open="{1 if auto_open else 0}" {"open" if auto_open else ""}>
      <header class="scan-dialog-head"><div><h2 id="routing-scan-title">Результаты проверки целей</h2><p>Домены, поддомены и публичные IP · до {limit} целей за запуск</p></div><button type="button" class="secondary" data-scan-close aria-label="Закрыть результаты">Закрыть</button></header>
      <p id="routing-scan-progress" class="scan-progress" role="status" aria-live="polite">{"Проверка завершена. Выберите цели и направления для черновика." if findings else "Готов к проверке."}</p>
      <p class="muted">TCP-соединение на порт 443 измеряется с VDS. Это не ICMP-пинг и не задержка телефона через VPN. DNS-адреса не доказывают наличие рекламы или преимущество маршрута.</p>
      <form id="routing-scan-apply" method="post" action="/operator/routing" data-checked-at="{checked}">
        <input type="hidden" name="action" value="apply_scan"><input type="hidden" name="csrf" value="{escape(csrf)}"><input type="hidden" name="scan_token" value="{escape(token)}">
        <div class="scan-table-wrap"><table><thead><tr><th>Выбор и цель</th><th>Статус и замер</th><th>IP / DNS</th><th>Рекомендация и резерв</th><th>Направление</th></tr></thead><tbody>{table}</tbody></table></div>
        <label class="scan-select-all"><input type="checkbox" id="routing-scan-select-all" {"" if ready else "disabled"}> Выбрать все доступные цели</label>
        <p class="muted">Рекомендация следует текущим правилам черновика. Направление выбирает оператор; недоступные цели добавить нельзя. Результаты действуют 10 минут и привязаны к этой сессии и версии черновика.</p>
        <p class="muted">Резерв TLS — отдельный профиль в APK, а не отдельное направление правила. Доменное правило охватывает его поддомены; IP добавляется как /32 или /128.</p>
        <footer class="scan-dialog-actions"><span id="routing-scan-selection" role="status">Выбрано: 0</span><button type="submit" id="routing-scan-confirm" {"" if ready else "disabled"}>Подтвердить и добавить в черновик</button></footer>
        <p class="muted">После подтверждения черновик можно проверить в «Правилах маршрута». Для отправки в APK нужна отдельная публикация.</p>
      </form>
    </dialog>'''


def scan_dialog_css() -> str:
    return """
    .routing-scan-dialog{width:min(1160px,calc(100vw - 32px));max-height:90vh;padding:20px;border:1px solid #40677e;border-radius:14px;background:#101f2e;color:#e1edf7;box-shadow:0 20px 100px #0009;overflow:auto}
    .routing-scan-dialog:not([open]){display:none}.routing-scan-dialog::backdrop{background:#030b16b8;backdrop-filter:blur(3px)}
    .scan-dialog-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.scan-dialog-head h2{margin:0 0 6px}.scan-dialog-head p{margin:0;color:#abc0d2;font-size:12px}.scan-dialog-head button{flex-shrink:0}
    .scan-progress{padding:10px 12px;border:1px solid #3d697c;background:#173445;border-radius:8px}.scan-table-wrap{overflow-x:auto}.routing-scan-dialog table{min-width:820px}.routing-scan-dialog small{display:block;color:#a6bdcf;margin-top:5px;font-size:12px}.scan-addresses{font-family:Consolas,monospace;font-size:12px;overflow-wrap:anywhere}
    .scan-pick{display:flex;align-items:flex-start;gap:9px;margin:0;overflow-wrap:anywhere}.scan-pick input,.scan-select-all input{width:18px;height:18px;min-width:18px;margin:2px 0}.scan-pick span{max-width:210px}.scan-backup{max-width:270px}.scan-select-all{display:flex;gap:9px;align-items:center;margin-top:14px}.scan-dialog-actions{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-top:18px}.routing-scan-dialog button:disabled{opacity:.5;cursor:not-allowed}.scan-dialog-actions span{color:#b3d1df}.routing-scanner .scan-open-results{width:100%;margin-top:10px}
    @media(max-width:640px){.routing-scan-dialog{padding:14px;width:calc(100vw - 16px)}.scan-dialog-head{flex-wrap:wrap}.scan-dialog-actions{align-items:stretch;flex-direction:column}.scan-dialog-actions button{width:100%}}
    """


def scan_dialog_script() -> str:
    return """<script>(() => {
      const source = document.getElementById('routing-scan-form');
      if (!source) return;
      let busy = false;
      const dialog = () => document.getElementById('routing-scan-dialog');
      const update = () => {
        const box = dialog(), picks = [...box.querySelectorAll('[name="scan_selected"]:not(:disabled)')];
        const count = picks.filter(pick => pick.checked).length;
        box.querySelector('#routing-scan-selection').textContent = 'Выбрано: ' + count;
        box.querySelector('#routing-scan-confirm').disabled = busy || !count;
        const all = box.querySelector('#routing-scan-select-all');
        all.checked = !!picks.length && count === picks.length;
        all.indeterminate = count > 0 && count < picks.length;
      };
      const open = () => {
        const box = dialog();
        if (box.open) box.removeAttribute('open');
        if (box.showModal) box.showModal(); else box.setAttribute('open', '');
        update();
      };
      document.addEventListener('click', event => {
        if (event.target.closest('[data-scan-open]')) open();
        if (event.target.closest('[data-scan-close]')) {
          const box = dialog(); if (box.close) box.close(); else box.removeAttribute('open');
        }
      });
      document.addEventListener('change', event => {
        if (!event.target.closest('#routing-scan-dialog')) return;
        if (event.target.id === 'routing-scan-select-all')
          dialog().querySelectorAll('[name="scan_selected"]:not(:disabled)').forEach(pick => pick.checked = event.target.checked);
        update();
      });
      document.addEventListener('submit', event => {
        if (event.target.id === 'routing-scan-apply' && (busy || !dialog().querySelector('[name="scan_selected"]:checked'))) {
          event.preventDefault(); update();
        }
      });
      source.addEventListener('submit', async event => {
        event.preventDefault(); if (busy) return;
        const previous = dialog().querySelector('[name="scan_token"]').value;
        busy = true; source.dataset.scanBusy = '1'; source.dispatchEvent(new Event('routing-scan-state')); open();
        dialog().querySelectorAll('[name="scan_selected"], [name^="scan_direction_"], #routing-scan-select-all').forEach(control => control.disabled = true);
        dialog().querySelector('[name="scan_token"]').value = '';
        const progress = dialog().querySelector('#routing-scan-progress');
        progress.textContent = 'Проверяем заданные цели: DNS и TCP/443 с VDS. До 10 секунд…';
        source.querySelector('button').disabled = true;
        try {
          const response = await fetch(source.getAttribute('action'), {method:'POST',body:new URLSearchParams(new FormData(source)),credentials:'same-origin',cache:'no-store'});
          if (!response.ok) throw new Error(response.status === 403 ? 'Сессия или подтверждение запроса недействительны. Обновите страницу.' : 'Проверка не выполнена. HTTP ' + response.status);
          const page = new DOMParser().parseFromString(await response.text(), 'text/html');
          const fresh = page.getElementById('routing-scan-dialog');
          if (!fresh || !fresh.querySelector('[name="scan_token"]').value || fresh.querySelector('[name="scan_token"]').value === previous)
            throw new Error(page.querySelector('.flash')?.textContent || 'Проверка не завершилась. Обновите страницу и повторите.');
          const summary = page.querySelector('.routing-scanner .routing-results');
          if (summary) document.querySelector('.routing-scanner .routing-results').replaceChildren(...summary.childNodes);
          if (dialog().close) dialog().close();
          dialog().replaceWith(fresh); busy = false; open();
        } catch (error) {
          progress.textContent = error.message || 'Проверка не выполнена. Повторите запрос.';
        } finally {busy = false; source.dataset.scanBusy = '0'; source.dispatchEvent(new Event('routing-scan-state')); source.querySelector('button').disabled = false; update();}
      });
      if (dialog().dataset.autoOpen === '1') open(); else update();
    })();</script>"""


def catalog_dialog(csrf: str, *, can_write: bool = True) -> str:
    """A paginated list of known targets; opening it never probes or changes rules."""
    escape = lambda value: html.escape(str(value), quote=True)
    disabled = "" if can_write else "disabled"
    return f'''<dialog id="routing-catalog-dialog" class="routing-catalog-dialog" aria-labelledby="routing-catalog-title" data-can-write="{1 if can_write else 0}">
      <header class="scan-dialog-head"><div><h2 id="routing-catalog-title">Каталог целей</h2><p>Все известные цели из ваших правил, списков и проверок — без повторов</p></div><button type="button" class="secondary" data-catalog-close aria-label="Закрыть каталог">Закрыть</button></header>
      <p class="muted">Это каталог подключённых списков, а не всех доменов Интернета. Поиск не сканирует сеть. Для замера выберите до 24 доменов, поддоменов или публичных IP.</p>
      <div class="catalog-search"><label>Поиск домена, поддомена или IP<input type="search" id="routing-catalog-search" maxlength="160" placeholder="Домен, поддомен или IPv4 / IPv6…" autocomplete="off"></label><label>Тип<select id="routing-catalog-kind"><option value="">Все типы</option><option value="domain">Домены и поддомены</option><option value="ip">Публичные IP (все)</option><option value="ipv4">Публичные IPv4</option><option value="ipv6">Публичные IPv6</option><option value="cidr">IP-сети (CIDR)</option></select></label></div>
      <p id="routing-catalog-status" class="scan-progress" role="status" aria-live="polite">Откройте каталог для загрузки списка.</p>
      <div class="catalog-pickbar"><label class="scan-select-all"><input type="checkbox" id="routing-catalog-select-all" {disabled}> Выбрать доступные на странице</label><button type="button" id="routing-catalog-clear" class="secondary" {disabled}>Снять выбор</button></div>
      <div class="scan-table-wrap"><table class="catalog-table"><thead><tr><th>Цель</th><th>Тип</th><th>Источник</th><th>TCP/443 с VDS</th></tr></thead><tbody id="routing-catalog-rows"><tr><td colspan="4">Список пока не загружен.</td></tr></tbody></table></div>
      <div class="catalog-pagination"><button type="button" id="routing-catalog-prev" class="secondary" disabled>← Назад</button><span id="routing-catalog-page" role="status">По 50 целей на странице</span><button type="button" id="routing-catalog-next" class="secondary" disabled>Далее →</button></div>
      <details class="catalog-notes"><summary>О замерах и IP-сетях</summary><p class="muted">CIDR — диапазон адресов: его нельзя измерить как один сервер, поэтому выбор сети для TCP-проверки недоступен. Неизмеренная цель не считается рабочей. Задержка VDS не равна пингу телефона; публикация маршрутов выполняется отдельно.</p></details>
      <footer class="scan-dialog-actions"><span id="routing-catalog-selection" role="status">Выбрано: 0 / 24</span><button type="button" id="routing-catalog-scan" disabled>Проверить выбранные</button></footer>
      <details class="catalog-import"><summary>Добавить свой список TXT</summary><p class="muted">До 1 МБ, домены / публичные IP / CIDR через запятую или с новой строки. Импорт добавляет только записи каталога: он не создаёт и не публикует правила.</p><label>Файл списка<input type="file" id="routing-catalog-file" accept=".txt,text/plain" {disabled}></label><button type="button" id="routing-catalog-import" class="secondary" {disabled}>Импортировать в каталог</button><p id="routing-catalog-import-status" role="status" aria-live="polite"></p></details>
      <input type="hidden" id="routing-catalog-csrf" value="{escape(csrf)}">
    </dialog>'''


def catalog_dialog_css() -> str:
    return """
    .routing-catalog-dialog{width:min(1160px,calc(100vw - 32px));max-height:90vh;padding:20px;border:1px solid #40677e;border-radius:14px;background:#101f2e;color:#e1edf7;box-shadow:0 20px 100px #0009;overflow:auto}.routing-catalog-dialog:not([open]){display:none}.routing-catalog-dialog::backdrop{background:#030b16b8;backdrop-filter:blur(3px)}
    .catalog-search{display:grid;grid-template-columns:minmax(0,1fr) 220px;gap:12px}.catalog-search label{display:flex;flex-direction:column;gap:6px;font-size:12px;color:#b5ccde}.catalog-search input,.catalog-search select{width:100%;box-sizing:border-box}.catalog-pickbar,.catalog-pagination{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:12px 0}.catalog-pickbar .scan-select-all{margin:0}.catalog-pagination span{color:#a6bdcf;font-size:12px}.catalog-table{width:100%;min-width:650px}.catalog-table small{display:block;color:#a6bdcf;font-size:11px;margin-top:5px}.catalog-table .scan-pick span{max-width:300px}.catalog-table td{overflow-wrap:anywhere}.catalog-table td:first-child{min-width:210px}.catalog-import{margin-top:18px;border-top:1px solid #345063;padding-top:14px}.catalog-import summary{cursor:pointer;color:#84d9ff}.catalog-import input[type=file]{display:block;max-width:100%;margin:8px 0}.routing-catalog-dialog button:disabled{opacity:.5;cursor:not-allowed}.routing-catalog-dialog input[type=checkbox]{width:18px;height:18px;min-width:18px}
    .routing-catalog-dialog[open]{display:flex;flex-direction:column;gap:8px;height:min(820px,calc(100dvh - 32px));max-height:90dvh;box-sizing:border-box;overflow:hidden}.routing-catalog-dialog>.scan-dialog-head,.routing-catalog-dialog>.catalog-search,.routing-catalog-dialog>.scan-progress,.routing-catalog-dialog>.catalog-pickbar,.routing-catalog-dialog>.catalog-pagination,.routing-catalog-dialog>.scan-dialog-actions{flex-shrink:0}.routing-catalog-dialog>p{margin:0;font-size:12px;line-height:1.4}.routing-catalog-dialog .catalog-search label{margin:0}.routing-catalog-dialog .catalog-pickbar,.routing-catalog-dialog .catalog-pagination,.routing-catalog-dialog .scan-dialog-actions{margin:0}.routing-catalog-dialog .scan-table-wrap{flex:1;min-height:90px;overflow:auto;overscroll-behavior:contain}.routing-catalog-dialog thead{position:sticky;top:0;background:#172d3e;z-index:1}.catalog-import,.catalog-notes{flex-shrink:0;margin:0;padding-top:6px;max-height:25vh;overflow:auto}.catalog-notes summary{cursor:pointer;font-size:12px;color:#84d9ff}.catalog-notes p{font-size:12px;margin:6px 0}
    @media(max-width:640px){.routing-catalog-dialog{padding:14px;width:calc(100vw - 16px)}.catalog-search{grid-template-columns:1fr}.catalog-pickbar{align-items:flex-start;flex-wrap:wrap}.catalog-pagination{gap:8px}.catalog-pagination button{padding:8px}.catalog-pagination span{text-align:center}}
    """


def catalog_dialog_script() -> str:
    return r"""<script>(() => {
      const box = document.getElementById('routing-catalog-dialog');
      const source = document.getElementById('routing-scan-form');
      if (!box || !source) return;
      const get = id => box.querySelector('#routing-catalog-' + id);
      const rows = get('rows'), status = get('status'), chosen = new Map();
      const canWrite = box.dataset.canWrite === '1', pageSize = 50;
      let current = [], offset = 0, matched = 0, total = 0, maxScan = 24;
      let sequence = 0, controller = null, debounce = null, loading = false, importing = false, scanAvailable = true;
      const labels = {domain:'Домен / поддомен',ip:'Публичный IP',cidr:'IP-сеть (CIDR)'};
      const familyLabel = item => item.ip_version === 4 || item.ip_version === 6 ? 'IPv' + item.ip_version : 'IP';
      const typeLabel = item => item.kind === 'ip' ? 'Публичный ' + familyLabel(item) : (item.kind === 'cidr' ? familyLabel(item) + '-сеть (CIDR)' : (labels[item.kind] || 'Неизвестный тип'));
      const statusLabels = {ok:'Доступна',timeout:'TCP/443 не ответил',unresolved:'Нет публичного DNS',budget:'Истёк лимит проверки'};
      const sourceLabels = {policy:'Действующие правила',draft:'Черновик',manual:'Введено вручную',scan:'Проверенная цель',dns:'DNS проверенных целей',import:'Импорт TXT'};
      const sourceLabel = value => sourceLabels[value] || (String(value).startsWith('seed:') ? 'Каталог: ' + String(value).slice(5) : String(value));
      const key = item => item.kind + ':' + item.target;
      const node = (tag, content, css) => {
        const element = document.createElement(tag);
        if (content !== undefined) element.textContent = String(content);
        if (css) element.className = css;
        return element;
      };
      const available = item => canWrite && item.selectable === true && item.kind !== 'cidr';
      const update = () => {
        get('selection').textContent = 'Выбрано: ' + chosen.size + ' / ' + maxScan;
        get('scan').disabled = !canWrite || loading || importing || !scanAvailable || source.dataset.scanBusy === '1' || !chosen.size || chosen.size > maxScan;
        get('clear').disabled = !canWrite || !chosen.size;
        const eligible = current.filter(available), count = eligible.filter(item => chosen.has(key(item))).length;
        get('select-all').disabled = loading || !eligible.length;
        get('select-all').checked = !!eligible.length && count === eligible.length;
        get('select-all').indeterminate = count > 0 && count < eligible.length;
        get('prev').disabled = loading || offset <= 0;
        get('next').disabled = loading || offset + pageSize >= matched;
        rows.querySelectorAll('input[type="checkbox"]').forEach(input => {
          input.checked = chosen.has(input.dataset.targetKey);
          input.disabled = loading || !canWrite || input.dataset.selectable !== '1' || (!input.checked && chosen.size >= maxScan);
        });
      };
      const render = () => {
        rows.replaceChildren();
        if (!current.length) {
          const row = node('tr'), cell = node('td', 'Цели не найдены. Измените поиск или импортируйте свой список.');
          cell.colSpan = 4; row.append(cell); rows.append(row);
        }
        current.forEach(item => {
          const row = node('tr'), targetCell = node('td'), pick = node('label', undefined, 'scan-pick');
          const input = node('input'); input.type = 'checkbox';
          input.dataset.targetKey = key(item); input.dataset.selectable = available(item) ? '1' : '0';
          input.setAttribute('aria-label', 'Выбрать ' + item.target);
          const text = node('span'); text.append(node('b', item.target));
          if (item.kind === 'cidr') text.append(node('small', 'Диапазон, не отдельный сервер'));
          if (Array.isArray(item.addresses) && item.addresses.length)
            text.append(node('small', 'IP / DNS: ' + item.addresses.slice(0,8).map(address => typeof address === 'string' ? address : (address.address || '')).join(' · ')));
          pick.append(input, text); targetCell.append(pick);
          const sourceCell = node('td', Array.isArray(item.sources) ? item.sources.map(sourceLabel).join(' · ') : (item.sources ? sourceLabel(item.sources) : 'Не указан'));
          const measured = node('td');
          if (item.status === 'ok' && Number.isFinite(item.latency_ms) && item.latency_ms > 0)
            measured.append(node('span', item.latency_ms + ' мс', 'ok'));
          else measured.append(node('span', statusLabels[item.status] || 'Не измерено', item.status ? 'warn' : 'muted'));
          if (Number.isFinite(item.checked_at) && item.checked_at > 0)
            measured.append(node('small', 'Замер: ' + new Date(item.checked_at * 1000).toLocaleString('ru-RU',{timeZone:'Europe/Moscow'}) + ' МСК'));
          measured.append(node('small', 'Источник замера: VDS · TCP/443'));
          row.append(targetCell, node('td', typeLabel(item)), sourceCell, measured);
          rows.append(row);
        });
        get('page').textContent = matched ? (offset + 1) + '–' + Math.min(offset + current.length, matched) + ' из ' + matched.toLocaleString('ru-RU') : '0 результатов';
        update();
      };
      const load = async (reset = false) => {
        if (reset) offset = 0;
        if (controller) controller.abort();
        controller = new AbortController();
        const request = ++sequence;
        loading = true; status.textContent = 'Загружаем каталог…'; update();
        try {
          const query = new URLSearchParams({q:get('search').value.trim(),kind:get('kind').value,offset:String(offset),limit:String(pageSize)});
          const response = await fetch('/operator/routing/catalog?' + query, {credentials:'same-origin',cache:'no-store',signal:controller.signal});
          if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'Сессия истекла. Обновите страницу и войдите снова.' : 'Каталог недоступен. HTTP ' + response.status);
          const data = await response.json();
          if (request !== sequence) return;
          if (!Array.isArray(data.items) || !Number.isFinite(data.total) || !Number.isFinite(data.matched)) throw new Error('Не удалось прочитать каталог. Обновите страницу.');
          current = data.items.slice(0,pageSize).filter(item => item && typeof item.target === 'string' && ['domain','ip','cidr'].includes(item.kind));
          total = Math.max(0,data.total); matched = Math.max(0,data.matched);
          offset = Math.max(0,Number(data.offset) || 0);
          maxScan = Math.max(1,Math.min(24,Number(data.max_scan) || 24));
          scanAvailable = data.scan_available !== false;
          const workers = Number.isFinite(data.workers) ? data.workers : null;
          status.textContent = 'Всего уникальных целей: ' + total.toLocaleString('ru-RU') + ' · найдено: ' + matched.toLocaleString('ru-RU') + (workers !== null ? ' · одновременных проверок с учётом нагрузки VDS: ' + workers : '') + '. Сеть не сканировалась.' + (data.scan_warning ? ' ' + String(data.scan_warning) : '') + (data.catalog_warning ? ' ' + String(data.catalog_warning) : '');
          render();
        } catch (error) {
          if (error.name !== 'AbortError' && request === sequence) {current = []; matched = 0; render(); status.textContent = error.message || 'Каталог не загружен.';}
        } finally {if (request === sequence) {loading = false; update();}}
      };
      const close = () => {
        if (controller) controller.abort();
        ++sequence; loading = false; clearTimeout(debounce);
        if (box.close) box.close(); else box.removeAttribute('open');
        update();
      };
      document.addEventListener('click', event => {
        if (event.target.closest('[data-catalog-open]')) {
          if (!box.open) {if (box.showModal) box.showModal(); else box.setAttribute('open','');}
          load(); get('search').focus();
        }
        if (event.target.closest('[data-catalog-close]')) close();
      });
      box.addEventListener('cancel', event => {event.preventDefault(); close();});
      source.addEventListener('routing-scan-state', update);
      get('search').addEventListener('input', () => {clearTimeout(debounce); if (controller) controller.abort(); ++sequence; loading = true; update(); debounce = setTimeout(() => load(true),250);});
      get('kind').addEventListener('change', () => {clearTimeout(debounce); load(true);});
      get('prev').addEventListener('click', () => {offset = Math.max(0,offset - pageSize); load();});
      get('next').addEventListener('click', () => {offset += pageSize; load();});
      rows.addEventListener('change', event => {
        const input = event.target;
        if (loading || input.type !== 'checkbox') return;
        const item = current.find(candidate => key(candidate) === input.dataset.targetKey);
        if (!item || !available(item)) return;
        if (input.checked && chosen.size < maxScan) chosen.set(key(item),item);
        else chosen.delete(key(item));
        update();
      });
      get('select-all').addEventListener('change', event => {
        if (loading) return;
        current.filter(available).forEach(item => {
          if (!event.target.checked) chosen.delete(key(item));
          else if (chosen.size < maxScan) chosen.set(key(item),item);
        });
        update();
      });
      get('clear').addEventListener('click', () => {chosen.clear(); update();});
      get('scan').addEventListener('click', () => {
        if (source.dataset.scanBusy === '1') {status.textContent = 'Предыдущая проверка ещё выполняется. Дождитесь её завершения.'; update(); return;}
        if (loading || importing || !canWrite || !scanAvailable || !chosen.size || chosen.size > maxScan) return;
        const field = source.querySelector('[name="routing_scan_targets"]');
        if (!field) return;
        field.value = [...chosen.values()].map(item => item.target).join('\n');
        close();
        if (source.requestSubmit) source.requestSubmit(); else source.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
      });
      get('import').addEventListener('click', async () => {
        if (!canWrite || importing) return;
        const file = get('file').files[0], note = get('import-status');
        if (!file) {note.textContent = 'Выберите TXT-файл со списком.'; return;}
        if (file.size > 1024 * 1024) {note.textContent = 'Файл слишком большой. Максимум 1 МБ.'; return;}
        if (!window.confirm('Добавить записи только в каталог? Действующие маршруты и черновик не изменятся.')) return;
        importing = true; get('import').disabled = true; get('file').disabled = true; update();
        note.textContent = 'Импортируем список в каталог…';
        try {
          const text = await file.text();
          const response = await fetch('/operator/routing/catalog/import',{method:'POST',credentials:'same-origin',cache:'no-store',body:new URLSearchParams({csrf:get('csrf').value,targets:text})});
          if (!response.ok) {
            let detail = null;
            if (response.status === 400) {try {const rejected = await response.json(); detail = String(rejected.message || rejected.error || '').slice(0,500);} catch (_) {}}
            throw new Error(detail || (response.status === 413 ? 'Список слишком большой. Максимум 1 МБ.' : (response.status === 401 || response.status === 403 ? 'Сессия или подтверждение запроса недействительны. Обновите страницу.' : 'Импорт не выполнен. HTTP ' + response.status)));
          }
          const result = await response.json();
          if (result.ok === false) throw new Error(result.error || 'Импорт не выполнен.');
          note.textContent = 'Каталог обновлён. Добавлено: ' + (result.added ?? result.inserted ?? 0) + ' · уже в каталоге: ' + (result.existing ?? result.duplicates ?? 0) + ' · отклонено: ' + (result.rejected ?? result.invalid ?? 0) + '. Маршруты не изменены.';
          get('file').value = '';
          await load(true);
        } catch (error) {note.textContent = error.message || 'Импорт не выполнен. Повторите запрос.';}
        finally {importing = false; get('import').disabled = !canWrite; get('file').disabled = !canWrite; update();}
      });
      update();
    })();</script>"""
