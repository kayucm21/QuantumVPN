"""Operator target-scan presentation. No probing, persistence or policy writes."""
from __future__ import annotations

import html


def scan_dialog(findings: list[dict], token: str, csrf: str, *, auto_open: bool = False,
                can_write: bool = True, reserve_available: bool = False, limit: int = 24) -> str:
    escape = lambda value: html.escape(str(value), quote=True)
    labels = {"proxy": "Через VPN", "direct": "Напрямую", "block": "Блок-лист", "observe": "Решение оператора"}
    statuses = {"ok": "Доступна", "timeout": "TCP/443 не ответил", "unresolved": "Нет публичного DNS-адреса",
                "budget": "Истёк лимит времени"}
    rows = []
    for index, item in enumerate(findings[:limit]):
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        target = str(item.get("target") or "")[:253]
        latency = item.get("latency_ms")
        latency_label = f"{latency} мс" if isinstance(latency, int) and latency > 0 else "Не измерена"
        ready = item.get("status") == "ok" and bool(token) and can_write
        recommendation = item.get("recommendation")
        default_direction = recommendation if recommendation in {"proxy", "direct", "block"} else "proxy"
        directions = ("proxy", "direct", "block") if kind == "domain" else ("proxy", "direct")
        options = "".join(f'<option value="{direction}" {"selected" if direction == default_direction else ""}>{labels[direction]}</option>'
                          for direction in directions)
        samples = []
        for sample in (item.get("addresses") or [])[:3]:
            if not isinstance(sample, dict):
                continue
            measured = sample.get("latency_ms")
            samples.append(escape(sample.get("address") or "") + " · " +
                           (f"{measured} мс" if isinstance(measured, int) and measured > 0 else "нет TCP-ответа"))
        backup = ("При сбое VPN проверить профиль «Резерв TLS» в APK; его путь здесь не измерялся."
                  if reserve_available else "Резерв TLS не настроен или выключен; запасной путь не измерялся.")
        rows.append(
            '<tr><td><label class="scan-pick">'
            f'<input type="checkbox" name="scan_selected" value="{index}" aria-label="Выбрать {escape(target)}" {"" if ready else "disabled"}>'
            f'<span><b>{escape(target)}</b><small>{"Домен / поддомен" if kind == "domain" else "Публичный IP"}</small></span></label></td>'
            f'<td><span class="{"ok" if ready else "warn"}">{escape(statuses.get(item.get("status"), "Нет данных"))}</span>'
            f'<small>TCP/443 с VDS: {escape(latency_label)}</small></td>'
            f'<td class="scan-addresses">{"<br>".join(samples) or "Адрес не получен"}</td>'
            f'<td><b>{escape(labels.get(recommendation, labels["observe"]))}</b><small>{escape(item.get("reason") or "")}</small>'
            f'<small class="scan-backup">{escape(backup)}</small></td>'
            f'<td><label>В черновик<select name="scan_direction_{index}" aria-label="Направление для {escape(target)}" {"" if ready else "disabled"}>{options}</select></label></td></tr>'
        )
    checked = max((int(item.get("checked_at") or 0) for item in findings if isinstance(item, dict)), default=0)
    table = ("".join(rows) or '<tr><td colspan="5">Введите конкретные цели и запустите проверку.</td></tr>')
    ready = bool(token) and can_write and any(item.get("status") == "ok" for item in findings if isinstance(item, dict))
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
        if (event.target.id === 'routing-scan-apply' && !dialog().querySelector('[name="scan_selected"]:checked')) {
          event.preventDefault(); update();
        }
      });
      source.addEventListener('submit', async event => {
        event.preventDefault(); if (busy) return;
        const previous = dialog().querySelector('[name="scan_token"]').value;
        busy = true; open();
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
        } finally {busy = false; source.querySelector('button').disabled = false; update();}
      });
      if (dialog().dataset.autoOpen === '1') open(); else update();
    })();</script>"""
