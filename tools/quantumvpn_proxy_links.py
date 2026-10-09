"""Validated owner-requested MTProto connection links and static controls.

This presentation helper has no filesystem, session, service or network access.
The controller must authorize the owner and verify an explicit CSRF-protected
POST before calling it, and return the result with no-store/no-referrer headers.
"""
from __future__ import annotations

import base64
import binascii
import html
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit


_KEYS = frozenset({"telegram", "https"})
_QUERY_KEYS = frozenset({"server", "port", "secret"})
_SECRET = re.compile(r"(?:[a-f0-9]{32}|dd[a-f0-9]{32})\Z", re.IGNORECASE)
_PORT = re.compile(r"[1-9][0-9]{0,4}\Z")
_WEB_PATH = re.compile(r"[a-z0-9_-]{8,64}\Z")
_WEB_SECRET = re.compile(r"[A-Za-z0-9_-]{23}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PRIVATE_DNS_SUFFIXES = (".local", ".localhost", ".internal", ".home", ".lan", ".invalid", ".test", ".example")


def _web_parameters(query: dict[str, str]) -> tuple[str, None, str]:
    parts = query["server"].split("/")
    if len(parts) != 2 or not _WEB_PATH.fullmatch(parts[1]):
        raise ValueError
    host = parts[0].lower()
    labels = host.split(".")
    if (not 1 <= len(host) <= 253 or len(labels) < 2 or not all(_DNS_LABEL.fullmatch(label) for label in labels)
            or host.endswith(_PRIVATE_DNS_SUFFIXES) or labels[-1].isdigit()):
        raise ValueError
    if host.encode("ascii").decode("idna").encode("idna").decode("ascii") != host:
        raise ValueError
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError
    secret = query["secret"]
    if not _WEB_SECRET.fullmatch(secret):
        raise ValueError
    decoded = base64.urlsafe_b64decode(secret + "=")
    if len(decoded) != 17 or decoded[0] != 0x70 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != secret:
        raise ValueError
    return host + "/" + parts[1], None, secret


def _link_parameters(value: str, variant: str, kind: str) -> tuple[str, int | None, str]:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValueError
    # urlsplit strips some leading/control whitespace. Refuse it beforehand,
    # so browsers and the server cannot interpret different destinations.
    if any(ord(char) <= 32 or ord(char) >= 127 for char in value):
        raise ValueError
    parts = urlsplit(value)
    endpoint = "proxy" if kind == "mtproto" else "webproxy"
    expected = ("tg", endpoint, "") if variant == "telegram" else ("https", "t.me", "/" + endpoint)
    if (parts.scheme, parts.netloc, parts.path) != expected or parts.fragment:
        raise ValueError
    keys = _QUERY_KEYS if kind == "mtproto" else frozenset({"server", "secret"})
    fields = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=len(keys))
    if len(fields) != len(keys) or {key for key, _ in fields} != keys:
        raise ValueError
    query = dict(fields)
    if kind == "web":
        return _web_parameters(query)
    address = ipaddress.ip_address(query["server"])
    if (not address.is_global or address.is_multicast or address.is_reserved
            or address.is_unspecified or address.is_loopback or address.is_link_local):
        raise ValueError
    port_text = query["port"]
    if not _PORT.fullmatch(port_text) or not 1 <= int(port_text) <= 65535:
        raise ValueError
    secret = query["secret"]
    if not _SECRET.fullmatch(secret):
        raise ValueError
    return address.compressed, int(port_text), secret.lower()


def validated_links(links: dict, *, kind: str = "mtproto") -> dict[str, str]:
    """Return only a matching canonical pair; reject with no credential data."""
    try:
        if kind not in {"mtproto", "web"} or type(links) is not dict or set(links) != _KEYS:
            raise ValueError
        telegram = _link_parameters(links["telegram"], "telegram", kind)
        https = _link_parameters(links["https"], "https", kind)
        if telegram != https:
            raise ValueError
        server, port, secret = telegram
        values = {"server": server, **({"port": port} if kind == "mtproto" else {}), "secret": secret}
        query = urlencode(values)
        endpoint = "proxy" if kind == "mtproto" else "webproxy"
        return {"telegram": "tg://" + endpoint + "?" + query, "https": "https://t.me/" + endpoint + "?" + query}
    except (ValueError, TypeError, KeyError, OverflowError, binascii.Error):
        raise ValueError("invalid_proxy_links") from None


def render_links(links: dict, *, kind: str = "mtproto") -> str:
    """Render links only after the controller has checked explicit owner access.

    Values stay in escaped DOM text/attributes, never in generated JavaScript.
    Hiding is a visual control, not revocation of the already revealed key.
    """
    safe = validated_links(links, kind=kind)
    telegram = html.escape(safe["telegram"], quote=True)
    https = html.escape(safe["https"], quote=True)
    prefix = "proxy-" + kind
    title = "Подключить Telegram · " + ("MTProto" if kind == "mtproto" else "WEBProxy")
    return f'''<section id="{prefix}-links" class="proxy-links" data-proxy-links aria-labelledby="{prefix}-title">
      <header class="proxy-links-heading"><h3 id="{prefix}-title">{title}</h3><button type="button" class="secondary" data-proxy-visibility aria-controls="{prefix}-values" aria-expanded="true">Скрыть ссылки</button></header>
      <p class="network-hint">Ссылки содержат ключ подключения. Передавайте их только доверенным пользователям. Скрытие не отзывает уже показанный ключ.</p>
      <div id="{prefix}-values" data-proxy-values>
        <label for="{prefix}-telegram-link">Ссылка для приложения Telegram</label>
        <textarea id="{prefix}-telegram-link" rows="2" readonly spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="Ссылка подключения Telegram">{telegram}</textarea>
        <div class="proxy-links-actions"><a class="network-button" href="{telegram}" rel="noreferrer noopener" referrerpolicy="no-referrer">Открыть Telegram</a><button type="button" class="secondary" data-proxy-copy="{prefix}-telegram-link">Копировать ссылку</button></div>
        <details class="proxy-links-share"><summary>HTTPS-ссылка для передачи</summary>
          <label for="{prefix}-https-link">Ссылка t.me</label><textarea id="{prefix}-https-link" rows="2" readonly spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="HTTPS-ссылка подключения Telegram">{https}</textarea>
          <div class="proxy-links-actions"><button type="button" class="secondary" data-proxy-copy="{prefix}-https-link">Копировать HTTPS-ссылку</button><a class="network-link" href="{https}" target="_blank" rel="noreferrer noopener" referrerpolicy="no-referrer">Открыть t.me</a></div>
        </details>
      </div>
      <p id="{prefix}-copy-status" class="network-hint proxy-copy-status" data-proxy-status role="status" aria-live="polite"></p>
    </section>'''


def render_connection_links(links: dict, *, kind: str = "mtproto") -> str:
    """Compatibility alias for controllers that name their link result explicitly."""
    return render_links(links, kind=kind)


def links_css() -> str:
    return """.proxy-links{margin-top:12px;padding:12px;border:1px solid var(--line,#25465e);border-radius:12px;min-width:0}.proxy-links-heading,.proxy-links-actions{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.proxy-links-heading h3{margin:0}.proxy-links label{display:block;margin:10px 0 5px;font-size:12px}.proxy-links textarea{width:100%;box-sizing:border-box;resize:vertical;font:12px/1.5 monospace;overflow-wrap:anywhere}.proxy-links-actions{justify-content:flex-start;margin-top:8px}.proxy-links-share{margin-top:12px}.proxy-links-share summary{cursor:pointer}.proxy-links [hidden]{display:none!important}.proxy-copy-status:empty{display:none}"""


def links_script() -> str:
    """Static delegated handlers also work for a subsequently inserted fragment."""
    return r'''<script>(() => {
      if (window.__quantumProxyLinksBound) return;
      window.__quantumProxyLinksBound = true;
      const allowed = new Set(['proxy-mtproto-telegram-link','proxy-mtproto-https-link','proxy-web-telegram-link','proxy-web-https-link']);
      const safeId = value => typeof value === 'string' && /^proxy-(?:mtproto|web)-[a-z0-9-]{1,48}$/.test(value);
      document.addEventListener('submit', async event => {
        const form = event.target;
        if (!form || typeof form.matches !== 'function' || !form.matches('form[data-proxy-reveal]')) return;
        event.preventDefault();
        if (form.dataset.proxyBusy === '1') return;
        const containerId = form.getAttribute('data-proxy-container'), statusId = form.getAttribute('data-proxy-status');
        if (!safeId(containerId) || !safeId(statusId) || containerId === statusId) return;
        const container = document.getElementById(containerId), status = document.getElementById(statusId);
        if (!container || !status) return;
        const data = new FormData(form), actions = data.getAll('action'), confirmations = data.getAll('csrf');
        if (form.getAttribute('action') !== '/operator/network/mtproto' || String(form.getAttribute('method')).toLowerCase() !== 'post'
            || actions.length !== 1 || !['links','web_links'].includes(actions[0])
            || confirmations.length !== 1 || typeof confirmations[0] !== 'string' || !confirmations[0]) {
          status.textContent = 'Запрос недействителен. Обновите страницу.'; return;
        }
        const prefix = actions[0] === 'links' ? 'proxy-mtproto-' : 'proxy-web-';
        if (!containerId.startsWith(prefix) || !statusId.startsWith(prefix)) return;
        const button = form.querySelector('button[type=submit],button:not([type])');
        const disabled = button ? button.disabled : false;
        form.dataset.proxyBusy = '1'; if (button) button.disabled = true;
        container.replaceChildren(); status.textContent = 'Загружаем ссылки…';
        let failure = 'Не удалось загрузить ссылки. Повторите запрос.';
        try {
          const response = await fetch('/operator/network/mtproto', {method:'POST',body:new URLSearchParams(data),
            credentials:'same-origin',cache:'no-store',redirect:'error',headers:{Accept:'application/json','X-QV-Request':'1'}});
          if (!response.ok) {
            if (response.status === 403 || response.status === 401) failure = 'Недостаточно прав или сессия истекла. Обновите страницу.';
            throw new Error();
          }
          const result = await response.json();
          if (!result || typeof result.html !== 'string' || !result.html.length || result.html.length >= 65536) throw new Error();
          // Only the authenticated fixed endpoint's validated server-rendered
          // fragment is inserted here; no target/model text becomes HTML.
          container.innerHTML = result.html;
          status.textContent = 'Ссылки готовы. Выберите действие ниже.';
        } catch (_) {container.replaceChildren(); status.textContent = failure;}
        finally {form.dataset.proxyBusy = '0'; if (button) button.disabled = disabled;}
      });
      const fallback = field => {
        const previous = document.activeElement;
        let copied = false;
        try {
          field.focus({preventScroll:true}); field.select();
          copied = typeof document.execCommand === 'function' && document.execCommand('copy') === true;
        } catch (_) {}
        if (copied && previous && typeof previous.focus === 'function') {
          try {previous.focus({preventScroll:true});} catch (_) {}
        }
        return copied;
      };
      document.addEventListener('click', async event => {
        const target = event.target;
        if (!target || typeof target.closest !== 'function') return;
        const button = target.closest('[data-proxy-copy], [data-proxy-visibility]');
        if (!button || button.disabled) return;
        const box = button.closest('[data-proxy-links]');
        if (!box) return;
        const status = box.querySelector('[data-proxy-status]');
        if (button.hasAttribute('data-proxy-visibility')) {
          const values = box.querySelector('[data-proxy-values]');
          if (!values) return;
          values.hidden = !values.hidden;
          button.setAttribute('aria-expanded', String(!values.hidden));
          button.textContent = values.hidden ? 'Показать ссылки' : 'Скрыть ссылки';
          if (status) status.textContent = '';
          return;
        }
        const id = button.getAttribute('data-proxy-copy');
        if (!allowed.has(id)) return;
        const field = box.querySelector('#' + id);
        if (!field || field.tagName !== 'TEXTAREA' || !field.readOnly || !field.value) return;
        button.disabled = true;
        let copied = false;
        try {
          if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            try {await navigator.clipboard.writeText(field.value); copied = true;} catch (_) {}
          }
          if (!copied) copied = fallback(field);
          if (status) status.textContent = copied ? 'Ссылка скопирована.' : 'Не удалось скопировать. Выделите ссылку и нажмите Ctrl+C.';
        } finally {button.disabled = false;}
      });
    })();</script>'''
