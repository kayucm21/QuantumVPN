"""Owner link presentation: validation, escaping and click-only clipboard use."""
import base64
import json
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from urllib.parse import urlencode

try:
    import quantumvpn_proxy_links as proxy_links
except ImportError:
    from tools import quantumvpn_proxy_links as proxy_links


def pair(server="150.241.96.191", port=3443, secret="dd" + "ab" * 16):
    query = urlencode({"server": server, "port": port, "secret": secret})
    return {"telegram": "tg://proxy?" + query, "https": "https://t.me/proxy?" + query}


def web_pair(server="pecaocek.ignorelist.com/quantum_test", secret=None):
    secret = secret if secret is not None else base64.urlsafe_b64encode(b"\x70" + b"\xab" * 16).decode().rstrip("=")
    query = urlencode({"server": server, "secret": secret})
    return {"telegram": "tg://webproxy?" + query, "https": "https://t.me/webproxy?" + query}


class Markup(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.elements = []
        self.ids = {}
        self.text = {}
        self.textarea = None
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if attrs.get("id"):
            self.ids.setdefault(attrs["id"], []).append((tag, attrs))
        if tag == "textarea":
            self.textarea = attrs.get("id")
            self.text[self.textarea] = ""

    def handle_data(self, data):
        if self.textarea:
            self.text[self.textarea] += data

    def handle_endtag(self, tag):
        if tag == "textarea":
            self.textarea = None


class ProxyLinksTests(unittest.TestCase):
    def test_canonical_pair_accepts_current_padded_and_unpadded_secrets(self):
        for secret in ("ab" * 16, "dd" + "ab" * 16, "DD" + "AB" * 16):
            with self.subTest(secret_length=len(secret)):
                self.assertEqual(proxy_links.validated_links(pair(secret=secret)), pair(secret=secret.lower()))

    def test_public_ipv6_is_canonical_and_parameters_may_be_ordered_differently(self):
        links = pair("2606:4700:4700:0:0:0:0:1111")
        links["https"] = "https://t.me/proxy?secret=" + "dd" + "ab" * 16 + "&port=3443&server=2606%3A4700%3A4700%3A%3A1111"
        self.assertEqual(proxy_links.validated_links(links), pair("2606:4700:4700::1111"))

    def test_rejects_mismatches_unknown_keys_duplicates_and_unsafe_destinations(self):
        good = pair()
        bad = [None, [], {}, {**good, "extra": "must-not-render"}, {"telegram": good["telegram"]},
               {**good, "https": pair(port=443)["https"]}, {**good, "https": pair(server="1.1.1.1")["https"]},
               {**good, "https": pair(secret="ac" * 16)["https"]}]
        suffixes = ("&unknown=x", "&port=3443", "#fragment", "&secret=x", "&server=1.1.1.1")
        bad.extend({**good, "telegram": good["telegram"] + suffix} for suffix in suffixes)
        bad.extend({**good, "https": good["https"].replace("https://t.me/proxy", destination)} for destination in (
            "http://t.me/proxy", "https://evil.example/proxy", "https://t.me.evil.example/proxy",
            "https://t.me:443/proxy", "https://user@t.me/proxy", "https://t.me/proxy/", "javascript:alert"))
        bad.extend({**good, "telegram": good["telegram"].replace("tg://proxy?", prefix)} for prefix in (
            "tg://evil?", "tg://proxy/?", "tg://user@proxy?", "tg://proxy:443?", "tg://proxy\n?"))
        bad.extend(pair(server) for server in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1",
                                               "::1", "fc00::1", "fe80::1", "ff02::1", "example.com", "[2606:4700:4700::1111]"))
        bad.extend(pair(port=port) for port in (0, -1, 65536, "03443", "443.0", " 443"))
        bad.extend(pair(secret=secret) for secret in ("", "dd", "ab" * 15, "gg" * 16, "ee" + "ab" * 16,
                                                       '"></textarea><script>must-not-render</script>'))
        bad.append({**good, "telegram": good["telegram"] + "x" * 513})
        for index, links in enumerate(bad):
            with self.subTest(case=index), self.assertRaisesRegex(ValueError, "^invalid_proxy_links$"):
                proxy_links.render_links(links)

    def test_fragment_has_escaped_readonly_values_and_only_fixed_copy_targets(self):
        links = pair()
        page = proxy_links.render_links(links)
        markup = Markup(page)
        self.assertNotIn("<script", page)
        self.assertNotIn("<form", page)
        self.assertIn("&amp;port=3443&amp;secret=", page)
        for field_id, key in (("proxy-mtproto-telegram-link", "telegram"), ("proxy-mtproto-https-link", "https")):
            self.assertEqual(len(markup.ids[field_id]), 1)
            tag, attrs = markup.ids[field_id][0]
            self.assertEqual(tag, "textarea")
            self.assertIn("readonly", attrs)
            self.assertNotIn("name", attrs)
            self.assertEqual(markup.text[field_id], links[key])
        copy_targets = [attrs["data-proxy-copy"] for _, attrs in markup.elements if "data-proxy-copy" in attrs]
        self.assertEqual(copy_targets, ["proxy-mtproto-telegram-link", "proxy-mtproto-https-link"])
        for tag, attrs in markup.elements:
            self.assertFalse(any(name.startswith("on") for name in attrs))
            if tag == "a":
                self.assertIn("noreferrer", attrs["rel"])
                self.assertIn("noopener", attrs["rel"])
                self.assertEqual(attrs["referrerpolicy"], "no-referrer")
        self.assertEqual(proxy_links.render_connection_links(links), page)

    def test_web_pair_has_exact_dns_basepath_and_marked_canonical_key(self):
        links = web_pair()
        self.assertEqual(proxy_links.validated_links(links, kind="web"), links)
        upper = web_pair("PECAOCEK.IGNORELIST.COM/quantum_test")
        self.assertEqual(proxy_links.validated_links(upper, kind="web"), links)
        self.assertEqual(proxy_links.validated_links(web_pair("xn--e1afmkfd.com/route_test"), kind="web"),
                         web_pair("xn--e1afmkfd.com/route_test"))
        self.assertNotIn("port=", proxy_links.render_links(links, kind="web"))
        self.assertEqual(proxy_links.render_connection_links(links, kind="web"), proxy_links.render_links(links, kind="web"))

    def test_web_rejects_wrong_endpoint_server_path_port_and_marked_key(self):
        links = web_pair()
        good_secret = base64.urlsafe_b64encode(b"\x70" + b"\xab" * 16).decode().rstrip("=")
        bad = [pair(), {**links, "telegram": links["telegram"] + "&port=443"},
               {**links, "telegram": links["telegram"] + "&secret=" + good_secret},
               {**links, "https": web_pair("another.example.org/quantum_test")["https"]},
               {**links, "https": web_pair(secret=base64.urlsafe_b64encode(b"\x70" + b"\xac" * 16).decode().rstrip("="))["https"]}]
        bad.extend(web_pair(server) for server in ("pecaocek.ignorelist.com", "pecaocek.ignorelist.com/short",
            "pecaocek.ignorelist.com:443/quantum_test", "pecaocek.ignorelist.com/UPPERCASE",
            "pecaocek.ignorelist.com/quantum_test/extra", "pecaocek.ignorelist.com/../quantum_test",
            "pecaocek.ignorelist.com/" + "a" * 65, "https://pecaocek.ignorelist.com/quantum_test",
            "127.0.0.1/quantum_test", "1.1.1.1/quantum_test", "[2606:4700:4700::1111]/quantum_test",
            "localhost/quantum_test", "proxy.local/quantum_test", "proxy.internal/quantum_test",
            "evil.test/quantum_test", "-bad.example.org/quantum_test", "bad_.example.org/quantum_test",
            "прокси.com/quantum_test", "xn--abc.example.org/quantum_test", "proxy.example.org./quantum_test", "user@proxy.example.org/quantum_test"))
        wrong_mark = base64.urlsafe_b64encode(b"\x71" + b"\xab" * 16).decode().rstrip("=")
        bad.extend(web_pair(secret=secret) for secret in ("", good_secret + "=", good_secret[:-1],
            good_secret + "x", wrong_mark, "!" * 23,
            base64.urlsafe_b64encode(b"\x70" + b"\xab" * 15).decode().rstrip("="),
            good_secret[:-1] + "t"))
        bad.extend({**links, "https": links["https"].replace("https://t.me/webproxy", prefix)} for prefix in (
            "https://evil.example/webproxy", "https://t.me/proxy", "http://t.me/webproxy", "https://t.me:443/webproxy"))
        for index, value in enumerate(bad):
            with self.subTest(case=index), self.assertRaisesRegex(ValueError, "^invalid_proxy_links$"):
                proxy_links.render_links(value, kind="web")
        for kind in ("WEB", "unsafe", "", None):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "^invalid_proxy_links$"):
                proxy_links.render_links(links, kind=kind)

    def test_both_profile_fragments_coexist_without_duplicate_ids(self):
        markup = Markup(proxy_links.render_links(pair()) + proxy_links.render_links(web_pair(), kind="web"))
        self.assertTrue(all(len(items) == 1 for items in markup.ids.values()))
        for kind, links in (("mtproto", pair()), ("web", web_pair())):
            for variant in ("telegram", "https"):
                self.assertEqual(markup.text[f"proxy-{kind}-{variant}-link"], links[variant])
            self.assertIn(f"proxy-{kind}-values", markup.ids)
            self.assertIn(f"proxy-{kind}-copy-status", markup.ids)
        self.assertEqual(len([item for item in markup.elements if "data-proxy-copy" in item[1]]), 4)

    def test_static_script_contains_no_link_values_storage_reads_or_logging(self):
        script = proxy_links.links_script()
        for forbidden in (pair()["telegram"], pair()["https"], web_pair()["telegram"], web_pair()["https"], "secret=", "readText", "localStorage", "sessionStorage",
                          "console.", "onclick="):
            self.assertNotIn(forbidden, script)
        self.assertIn("document.addEventListener('click'", script)
        self.assertIn("navigator.clipboard.writeText(field.value)", script)
        self.assertIn("document.execCommand('copy')", script)
        self.assertIn("allowed.has(id)", script)
        self.assertIn("values.hidden = !values.hidden", script)
        self.assertEqual(script.count("container.innerHTML = result.html"), 1)
        self.assertIn("result.html.length >= 65536", script)
        self.assertIn("credentials:'same-origin',cache:'no-store'", script)
        self.assertIn("'X-QV-Request':'1'", script)
        self.assertIn("[hidden]{display:none!important}", proxy_links.links_css())

    def test_generated_javascript_is_syntactically_valid(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node unavailable; browser integration still required")
        script = proxy_links.links_script().removeprefix("<script>").removesuffix("</script>")
        result = subprocess.run([node, "--check"], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_copy_is_click_only_with_denied_or_missing_clipboard_fallback_and_hide(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node unavailable; browser integration still required")
        script = proxy_links.links_script().removeprefix("<script>").removesuffix("</script>")
        harness = r'''
        const assert = require('node:assert/strict');
        let handler, writes = [], copies = 0, selections = 0, focuses = 0, restore = 0;
        const fields = {
          'proxy-mtproto-telegram-link': {tagName:'TEXTAREA',readOnly:true,value:'telegram-test-value',select(){selections++;},focus(){focuses++;}},
          'proxy-mtproto-https-link': {tagName:'TEXTAREA',readOnly:true,value:'https-test-value',select(){selections++;},focus(){focuses++;}},
          'proxy-web-telegram-link': {tagName:'TEXTAREA',readOnly:true,value:'web-telegram-test-value',select(){selections++;},focus(){focuses++;}},
          'proxy-web-https-link': {tagName:'TEXTAREA',readOnly:true,value:'web-https-test-value',select(){selections++;},focus(){focuses++;}},
        };
        const status = {textContent:''}, values = {hidden:false};
        const webStatus = {textContent:''}, webValues = {hidden:false};
        const boxes = Object.fromEntries(['mtproto','web'].map(kind => [kind,{querySelector:selector =>
          selector === '[data-proxy-status]' ? (kind === 'web' ? webStatus : status) :
          selector === '[data-proxy-values]' ? (kind === 'web' ? webValues : values) :
          selector.startsWith('#proxy-' + kind + '-') ? fields[selector.slice(1)] : null}]));
        global.window = {};
        global.document = {activeElement:{focus(){restore++;}},addEventListener:(event,fn) => {assert.ok(['click','submit'].includes(event));if(event === 'click') handler = fn;},execCommand:command => {assert.equal(command,'copy');copies++;return true;}};
        const setClipboard = clipboard => Object.defineProperty(global,'navigator',{value:{clipboard},configurable:true});
        setClipboard({writeText:async text => {writes.push(text);}});
        const button = (target,visibility = false,kind = 'mtproto') => ({disabled:false,attrs:{},textContent:'',
          closest:selector => selector === '[data-proxy-links]' ? boxes[target && target.startsWith('proxy-web-') ? 'web' : kind] : null,
          hasAttribute:name => visibility && name === 'data-proxy-visibility',
          getAttribute:name => name === 'data-proxy-copy' ? target : null,
          setAttribute(name,value){this.attrs[name] = value;}});
        const click = control => handler({target:{closest:selector => selector === '[data-proxy-copy], [data-proxy-visibility]' ? control : null}});
        eval(SCRIPT);
        (async () => {
          assert.equal(writes.length,0); assert.equal(copies,0); assert.equal(selections,0);
          const primary = button('proxy-mtproto-telegram-link'); await click(primary);
          assert.deepEqual(writes,['telegram-test-value']); assert.equal(copies,0); assert.equal(primary.disabled,false);
          assert.equal(status.textContent,'Ссылка скопирована.');
          const second = button('proxy-mtproto-https-link'); await click(second);
          assert.deepEqual(writes,['telegram-test-value','https-test-value']);
          await click(button('proxy-web-telegram-link')); await click(button('proxy-web-https-link'));
          assert.deepEqual(writes,['telegram-test-value','https-test-value','web-telegram-test-value','web-https-test-value']);
          assert.equal(webStatus.textContent,'Ссылка скопирована.');
          setClipboard({writeText:async () => {throw new Error('permission denied private data');}});
          await click(primary); assert.equal(copies,1); assert.equal(selections,1); assert.equal(focuses,1); assert.equal(restore,1);
          assert.equal(status.textContent,'Ссылка скопирована.');
          setClipboard(undefined); await click(second); assert.equal(copies,2);
          document.execCommand = () => {copies++;return false;};
          await click(primary); assert.match(status.textContent,/Не удалось скопировать/); assert.match(status.textContent,/Ctrl\+C/);
          assert.equal(primary.disabled,false); assert.equal(restore,2);
          document.execCommand = () => {throw new Error('private error');};
          await click(primary); assert.match(status.textContent,/Не удалось скопировать/); assert.equal(primary.disabled,false);
          delete document.execCommand; await click(primary); assert.match(status.textContent,/Не удалось скопировать/);
          const ignored = copies; await click(button('admin-password')); assert.equal(copies,ignored);
          primary.disabled = true; await click(primary); assert.equal(copies,ignored); primary.disabled = false;
          const visibility = button(null,true); await click(visibility);
          assert.equal(values.hidden,true); assert.equal(visibility.attrs['aria-expanded'],'false'); assert.equal(visibility.textContent,'Показать ссылки'); assert.equal(status.textContent,'');
          await click(visibility); assert.equal(values.hidden,false); assert.equal(visibility.attrs['aria-expanded'],'true');
          assert.equal(visibility.textContent,'Скрыть ссылки');
          await click(button(null,true,'web')); assert.equal(webValues.hidden,true); assert.equal(values.hidden,false);
          let resolve;
          setClipboard({writeText:() => new Promise(done => resolve = done)});
          const pending = click(primary); assert.equal(primary.disabled,true);
          await click(primary); resolve(); await pending; assert.equal(primary.disabled,false);
          const initialHandler = handler; eval(SCRIPT); assert.equal(handler,initialHandler);
          console.log('proxy-links-behavior-ok');
        })().catch(error => {console.error(error);process.exitCode = 1;});
        '''.replace("SCRIPT", json.dumps(script))
        result = subprocess.run([node, "-e", harness], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("proxy-links-behavior-ok", result.stdout)

    def test_reveal_is_explicit_fixed_origin_json_fetch_and_stays_in_current_page(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node unavailable; browser integration still required")
        script = proxy_links.links_script().removeprefix("<script>").removesuffix("</script>")
        harness = r'''
        const assert = require('node:assert/strict');
        const listeners = {}, calls = [], status = {textContent:''};
        const container = {html:'old-credential',cleared:0,replaceChildren(){this.html = '';this.cleared++;},set innerHTML(value){this.html = value;}};
        const submit = {disabled:false};
        const attrs = {action:'/operator/network/mtproto',method:'post','data-proxy-container':'proxy-mtproto-container','data-proxy-status':'proxy-mtproto-status'};
        const form = {dataset:{},fields:[['action','links'],['csrf','isolated-csrf']],matches:selector => selector === 'form[data-proxy-reveal]',getAttribute:name => attrs[name],querySelector:() => submit};
        global.window = {};
        global.document = {addEventListener:(event,handler) => listeners[event] = handler,getElementById:id => id === attrs['data-proxy-container'] ? container : id === attrs['data-proxy-status'] ? status : null};
        global.FormData = class extends URLSearchParams {constructor(form){super(form.fields);}};
        let response = {ok:true,status:200,json:async () => ({html:'<section data-proxy-links>validated-server-fragment</section>'})};
        global.fetch = async (url,options) => {calls.push({url,options});return response;};
        eval(SCRIPT);
        let prevented = 0;
        const fire = () => listeners.submit({target:form,preventDefault(){prevented++;}});
        (async () => {
          assert.equal(calls.length,0); assert.equal(container.html,'old-credential');
          await fire(); assert.equal(calls.length,1); assert.equal(prevented,1);
          assert.equal(calls[0].url,'/operator/network/mtproto');
          const options = calls[0].options;
          assert.equal(options.method,'POST'); assert.equal(options.credentials,'same-origin'); assert.equal(options.cache,'no-store');
          assert.equal(options.redirect,'error'); assert.equal(options.headers.Accept,'application/json'); assert.equal(options.headers['X-QV-Request'],'1');
          assert.equal(options.body.get('csrf'),'isolated-csrf'); assert.equal(options.body.getAll('action').length,1);
          assert.match(container.html,/validated-server-fragment/); assert.match(status.textContent,/Ссылки готовы/);
          assert.equal(submit.disabled,false); assert.equal(form.dataset.proxyBusy,'0');
          response = {ok:false,status:403,json:async () => {throw new Error('must not parse');}};
          await fire(); assert.equal(container.html,''); assert.match(status.textContent,/Недостаточно прав/); assert.equal(submit.disabled,false);
          response = {ok:true,status:200,json:async () => ({html:'x'.repeat(65536)})};
          await fire(); assert.equal(container.html,''); assert.match(status.textContent,/Не удалось загрузить/);
          response = {ok:true,status:200,json:async () => ({html:42})};
          await fire(); assert.equal(container.html,''); assert.match(status.textContent,/Не удалось загрузить/);
          response = {ok:true,status:200,json:async () => {throw new Error('private data');}};
          await fire(); assert.equal(container.html,''); assert.equal(status.textContent.includes('private'),false);
          const count = calls.length;
          attrs.action = 'https://evil.example/steal'; await fire(); assert.equal(calls.length,count); attrs.action = '/operator/network/mtproto';
          form.fields.push(['action','web_links']); await fire(); assert.equal(calls.length,count); form.fields.pop();
          attrs['data-proxy-container'] = 'admin-password'; await fire(); assert.equal(calls.length,count);
          attrs['data-proxy-container'] = 'proxy-web-container'; await fire(); assert.equal(calls.length,count);
          attrs['data-proxy-status'] = 'proxy-web-status'; form.fields[0][1] = 'web_links';
          response = {ok:true,status:200,json:async () => ({html:'<section data-proxy-links>web-server-fragment</section>'})};
          await fire(); assert.equal(calls.length,count + 1); assert.match(container.html,/web-server-fragment/);
          let resolve;
          global.fetch = (url,options) => {calls.push({url,options});return new Promise(done => resolve = done);};
          const pending = fire(); assert.equal(container.html,''); assert.equal(submit.disabled,true);
          const pendingCount = calls.length; await fire(); assert.equal(calls.length,pendingCount);
          resolve(response); await pending; assert.equal(submit.disabled,false); assert.equal(form.dataset.proxyBusy,'0');
          console.log('proxy-reveal-behavior-ok');
        })().catch(error => {console.error(error);process.exitCode = 1;});
        '''.replace("SCRIPT", json.dumps(script))
        result = subprocess.run([node, "-e", harness], text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("proxy-reveal-behavior-ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
