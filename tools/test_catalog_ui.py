"""Presentation guarantees for the known-target catalog (no network access)."""
import json
import shutil
import subprocess
import unittest
from html.parser import HTMLParser

from quantumvpn_target_scan import (
    catalog_dialog, catalog_dialog_css, catalog_dialog_script, scan_dialog_script,
)


class Markup(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = {}
        self.options = {}
        self.current_select = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.elements[attrs["id"]] = (tag, attrs)
        if tag == "select":
            self.current_select = attrs.get("id")
            self.options[self.current_select] = []
        elif tag == "option" and self.current_select:
            self.options[self.current_select].append(attrs.get("value", ""))

    def handle_endtag(self, tag):
        if tag == "select":
            self.current_select = None


class CatalogUITests(unittest.TestCase):
    def test_known_catalog_has_search_kind_pages_multiselect_and_import(self):
        page = catalog_dialog("token")
        parsed = Markup(page)
        for suffix in ("dialog", "search", "kind", "rows", "status", "page", "prev", "next",
                       "select-all", "selection", "clear", "scan", "file", "import", "csrf"):
            self.assertIn("routing-catalog-" + suffix, parsed.elements)
        self.assertIn("Каталог целей", page)
        self.assertIn("а не всех доменов Интернета", page)
        self.assertIn("Поиск не сканирует сеть", page)
        self.assertIn("не создаёт и не публикует правила", page)
        self.assertIn("выбор сети для TCP-проверки недоступен", page)
        self.assertIn("до 24", page)
        self.assertNotIn('action="/operator/routing"', page)
        self.assertEqual(parsed.options["routing-catalog-kind"], ["", "domain", "ip", "cidr"])
        self.assertEqual(parsed.elements["routing-catalog-search"][1]["maxlength"], "160")

    def test_csrf_is_escaped_and_viewer_cannot_enable_writes(self):
        page = catalog_dialog('" /><script>alert(1)</script>', can_write=False)
        self.assertNotIn("<script>alert(1)</script>", page)
        parsed = Markup(page)
        self.assertEqual(parsed.elements["routing-catalog-csrf"][1]["value"], '" /><script>alert(1)</script>')
        self.assertEqual(parsed.elements["routing-catalog-dialog"][1]["data-can-write"], "0")
        for suffix in ("file", "import", "scan", "select-all", "clear"):
            self.assertIn("disabled", parsed.elements["routing-catalog-" + suffix][1])

    def test_script_uses_safe_text_pagination_abort_and_bounded_review_flow(self):
        script = catalog_dialog_script()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("insertAdjacentHTML", script)
        self.assertIn("element.textContent", script)
        self.assertIn("new Map()", script)
        self.assertIn("new AbortController()", script)
        self.assertIn("request !== sequence", script)
        self.assertIn("setTimeout(() => load(true),250)", script)
        self.assertIn("limit:String(pageSize)", script)
        self.assertIn("Math.min(24", script)
        self.assertIn("chosen.size < maxScan", script)
        self.assertIn("item.kind !== 'cidr'", script)
        self.assertIn("data.scan_available !== false", script)
        self.assertIn("data.scan_warning", script)
        self.assertIn("IP / DNS: ", script)
        self.assertIn("sourceLabels", script)
        self.assertIn("result.existing", script)
        self.assertIn("source.requestSubmit()", script)
        self.assertIn("source.addEventListener('routing-scan-state', update)", script)
        self.assertIn("/operator/routing/catalog/import", script)
        self.assertIn("csrf:get('csrf').value", script)
        self.assertIn("file.size > 1024 * 1024", script)
        self.assertIn("window.confirm", script)
        self.assertNotIn("action:'publish'", script)
        self.assertIn("box.addEventListener('cancel'", script)
        self.assertIn(".join('\\n')", script)

    def test_scan_disables_previous_evidence_when_new_scan_starts(self):
        script = scan_dialog_script()
        self.assertIn("(busy || !dialog().querySelector", script)
        self.assertIn("control.disabled = true", script)
        self.assertIn("querySelector('[name=\"scan_token\"]').value = ''", script)

    def test_css_constrains_catalog_to_viewport(self):
        css = catalog_dialog_css()
        self.assertIn("max-height:90vh", css)
        self.assertIn("overflow:auto", css)
        self.assertIn("@media(max-width:640px)", css)
        self.assertIn("flex-direction:column", css)
        self.assertIn(".scan-table-wrap{flex:1;min-height:90px;overflow:auto", css)

    def test_generated_javascript_is_syntactically_valid(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node unavailable; live browser integration remains required")
        for generator in (catalog_dialog_script, scan_dialog_script):
            script = generator().removeprefix("<script>").removesuffix("</script>")
            checked = subprocess.run([node, "--check"], input=script, text=True, capture_output=True, timeout=15)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_catalog_browser_behavior_pages_search_selection_and_scan_handoff(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node unavailable; live browser integration remains required")
        script = catalog_dialog_script().removeprefix("<script>").removesuffix("</script>")
        harness = r'''
        const assert = require('node:assert/strict');
        class Element {
          constructor(tag) {this.tag = tag; this.children = []; this.dataset = {}; this.listeners = {}; this.disabled = false; this.checked = false; this.value = ''; this.textContent = ''; this.files = [];}
          append(...nodes) {this.children.push(...nodes);}
          replaceChildren(...nodes) {this.children = [...nodes];}
          setAttribute(name,value) {this[name] = value;}
          removeAttribute(name) {delete this[name];}
          addEventListener(name,handler) {(this.listeners[name] ||= []).push(handler);}
          fire(name,target = this) {(this.listeners[name] || []).forEach(handler => handler({target,preventDefault(){}}));}
          querySelectorAll() {const found = []; const walk = item => {if (item.tag === 'input' && item.type === 'checkbox') found.push(item); item.children.forEach(walk);}; this.children.forEach(walk); return found;}
          focus() {}
          showModal() {this.open = true;}
          close() {this.open = false;}
        }
        const names = ['rows','status','selection','search','kind','select-all','scan','clear','prev','next','page','csrf','file','import','import-status'];
        const elements = Object.fromEntries(names.map(name => [name,new Element(name)]));
        const box = new Element('dialog'); box.dataset.canWrite = '1'; box.querySelector = selector => elements[selector.replace('#routing-catalog-','')];
        elements.kind.value = DEFAULT_KIND; elements.csrf.value = 'safe-token';
        const source = new Element('form'), field = new Element('textarea');
        let submissions = 0; source.querySelector = () => field; source.requestSubmit = () => submissions++;
        const documentListeners = {};
        global.document = {getElementById:id => id === 'routing-catalog-dialog' ? box : source,createElement:tag => new Element(tag),addEventListener:(event,handler) => documentListeners[event] = handler};
        global.window = {confirm:() => true};
        const entry = (number,kind = 'domain') => ({target:'target' + number + '.example',kind,selectable:kind !== 'cidr',sources:['policy','Imported <img src=x>'],addresses:['1.1.1.1'],status:null,latency_ms:null,checked_at:null});
        let delayedResolve = null, calls = [];
        global.fetch = async (url,options) => {
          calls.push({url,options});
          if (options.method === 'POST') return {ok:true,json:async () => ({ok:true,added:2,duplicates:1,rejected:1})};
          const q = new URL('http://local' + url).searchParams;
          assert.ok(['','domain','ip','cidr'].includes(q.get('kind')), 'Backend rejects unsupported kind filter');
          const searched = q.get('q'), start = Number(q.get('offset'));
          const response = value => ({ok:true,json:async () => value});
          const result = {total:120,matched:120,offset:start,limit:50,max_scan:24,workers:2,items:Array.from({length:Math.min(50,120 - start)},(_,i) => entry(start + i, i === 49 ? 'cidr' : 'domain'))};
          if (searched === 'old') return await new Promise(resolve => delayedResolve = () => resolve(response({...result,matched:1,offset:0,items:[{...entry(1),target:'old.example'}]})));
          if (searched === 'overloaded') return response({...result,scan_available:false,scan_warning:'VDS перегружен. Повторите позже.'});
          if (searched) return response({...result,matched:1,offset:0,items:[{...entry(1),target:searched + '.example'}]});
          return response(result);
        };
        const flush = async () => {for (let i = 0; i < 6; i++) await new Promise(resolve => setImmediate(resolve));};
        eval(SCRIPT);
        (async () => {
          documentListeners.click({target:{closest:selector => selector === '[data-catalog-open]' ? {} : null}});
          await flush();
          assert.equal(box.open,true); assert.equal(elements.rows.children.length,50);
          assert.match(elements.status.textContent,/120/); assert.match(elements.status.textContent,/проверок.*2/);
          assert.match(elements.rows.children[0].children[0].children[0].children[1].children[1].textContent,/1\.1\.1\.1/);
          assert.match(elements.rows.children[0].children[2].textContent,/Действующие правила/);
          let inputs = elements.rows.querySelectorAll(); assert.equal(inputs[49].disabled,true);
          inputs[0].checked = true; elements.rows.fire('change',inputs[0]); assert.match(elements.selection.textContent,/1 \/ 24/);
          elements.next.fire('click'); await flush(); assert.match(elements.page.textContent,/51–100/);
          elements['select-all'].checked = true; elements['select-all'].fire('change');
          assert.match(elements.selection.textContent,/24 \/ 24/);
          elements.prev.fire('click'); await flush();
          inputs = elements.rows.querySelectorAll(); assert.equal(inputs[0].checked,true);
          elements.clear.fire('click'); assert.match(elements.selection.textContent,/0 \/ 24/);
          elements.search.value = 'old'; elements.kind.fire('change'); await flush();
          elements.search.value = 'new'; elements.kind.fire('change'); await flush();
          assert.equal(elements.rows.children[0].children[0].children[0].children[1].children[0].textContent,'new.example');
          delayedResolve(); await flush();
          assert.equal(elements.rows.children[0].children[0].children[0].children[1].children[0].textContent,'new.example');
          const chosen = elements.rows.querySelectorAll()[0]; chosen.checked = true; elements.rows.fire('change',chosen);
          source.dataset.scanBusy = '1'; source.fire('routing-scan-state');
          assert.equal(elements.scan.disabled,true);
          elements.scan.fire('click'); assert.equal(submissions,0); assert.match(elements.status.textContent,/ещё выполняется/);
          source.dataset.scanBusy = '0'; source.fire('routing-scan-state');
          assert.equal(elements.scan.disabled,false);
          elements.scan.fire('click'); assert.equal(submissions,1); assert.equal(field.value,'new.example'); assert.equal(box.open,false);
          elements.search.value = 'overloaded'; elements.kind.fire('change'); await flush();
          assert.equal(elements.rows.children.length,50); assert.equal(elements.scan.disabled,true); assert.match(elements.status.textContent,/VDS перегружен/);
          elements.scan.fire('click'); assert.equal(submissions,1);
          elements.file.files = [{size:9,text:async () => 'one.example\ntwo.example'}];
          elements.import.fire('click'); await flush();
          const posted = calls.find(item => item.options.method === 'POST');
          assert.equal(posted.url,'/operator/routing/catalog/import'); assert.equal(posted.options.body.get('csrf'),'safe-token');
          assert.match(elements['import-status'].textContent,/Добавлено: 2.*уже в каталоге: 1.*отклонено: 1/);
          assert.equal(submissions,1); console.log('behavior-ok');
        })().catch(error => {console.error(error); process.exitCode = 1;});
        '''.replace("SCRIPT", json.dumps(script)).replace("DEFAULT_KIND", json.dumps(Markup(catalog_dialog("csrf")).options["routing-catalog-kind"][0]))
        checked = subprocess.run([node, "-e", harness], text=True, capture_output=True, timeout=15)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("behavior-ok", checked.stdout)


if __name__ == "__main__":
    unittest.main()
