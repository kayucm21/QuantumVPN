"""Local Chromium regression tests for settings-loss warnings; no VDS access.

The fixture intercepts every HTTP request. Set QVPN_NODE_TEST_EXE and
QVPN_PLAYWRIGHT_MODULE when these dependencies are not installed system-wide.
The dependency-free checks still run without a browser runtime.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


SPEC = importlib.util.spec_from_file_location("unsaved_aurora", Path(__file__).with_name("quantumvpn_aurora.py"))
AURORA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AURORA)


class UnsavedSourceTests(unittest.TestCase):
    def test_only_one_guard_is_included_by_existing_shell(self):
        script = AURORA.aurora_unsaved_script()
        self.assertEqual(script.count("<script>"), 1)
        self.assertEqual(AURORA.aurora_script().count(script), 1)
        self.assertIn("auroraUnsavedReady", script)

    def test_no_persistence_network_or_field_value_messages(self):
        script = AURORA.aurora_unsaved_script()
        for forbidden in ("localStorage", "sessionStorage", "fetch(", "console.", "innerHTML", "JSON.stringify(state", "form.submit("):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, script)
        self.assertIn("note.setAttribute('role', 'status')", script)
        self.assertIn("note.setAttribute('aria-live', 'polite')", script)
        self.assertIn(".aurora-unsaved-status[hidden]", AURORA.aurora_css())


BROWSER_TEST = r"""
const assert = require('node:assert/strict');
const {chromium} = require(input.playwright);
const fixture = `<!doctype html><html><body><main class="panel-content">
<form id="first" method="post" action="/operator/policy"><h2>First settings</h2>
<input name="title" value="Original"><input name="csrf" type="hidden" value="hidden-secret">
<input name="readonly" readonly value="fixed"><input name="disabled" disabled value="fixed">
<button id="save">Save</button><button id="reset" type="reset">Reset</button></form>
<form id="second" method="post" action="/operator/policy"><input name="note" value="Old"><button id="save-second">Save second</button></form>
<form id="routing-policy" method="post" action="/operator/routing"><textarea name="routes">example.test</textarea><button id="save-routing">Save routing</button></form>
<input form="routing-policy" id="external-check" type="checkbox" name="enabled">
<select form="routing-policy" id="external-dns" name="dns"><option value="one">One</option><option value="two">Two</option></select>
<form id="routing-scan-form" method="post" action="/operator/routing"><textarea name="routing_scan_targets"></textarea><button>Scan</button></form>
<form method="post" action="/operator/network/mtproto" data-proxy-reveal><input name="link" value=""><button>Reveal</button></form>
<form id="search-form" method="get" action="/operator"><input name="q"><button>Find</button></form>
<form id="upload" method="post" action="/operator/upload"><input id="apk" type="file" name="apk"><button>Upload</button><button id="reset-file" type="reset">Reset</button></form>
<form id="action" method="post" action="/operator/actions"><input type="hidden" name="action" value="run"><button id="run">Run</button></form>
<a id="leave" href="/operator?tab=other">Other tab</a>
<a id="blank" target="_blank" href="/operator?tab=other">Open tab</a>
<a id="download" download="empty.txt" href="/operator/download">Download</a>
</main>${input.script}</body></html>`;
let checks = 0;
const check = (actual, expected, message) => {assert.deepEqual(actual, expected, message); checks++;};
const browser = await chromium.launch({channel: process.env.QVPN_BROWSER_CHANNEL || (process.platform === 'win32' ? 'chrome' : undefined), headless:true});
const context = await browser.newContext({acceptDownloads:true});
await context.route('**/*', route => route.fulfill({status:200, contentType:'text/html', body:fixture}));
const fresh = async () => {
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:9876/operator');
  await page.waitForSelector('[data-aurora-unsaved-ready=true]');
  return page;
};
const warning = page => page.evaluate(() => {
  const event = new Event('beforeunload', {cancelable:true});
  window.dispatchEvent(event); return event.defaultPrevented;
});
const note = (page, id) => page.locator('#'+id+' .aurora-unsaved-status').isVisible();
try {
  let page = await fresh();
  check(await warning(page), false, 'Initial settings do not warn');
  check(await page.locator('.aurora-unsaved-status').count(), 4, 'Only four editable configuration forms tracked');
  await page.locator('[name=title]').fill('Edited');
  check(await note(page,'first'), true, 'Edited settings have an accessible status');
  await page.addScriptTag({content:input.script.replace(/^<script>/,'').replace(/<\/script>$/,'')});
  check(await page.locator('.aurora-unsaved-status').count(),4,'Duplicate initialization adds no status or baseline reset');
  check(await warning(page), true, 'Edited settings warn before leaving');
  const notice = await page.locator('#first .aurora-unsaved-status').innerText();
  check(notice.length > 20 && !notice.includes('Edited') && !notice.includes('hidden-secret'), true, 'Message contains no value');
  await page.locator('[name=title]').fill('Original');
  check(await warning(page), false, 'Undo clears warning');
  await page.locator('[name=title]').fill('Again');
  await page.locator('#reset').click();
  check(await warning(page), false, 'Reset restores loaded baseline');
  await page.evaluate(() => {
    for (const name of ['csrf','readonly','disabled']) {
      const input = document.querySelector('[name='+name+']'); input.value = 'Changed';
      input.dispatchEvent(new Event('input',{bubbles:true}));
    }
  });
  check(await warning(page), false, 'Hidden tokens and readonly/disabled fields are excluded');
  await page.locator('#routing-scan-form textarea').fill('scanner.test');
  await page.locator('[data-proxy-reveal] input').fill('temporary');
  await page.locator('#search-form input').fill('search');
  check(await warning(page), false, 'Scanner, reveal and GET search are transient');
  await page.locator('#external-check').check();
  check(await note(page,'routing-policy'), true, 'Externally associated checkbox is tracked');
  await page.locator('#external-check').uncheck();
  await page.locator('#external-dns').selectOption('two');
  check(await warning(page), true, 'Externally associated select is tracked');
  await page.locator('#external-dns').selectOption('one');
  check(await warning(page), false, 'Select undo clears warning');
  await page.locator('#apk').setInputFiles({name:'fixture.apk',mimeType:'application/octet-stream',buffer:Buffer.from('fixture')});
  check(await note(page,'upload'), true, 'Selected APK is tracked without reading content');
  await page.locator('#reset-file').click();
  check(await warning(page), false, 'Reset clears selected APK');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Cancel me');
  await page.evaluate(() => document.getElementById('first').addEventListener('submit', event => event.preventDefault()));
  await page.locator('#save').click();
  check(await warning(page), true, 'Prevented async submit does not clear changes');
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true})));
  check(await warning(page), true, 'bfcache pageshow preserves original baseline');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('');
  await page.evaluate(() => document.querySelector('[name=title]').required=true);
  await page.locator('#save').click();
  check(await warning(page), true, 'Invalid native form does not grant unload exemption');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Only this saved');
  let dialogs = 0;
  page.on('dialog', async dialog => {dialogs++; await dialog.dismiss();});
  await Promise.all([page.waitForURL('**/operator/policy'), page.locator('#save').click()]);
  check(dialogs, 0, 'Native save of the only dirty form has no loss warning');
  await page.close();

  page = await fresh();
  await page.route('**/operator/policy', async route => {
    await new Promise(resolve => setTimeout(resolve, 2200));
    await route.fulfill({status:200,contentType:'text/html',body:fixture});
  });
  await page.locator('[name=title]').fill('Slow save');
  let slowDialogs=0;
  page.on('dialog', async dialog=>{slowDialogs++;await dialog.accept();});
  await Promise.all([page.waitForURL('**/operator/policy'),page.locator('#save').click()]);
  check(slowDialogs, 0, 'Slow native POST does not produce a spurious loss warning');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('First changed');
  await page.locator('[name=note]').fill('Second changed');
  const blocked = page.waitForEvent('dialog');
  const click = page.locator('#save').click();
  const dialog = await blocked; check(dialog.type(), 'beforeunload', 'Other dirty form blocks native save navigation');
  await dialog.dismiss(); await click;
  check(await warning(page), true, 'Dismissed navigation consumes exemption and preserves both edits');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Stay on page');
  const go = page.waitForEvent('dialog');
  const nav = page.locator('#leave').click();
  const leaveDialog = await go; check(leaveDialog.type(), 'beforeunload', 'Ordinary tab navigation asks browser');
  await leaveDialog.dismiss(); await nav;
  check(await warning(page), true, 'Cancelled tab navigation remains dirty');
  let newTabDialogs=0;
  page.on('dialog', async d=>{newTabDialogs++;await d.dismiss();});
  const popupReady = page.waitForEvent('popup'); await page.locator('#blank').click();
  const popup = await popupReady; await popup.waitForLoadState(); await popup.close();
  check(newTabDialogs, 0, 'New-tab link does not prompt unnecessarily');
  check(await warning(page), true, 'New-tab link does not clear pending edits');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Downloading does not leave');
  let downloadDialogs=0;
  page.on('dialog',async dialog=>{downloadDialogs++;await dialog.dismiss();});
  const downloaded=page.waitForEvent('download'); await page.locator('#download').click();
  await downloaded;
  check(downloadDialogs,0,'Direct download does not prompt unnecessarily');
  check(await warning(page),true,'Direct download preserves settings');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Other action');
  const actionDialogReady = page.waitForEvent('dialog'); const actionClick = page.locator('#run').click();
  const actionDialog=await actionDialogReady; check(actionDialog.type(), 'beforeunload', 'Unrelated action form does not bypass edits');
  await actionDialog.dismiss(); await actionClick; await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Multi form');
  await page.evaluate(() => {
    const input=document.querySelector('[name=title]'); input.disabled=true;
    window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
  });
  check(await warning(page), true, 'Temporarily disabling an edited field does not hide changes');
  await page.close();

  page = await fresh();
  await page.locator('[name=title]').fill('Removed form');
  await page.evaluate(() => {
    document.getElementById('first').remove();
    const panel=document.querySelector('.panel-content');
    const form=document.createElement('form');form.id='replacement';form.method='post';form.action='/operator/policy';
    const field=document.createElement('input');field.name='replacement';field.value='Loaded';form.append(field);panel.append(form);
    panel.dispatchEvent(new Event('aurora:refresh'));
  });
  check(await warning(page),false,'Removed form is forgotten and replacement gets loaded baseline');
  await page.locator('[name=replacement]').fill('Changed replacement');
  check(await warning(page),true,'Refreshed configuration form is tracked');
  await page.locator('[name=replacement]').fill('Loaded');
  await page.evaluate(() => {
    const field=document.createElement('textarea');field.name='added';field.value='Initial';
    document.getElementById('replacement').append(field);
    document.querySelector('.panel-content').dispatchEvent(new Event('aurora:refresh'));
  });
  check(await warning(page),false,'New field gets baseline at explicit fragment refresh');
  await page.locator('[name=added]').fill('Changed added');
  check(await warning(page),true,'Newly refreshed field is tracked');
  await page.close();
  process.stdout.write(JSON.stringify({ok:true, assertions:checks, browser:'Chromium', externalRequests:0}));
} finally { await browser.close(); }
"""


class UnsavedBrowserTests(unittest.TestCase):
    def test_real_chromium_form_and_navigation_contract(self):
        node = os.environ.get("QVPN_NODE_TEST_EXE") or shutil.which("node")
        module = os.environ.get("QVPN_PLAYWRIGHT_MODULE", "playwright")
        if not node:
            self.skipTest("Node is not available; browser regression gate remains open")
        explicit_runtime = bool(os.environ.get("QVPN_NODE_TEST_EXE") or os.environ.get("QVPN_PLAYWRIGHT_MODULE"))
        probe = subprocess.run([node, "-e", "require.resolve(process.argv[1])", module],
                               text=True, encoding="utf-8", capture_output=True, timeout=10)
        if probe.returncode and not explicit_runtime:
            self.skipTest("Playwright is not installed; browser regression gate remains open")
        self.assertEqual(probe.returncode, 0, probe.stderr)
        request = json.dumps({"script": AURORA.aurora_unsaved_script(), "playwright": module, "test": BROWSER_TEST})
        # Keep argv ASCII on Windows. Static browser code and synthetic fixture
        # travel via stdin, never through shell interpolation or a live server.
        runner = "const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;new AsyncFunction('input','require',input.test)(input,require).catch(e=>{console.error(e);process.exit(1)});"
        completed = subprocess.run([node, "--input-type=commonjs", "-e", runner],
                                   input=request, text=True, encoding="utf-8", capture_output=True, timeout=120)
        if completed.returncode and not explicit_runtime and any(message in completed.stderr for message in (
                "Executable doesn't exist", "distribution 'chrome' is not found")):
            self.skipTest("Chromium is not installed; browser regression gate remains open")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["assertions"], 25)
        self.assertEqual(result["externalRequests"], 0)
        print(f"Chromium: {result['assertions']} assertions passed; fixture-only HTTP.")


if __name__ == "__main__":
    unittest.main()
