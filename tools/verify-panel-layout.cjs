// Local fixture only: no production credentials, writes, or external requests.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');

async function main() {
  const base = new URL(process.argv[2] || 'http://127.0.0.1:8772');
  assert.equal(base.protocol, 'http:');
  assert.equal(base.hostname, '127.0.0.1');
  assert.equal(base.username + base.password + base.search + base.hash, '');
  assert.equal(base.pathname, '/');
  const output = path.resolve(process.argv[3] || 'artifacts/quantum5-panel-preview');
  await fs.mkdir(output, { recursive: true });
  const channel = process.env.PLAYWRIGHT_BROWSER_CHANNEL;
  assert(!channel || ['chrome','msedge'].includes(channel));
  const browser = await chromium.launch({ headless: true, ...(channel ? {channel} : {}) });
  const results = [];
  try {
    for (const viewport of [{width:1280,height:720}, {width:390,height:844}]) {
      const context = await browser.newContext({ viewport,
        // The panel intentionally renders login with 200, not a Basic challenge.
        extraHTTPHeaders: {Authorization:'Basic ' + Buffer.from('preview:preview-local').toString('base64')},
        reducedMotion:'reduce' });
      try {
        await context.route('**/*', route => new URL(route.request().url()).origin === base.origin
          ? route.continue() : route.abort());
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const response = await page.goto(base.origin + '/operator?tab=dashboard', {waitUntil:'networkidle'});
        assert.equal(response.status(), 200);
        const labels = await page.locator('.aurora-nav > a').allTextContents();
        for (const label of ['Обзор','Сеть','Пользователи','Релизы','Игры','Система']) {
          assert(labels.some(text => text.includes(label)), label);
        }
        assert.equal(labels.length, 6);
        assert.equal(await page.locator('.aurora-nav > a[aria-current="page"]').count(), 1);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
        assert.equal(overflow, false, 'No whole-page horizontal overflow');
        await page.locator('.measurement-help > summary').click();
        assert.equal(await page.locator('.measurement-help').getAttribute('open'), '');
        await page.locator('.measurement-help > summary').click();
        assert.equal(await page.locator('.overview-secondary').getAttribute('open'), null);
        await page.locator('.overview-secondary > summary').click();
        assert.equal(await page.locator('.overview-secondary').getAttribute('open'), '');
        await page.locator('.overview-secondary > summary').click();
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({path:path.join(output, `dashboard-${viewport.width}.png`)});
        for (const tab of ['network','users','release','cards','integrations']) {
          await page.locator(`.aurora-nav > a[href="/operator?tab=${tab}"]`).click();
          await page.waitForURL(base.origin + '/operator?tab=' + tab);
          assert.equal(await page.locator('.aurora-nav > a[aria-current="page"]').count(), 1);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false, tab);
        }
        assert.deepEqual(errors, []);
        results.push({viewport, groups:labels.length, destinations:6, horizontalOverflow:false, pageErrors:0});
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  console.log(JSON.stringify({status:'Passed', source:'local fixture, not VDS', results, output}));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
