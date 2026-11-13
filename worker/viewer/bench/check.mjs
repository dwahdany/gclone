// The device test page, run once in desktop browsers: that it goes through its three cycles by
// itself (reloads included), reports to its server and reaches a verdict. What it says about a
// phone, only the phone can say.
//
//   node worker/viewer/bench/check.mjs [chrome] [webkit] [firefox]     (default: chrome)
//
// Needs worker/viewer/bench/pkg (see serve.mjs) and playwright-core (`npm ci` in worker/test/e2e, or
// GCLONE_PLAYWRIGHT_CORE).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { start } from './serve.mjs';

const engines = process.argv.slice(2).length ? process.argv.slice(2) : ['chrome'];
const results = [];
const log = console.log;
console.log = (line) => { if (String(line).startsWith('RESULT-BEGIN')) results.push(String(line)); else log(line); };
const server = await start(0, '127.0.0.1');
const origin = `http://127.0.0.1:${server.address().port}`;
// playwright-core: GCLONE_PLAYWRIGHT_CORE (the package's directory), else the copy the browser tests install
// (`npm ci` in worker/test/e2e), else by name.
const dir = process.env.GCLONE_PLAYWRIGHT_CORE;
const local = fileURLToPath(new URL('../../test/e2e/node_modules/playwright-core/index.mjs', import.meta.url));
const playwright = await import(dir ? pathToFileURL(path.join(dir, 'index.mjs')).href : fs.existsSync(local) ? pathToFileURL(local).href : 'playwright-core');
const launch = {
  chrome: () => playwright.chromium.launch({ headless: true, channel: 'chrome' }),
  webkit: () => playwright.webkit.launch({ headless: true }),
  firefox: () => playwright.firefox.launch({ headless: true }),
};
try {
  for (const engine of engines) {
    const browser = await launch[engine]();
    const page = await (await browser.newContext()).newPage();
    const problems = [];
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(m.text()); });
    page.on('pageerror', (e) => problems.push(String(e)));
    await page.goto(`${origin}/`);
    await page.click('#start');
    await page.waitForFunction(() => document.title === 'done', null, { timeout: 180000 });
    const text = await page.textContent('#out');
    assert.equal((text.match(/ok — derive \d+ ms, wasm memory 25\d MiB; index 100 MiB held/g) || []).length, 10, text);
    assert.equal((text.match(/^ {2}\d\. ok — \d+ ms, wasm memory 25\d MiB$/gm) || []).length, 3, text);
    assert.match(text, /RESULT: A and B pass: this device unlocks with Lock = reload, as the viewer is built\./);
    assert.deepEqual(problems.filter((line) => !/is not cross-origin isolated/.test(line)), [], `${engine}: console`);
    assert.ok(results.at(-1).includes('RESULT: A and B pass'), 'the page reported to its server');
    const times = [...text.matchAll(/derive (\d+) ms/g)].map((m) => Number(m[1]));
    log(`${engine} ${browser.version()}: cycles A (5 reloads), B (3 in one worker) and C (5 teardowns) ran by themselves; derivations ${Math.min(...times)}–${Math.max(...times)} ms`);
    await browser.close();
  }
  log('OK');
} finally {
  server.close();
}
