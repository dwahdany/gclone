// The README's picture of the time machine: a part of the demo vault of content.mjs — its
// documents, which need no ffmpeg — with some history, shown as it was before the last
// changes. A script of its own, so that the other pictures (viewer.mjs) are not shot again.
//
//   node worker/test/e2e/readme/timemachine.mjs <output directory>
//
// Needs what viewer.mjs needs, less ffmpeg: the native binary (GCLONE_BIN, else
// target/release), the built core (GCLONE_WEB_CORE_PKG, else web-core/pkg), playwright-core
// (GCLONE_PLAYWRIGHT_CORE) and Google Chrome. Nothing real is involved.
//
// Writes viewer-timemachine-<light|dark>.png. The binary has no clock to set: the history is
// made by runs a little over a second apart, so every change in the picture is minutes old.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FakeDrive } from '../fake-drive.mjs';
import { britishChrome, bundle, loadPlaywright } from '../harness.mjs';
import { ViewerServer } from '../server.mjs';
import { Device, PASS, nativeBinary } from '../vault.mjs';
import { makeDemo } from './content.mjs';

const out = path.resolve(process.argv[2] || 'shots');
fs.mkdirSync(out, { recursive: true });
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-readme-time-'));
const src = path.join(work, 'src');
// The files that are text, tables, drawings and PDFs: no photograph, no film, no sound.
await makeDemo(src, (rel) => rel.startsWith('Documents/') || ['notes.md', 'todo.txt', 'budget-2026.csv', 'floor-plan.pdf', 'garden-plan.svg'].includes(rel));

const vaultDir = path.join(work, 'store');
fs.mkdirSync(vaultDir);
const device = new Device(nativeBinary(), work, 'laptop');
device.env.GCLONE_KEYSTORE_TRIAL = '0';
device.login(vaultDir);
device.run('copy', src, ':');

// History: two files edited, a drawing deleted, a folder deleted, a file moved, a recipe
// edited — each a run of its own, at a time of its own.
const pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1100);
const edit = (rel, more) => fs.appendFileSync(path.join(src, rel), more);
pause();
edit('todo.txt', '- book the ferry for August\n');
edit('budget-2026.csv', '2026-11,groceries,412.80\n');
device.run('copy', src, ':');
pause();
device.run('rm', ':garden-plan.svg');
fs.rmSync(path.join(src, 'garden-plan.svg'));
pause();
device.run('rm', '-r', ':Documents/Travel');
fs.rmSync(path.join(src, 'Documents/Travel'), { recursive: true });
pause();
device.run('mv', ':notes.md', ':Documents/notes.md');
fs.renameSync(path.join(src, 'notes.md'), path.join(src, 'Documents/notes.md'));
pause();
edit('Documents/Recipes/sourdough.md', '\nNext time: a longer rest in the fridge.\n');
device.run('copy', src, ':');

const drive = new FakeDrive(vaultDir);
await drive.listen();
const server = new ViewerServer({ dist: bundle(work), drive, email: 'you@example.com' });
await server.listen();
const playwright = await loadPlaywright();
// (The date field is the browser's own control: British, like the dates the page writes.)
const browser = await britishChrome(playwright);

try {
  for (const scheme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: scheme, deviceScaleFactor: 2, locale: 'en-GB', timezoneId: 'UTC' });
    await context.addCookies([{ ...server.signIn(), url: server.origin, httpOnly: true, sameSite: 'Strict' }]);
    const page = await context.newPage();
    await page.goto(`${server.origin}/`);
    await page.waitForSelector('#shell[data-screen="unlock"]:not([hidden])');
    await page.fill('#unlock-pass', PASS);
    await page.click('#unlock-go');
    await page.waitForSelector('#rows .row');
    await page.waitForFunction(() => /files/.test(document.getElementById('summary').textContent));
    // The bar, then back through the five changes: the vault before the first of them.
    await page.click('#time-btn');
    await page.waitForFunction(() => !document.getElementById('time-prev').disabled);
    for (let i = 0; i < 5; i += 1) {
      const shown = await page.$eval('#list', (list) => list.dataset.at);
      await page.click('#time-prev');
      await page.waitForFunction((was) => {
        const list = document.getElementById('list');
        return list.dataset.at !== was && /^\d+$/.test(list.dataset.at) && /item/.test(document.getElementById('count').textContent);
      }, shown);
    }
    await page.mouse.move(0, 0);
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(out, `viewer-timemachine-${scheme}.png`) });
    await context.close();
  }
  console.log(`screenshots in ${out}`);
} finally {
  await browser.close();
  await server.close();
  await drive.close();
  fs.rmSync(work, { recursive: true, force: true });
}
