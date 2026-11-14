// The shared page under its other provider: `gclone web`, the local viewer, in a real browser.
// The hosted viewer runs the same app.js through a seam (`window.gcloneProvider`); this checks
// that without one the page behaves as it did: the server's API and file addresses, places in
// history.state, download links with the `download` attribute, the PDF in a frame.
//
//   node worker/test/e2e/local.mjs [chrome] [webkit] [firefox]      (default: chrome)
//
// A directory vault written by the native binary (GCLONE_BIN), served by `gclone web
// --no-browser` of the same binary on a loopback port. Nothing real is involved.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ENGINES, loadPlaywright } from './harness.mjs';
import { MANY, beforePhone, timeMachine, timeMachinePhone } from './timemachine.mjs';
import { BIDI_DIR, BIDI_NAME, ODD_NAMES, addHistory, buildVault } from './vault.mjs';

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-viewer-local-'));
const vault = buildVault(work, { many: 30 });

/** Starts `gclone web --no-browser` over `of`; resolves to `{ link, stop }` once it printed its link. */
function startViewer(of = vault) {
  const child = spawn(of.bin, ['web', '--no-browser'], { env: of.device.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`gclone web printed no link:\n${out}`)), 20000);
    const read = (chunk) => {
      out += chunk;
      const match = /http:\/\/127\.0\.0\.1:\d+\/\?k=[A-Za-z0-9_-]+/.exec(out);
      if (match) {
        clearTimeout(timer);
        resolve({ link: match[0], stop: () => new Promise((done) => { child.once('exit', done); child.kill('SIGINT'); }) });
      }
    };
    child.stdout.on('data', read);
    child.stderr.on('data', read);
    child.once('exit', (code) => reject(new Error(`gclone web ended with ${code}:\n${out}`)));
  });
}

async function run(engine, playwright) {
  const viewer = await startViewer();
  const browser = await ENGINES[engine](playwright);
  const label = `${engine} ${browser.version()}`;
  const problems = [];
  try {
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`pageerror: ${e}`));
    await page.goto(viewer.link);
    await page.waitForSelector('#rows .row');
    const base = page.url();
    assert.match(base, /^http:\/\/127\.0\.0\.1:\d+\/s-[A-Za-z0-9_-]+\/$/, 'the page lives under its session prefix');
    assert.equal(await page.evaluate(() => window.gcloneProvider), undefined, 'no provider is set: the page uses its own');
    const names = () => page.$$eval('#rows .row .name', (nodes) => nodes.map((n) => n.title));
    assert.deepEqual(await names(), ['bin', 'deep', 'docs', 'many', 'media', 'names', 'pics', 'README.md']);
    // (The list draws its rows anew when it has news: a row that went away is looked up again.)
    const row = async (name) => {
      for (let attempt = 0; ; attempt += 1) {
        const handle = await page.evaluateHandle((wanted) => [...document.querySelectorAll('#rows .row')].find((r) => r.querySelector('.name').title === wanted) || null, name);
        try {
          await handle.asElement().click({ timeout: 2000 });
          return;
        } catch (error) {
          if (attempt >= 5) throw error;
        }
      }
    };
    const listed = (dir, n) => page.waitForFunction(([d, count]) => document.querySelector('#crumbs [aria-current]').title === d && document.getElementById('count').textContent === (count === 1 ? '1 item' : `${count} items`), [dir, n]);
    const info = await page.evaluate(async () => (await fetch('api/info')).json());
    assert.equal(info.backend, 'dir');
    assert.equal(info.files, vault.files.size);
    assert.equal(info.head, undefined, 'the local summary has no head field');

    // Places are in history.state, as before the seam: the place itself, a depth, a flag.
    await row('docs');
    await listed('docs', 5);
    assert.deepEqual(await page.evaluate(() => history.state), { dir: 'docs', depth: 1, began: false });
    await row('notes.txt');
    await page.waitForSelector('#viewer-body pre');
    assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), vault.files.get('docs/notes.txt').toString());
    assert.deepEqual(await page.evaluate(() => history.state), { file: 'docs/notes.txt', depth: 2, began: false });
    assert.equal(page.url(), base);
    assert.equal(await page.title(), 'gclone');
    // Files are addressed by the server's sealed ids, and download links carry `download`.
    const href = await page.getAttribute('#viewer-download', 'href');
    assert.match(href, /^file\?id=[A-Za-z0-9_%-]+&dl=1$/);
    assert.equal(await page.getAttribute('#viewer-download', 'download'), '');
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#viewer-download')]);
    const saved = path.join(work, `saved-${engine}`);
    await download.saveAs(saved);
    assert.ok(fs.readFileSync(saved).equals(vault.files.get('docs/notes.txt')));
    assert.equal(download.suggestedFilename(), 'notes.txt');
    // The PDF is in a frame (the hosted viewer keeps it out of its page; this provider does not).
    await page.click('#viewer-next');
    await page.waitForFunction(() => document.getElementById('viewer-name').title === 'page.html');
    await page.click('#viewer-next');
    await page.waitForFunction(() => document.getElementById('viewer-name').title === 'report.pdf');
    await page.waitForSelector('#viewer-body iframe');
    assert.match(await page.getAttribute('#viewer-body iframe', 'src'), /^file\?id=/);
    await page.keyboard.press('Escape');
    await page.waitForSelector('#viewer', { state: 'hidden' });
    assert.deepEqual(await page.evaluate(() => history.state), { dir: 'docs', depth: 1, began: false });
    // Back and forward, and a reload: the place is in the entry.
    await page.goBack();
    await listed('gclone', 8).catch(async () => assert.deepEqual(await names(), ['bin', 'deep', 'docs', 'many', 'media', 'names', 'pics', 'README.md']));
    await page.goForward();
    await listed('docs', 5);
    await page.reload();
    await page.waitForSelector('#rows .row');
    await listed('docs', 5);
    // A search, begun from inside the page, and its end.
    await page.fill('#search', 'leaf');
    await page.waitForFunction(() => document.getElementById('count').textContent === '1 match');
    assert.deepEqual(await page.evaluate(() => history.state), { search: 'leaf', depth: 2, began: true });
    await page.fill('#search', '');
    await listed('docs', 5);
    // Names that an address could trip over.
    await page.click('#brand');
    await listed('gclone', 8);
    await row('names');
    await listed('names', ODD_NAMES.length);
    for (const name of ODD_NAMES) {
      await row(name);
      await page.waitForFunction((wanted) => document.getElementById('viewer-name').title === wanted && !!document.querySelector('#viewer-body pre'), name);
      assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), vault.files.get(`names/${name}`).toString());
      await page.click('#viewer-close');
      await page.waitForSelector('#viewer', { state: 'hidden' });
    }
    // A name that turns its own end around (U+202E) is drawn in the order it has, with a mark
    // in the character's place, and saved under a name without it.
    await page.click('#brand');
    await listed('gclone', 8);
    assert.equal(BIDI_DIR, 'deep/a');
    await row('deep');
    await listed('deep', 1);
    await row('a');
    await listed('a', 2);
    const marked = BIDI_NAME.replace('\u202e', '\ufffd');
    assert.equal(await page.evaluate((wanted) => [...document.querySelectorAll('#rows .row .name')].find((n) => n.title === wanted).lastChild.textContent, BIDI_NAME), marked);
    await row(BIDI_NAME);
    await page.waitForFunction((wanted) => document.getElementById('viewer-name').title === wanted && !!document.querySelector('#viewer-body .card a.dl'), BIDI_NAME);
    assert.deepEqual(await page.evaluate(() => [document.getElementById('viewer-name').textContent, document.querySelector('#viewer-body .card h2').textContent, document.body.innerText.includes('\u202e')]), [marked, marked, false]);
    const [turned] = await Promise.all([page.waitForEvent('download'), page.click('#viewer-body .card a.dl')]);
    assert.equal(turned.suggestedFilename(), 'invoice_fdp.exe', `${label}: the name the browser saves under`);
    await turned.cancel().catch(() => {});
    await page.click('#viewer-close');
    await page.waitForSelector('#viewer', { state: 'hidden' });
    // An image, and the sort order.
    await page.click('#brand');
    await listed('gclone', 8);
    await row('pics');
    await listed('pics', 3);
    await row('photo.png');
    await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth === 480; });
    // A file that is shown carries no name: in a tab of its own neither the title nor the
    // address holds it (a title is written to the browser's history).
    const shownAs = await page.evaluate(async (u) => { const res = await fetch(u); await res.arrayBuffer(); return res.headers.get('content-disposition'); }, await page.getAttribute('#viewer-open', 'href'));
    assert.equal(shownAs, 'inline');
    assert.equal(await page.isVisible('#viewer-open'), true, 'the local viewer offers a tab of its own for every kind it shows');
    const [tab] = await Promise.all([context.waitForEvent('page'), page.click('#viewer-open')]);
    await tab.waitForLoadState('load');
    const inTab = { url: tab.url(), title: await tab.title() };
    await tab.close();
    assert.ok(!JSON.stringify(inTab).includes('photo'), `${label}: the image in a tab of its own left its name: ${JSON.stringify(inTab)}`);
    await page.click('#viewer-close');
    await page.click('#h-size button');
    await page.waitForFunction(() => document.querySelector('#rows .row .name').title === 'photo.png');
    await page.click('#h-name button');
    // (Firefox's own PDF viewer, in the frame, remarks on its layout.)
    assert.deepEqual(problems.filter((line) => !/Layout was forced before the page was fully loaded/.test(line)), [], `${label}: console`);
    console.log(`${label}: the local viewer (gclone web) behaves as before the seam: API and file ids of the server, places in history.state, download and PDF frame`);
    await context.close();
    await timeMachineLocal(browser, engine, label);
  } finally {
    await browser.close();
    await viewer.stop();
  }
}

/**
 * The time machine in the local viewer: the checks the hosted viewer gets (timemachine.mjs),
 * over a vault of its own with history — and here the places are in history.state, with the
 * moment and the version in them.
 */
async function timeMachineLocal(browser, engine, label) {
  const storied = buildVault(path.join(work, `storied-${engine}`), { many: MANY });
  const past = addHistory(storied);
  const viewer = await startViewer(storied);
  const problems = [];
  const watch = (page) => {
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`pageerror: ${e}`));
  };
  try {
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    watch(page);
    await page.goto(viewer.link);
    await page.waitForSelector('#rows .row');
    const api = (name, params) => page.evaluate(async ([n, p]) => {
      const res = await fetch(`api/${n}${p ? `?${new URLSearchParams(p)}` : ''}`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`${n}: ${res.status} ${await res.text()}`);
      return res.json();
    }, [name, params]);
    const download = async (click) => {
      const [saved] = await Promise.all([page.waitForEvent('download'), click()]);
      const file = path.join(work, `saved-${engine}-${Math.random().toString(16).slice(2)}`);
      await saved.saveAs(file);
      const bytes = fs.readFileSync(file);
      fs.rmSync(file);
      return { name: saved.suggestedFilename(), bytes };
    };
    await timeMachine({
      page, label, vault: storied, past, work: path.join(work, `storied-${engine}`), api, download,
      slowLists: async (ms) => {
        const calls = [];
        const lists = /\/api\/list\?/;
        const slowly = async (route) => {
          const asked = new URL(route.request().url()).searchParams;
          calls.push([asked.get('at'), asked.get('offset') || '0']);
          await new Promise((done) => { setTimeout(done, ms); });
          await route.continue();
        };
        await page.route(lists, slowly);
        return { calls: async () => calls, stop: () => page.unroute(lists, slowly) };
      },
      state: () => page.evaluate(() => history.state),
    });
    // The address and the title never changed, and nothing but the sort order is stored.
    assert.match(page.url(), /^http:\/\/127\.0\.0\.1:\d+\/s-[A-Za-z0-9_-]+\/$/);
    assert.equal(await page.title(), 'gclone');
    assert.deepEqual(await page.evaluate(() => [Object.keys(localStorage).filter((k) => k !== 'gclone.sort'), Object.keys(sessionStorage)]), [[], []]);
    // A reload in the past: the place — with its moment — is in the entry.
    await page.click('#time-btn');
    await page.waitForFunction(() => !document.getElementById('time-prev').disabled);
    await page.click('#time-prev');
    await page.waitForSelector('html.past');
    const at = await page.evaluate(() => history.state.at);
    assert.ok(Number.isInteger(at) && at > 0);
    await page.reload();
    await page.waitForFunction((wanted) => document.documentElement.classList.contains('past') && document.getElementById('list').dataset.at === String(wanted), at);
    assert.equal(await page.isVisible('#time-now'), true, 'the bar, and the way back, are there after a reload');
    await page.click('#time-now');
    await page.waitForSelector('html:not(.past)');
    assert.deepEqual(await page.evaluate(() => Object.keys(history.state).sort()), ['began', 'depth', 'dir']);
    // An entry whose moment is no time a clock can show (history.state is the browser's to
    // keep, and anyone's to forge): the present, and no error in the page.
    for (const at of [1e300, 9e18, 8640000000000001, -5, 12.5, '1700000000000']) {
      const shown = await page.$eval('#list', (list) => Number(list.dataset.n));
      await page.evaluate((forged) => {
        history.replaceState({ dir: 'docs', at: forged, depth: 0, began: false }, '');
        window.dispatchEvent(new PopStateEvent('popstate'));
      }, at);
      await page.waitForFunction((n) => {
        const list = document.getElementById('list');
        return Number(list.dataset.n) > n && list.dataset.at === 'now' && /items?/.test(document.getElementById('count').textContent);
      }, shown);
      assert.equal(await page.evaluate(() => document.documentElement.classList.contains('past')), false, `at = ${at}`);
      await page.evaluate(() => {
        history.replaceState({ dir: '', depth: 0, began: false }, '');
        window.dispatchEvent(new PopStateEvent('popstate'));
      });
      await page.waitForFunction((n) => Number(document.getElementById('list').dataset.n) > n + 1, shown);
    }
    // The viewer is read-only: a POST to the new routes is refused, by name.
    for (const route of ['versions?path=docs/notes.txt', 'deleted', 'timeline']) {
      const refused = await page.evaluate(async (r) => { const res = await fetch(`api/${r}`, { method: 'POST' }); return [res.status, res.headers.get('allow')]; }, route);
      assert.deepEqual(refused, [405, 'GET, HEAD'], route);
    }
    await context.close();

    beforePhone(storied);
    const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: engine !== 'firefox' });
    const small = await phone.newPage();
    watch(small);
    // A second page of the same session: the link works once, the cookie is the context's.
    const second = await startViewer(storied);
    try {
      await small.goto(second.link);
      await small.waitForSelector('#rows .row');
      await timeMachinePhone(small, label);
    } finally {
      // The page goes first: one that outlives its server reports a refused connection.
      await phone.close();
      await second.stop();
    }
    // (The refused POSTs above are the browser's to remark on; Firefox's PDF viewer has its own.)
    assert.deepEqual(problems.filter((line) => !/Layout was forced before the page was fully loaded|405|Method Not Allowed/.test(line)), [], `${label}: console`);
    console.log(`${label}: the time machine in the local viewer: versions, deleted files, earlier moments, the copied commands, keyboard, phone; places with their moment in history.state`);
  } finally {
    await viewer.stop();
  }
}

try {
  const playwright = await loadPlaywright();
  for (const engine of process.argv.slice(2).length ? process.argv.slice(2) : ['chrome']) await run(engine, playwright);
  console.log('OK');
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
