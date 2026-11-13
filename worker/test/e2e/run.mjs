// The hosted viewer, end to end, in real browsers (design §11): the built bundle served as
// the deployment serves it, a fake of the Worker's browser routes, and a fake Google Drive on
// another origin over a vault that the native `gclone` binary wrote. Everything is asserted by
// the script; a console error or a policy violation that a step did not announce fails it.
//
//   node worker/test/e2e/run.mjs [chrome] [webkit] [firefox]      (default: all three)
//
// Environment:
//   GCLONE_BIN                the native binary [default: target/release/gclone]
//   GCLONE_WEB_CORE_PKG       the built core    [default: web-core/pkg]
//   GCLONE_VIEWER_DIST        a built dist/ to test as it is [default: build one]
//   GCLONE_PLAYWRIGHT_CORE    the directory of the playwright-core package
//   PLAYWRIGHT_BROWSERS_PATH  Playwright's WebKit and Firefox
//   GCLONE_E2E_BIG            a large video (fixtures/make-big.sh): adds the streaming,
//                             throughput and byte-budget steps
//   GCLONE_E2E_ONLY           a comma-separated list of step names to run (after sign-in and unlock)
//
// Chrome is the installed Google Chrome. Nothing real is involved: no Google, no Cloudflare,
// no vault of anyone's.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ENGINES, loadPlaywright, startStack } from './harness.mjs';
import { BIDI_DIR, BIDI_NAME, HOSTILE_HTML, ODD_NAMES, PASS, foreignKeyfile, tree } from './vault.mjs';

const BIG = process.env.GCLONE_E2E_BIG || null;
const ONLY = process.env.GCLONE_E2E_ONLY ? process.env.GCLONE_E2E_ONLY.split(',') : null;
const MIB = 1024 * 1024;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The most the fake Drive may serve for the media steps with the large file (48.7 MiB), per
// engine, on macOS. Measured: the play 48.7 / 48.9 / 48.7 MiB (Chrome / WebKit / Firefox) —
// the file once; three seeks afterwards 1.1 / 0.8 / 0.0 MiB (what was played is still held).
const BYTE_BUDGET = {
  chrome: { play: 60 * MIB, seeks: 20 * MIB },
  webkit: { play: 64 * MIB, seeks: 24 * MIB },
  firefox: { play: 60 * MIB, seeks: 20 * MIB },
};

// Console lines that are an engine's own remarks and not about the viewer. WebKit notes, when
// something looks at `SharedArrayBuffer`, that the page is not cross-origin isolated: the
// viewer does not use shared memory and sends no COEP header on purpose (design §4.3).
const ENGINE_NOISE = [
  /is not cross-origin isolated because the Cross-Origin-Embedder-Policy header is missing/,
  // Firefox, now and then, about its own document for a vault file that is opened in a tab of its own (the file is
  // answered as text or as an image under `sandbox`; no script of the viewer runs there). Depends on timing.
  /Layout was forced before the page was fully loaded/,
];

/** Runs in every document before its scripts: what the page says and is told, and what its policy refused. */
function instrument() {
  // Once per document: an engine may run this again when a navigation ends as a download.
  if (window.__instrumented) return;
  window.__instrumented = true;
  const flagged = ['key', 'bundle', 'ticket', 'header', 'keys', 'master'];
  const describe = (value, depth = 0) => {
    if (value instanceof Uint8Array || value instanceof ArrayBuffer) return { bytes: value.byteLength };
    if (value === null || typeof value !== 'object' || depth > 6) return value;
    if (typeof MessagePort !== 'undefined' && value instanceof MessagePort) return { port: true };
    if (Array.isArray(value)) return value.map((item) => describe(item, depth + 1));
    const out = {};
    for (const [name, item] of Object.entries(value)) out[name] = describe(item, depth + 1);
    return out;
  };
  const names = (value, found = []) => {
    if (value && typeof value === 'object') {
      for (const [name, item] of Object.entries(value)) {
        if (flagged.includes(name)) found.push(name);
        names(item, found);
      }
    }
    return found;
  };
  window.__messages = [];
  window.__flagged = [];
  window.__bytes = [];
  const record = (way, data) => {
    const said = describe(data);
    window.__messages.push([way, JSON.stringify(said)]);
    for (const name of names(said)) window.__flagged.push(`${way}: ${name}`);
    const walk = (v) => {
      if (v && typeof v === 'object') {
        if (typeof v.bytes === 'number' && Object.keys(v).length === 1 && v.bytes > 0) window.__bytes.push(`${way}: ${v.bytes} bytes`);
        else Object.values(v).forEach(walk);
      }
    };
    walk(said);
  };
  window.__workers = [];
  const NativeWorker = window.Worker;
  window.Worker = class extends NativeWorker {
    constructor(url, options) {
      super(url, options);
      window.__workers.push(String(url));
      this.addEventListener('message', (event) => record('from worker', event.data));
    }

    postMessage(message, transfer) {
      record('to worker', message);
      return super.postMessage(message, transfer);
    }
  };
  if (window.ServiceWorker) {
    const post = ServiceWorker.prototype.postMessage;
    ServiceWorker.prototype.postMessage = function postMessage(message, transfer) {
      record('to service worker', message);
      return post.call(this, message, transfer);
    };
    navigator.serviceWorker.addEventListener('message', (event) => record('from service worker', event.data));
  }
  window.__violations = [];
  document.addEventListener('securitypolicyviolation', (event) => window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
  // What the list was last loaded with: the folder of the last `list` answer, or the search.
  window.__lists = 0;
  window.__listed = null;
  let provider;
  Object.defineProperty(window, 'gcloneProvider', {
    configurable: true,
    get: () => provider,
    set(value) {
      provider = value;
      const api = value.api;
      value.api = async (...args) => {
        const out = await api.apply(value, args);
        if (args[0] === 'list' || args[0] === 'search') {
          window.__listed = args[0] === 'list' ? (args[1] && args[1].path) || '' : `search:${args[1].q}`;
          window.__lists += 1;
        }
        return out;
      };
    },
  });
  window.__marks = [];
  window.addEventListener('message', (event) => { if (event.data === 'gclone-script-ran') window.__marks.push('message'); });
}

class Session {
  constructor(engine, playwright, stack) {
    this.engine = engine;
    this.playwright = playwright;
    this.stack = stack;
    this.problems = [];
    /** Patterns of console lines a step expects. */
    this.expected = [];
    /** Patterns a step expects for all of its parts (it removes them when it ends). */
    this.tolerated = [];
    this.notes = [];
  }

  note(text) {
    this.notes.push(text);
    console.log(`  ${this.engine}: ${text}`);
  }

  async launch() {
    this.browser = await ENGINES[this.engine](this.playwright);
    this.label = `${this.engine} ${this.browser.version()}`;
  }

  /** A new browser context with the instrumentation, and its first page. */
  async open(options = {}) {
    const context = await this.browser.newContext({ acceptDownloads: true, ...options });
    await context.addInitScript(instrument);
    // "Google": a navigation to the authorization address is not let out. The test takes the
    // address the page asked for and comes back to `/callback` itself, as Google's redirect would.
    await context.route('https://accounts.google.com/**', async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith('/o/oauth2/v2/auth')) this.lastAuthorization = url;
      await route.abort('aborted');
    });
    const page = await context.newPage();
    this.watch(page);
    return { context, page };
  }

  /** What a failed step leaves to look at: where each page is, and what was said. */
  async diagnose() {
    const lines = [];
    for (const context of this.browser.contexts()) {
      for (const page of context.pages()) {
        const state = await Promise.race([
          page.evaluate(() => ({
            url: location.href,
            screen: document.getElementById('shell') && !document.getElementById('shell').hidden ? document.getElementById('shell').dataset.screen : 'the file list',
            said: [...document.querySelectorAll('.problem:not([hidden]), #stop-text, #notice-text, #viewer-body .card')].map((n) => n.textContent).filter(Boolean),
          })).catch((error) => ({ error: String(error) })),
          sleep(3000).then(() => ({ error: 'the page does not answer' })),
        ]);
        lines.push(`page: ${JSON.stringify(state)}`);
      }
    }
    lines.push(`console: ${JSON.stringify(this.problems.slice(-12))}`);
    lines.push(`worker log: ${JSON.stringify(this.stack.server.log.slice(-12))}`);
    lines.push(`strays: ${JSON.stringify(this.stack.server.strays.slice(-6))}`);
    return lines.join('\n');
  }

  watch(page) {
    page.on('console', (message) => {
      if (['error', 'warning'].includes(message.type())) this.problems.push(`console ${message.type()}: ${message.text()} (${message.location().url || ''})`);
    });
    page.on('pageerror', (error) => this.problems.push(`pageerror: ${error}`));
  }

  /** Console lines that match are expected from here on (until `settle`). */
  expect(...patterns) {
    this.expected.push(...patterns);
  }

  /** Fails on console errors and policy violations that no step announced; then starts over. */
  async settle(page, what) {
    const violations = page && !page.isClosed() ? await page.evaluate(() => window.__violations.splice(0)).catch(() => []) : [];
    const unexpected = this.problems.filter((line) => ![...ENGINE_NOISE, ...this.tolerated, ...this.expected].some((pattern) => pattern.test(line)));
    const stray = violations.filter((line) => !this.expected.some((pattern) => pattern.test(line)));
    this.problems = [];
    this.expected = [];
    assert.deepEqual(unexpected, [], `${this.label}, ${what}: console`);
    assert.deepEqual(stray, [], `${this.label}, ${what}: policy violations`);
  }

  // --- the page, driven ------------------------------------------------------------------------

  async screen(page, name, timeout = 30000) {
    await page.waitForSelector(`#shell[data-screen="${name}"]:not([hidden])`, { timeout });
  }

  /** Clicks "Sign in with Google" and returns the authorization address the page went to. */
  async toGoogle(page) {
    this.lastAuthorization = null;
    await page.click('#signin-go');
    for (let i = 0; i < 100 && !this.lastAuthorization; i += 1) await sleep(50);
    assert.ok(this.lastAuthorization, `${this.label}: the page did not go to Google`);
    return this.lastAuthorization;
  }

  /** Where Google sends the browser after the consent: `/callback` with a code for that sign-in. */
  callback(asked) {
    const back = new URL(asked.searchParams.get('redirect_uri'));
    back.searchParams.set('state', asked.searchParams.get('state'));
    back.searchParams.set('code', this.stack.server.consent(asked.searchParams.get('state')));
    back.searchParams.set('iss', 'https://accounts.google.com');
    back.searchParams.set('scope', 'email openid https://www.googleapis.com/auth/drive.file');
    return back.href;
  }

  /** Signed in without the round trip: the session cookie of the fake Worker. */
  async signedIn(context, page) {
    const cookie = this.stack.server.signIn();
    await context.addCookies([{ ...cookie, url: this.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
    await page.goto(`${this.stack.origin}/`);
    await this.screen(page, 'unlock');
  }

  async unlock(page, pass = PASS) {
    await page.fill('#unlock-pass', pass);
    await page.click('#unlock-go');
    await page.waitForSelector('#rows .row', { timeout: 60000 });
  }

  /** A fresh context, signed in and unlocked. */
  async fresh(options) {
    const { context, page } = await this.open(options);
    await this.signedIn(context, page);
    await this.unlock(page);
    return { context, page };
  }

  api(page, name, params) {
    return page.evaluate(([n, p]) => window.gcloneProvider.api(n, p), [name, params]);
  }

  /** How many list answers the page has had: a navigation that loads a folder adds to it. */
  lists(page) {
    return page.evaluate(() => window.__lists);
  }

  /** Waits until the list shows the folder `dir`, loaded after `before` answers (see `lists`). */
  async waitListed(page, dir, before = -1) {
    await page.waitForFunction(([wanted, n]) => {
      const count = document.getElementById('count');
      return window.__lists > n && window.__listed === wanted && count && /item/.test(count.textContent) && !/loaded/.test(count.textContent);
    }, [dir, before]);
  }

  /** Clicks the row called `name`. (The list draws its rows anew when it has news: a row that went away is looked up again.) */
  async clickRow(page, name) {
    for (let attempt = 0; ; attempt += 1) {
      const row = await page.evaluateHandle((wanted) => [...document.querySelectorAll('#rows .row')].find((r) => r.querySelector('.name').title === wanted) || null, name);
      const element = row.asElement();
      assert.ok(element, `${this.label}: no row named ${JSON.stringify(name)}`);
      try {
        await element.click({ timeout: 2000 });
        return;
      } catch (error) {
        if (attempt >= 5) throw error;
      }
    }
  }

  /** From the vault's root into `dir`, by clicks. */
  async goDir(page, dir) {
    // At the root already: a click on the vault's name loads nothing anew.
    if (await page.evaluate(() => window.__listed) !== '') {
      const before = await this.lists(page);
      await page.click('#brand');
      await this.waitListed(page, '', before);
    }
    let at = '';
    for (const part of dir ? dir.split('/') : []) {
      const before = await this.lists(page);
      await this.clickRow(page, part);
      at = at ? `${at}/${part}` : part;
      await this.waitListed(page, at, before);
    }
  }

  /** Opens the file `name` of the folder that is shown; resolves when the viewer has its metadata. */
  async openFile(page, name) {
    await this.clickRow(page, name);
    await page.waitForFunction((wanted) => !document.getElementById('viewer').hidden && document.getElementById('viewer-name').title === wanted
      && document.getElementById('viewer-meta').textContent !== '', name);
  }

  async closeFile(page) {
    await page.click('#viewer-close');
    await page.waitForSelector('#viewer', { state: 'hidden' });
  }

  /** The address of the file in the viewer (`/v/<id>`), as the page uses it. */
  fileUrl(page) {
    return page.evaluate(() => document.getElementById('viewer-download').getAttribute('href').replace(/\?dl=1$/, ''));
  }

  ping(page) {
    return page.evaluate(() => new Promise((resolve) => {
      const listen = (event) => {
        if (event.data && event.data.type === 'pong') {
          navigator.serviceWorker.removeEventListener('message', listen);
          resolve(event.data);
        }
      };
      navigator.serviceWorker.addEventListener('message', listen);
      navigator.serviceWorker.controller.postMessage({ type: 'ping' });
    }));
  }

  /** Clicks a download control and returns `{ name, bytes }` of what the browser saved. */
  async download(page, click) {
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 120000 }), click()]);
    const file = path.join(this.stack.work, `download-${this.engine}-${crypto.randomBytes(4).toString('hex')}`);
    await download.saveAs(file);
    const bytes = fs.readFileSync(file);
    fs.rmSync(file);
    return { name: download.suggestedFilename(), bytes };
  }
}

// ------------------------------------------------------------------------------------------------
// Steps. Each gets the session and a page that is signed in and unlocked, at the vault's root.
// ------------------------------------------------------------------------------------------------

const steps = {};

steps.listing = async (s, page) => {
  const { vault } = s.stack;
  // The whole tree, through the page's provider, as `gclone tree` draws it.
  const rows = await page.evaluate(async () => {
    const out = [];
    const visit = async (dir) => {
      let offset = 0;
      for (;;) {
        const answer = await window.gcloneProvider.api('list', { path: dir, sort: 'name', order: 'asc', offset: String(offset), limit: '100' });
        for (const entry of answer.entries) {
          const p = dir ? `${dir}/${entry.name}` : entry.name;
          out.push({ path: p, dir: entry.dir });
          if (entry.dir) await visit(p);
        }
        offset += answer.entries.length;
        if (offset >= answer.total || answer.entries.length === 0) break;
      }
    };
    // (The test's own calls are not what the list shows: put its mark back.)
    const shown = window.__listed;
    await visit('');
    window.__listed = shown;
    return out;
  });
  assert.deepEqual(tree(rows), vault.device.lines('tree'), `${s.label}: the tree equals \`gclone tree\``);
  assert.deepEqual(rows.filter((r) => !r.dir).map((r) => r.path).sort(), [...vault.files.keys()].sort());
  // The rows of the root, as the page draws them: folders first, natural order.
  const drawn = await page.$$eval('#rows .row .name', (nodes) => nodes.map((n) => n.title));
  assert.deepEqual(drawn, ['bin', 'deep', 'docs', 'many', 'media', 'names', 'pics', 'README.md']);
  // The summary and the info panel: the same vault `gclone status` describes.
  const info = await s.api(page, 'info');
  assert.equal(info.head, vault.device.head(), `${s.label}: the head fingerprint`);
  assert.deepEqual([info.backend, info.device, info.read_only, info.files], ['drive', 'this browser', true, vault.files.size]);
  await page.click('#info-btn');
  const panel = await page.textContent('#info');
  assert.match(panel, /on Google Drive, encrypted/);
  assert.equal(await page.textContent('#session-head'), info.head);
  assert.equal(await page.textContent('#session-email'), s.stack.server.email);
  assert.equal(await page.textContent('#session-build'), s.stack.server.build);
  await page.keyboard.press('Escape');
  // A folder of 250 entries: paged, drawn as a window of rows, natural order.
  await s.goDir(page, 'many');
  assert.match(await page.textContent('#count'), /^250 items$/);
  const first = await page.$$eval('#rows .row .name', (nodes) => nodes.slice(0, 3).map((n) => n.title));
  assert.deepEqual(first, ['file-1.txt', 'file-2.txt', 'file-3.txt']);
  assert.ok(await page.$$eval('#rows .row', (nodes) => nodes.length) < 80, 'only the rows in view are in the document');
  await s.goDir(page, '');
  s.note(`listing: ${rows.length} entries equal \`gclone tree\`; head ${info.head}`);
};

steps.sort = async (s, page) => {
  await s.goDir(page, 'bin');
  const names = () => page.$$eval('#rows .row .name', (nodes) => nodes.map((n) => n.title));
  assert.deepEqual(await names(), ['archive.zip', 'empty.dat', 'pattern-3m.bin']);
  await page.click('#h-size button');
  await page.waitForFunction(() => document.getElementById('h-size').getAttribute('aria-sort') === 'descending' && document.querySelector('#rows .row .name').title === 'pattern-3m.bin');
  assert.deepEqual(await names(), ['pattern-3m.bin', 'archive.zip', 'empty.dat']);
  await page.click('#h-size button');
  await page.waitForFunction(() => document.querySelector('#rows .row .name').title === 'empty.dat');
  assert.deepEqual(await names(), ['empty.dat', 'archive.zip', 'pattern-3m.bin']);
  await page.click('#h-name button');
  await page.waitForFunction(() => document.getElementById('h-name').getAttribute('aria-sort') === 'ascending' && document.querySelector('#rows .row .name').title === 'archive.zip');
  // The order is this browser's to keep, and holds no name.
  assert.equal(await page.evaluate(() => localStorage.getItem('gclone.sort')), '{"key":"name","desc":false}');
  await s.goDir(page, '');
};

steps.search = async (s, page) => {
  const search = async (q) => {
    const before = await s.lists(page);
    await page.fill('#search', q);
    await page.waitForFunction(([wanted, n]) => window.__lists > n && window.__listed === `search:${wanted}` && /match/.test(document.getElementById('count').textContent), [q, before]);
    return page.$$eval('#rows .row', (nodes) => nodes.map((n) => [n.querySelector('.name').title, n.querySelector('.sub').title]));
  };
  assert.deepEqual(await search('leaf'), [['leaf.txt', 'deep/a/b/c/d']]);
  assert.deepEqual(await search('日本語'), [['ünïcödé — 日本語 🙂.txt', 'names']]);
  assert.deepEqual(await search('ÜNÏCÖDÉ'), [['ünïcödé — 日本語 🙂.txt', 'names']], 'case is folded');
  assert.deepEqual((await search('%20')).map((r) => r[0]), ['percent%20encoded%2Fslash.txt']);
  assert.deepEqual(await search('clip'), [['clip-faststart.mp4', 'media'], ['clip-moov-at-end.mp4', 'media']]);
  assert.deepEqual(await search('no such thing anywhere'), []);
  assert.equal(await page.textContent('#empty-title'), 'Nothing found');
  // A match opens over the results; closing it returns to them.
  await search('leaf');
  await s.openFile(page, 'leaf.txt');
  await page.waitForSelector('#viewer-body pre');
  assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), 'at the bottom\n');
  await s.closeFile(page);
  assert.equal(await page.inputValue('#search'), 'leaf');
  await page.fill('#search', '');
  await s.waitListed(page, '');
};

steps.names = async (s, page) => {
  const { vault } = s.stack;
  await s.goDir(page, 'names');
  const sorted = await page.$$eval('#rows .row .name', (nodes) => nodes.map((n) => n.title));
  assert.deepEqual([...sorted].sort(), [...ODD_NAMES].sort());
  for (const name of ODD_NAMES) {
    await s.openFile(page, name);
    await page.waitForSelector('#viewer-body pre');
    assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), vault.files.get(`names/${name}`).toString(), name);
    assert.equal(await page.textContent('#viewer-name'), name);
    // The address, the title and the entry of the session history hold nothing of the name.
    assert.equal(page.url(), `${s.stack.origin}/`);
    assert.equal(await page.title(), 'gclone');
    const url = await s.fileUrl(page);
    assert.match(url, /^\/v\/[A-Za-z0-9_-]{22}$/);
    // The name travels in the answer's Content-Disposition, encoded so that it cannot end the header.
    const headers = await page.evaluate(async (u) => {
      const res = await fetch(`${u}?dl=1`);
      await res.arrayBuffer();
      return { disposition: res.headers.get('content-disposition'), type: res.headers.get('content-type') };
    }, url);
    assert.equal(headers.type, 'application/octet-stream');
    assert.ok(headers.disposition.startsWith('attachment; filename="'), headers.disposition);
    const star = /filename\*=UTF-8''([^;]+)$/.exec(headers.disposition);
    assert.ok(star, headers.disposition);
    assert.equal(decodeURIComponent(star[1]), name);
    assert.ok(!/[\r\n]/.test(headers.disposition));
    await s.closeFile(page);
  }
  // One of them through the browser's own download: the bytes, and a name the browser derived.
  await s.openFile(page, ODD_NAMES[3]);
  const saved = await s.download(page, () => page.click('#viewer-download'));
  assert.ok(saved.bytes.equals(vault.files.get(`names/${ODD_NAMES[3]}`)));
  assert.equal(saved.name.normalize('NFC'), ODD_NAMES[3].normalize('NFC'));
  await s.closeFile(page);

  // A name that turns its own end around (U+202E): drawn in the order it has, with a mark
  // where the character is — never as "invoiceexe.pdf" — and saved under a name without it.
  const RLO = '\u202e';
  const marked = BIDI_NAME.replace(RLO, '\ufffd');
  assert.ok(BIDI_NAME.includes(RLO) && !marked.includes(RLO));
  await s.goDir(page, BIDI_DIR);
  const drawn = await page.evaluate((wanted) => {
    const row = [...document.querySelectorAll('#rows .row')].find((r) => r.querySelector('.name').title === wanted);
    return row ? { text: row.querySelector('.name').lastChild.textContent, icon: row.querySelector('.c-name use').getAttribute('href') } : null;
  }, BIDI_NAME);
  assert.deepEqual(drawn, { text: marked, icon: '#i-file' }, 'the row shows the name in its order, and the kind of what it is');
  await s.openFile(page, BIDI_NAME);
  await page.waitForSelector('#viewer-body .card');
  const shownNames = await page.evaluate(() => [document.getElementById('viewer-name').textContent, document.querySelector('#viewer-body .card h2').textContent, document.body.innerText.includes('\u202e')]);
  assert.deepEqual(shownNames, [marked, marked, false], `${s.label}: the name on the page`);
  const bidi = await page.evaluate(async (u) => {
    const res = await fetch(`${u}?dl=1`);
    await res.arrayBuffer();
    return res.headers.get('content-disposition');
  }, await s.fileUrl(page));
  assert.equal(bidi, 'attachment; filename="invoice_fdp.exe"; filename*=UTF-8\'\'invoice_fdp.exe');
  const asSaved = await s.download(page, () => page.click('#viewer-body .card a.dl'));
  assert.equal(asSaved.name, 'invoice_fdp.exe', `${s.label}: the name the browser saves under`);
  assert.ok(asSaved.bytes.equals(vault.files.get(`${BIDI_DIR}/${BIDI_NAME}`)));
  await s.closeFile(page);
  await s.goDir(page, '');
};

/** A frame of a video element, as a number: equal frames give equal numbers. */
const FRAME = `async (video) => {
  await new Promise((resolve) => {
    if (video.requestVideoFrameCallback) video.requestVideoFrameCallback(() => resolve());
    else requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    setTimeout(resolve, 1500);
  });
  const canvas = document.createElement('canvas');
  canvas.width = 64; canvas.height = 36;
  const g = canvas.getContext('2d', { willReadFrequently: true });
  g.drawImage(video, 0, 0, 64, 36);
  const data = g.getImageData(0, 0, 64, 36).data;
  let sum = 0;
  for (let i = 0; i < data.length; i += 4) sum = (Math.imul(sum, 31) + (data[i] >> 3) * 1024 + (data[i + 1] >> 3) * 32 + (data[i + 2] >> 3)) >>> 0;
  return sum;
}`;

async function seekTo(page, selector, time) {
  return page.$eval(selector, (media, t) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no seeked event for ${t}`)), 20000);
    media.addEventListener('seeked', () => { clearTimeout(timer); resolve(media.currentTime); }, { once: true });
    media.addEventListener('error', () => { clearTimeout(timer); reject(new Error('media error')); }, { once: true });
    media.currentTime = t;
  }), time);
}

steps.previews = async (s, page) => {
  const { vault, server } = s.stack;
  const straysBefore = server.strays.length;
  const logoutsBefore = server.log.filter((line) => line === 'POST /web/logout').length;

  // --- image, SVG, and an SVG that carries script ---
  await s.goDir(page, 'pics');
  await s.openFile(page, 'photo.png');
  await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth > 0; });
  assert.deepEqual(await page.$eval('#viewer-body img', (img) => [img.naturalWidth, img.naturalHeight]), [480, 320]);
  assert.match(await page.$eval('#viewer-body img', (img) => img.getAttribute('src')), /^\/v\/[A-Za-z0-9_-]{22}$/);
  let headers = await page.evaluate(async (u) => {
    const res = await fetch(u);
    const body = new Uint8Array(await res.arrayBuffer());
    return { status: res.status, type: res.headers.get('content-type'), csp: res.headers.get('content-security-policy'), sniff: res.headers.get('x-content-type-options'), cache: res.headers.get('cache-control'), corp: res.headers.get('cross-origin-resource-policy'), ranges: res.headers.get('accept-ranges'), length: res.headers.get('content-length'), n: body.length, disposition: res.headers.get('content-disposition') };
  }, await s.fileUrl(page));
  assert.deepEqual(headers, {
    status: 200, type: 'image/png', csp: "sandbox; default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    sniff: 'nosniff', cache: 'no-store', corp: 'same-origin', ranges: 'bytes', length: String(vault.files.get('pics/photo.png').length), n: vault.files.get('pics/photo.png').length,
    disposition: headers.disposition,
  });
  // Shown, not saved: no name travels with it (a browser would make it a tab's title).
  assert.equal(headers.disposition, 'inline');
  assert.equal(await page.isVisible('#viewer-open'), true);
  assert.match(await page.getAttribute('#viewer-open', 'title'), /stays open after Lock/);
  await page.click('#viewer-next');
  await page.waitForFunction(() => document.getElementById('viewer-name').title === 'scripted.svg' && document.getElementById('viewer-meta').textContent !== '');
  await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth > 0; });
  const svgUrl = await s.fileUrl(page);
  await page.click('#viewer-prev');
  await page.click('#viewer-prev');
  await page.waitForFunction(() => document.getElementById('viewer-name').title === 'drawing.svg');
  await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth > 0; });
  await s.closeFile(page);

  // --- text, a long text, and HTML that is shown as text ---
  await s.goDir(page, 'docs');
  await s.openFile(page, 'notes.txt');
  await page.waitForSelector('#viewer-body pre');
  assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), vault.files.get('docs/notes.txt').toString());
  await s.closeFile(page);
  await s.openFile(page, 'long.txt');
  await page.waitForSelector('#viewer-body pre .v-note');
  assert.match(await page.textContent('#viewer-body pre .v-note'), /^The first 512 KiB of /);
  const shown = await page.$eval('#viewer-body pre', (pre) => pre.lastChild.textContent);
  assert.equal(shown, vault.files.get('docs/long.txt').subarray(0, 512 * 1024).toString());
  await s.closeFile(page);
  await s.openFile(page, 'page.html');
  await page.waitForSelector('#viewer-body pre');
  assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), HOSTILE_HTML, 'markup is text');
  assert.equal(await page.$$eval('#viewer-body pre *', (nodes) => nodes.length), 0, 'no element came out of the file');
  const htmlUrl = await s.fileUrl(page);
  headers = await page.evaluate(async (u) => { const res = await fetch(u); await res.arrayBuffer(); return [res.headers.get('content-type'), res.headers.get('content-security-policy')]; }, htmlUrl);
  assert.deepEqual(headers, ['text/plain; charset=utf-8', "sandbox; default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"]);
  await s.closeFile(page);

  // --- PDF: never in a frame of the viewer's page (a link in a PDF takes the whole tab along) —
  //     a card with "Open", a tab of its own on the Service Worker's address ---
  await s.openFile(page, 'report.pdf');
  await page.waitForSelector('#viewer-body .card a.btn[target="_blank"]');
  assert.equal(await page.$('#viewer-body iframe'), null, `${s.label}: no frame for a PDF`);
  assert.match(await page.textContent('#viewer-body .card'), /A PDF opens in a tab of its own\. That tab is not part of the viewer: close it when you are done\./);
  assert.match(await page.getAttribute('#viewer-body .card a.btn[target="_blank"]', 'href'), /^\/v\/[A-Za-z0-9_-]{22}$/);
  assert.equal(await page.getAttribute('#viewer-body .card a.btn[target="_blank"]', 'rel'), 'noopener');
  const pdf = await page.evaluate(async (u) => {
    const res = await fetch(u);
    const body = new Uint8Array(await res.arrayBuffer());
    return { type: res.headers.get('content-type'), csp: res.headers.get('content-security-policy'), disposition: res.headers.get('content-disposition'), head: String.fromCharCode(...body.subarray(0, 8)), n: body.length };
  }, await s.fileUrl(page));
  assert.deepEqual(pdf, { type: 'application/pdf', csp: "default-src 'none'; frame-ancestors 'self'", disposition: 'inline', head: '%PDF-1.4', n: vault.files.get('docs/report.pdf').length });

  // --- files in a tab of their own: neither the tab's title nor its history entry holds a name ---
  const ownTab = async (click, name) => {
    const [tab] = await Promise.all([page.context().waitForEvent('page'), click()]);
    s.watch(tab);
    // (Firefox looks for an icon of the tab's document, which that document's policy refuses.)
    s.expect(/favicon\.ico/, /sandbox/i);
    const stem = name.replace(/\.[^.]+$/, '');
    // An engine that does not show the kind (Playwright's Firefox and WebKit: a PDF) saves it instead: no tab to look at.
    const loaded = await tab.waitForLoadState('load', { timeout: 10000 }).then(() => true, () => false);
    await sleep(300);
    const shown = loaded && !tab.isClosed() && tab.url().startsWith(s.stack.origin);
    const seen = { shown, url: tab.isClosed() ? '' : tab.url(), title: shown ? await tab.title().catch(() => '') : '' };
    if (shown && s.engine === 'chrome') {
      const cdp = await tab.context().newCDPSession(tab);
      const history = await cdp.send('Page.getNavigationHistory');
      seen.history = history.entries.map((entry) => `${entry.url} | ${entry.title}`);
      await cdp.detach();
    }
    if (!tab.isClosed()) await tab.close();
    assert.ok(!JSON.stringify(seen).includes(stem), `${s.label}: ${name} in a tab of its own left its name: ${JSON.stringify(seen)}`);
    if (shown) assert.match(new URL(seen.url).pathname, /^\/v\/[A-Za-z0-9_-]{22}$/);
    return seen;
  };
  const pdfTab = await ownTab(() => page.click('#viewer-body .card a.btn[target="_blank"]'), 'report.pdf');
  if (s.engine === 'chrome') assert.ok(pdfTab.shown && pdfTab.history.length >= 1, `${s.label}: the PDF is shown in its tab`);
  await s.closeFile(page);
  await s.goDir(page, 'pics');
  await s.openFile(page, 'photo.png');
  const imageTab = await ownTab(() => page.click('#viewer-open'), 'photo.png');
  assert.ok(imageTab.shown, `${s.label}: the image is shown in its tab`);
  await s.closeFile(page);
  await s.goDir(page, 'docs');
  await s.openFile(page, 'notes.txt');
  await page.waitForSelector('#viewer-body pre');
  const textTab = await ownTab(() => page.click('#viewer-open'), 'notes.txt');
  assert.ok(textTab.shown);
  await s.closeFile(page);

  // --- the hostile files, opened directly: a tab of their own on the Service Worker's address ---
  for (const [url, what] of [[htmlUrl, 'the HTML file'], [svgUrl, 'the scripted SVG']]) {
    const tab = await page.context().newPage();
    s.watch(tab);
    // A sandboxed document may not run script: the engines say so on the console.
    // (Firefox also looks for an icon of the tab's document, which that document's policy refuses.)
    s.expect(/sandbox/i, /Blocked script execution/i, /allow-scripts/i, /favicon\.ico/);
    await tab.goto(`${s.stack.origin}${url}`).catch((error) => assert.fail(`${what} did not open in a tab of its own: ${error}`));
    // What a script there would do is looked for below: a request, storage, a message.
    await sleep(500);
    await tab.close();
  }
  await sleep(200);
  assert.deepEqual(await page.evaluate(() => [window.__ran, window.__marks, localStorage.getItem('gclone.ran')]), [undefined, [], null], 'no script of the vault ran in the viewer\'s origin');
  assert.deepEqual(server.strays.slice(straysBefore).filter((line) => line.includes('script-ran')), []);
  assert.equal(server.log.filter((line) => line === 'POST /web/logout').length, logoutsBefore);

  // --- the policy of the page itself ---
  s.expect(/blob:/, /frame-src/, /eval/i, /EvalError/, /unsafe-eval/, /TrustedHTML|TrustedScript|Trusted Type/i, /script-src/, /require-trusted-types-for/);
  // Text is never compiled as script: a string handed to a timer is the page's own eval (the
  // test's `evaluate` itself is exempt from the policy, so `eval` there would prove nothing).
  const evaluated = await page.evaluate(() => new Promise((resolve) => {
    window.__evaluated = 0;
    try { setTimeout('window.__evaluated = 1', 0); } catch (error) { resolve(error.name); return; }
    setTimeout(() => resolve(window.__evaluated ? 'ran' : 'refused'), 300);
  }));
  assert.ok(['refused', 'TypeError', 'EvalError'].includes(evaluated), `a string was compiled as script: ${evaluated}`);
  const blobFrame = await page.evaluate(() => new Promise((resolve) => {
    document.addEventListener('securitypolicyviolation', (event) => { if (String(event.blockedURI).startsWith('blob')) resolve('refused'); }, { once: true });
    const frame = document.createElement('iframe');
    frame.src = URL.createObjectURL(new Blob(['<p>blob</p>'], { type: 'text/html' }));
    document.body.append(frame);
    setTimeout(() => { frame.remove(); resolve('not refused'); }, 3000);
  }));
  assert.equal(blobFrame, 'refused', 'a blob: frame is refused by the page\'s policy');
  // Trusted Types: markup cannot be assigned as a string anywhere in the page.
  assert.equal(await page.evaluate(() => { try { document.createElement('div').innerHTML = '<b>x</b>'; return 'set'; } catch (error) { return error.name; } }), 'TypeError');
  await s.goDir(page, '');
  s.note(`previews: image, SVG, text, long text, HTML as text, PDF behind "Open"; a file in a tab of its own is titled ${JSON.stringify(imageTab.title)} / ${JSON.stringify(pdfTab.title)} (image / PDF), never by its name; the hostile HTML and SVG ran nothing; eval and blob: frames are refused`);
};

steps.media = async (s, page) => {
  const { drive } = s.stack;
  await s.goDir(page, 'media');
  // --- audio: metadata, a seek, a second of play ---
  await s.openFile(page, 'tone.mp3');
  await page.waitForFunction(() => { const a = document.querySelector('#viewer-body audio'); return a && a.readyState >= 1; });
  const duration = await page.$eval('#viewer-body audio', (a) => a.duration);
  assert.ok(Math.abs(duration - 12) < 0.3, `the tone lasts ${duration} s`);
  // No tab of its own for audio and video: the browser's player there is out of the Service Worker's reach.
  assert.equal(await page.isHidden('#viewer-open'), true, `${s.label}: no "open in a new tab" for audio`);
  assert.ok(Math.abs(await seekTo(page, '#viewer-body audio', 8) - 8) < 0.5);
  const played = await page.$eval('#viewer-body audio', async (a) => {
    a.muted = true;
    const from = a.currentTime;
    await a.play();
    // Up to 15 s for half a second of sound: a shared CI runner starts its audio output slowly.
    for (let i = 0; i < 150 && a.currentTime - from <= 0.5; i += 1) await new Promise((resolve) => setTimeout(resolve, 100));
    a.pause();
    return a.currentTime - from;
  });
  assert.ok(played > 0.5, `the tone played ${played} s`);
  await s.closeFile(page);

  // --- video: both layouts of the same streams; the frame after a seek is the same in both ---
  const sums = {};
  for (const name of ['clip-faststart.mp4', 'clip-moov-at-end.mp4']) {
    await s.openFile(page, name);
    await page.waitForFunction(() => { const v = document.querySelector('#viewer-body video'); return v && v.readyState >= 1; }, null, { timeout: 30000 });
    const size = await page.$eval('#viewer-body video', (v) => [v.videoWidth, v.videoHeight, Math.round(v.duration)]);
    assert.deepEqual(size, [320, 180, 12], name);
    assert.equal(await page.isHidden('#viewer-open'), true, `${s.label}: no "open in a new tab" for video`);
    sums[name] = [];
    for (const t of [9.05, 2.05, 11.05]) {
      const at = await seekTo(page, '#viewer-body video', t);
      assert.ok(Math.abs(at - t) < 0.2, `${name}: seek to ${t} ended at ${at}`);
      sums[name].push(await page.$eval('#viewer-body video', new Function(`return (${FRAME})(arguments[0])`)));
    }
    assert.equal(new Set(sums[name]).size, 3, `${name}: three positions, three different frames (${sums[name]})`);
    const moved = await page.$eval('#viewer-body video', async (v) => {
      v.muted = true;
      v.currentTime = 3;
      await new Promise((resolve) => v.addEventListener('seeked', resolve, { once: true }));
      const from = v.currentTime;
      await v.play();
      for (let i = 0; i < 150 && v.currentTime - from <= 0.5; i += 1) await new Promise((resolve) => setTimeout(resolve, 100));
      v.pause();
      return v.currentTime - from;
    });
    assert.ok(moved > 0.5, `${name} played ${moved} s`);
    await s.closeFile(page);
  }
  assert.deepEqual(sums['clip-faststart.mp4'], sums['clip-moov-at-end.mp4'], `${s.label}: the frames after a seek are the same in both files`);
  // Media answers are ranges of ciphertext, never a whole blob without a Range.
  const gets = drive.log.gets.filter((g) => /^[0-9a-f]{32}$/.test(g.name));
  assert.ok(gets.length > 0 && gets.every((g) => g.range), 'every read of a data blob is a ranged request');
  await s.goDir(page, '');
  s.note(`media: MP3 seek and play; MP4 (moov first and moov last) seek to three positions, frames equal across both files (${sums['clip-faststart.mp4'].join(', ')})`);
};

steps.download = async (s, page) => {
  const { vault, drive } = s.stack;
  await s.goDir(page, 'bin');
  // A file of 47 chunks in a blob of its own, through the page's download button.
  await s.openFile(page, 'pattern-3m.bin');
  const saved = await s.download(page, () => page.click('#viewer-body .card a.dl'));
  assert.equal(saved.name, 'pattern-3m.bin');
  assert.equal(sha256(saved.bytes), sha256(vault.files.get('bin/pattern-3m.bin')), `${s.label}: the download is byte-identical`);
  // Ranges of it, as an element or a script would ask: exact bytes, exact headers.
  const url = await s.fileUrl(page);
  const size = vault.files.get('bin/pattern-3m.bin').length;
  const ranges = await page.evaluate(async ([u, total]) => {
    const out = [];
    for (const range of ['bytes=0-1', 'bytes=65530-65545', `bytes=${total - 10}-`, 'bytes=-7', `bytes=${total}-`, 'bytes=5-1', 'bytes=0-3,9-12', 'lines=1-2']) {
      const res = await fetch(u, { headers: { Range: range } });
      const body = new Uint8Array(await res.arrayBuffer());
      out.push([range, res.status, res.headers.get('content-range'), res.headers.get('content-length'), Array.from(body.subarray(0, 16))]);
    }
    return out;
  }, [url, size]);
  const plain = vault.files.get('bin/pattern-3m.bin');
  const want = (range, status, from, to) => [range, status, status === 206 ? `bytes ${from}-${to - 1}/${size}` : status === 416 ? `bytes */${size}` : null, String(status === 416 ? 0 : to - from), status === 416 ? [] : Array.from(plain.subarray(from, Math.min(to, from + 16)))];
  assert.deepEqual(ranges, [
    want('bytes=0-1', 206, 0, 2),
    want('bytes=65530-65545', 206, 65530, 65546),
    want(`bytes=${size - 10}-`, 206, size - 10, size),
    want('bytes=-7', 206, size - 7, size),
    want(`bytes=${size}-`, 416, 0, 0),
    want('bytes=5-1', 200, 0, size),
    want('bytes=0-3,9-12', 200, 0, size),
    want('lines=1-2', 200, 0, size),
  ]);
  await s.closeFile(page);
  // An empty file: said so, and an empty answer.
  await s.openFile(page, 'empty.dat');
  await page.waitForSelector('#viewer-body .card');
  assert.match(await page.textContent('#viewer-body .card'), /No preview for this kind of file \(0 B\)\./);
  assert.deepEqual(await page.evaluate(async (u) => { const res = await fetch(u); return [res.status, (await res.arrayBuffer()).byteLength, res.headers.get('content-length')]; }, await s.fileUrl(page)), [200, 0, '0']);
  await s.closeFile(page);
  await s.goDir(page, 'docs');
  await s.openFile(page, 'empty.txt');
  await page.waitForSelector('#viewer-body .card');
  assert.match(await page.textContent('#viewer-body .card'), /This file is empty\./);
  await s.closeFile(page);
  // "Download" of what a browser could show itself — a text, an image, a PDF — is a download:
  // application/octet-stream and attachment, and the viewer stays as it is.
  for (const [dir, name] of [['docs', 'notes.txt'], ['pics', 'photo.png'], ['docs', 'report.pdf']]) {
    await s.goDir(page, dir);
    await s.openFile(page, name);
    const got = await page.evaluate(async (u) => { const res = await fetch(`${u}?dl=1`); await res.arrayBuffer(); return [res.headers.get('content-type'), res.headers.get('content-disposition').split(';')[0], res.headers.get('content-security-policy')]; }, await s.fileUrl(page));
    assert.deepEqual(got, ['application/octet-stream', 'attachment', "sandbox; default-src 'none'; frame-ancestors 'none'"], name);
    const file = await s.download(page, () => page.click('#viewer-download'));
    assert.ok(file.bytes.equals(vault.files.get(`${dir}/${name}`)), name);
    assert.equal(file.name, name);
    assert.equal(await page.isVisible('#viewer-name'), true, 'the viewer stays unlocked after a download');
    assert.equal(page.url(), `${s.stack.origin}/`);
    await s.closeFile(page);
  }
  // A blob whose recorded id the store no longer knows (a vault that was moved to another
  // account, or restored) is found by its name.
  await s.goDir(page, 'deep/a/b/c/d');
  const blobs = drive.objects().filter((o) => /^[0-9a-f]{32}$/.test(o.name));
  for (const blob of blobs) drive.reissued.set(blob.id, `moved-${blob.id}`);
  const listsBefore = drive.log.lists.length;
  try {
    await s.openFile(page, 'leaf.txt');
    await page.waitForSelector('#viewer-body pre');
    assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), 'at the bottom\n');
    assert.ok(drive.log.lists.slice(listsBefore).some((l) => /^name = '[0-9a-f]{32}' and trashed = false$/.test(l.q)), 'the blob was looked up by name');
    assert.ok(drive.log.gets.at(-1).id.startsWith('moved-'));
    await s.closeFile(page);
    // A blob that is gone altogether: the reason is in the page, not a download that breaks.
    s.expect(/502/, /Failed to load resource/);
    drive.hidden = new Set(blobs.map((b) => b.name));
    await s.goDir(page, '');
    await s.openFile(page, 'README.md');
    await page.waitForSelector('#viewer-body .card.error');
    assert.match(await page.textContent('#viewer-body .card.error'), /The file could not be read from the vault: its data is missing from the store \(blob [0-9a-f]{32}\)\./);
    await s.closeFile(page);
  } finally {
    drive.reissued.clear();
    drive.hidden = new Set();
    // The ids are the old ones again: what the Service Worker learned in between goes.
    await page.evaluate(() => navigator.serviceWorker.controller.postMessage({ type: 'forget' }));
  }
  await s.goDir(page, '');
  s.note('download: 3 MiB file byte-identical; ranges exact; text, image and PDF downloads are attachments; a blob found by name; a missing blob is said in the page');
};

steps.recovery = async (s, page) => {
  const { drive, server } = s.stack;
  await s.goDir(page, 'docs');
  await s.openFile(page, 'notes.txt');
  await page.waitForSelector('#viewer-body pre');
  const url = await s.fileUrl(page);
  const read = () => page.evaluate(async (u) => { const res = await fetch(u, { headers: { Range: 'bytes=0-9' } }); return [res.status, await res.text()]; }, url);
  assert.deepEqual(await read(), [206, 'These are ']);
  // The Service Worker loses everything it holds (its map, the token, the port): the page
  // hands out a new channel and the vault worker issues the ticket again.
  await page.evaluate(() => navigator.serviceWorker.controller.postMessage({ type: 'forget' }));
  assert.deepEqual([(await s.ping(page)).tickets, (await s.ping(page)).port], [0, false]);
  assert.deepEqual(await read(), [206, 'These are '], 'after forget');
  assert.deepEqual([(await s.ping(page)).tickets, (await s.ping(page)).port], [1, true]);
  if (s.engine === 'chrome') {
    // The browser stops the Service Worker (as it does after 30 idle seconds): the same recovery.
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await sleep(300);
    assert.deepEqual(await read(), [206, 'These are '], 'after the Service Worker was stopped');
    await cdp.detach();
  }
  // The access token the contexts hold stops working: each gets a fresh one from the Worker.
  const refreshes = () => server.log.filter((line) => line === 'POST /web/refresh').length;
  const before = refreshes();
  drive.tokens.clear();
  assert.deepEqual(await read(), [206, 'These are '], 'after the token was withdrawn (Service Worker)');
  await s.api(page, 'refresh');
  assert.ok(refreshes() >= before + 1, 'a fresh token was fetched');
  // An address of an id nobody issued: 410, at once for the page that asks.
  s.expect(/410/, /Failed to load resource/);
  const unknown = await page.evaluate(async () => { const res = await fetch('/v/AAAAAAAAAAAAAAAAAAAAAA'); return [res.status, await res.text(), res.headers.get('content-type')]; });
  assert.deepEqual(unknown, [410, 'This link has expired. Open the file from the viewer again.', 'text/plain; charset=utf-8']);
  // A broken connection in the middle of a file: the stream goes on from the last verified chunk.
  await s.closeFile(page);
  await s.goDir(page, 'bin');
  await s.openFile(page, 'pattern-3m.bin');
  const big = await s.fileUrl(page);
  const blob = drive.objects().find((o) => /^[0-9a-f]{32}$/.test(o.name) && o.size > 3 * MIB && o.size < 4 * MIB);
  drive.cutAfter.set(blob.id, 1000000);
  const digest = await page.evaluate(async (u) => {
    const res = await fetch(u);
    const body = await res.arrayBuffer();
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
    return [res.status, body.byteLength, Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('')];
  }, big);
  assert.deepEqual(digest, [200, s.stack.vault.files.get('bin/pattern-3m.bin').length, sha256(s.stack.vault.files.get('bin/pattern-3m.bin'))], 'a cut connection is resumed');
  assert.equal(drive.cutAfter.size, 0, 'the connection was cut');
  await s.closeFile(page);
  await s.goDir(page, '');
  s.note('recovery: tickets come back after the Service Worker forgot them' + (s.engine === 'chrome' ? ' and after it was stopped' : '') + '; a withdrawn token is renewed; a cut stream resumes');
};

steps.refresh = async (s, page) => {
  const { vault } = s.stack;
  const src = path.join(s.stack.work, `late-${s.engine}`);
  const name = `arrived-later-${s.engine}.txt`;
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(src, name), `uploaded while ${s.engine} was open\n`);
  vault.device.run('copy', src, ':');
  vault.files.set(name, fs.readFileSync(path.join(src, name)));
  assert.equal(await page.evaluate((n) => [...document.querySelectorAll('#rows .row .name')].some((node) => node.title === n), name), false);
  await page.click('#refresh');
  await page.waitForFunction((n) => [...document.querySelectorAll('#rows .row .name')].some((node) => node.title === n), name);
  assert.match(await page.textContent('#notice-text'), /^Refreshed: \d+ new change sets? from other devices\.$/);
  await s.openFile(page, name);
  await page.waitForSelector('#viewer-body pre');
  assert.equal(await page.$eval('#viewer-body pre', (pre) => pre.textContent), `uploaded while ${s.engine} was open\n`);
  await s.closeFile(page);
  assert.equal((await s.api(page, 'info')).head, vault.device.head());
  await page.click('#refresh');
  await page.waitForFunction(() => document.getElementById('notice-text').textContent === 'Up to date.');
  s.note('refresh: a file uploaded by the native binary appears; the head equals `gclone status`');
};

steps.keys = async (s, page) => {
  // Everything the page said to a worker or the Service Worker, and everything it was told:
  // no field named like a key, a bundle or a ticket, and no bytes at all.
  const seen = await page.evaluate(() => ({ flagged: window.__flagged, bytes: window.__bytes, n: window.__messages.length, workers: window.__workers, sample: window.__messages.slice(0, 400) }));
  assert.deepEqual(seen.flagged, [], `${s.label}: a message of the page carries key material`);
  assert.deepEqual(seen.bytes, [], `${s.label}: bytes crossed the page`);
  assert.ok(seen.n > 20, 'the page did talk to its workers');
  const text = seen.sample.map((m) => m[1]).join('\n');
  assert.ok(text.includes('"call":"issue"') && text.includes('"type":"port"'), 'the page asked for tickets and handed out the port');
  // The one secret that does cross the page is the passphrase, once per attempt, to the KDF worker.
  assert.equal(seen.sample.filter((m) => m[1].includes(PASS)).length, 1);
  assert.ok(seen.sample.find((m) => m[1].includes(PASS))[0] === 'to worker');
  // Nothing of the vault in storage.
  const stored = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage), cookie: document.cookie }));
  assert.deepEqual(stored.session, []);
  assert.ok(stored.local.every((k) => k === 'gclone.sort'), `localStorage holds ${stored.local}`);
  assert.equal(stored.cookie, '', 'the session cookie is HttpOnly');
  s.note(`keys: ${seen.n} messages between the page and its workers, none with a key, a ticket or bytes`);
};

/** The entries of the session history that this run of the page made (the place table's), newest first. Ends where it began. */
async function walkOwnHistory(page) {
  const snapshot = () => page.evaluate(() => ({ state: history.state, url: location.href, title: document.title }));
  const entries = [await snapshot()];
  let back = 0;
  // An entry of depth 0 is where this run began: one step further back is another document.
  while (entries.at(-1).state && entries.at(-1).state.depth > 0 && back < 80) {
    await page.evaluate(() => new Promise((resolve) => {
      window.addEventListener('popstate', resolve, { once: true });
      history.back();
    }));
    back += 1;
    entries.push(await snapshot());
  }
  if (back) await page.evaluate((n) => new Promise((resolve) => { window.addEventListener('popstate', resolve, { once: true }); history.go(n); }), back);
  return entries;
}

/** Every entry the browser kept for the tab, newest first, back to the blank page it started on. The page is left there. */
async function walkAllHistory(page, origin) {
  const entries = [];
  for (let i = 0; i < 80; i += 1) {
    if (!page.url().startsWith(origin)) break;
    entries.push(await page.evaluate(() => ({ state: history.state, url: location.href, title: document.title })));
    const before = await page.evaluate(() => history.length);
    if (before <= 1) break;
    try {
      await page.goBack({ waitUntil: 'commit', timeout: 5000 });
    } catch {
      break;
    }
  }
  return entries;
}

function assertNoNames(s, entries, what) {
  const names = new Set();
  for (const p of s.stack.vault.files.keys()) for (const part of p.split('/')) names.add(part);
  for (const entry of entries) {
    assert.equal(entry.url, `${s.stack.origin}/`, `${what}: the address`);
    assert.equal(entry.title, 'gclone', `${what}: the title`);
    const state = entry.state;
    if (state === null) continue;
    assert.deepEqual(Object.keys(state).filter((k) => !['depth', 'began', 'e', 'n'].includes(k)), [], `${what}: history.state holds ${JSON.stringify(state)}`);
    // Two numbers, a flag and the tag of the page's run: nothing in it can be a name.
    assert.ok(Number.isInteger(state.n) && Number.isInteger(state.depth) && typeof state.began === 'boolean' && /^[0-9a-f]{32}$/.test(state.e), `${what}: ${JSON.stringify(state)}`);
    const text = JSON.stringify(state);
    for (const name of names) if (name.length >= 5) assert.ok(!text.includes(name), `${what}: history.state holds the name ${name}`);
  }
}

steps.history = async (s, page) => {
  // A walk: folders, a file, a search — then every entry the browser kept.
  await s.goDir(page, 'docs');
  await s.openFile(page, 'notes.txt');
  await s.closeFile(page);
  await s.goDir(page, 'deep/a/b');
  await page.fill('#search', 'leaf');
  await page.waitForFunction(() => window.__listed === 'search:leaf' && /match/.test(document.getElementById('count').textContent));
  await s.openFile(page, 'leaf.txt');
  const entries = await walkOwnHistory(page);
  assert.ok(entries.length >= 5, `${entries.length} history entries`);
  assertNoNames(s, entries, `${s.label}, while unlocked`);
  // Back and forward lead to the places, from the table in the page's memory.
  await page.goBack();
  await page.waitForSelector('#viewer', { state: 'hidden' });
  assert.equal(await page.inputValue('#search'), 'leaf');
  await page.goForward();
  await page.waitForFunction(() => !document.getElementById('viewer').hidden && document.getElementById('viewer-name').title === 'leaf.txt');
  await s.closeFile(page);
  await page.fill('#search', '');
  await s.goDir(page, '');
  s.note(`history: ${entries.length} entries, each with two numbers and a flag, the address / and the title gclone`);
};

steps.lock = async (s) => {
  // Each case is a page of its own: a lock is a reload, and the clock is the test's.
  const workersOf = (page) => page.workers().length;
  const locked = async (page, what) => {
    await s.screen(page, 'unlock');
    assert.equal(await page.$('#rows'), null, `${what}: no list in the document`);
    assert.equal(await page.inputValue('#unlock-pass'), '');
    const pong = await s.ping(page);
    assert.deepEqual([pong.tickets, pong.port], [0, false], `${what}: the Service Worker holds no ticket and no port`);
    assert.equal(workersOf(page), 1, `${what}: only the new vault worker (which holds no key) runs`);
    assert.equal(await page.evaluate(() => history.state), null);
    assert.equal(page.url(), `${s.stack.origin}/`);
  };
  const openSomething = async (page) => {
    await s.goDir(page, 'docs');
    await s.openFile(page, 'notes.txt');
    await page.waitForSelector('#viewer-body pre');
    await s.closeFile(page);
  };
  const setHidden = (page, hidden) => page.evaluate((h) => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => (h ? 'hidden' : 'visible') });
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => h });
    document.dispatchEvent(new Event('visibilitychange', { bubbles: true }));
  }, hidden);
  const key = (page) => page.evaluate(() => {
    let reached = 0;
    const listen = () => { reached += 1; };
    document.addEventListener('keydown', listen);
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    document.removeEventListener('keydown', listen);
    return reached;
  });
  const start = async () => {
    const { context, page } = await s.open();
    await page.clock.install();
    await s.signedIn(context, page);
    await s.unlock(page);
    await openSomething(page);
    assert.ok((await s.ping(page)).tickets >= 1);
    return { context, page };
  };
  const advance = (page, minutes) => page.evaluate((ms) => Date.now() + ms, minutes * 60000).then((t) => page.clock.setSystemTime(t));

  // 1. 14 minutes without input: still open, and the key counts as input. 16 minutes: the
  //    next key locks, and reaches nothing.
  let { context, page } = await start();
  await advance(page, 14);
  assert.equal(await key(page), 1, 'a key after 14 minutes reaches the page');
  assert.ok(await page.$('#rows'));
  await advance(page, 14);
  assert.equal(await key(page), 1, 'the key 14 minutes later counted as input');
  await advance(page, 16);
  const reached = await key(page).catch(() => 0);
  assert.equal(reached, 0, 'the key that found the vault overdue reached nothing');
  await locked(page, 'idle for 16 minutes');
  // What the browser kept of the session history after the lock: no place, no name.
  const kept = await walkAllHistory(page, s.stack.origin);
  assert.ok(kept.length >= 2, `${kept.length} entries after the lock`);
  assertNoNames(s, kept, `${s.label}, after Lock`);
  await context.close();

  // 2. The same without any input: the check that runs every 15 s locks.
  ({ context, page } = await start());
  await page.clock.fastForward(16 * 60000);
  await locked(page, 'idle for 16 minutes, no event');
  await context.close();

  // 3. Hidden for 4 minutes: open. Hidden for 6: locked on return, whatever the idle clock says.
  ({ context, page } = await start());
  await setHidden(page, true);
  await advance(page, 4);
  await setHidden(page, false);
  assert.ok(await page.$('#rows'), 'four minutes in the background do not lock');
  await setHidden(page, true);
  await advance(page, 6);
  await setHidden(page, false);
  await locked(page, 'hidden for 6 minutes');
  await context.close();

  // 4. In the background with media playing: its progress holds the vault open; five minutes
  //    after it stops, the rule applies.
  ({ context, page } = await start());
  await s.goDir(page, 'media');
  await s.openFile(page, 'tone.mp3');
  await page.waitForSelector('#viewer-body audio');
  await setHidden(page, true);
  for (let i = 0; i < 4; i += 1) {
    await advance(page, 4);
    await page.$eval('#viewer-body audio', (a) => a.dispatchEvent(new Event('timeupdate')));
  }
  await setHidden(page, false);
  assert.ok(await page.$('#rows'), '16 minutes in the background with audio playing do not lock');
  await setHidden(page, true);
  await advance(page, 6);
  await setHidden(page, false);
  await locked(page, 'hidden for 6 minutes after the audio stopped');
  await context.close();

  // 5. A page that comes back from the back/forward cache locks without looking at the clock.
  ({ context, page } = await start());
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await locked(page, 'restored from the back/forward cache');
  await context.close();

  // 6. The Lock button; then the passphrase opens the vault again, at its root.
  ({ context, page } = await start());
  await page.click('#lock-btn');
  await locked(page, 'the Lock button');
  await s.unlock(page);
  await s.waitListed(page, '');
  await context.close();
  s.note('lock: 16 idle minutes (by an event, and by the 15 s check), 6 minutes hidden, 6 minutes after background audio stopped, a back/forward-cache restore and the button all end at the passphrase screen with no worker, ticket or history state left');
};

steps.signout = async (s) => {
  const { server } = s.stack;
  const { context, page } = await s.fresh();
  await s.goDir(page, 'docs');
  await s.openFile(page, 'notes.txt');
  await s.closeFile(page);
  const sessions = server.sessions.size;
  await page.click('#info-btn');
  await page.click('#session-out');
  await s.screen(page, 'out');
  assert.match(await page.textContent('#shell .screen[data-screen="out"]'), /Signed out of the viewer.*still signed in to your Google account.*sign out of Google too/s);
  assert.equal(await page.getAttribute('#shell .screen[data-screen="out"] a', 'href'), 'https://accounts.google.com/Logout');
  assert.equal(server.sessions.size, sessions - 1, 'the session is gone at the Worker');
  assert.deepEqual((await context.cookies()).filter((c) => c.name.startsWith('gclone')), [], 'the cookie is gone');
  assert.deepEqual(await page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)]), [[], []]);
  assert.equal(await page.$('#rows'), null);
  // "Sign in again" leads to the sign-in screen; so does a reload.
  s.expect(/401/, /Failed to load resource/);
  await page.click('#out-again');
  await s.screen(page, 'signin');
  await page.reload();
  await s.screen(page, 'signin');
  assertNoNames(s, await walkAllHistory(page, s.stack.origin), `${s.label}, after sign-out`);
  await context.close();
  s.note('sign-out: the signed-out screen with the Google sentence; cookie, session and storage gone; no name in the history');
};

steps.tabs = async (s) => {
  // Two tabs of the viewer in one browser. The Lock button and Sign out are for the browser.
  const { server } = s.stack;
  const { context, page: first } = await s.fresh();
  const tab = async () => {
    const page = await context.newPage();
    s.watch(page);
    await page.goto(`${s.stack.origin}/`);
    await s.screen(page, 'unlock');
    return page;
  };
  const openNotes = async (page) => {
    await s.goDir(page, 'docs');
    await s.openFile(page, 'notes.txt');
    await page.waitForSelector('#viewer-body pre');
    await s.closeFile(page);
  };
  let second = await tab();
  await s.unlock(second);
  await openNotes(first);
  await openNotes(second);
  assert.ok((await s.ping(first)).tickets >= 1);

  // 1. The Lock button in one tab: the other forgets the vault too, and says why.
  await first.click('#lock-btn');
  await s.screen(first, 'unlock');
  await s.screen(second, 'unlock');
  assert.equal(await second.textContent('#unlock-killed'), 'The vault was locked in another tab.');
  assert.equal(await first.isVisible('#unlock-killed'), false);
  for (const page of [first, second]) assert.equal(await page.$('#rows'), null);
  assert.deepEqual([(await s.ping(second)).tickets, (await s.ping(second)).port], [0, false]);

  // 2. A tab that leaves — taken to another address — leaves no ticket behind.
  await s.unlock(first);
  await openNotes(first);
  assert.ok((await s.ping(second)).tickets >= 1, 'the Service Worker holds the open tab\'s ticket');
  await first.goto(`${s.stack.origin}/privacy`).catch(() => {});
  await sleep(300);
  assert.deepEqual([(await s.ping(second)).tickets, (await s.ping(second)).port], [0, false], `${s.label}: a tab that was taken away left tickets in the Service Worker`);
  await first.goto(`${s.stack.origin}/`);
  await s.screen(first, 'unlock');

  // 3. A message that the Service Worker belongs to another build is for the page that is of
  //    another build, and for no other. A ticket that names a foreign build arrives on the
  //    first tab's port: the worker answers that tab alone, with its own build — which is
  //    this page's, so the page stays — and the second tab hears nothing.
  await s.unlock(first);
  await s.unlock(second);
  await second.evaluate(() => { window.__reloads = []; navigator.serviceWorker.addEventListener('message', (event) => { if (event.data && event.data.type === 'reload') window.__reloads.push(event.data); }); });
  const told = await first.evaluate(() => new Promise((resolve) => {
    navigator.serviceWorker.addEventListener('message', (event) => { if (event.data && event.data.type === 'reload') resolve(event.data); });
    const channel = new MessageChannel();
    navigator.serviceWorker.controller.postMessage({ type: 'port' }, [channel.port2]);
    channel.port1.postMessage({ type: 'ticket', id: 'A'.repeat(22), ticket: '{}', build: '0000000000000000' });
    setTimeout(() => resolve(null), 3000);
  }));
  assert.deepEqual(told, { type: 'reload', build: server.build }, `${s.label}: the Service Worker names its build`);
  await sleep(300);
  assert.deepEqual(await second.evaluate(() => window.__reloads), [], `${s.label}: a tab of the right build was told to reload`);
  assert.equal(await first.isVisible('#rows'), true, 'a page of the Service Worker\'s own build stays unlocked');
  assert.equal(await second.isVisible('#rows'), true);
  // A page of another build does lock, and says why.
  await second.evaluate(() => navigator.serviceWorker.dispatchEvent(new MessageEvent('message', { data: { type: 'reload', build: 'ffffffffffffffff' } })));
  await s.screen(second, 'unlock');
  assert.equal(await second.textContent('#unlock-killed'), 'The viewer was updated. Unlock the vault again.');
  // (The test took the first tab's port: the page hands out a new one.)
  await first.evaluate(() => navigator.serviceWorker.controller.postMessage({ type: 'forget' }));

  // 4. Sign out in one tab: an unlocked tab and one at the passphrase both end at the sign-in
  //    screen, with nothing of the vault left to list, search or open.
  await s.unlock(second);
  await openNotes(second);
  const third = await tab();
  s.expect(/401/, /Failed to load resource/);
  const sessions = server.sessions.size;
  await first.click('#info-btn');
  await first.click('#session-out');
  await s.screen(first, 'out');
  assert.equal(server.sessions.size, sessions - 1);
  for (const [page, what] of [[second, 'the unlocked tab'], [third, 'the tab at the passphrase']]) {
    await s.screen(page, 'signin');
    assert.equal(await page.textContent('#signin-problem'), 'You signed out in another tab.', what);
    assert.equal(await page.$('#rows'), null, what);
    assert.equal(await page.evaluate(() => window.gcloneProvider), undefined, `${what} holds no vault`);
    assert.equal(page.workers().length, 0, `${what}: no worker is left`);
  }
  assert.deepEqual((await context.cookies()).filter((c) => c.name.startsWith('gclone') || c.name.startsWith('__Host')), []);
  await context.close();
  s.note('tabs: the Lock button and Sign out reach every tab of the viewer; a tab that is taken away leaves no ticket; "reload" goes to the page of the other build only');
};

steps.hardening = async (s) => {
  // The page when its own files do not arrive (a deployment in progress, a bad connection, a
  // content blocker). These pages are not watched: failed requests are what they are about.
  const visible = (page) => page.evaluate(() => [...document.querySelectorAll('#shell .screen')].filter((section) => {
    const style = getComputedStyle(section);
    return !section.hidden && style.display !== 'none' && style.visibility !== 'hidden';
  }).map((section) => section.dataset.screen));
  const inert = async (page, what) => {
    assert.deepEqual(await visible(page), ['boot'], `${what}: the first screen, and no other`);
    assert.equal(await page.isVisible('#unlock-pass'), false, `${what}: no passphrase field is offered`);
    assert.equal(await page.isVisible('#signin-go'), false, what);
    assert.deepEqual(await page.evaluate(() => [document.getElementById('unlock-fields').disabled, document.getElementById('unlock-pass').matches(':disabled'), document.getElementById('unlock-form').method]), [true, true, 'dialog'], `${what}: the form is dead until a script enables it, and can never be sent`);
  };
  // 1. The scripts do not load; the style sheets do. "Starting…", and after ten seconds the reason.
  let context = await s.browser.newContext();
  await context.route(`${s.stack.origin}/a/**/*.js`, (route) => route.fulfill({ status: 404, body: '' }));
  let page = await context.newPage();
  await page.goto(`${s.stack.origin}/`);
  await inert(page, 'no scripts');
  const late = page.locator('#shell .screen[data-screen="boot"] .late');
  assert.equal(await late.textContent(), 'The viewer did not start: one of its files could not be loaded. Reload the page.');
  assert.equal(await late.evaluate((node) => getComputedStyle(node).visibility), 'hidden', 'not said while the page may still start');
  const delay = await late.evaluate((node) => { const style = getComputedStyle(node); return [style.animationName, style.animationDelay]; });
  assert.deepEqual(delay, ['late', '10s']);
  // (Ten seconds later, without the wait: the animation's clock is moved to its end.)
  await late.evaluate((node) => { for (const animation of node.getAnimations()) animation.finish(); });
  assert.equal(await late.evaluate((node) => getComputedStyle(node).visibility), 'visible', `${s.label}: the page says that it did not start`);
  await context.close();
  // 2. Nothing under /a/ loads, the style sheets included: still one screen, and no field to type a passphrase into.
  context = await s.browser.newContext();
  await context.route(`${s.stack.origin}/a/**`, (route) => route.fulfill({ status: 404, body: '' }));
  page = await context.newPage();
  await page.goto(`${s.stack.origin}/`);
  await inert(page, 'no scripts and no styles');
  assert.equal(await page.isVisible('#shell .screen[data-screen="boot"] .late'), true, 'without styles the sentence is there at once');
  await context.close();
  // 3. The style sheets do not load; the scripts do: the shell shows its screens by attribute.
  context = await s.browser.newContext();
  await context.route(`${s.stack.origin}/a/**/*.css`, (route) => route.fulfill({ status: 404, body: '' }));
  page = await context.newPage();
  await context.addCookies([{ ...s.stack.server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
  await page.goto(`${s.stack.origin}/`);
  await page.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock', null, { timeout: 30000 });
  assert.deepEqual(await visible(page), ['unlock'], 'without styles: one screen, the one the shell names');
  assert.equal(await page.isEnabled('#unlock-pass'), true);
  await context.close();
  // With everything in place the first screen gives way at once, and the sentence is never seen.
  ({ context, page } = await s.open());
  await context.addCookies([{ ...s.stack.server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
  await page.goto(`${s.stack.origin}/`);
  await s.screen(page, 'unlock');
  assert.deepEqual(await visible(page), ['unlock']);
  assert.equal(await page.isEnabled('#unlock-pass'), true);
  await context.close();
  s.note('hardening: without its scripts the page shows one screen and says after ten seconds that it did not start; without its styles too, no passphrase field is offered and the form cannot be sent');
};

steps.unreachable = async (s) => {
  // A store that cannot be reached is said within seconds, once — not after a minute of spinner.
  const { drive } = s.stack;
  const { context, page } = await s.fresh();
  s.expect(/502/, /403/, /Failed to load resource/);
  await s.goDir(page, 'pics');
  // Drive limits every request, without end. An image: the element fails, the page asks why.
  drive.rateLimitNext = 1e9;
  let t0 = Date.now();
  await s.clickRow(page, 'photo.png');
  await page.waitForSelector('#viewer-body .card.error', { timeout: 40000 });
  const limited = Date.now() - t0;
  assert.match(await page.textContent('#viewer-body .card.error'), /The file could not be read from the vault: Google Drive is limiting requests\. Try again in a few minutes\./);
  assert.ok(limited < 25000, `${s.label}: a rate limit that does not end was said after ${limited} ms`);
  // The reason is remembered for a few seconds: asking again at once costs the store nothing.
  const before = drive.log.gets.length + drive.log.lists.length;
  const requestsBefore = drive.rateLimitNext;
  t0 = Date.now();
  const again = await page.evaluate(async (u) => { const res = await fetch(u, { headers: { Range: 'bytes=0-0' } }); return [res.status, await res.text()]; }, await s.fileUrl(page));
  assert.deepEqual(again, [502, 'The file could not be read from the vault: Google Drive is limiting requests. Try again in a few minutes.']);
  assert.ok(Date.now() - t0 < 2000 && drive.rateLimitNext === requestsBefore && drive.log.gets.length + drive.log.lists.length === before, 'answered from what was just learned');
  // Refresh, in the vault worker: the same patience, and the list stays.
  t0 = Date.now();
  await page.click('#viewer-close');
  await page.click('#refresh');
  await page.waitForFunction(() => /Google Drive is limiting requests/.test(document.getElementById('notice-text').textContent), null, { timeout: 40000 });
  const refreshed = Date.now() - t0;
  assert.ok(refreshed < 25000, `${s.label}: the refresh gave up after ${refreshed} ms`);
  assert.equal(await page.isVisible('#rows'), true);
  // The store answers again: after the few seconds, so does the file.
  drive.rateLimitNext = 0;
  await sleep(5200);
  await s.clickRow(page, 'photo.png');
  await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth > 0; }, null, { timeout: 30000 });
  await s.closeFile(page);
  await s.settle(page, 'unreachable: a rate limit');

  // The store does not answer at all (the connection is closed on it): the same patience,
  // then the reason — for a text, which the page reads itself, with one round of attempts.
  s.expect(/502/, /Failed to load resource/, /ERR_|NetworkError|network connection|Load failed|Failed to fetch|access control checks/i, /A ServiceWorker intercepted the request and encountered an unexpected error/);
  await s.goDir(page, 'docs');
  drive.dead = true;
  t0 = Date.now();
  await s.clickRow(page, 'notes.txt');
  await page.waitForSelector('#viewer-body .card.error', { timeout: 40000 });
  const dead = Date.now() - t0;
  assert.match(await page.textContent('#viewer-body .card.error'), /The file could not be read from the vault: Google Drive does not answer\. Check the connection and try again\./);
  assert.ok(dead < 20000, `${s.label}: a store that does not answer was said after ${dead} ms`);
  drive.dead = false;
  await s.closeFile(page);
  await s.settle(page, 'unreachable: a dead store');

  // Offline — the one thing a browser knows about its connection for certain: said at once.
  s.expect(/502/, /Failed to load resource/, /ERR_INTERNET_DISCONNECTED|NetworkError|offline|network connection/i, /A ServiceWorker intercepted the request and encountered an unexpected error/, /Load failed|Failed to fetch/i);
  await sleep(5200);
  await context.setOffline(true);
  t0 = Date.now();
  await s.clickRow(page, 'notes.txt');
  await page.waitForSelector('#viewer-body .card.error', { timeout: 40000 });
  const offline = Date.now() - t0;
  const said = await page.textContent('#viewer-body .card.error');
  assert.match(said, /offline|does not answer|could not be fetched/i, said);
  assert.ok(offline < 15000, `${s.label}: offline was said after ${offline} ms`);
  await context.setOffline(false);
  await context.close();
  s.note(`unreachable: a Drive rate limit without end is said after ${(limited / 1000).toFixed(1)} s for a file and ${(refreshed / 1000).toFixed(1)} s for a refresh, and the reason is remembered for the page's own question; a store that does not answer after ${(dead / 1000).toFixed(1)} s; offline after ${(offline / 1000).toFixed(1)} s (${JSON.stringify(said.replace('This file cannot be read', ''))})`);
};

steps.signin = async (s) => {
  const { server } = s.stack;
  const { context, page } = await s.open();
  s.expect(/401/, /Failed to load resource/);
  // The page without a session: the static sentences, readable as served.
  const html = await (await fetch(`${s.stack.origin}/`)).text();
  assert.ok(html.includes('Status: ready'));
  for (const sentence of [
    'This site signs you in with a redirect to Google and nothing else. It never asks you to enter a code at google.com/device. A page that does is not gclone.',
    'Open this page from your bookmark or home-screen icon, and check that the address starts with',
    'only on your own device',
    'Never enter a code that someone sent you.',
    'gclone never asks you to enter a code at google.com/device.',
    'Save this passphrase only in a password manager that Google cannot read (Google Password Manager with on-device encryption turned on, iCloud Keychain, or a separate manager). Otherwise decline when the browser offers to save it.',
    'This browser is still signed in to your Google account. On a device that is not yours, sign out of Google too:',
  ]) assert.ok(html.includes(sentence), sentence);
  assert.ok(!/<script(?![^>]*\ssrc=)/.test(html) && !/\son[a-z]+=/.test(html) && !/<style|\sstyle=/.test(html), 'no inline script, handler or style');
  // A code that this tab did not ask for (another state): nothing is sent, the address is cleaned.
  await page.goto(`${s.stack.origin}/callback?code=4%2Fnot-asked-for-code&state=AAAAAAAAAAAAAAAAAAAAAA&iss=https%3A%2F%2Faccounts.google.com`);
  await s.screen(page, 'signin');
  assert.equal(page.url(), `${s.stack.origin}/`);
  assert.equal(server.log.filter((line) => line === 'POST /web/token').length, 0, 'an unasked code is never sent on');
  assert.equal(await page.textContent('#signin-address'), `https://${new URL(s.stack.origin).host}/`);
  // The sign-in: a redirect to Google and back, with PKCE.
  const tokensBefore = server.log.filter((line) => line === 'POST /web/token').length;
  await page.check('#signin-remember');
  // (The test leaves "Google" at once, without a click there: Firefox takes that for a bounce.)
  s.expect(/accounts\.google\.com/, /Failed to load resource/, /cancelled|aborted/i, /bounce tracker/);
  const asked = await s.toGoogle(page);
  assert.equal(asked.origin + asked.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.match(asked.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
  assert.match(asked.searchParams.get('state'), /^[A-Za-z0-9_-]{22}$/);
  assert.equal(asked.searchParams.get('redirect_uri'), `${s.stack.origin}/callback`);
  // The verifier waits in this tab's session storage, and nowhere else.
  const waiting = JSON.parse(await page.evaluate(() => sessionStorage.getItem('gclone.login')));
  assert.deepEqual(Object.keys(waiting).sort(), ['at', 'remember', 'state', 'verifier']);
  assert.equal(waiting.state, asked.searchParams.get('state'));
  assert.equal(crypto.createHash('sha256').update(waiting.verifier).digest('base64url'), asked.searchParams.get('code_challenge'));
  await page.goto(s.callback(asked));
  await s.screen(page, 'unlock');
  assert.equal(page.url(), `${s.stack.origin}/`, 'the code is out of the address');
  assert.equal(server.log.filter((line) => line === 'POST /web/token').length, tokensBefore + 1);
  assert.equal(await page.evaluate(() => sessionStorage.getItem('gclone.login')), null);
  assert.equal([...server.sessions.values()].at(-1).remember, true, '"stay signed in" was sent');
  assert.equal(await page.textContent('#unlock-email'), server.email);
  assert.match(await page.inputValue('#unlock-user'), /^gclone vault [0-9a-f]{8}$/);
  assert.equal(await page.getAttribute('#unlock-pass', 'autocomplete'), 'current-password');
  assert.equal(await page.getAttribute('#unlock-user', 'autocomplete'), 'username');
  assert.match(await page.textContent('#unlock-cost'), /256 MiB/);

  // Wrong passphrases: said each time, the field emptied, one KDF worker for all attempts.
  for (const wrong of ['not the passphrase', PASS.toUpperCase(), `${PASS}!`]) {
    await page.fill('#unlock-pass', wrong);
    await page.click('#unlock-go');
    await page.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock' && !document.getElementById('unlock-problem').hidden);
    assert.equal(await page.textContent('#unlock-problem'), 'That passphrase does not open this vault.');
    assert.equal(await page.inputValue('#unlock-pass'), '');
  }
  const kdfWorkers = () => page.evaluate(() => window.__workers.filter((url) => url.endsWith('/kdf-worker.js')).length);
  assert.equal(await kdfWorkers(), 1, 'three wrong attempts use one KDF worker');
  assert.equal(page.workers().length, 2, 'the vault worker and the KDF worker');
  await s.unlock(page);
  assert.equal(await kdfWorkers(), 1);
  await page.waitForFunction(() => true);
  await sleep(100);
  assert.equal(page.workers().length, 1, 'the KDF worker is terminated after the unlock');
  assert.equal(page.url(), `${s.stack.origin}/`);
  // A sign-in that ended at the Worker while the vault is open: the next call locks and says so.
  await context.close();
  s.note('sign-in: static sentences served; an unasked code is not sent; redirect with PKCE and back; three wrong passphrases use one KDF worker');
};

steps.states = async (s) => {
  const { server, drive } = s.stack;
  // The sign-in ends while the vault is open (the session ran out at the Worker).
  let { context, page } = await s.fresh();
  s.expect(/401/, /Failed to load resource/);
  server.sessions.clear();
  drive.tokens.clear();
  await page.click('#refresh');
  await s.screen(page, 'signin');
  assert.equal(await page.textContent('#signin-problem'), 'Your sign-in has ended. Sign in again.');
  assert.equal(await page.$('#rows'), null);
  await context.close();

  // The same, found out by opening a file: the Service Worker gets no token, tells the page,
  // and the page locks — it does not stay on a list in which nothing opens any more.
  ({ context, page } = await s.fresh());
  s.expect(/401/, /502/, /Failed to load resource/);
  await s.goDir(page, 'docs');
  server.sessions.clear();
  drive.tokens.clear();
  await s.clickRow(page, 'notes.txt');
  await s.screen(page, 'signin');
  assert.equal(await page.textContent('#signin-problem'), 'Your sign-in has ended. Sign in again.');
  assert.equal(await page.$('#rows'), null);
  await context.close();

  // The address was taken off the allowlist: said on the sign-in screen.
  ({ context, page } = await s.open());
  s.expect(/403/, /Failed to load resource/);
  const cookie = server.signIn();
  await context.addCookies([{ ...cookie, url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
  server.refreshError = 'email_not_allowed';
  await page.goto(`${s.stack.origin}/`);
  await s.screen(page, 'signin');
  assert.match(await page.textContent('#signin-problem'), /may not use this viewer/);
  server.refreshError = null;
  await context.close();

  // Google is out of reach for the Worker: a reason and Reload, and the session is kept.
  ({ context, page } = await s.open());
  s.expect(/502/, /Failed to load resource/);
  await context.addCookies([{ ...server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
  server.refreshError = 'upstream_error';
  await page.goto(`${s.stack.origin}/`);
  await s.screen(page, 'stop');
  assert.match(await page.textContent('#stop-text'), /Google did not answer/);
  server.refreshError = null;
  await page.click('#stop-reload');
  await s.screen(page, 'unlock');

  // A tab that the browser killed during the key derivation says so on the next visit.
  await page.evaluate(() => sessionStorage.setItem('gclone.kdf', '262144'));
  await context.addInitScript(() => { if (!sessionStorage.getItem('gclone.once')) { sessionStorage.setItem('gclone.once', '1'); sessionStorage.setItem('gclone.kdf', '262144'); } });
  await page.reload();
  await s.screen(page, 'unlock');
  assert.match(await page.textContent('#unlock-killed'), /may not have the 256 MiB of memory the vault's keyfile asks for/);
  await context.close();

  // No vault visible to the sign-in; and one that needs a newer viewer.
  const descriptor = path.join(s.stack.vault.vaultDir, 'gclone', 'gclone-vault.json');
  const original = fs.readFileSync(descriptor);
  try {
    fs.renameSync(descriptor, `${descriptor}.away`);
    ({ context, page } = await s.open());
    await context.addCookies([{ ...server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
    await page.goto(`${s.stack.origin}/`);
    await s.screen(page, 'stop');
    assert.equal(await page.textContent('#stop-title'), 'No vault here');
    fs.writeFileSync(descriptor, JSON.stringify({ ...JSON.parse(original.toString()), min_reader: 2 }));
    await page.reload();
    await s.screen(page, 'stop');
    assert.equal(await page.textContent('#stop-title'), 'A newer viewer is needed');
    assert.match(await page.textContent('#stop-text'), /needs a newer viewer/);
    await context.close();
  } finally {
    fs.rmSync(`${descriptor}.away`, { force: true });
    fs.writeFileSync(descriptor, original);
  }

  // Two vaults in the account: the page asks which one. And an index object that claims to be
  // huge (planted by whoever has the Drive account): the page asks first, and it can be left out.
  const index = fs.readdirSync(path.join(s.stack.vault.vaultDir, 'gclone', 'index'));
  const snapshot = index.filter((name) => name.startsWith('c-')).sort().at(-1);
  assert.ok(snapshot, 'the fixture has a snapshot');
  const plantedName = `c-ffffffffffffffff-${snapshot.split('-')[2]}-0badc0de`;
  drive.planted.push(
    { id: 'second-descriptor', name: 'gclone-vault.json', parent: 'second-folder', size: 0, bytes: Buffer.from(JSON.stringify({ ...JSON.parse(original.toString()), vault_id: 'ab'.repeat(16), created_ms: 1780000000000 })) },
    { id: 'second-folder', name: 'An older vault', parent: 'root-of-my-drive', size: 0, folder: true },
    { id: 'planted-snapshot', name: plantedName, parent: drive.idOf('gclone/index'), size: 70 * MIB, fill: 5 },
  );
  drive.planted[0].size = drive.planted[0].bytes.length;
  try {
    ({ context, page } = await s.open());
    await context.addCookies([{ ...server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
    await page.goto(`${s.stack.origin}/`);
    await s.screen(page, 'ask');
    assert.equal(await page.textContent('#ask-title'), 'Which vault?');
    const choices = await page.$$eval('#ask-choices button', (buttons) => buttons.map((b) => b.textContent));
    assert.equal(choices.length, 2);
    assert.ok(choices.some((c) => /^An older vault.*abababab$/.test(c)) && choices.some((c) => /^gclone/.test(c)), choices.join(' | '));
    await page.click('#ask-choices button:has-text("gclone")');
    await s.screen(page, 'unlock');
    assert.equal(await page.textContent('#unlock-folder'), 'gclone');
    await page.fill('#unlock-pass', PASS);
    await page.click('#unlock-go');
    await s.screen(page, 'ask', 60000);
    assert.equal(await page.textContent('#ask-title'), 'A large index');
    assert.match(await page.textContent('#ask-text'), /^The index of this vault is 70 MiB\. Loading it needs several times that in memory and may not work in this browser\.$/);
    assert.deepEqual(await page.$$eval('#ask-choices button', (buttons) => buttons.map((b) => b.textContent)), ['Load it', `Skip ${plantedName}70 MiB`, 'Cancel']);
    drive.resetLog();
    await page.click(`#ask-choices button:has-text("Skip")`);
    await page.waitForSelector('#rows .row', { timeout: 60000 });
    assert.ok(!drive.log.gets.some((g) => g.id === 'planted-snapshot'), 'the object that was left out was never requested');
    assert.equal((await s.api(page, 'info')).head, s.stack.vault.device.head());
    assert.match(await page.textContent('#notice-text'), /Not loaded, as you chose: c-ffffffffffffffff/);
    await context.close();
  } finally {
    drive.planted.length = 0;
  }

  // Keyfiles that someone with the Drive account put there. Four names of higher generations
  // that are no keyfiles take no place: the vault opens as if they were not there.
  const rootId = drive.idOf('gclone');
  drive.planted.push(...[0x10, 0x11, 0x12, 0x13].map((g, i) => ({ id: `junk-key-${i}`, name: `gclone-key-${g.toString(16).padStart(8, '0')}-0badc0de`, parent: rootId, size: 300, fill: 7 })));
  try {
    ({ context, page } = await s.open());
    await s.signedIn(context, page);
    await s.unlock(page);
    assert.equal((await s.api(page, 'info')).head, s.stack.vault.device.head());
    await context.close();
  } finally {
    drive.planted.length = 0;
  }
  // Four well-formed keyfiles of another vault, under another passphrase: the right passphrase
  // is "wrong" for each of them — the page says that one more keyfile was not tried, and tries
  // it when asked to.
  const foreign = foreignKeyfile(s.stack.work);
  drive.planted.push(...[9, 8, 7, 6].map((g) => ({ id: `foreign-key-${g}`, name: foreign.name(g), parent: rootId, size: foreign.bytes.length, bytes: foreign.bytes })));
  try {
    ({ context, page } = await s.open());
    await s.signedIn(context, page);
    assert.equal(await page.isVisible('#unlock-more-row'), false);
    await page.fill('#unlock-pass', PASS);
    await page.click('#unlock-go');
    await page.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock' && !document.getElementById('unlock-problem').hidden, null, { timeout: 60000 });
    assert.equal(await page.textContent('#unlock-problem'), 'That passphrase does not open the 4 newest keyfiles of this vault. One more was not tried.');
    assert.equal(await page.isVisible('#unlock-more-row'), true);
    assert.equal(await page.textContent('#unlock-more-text'), 'Also try the one older keyfile of this vault. Slower: one key derivation for each.');
    assert.equal(await page.isChecked('#unlock-more'), false, 'never without being asked');
    // Without the tick the next attempt costs the same four derivations, and says the same.
    await page.fill('#unlock-pass', 'not the passphrase');
    await page.click('#unlock-go');
    await page.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock' && !document.getElementById('unlock-problem').hidden, null, { timeout: 60000 });
    assert.match(await page.textContent('#unlock-problem'), /One more was not tried\.$/);
    await page.check('#unlock-more');
    await s.unlock(page);
    assert.equal((await s.api(page, 'info')).head, s.stack.vault.device.head());
    await context.close();
  } finally {
    drive.planted.length = 0;
  }

  // What a listing says is somebody's text: a name that is no name of gclone's is never put
  // on the page, and a folder's name is cut. And a refresh downloads nothing large unasked.
  const sentence = 'SECURITY NOTICE — your session was moved. Sign in again at https://gclone-viewer.example/unlock and enter your passphrase';
  const indexId = drive.idOf('gclone/index');
  const descriptorNow = JSON.parse(fs.readFileSync(descriptor, 'utf8'));
  drive.planted.push(
    { id: 'planted-name', name: sentence, parent: indexId, size: 2048 * MIB, fill: 1 },
    { id: 'long-descriptor', name: 'gclone-vault.json', parent: 'long-folder', size: 0, bytes: Buffer.from(JSON.stringify({ ...descriptorNow, vault_id: 'cd'.repeat(16) })) },
    { id: 'long-folder', name: `${sentence} ${sentence}`, parent: 'root-of-my-drive', size: 0, folder: true },
  );
  drive.planted[1].size = drive.planted[1].bytes.length;
  try {
    ({ context, page } = await s.open());
    await context.addCookies([{ ...server.signIn(), url: s.stack.origin, httpOnly: true, sameSite: 'Strict' }]);
    await page.goto(`${s.stack.origin}/`);
    await s.screen(page, 'ask');
    const offered = await page.$$eval('#ask-choices button span', (spans) => spans.map((span) => span.firstChild.textContent));
    assert.ok(offered.includes(`${sentence.slice(0, 64)}…`), `the folder's name is cut: ${JSON.stringify(offered)}`);
    assert.ok(offered.every((label) => label.length <= 65));
    await page.click('#ask-choices button:has-text("gclone")');
    await s.screen(page, 'unlock');
    await s.unlock(page);
    await page.waitForFunction(() => !document.getElementById('notice').hidden);
    let notice = await page.textContent('#notice-text');
    assert.equal(notice, "Damaged index objects: an object that is not gclone's (2,048 MiB): larger than an index object can be.");
    assert.ok(!(await page.evaluate(() => document.body.innerText)).includes('SECURITY NOTICE'), 'the planted sentence is nowhere on the page');
    // A segment of 300 MiB appears in the listing while the vault is open; Refresh is pressed.
    const newest = fs.readdirSync(path.join(s.stack.vault.vaultDir, 'gclone', 'index')).filter((name) => name.startsWith('s-')).sort().at(-1);
    const [, writer, seq] = /^s-([0-9a-f]{16})-([0-9a-f]{16})-/.exec(newest);
    drive.planted.push({ id: 'planted-segment', name: `s-${writer}-${(BigInt(`0x${seq}`) + 1n).toString(16).padStart(16, '0')}-0badc0de`, parent: indexId, size: 300 * MIB, fill: 3 });
    drive.resetLog();
    await page.click('#refresh');
    await page.waitForFunction(() => /was not loaded/.test(document.getElementById('notice-text').textContent), null, { timeout: 30000 });
    notice = await page.textContent('#notice-text');
    assert.match(notice, /^1 new index object \(300 MiB\) was not loaded: a refresh downloads no more than 64 MiB without asking\. Lock the vault and unlock it again to decide\./);
    assert.ok(!drive.log.gets.some((g) => g.id === 'planted-segment' || g.id === 'planted-name'), 'a refresh downloaded a planted object');
    assert.equal(await page.isVisible('#rows'), true, 'the list stays, and nothing was asked over it');
    assert.equal((await s.api(page, 'info')).head, s.stack.vault.device.head());
    await context.close();
  } finally {
    drive.planted.length = 0;
  }

  // A phone's Safari, like every browser here, shows a PDF in a tab of its own: a card with "Open".
  ({ context, page } = await s.fresh({ userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1' }));
  await s.goDir(page, 'docs');
  await s.openFile(page, 'report.pdf');
  await page.waitForSelector('#viewer-body .card a.btn[target="_blank"]');
  assert.equal(await page.$('#viewer-body iframe'), null);
  assert.match(await page.getAttribute('#viewer-body .card a.btn[target="_blank"]', 'href'), /^\/v\/[A-Za-z0-9_-]{22}$/);
  await context.close();
  s.note('states: an ended sign-in locks and says so (found by a refresh, and by opening a file); an address off the allowlist; an unreachable Google; a killed tab; no vault; a newer format; two vaults; a 70 MiB planted index object asked about and skipped; four planted keyfile names, and four foreign keyfiles; a planted sentence and a 300 MiB segment at refresh; the PDF card of iOS');
};

steps.big = async (s) => {
  if (!BIG) return;
  const { vault, drive } = s.stack;
  const size = vault.files.get('media/big.mp4').length;
  const want = sha256(vault.files.get('media/big.mp4'));
  // Firefox writes "A ServiceWorker intercepted the request and encountered an unexpected
  // error" for every answer of a Service Worker whose reader stops in the middle — a cancelled
  // fetch, a seek — whatever the worker does (checked with a ten-line worker). This step
  // cancels on purpose; what it reads to the end is compared byte for byte.
  s.tolerated = [/A ServiceWorker intercepted the request and encountered an unexpected error/];
  const { context, page } = await s.fresh();
  await s.goDir(page, 'media');
  await s.openFile(page, 'big.mp4');
  const url = await s.fileUrl(page);
  await page.$eval('#viewer-body video', (v) => { v.removeAttribute('src'); v.load(); });
  await s.closeFile(page);

  // --- streamed, not held: the first bytes arrive while the store has served a sliver ---
  drive.bitsPerSecond = 40 * 1000 * 1000;
  drive.resetLog();
  const memoryBefore = (await s.ping(page)).memory;
  const first = await page.evaluate(async (u) => {
    const res = await fetch(u);
    const reader = res.body.getReader();
    const { value } = await reader.read();
    await reader.cancel();
    return [res.status, value.length, res.headers.get('content-length')];
  }, url);
  assert.deepEqual([first[0], first[2]], [200, String(size)]);
  await sleep(300);
  assert.ok(drive.log.bytes < 8 * MIB, `after the first bytes and a cancel the store had served ${drive.log.bytes} bytes of ${size}`);
  await s.settle(page, 'big: a cancelled read');
  // The whole file through the browser's download, with the store at 400 Mbit/s.
  drive.bitsPerSecond = 400 * 1000 * 1000;
  drive.resetLog();
  const t0 = Date.now();
  await s.openFile(page, 'big.mp4');
  await page.$eval('#viewer-body video', (v) => { v.removeAttribute('src'); v.load(); });
  const saved = await s.download(page, () => page.click('#viewer-download'));
  assert.equal(saved.bytes.length, size);
  assert.equal(sha256(saved.bytes), want, `${s.label}: the large download is byte-identical`);
  const memoryAfter = (await s.ping(page)).memory;
  assert.ok(memoryAfter < 16 * MIB, `the Service Worker's wasm memory is ${memoryAfter} bytes after a ${size}-byte download`);
  await s.settle(page, 'big: the download');
  s.note(`big: ${(size / MIB).toFixed(1)} MiB downloaded byte-identical in ${((Date.now() - t0) / 1000).toFixed(1)} s; Service Worker wasm memory ${(memoryBefore / MIB).toFixed(1)} → ${(memoryAfter / MIB).toFixed(1)} MiB; the store served ${(drive.log.bytes / MIB).toFixed(1)} MiB`);

  // --- a store that is far ahead of the reader: as fast as the loopback goes, and a reader
  //     that pauses. What the Service Worker holds is bounded by its own rules — one window of
  //     the store at a time, a mebibyte into the core per call — not by how the engine hands
  //     a fast answer over (WebKit: in one piece as large as what has arrived). ---
  drive.bitsPerSecond = 0;
  drive.resetLog();
  const fast = await page.evaluate(async (u) => {
    const res = await fetch(u);
    const reader = res.body.getReader();
    const parts = [];
    let total = 0;
    let paused = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
      total += value.length;
      // After the first bytes the reader stops for a while: the store's answer piles up.
      if (!paused) {
        paused = true;
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await new Blob(parts).arrayBuffer()));
    return [res.status, total, Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')];
  }, url);
  assert.deepEqual(fast, [200, size, want], `${s.label}: read from a store that is ahead`);
  const memoryFast = (await s.ping(page)).memory;
  assert.ok(memoryFast < 16 * MIB, `${s.label}: the Service Worker's wasm memory is ${(memoryFast / MIB).toFixed(1)} MiB after a read from a store that was ahead of it`);
  const asked = drive.log.gets.filter((g) => g.range).map((g) => g.range[1] - g.range[0]);
  assert.ok(Math.max(...asked) <= 16 * MIB, `the largest request to the store was ${Math.max(...asked)} bytes`);
  assert.ok(asked.length >= Math.ceil(size / (16 * MIB)), `${asked.length} requests for ${size} bytes`);
  // While the reader paused, the store was not asked for more than the window in hand and the next.
  await s.settle(page, 'big: a store that is ahead');
  s.note(`big: a store at loopback speed and a reader that pauses: ${asked.length} requests of at most ${(Math.max(...asked) / MIB).toFixed(1)} MiB; Service Worker wasm memory ${(memoryFast / MIB).toFixed(1)} MiB`);
  await s.closeFile(page);

  // --- throughput: 300 ms to the first byte, 60 Mbit/s; a 20 Mbit/s recording plays through ---
  drive.latencyMs = 300;
  drive.bitsPerSecond = 60 * 1000 * 1000;
  drive.resetLog();
  await s.openFile(page, 'big.mp4');
  const played = await page.$eval('#viewer-body video', (v) => new Promise((resolve, reject) => {
    const events = [];
    let started = false;
    v.muted = true;
    for (const type of ['waiting', 'stalled']) v.addEventListener(type, () => { if (started && !v.ended && v.currentTime < v.duration - 0.5) events.push([type, Number(v.currentTime.toFixed(2))]); });
    v.addEventListener('playing', () => { started = true; }, { once: true });
    v.addEventListener('ended', () => resolve({ events, duration: v.duration, at: v.currentTime }));
    v.addEventListener('error', () => reject(new Error(`media error ${v.error && v.error.code}`)));
    setTimeout(() => resolve({ events, duration: v.duration, at: v.currentTime, timeout: true }), 60000);
    v.play().catch(reject);
  }));
  assert.ok(!played.timeout, `the recording did not finish in 60 s (at ${played.at} of ${played.duration})`);
  assert.ok(Math.abs(played.duration - 20) < 0.5);
  // Once it runs, playback never waits for data. (The first second is the start itself: the
  // element had only the metadata, and the first window is the small one. `stalled` only says
  // that no data arrived for a while, which is what windowed answers look like in between.)
  const waits = played.events.filter(([type, at]) => type === 'waiting' && at >= 1);
  assert.deepEqual(waits, [], `${s.label}: playback waited for data`);
  const early = played.events.filter(([type, at]) => type === 'waiting' && at < 1).length;
  await s.settle(page, 'big: the play');
  const playBytes = drive.log.bytes;
  assert.ok(playBytes <= BYTE_BUDGET[s.engine].play, `20 s of play made the store serve ${playBytes} bytes`);
  // Three seeks: each abandons at most the window it interrupts.
  drive.resetLog();
  for (const t of [15, 4, 11]) {
    const at = await seekTo(page, '#viewer-body video', t);
    assert.ok(Math.abs(at - t) < 0.3);
  }
  await sleep(500);
  const seekBytes = drive.log.bytes;
  assert.ok(seekBytes <= BYTE_BUDGET[s.engine].seeks, `three seeks made the store serve ${seekBytes} bytes`);
  const windows = drive.log.gets.filter((g) => g.range).map((g) => g.range[1] - g.range[0]);
  assert.ok(Math.max(...windows) <= 8 * MIB + 2 * 65552, `the largest request to the store was ${Math.max(...windows)} bytes`);
  drive.latencyMs = 0;
  drive.bitsPerSecond = 0;
  await s.settle(page, 'big: the seeks');
  s.tolerated = [];
  await context.close();
  s.note(`throughput: 20 s at 20 Mbit/s over a 60 Mbit/s store with 300 ms to first byte played without waiting after its first second (waits while starting: ${early}; stalled events: ${played.events.filter(([type]) => type === 'stalled').length}); the store served ${(playBytes / MIB).toFixed(1)} MiB for the play and ${(seekBytes / MIB).toFixed(1)} MiB for three seeks`);
};

// ------------------------------------------------------------------------------------------------

/** Steps that share one unlocked page, in this order; then the ones that make their own. */
const SHARED = ['listing', 'sort', 'search', 'names', 'previews', 'media', 'download', 'recovery', 'refresh', 'history', 'keys'];
const OWN = ['signin', 'lock', 'tabs', 'signout', 'hardening', 'unreachable', 'states', 'big'];

async function runEngine(engine, playwright) {
  const stack = await startStack({ big: BIG || undefined });
  const s = new Session(engine, playwright, stack);
  await s.launch();
  const started = Date.now();
  console.log(`${s.label}: build ${stack.server.build}`);
  try {
    const wanted = (name) => !ONLY || ONLY.includes(name);
    if (SHARED.some(wanted)) {
      const { context, page } = await s.open();
      await s.signedIn(context, page);
      await s.unlock(page);
      await s.settle(page, 'unlock');
      for (const name of SHARED.filter(wanted)) {
        await steps[name](s, page);
        await s.settle(page, name);
      }
      // No request for a file ever reached the "Worker": every /v/ address was the Service Worker's.
      assert.deepEqual(stack.server.strays.filter((line) => line.includes('/v/')), [], 'a /v/ address reached the network');
      await context.close();
    }
    for (const name of OWN.filter(wanted)) {
      await steps[name](s);
      await s.settle(null, name);
    }
    // What the fake Drive saw of the viewer: its origin, and never a cookie or a token in an address.
    assert.deepEqual([...stack.drive.log.origins], [stack.origin]);
    console.log(`${s.label}: OK (${((Date.now() - started) / 1000).toFixed(0)} s)`);
  } catch (error) {
    console.error(`${s.label}: FAILED\n${await s.diagnose().catch((e) => `(no diagnosis: ${e})`)}`);
    throw error;
  } finally {
    await s.browser.close();
    await stack.close();
  }
}

const playwright = await loadPlaywright();
const engines = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(ENGINES);
for (const engine of engines) {
  if (!ENGINES[engine]) throw new Error(`no engine named ${engine}: ${Object.keys(ENGINES).join(', ')}`);
  await runEngine(engine, playwright);
}
console.log('OK');
