// The module smoke test (design §11, first milestone of P2): the `--target no-modules` build
// is loaded with importScripts() in a dedicated worker (twice: KDF worker, vault worker) and
// in a Service Worker, under the Content-Security-Policy and the Trusted Types policy of design
// §4.3; a key bundle goes KDF worker → vault worker and a ticket vault worker → Service Worker
// over MessagePorts the page made and gave away; one ranged read and one whole read answer.
//
//   node run.mjs [chrome] [webkit] [firefox]        (default: all three)
//
// Environment: GCLONE_WEB_CORE_EXPORT (what tests/parity.rs exported — the vault that is
// served), GCLONE_WEB_CORE_PKG (default ../../pkg), GCLONE_PLAYWRIGHT_CORE (the directory of
// the playwright-core package, if `playwright-core` does not resolve from here),
// PLAYWRIGHT_BROWSERS_PATH (Playwright's WebKit and Firefox). Chrome is the installed Google
// Chrome (`channel: 'chrome'`), never Playwright's Chromium.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(here, 'app');
const PKG = process.env.GCLONE_WEB_CORE_PKG || path.join(here, '..', '..', 'pkg');
const EXPORT = process.env.GCLONE_WEB_CORE_EXPORT;
if (!EXPORT) throw new Error('GCLONE_WEB_CORE_EXPORT is not set (cargo test --test parity writes it; see test/run.sh)');

const playwright = await import(process.env.GCLONE_PLAYWRIGHT_CORE
  ? pathToFileURL(path.join(process.env.GCLONE_PLAYWRIGHT_CORE, 'index.mjs')).href
  : 'playwright-core');

// The header set of design §4.3. (`connect-src`: the viewer adds the Drive host; here the
// "store" is this server.)
const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; "
  + "media-src 'self'; frame-src 'self'; worker-src 'self'; connect-src 'self'; base-uri 'none'; "
  + "form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types gclone";
const HEADERS = {
  'Content-Security-Policy': CSP,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-cache',
};
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.wasm': 'application/wasm', '.json': 'application/json' };

const busy = JSON.parse(fs.readFileSync(path.join(EXPORT, 'busy/expect.json'), 'utf8'));
const gates = JSON.parse(fs.readFileSync(path.join(EXPORT, 'gates/expect.json'), 'utf8'));
const keyfile = gates.keyfiles.find((k) => k.expect === 'ok');
const file = busy.files.find((f) => f.ticket.size > 3 * 65536);
const plain = fs.readFileSync(path.join(EXPORT, 'busy', file.plain));
const [start, end] = [70000, 140010];
const fixture = {
  listing: busy.listing,
  keyfile: { url: `/fixture/keyfiles/${keyfile.name}`, name: keyfile.name, pass: keyfile.pass, vault_id: keyfile.vault_id },
  file: { path: file.path, start, end },
  id: 'smoke_0123456789-abcdE',
};
const requests = [];

function serve(req, res) {
  const url = new URL(req.url, 'http://x');
  requests.push(`${req.method} ${url.pathname}${req.headers.range ? ` [${req.headers.range}]` : ''}`);
  const send = (status, type, body, extra = {}) => {
    res.writeHead(status, { ...HEADERS, 'Content-Type': type, 'Content-Length': body.length, ...extra });
    res.end(body);
  };
  let target;
  if (url.pathname === '/favicon.ico') return send(200, 'image/x-icon', Buffer.alloc(0));
  if (url.pathname === '/') target = path.join(APP, 'index.html');
  else if (url.pathname === '/fixture.json') return send(200, TYPES['.json'], Buffer.from(JSON.stringify(fixture)));
  else if (url.pathname === '/core.js' || url.pathname === '/core.wasm') target = path.join(PKG, url.pathname.slice(1));
  else if (url.pathname.startsWith('/fixture/')) target = path.join(EXPORT, decodeURIComponent(url.pathname.slice('/fixture/'.length)));
  else target = path.join(APP, url.pathname.slice(1));
  const root = url.pathname.startsWith('/fixture/') ? EXPORT : url.pathname.startsWith('/core.') ? PKG : APP;
  if (!path.resolve(target).startsWith(path.resolve(root) + path.sep) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
    return send(404, 'text/plain; charset=utf-8', Buffer.from('not found'));
  }
  const body = fs.readFileSync(target);
  const type = TYPES[path.extname(target)] || 'application/octet-stream';
  const range = /^bytes=(\d+)-(\d+)$/.exec(req.headers.range || '');
  if (range) {
    const [from, to] = [Number(range[1]), Math.min(Number(range[2]), body.length - 1)];
    return send(206, type, body.subarray(from, to + 1), { 'Content-Range': `bytes ${from}-${to}/${body.length}` });
  }
  return send(200, type, body);
}

const ENGINES = {
  chrome: () => playwright.chromium.launch({ headless: true, channel: 'chrome' }),
  webkit: () => playwright.webkit.launch({ headless: true }),
  firefox: () => playwright.firefox.launch({ headless: true }),
};

async function run(engine) {
  const server = http.createServer(serve);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await ENGINES[engine]();
  try {
    const page = await (await browser.newContext()).newPage();
    const problems = [];
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`pageerror: ${e}`));
    await page.goto(`${origin}/`);
    await page.waitForFunction(() => window.__smoke && window.__smoke.done, null, { timeout: 60000 });
    const out = await page.evaluate(() => window.__smoke);
    const label = `${engine} ${browser.version()}`;
    assert.equal(out.error, undefined, `${label}: ${out.error}\n${problems.join('\n')}`);
    // The module ran in all three kinds of context, loaded by importScripts.
    for (const context of ['kdf', 'vault', 'sw']) assert.equal(out[context].version, busy.version, `${label}: ${context}`);
    assert.deepEqual(out.kdf.cost, keyfile.cost);
    // The keys crossed from worker to worker; the vault worker loaded the index.
    assert.deepEqual([out.vault.vault_id, out.vault.wiped, out.vault.snapshot, out.vault.head, out.vault.files, out.vault.blocked],
      [busy.vault_id, true, true, busy.head, busy.report.files, 0], label);
    // One ticket crossed to the Service Worker, and it answers ranges and whole reads.
    assert.deepEqual([out.issue.issued, out.sw.tickets], [fixture.id, 1], label);
    assert.equal(out.read.status, 206, label);
    assert.equal(out.read.range, `bytes ${start}-${end - 1}/${plain.length}`);
    assert.equal(out.read.length, String(end - start));
    assert.equal(out.read.hex, plain.subarray(start, end).toString('hex'), `${label}: the ranged read`);
    assert.equal(out.read.type, 'video/mp4');
    assert.match(out.read.csp, /^sandbox; default-src 'none'/);
    assert.deepEqual([out.whole.status, out.whole.length, out.whole.sha256],
      [200, plain.length, crypto.createHash('sha256').update(plain).digest('hex')], `${label}: the whole read`);
    assert.equal(out.unknown.status, 410, `${label}: no ticket, no answer`);
    // The policy held: no eval, no violation reported, and nothing a worker told the page
    // holds key material.
    assert.equal(out.evalThrows, true, `${label}: eval is refused`);
    // The two probes the page makes on purpose are the only things a browser complains about:
    // the request without a ticket (410) and the `eval` that the policy refuses.
    // (A script URL that the policy refused would not be a console line only: the worker
    // would not start, and the assertions above would have failed.)
    const expected = [/status of 410/, /410 \(/, /TrustedScript/, /require-trusted-types-for/, /unsafe-eval/, /EvalError/, /call to eval\(\)/i];
    assert.deepEqual(problems.filter((p) => !expected.some((e) => e.test(p))), [], `${label}: console`);
    const told = out.seen.join('\n');
    assert.ok(!/"key"|"bundle"|"ticket"|"header"/.test(told), `${label}: the page was told ${told}`);
    // The ciphertext was asked for by range: the chunks of the range, then of the file.
    const blobGets = requests.filter((r) => r.includes('/fixture/busy/blobs/'));
    assert.ok(blobGets.length === 2 && blobGets.every((r) => r.includes('[bytes=')), blobGets.join('; '));
    const types = [out.trustedTypes, out.kdf.trustedTypes, out.vault.trustedTypes, out.sw.trustedTypes];
    console.log(`${label}: core ${busy.version} loaded by importScripts in KDF worker, vault worker and Service Worker; `
      + `unlock ${out.kdf.ms} ms (${keyfile.cost.m_kib} KiB); bundle and ticket over MessagePorts; 206 and 200 identical; eval refused; `
      + `Trusted Types enforced in page/kdf/vault/sw: ${types.join('/')}`);
    return types;
  } finally {
    await browser.close();
    server.close();
    requests.length = 0;
  }
}

const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(ENGINES);
for (const engine of wanted) await run(engine);
console.log('OK');
