// The sign-in round trip against the REAL Worker code (design §11): `handle()` of
// worker/src/index.ts, bundled with the esbuild that wrangler ships and run in Node, with a
// fake Google behind it; the built viewer bundle in front; the fake Drive for the vault.
//
//   page → POST /web/start → "Google" → /callback → POST /web/token → cookie
//        → reload → POST /web/refresh → unlock → the list → POST /web/logout
//
//   node worker/test/e2e/signin.mjs
//
// Chrome only: it takes a `Secure` `__Host-` cookie on http://127.0.0.1; what Safari does
// with it is checked on the deployment. Environment as for run.mjs. Nothing real is
// involved: Google's endpoints are functions of this file.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { ENGINES, REPO, bundle, loadPlaywright } from './harness.mjs';
import { FakeDrive } from './fake-drive.mjs';
import { ViewerServer } from './server.mjs';
import { PASS, buildVault } from './vault.mjs';

const WEB_CLIENT = { id: 'web-cid.apps.googleusercontent.com', secret: 'test-web-secret' };
const EMAIL = 'owner@example.com';
const GRANTED = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file';
const b64url = (value) => Buffer.from(value).toString('base64url');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-viewer-signin-'));

// --- the Worker's code, as wrangler would bundle it ------------------------------------------------
const require = createRequire(path.join(REPO, 'worker', 'package.json'));
const esbuild = require('esbuild');
const bundled = path.join(work, 'worker.mjs');
await esbuild.build({ entryPoints: [path.join(REPO, 'worker', 'src', 'index.ts')], bundle: true, format: 'esm', platform: 'neutral', outfile: bundled, logLevel: 'silent' });
const { handle, GOOGLE_AUTH_URL } = await import(pathToFileURL(bundled).href);

// --- Google, as two functions ------------------------------------------------------------------------
class FakeGoogle {
  constructor(drive) {
    this.drive = drive;
    /** code → { challenge, nonce, redirect, email } */
    this.codes = new Map();
    this.refreshTokens = new Map();
    this.calls = [];
    this.revoked = [];
  }

  /** The consent: what Google's page would send the browser back with. */
  consent(asked, email = EMAIL) {
    const code = `4/0A${crypto.randomBytes(18).toString('base64url')}`;
    this.codes.set(code, { challenge: asked.searchParams.get('code_challenge'), nonce: asked.searchParams.get('nonce'), redirect: asked.searchParams.get('redirect_uri'), email });
    const back = new URL(asked.searchParams.get('redirect_uri'));
    back.searchParams.set('state', asked.searchParams.get('state'));
    back.searchParams.set('code', code);
    back.searchParams.set('scope', 'email openid https://www.googleapis.com/auth/drive.file');
    back.searchParams.set('iss', 'https://accounts.google.com');
    return back.href;
  }

  access() {
    const token = `ya29.fake-${crypto.randomBytes(9).toString('base64url')}`;
    this.drive.tokens.add(token);
    return token;
  }

  idToken(email, nonce) {
    const claims = { iss: 'https://accounts.google.com', aud: WEB_CLIENT.id, azp: WEB_CLIENT.id, sub: '1234567890', email, email_verified: true, iat: 1, exp: 2 };
    if (nonce) claims.nonce = nonce;
    return `${b64url(JSON.stringify({ alg: 'RS256', kid: 'fake', typ: 'JWT' }))}.${b64url(JSON.stringify(claims))}.c2lnbmF0dXJl`;
  }

  /** `deps.fetch` of the Worker: the token endpoint and the revocation endpoint. */
  async fetch(input, init) {
    const url = String(input instanceof Request ? input.url : input);
    const form = new URLSearchParams(init && init.body ? String(init.body) : '');
    this.calls.push({ url, grant: form.get('grant_type') });
    const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    if (url === 'https://oauth2.googleapis.com/revoke') {
      this.revoked.push(form.get('token'));
      return json(200, {});
    }
    if (url !== 'https://oauth2.googleapis.com/token') return json(404, { error: 'not_found' });
    if (form.get('client_id') !== WEB_CLIENT.id || form.get('client_secret') !== WEB_CLIENT.secret) return json(401, { error: 'invalid_client' });
    if (form.get('grant_type') === 'authorization_code') {
      const issued = this.codes.get(form.get('code'));
      this.codes.delete(form.get('code'));
      const challenge = crypto.createHash('sha256').update(form.get('code_verifier') || '').digest('base64url');
      if (!issued || issued.challenge !== challenge) return json(400, { error: 'invalid_grant', error_description: 'Bad Request' });
      if (issued.redirect !== form.get('redirect_uri')) return json(400, { error: 'redirect_uri_mismatch' });
      const refresh = `1//fake-refresh-${crypto.randomBytes(24).toString('base64url')}`;
      this.refreshTokens.set(refresh, issued.email);
      return json(200, { access_token: this.access(), expires_in: 3599, refresh_token: refresh, scope: GRANTED, token_type: 'Bearer', id_token: this.idToken(issued.email, issued.nonce) });
    }
    if (form.get('grant_type') === 'refresh_token') {
      const email = this.refreshTokens.get(form.get('refresh_token'));
      if (!email) return json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
      return json(200, { access_token: this.access(), expires_in: 3599, scope: GRANTED, token_type: 'Bearer', id_token: this.idToken(email) });
    }
    return json(400, { error: 'unsupported_grant_type' });
  }
}

// --- the viewer's origin: static files as the asset layer serves them, everything else the Worker ----
class WorkerServer extends ViewerServer {
  constructor(options) {
    super(options);
    this.google = options.google;
    this.env = {
      GOOGLE_CLIENT_ID: 'device-cid.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET: 'test-device-secret',
      GOOGLE_LEGACY_CLIENT_ID: WEB_CLIENT.id, GOOGLE_LEGACY_CLIENT_SECRET: WEB_CLIENT.secret,
      SEAL_KEY: crypto.randomBytes(32).toString('base64'),
      ALLOWED_EMAILS: EMAIL,
      // The assets binding: the Worker reads index.html from it and nothing else.
      ASSETS: { fetch: async (request) => {
        const asked = new URL(request.url).pathname;
        this.assetRequests.push(asked);
        return asked === '/index.html' ? new Response(fs.readFileSync(path.join(this.dist, 'index.html'))) : new Response(null, { status: 404 });
      } },
    };
    this.assetRequests = [];
    this.deps = {
      fetch: (input, init) => this.google.fetch(input, init),
      now: () => Date.now(),
      google: { deviceCodeUrl: 'https://oauth2.googleapis.com/device/code', tokenUrl: 'https://oauth2.googleapis.com/token', revokeUrl: 'https://oauth2.googleapis.com/revoke', authUrl: GOOGLE_AUTH_URL },
    };
    /** What the Worker answered on its JSON routes: `[path, status, body text]`. */
    this.answers = [];
  }

  async handle(req, res) {
    const url = new URL(req.url, this.origin);
    this.log.push(`${req.method} ${url.pathname}`);
    if (url.pathname.startsWith('/a/') || url.pathname === '/sw.js') return this.asset(req, res, url);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
    const request = new Request(url.href, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : Buffer.concat(chunks) });
    const logged = [];
    const log = console.log;
    console.log = (line) => logged.push(line); // the Worker's one log line per request
    let answer;
    try { answer = await handle(request, this.env, this.deps); } finally { console.log = log; }
    this.workerLog = (this.workerLog || []).concat(logged);
    const out = {};
    for (const [name, value] of answer.headers) if (name !== 'set-cookie') out[name] = value;
    // The one swap of the test server: the Drive host in the page's policy.
    if (out['content-security-policy']) out['content-security-policy'] = out['content-security-policy'].replace('https://www.googleapis.com', this.drive.origin);
    const cookies = answer.headers.getSetCookie();
    if (cookies.length) out['set-cookie'] = cookies;
    const body = Buffer.from(await answer.arrayBuffer());
    if (url.pathname.startsWith('/web/') || url.pathname === '/refresh') this.answers.push([url.pathname, answer.status, body.toString()]);
    res.writeHead(answer.status, out);
    res.end(body);
    return undefined;
  }
}

const vault = buildVault(work, { many: 5 });
const drive = new FakeDrive(vault.vaultDir);
await drive.listen();
const google = new FakeGoogle(drive);
const server = new WorkerServer({ dist: bundle(work), drive, google });
await server.listen();
const origin = server.origin;
const playwright = await loadPlaywright();
const browser = await ENGINES.chrome(playwright);
try {
  const context = await browser.newContext();
  let asked = null;
  await context.route('https://accounts.google.com/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/o/oauth2/v2/auth')) asked = url;
    await route.abort('aborted');
  });
  const page = await context.newPage();
  const screen = (name) => page.waitForSelector(`#shell[data-screen="${name}"]:not([hidden])`, { timeout: 30000 });
  const toGoogle = async () => {
    asked = null;
    await page.click('#signin-go');
    for (let i = 0; i < 100 && !asked; i += 1) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(asked, 'the page went to Google');
    return asked;
  };
  const cookie = async () => (await context.cookies(origin)).find((c) => c.name === '__Host-gclone-web');

  // The page as the Worker serves it: the bundle's index.html with the status line.
  await page.goto(`${origin}/`);
  await screen('signin');
  const html = await (await fetch(`${origin}/`)).text();
  assert.ok(html.includes('Status: ready') && !html.includes('gclone-status'), 'the Worker put the status line in');
  assert.deepEqual([...new Set(server.assetRequests)], ['/index.html']);

  // An account that is not on the allowlist: refused by the Worker, said on the sign-in screen, no cookie.
  let url = await toGoogle();
  await page.goto(google.consent(url, 'stranger@example.org'));
  await screen('signin');
  assert.match(await page.textContent('#signin-problem'), /s\*\*\*@example\.org/);
  assert.equal(await cookie(), undefined);
  assert.equal(google.revoked.length, 1, 'the grant of the stranger was revoked');

  // The owner: the authorization address is the Worker's, the code comes back, the cookie is set.
  url = await toGoogle();
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.deepEqual([...url.searchParams.keys()], ['client_id', 'redirect_uri', 'response_type', 'scope', 'access_type', 'prompt', 'code_challenge', 'code_challenge_method', 'state', 'nonce']);
  assert.equal(url.searchParams.get('client_id'), WEB_CLIENT.id);
  assert.equal(url.searchParams.get('redirect_uri'), `${origin}/callback`);
  assert.equal(url.searchParams.get('scope'), 'openid email https://www.googleapis.com/auth/drive.file');
  await page.goto(google.consent(url));
  await screen('unlock');
  assert.equal(page.url(), `${origin}/`);
  assert.equal(await page.textContent('#unlock-email'), EMAIL);
  const set = await cookie();
  assert.ok(set, 'Chrome took the session cookie');
  assert.deepEqual([set.httpOnly, set.secure, set.sameSite, set.path, set.expires], [true, true, 'Strict', '/', -1], 'HttpOnly, Secure, SameSite=Strict, a session cookie');
  assert.equal(await page.evaluate(() => document.cookie), '', 'script cannot read it');

  // A reload: the session is the cookie; the Worker asks Google with the sealed refresh token.
  const refreshes = () => google.calls.filter((c) => c.grant === 'refresh_token').length;
  const before = refreshes();
  await page.reload();
  await screen('unlock');
  assert.equal(refreshes(), before + 1);
  assert.equal(await page.textContent('#unlock-email'), EMAIL);

  // The vault opens with the tokens that came through the Worker.
  await page.fill('#unlock-pass', PASS);
  await page.click('#unlock-go');
  await page.waitForSelector('#rows .row', { timeout: 60000 });
  assert.deepEqual(await page.$$eval('#rows .row .name', (nodes) => nodes.map((n) => n.title)), ['bin', 'deep', 'docs', 'many', 'media', 'names', 'pics', 'README.md']);

  // Sign out: the cookie goes, the signed-out screen says what is left.
  await page.click('#info-btn');
  await page.click('#session-out');
  await screen('out');
  assert.equal(await cookie(), undefined, 'the cookie is cleared');
  await page.reload();
  await screen('signin');

  // No answer of the Worker ever carried the refresh token, and its log lines hold no secret.
  const said = server.answers.map((a) => a.join(' ')).join('\n');
  assert.ok(!said.includes('1//fake-refresh'), 'a refresh token left the Worker');
  assert.ok(server.answers.some(([p, status]) => p === '/web/token' && status === 200) && server.answers.some(([p, status]) => p === '/web/refresh' && status === 200) && server.answers.some(([p, status]) => p === '/web/logout' && status === 200));
  const logged = (server.workerLog || []).join('\n');
  assert.ok(logged.includes('/web/token') && !/ya29|1\/\/fake|4\/0A|@example/.test(logged), 'the Worker logs routes and statuses only');
  console.log(`chrome ${browser.version()}: sign-in round trip through the real Worker code: start → Google → /callback → token (cookie: HttpOnly, Secure, SameSite=Strict) → reload → refresh → unlock → logout; an address off the allowlist is refused and revoked`);
  console.log('OK');
} finally {
  await browser.close();
  await server.close();
  await drive.close();
  fs.rmSync(work, { recursive: true, force: true });
}
