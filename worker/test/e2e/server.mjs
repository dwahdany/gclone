// The viewer's origin for the tests: a built `dist/` served the way the deployment serves it,
// and a fake of the Worker's browser routes.
//
//   /a/<build>/*, /sw.js     the files of `dist/` with the header set of `dist/_headers`,
//                            `Cache-Control: public, max-age=0, must-revalidate`, an ETag and
//                            `304`; a miss under /a/ is an empty 404 (the asset layer's answers)
//   /, /callback             `dist/index.html` with the status line, the header set, `no-store`
//   POST /web/start|token|refresh|logout   the shapes of worker/test/contract.json
//   anything else            the Worker's JSON 404
//
// One thing differs from the deployment, and only on the way out: the Drive host. The bundle
// names `https://www.googleapis.com` in exactly two places — `connect-src` of the policy and
// one constant in drive.js — and this server answers both with the fake Drive's origin
// instead. The files on disk are not touched.
//
// The fake sign-in: `/web/start` answers Google's real authorization address (the page checks
// it); the test answers the navigation there itself and comes back to `/callback` with the
// code this server expects. The session is a cookie without `Secure` (the real one is
// `__Host-…; Secure`, which not every engine takes on http://127.0.0.1).
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

const DRIVE_HOST = 'https://www.googleapis.com';
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.json': 'application/json',
};
const COOKIE = 'gclone-web-fake';

/** `_headers` → the header set of its first rule (both rules carry the same set). */
export function parseHeadersFile(text) {
  const rules = new Map();
  let current = null;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      current = {};
      rules.set(line.trim(), current);
    } else {
      const at = line.indexOf(':');
      current[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
  }
  return rules;
}

export class ViewerServer {
  /**
   * `dist`: a built bundle. `drive`: a FakeDrive (its origin replaces the Drive host, and it
   * accepts the tokens this server issues). `email`: who signs in.
   */
  constructor({ dist, drive, email = 'owner@example.com', status = 'Status: ready' }) {
    this.dist = dist;
    this.drive = drive;
    this.email = email;
    this.status = status;
    /** Seconds an access token is said to live. */
    this.expiresIn = 3599;
    /** sid → { email, exp, remember } */
    this.sessions = new Map();
    /** code → { challenge } (single use) */
    this.codes = new Map();
    /** state → challenge, of sign-ins that were started */
    this.started = new Map();
    this.tokenCount = 0;
    this.log = [];
    /** Requests that reached the "Worker" for a path it does not serve (a `/v/…` that missed the Service Worker). */
    this.strays = [];
    /** true: `GET /dev/signin` signs in without Google (serve.mjs only). */
    this.dev = false;
    /** Set to an error code to make `/web/refresh` fail with it. */
    this.refreshError = null;
    const rules = parseHeadersFile(fs.readFileSync(path.join(dist, '_headers'), 'utf8'));
    this.assetHeaders = rules.get('/a/*');
    if (!this.assetHeaders || JSON.stringify(rules.get('/sw.js')) !== JSON.stringify(this.assetHeaders)) {
      throw new Error('dist/_headers does not carry one header set for /a/* and /sw.js');
    }
    const builds = fs.readdirSync(path.join(dist, 'a'));
    if (builds.length !== 1) throw new Error('dist/a must hold exactly one build');
    [this.build] = builds;
    // The Drive host is named once in the scripts: that is what makes the swap below complete.
    const named = fs.readdirSync(path.join(dist, 'a', this.build)).filter((name) => name.endsWith('.js'))
      .map((name) => [name, fs.readFileSync(path.join(dist, 'a', this.build, name), 'utf8').split(DRIVE_HOST).length - 1])
      .filter(([, n]) => n > 0);
    if (JSON.stringify(named) !== JSON.stringify([['drive.js', 1]])) {
      throw new Error(`the Drive host must be named exactly once, in drive.js; found ${JSON.stringify(named)}`);
    }
    if (fs.readFileSync(path.join(dist, 'sw.js'), 'utf8').includes(DRIVE_HOST)) throw new Error('sw.js names the Drive host');
    this.sockets = new Set();
    this.server = http.createServer((req, res) => {
      this.handle(req, res).catch((error) => {
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(String(error && error.stack));
      });
    });
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
    });
  }

  async listen(port = 0) {
    await new Promise((resolve) => this.server.listen(port, '127.0.0.1', resolve));
    this.origin = `http://127.0.0.1:${this.server.address().port}`;
    return this.origin;
  }

  async close() {
    for (const socket of this.sockets) socket.destroy();
    await new Promise((resolve) => this.server.close(resolve));
  }

  /** The header set, with the fake Drive in place of the Drive host. */
  headers() {
    const out = { ...this.assetHeaders };
    const csp = out['Content-Security-Policy'];
    if (csp.split(DRIVE_HOST).length !== 2) throw new Error('the policy must name the Drive host exactly once');
    out['Content-Security-Policy'] = csp.replace(DRIVE_HOST, this.drive.origin);
    return out;
  }

  /** A signed-in session without the round trip to "Google": the cookie value for the tests. */
  signIn({ remember = false } = {}) {
    const sid = crypto.randomBytes(24).toString('base64url');
    this.sessions.set(sid, { email: this.email, exp: Date.now() + (remember ? 2592000 : 43200) * 1000, remember });
    return { name: COOKIE, value: sid };
  }

  /** The code "Google" hands back for a sign-in that was started with `state`. */
  consent(state) {
    const challenge = this.started.get(state);
    if (!challenge) throw new Error('no sign-in was started with this state');
    const code = `4/fake-${crypto.randomBytes(12).toString('base64url')}`;
    this.codes.set(code, { challenge });
    return code;
  }

  issueToken() {
    this.tokenCount += 1;
    const token = `fake-access-${this.tokenCount}-${crypto.randomBytes(6).toString('hex')}`;
    this.drive.tokens.add(token);
    return token;
  }

  session(req) {
    const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map((part) => part.trim().split('=')).filter((pair) => pair.length === 2));
    const sid = cookies[COOKIE];
    const session = sid && this.sessions.get(sid);
    if (!session) return { sid: sid || null, session: null };
    if (Date.now() > session.exp) {
      this.sessions.delete(sid);
      return { sid, session: null };
    }
    return { sid, session };
  }

  async handle(req, res) {
    const url = new URL(req.url, this.origin);
    this.log.push(`${req.method} ${url.pathname}`);
    if (url.pathname.startsWith('/a/') || url.pathname === '/sw.js') return this.asset(req, res, url);
    const json = (status, body, extra = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
      res.end(JSON.stringify(body));
    };
    const fail = (status, error, message, extra) => json(status, { error, message }, extra);
    if (url.pathname === '/' || url.pathname === '/callback') {
      if (req.method !== 'GET') return fail(405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
      const page = fs.readFileSync(path.join(this.dist, 'index.html'), 'utf8').replace('<!--gclone-status-->', () => this.status);
      res.writeHead(200, { ...this.headers(), 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(page);
      return undefined;
    }
    if (url.pathname === '/dev/signin' && this.dev) {
      // For looking at the viewer by hand (serve.mjs): signed in without the trip to Google.
      const cookie = this.signIn();
      res.writeHead(303, { Location: '/', 'Set-Cookie': `${COOKIE}=${cookie.value}; Path=/; HttpOnly; SameSite=Strict`, 'Cache-Control': 'no-store' });
      res.end();
      return undefined;
    }
    if (url.pathname === '/privacy') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('<!doctype html><title>Privacy</title><p>The privacy page of the fake Worker.</p>');
      return undefined;
    }
    if (!url.pathname.startsWith('/web/')) {
      this.strays.push(`${req.method} ${url.pathname}${url.search}`);
      return fail(404, 'not_found', 'There is nothing here.');
    }
    // The common rules of the four browser routes (worker/src/web.ts), in their order.
    if (req.method !== 'POST') return fail(405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    const site = req.headers['sec-fetch-site'];
    if (req.headers.origin !== this.origin || (site !== undefined && site !== 'same-origin')) return fail(403, 'cross_origin', 'This route answers the viewer\'s own page only.');
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) return fail(415, 'unsupported_media_type', 'Send JSON.');
    let raw = '';
    for await (const piece of req) raw += piece;
    if (raw.length > 8192) return fail(413, 'payload_too_large', 'The request is too large.');
    let body;
    try { body = JSON.parse(raw); } catch { body = null; }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) return fail(400, 'invalid_request', 'The request is not a JSON object.');
    const clear = { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` };
    const grant = (session) => ({
      access_token: this.issueToken(), expires_in: this.expiresIn, scope: 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file',
      email: session.email, session_expires_in: Math.max(0, Math.floor((session.exp - Date.now()) / 1000)),
    });

    if (url.pathname === '/web/start') {
      if (typeof body.challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.challenge) || typeof body.state !== 'string' || !/^[A-Za-z0-9_-]{22,128}$/.test(body.state)) {
        return fail(400, 'invalid_request', 'The sign-in request is malformed.');
      }
      this.started.set(body.state, body.challenge);
      const query = new URLSearchParams({
        client_id: 'web-cid.apps.googleusercontent.com', redirect_uri: `${this.origin}/callback`, response_type: 'code',
        scope: 'openid email https://www.googleapis.com/auth/drive.file', access_type: 'offline', prompt: 'consent',
        code_challenge: body.challenge, code_challenge_method: 'S256', state: body.state, nonce: 'fake-nonce',
      });
      return json(200, { authorization_url: `https://accounts.google.com/o/oauth2/v2/auth?${query}` });
    }
    if (url.pathname === '/web/token') {
      if (typeof body.code !== 'string' || !/^[A-Za-z0-9_/.~+=-]{8,512}$/.test(body.code) || typeof body.verifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(body.verifier)
        || (body.remember !== undefined && typeof body.remember !== 'boolean')) {
        return fail(400, 'invalid_request', 'The sign-in answer is malformed.');
      }
      const issued = this.codes.get(body.code);
      this.codes.delete(body.code);
      const challenge = crypto.createHash('sha256').update(body.verifier).digest('base64url');
      if (!issued || issued.challenge !== challenge) return fail(400, 'invalid_grant', 'Google refused the sign-in. Start it again.');
      const remember = body.remember === true;
      const cookie = this.signIn({ remember });
      const session = this.sessions.get(cookie.value);
      return json(200, grant(session), { 'Set-Cookie': `${COOKIE}=${cookie.value}; Path=/; HttpOnly; SameSite=Strict${remember ? '; Max-Age=2592000' : ''}` });
    }
    if (url.pathname === '/web/refresh') {
      const { sid, session } = this.session(req);
      if (!session) return fail(401, 'no_session', 'Sign in.', sid ? clear : {});
      if (this.refreshError === 'email_not_allowed') {
        this.sessions.delete(sid);
        return fail(403, 'email_not_allowed', 'o***@example.com may not use this viewer.', clear);
      }
      if (this.refreshError === 'upstream_error') return fail(502, 'upstream_error', 'Google did not answer. Try again.');
      return json(200, grant(session));
    }
    if (url.pathname === '/web/logout') {
      const { sid } = this.session(req);
      if (sid) this.sessions.delete(sid);
      return json(200, {}, { ...clear, 'Clear-Site-Data': '"storage"' });
    }
    return fail(404, 'not_found', 'There is nothing here.');
  }

  asset(req, res, url) {
    const headers = this.headers();
    const rel = url.pathname === '/sw.js' ? 'sw.js' : url.pathname.slice(1);
    const file = path.join(this.dist, rel);
    const inside = path.resolve(file).startsWith(path.resolve(this.dist) + path.sep);
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, headers);
      res.end();
      return;
    }
    if (!inside || !fs.existsSync(file) || !fs.statSync(file).isFile() || rel.includes('..')) {
      res.writeHead(404, headers);
      res.end();
      return;
    }
    let body = fs.readFileSync(file);
    if (path.basename(file) === 'drive.js') body = Buffer.from(body.toString('utf8').replace(DRIVE_HOST, this.drive.origin));
    const etag = `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 32)}"`;
    const common = { ...headers, ETag: etag, 'Cache-Control': 'public, max-age=0, must-revalidate' };
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, common);
      res.end();
      return;
    }
    res.writeHead(200, { ...common, 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Content-Length': body.length });
    res.end(req.method === 'HEAD' ? undefined : body);
  }
}
