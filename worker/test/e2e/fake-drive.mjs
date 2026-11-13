// A fake Google Drive for the hosted viewer's tests: the three calls the viewer makes, with
// the shapes and the CORS answers of the real API, over a directory vault that the native
// `gclone` binary wrote (`gclone login --vault-dir DIR`). It runs on an origin of its own.
//
//   files.list   GET /drive/v3/files?q=…&pageSize=…&fields=…[&pageToken=…]
//   files.get    GET /drive/v3/files/<id>?fields=…
//   content      GET /drive/v3/files/<id>?alt=media   (with `Range`)
//
// What a test can turn: time to first byte, a bandwidth cap, the page size, tokens that stop
// being accepted, rate limits, ids that are "not found" (so that a blob is looked up by its
// name), the abuse flag, a connection that breaks in the middle, a store that does not answer
// at all, listed sizes that lie, and planted objects that exist only in the listing.
// Everything is counted in `log`.
//
// No gclone code in here, and nothing of a real account: the directory is read as it is.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';

const FOLDER = 'application/vnd.google-apps.folder';
const ROOT = 'root-of-my-drive';

export class FakeDrive {
  /** `dir`: what was given to `--vault-dir` (it holds the vault's folder and the id journal). */
  constructor(dir, options = {}) {
    this.dir = dir;
    /** Milliseconds before the first byte of every answer. */
    this.latencyMs = options.latencyMs ?? 0;
    /** Bits per second of every content answer; 0 = as fast as the loopback goes. */
    this.bitsPerSecond = options.bitsPerSecond ?? 0;
    /** The most objects a listing page holds (Drive may answer short pages). */
    this.pageMax = options.pageMax ?? 1000;
    /** Access tokens that are accepted. */
    this.tokens = new Set(options.tokens ?? []);
    /** Ids answered `404` although the object exists. */
    this.unknownIds = new Set();
    /** id → the id the object has now: the old one is `404`, a listing by name shows the new one (a vault that was moved). */
    this.reissued = new Map();
    /** Ids whose content needs `acknowledgeAbuse=true`. */
    this.abusiveIds = new Set();
    /** id → bytes after which the next content answer of that id is cut (once). */
    this.cutAfter = new Map();
    /** name → the size a listing claims. */
    this.listedSize = new Map();
    /** Objects that exist only here: `{ id, name, parent, size, bytes?: Buffer, fill?: number }`. */
    this.planted = [];
    /** Names a listing does not show although the objects exist (a listing that lags). */
    this.hidden = new Set();
    /** Content answers in flight right now. */
    this.inFlight = 0;
    /** The next n requests are answered with a rate-limit `403`. */
    this.rateLimitNext = 0;
    /** The next n requests are answered `500`. */
    this.failNext = 0;
    /** While true, every request is dropped without an answer: the connection is closed (a store out of reach). */
    this.dead = false;
    this.log = { preflights: 0, lists: [], metas: [], gets: [], bytes: 0, unauthorized: 0, origins: new Set() };
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

  /** Starts the counters over. The origins that ever asked are kept. */
  resetLog() {
    this.log = { preflights: 0, lists: [], metas: [], gets: [], bytes: 0, unauthorized: 0, origins: this.log.origins };
  }

  // --- the directory as Drive objects ------------------------------------------------------------

  /** id → relative path, from the directory backend's journal. */
  journal() {
    const map = new Map();
    let text = '';
    try { text = fs.readFileSync(path.join(this.dir, '.gclone-dir-ids.json'), 'utf8'); } catch { return map; }
    const under = (p, root) => p === root || p.startsWith(`${root}/`);
    for (const line of text.split('\n').filter(Boolean)) {
      let rec;
      try { rec = JSON.parse(line); } catch { continue; }
      if (rec.op === 'bind') map.set(rec.id, rec.path);
      else if (rec.op === 'move') {
        for (const [id, p] of map) if (under(p, rec.from)) map.set(id, rec.to + p.slice(rec.from.length));
      } else if (rec.op === 'drop') {
        for (const [id, p] of map) if (under(p, rec.path)) map.delete(id);
      }
    }
    return map;
  }

  /** Every object: `{ id, name, parent, folder, size, createdTime, file }`. Read anew each time. */
  objects() {
    const ids = new Map([...this.journal()].map(([id, rel]) => [rel, id]));
    const idOf = (rel) => ids.get(rel) ?? `x${crypto.createHash('sha256').update(rel).digest('hex').slice(0, 31)}`;
    const out = [];
    const walk = (rel, parent) => {
      for (const entry of fs.readdirSync(path.join(this.dir, rel), { withFileTypes: true })) {
        if (entry.name.startsWith('.') || !(entry.isFile() || entry.isDirectory())) continue;
        const child = rel ? `${rel}/${entry.name}` : entry.name;
        const file = path.join(this.dir, child);
        let stat;
        try { stat = fs.statSync(file); } catch { continue; }
        const id = entry.isDirectory() ? idOf(child) : this.reissued.get(idOf(child)) ?? idOf(child);
        out.push({
          id, name: entry.name, parent, folder: entry.isDirectory(), size: entry.isDirectory() ? 0 : stat.size,
          createdTime: new Date(Math.floor(stat.mtimeMs)).toISOString(), file,
        });
        if (entry.isDirectory()) walk(child, id);
      }
    };
    walk('', ROOT);
    for (const planted of this.planted) {
      out.push({ folder: false, createdTime: '2026-11-01T00:00:00.000Z', file: null, ...planted });
    }
    return out;
  }

  /** The id of the object at a path below `dir` (`gclone/index`). */
  idOf(rel) {
    const file = path.join(this.dir, rel);
    const found = this.objects().find((object) => object.file === file);
    if (!found) throw new Error(`no object at ${rel}`);
    return found.id;
  }

  json(object) {
    const out = {
      id: object.id, name: object.name, mimeType: object.folder ? FOLDER : 'application/octet-stream',
      parents: [object.parent], createdTime: object.createdTime, trashed: false,
    };
    // Drive gives sizes as strings, and none for a folder.
    if (!object.folder) out.size = String(this.listedSize.get(object.name) ?? object.size);
    return out;
  }

  // --- HTTP --------------------------------------------------------------------------------------

  async handle(req, res) {
    if (this.dead) {
      this.log.dropped = (this.log.dropped || 0) + 1;
      req.socket.destroy();
      return;
    }
    const origin = req.headers.origin;
    if (origin) this.log.origins.add(origin);
    if (req.method === 'OPTIONS') {
      // What www.googleapis.com answers to a preflight (measured without credentials).
      this.log.preflights += 1;
      res.writeHead(200, {
        'Access-Control-Allow-Origin': origin || '*',
        Vary: 'origin',
        'Access-Control-Allow-Methods': 'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT',
        'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || '',
        'Access-Control-Max-Age': '3600',
      });
      res.end();
      return;
    }
    const cors = {
      'Access-Control-Allow-Origin': origin || '*',
      // `Content-Range` is not among them, as on the real host.
      'Access-Control-Expose-Headers': 'Content-Length, Date, Server, Transfer-Encoding, Retry-After',
      Vary: 'Origin, X-Origin',
    };
    const fail = (status, reason, message, extra = {}) => {
      const body = JSON.stringify({ error: { code: status, message, errors: [{ message, domain: 'global', reason }] } });
      res.writeHead(status, { ...cors, 'Content-Type': 'application/json; charset=UTF-8', ...extra });
      res.end(body);
    };
    if (this.latencyMs) await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    const url = new URL(req.url, 'http://drive');
    if (req.method !== 'GET') return fail(405, 'methodNotAllowed', 'The fake Drive is read-only.');
    // No request of the viewer may carry a token in its address, or a cookie.
    if (url.searchParams.has('access_token') || req.headers.cookie) return fail(400, 'badRequest', 'A token in the address, or a cookie.');
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!bearer || !this.tokens.has(bearer[1])) {
      this.log.unauthorized += 1;
      return fail(401, 'authError', 'Invalid Credentials');
    }
    if (this.rateLimitNext > 0) {
      this.rateLimitNext -= 1;
      return fail(403, 'userRateLimitExceeded', 'User rate limit exceeded.');
    }
    if (this.failNext > 0) {
      this.failNext -= 1;
      return fail(500, 'backendError', 'Backend Error');
    }
    if (url.pathname === '/drive/v3/files') return this.list(url, res, cors, fail);
    const match = /^\/drive\/v3\/files\/([^/]+)$/.exec(url.pathname);
    if (!match) return fail(404, 'notFound', 'Not Found');
    const id = decodeURIComponent(match[1]);
    const object = this.unknownIds.has(id) ? null : this.objects().find((o) => o.id === id);
    if (!object) return fail(404, 'notFound', `File not found: ${id}.`);
    if (url.searchParams.get('alt') !== 'media') {
      this.log.metas.push({ id, fields: url.searchParams.get('fields') });
      res.writeHead(200, { ...cors, 'Content-Type': 'application/json; charset=UTF-8' });
      res.end(JSON.stringify(this.json(object)));
      return;
    }
    if (object.folder) return fail(403, 'fileNotDownloadable', 'Only files with binary content can be downloaded.');
    if (this.abusiveIds.has(id) && url.searchParams.get('acknowledgeAbuse') !== 'true') {
      return fail(403, 'cannotDownloadAbusiveFile', 'This file has been identified as malware or spam and cannot be downloaded.');
    }
    return this.content(req, res, object, cors, fail);
  }

  list(url, res, cors, fail) {
    const q = url.searchParams.get('q') || '';
    const entry = { q, pageSize: url.searchParams.get('pageSize'), fields: url.searchParams.get('fields'), pageToken: url.searchParams.get('pageToken'), spaces: url.searchParams.get('spaces') };
    this.log.lists.push(entry);
    const unquote = (text) => text.replace(/\\(['\\])/g, '$1');
    const byName = /^name = '((?:[^'\\]|\\.)*)' and trashed = false$/.exec(q);
    const byParent = /^'((?:[^'\\]|\\.)*)' in parents and trashed = false$/.exec(q);
    let hits;
    if (byName) hits = this.objects().filter((o) => o.name === unquote(byName[1]));
    else if (byParent) hits = this.objects().filter((o) => o.parent === unquote(byParent[1]));
    else return fail(400, 'invalid', `Invalid Value: the fake Drive does not know the query ${q}`);
    hits = hits.filter((o) => !this.hidden.has(o.name));
    const size = Math.max(1, Math.min(Number(entry.pageSize) || 100, this.pageMax));
    let start = 0;
    if (entry.pageToken) {
      const token = /^page-(\d+)$/.exec(entry.pageToken);
      if (!token) return fail(400, 'invalid', 'Invalid Value: pageToken');
      start = Number(token[1]);
    }
    const page = { kind: 'drive#fileList', files: hits.slice(start, start + size).map((o) => this.json(o)) };
    if (start + size < hits.length) page.nextPageToken = `page-${start + size}`;
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json; charset=UTF-8' });
    res.end(JSON.stringify(page));
    return undefined;
  }

  async content(req, res, object, cors, fail) {
    const size = object.size;
    let start = 0;
    let end = size; // exclusive
    let status = 200;
    const range = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range || '');
    if (range) {
      start = Number(range[1]);
      end = range[2] === '' ? size : Math.min(size, Number(range[2]) + 1);
      if (start >= size || start >= end) {
        return fail(416, 'requestedRangeNotSatisfiable', 'Requested range not satisfiable', { 'Content-Range': `bytes */${size}` });
      }
      status = 206;
    }
    // `others`: the most other content answers that were in flight while this one was.
    const record = { id: object.id, name: object.name, range: range ? [start, end] : null, bytes: 0, others: this.inFlight };
    for (const other of this.log.gets) if (other.open) other.others = Math.max(other.others, this.inFlight + 0, 1);
    record.open = true;
    this.inFlight += 1;
    this.log.gets.push(record);
    const headers = { ...cors, 'Content-Type': 'application/octet-stream', 'Content-Length': String(end - start) };
    if (status === 206) headers['Content-Range'] = `bytes ${start}-${end - 1}/${size}`;
    res.writeHead(status, headers);
    let cut = this.cutAfter.get(object.id);
    if (cut !== undefined) this.cutAfter.delete(object.id);
    const piece = 16 * 1024;
    const fd = object.file ? fs.openSync(object.file, 'r') : null;
    let closed = false;
    res.on('close', () => { closed = true; });
    try {
      for (let at = start; at < end && !closed;) {
        const n = Math.min(piece, end - at);
        let chunk;
        if (fd !== null) {
          chunk = Buffer.alloc(n);
          fs.readSync(fd, chunk, 0, n, at);
        } else if (object.bytes) {
          chunk = object.bytes.subarray(at, at + n);
        } else {
          chunk = Buffer.alloc(n, object.fill ?? 0);
        }
        if (cut !== undefined && record.bytes + n > cut) {
          res.write(chunk.subarray(0, Math.max(0, cut - record.bytes)));
          await new Promise((resolve) => setTimeout(resolve, 20));
          res.destroy();
          return;
        }
        const drained = res.write(chunk);
        record.bytes += n;
        this.log.bytes += n;
        at += n;
        if (this.bitsPerSecond) await new Promise((resolve) => setTimeout(resolve, (n * 8000) / this.bitsPerSecond));
        else if (!drained) {
          await new Promise((resolve) => {
            const done = () => {
              res.off('drain', done);
              res.off('close', done);
              resolve();
            };
            res.on('drain', done);
            res.on('close', done);
          });
        }
      }
      res.end();
    } finally {
      if (fd !== null) fs.closeSync(fd);
      record.open = false;
      this.inFlight -= 1;
    }
    return undefined;
  }
}
