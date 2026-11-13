// gclone viewer — the Service Worker. It answers `GET /v/<id>` with the decrypted bytes of
// one file, with `Range`, for the page's <img>, <video>, <audio>, <iframe>, fetch() and
// download links. Nothing else is touched.
//
// It never holds the passphrase or a master key. What it holds is tickets — the key of one
// file's stream and where its ciphertext is — which the vault worker sends over a port the
// page hands to both sides, and an access token. A ticket opens one file and nothing else.
//
// Every answer's type, policy and disposition come from the file NAME through the core's
// table (`src/web/mime.rs`); content is never sniffed. Only a download carries the name: an
// answer that is shown is a bare `inline` (a browser would make the name the title of a tab
// that shows the file, and with that an entry of its history). Plaintext is released chunk by
// chunk, each only after its authentication tag verified.
//
// Memory is bounded on both sides, whatever the engine and the line do: the store is asked for
// one window of ciphertext at a time, the next only when the consumer wants more, and the
// core is handed at most a mebibyte per call. (A wasm memory never shrinks, and an engine
// that delivers a fast answer in one piece would otherwise make it as large as that piece.)
'use strict';
// The build this script belongs to, stamped in by the build. Its other files are under BASE.
const BUILD = '__GCLONE_BUILD__';
const BASE = `/a/${BUILD}/`;
// This context's one Trusted Types policy: script URLs of this build only.
const scriptUrl = (() => {
  const allowed = ['core.js', 'token.js', 'drive.js'].map((name) => BASE + name);
  const check = (url) => {
    if (!allowed.includes(url)) throw new TypeError('not a script of this build');
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
importScripts(scriptUrl(`${BASE}core.js`), scriptUrl(`${BASE}token.js`), scriptUrl(`${BASE}drive.js`));

(() => {
  const core = wasm_bindgen;
  const { token, DriveError } = self.gclone;
  const MIB = 1024 * 1024;
  // Someone is looking at what is read here: a store that is out of reach is said so after
  // about ten seconds of pauses, not after the half minute of the index load.
  const drive = self.gclone.createDrive({ token, patience: 10000 });
  // A media element is answered one window at a time: engines rarely cancel a range they
  // abandoned, and an unbounded answer keeps pulling from the store. Sequential play doubles
  // the window (one round trip to the store per window); a seek starts small again.
  const MEDIA_WINDOW_MIN = 2 * MIB;
  const MEDIA_WINDOW_MAX = 8 * MIB;
  const STORE_WINDOW = 16 * MIB; // of ciphertext, per request to the store
  const PUSH_MAX = MIB; // of ciphertext, per call into the core
  const FAILURE_MEMORY_MS = 5000; // a store that was out of reach is not asked again at once
  // The sign-in is over: the pages are told, and lock.
  const SESSION_OVER = ['no_session', 'email_not_allowed', 'invalid_grant'];
  const TICKET_GRACE_MS = 200; // a ticket that is on its way
  const TICKET_WAIT_MS = 3000; // a ticket the page has to issue again
  const STREAM_RETRIES = 5; // consecutive failures of the store without a verified byte
  const EXPIRED = 'This link has expired. Open the file from the viewer again.';
  const UNREADABLE = 'The file could not be read from the vault: ';

  let wasm = null;
  let memory = null; // the core's linear memory, for the size the page may ask about
  const ready = () => {
    if (!wasm) {
      wasm = core({ module_or_path: `${BASE}core.wasm` });
      wasm.then((exports) => { memory = exports.memory; }, () => { wasm = null; });
    }
    return wasm;
  };

  /** id → { json, ticket, blob, next, win, failed } */
  const tickets = new Map();
  /** id → the sentence the vault worker gave instead of a ticket */
  const refused = new Map();
  /** id → [resolve] of requests that wait for a ticket */
  const waiters = new Map();
  /** client id → the ticket port that client's page handed over */
  const ports = new Map();
  let streams = 0;

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function wake(id) {
    for (const resolve of waiters.get(id) || []) resolve();
    waiters.delete(id);
  }

  async function tellPages(message) {
    for (const client of await self.clients.matchAll({ type: 'window', includeUncontrolled: true })) client.postMessage(message);
  }

  /** What arrives on the ticket port of the page `who`, from its vault worker. */
  function onPort(who, data) {
    if (!data || typeof data.id !== 'string') return;
    if (data.build !== BUILD) {
      // A page of another build: it — and only it — has to load the files this Service Worker
      // belongs to. (A page of this build that hears it anyway knows by the build named.)
      self.clients.get(who).then((client) => { if (client) client.postMessage({ type: 'reload', build: BUILD }); }, () => {});
      return;
    }
    if (data.type === 'ticket' && typeof data.ticket === 'string') {
      const known = tickets.get(data.id);
      if (!known || known.json !== data.ticket) {
        tickets.set(data.id, { json: data.ticket, ticket: JSON.parse(data.ticket), blob: null, next: -1, win: MEDIA_WINDOW_MIN, failed: null });
      }
      refused.delete(data.id);
      if (data.token) token.seed(data.token, data.exp);
      wake(data.id);
    } else if (data.type === 'ticket-error') {
      refused.set(data.id, String(data.message || 'it cannot be opened'));
      wake(data.id);
    }
  }

  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

  self.addEventListener('message', (event) => {
    const data = event.data || {};
    const source = event.source;
    const who = source && source.id;
    if (data.type === 'port' && event.ports[0]) {
      const old = ports.get(who);
      if (old) old.close();
      ports.set(who, event.ports[0]);
      event.ports[0].onmessage = (message) => onPort(who, message.data);
    } else if (data.type === 'forget') {
      // Lock and sign-out: tickets, the token and the ports go; streams already open finish.
      tickets.clear();
      refused.clear();
      token.forget();
      for (const port of ports.values()) port.close();
      ports.clear();
    } else if (data.type === 'claim') {
      // A page that this worker does not control yet (it was loaded past it — a forced
      // reload — or before the worker was active) asks to be taken over.
      event.waitUntil(self.clients.claim());
    } else if (data.type === 'ping' && source) {
      // Counts and sizes only: how many streams are open, whether this page's port is held,
      // how many tickets, and how large the core's memory is.
      source.postMessage({ type: 'pong', build: BUILD, streams, port: ports.has(who), tickets: tickets.size, memory: memory ? memory.buffer.byteLength : 0 });
    }
  });

  /** The ticket of `id`: in hand, on its way, or issued again by the page that knows the id. */
  async function lookup(id) {
    const waitFor = (ms) => {
      if (tickets.has(id) || refused.has(id)) return Promise.resolve();
      return Promise.race([
        new Promise((resolve) => {
          if (!waiters.has(id)) waiters.set(id, []);
          waiters.get(id).push(resolve);
        }),
        sleep(ms),
      ]);
    };
    await waitFor(TICKET_GRACE_MS);
    if (!tickets.has(id) && !refused.has(id)) {
      for (const client of await self.clients.matchAll({ type: 'window', includeUncontrolled: true })) {
        client.postMessage({ type: 'need-ticket', id, port: ports.has(client.id) });
      }
      await waitFor(TICKET_WAIT_MS);
    }
    return tickets.get(id) || null;
  }

  const BARE = {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Security-Policy': "sandbox; default-src 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
  const plain = (status, text) => new Response(text, { status, headers: BARE });

  /** One sentence for a failure; never a stack. */
  function why(error) {
    if (error instanceof DriveError || error instanceof self.gclone.TokenError) return error.message;
    const text = String((error && error.message) || error);
    const match = /^[a-z-]+: (.*)$/s.exec(text);
    return match ? match[1] : text;
  }
  /** What a failed read leaves behind: pages that lock when the sign-in is over, and the reason, for the next seconds, when the store is out of reach. */
  function noteFailure(entry, error, text) {
    if (error instanceof self.gclone.TokenError && SESSION_OVER.includes(error.code)) {
      tellPages({ type: 'session-ended', code: error.code, message: error.message });
    }
    const unreachable = (error instanceof DriveError && ['unreachable', 'rate', 'quota'].includes(error.kind))
      || (error instanceof self.gclone.TokenError && error.code === 'unreachable');
    entry.failed = unreachable ? { at: Date.now(), text } : null;
  }

  /** A failure that asking the store again cannot cure: damage, the store's own refusal, a dead core. */
  const final = (error) => error instanceof DriveError || error instanceof self.gclone.TokenError
    || error instanceof WebAssembly.RuntimeError || error instanceof RangeError
    || /^[a-z-]+: /.test(String(error && error.message));

  /** Where a ticket's blob is: by the id the index recorded, else by its name (SPEC §3.2). */
  async function byName(entry) {
    const hits = (await drive.named(entry.ticket.blob_name)).filter((file) => !file.folder);
    if (hits.length !== 1) throw new Error(`its data is missing from the store (blob ${entry.ticket.blob_name}).`);
    entry.blob = hits[0].id;
    return entry.blob;
  }

  async function serve(request, url) {
    try {
      await ready();
    } catch (_) {
      return plain(502, `${UNREADABLE}the viewer's files could not be loaded. Reload the page.`);
    }
    const id = url.pathname.slice(3);
    const entry = await lookup(id);
    if (!entry) return refused.has(id) ? plain(502, UNREADABLE + refused.get(id)) : plain(410, EXPIRED);
    // The store was out of reach a moment ago (an element failed; the page now asks why): the
    // same reason, without another round of attempts.
    if (entry.failed && Date.now() - entry.failed.at < FAILURE_MEMORY_MS) return plain(502, entry.failed.text);
    entry.failed = null;
    const ticket = entry.ticket;
    const served = JSON.parse(core.served(ticket.name, url.searchParams.get('dl') === '1'));
    const range = JSON.parse(core.parse_range(request.headers.get('range') ?? undefined, ticket.size));
    const headers = {
      'Content-Type': served.mime,
      'Content-Security-Policy': served.csp,
      'Content-Disposition': served.disposition,
      'X-Content-Type-Options': 'nosniff',
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store',
      'Cross-Origin-Resource-Policy': 'same-origin',
    };
    if (range.kind === 'unsatisfiable') {
      return new Response(null, { status: 416, headers: { ...headers, 'Content-Range': `bytes */${ticket.size}`, 'Content-Length': '0' } });
    }
    const partial = range.kind === 'range';
    const start = range.start;
    let end = range.end;
    if (partial && (request.destination === 'video' || request.destination === 'audio')) {
      entry.win = start === entry.next ? Math.min(entry.win * 2, MEDIA_WINDOW_MAX) : MEDIA_WINDOW_MIN;
      if (end - start > entry.win) end = start + entry.win;
      entry.next = end;
    }
    headers['Content-Length'] = String(end - start);
    if (partial) headers['Content-Range'] = `bytes ${start}-${end - 1}/${ticket.size}`;
    const status = partial ? 206 : 200;
    if (end === start) return new Response(new Uint8Array(0), { status, headers });

    const reader = new core.FileReader(entry.json, start, end);
    const abort = new AbortController();
    let upstream = null; // the store's answer for the window in hand
    let windowEnd = 0; // where that window ends in the blob
    let at = -1; // the blob offset of the next byte the store is to send; -1: where the core resumes
    let piece = null; // what the store sent and the core has not been given yet
    let pieceAt = 0;
    let failures = 0;
    let open = true;

    /** Asks the store for the next window: from where the last one ended, or — after a break — from the first chunk that is not verified yet. */
    async function connect() {
      // (`resume_at()` drops a partial chunk the core holds: only after a break, and at the start.)
      if (at < 0) at = reader.resume_at();
      const to = Math.min(reader.cipher_end(), at + STORE_WINDOW);
      if (to <= at) throw new Error('the store ended its answer early.');
      let res;
      try {
        res = await drive.getRange(entry.blob || ticket.file_id, at, to, abort.signal);
      } catch (error) {
        if (!(error instanceof DriveError) || error.kind !== 'not-found' || entry.blob) throw error;
        res = await drive.getRange(await byName(entry), at, to, abort.signal);
      }
      upstream = res.body.getReader();
      windowEnd = to;
    }

    /** The next verified plaintext (never empty), or `null` at the end of the range. */
    async function more() {
      for (;;) {
        if (reader.remaining() === 0) return null;
        try {
          if (!piece) {
            if (!upstream) await connect();
            const { done, value } = await upstream.read();
            if (done) {
              if (at !== windowEnd) throw new Error('the store ended its answer early.');
              upstream = null; // this window is through; the next is asked for when more is wanted
              continue;
            }
            if (!value.length) continue;
            at += value.length;
            if (at > windowEnd) throw new Error('the store answered with more than it was asked for.');
            piece = value;
            pieceAt = 0;
          }
          // An engine may hand a whole window over in one piece: the core gets it in slices.
          const slice = piece.subarray(pieceAt, pieceAt + PUSH_MAX);
          pieceAt += slice.length;
          if (pieceAt >= piece.length) piece = null;
          const bytes = reader.push(slice);
          if (bytes.length) {
            failures = 0;
            return bytes;
          }
        } catch (error) {
          // Damage and the store's own refusals are final; a broken connection is asked again.
          if (!open || final(error)) throw error;
          if (upstream) upstream.cancel().catch(() => {});
          upstream = null;
          piece = null;
          at = -1;
          failures += 1;
          if (failures >= STREAM_RETRIES) throw error;
          await sleep(200 * 2 ** failures);
        }
      }
    }

    const finish = () => {
      if (!open) return;
      open = false;
      streams -= 1;
      abort.abort();
      try { reader.free(); } catch (_) { /* already freed */ }
    };

    streams += 1;
    // A request the page gave up (a seek, a closed preview) stops asking the store at once.
    if (request.signal) request.signal.addEventListener('abort', finish, { once: true });
    let first;
    try {
      // The answer waits for the first verified bytes: a blob that is missing, damaged from
      // its start or out of reach is an answer with a reason, not a download that breaks.
      first = await more();
    } catch (error) {
      const gone = !open;
      finish();
      if (gone) return Response.error();
      const text = UNREADABLE + why(error);
      noteFailure(entry, error, text);
      return plain(502, text);
    }
    const body = new ReadableStream({
      async pull(controller) {
        try {
          const bytes = first || await more();
          first = null;
          if (bytes) controller.enqueue(bytes);
          if (!bytes || reader.remaining() === 0) {
            finish();
            controller.close();
          }
        } catch (error) {
          // After cancel() the stream is left alone: an error there is only logged noise.
          if (open) {
            finish();
            noteFailure(entry, error, UNREADABLE + why(error));
            controller.error(error);
          }
        }
      },
      cancel() {
        finish();
      },
    }, { highWaterMark: 1 });
    return new Response(body, { status, headers });
  }

  self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.method !== 'GET') return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin || !/^\/v\/[A-Za-z0-9_-]{22}$/.test(url.pathname)) return;
    event.respondWith(serve(request, url).catch((error) => plain(502, UNREADABLE + why(error))));
  });
})();
