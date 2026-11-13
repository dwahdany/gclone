// Service Worker of the smoke test: the core loaded with importScripts under the policy of
// design §4.3, tickets over a transferred MessagePort, `GET /v/<id>` answered with decrypted
// bytes and `Range`. The least a Service Worker of the viewer does — the real one is P5's.
'use strict';
// The context's one Trusted Types policy (design §4.3): script URLs of this build only.
const scriptUrl = (() => {
  const check = (url) => {
    if (url !== '/core.js') throw new TypeError(`not a script of this build: ${url}`);
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
const hasTrustedTypes = !!self.trustedTypes;
importScripts(scriptUrl('/core.js'));

const ready = wasm_bindgen({ module_or_path: '/core.wasm' });
const tickets = new Map();
const waiting = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
  const message = event.data;
  if (message.type === 'port') {
    event.ports[0].onmessage = (e) => {
      if (e.data.type !== 'ticket') return;
      tickets.set(e.data.id, e.data.ticket);
      (waiting.get(e.data.id) || []).forEach((resolve) => resolve());
      waiting.delete(e.data.id);
    };
  } else if (message.type === 'ping') {
    event.waitUntil(ready.then(() => event.source.postMessage({
      type: 'pong', version: wasm_bindgen.core_version(), tickets: tickets.size, trustedTypes: hasTrustedTypes,
    })));
  }
});

const plain = (status, text) => new Response(text, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });

async function ticketFor(id) {
  if (!tickets.has(id)) {
    await Promise.race([
      new Promise((resolve) => waiting.set(id, [...(waiting.get(id) || []), resolve])),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
  }
  return tickets.get(id);
}

async function serve(request, url) {
  await ready;
  const ticketJson = await ticketFor(url.pathname.slice(3));
  if (!ticketJson) return plain(410, 'This link has expired. Open the file from the viewer again.');
  const ticket = JSON.parse(ticketJson);
  const served = JSON.parse(wasm_bindgen.served(ticket.name, url.searchParams.get('dl') === '1'));
  const range = JSON.parse(wasm_bindgen.parse_range(request.headers.get('range') ?? undefined, ticket.size));
  const headers = {
    'Content-Type': served.mime,
    'Content-Security-Policy': served.csp,
    'Content-Disposition': served.disposition,
    'X-Content-Type-Options': 'nosniff',
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
  if (range.kind === 'unsatisfiable') return new Response(null, { status: 416, headers: { ...headers, 'Content-Range': `bytes */${ticket.size}` } });
  const reader = new wasm_bindgen.FileReader(ticketJson, range.start, range.end);
  headers['Content-Length'] = String(reader.remaining());
  if (range.kind === 'range') headers['Content-Range'] = `bytes ${range.start}-${range.end - 1}/${ticket.size}`;
  const status = range.kind === 'range' ? 206 : 200;
  if (reader.cipher_start() === reader.cipher_end()) {
    reader.free();
    return new Response(new Uint8Array(0), { status, headers });
  }
  const upstream = await fetch(`/fixture/busy/blobs/${ticket.file_id}`, {
    headers: { Authorization: 'Bearer smoke-token', Range: `bytes=${reader.cipher_start()}-${reader.cipher_end() - 1}` },
  });
  if (upstream.status !== 206) {
    reader.free();
    return plain(502, `The file could not be read from the vault: the store answered ${upstream.status}`);
  }
  const source = upstream.body.getReader();
  const body = new ReadableStream({
    async pull(controller) {
      try {
        for (;;) {
          const { done, value } = await source.read();
          if (done) {
            if (reader.remaining() !== 0) throw new Error('the store ended the answer early');
            reader.free();
            controller.close();
            return;
          }
          const ready = reader.push(value);
          if (ready.length) {
            controller.enqueue(ready);
            return;
          }
        }
      } catch (error) {
        controller.error(error);
      }
    },
    cancel() {
      source.cancel().catch(() => {});
    },
  }, { highWaterMark: 1 });
  return new Response(body, { status, headers });
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (!/^\/v\/[A-Za-z0-9_-]{22}$/.test(url.pathname)) return;
  event.respondWith(serve(event.request, url).catch((error) => plain(502, `The file could not be read from the vault: ${(error && error.message) || error}`)));
});
