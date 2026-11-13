// The page of the smoke test: it starts the three contexts that load the core, hands them
// their ports, and asks for one ranged read. Like the viewer's page, it never loads the wasm
// and never sees a key or a ticket.
(async () => {
  'use strict';
  const out = { done: false };
  window.__smoke = out;
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  try {
    // Trusted Types: the page's policy is inline-free — the same check as policy.js.
    const allowed = ['/kdf-worker.js', '/vault-worker.js', '/sw.js'];
    const check = (url) => {
      if (!allowed.includes(url)) throw new TypeError(`not a script of this build: ${url}`);
      return url;
    };
    out.trustedTypes = !!window.trustedTypes;
    const policy = window.trustedTypes ? window.trustedTypes.createPolicy('gclone', { createScriptURL: check }) : null;
    const script = (url) => (policy ? policy.createScriptURL(url) : check(url));

    await navigator.serviceWorker.register(script('/sw.js'), { scope: '/' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((resolve) => navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true }));
    }
    const sw = navigator.serviceWorker.controller;
    const fromSw = (type) => new Promise((resolve) => {
      const listen = (event) => {
        if (event.data && event.data.type === type) {
          navigator.serviceWorker.removeEventListener('message', listen);
          resolve(event.data);
        }
      };
      navigator.serviceWorker.addEventListener('message', listen);
    });

    const fixture = await (await fetch('/fixture.json')).json();
    const ask = (worker, message, transfer = []) => new Promise((resolve, reject) => {
      worker.onmessage = (event) => (event.data.error ? reject(new Error(event.data.error)) : resolve(event.data));
      worker.onerror = (event) => reject(new Error(event.message || 'the worker failed to start'));
      worker.postMessage(message, transfer);
    });
    // Everything the page ever receives from a worker is recorded: none of it may hold a key.
    const seen = [];
    const record = (label, data) => { seen.push(`${label}: ${JSON.stringify(data)}`); return data; };

    const kdf = new Worker(script('/kdf-worker.js'));
    const vault = new Worker(script('/vault-worker.js'));
    // Two channels the page makes and gives away: keys (KDF worker → vault worker) and
    // tickets (vault worker → Service Worker).
    const keys = new MessageChannel();
    const tickets = new MessageChannel();
    sw.postMessage({ type: 'port' }, [tickets.port2]);
    const started = ask(vault, { type: 'start', keyPort: keys.port1, ticketPort: tickets.port1, fixture }, [keys.port1, tickets.port1]);
    out.kdf = record('kdf', await ask(kdf, { type: 'unlock', port: keys.port2, keyfile: fixture.keyfile }, [keys.port2]));
    out.vault = record('vault', await started);
    kdf.terminate();

    const id = fixture.id;
    out.issue = record('issue', await ask(vault, { type: 'issue', id, path: fixture.file.path }));
    const ranged = await fetch(`/v/${id}`, { headers: { Range: `bytes=${fixture.file.start}-${fixture.file.end - 1}` } });
    out.read = {
      status: ranged.status,
      type: ranged.headers.get('content-type'),
      range: ranged.headers.get('content-range'),
      length: ranged.headers.get('content-length'),
      csp: ranged.headers.get('content-security-policy'),
      hex: hex(new Uint8Array(await ranged.arrayBuffer())),
    };
    const whole = await fetch(`/v/${id}`);
    const body = new Uint8Array(await whole.arrayBuffer());
    out.whole = {
      status: whole.status,
      length: body.length,
      sha256: hex(new Uint8Array(await crypto.subtle.digest('SHA-256', body))),
    };
    const unknown = await fetch('/v/0000000000000000000000');
    out.unknown = { status: unknown.status };
    const pong = fromSw('pong');
    sw.postMessage({ type: 'ping' });
    out.sw = record('sw', await pong);
    // The policy the page runs under: `eval` is refused although wasm compiles.
    out.evalThrows = (() => { try { (0, eval)('1'); return false; } catch { return true; } })();
    out.seen = seen;
  } catch (error) {
    out.error = String((error && error.stack) || error);
  }
  out.done = true;
  document.getElementById('out').textContent = out.error ? `failed: ${out.error}` : 'done';
})();
