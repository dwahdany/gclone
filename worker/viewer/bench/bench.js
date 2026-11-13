// gclone device test (design package P0): whether this device can run the hosted viewer's
// unlock, in the cycles the viewer really produces.
//
//   A  the reload cycle (Lock = reload): five rounds of { reload the page; derive at 256 MiB
//      in a fresh worker; end it; hold 100 MiB in a second worker, as the index, until the
//      next reload }
//   B  retries: three derivations in one worker (wrong passphrases reuse the KDF worker)
//   C  the teardown cycle (Lock without reload): five rounds of A without the reload — the
//      100 MiB worker is ended instead
//
// A and B pass → Lock = reload, as built. A fails and C passes → Lock has to tear down without
// a reload. A and C fail → this device cannot unlock a vault whose keyfile asks for 256 MiB.
//
// The progress is kept in sessionStorage, so the page goes on by itself after each reload —
// and notices when the browser closed it in the middle of a round.
'use strict';
(() => {
  const M_KIB = 262144;
  const T = 3;
  const INDEX_MIB = 100;
  const ROUNDS = 5;
  const RETRIES = 3;
  const KEY = 'gclone.bench';
  const $ = (id) => document.getElementById(id);

  const scriptUrl = (() => {
    const base = new URL('.', document.currentScript.src).pathname;
    const allowed = [`${base}bench-worker.js`];
    const check = (url) => {
      if (!allowed.includes(url)) throw new TypeError('not a script of this page');
      return url;
    };
    const make = window.trustedTypes ? window.trustedTypes.createPolicy('gclone', { createScriptURL: check }) : { createScriptURL: check };
    return () => make.createScriptURL(allowed[0]);
  })();

  const load = () => {
    try { return JSON.parse(sessionStorage.getItem(KEY)); } catch (_) { return null; }
  };
  const save = (state) => sessionStorage.setItem(KEY, JSON.stringify(state));

  function ask(worker, message, timeoutMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({ ok: false, error: `no answer in ${timeoutMs / 1000} s` }), timeoutMs);
      worker.onmessage = (event) => { clearTimeout(timer); resolve(event.data); };
      worker.onerror = (event) => { clearTimeout(timer); resolve({ ok: false, error: event.message || 'the worker failed' }); };
      worker.postMessage(message);
    });
  }

  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const describe = (r) => (r.ok ? `${r.ms} ms, wasm memory ${Math.round(r.bytes / 1048576)} MiB` : `FAILED: ${r.error}`);

  /** One round of the unlock: derive in a fresh worker, end it, hold the index in another. */
  async function round(keep) {
    const kdf = new Worker(scriptUrl());
    const derived = await ask(kdf, { op: 'kdf', mKib: M_KIB, t: T }, 120000);
    kdf.terminate();
    const index = new Worker(scriptUrl());
    const held = await ask(index, { op: 'hold', mib: INDEX_MIB }, 60000);
    if (!keep) {
      await pause(300);
      index.terminate();
    } else {
      window.__index = index; // until the reload
    }
    return { ok: derived.ok && held.ok, text: `derive ${describe(derived)}; index ${held.ok ? `${Math.round(held.bytes / 1048576)} MiB held` : `FAILED: ${held.error}`}` };
  }

  function render(state) {
    const lines = [navigator.userAgent, `deviceMemory: ${navigator.deviceMemory ?? 'n/a'} GiB, cores: ${navigator.hardwareConcurrency ?? 'n/a'}`, ''];
    const part = (name, title) => {
      const rows = state.results.filter((r) => r.cycle === name);
      if (!rows.length) return;
      lines.push(title);
      for (const r of rows) lines.push(`  ${r.n}. ${r.ok ? 'ok' : 'FAILED'} — ${r.text}`);
    };
    part('A', 'A  reload cycle (the viewer as built: Lock = reload)');
    part('B', 'B  retries in one worker (wrong passphrases)');
    part('C', 'C  teardown cycle (Lock without a reload)');
    if (state.verdict) lines.push('', `RESULT: ${state.verdict}`);
    $('out').textContent = lines.join('\n');
    return lines.join('\n');
  }

  const passed = (state, cycle, n) => state.results.filter((r) => r.cycle === cycle && r.ok).length === n;

  async function run() {
    let state = load();
    if (!state) return;
    $('start').hidden = true;
    // A round that was begun and never finished: the browser closed the page under it.
    if (state.inflight) {
      state.results.push({ cycle: state.inflight.cycle, n: state.inflight.n, ok: false, text: 'the browser closed or reloaded the page during this round (out of memory?)' });
      if (state.inflight.cycle === 'A') state.phase = 'B'; // no further reload rounds after a kill
      state.inflight = null;
      save(state);
    }
    render(state);
    if (state.phase === 'A') {
      const n = state.results.filter((r) => r.cycle === 'A').length + 1;
      if (n <= ROUNDS) {
        $('state').textContent = `Cycle A, round ${n} of ${ROUNDS}…`;
        state.inflight = { cycle: 'A', n };
        save(state);
        const result = await round(true);
        state.inflight = null;
        state.results.push({ cycle: 'A', n, ...result });
        if (!result.ok) state.phase = 'B';
        save(state);
        render(state);
        await pause(500);
        // The reload that a Lock is — with the 100 MiB worker still alive, as in the viewer.
        location.reload();
        return;
      }
      state.phase = 'B';
      save(state);
    }
    if (state.phase === 'B') {
      $('state').textContent = 'Cycle B: three derivations in one worker…';
      state.inflight = { cycle: 'B', n: 1 };
      save(state);
      const worker = new Worker(scriptUrl());
      for (let n = 1; n <= RETRIES; n += 1) {
        state.inflight = { cycle: 'B', n };
        save(state);
        const r = await ask(worker, { op: 'kdf', mKib: M_KIB, t: T }, 120000);
        state.results.push({ cycle: 'B', n, ok: r.ok, text: describe(r) });
        state.inflight = null;
        save(state);
        render(state);
        if (!r.ok) break;
      }
      worker.terminate();
      state.phase = 'C';
      save(state);
    }
    if (state.phase === 'C') {
      for (let n = state.results.filter((r) => r.cycle === 'C').length + 1; n <= ROUNDS; n += 1) {
        $('state').textContent = `Cycle C, round ${n} of ${ROUNDS}…`;
        state.inflight = { cycle: 'C', n };
        save(state);
        const result = await round(false);
        state.inflight = null;
        state.results.push({ cycle: 'C', n, ...result });
        save(state);
        render(state);
        if (!result.ok) break;
      }
      state.phase = 'done';
    }
    const a = passed(state, 'A', ROUNDS);
    const b = passed(state, 'B', RETRIES);
    const c = passed(state, 'C', ROUNDS);
    state.verdict = a && b ? 'A and B pass: this device unlocks with Lock = reload, as the viewer is built.'
      : c ? 'A or B fails, C passes: this device needs the Lock that tears down without a reload (design 7.1).'
        : 'A and C fail: this device cannot unlock a vault whose keyfile asks for 256 MiB.';
    save(state);
    const text = render(state);
    $('state').textContent = 'Done.';
    $('again').hidden = false;
    document.title = 'done';
    // The page's own server prints the result (handy when the phone is on the LAN).
    fetch('result', { method: 'POST', body: text }).catch(() => {});
  }

  const begin = () => {
    save({ phase: 'A', results: [], inflight: null, verdict: null });
    run();
  };
  $('start').addEventListener('click', begin);
  $('again').addEventListener('click', () => { $('again').hidden = true; begin(); });
  const state = load();
  if (state && state.phase === 'done') {
    $('start').hidden = true;
    $('again').hidden = false;
    render(state);
    $('state').textContent = 'Done.';
  } else if (state) run();
})();
