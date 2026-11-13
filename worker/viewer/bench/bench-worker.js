// gclone device test — the worker. `kdf`: one Argon2id derivation in the core (a build with the
// `bench` feature); `hold`: memory the size of a loaded index, kept until the worker ends.
'use strict';
const BASE = self.location.pathname.replace(/[^/]*$/, '');
const scriptUrl = (() => {
  const allowed = [`${BASE}pkg/core.js`];
  const check = (url) => {
    if (!allowed.includes(url)) throw new TypeError('not a script of this page');
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
importScripts(scriptUrl(`${BASE}pkg/core.js`));

let wasm = null;
let held = null;
self.onmessage = async (event) => {
  const { op } = event.data;
  try {
    if (op === 'kdf') {
      if (!wasm) wasm = await wasm_bindgen({ module_or_path: `${BASE}pkg/core.wasm` });
      const t0 = performance.now();
      wasm_bindgen.kdf_bench(event.data.mKib, event.data.t);
      self.postMessage({ ok: true, ms: Math.round(performance.now() - t0), bytes: wasm.memory.buffer.byteLength });
    } else if (op === 'hold') {
      // As the vault worker holds its index: wasm memory, every page of it written.
      const pages = Math.ceil((event.data.mib * 1024 * 1024) / 65536);
      held = new WebAssembly.Memory({ initial: pages });
      const bytes = new Uint8Array(held.buffer);
      for (let at = 0; at < bytes.length; at += 4096) bytes[at] = 1;
      self.postMessage({ ok: true, bytes: bytes.length });
    }
  } catch (error) {
    self.postMessage({ ok: false, error: String((error && error.message) || error) });
  }
};
