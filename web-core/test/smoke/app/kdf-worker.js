// KDF worker of the smoke test: loads the core with importScripts under the page's policy,
// unlocks the fixture's keyfile and gives the key bundle to the port it was handed — never to
// the page.
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

self.onmessage = async (event) => {
  try {
    const { port, keyfile } = event.data;
    await wasm_bindgen({ module_or_path: '/core.wasm' });
    const bytes = new Uint8Array(await (await fetch(keyfile.url)).arrayBuffer());
    const cost = JSON.parse(wasm_bindgen.keyfile_cost(keyfile.name, bytes));
    const t0 = performance.now();
    const bundle = wasm_bindgen.unlock(keyfile.name, bytes, keyfile.pass, keyfile.vault_id);
    port.postMessage({ bundle }, [bundle.buffer]);
    self.postMessage({ version: wasm_bindgen.core_version(), cost, ms: Math.round(performance.now() - t0), trustedTypes: hasTrustedTypes });
  } catch (error) {
    self.postMessage({ error: `kdf worker: ${(error && error.message) || error}` });
  }
};
