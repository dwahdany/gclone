// Vault worker of the smoke test: keys from the KDF worker's port, the index from the
// fixture, tickets to the Service Worker's port. What it posts to the page holds no key.
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

let vault;
let ticketPort;
const bytesOf = async (url) => new Uint8Array(await (await fetch(url)).arrayBuffer());

self.onmessage = async (event) => {
  try {
    const message = event.data;
    if (message.type === 'start') {
      ticketPort = message.ticketPort;
      await wasm_bindgen({ module_or_path: '/core.wasm' });
      const bundle = await new Promise((resolve) => { message.keyPort.onmessage = (e) => resolve(e.data.bundle); });
      vault = wasm_bindgen.Vault.from_keys(bundle);
      const wiped = bundle.every((b) => b === 0);
      const listing = message.fixture.listing;
      const names = JSON.stringify(listing.map((o) => o.name));
      const created = new Map(listing.map((o) => [o.name, o.created_ms]));
      let snapshot = null;
      for (const name of JSON.parse(vault.snapshot_candidates(names))) {
        if (vault.load_snapshot(name, await bytesOf(`/fixture/busy/index/${name}`))) { snapshot = name; break; }
      }
      for (const name of JSON.parse(vault.needed_segments(names))) {
        vault.add_segment(name, await bytesOf(`/fixture/busy/index/${name}`), created.get(name));
      }
      const report = JSON.parse(vault.finish());
      self.postMessage({
        version: wasm_bindgen.core_version(), vault_id: vault.vault_id(), wiped, snapshot: snapshot !== null,
        head: report.head, files: report.files, blocked: report.blocked.length,
        root: JSON.parse(vault.list('')).entries.map((e) => e.name),
        trustedTypes: hasTrustedTypes,
      });
    } else if (message.type === 'issue') {
      // The ticket goes to the Service Worker; the page learns only that it went.
      ticketPort.postMessage({ type: 'ticket', id: message.id, ticket: vault.ticket(message.path), token: 'smoke-token', exp: 0, build: 'smoke' });
      self.postMessage({ issued: message.id });
    }
  } catch (error) {
    self.postMessage({ error: `vault worker: ${(error && error.message) || error}` });
  }
};
