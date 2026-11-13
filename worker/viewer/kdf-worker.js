// gclone viewer — the KDF worker: one per visit of the unlock screen. It runs Argon2id and
// opens a keyfile, gives the key bundle to the vault worker over the port it was handed —
// never to the page — and is terminated by the page. Its wasm memory grows by what the
// keyfile asks for (256 MiB as the CLI writes them) and never shrinks: that is why this is a
// worker of its own, and why every attempt of one unlock screen reuses it.
//
// The candidate loop is the CLI's (`cli::login::unlock`): the passphrase is tried on each
// candidate, highest generation first. `wrong-passphrase` keeps the candidate; `damaged`,
// `other-vault` and `needs-newer` drop it. Nothing opened: "wrong passphrase" if a candidate
// is left, otherwise "no usable keyfile" — or "needs a newer viewer" when a keyfile version
// was the reason.
'use strict';
// This context's one Trusted Types policy: script URLs of this build only.
const BASE = self.location.pathname.replace(/[^/]*$/, '');
const scriptUrl = (() => {
  const allowed = [`${BASE}core.js`];
  const check = (url) => {
    if (!allowed.includes(url)) throw new TypeError('not a script of this build');
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
importScripts(scriptUrl(`${BASE}core.js`));

(() => {
  const core = wasm_bindgen;
  // What one attempt costs at most without being asked for more: the CLI's KEYFILE_TRY_MAX.
  const KEYFILE_TRY = 4;
  const CODES = ['wrong-passphrase', 'damaged', 'other-vault', 'needs-newer', 'bad-input'];
  const codeOf = (error) => {
    const match = /^([a-z-]+): /.exec(String(error && error.message));
    return match && CODES.includes(match[1]) ? match[1] : null;
  };
  const ready = core({ module_or_path: `${BASE}core.wasm` });
  let port = null;
  let vaultId = null;
  /** `[{ name, bytes }]`, in the order `keyfile_candidates` gave. */
  let candidates = null;
  let newer = false;
  let gotKeyfiles;
  const keyfiles = new Promise((resolve) => { gotKeyfiles = resolve; });

  /**
   * Tries the passphrase on the keyfiles, in their order, until one opens or `limit` of them
   * have said "wrong passphrase" (each of those is one derivation). A keyfile that is refused
   * for another reason is dropped and does not count: it cost nothing, or it is not this
   * vault's. `untried`: the keyfiles this attempt did not get to.
   */
  function attempt(passphrase, limit) {
    const tried = [];
    const kept = [];
    const dropped = [];
    let bundle = null;
    let wrong = 0;
    let untried = 0;
    for (const candidate of candidates) {
      if (bundle || wrong >= limit) {
        kept.push(candidate);
        if (!bundle) untried += 1;
        continue;
      }
      const t0 = performance.now();
      try {
        bundle = core.unlock(candidate.name, candidate.bytes, passphrase, vaultId);
        kept.push(candidate);
        tried.push({ name: candidate.name, outcome: 'opened', ms: Math.round(performance.now() - t0) });
      } catch (error) {
        const code = codeOf(error);
        // Not an answer of the core: its instance is gone (out of memory). The page discards this worker.
        if (!code) throw error;
        tried.push({ name: candidate.name, outcome: code, ms: Math.round(performance.now() - t0) });
        if (code === 'wrong-passphrase') {
          kept.push(candidate);
          wrong += 1;
        } else {
          dropped.push(candidate.name);
          if (code === 'needs-newer') newer = true;
        }
      }
    }
    candidates = kept;
    const outcome = bundle ? 'opened'
      : candidates.length ? 'wrong-passphrase'
      : newer ? 'needs-newer' : 'no-usable-keyfile';
    // The bundle goes to the vault worker, and only there.
    if (bundle) port.postMessage({ type: 'bundle', bundle }, [bundle.buffer]);
    return { type: 'result', outcome, tried, dropped, left: candidates.length, untried };
  }

  self.onmessage = async (message) => {
    const data = message.data || {};
    try {
      if (data.type === 'start') {
        port = message.ports[0];
        port.onmessage = (event) => {
          if (!event.data || event.data.type !== 'keyfiles') return;
          vaultId = event.data.vault_id;
          candidates = event.data.candidates;
          gotKeyfiles();
        };
        await ready;
        self.postMessage({ type: 'ready' });
      } else if (data.type === 'attempt') {
        await ready;
        await keyfiles;
        self.postMessage(attempt(String(data.passphrase), data.limit > 0 ? data.limit : KEYFILE_TRY));
      }
    } catch (error) {
      self.postMessage({ type: 'result', outcome: 'failed', tried: [], dropped: [], left: 0, untried: 0, memory: /memory|unreachable|RangeError/i.test(String(error)) });
    }
  };
})();
