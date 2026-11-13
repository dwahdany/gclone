// gclone viewer — the vault worker. It holds the keyring and the decrypted index for as long
// as the vault is unlocked, reads the index from Drive, answers the page's five API calls and
// issues per-file tickets — to the Service Worker, over a port the page never reads.
//
// Nothing this worker posts to the page holds a key: the key bundle arrives on a port from
// the KDF worker, tickets leave on a port to the Service Worker, and no call exports a key.
'use strict';
// This context's one Trusted Types policy: script URLs of this build only.
const BASE = self.location.pathname.replace(/[^/]*$/, '');
const scriptUrl = (() => {
  const allowed = ['core.js', 'token.js', 'drive.js', 'loader.js'].map((name) => BASE + name);
  const check = (url) => {
    if (!allowed.includes(url)) throw new TypeError('not a script of this build');
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
importScripts(scriptUrl(`${BASE}core.js`), scriptUrl(`${BASE}token.js`), scriptUrl(`${BASE}drive.js`), scriptUrl(`${BASE}loader.js`));

(() => {
  const { loader, token } = self.gclone;
  const BUILD = BASE.split('/')[2] || '';
  const core = wasm_bindgen;
  const drive = self.gclone.createDrive({ token });
  // Finding the vault and loading its index follow the CLI's retry schedule; once the list is
  // on the screen, a request gives up after about ten seconds of pauses.
  const INTERACTIVE_PATIENCE_MS = 10000;

  let found = null; // discover(): { vaults, unreadable, damaged }
  let chosen = null; // the vault in use: { root, folder, vault_id, created_ms }
  let opened = null; // open(): { index, data, candidates }
  let vault = null; // the core's Vault, once unlocked
  let index = null; // loader.createIndex(...)
  // locked → loading → ready; `broken`: a load failed half way (a refresh retries it); `dead`:
  // the vault needs a newer viewer, or the core's instance is gone.
  let phase = 'locked';
  let why = 'The vault is locked.';
  let ticketPort = null;
  let pendingConfirm = null;
  const waitingIssues = [];

  const event = (name, data) => self.postMessage({ event: name, ...data });

  class Refusal extends Error {
    constructor(code, message) {
      super(message);
      this.code = code;
    }
  }

  /** What the page is told about a failure: a code and one sentence. Never a stack, never bytes. */
  function describe(error) {
    if (error instanceof Refusal || error instanceof loader.LoadError) return { code: error.code, message: error.message };
    if (error instanceof self.gclone.TokenError) return { code: error.code, message: error.message };
    if (error instanceof self.gclone.DriveError) return { code: `drive-${error.kind}`, message: error.message };
    const code = loader.codeOf(error);
    if (code) return { code, message: loader.sentenceOf(error) };
    // Anything else out of the core means its instance is gone (most likely out of memory).
    return { code: 'crashed', message: 'The viewer failed while it worked on the vault (it may have run out of memory). Reload the page.' };
  }

  const need = (value, message) => {
    if (!value) throw new Refusal('bad-state', message);
    return value;
  };

  const hooks = {
    confirm: (question) => new Promise((resolve) => {
      pendingConfirm = resolve;
      event('confirm', question);
    }),
    progress: (state) => event('progress', state),
    begin: (total) => event('load-begin', { total }),
    end: () => event('load-end', {}),
  };

  function summary(report) {
    return { head: report.head, files: report.files, dirs: report.dirs, bytes: report.bytes, vault: report.vault_name, blocked: report.blocked.length };
  }

  const fatal = (code) => code === 'needs-newer' || code === 'crashed';

  /** `quiet`: the file list is on the screen and nobody can be asked (a refresh that has to start over). */
  async function loadIndex(quiet) {
    phase = 'loading';
    why = 'The index is being loaded.';
    try {
      const report = await index.load({ quiet: !!quiet });
      phase = 'ready';
      return summary(report);
    } catch (error) {
      const said = describe(error);
      // What the core holds now is a part of the index: it is not queried.
      phase = fatal(said.code) ? 'dead' : 'broken';
      why = said.message;
      throw error;
    }
  }

  const info = () => JSON.parse(vault.info(JSON.stringify(index.state())));

  async function refresh() {
    let outcome;
    try {
      // Someone is waiting for this: it says within seconds that the store is out of reach.
      drive.patience(INTERACTIVE_PATIENCE_MS);
      outcome = await index.refresh();
    } catch (error) {
      const said = describe(error);
      // A newer format ends the session; a sign-in that ended is the page's to show.
      if (fatal(said.code)) {
        phase = 'dead';
        why = said.message;
        throw error;
      }
      if (said.code === 'no_session') throw error;
      index.failed(said.message);
      return info();
    }
    if (outcome.reload) {
      vault.reset();
      await loadIndex(true);
    }
    return info();
  }

  /** The five calls of the viewer's API (`src/web/rules.rs` decides every answer). */
  async function api(name, params) {
    need(vault && index, 'The vault is locked.');
    if (name === 'refresh' && phase === 'broken') {
      // A load that failed half way: the refresh is the retry, from the start.
      vault.reset();
      await loadIndex(true);
      return info();
    }
    if (phase !== 'ready') throw new Refusal('unusable', why);
    if (name === 'refresh') return refresh();
    const p = params || {};
    switch (name) {
      case 'info': return info();
      case 'list': return JSON.parse(vault.list(p.path || '', p.sort, p.order, p.offset, p.limit));
      case 'stat': return JSON.parse(vault.stat(String(p.path || '')));
      case 'search': return JSON.parse(vault.search(String(p.q || ''), p.limit, p.sort, p.order));
      default: throw new Refusal('bad-input', 'There is no such call.');
    }
  }

  /** A ticket for one file, to the Service Worker. The page learns nothing of it. */
  function issue(id, path) {
    if (!ticketPort) {
      waitingIssues.push([id, path]);
      return;
    }
    try {
      need(vault && phase === 'ready', why);
      const ticket = vault.ticket(path);
      const current = token.peek();
      ticketPort.postMessage({ type: 'ticket', id, ticket, token: current ? current.token : null, exp: current ? current.exp : 0, build: BUILD });
    } catch (error) {
      ticketPort.postMessage({ type: 'ticket-error', id, message: describe(error).message, build: BUILD });
    }
  }

  /** The key bundle comes in on `port` from the KDF worker; the keyfiles go out on it. */
  function keys(port, use) {
    need(opened && chosen, 'No vault is chosen.');
    port.onmessage = (message) => {
      const data = message.data;
      if (!data || data.type !== 'bundle' || !(data.bundle instanceof Uint8Array)) return;
      port.close();
      try {
        if (vault) vault.free();
        // `from_keys` zero-fills the buffer it is given.
        vault = core.Vault.from_keys(data.bundle);
        if (vault.vault_id() !== chosen.vault_id) throw new Refusal('other-vault', 'The keys belong to another vault.');
        index = loader.createIndex({ core, drive, vault, folder: opened.index, hooks });
        event('unlocked', {});
      } catch (error) {
        vault = null;
        event('unlock-failed', describe(error));
      }
    };
    const candidates = opened.candidates
      .filter((candidate, i) => use.includes(i))
      .map((candidate) => ({ name: candidate.name, bytes: candidate.bytes.slice() }));
    port.postMessage({ type: 'keyfiles', vault_id: chosen.vault_id, candidates });
  }

  const calls = {
    async init(args) {
      token.seed(args.token, args.exp);
      await core({ module_or_path: `${BASE}core.wasm` });
      return { version: core.core_version(), build: BUILD };
    },
    seed(args) {
      token.seed(args.token, args.exp);
    },
    async discover() {
      found = await loader.discover(core, drive);
      return {
        vaults: found.vaults.map((v) => ({ folder: v.folder, id8: v.vault_id.slice(0, 8), created_ms: v.created_ms })),
        unreadable: found.unreadable,
        damaged: found.damaged,
      };
    },
    async open(args) {
      chosen = need(found && found.vaults[args.n], 'There is no such vault.');
      opened = await loader.open(core, drive, chosen.root);
      return {
        folder: chosen.folder,
        id8: chosen.vault_id.slice(0, 8),
        candidates: opened.candidates.map((c) => ({ name: c.name, cost: c.cost, expensive: loader.expensive(c.cost) })),
        refused: opened.refused,
        newer: opened.newer,
        unseen: opened.unseen,
      };
    },
    keys(args, ports) {
      keys(need(ports[0], 'No port.'), Array.isArray(args.use) ? args.use : []);
    },
    load() {
      need(vault && index, 'The vault is locked.');
      return loadIndex();
    },
    answer(args) {
      const resolve = pendingConfirm;
      pendingConfirm = null;
      if (resolve) resolve(args.answer);
    },
    api: (args) => api(String(args.name), args.params),
    tickets(args, ports) {
      if (ticketPort) ticketPort.close();
      ticketPort = need(ports[0], 'No port.');
      for (const [id, path] of waitingIssues.splice(0)) issue(id, path);
    },
    issue(args) {
      issue(String(args.id), String(args.path));
    },
  };

  self.onmessage = async (message) => {
    const { seq, call, args } = message.data || {};
    try {
      if (!Object.prototype.hasOwnProperty.call(calls, call)) throw new Refusal('bad-input', 'There is no such call.');
      const value = await calls[call](args || {}, message.ports || []);
      if (seq != null) self.postMessage({ seq, ok: true, value: value === undefined ? null : value });
    } catch (error) {
      if (seq != null) self.postMessage({ seq, ok: false, ...describe(error) });
    }
  };
})();
