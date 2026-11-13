// gclone viewer — the vault worker. It holds the keyring and the decrypted index for as long
// as the vault is unlocked, reads the index from Drive, answers the page's five API calls and
// issues per-file tickets to the Service Worker.
//
// Nothing that leaves this worker after the unlock holds a key that the page — or a script in
// it — can read. No call exports a master key. A ticket (the key of one file's stream) leaves
// only sealed to the Service Worker (seal.js): the port it travels on is the page's to hand
// out, so whoever holds the other end, or sits in the middle, gets ciphertext. What the page
// does get is what it is for: names, sizes, and — through the Service Worker — the bytes of
// any file it asks for, for as long as the vault is unlocked.
//
// Before the unlock it is different, and cannot be otherwise: the page sees the passphrase
// as it is typed, and it hands this worker the port the key bundle arrives on. A script that
// already runs in the page at that moment has the vault.
'use strict';
// This context's one Trusted Types policy: script URLs of this build only.
const BASE = self.location.pathname.replace(/[^/]*$/, '');
const scriptUrl = (() => {
  const allowed = ['core.js', 'token.js', 'drive.js', 'loader.js', 'seal.js'].map((name) => BASE + name);
  const check = (url) => {
    if (!allowed.includes(url)) throw new TypeError('not a script of this build');
    return url;
  };
  if (!self.trustedTypes) return check;
  const policy = self.trustedTypes.createPolicy('gclone', { createScriptURL: check });
  return (url) => policy.createScriptURL(url);
})();
importScripts(scriptUrl(`${BASE}core.js`), scriptUrl(`${BASE}token.js`), scriptUrl(`${BASE}drive.js`), scriptUrl(`${BASE}loader.js`), scriptUrl(`${BASE}seal.js`));

(() => {
  const { loader, token, seal } = self.gclone;
  const BUILD = BASE.split('/')[2] || '';
  const core = wasm_bindgen;
  const drive = self.gclone.createDrive({ token });
  // Finding the vault and loading its index follow the CLI's retry schedule; once the list is
  // on the screen, a request gives up after about ten seconds of pauses.
  const INTERACTIVE_PATIENCE_MS = 10000;
  // The Service Worker's key is asked for this often, with these pauses before each attempt.
  // (An engine may take a moment to put a new worker's requests under the Service Worker.)
  const SEAL_PAUSES_MS = [0, 100, 300, 800];
  const NO_SEAL = 'The viewer\'s Service Worker does not answer its vault worker, so no file can be opened. Reload the page.';

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
  let channel = null; // agree(): a promise of { to, from, key }, the seal of the ticket port
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

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  /**
   * The Service Worker's public key, from the Service Worker itself: this worker's own request,
   * which the page has no part in (seal.js). `null` when something else answered — the host,
   * where no Service Worker is in control of this worker, or a Service Worker of another build.
   */
  async function sealKey() {
    const res = await fetch(seal.PATH, { cache: 'no-store', credentials: 'omit', redirect: 'error' });
    const body = new Uint8Array(await res.arrayBuffer());
    return res.status === 200 && res.headers.get(seal.BUILD_HEADER) === BUILD && seal.isPublic(body) ? body : null;
  }

  /** The seal of the ticket port: agreed once per channel, with the Service Worker that is in control then. */
  function agree() {
    if (!channel) {
      const mine = (async () => {
        let to = null;
        for (const pause of SEAL_PAUSES_MS) {
          if (pause) await sleep(pause);
          to = await sealKey().catch(() => null);
          if (to) break;
        }
        if (!to) throw new Refusal('no-service-worker', NO_SEAL);
        try {
          const own = await seal.generate();
          return { to, from: own.raw, key: await seal.agree(own.secret, to, to, own.raw, 'encrypt') };
        } catch (_) {
          throw new Refusal('no-service-worker', NO_SEAL);
        }
      })();
      channel = mine;
      // A failure is not kept: the next ticket asks again.
      mine.catch(() => { if (channel === mine) channel = null; });
    }
    return channel;
  }

  /**
   * A ticket for one file, to the Service Worker — sealed, so that it is a ticket to the
   * Service Worker only: the page that hands the port out, and anyone it hands it to, reads
   * the id and nothing else.
   */
  async function issue(id, path) {
    if (!ticketPort) {
      waitingIssues.push([id, path]);
      return;
    }
    // The ticket is sealed for, and posted on, the channel that is current when it is ready —
    // not the one that was current when it was asked for. When the Service Worker has lost its
    // tickets (another tab left, the browser stopped it) and several files are asked for at
    // once, every `need-ticket` makes the page open a new channel, which closes the port of
    // the one before: a ticket that was being sealed for that one was posted on a closed
    // port, and all but the last file were answered "410 This link has expired" after 3 s.
    // (The rounds are bounded: a page that keeps sending ports gets an answer all the same.)
    let port;
    let message;
    for (let round = 0; ; round += 1) {
      port = ticketPort;
      const replaced = () => port !== ticketPort && round < 16;
      try {
        need(vault && phase === 'ready', why);
        const mine = agree();
        const { to, from, key } = await mine;
        // A new channel came in while this one's key was agreed: the ticket is sealed for the new one.
        if (replaced() || (mine !== channel && round < 16)) continue;
        need(vault && phase === 'ready', why);
        const current = token.peek();
        const text = JSON.stringify({ ticket: vault.ticket(path), token: current ? current.token : null, exp: current ? current.exp : 0 });
        const sealed = await seal.close(key, id, text).catch(() => { throw new Refusal('no-service-worker', NO_SEAL); });
        if (replaced()) continue;
        message = { type: 'ticket', id, sealed: { to, from, iv: sealed.iv, data: sealed.data }, build: BUILD };
      } catch (error) {
        if (replaced()) continue;
        // No key in this: the sentence the Service Worker answers the file's address with.
        message = { type: 'ticket-error', id, message: describe(error).message, build: BUILD };
      }
      break;
    }
    port.postMessage(message);
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
      // Asked now, before anyone typed a passphrase: a worker that cannot reach the Service
      // Worker opens no file, and the page can still start another.
      const sealed = await agree().then(() => true, () => false);
      return { version: core.core_version(), build: BUILD, sealed };
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
      const port = need(ports[0], 'No port.');
      if (ticketPort) {
        // A new channel: the Service Worker was restarted, replaced or told to forget, and
        // its key went with that. The seal is agreed anew.
        ticketPort.close();
        channel = null;
      }
      ticketPort = port;
      for (const [id, path] of waitingIssues.splice(0)) issue(id, path);
    },
    issue(args) {
      // Not waited for: the answer goes to the Service Worker, and `issue` never throws.
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
