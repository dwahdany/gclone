// gclone viewer — the page's side of the vault: the vault worker's client, the ticket channel,
// and `window.gcloneProvider`, the object the shared page script (app.js) gets its answers and
// its file addresses from.
//
// The page holds ids and paths. It creates the two channels that keys travel on and gives
// their ports away — the key bundle KDF worker → vault worker, tickets vault worker → Service
// Worker — and that is a convention of this script, not a boundary: any script in the page
// could keep a port, or put its own in place. What makes the ticket channel safe to hand out
// is that tickets cross it sealed to the Service Worker (seal.js), so a port in the wrong
// hands carries ciphertext. Nothing protects the key bundle's channel in that way, and nothing
// needs to: a script that is in the page while the passphrase is typed has the passphrase.
//
// What the page gets by design, and any script in it with it: every name, and the bytes of
// every file through `/v/<id>`, for as long as the vault is unlocked.
'use strict';
(() => {
  const gclone = (window.gclone = window.gclone || {});
  // Where this build's files are: the directory this script was loaded from.
  const BASE = new URL('.', document.currentScript.src).pathname;
  const BUILD = BASE.split('/')[2] || '';

  // The page's one Trusted Types policy: script URLs of this build, and the Service Worker.
  const scriptUrl = (() => {
    const allowed = ['vault-worker.js', 'kdf-worker.js', 'app.js'].map((name) => BASE + name).concat('/sw.js');
    const check = (url) => {
      if (!allowed.includes(url)) throw new TypeError('not a script of this build');
      return url;
    };
    if (!window.trustedTypes) return check;
    const policy = window.trustedTypes.createPolicy('gclone', { createScriptURL: check });
    return (url) => policy.createScriptURL(url);
  })();

  const terminateWorker = Worker.prototype.terminate;

  class VaultError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'VaultError';
      this.code = code;
    }
  }

  /** The vault worker, as calls that answer and events. */
  function createVault() {
    const worker = new Worker(scriptUrl(`${BASE}vault-worker.js`));
    const waiting = new Map();
    const listeners = new Map();
    let seq = 0;
    let gone = null;
    const emit = (name, data) => { for (const fn of listeners.get(name) || []) fn(data); };
    const fail = (error) => {
      gone = error;
      for (const { reject } of waiting.values()) reject(error);
      waiting.clear();
      emit('gone', error);
    };
    worker.onmessage = (message) => {
      const data = message.data || {};
      if (data.event) {
        emit(data.event, data);
        return;
      }
      const call = waiting.get(data.seq);
      if (!call) return;
      waiting.delete(data.seq);
      if (data.ok) call.resolve(data.value);
      else call.reject(new VaultError(data.code, data.message));
    };
    // A worker whose script did not load: most likely the build was replaced by a deployment.
    worker.onerror = (event) => {
      if (event && event.preventDefault) event.preventDefault();
      fail(new VaultError('gone', 'The viewer was updated or one of its files could not be loaded. Reload the page.'));
    };
    return {
      call(name, args, transfer) {
        if (gone) return Promise.reject(gone);
        return new Promise((resolve, reject) => {
          seq += 1;
          waiting.set(seq, { resolve, reject });
          worker.postMessage({ seq, call: name, args: args || {} }, transfer || []);
        });
      },
      /** A call nobody waits for. */
      send(name, args, transfer) {
        if (!gone) worker.postMessage({ call: name, args: args || {} }, transfer || []);
      },
      on(name, fn) {
        if (!listeners.has(name)) listeners.set(name, []);
        listeners.get(name).push(fn);
      },
      terminate() {
        terminateWorker.call(worker);
        if (!gone) fail(new VaultError('locked', 'The vault is locked.'));
      },
    };
  }

  const id22 = () => {
    let text = '';
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  /**
   * `window.gcloneProvider` over an unlocked vault. `hooks.info(info)`: every summary that
   * passes; `hooks.failed(error)`: a call failed with a code the shell has to act on.
   */
  function createProvider(vault, hooks) {
    /**
     * One id per file and unlock: 128 random bits. The Service Worker knows files by these.
     * An earlier version of a file (the time machine) is a file of its own here: `ids` is
     * keyed by the path, or by path, NUL and version id — no path holds a NUL — and `paths`
     * gives `{ path, v }` back for an id.
     */
    const ids = new Map();
    const paths = new Map();
    const controller = () => navigator.serviceWorker.controller;

    /** A new ticket channel: one end to the vault worker, one to the Service Worker. What crosses it is sealed (seal.js). */
    function openChannel() {
      const channel = new MessageChannel();
      vault.send('tickets', {}, [channel.port1]);
      const sw = controller();
      if (sw) sw.postMessage({ type: 'port' }, [channel.port2]);
    }

    function onServiceWorker(event) {
      const data = event.data || {};
      if (data.type !== 'need-ticket') return;
      // The Service Worker has no ticket for an id: it was restarted, or the browser asked
      // for the address before the ticket arrived. Only an id of this unlock is answered.
      const file = paths.get(data.id);
      if (!file) return;
      if (!data.port) openChannel();
      vault.send('issue', { id: data.id, path: file.path, v: file.v });
    }
    navigator.serviceWorker.addEventListener('message', onServiceWorker);
    navigator.serviceWorker.addEventListener('controllerchange', openChannel);
    openChannel();

    function idOf(path, v) {
      const name = v ? `${path}\0${v}` : path;
      let id = ids.get(name);
      if (!id) {
        id = id22();
        ids.set(name, id);
        paths.set(id, { path, v: v || null });
      }
      vault.send('issue', { id, path, v: v || null });
      return id;
    }

    return {
      async api(name, params) {
        let value;
        try {
          value = await vault.call('api', { name, params: params ? { ...params } : null });
        } catch (error) {
          if (hooks && hooks.failed) hooks.failed(error);
          throw new Error(error.message);
        }
        // What the page fetches a file by: an opaque id, never its name. A `stat` of an
        // earlier moment or of one version says which version it shows (`v`): its id is that
        // version's, and stays that version's whatever becomes of the file.
        if (name === 'stat' && value && !value.dir && typeof value.path === 'string') {
          value.id = idOf(value.path, typeof value.v === 'string' ? value.v : null);
        }
        if ((name === 'info' || name === 'refresh') && hooks && hooks.info) hooks.info(value);
        return value;
      },
      fileUrl: (id, download) => `/v/${id}${download ? '?dl=1' : ''}`,
      unreachable: 'The file could not be fetched. Check the connection, or reload the page.',
      privateAddress: true,
      // A PDF is shown in a frame of the preview, as every other kind is shown in the page
      // (0.6.1). It is the one kind of vault content without `sandbox` on its answer (Chrome's
      // PDF viewer does not load under it), and a link in a framed PDF takes the whole tab —
      // the unlocked viewer — to an address of the file's choosing. The page guards the
      // frame (app.js, `guardPdf`): a sandboxed frame in Firefox, where a click on the link
      // then does nothing; elsewhere the browser's question before the tab leaves. What that leaves
      // open is in SPEC §15.
      pdfGuard: true,
      // No "Open in a new tab" for audio and video: the answer's `sandbox` policy gives the
      // browser's own media document an origin the Service Worker does not control, so its
      // player would ask the network for `/v/<id>` — where nothing answers.
      openInTab: (kind) => kind !== 'audio' && kind !== 'video',
      // Chrome fetches a link that carries `download` past the Service Worker — to the
      // network, where nothing answers `/v/…`. A plain link is a navigation the Service Worker
      // answers as an attachment: the browser saves it and the page stays.
      downloadAttribute: false,
    };
  }

  gclone.page = { BASE, BUILD, scriptUrl };
  gclone.VaultError = VaultError;
  gclone.createVault = createVault;
  gclone.createProvider = createProvider;
})();
