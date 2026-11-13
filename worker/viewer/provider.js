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
    /** One id per path and unlock: 128 random bits. The Service Worker knows files by these. */
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
      const path = paths.get(data.id);
      if (!path) return;
      if (!data.port) openChannel();
      vault.send('issue', { id: data.id, path });
    }
    navigator.serviceWorker.addEventListener('message', onServiceWorker);
    navigator.serviceWorker.addEventListener('controllerchange', openChannel);
    openChannel();

    function idOf(path) {
      let id = ids.get(path);
      if (!id) {
        id = id22();
        ids.set(path, id);
        paths.set(id, path);
      }
      vault.send('issue', { id, path });
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
        // What the page fetches a file by: an opaque id, never its name.
        if (name === 'stat' && value && !value.dir && typeof value.path === 'string') value.id = idOf(value.path);
        if ((name === 'info' || name === 'refresh') && hooks && hooks.info) hooks.info(value);
        return value;
      },
      fileUrl: (id, download) => `/v/${id}${download ? '?dl=1' : ''}`,
      unreachable: 'The file could not be fetched. Check the connection, or reload the page.',
      privateAddress: true,
      // A PDF is never shown in a frame of this page: in a tab of its own, behind "Open".
      // A PDF is the one kind of vault content that is shown without `sandbox` (a browser's
      // PDF viewer does not run in a sandboxed frame), and a link in it takes the whole tab
      // to wherever it points with one click (Chrome) — the unlocked viewer, to a page of the
      // file's choosing. In a tab of its own (`rel=noopener`) it can only take itself. (iPhone
      // and iPad show only the first page of a PDF in a frame anyway.)
      pdfInline: false,
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
