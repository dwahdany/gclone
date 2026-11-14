// gclone viewer — the shell: everything around the file list. It signs in (a redirect to
// Google and back), starts the Service Worker, finds the vault, asks for the passphrase,
// loads the index, starts the shared page script (app.js) and locks.
//
// The page is the UI and nothing else. It sees the passphrase while it is typed and hands it
// to the KDF worker; it never loads the core. After the unlock nothing that reaches it — or a
// port it creates — holds a key it could read: tickets cross its channel sealed to the Service
// Worker (seal.js). Before that, a script in this page has the passphrase, and the port the
// key bundle travels on.
// Nothing is kept beyond the tab but the sign-in cookie (HttpOnly, the Worker's) and the sort
// order. Names of the vault never get into the address, the title or the session history.
//
// Lock goes by the wall clock, never by a timer's own count: a frozen tab's timers do not
// run. Locking is a reload — the most complete wipe a page can do; the cookie remains, so the
// next screen is the passphrase. The Lock button and Sign out are meant for the browser, not
// for one tab: the other tabs of the viewer are told, and lock too.
'use strict';
(() => {
  const gclone = window.gclone;
  const { BASE, BUILD, scriptUrl } = gclone.page;
  const token = gclone.token;
  const $ = (id) => document.getElementById(id);
  const shell = $('shell');
  // What a lock must do, with functions taken now — before any script that arrives later
  // could put its own in their place — and each step on its own: a step that throws (a
  // script that redefined `document.body.hidden` to throw kept the whole lock from happening,
  // for this tab and for every later Lock, clock and Sign out) does not keep the next from
  // running. This narrows what a script in the page can do after the fact; it does not make
  // the page safe from one (it can still keep a lock from being asked for, design §7.1).
  const postToServiceWorker = window.ServiceWorker ? ServiceWorker.prototype.postMessage : null;
  const terminateWorker = window.Worker ? Worker.prototype.terminate : null;
  const attempt = (fn) => { try { fn(); } catch (_) { /* the next step still happens */ } };
  /** Tells the Service Worker to forget, with the function taken at load. */
  function forgetInServiceWorker() {
    attempt(() => {
      const controller = navigator.serviceWorker && navigator.serviceWorker.controller;
      if (controller && postToServiceWorker) postToServiceWorker.call(controller, { type: 'forget' });
    });
  }
  /**
   * The irreversible half of a lock, before anything of the DOM or the history is touched:
   * the Service Worker forgets, the vault worker (which holds the master keys) and the KDF
   * worker end. After this the page holds nothing of the vault.
   */
  function dropVault() {
    forgetInServiceWorker();
    attempt(() => { if (vault) vault.terminate(); });
    attempt(() => endKdf());
  }

  const MINUTE = 60 * 1000;
  const IDLE_LOCK = 15 * MINUTE; // without input
  const HIDDEN_LOCK = 5 * MINUTE; // in the background
  const LOCK_CHECK = 15 * 1000;
  const KDF_IDLE = 2 * MINUTE; // a KDF worker without an attempt
  const PING_EVERY = 20 * 1000; // keeps the Service Worker alive through a long download
  const LOGIN_TTL = 10 * MINUTE; // a sign-in that was begun and not finished
  const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth?';
  const GOOGLE_ISSUER = 'https://accounts.google.com';
  const NEWER = 'This vault needs a newer viewer. It was written by a newer gclone than the one this site runs.';
  const UPDATED = 'The viewer was updated, or one of its files could not be loaded. Reload the page.';
  const MIB = 1024 * 1024;
  const SESSION_OVER = ['no_session', 'email_not_allowed', 'invalid_grant'];
  const LOCKED_ELSEWHERE = 'The vault was locked in another tab.';
  const OUT_ELSEWHERE = 'You signed out in another tab.';
  const NO_SERVICE_WORKER = 'The viewer\'s Service Worker is gone (this site\'s data was cleared). Unlock the vault again.';
  const NO_SEAL = 'The viewer\'s Service Worker does not answer the worker that holds the vault\'s keys, so no file could be opened. Reload the page; if that does not help, close the other tabs of the viewer and try again.';
  const VAULT_STARTS = 3; // vault workers started before the viewer gives up on reaching its Service Worker

  // ---- small things ---------------------------------------------------------------------------

  /** sessionStorage, which a browser may refuse: flags of this tab, never a secret but the PKCE verifier. */
  const flags = {
    get(name) {
      try { return sessionStorage.getItem(name); } catch (_) { return null; }
    },
    set(name, value) {
      try { sessionStorage.setItem(name, value); return true; } catch (_) { return false; }
    },
    remove(name) {
      try { sessionStorage.removeItem(name); } catch (_) { /* nothing to remove */ }
    },
    take(name) {
      const value = this.get(name);
      if (value !== null) this.remove(name);
      return value;
    },
  };

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const forever = () => new Promise(() => {});
  const mib = (bytes) => `${Math.max(1, Math.round(bytes / MIB)).toLocaleString()} MiB`;

  function base64url(bytes) {
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /** A sentence with `commands` in it: text nodes and <code> elements, never markup. */
  function prose(node, text) {
    node.replaceChildren(...String(text || '').split('`').map((part, i) => {
      if (i % 2 === 0) return document.createTextNode(part);
      const code = document.createElement('code');
      code.textContent = part;
      return code;
    }));
  }

  function setProblem(id, text) {
    const node = $(id);
    node.hidden = !text;
    prose(node, text || '');
  }

  // ---- screens --------------------------------------------------------------------------------

  let screen = 'boot';
  const screens = [...shell.querySelectorAll('.screen')];
  function show(name) {
    screen = name;
    shell.dataset.screen = name;
    // Also by attribute: one screen shows even where the style sheet did not load.
    for (const section of screens) section.hidden = section.dataset.screen !== name;
    shell.hidden = false;
  }

  function work(text, detail) {
    $('work-text').textContent = text;
    $('work-detail').textContent = detail || '';
    $('work-meter').hidden = true;
    show('work');
  }

  function meter(done, total) {
    $('work-meter').hidden = false;
    $('work-bar').style.width = `${total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0}%`;
  }

  /** The end of the road for this page load: a sentence, Reload, Sign out. */
  function stop(text, options) {
    // With the file list on the page there is no screen to show this on: lock, and say it there.
    if (unlocked) {
      lock(text);
      return;
    }
    endKdf();
    $('stop-title').textContent = (options && options.title) || 'The viewer cannot go on';
    prose($('stop-text'), text);
    // What the last page load left to say (a sign-out that did not arrive) is said here too.
    setProblem('stop-note', flags.take('gclone.note') || '');
    $('stop-reload').hidden = !!(options && options.noReload);
    $('stop-out').hidden = !!(options && options.noSignOut);
    show('stop');
  }

  /** A question with buttons; resolves to the chosen `value`. */
  function ask(title, text, choices, column) {
    return new Promise((resolve) => {
      $('ask-title').textContent = title;
      prose($('ask-text'), text);
      const box = $('ask-choices');
      box.className = column ? 'choices column' : 'choices';
      box.replaceChildren(...choices.map((choice) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = column || !choice.primary ? 'btn quiet' : 'btn';
        const label = document.createElement('span');
        label.textContent = choice.label;
        button.append(label);
        if (choice.sub) {
          const sub = document.createElement('small');
          sub.textContent = choice.sub;
          label.append(sub);
        }
        button.addEventListener('click', () => resolve(choice.value), { once: true });
        return button;
      }));
      show('ask');
      const first = box.querySelector('button');
      if (first) first.focus();
    });
  }

  function showSignIn(problem) {
    endKdf();
    if (vault) vault.terminate();
    vault = null;
    setProblem('signin-problem', problem || flags.take('gclone.note') || '');
    $('signin-go').disabled = false;
    show('signin');
  }

  /** What a failed step leads to: the sign-in screen when the session is over, else the reason. */
  function fail(error) {
    const code = error && error.code;
    if (code === 'no_session') showSignIn();
    else if (code === 'email_not_allowed' || code === 'invalid_grant') showSignIn(error.message);
    else if (code === 'locked') { /* the page is on its way out */ }
    else stop((error && error.message) || String(error));
  }

  // ---- the Service Worker ---------------------------------------------------------------------

  /** `{ build, streams, port, tickets }` from the Service Worker in control, or `null`. */
  function ping(timeout) {
    const controller = navigator.serviceWorker.controller;
    if (!controller) return Promise.resolve(null);
    return new Promise((resolve) => {
      let timer = 0;
      const done = (value) => {
        navigator.serviceWorker.removeEventListener('message', listen);
        clearTimeout(timer);
        resolve(value);
      };
      function listen(event) {
        if (event.data && event.data.type === 'pong') done(event.data);
      }
      navigator.serviceWorker.addEventListener('message', listen);
      timer = setTimeout(() => done(null), timeout || 3000);
      controller.postMessage({ type: 'ping' });
    });
  }

  /** Resolves to whether a Service Worker controls the page, at the latest after `ms`. */
  const controlled = (ms) => new Promise((resolve) => {
    const sw = navigator.serviceWorker;
    if (sw.controller) {
      resolve(true);
      return;
    }
    let timer = 0;
    const done = () => {
      sw.removeEventListener('controllerchange', done);
      clearTimeout(timer);
      resolve(!!sw.controller);
    };
    sw.addEventListener('controllerchange', done);
    timer = setTimeout(done, ms);
  });

  const controlChange = (ms) => Promise.race([
    new Promise((resolve) => navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true })),
    sleep(ms),
  ]);

  /** Registers `/sw.js` and waits until the Service Worker of this build controls the page. */
  async function startServiceWorker() {
    const sw = navigator.serviceWorker;
    sw.startMessages();
    // The viewer has one Service Worker: `/sw.js`, for the whole origin. A registration of
    // another script, or for another scope, is not this build's — it is what someone who
    // served this origin before left in the browser (a worker for `/callback` alone would
    // take the way back from Google). It is removed whenever this page gets to run. (A foreign
    // worker for the whole origin answers `/` itself, and this page never runs: that takes
    // clearing the site's data by hand — docs/SECURITY.md, "After a change of hands".)
    try {
      for (const other of await sw.getRegistrations()) {
        const worker = other.active || other.waiting || other.installing;
        const own = other.scope === `${location.origin}/` && worker && new URL(worker.scriptURL).pathname === '/sw.js';
        if (!own) await other.unregister();
      }
    } catch (_) { /* a browser that does not list them: the registration below still takes the origin */ }
    let registration;
    try {
      registration = await sw.register(scriptUrl('/sw.js'), { scope: '/' });
    } catch (_) {
      throw new Error('The viewer could not install its Service Worker, which decrypts the files. Reload the page; if that does not help, this browser or its settings do not allow it here.');
    }
    if (!sw.controller && registration.active) {
      // The page was loaded past an active Service Worker (a forced reload does that): it is
      // not taken over by itself, so it asks.
      registration.active.postMessage({ type: 'claim' });
      await controlled(3000);
    } else if (!(await controlled(3000))) {
      // A first visit: the worker claims its pages when it becomes active. If that did not
      // reach this page, it asks.
      const active = await Promise.race([sw.ready.then((ready) => ready.active), sleep(5000).then(() => null)]);
      if (active && !sw.controller) active.postMessage({ type: 'claim' });
      await controlled(3000);
    }
    if (!sw.controller) {
      // Once more, the plain way.
      if (flags.get('gclone.sw') !== '1' && flags.set('gclone.sw', '1')) {
        location.reload();
        await forever();
      }
      throw new Error('The viewer\'s Service Worker did not take over this page. Close the other tabs of the viewer and reload.');
    }
    let pong = await ping();
    if (!pong || pong.build !== BUILD) {
      // Another build's Service Worker: fetch this one, which takes over as soon as it is in.
      try { await registration.update(); } catch (_) { /* the reload below is the retry */ }
      for (let i = 0; i < 5 && (!pong || pong.build !== BUILD); i += 1) {
        await controlChange(1000);
        pong = await ping();
      }
    }
    if (!pong || pong.build !== BUILD) {
      if (flags.get('gclone.swb') !== '1' && flags.set('gclone.swb', '1')) {
        location.reload();
        await forever();
      }
      throw new Error(UPDATED);
    }
    flags.remove('gclone.sw');
    flags.remove('gclone.swb');
    openStreams = pong.streams;
  }

  // While a stream is open — a download that outlives a Lock included — the Service Worker
  // is pinged, so that the browser does not stop it in the middle.
  let openStreams = 0;
  setInterval(async () => {
    if (!unlocked && openStreams === 0) return;
    if (unlocked && !navigator.serviceWorker.controller) {
      lock(outElsewhere ? OUT_ELSEWHERE : NO_SERVICE_WORKER);
      return;
    }
    const pong = await ping();
    openStreams = pong ? pong.streams : 0;
  }, PING_EVERY);

  // ---- sign-in (design §4.2) ------------------------------------------------------------------

  async function beginSignIn() {
    const button = $('signin-go');
    button.disabled = true;
    setProblem('signin-problem', '');
    try {
      const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
      const challenge = base64url(new Uint8Array(digest));
      const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
      const kept = flags.set('gclone.login', JSON.stringify({ state, verifier, remember: $('signin-remember').checked, at: Date.now() }));
      if (!kept) throw new Error('This browser does not let the page keep anything for the length of the sign-in (session storage is off).');
      const answer = await token.post('/web/start', { challenge, state });
      if (typeof answer.authorization_url !== 'string' || !answer.authorization_url.startsWith(GOOGLE_AUTH)) {
        throw new Error('The sign-in service answered with an address that is not Google\'s.');
      }
      location.assign(answer.authorization_url);
    } catch (error) {
      flags.remove('gclone.login');
      setProblem('signin-problem', error.message);
      button.disabled = false;
    }
  }

  /**
   * On `/callback`: the way back from Google. Nothing is sent unless this tab began the
   * sign-in (its `state`), not more than ten minutes ago, and Google is who answers.
   * Returns `null` (nothing to finish), `{ ok: true }` or `{ problem }`.
   */
  async function finishSignIn() {
    const query = new URLSearchParams(location.search);
    const saved = flags.take('gclone.login');
    history.replaceState(null, '', '/');
    let login = null;
    try { login = JSON.parse(saved); } catch (_) { /* no sign-in was begun here */ }
    const state = query.get('state');
    if (!login || typeof login.state !== 'string' || typeof login.verifier !== 'string' || !state || state !== login.state) return null;
    if (!(Date.now() - Number(login.at) <= LOGIN_TTL)) return { problem: 'The sign-in took longer than ten minutes. Start it again.' };
    const issuer = query.get('iss');
    if (issuer !== null && issuer !== GOOGLE_ISSUER) return { problem: 'The answer to the sign-in did not come from Google. Start it again.' };
    const code = query.get('code');
    if (!code) {
      return { problem: query.get('error') === 'access_denied' ? 'Google did not sign you in: the request was declined.' : 'Google did not complete the sign-in. Start it again.' };
    }
    work('Signing in…');
    try {
      token.take(await token.post('/web/token', { code, verifier: login.verifier, remember: login.remember === true }));
      return { ok: true };
    } catch (error) {
      return { problem: error.message };
    }
  }

  // ---- vault, keyfiles, unlock ----------------------------------------------------------------

  let vault = null;
  /** `{ folder, id8, candidates, use, mKib }` of the vault in use. */
  let target = null;
  let kdf = null;
  let busy = false;
  /** What a tab that the browser killed left behind (read at boot). */
  let killed = { kdf: null, load: null };

  function endKdf() {
    if (!kdf) return;
    const ending = kdf;
    kdf = null;
    attempt(() => clearTimeout(ending.timer));
    attempt(() => terminateWorker.call(ending.worker));
  }

  /** The KDF worker of this unlock screen: made for the first attempt, reused for the next. */
  function useKdf() {
    if (kdf) {
      clearTimeout(kdf.timer);
      return kdf;
    }
    const worker = new Worker(scriptUrl(`${BASE}kdf-worker.js`));
    // The key bundle crosses from the KDF worker to the vault worker on this channel.
    const channel = new MessageChannel();
    vault.send('keys', { use: target.use }, [channel.port1]);
    worker.postMessage({ type: 'start' }, [channel.port2]);
    const mine = { worker, timer: 0, waiting: null };
    worker.onmessage = (message) => {
      const data = message.data || {};
      if (data.type !== 'result' || !mine.waiting) return;
      const resolve = mine.waiting;
      mine.waiting = null;
      resolve(data);
    };
    worker.onerror = (event) => {
      if (event && event.preventDefault) event.preventDefault();
      const resolve = mine.waiting;
      mine.waiting = null;
      if (resolve) resolve({ type: 'result', outcome: 'failed', tried: [], dropped: [], left: 0, untried: 0, memory: true });
    };
    // `limit`: how many keyfiles may say "wrong passphrase" before the attempt ends (0: the usual four).
    mine.attempt = (passphrase, limit) => new Promise((resolve) => {
      mine.waiting = resolve;
      worker.postMessage({ type: 'attempt', passphrase, limit });
    });
    kdf = mine;
    return mine;
  }

  async function findVault() {
    work('Looking for your vault…');
    try {
      const current = await token.get(false).then(() => token.peek());
      // The vault worker seals tickets to the Service Worker, whose key it asks for itself
      // (seal.js). A worker whose requests the engine did not put under the Service Worker
      // (WebKit, when two tabs load the worker's script at the same moment) cannot: it is
      // replaced here, where it holds nothing yet.
      for (let start = 1; ; start += 1) {
        vault = gclone.createVault();
        vault.on('gone', (error) => {
          if (error.code === 'gone') stop(UPDATED);
        });
        vault.on('progress', (state) => {
          $('work-detail').textContent = `${mib(state.done)} of ${mib(state.total)}`;
          meter(state.done, state.total);
        });
        vault.on('load-begin', (state) => flags.set('gclone.load', String(state.total)));
        vault.on('load-end', () => flags.remove('gclone.load'));
        vault.on('confirm', confirmIndex);
        const started = await vault.call('init', { token: current ? current.token : null, exp: current ? current.exp : 0 });
        if (started.sealed) break;
        vault.terminate();
        vault = null;
        if (start >= VAULT_STARTS) {
          stop(NO_SEAL);
          return;
        }
        await sleep(200 * start);
      }
      const found = await vault.call('discover');
      if (found.vaults.length === 0) {
        stop(found.unreadable ? NEWER
          : 'No gclone vault is visible to this sign-in. It sees the vaults that were made by a device that signed in through this site with the same Google account.',
        { title: found.unreadable ? 'A newer viewer is needed' : 'No vault here' });
        return;
      }
      let n = 0;
      if (found.vaults.length > 1) {
        const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
        n = await ask('Which vault?', 'This Google account holds more than one gclone vault.', found.vaults.map((v, i) => ({
          label: v.folder || 'Vault',
          sub: `made ${date.format(new Date(v.created_ms))} · ${v.id8}`,
          value: i,
        })), true);
        work('Opening the vault…');
      }
      const opened = await vault.call('open', { n });
      // Every keyfile that can be tried, highest generation first. What the listing held
      // under a keyfile's name without being one was refused in the vault worker.
      let use = opened.candidates.map((_, i) => i);
      const costly = use.filter((i) => opened.candidates[i].expensive);
      if (costly.length) {
        // Someone with the Drive account can plant a keyfile that asks for far more.
        const memory = mib(Math.max(...costly.map((i) => opened.candidates[i].cost.m_kib)) * 1024);
        const passes = Math.max(...costly.map((i) => opened.candidates[i].cost.t));
        const text = costly.length === 1
          ? `The keyfile \`${opened.candidates[costly[0]].name}\` asks for ${memory} of memory and ${passes} passes to unlock. gclone writes keyfiles of 256 MiB and 3 passes. If you did not make this one, skip it.`
          : `${costly.length} keyfiles of this vault ask for more than gclone's 256 MiB and 3 passes to unlock: up to ${memory} of memory and ${passes} passes. If you did not make them, skip them.`;
        const answer = await ask(costly.length === 1 ? 'A keyfile asks for a lot' : 'Keyfiles that ask for a lot', text, [
          { label: costly.length === 1 ? 'Skip it' : 'Skip them', value: 'skip', primary: true },
          { label: costly.length === 1 ? 'Use it' : 'Use them', value: 'use' },
        ]);
        if (answer !== 'use') use = use.filter((i) => !costly.includes(i));
      }
      if (use.length === 0) {
        stop(opened.newer ? NEWER
          : opened.unseen ? 'The vault\'s folder holds more objects under keyfile names than the viewer looks at, and none of those it looked at is a keyfile it can use. Remove the stray ones in drive.google.com, or run `gclone passwd` on one of your devices.'
            : 'This vault has no keyfile the viewer can use. Run `gclone check` on one of your devices.', { title: opened.newer ? 'A newer viewer is needed' : 'No usable keyfile' });
        return;
      }
      target = { folder: opened.folder, id8: opened.id8, candidates: opened.candidates, use, untried: 0, mKib: Math.max(...use.map((i) => opened.candidates[i].cost.m_kib)) };
      showUnlock();
    } catch (error) {
      fail(error);
    }
  }

  function showUnlock(problem) {
    $('unlock-email').textContent = token.session().email || 'your Google account';
    $('unlock-folder').textContent = target.folder || 'gclone';
    $('unlock-user').value = `gclone vault ${target.id8}`;
    $('unlock-cost').textContent = `Unlocking takes a moment and ${mib(target.mKib * 1024)} of memory.`;
    let note = flags.take('gclone.note') || '';
    if (killed.kdf) {
      note = `The last attempt to unlock ended with the browser closing the page. This browser may not have the ${mib(Number(killed.kdf) * 1024)} of memory the vault's keyfile asks for. Close this tab and open the viewer in a new one.`;
    } else if (killed.load) {
      note = `The last attempt to load this vault's index (${mib(Number(killed.load))}) ended with the browser closing the page. The index may be too large for this browser.`;
    }
    killed = { kdf: null, load: null };
    setProblem('unlock-killed', note);
    setProblem('unlock-problem', problem || '');
    // Keyfiles the last attempt did not get to (more than four are there: a vault has one,
    // two after `gclone passwd` ran on two devices at once — the rest was put there).
    const more = target.untried;
    $('unlock-more-row').hidden = !more;
    $('unlock-more').checked = false;
    $('unlock-more-text').textContent = more ? `Also try the ${more === 1 ? 'one older keyfile' : `${more} older keyfiles`} of this vault. Slower: one key derivation for each.` : '';
    // The fields are dead until a script listens to them.
    $('unlock-fields').disabled = false;
    $('unlock-go').disabled = false;
    busy = false;
    show('unlock');
    $('unlock-pass').focus();
  }

  async function unlock(event) {
    event.preventDefault(); // the form never submits anywhere
    const field = $('unlock-pass');
    const passphrase = field.value;
    if (busy || !passphrase) return;
    busy = true;
    field.value = '';
    $('unlock-go').disabled = true;
    const all = target.untried > 0 && $('unlock-more').checked;
    work('Unlocking…', `Deriving the key: ${mib(target.mKib * 1024)} of memory${all ? `, once for each of up to ${target.use.length} keyfiles` : ''}.`);
    const opened = new Promise((resolve) => {
      vault.on('unlocked', () => resolve(null));
      vault.on('unlock-failed', (error) => resolve(error));
    });
    flags.set('gclone.kdf', String(target.mKib));
    const worker = useKdf();
    const result = await worker.attempt(passphrase, all ? target.use.length : 0);
    flags.remove('gclone.kdf');
    if (kdf === worker) worker.timer = setTimeout(endKdf, KDF_IDLE);
    // A candidate the worker dropped stays dropped until the page is loaded again.
    target.use = target.use.filter((i) => !result.dropped.includes(target.candidates[i].name));
    target.untried = result.untried || 0;
    if (result.outcome === 'opened') {
      const refused = await opened;
      endKdf();
      if (refused) stop(refused.message);
      else loadIndex();
    } else if (result.outcome === 'wrong-passphrase') {
      const wrong = result.tried.filter((t) => t.outcome === 'wrong-passphrase').length;
      // Said differently when not every keyfile was tried: the right passphrase may open one of the others.
      showUnlock(target.untried ? `That passphrase does not open the ${wrong} newest keyfiles of this vault. ${target.untried === 1 ? 'One more was' : `${target.untried} more were`} not tried.` : 'That passphrase does not open this vault.');
    } else if (result.outcome === 'needs-newer') {
      stop(NEWER, { title: 'A newer viewer is needed' });
    } else if (result.outcome === 'no-usable-keyfile') {
      stop('No keyfile of this vault can be opened: what is there is damaged or belongs to another vault. Run `gclone check` on one of your devices.', { title: 'No usable keyfile' });
    } else {
      endKdf();
      showUnlock(`This browser could not derive the key. It may not have the ${mib(target.mKib * 1024)} of memory the keyfile asks for: close other tabs and try again.`);
    }
  }

  async function confirmIndex(question) {
    const choices = [{ label: 'Load it', value: 'load', primary: true }];
    if (question.big) choices.push({ label: `Skip ${question.big.name}`, sub: mib(question.big.size), value: 'skip' });
    choices.push({ label: 'Cancel', value: 'cancel' });
    const answer = await ask('A large index',
      `The index of this vault is ${mib(question.total)}. Loading it needs several times that in memory and may not work in this browser.`, choices);
    work('Loading the index…');
    vault.send('answer', { answer });
  }

  async function loadIndex() {
    work('Loading the index…');
    try {
      await vault.call('load');
    } catch (error) {
      flags.remove('gclone.load');
      if (error.code === 'cancelled') stop('The index was not loaded.', { title: 'Not loaded' });
      else fail(error);
      return;
    }
    startApp();
  }

  // ---- the file list --------------------------------------------------------------------------

  let unlocked = false;

  /** The sign-in ended (the cookie ran out, or was withdrawn): nothing more can be read. Said by the vault worker, or by the Service Worker. */
  function sessionOver(error) {
    if (!unlocked || !SESSION_OVER.includes(error && error.code)) return;
    lock(error.code === 'no_session' ? 'Your sign-in has ended. Sign in again.' : String(error.message || 'Your sign-in has ended. Sign in again.'));
  }

  function startApp() {
    const provider = gclone.createProvider(vault, {
      info(info) {
        const head = $('session-head');
        if (head) head.textContent = info.head || 'none yet';
      },
      failed: sessionOver,
    });
    window.gcloneProvider = provider;
    const parts = $('shell-parts').content.cloneNode(true);
    const app = $('app').content.cloneNode(true);
    const lockButton = parts.getElementById('lock-btn');
    const session = parts.getElementById('session');
    shell.hidden = true;
    document.body.append(app);
    $('info-btn').after(lockButton);
    $('info').append(session);
    $('session-email').textContent = token.session().email || '';
    $('session-build').textContent = BUILD;
    // A file in a tab of its own has left the viewer: Lock does not reach it.
    const openInTab = $('viewer-open');
    if (openInTab) {
      openInTab.title = 'Open in a new tab (that tab stays open after Lock: close it yourself)';
      openInTab.setAttribute('aria-label', openInTab.title);
    }
    lockButton.addEventListener('click', lockEverywhere);
    $('session-lock').addEventListener('click', lockEverywhere);
    $('session-out').addEventListener('click', signOut);
    lastInput = Date.now();
    hiddenAt = document.visibilityState === 'hidden' ? Date.now() : null;
    unlocked = true;
    const script = document.createElement('script');
    script.addEventListener('error', () => stop(UPDATED));
    script.src = scriptUrl(`${BASE}app.js`);
    document.body.append(script);
  }

  // ---- lock (design §7.1 step 5) --------------------------------------------------------------

  let lastInput = Date.now();
  let hiddenAt = null;
  let leaving = false;

  const due = (now) => now - lastInput > IDLE_LOCK || (hiddenAt !== null && now - hiddenAt > HIDDEN_LOCK);

  /** Forgets everything of the vault and loads the page again. `note`: said on the next screen. */
  function lock(note) {
    if (leaving) return;
    leaving = true;
    unlocked = false;
    dropVault();
    // Nothing of the list is painted after this task.
    attempt(() => { document.body.hidden = true; });
    attempt(() => history.replaceState(null, '', '/'));
    attempt(() => { if (typeof note === 'string' && note) flags.set('gclone.note', note); });
    location.reload();
  }

  // The other tabs of the viewer in this browser. Nothing of the vault is ever said here:
  // three words, "lock", "outgoing" and "out".
  // "outgoing" comes before the sign-out's request: its answer clears this site's data, and a
  // tab may see its Service Worker go before "out" arrives. It then says the true reason.
  let outElsewhere = false;
  const tabs = (() => {
    try { return new BroadcastChannel('gclone'); } catch (_) { return null; }
  })();
  function tellTabs(type) {
    try { if (tabs) tabs.postMessage({ type }); } catch (_) { /* a closed channel: nobody to tell */ }
  }
  if (tabs) {
    tabs.onmessage = (event) => {
      const type = event.data && event.data.type;
      if (leaving) return;
      if (type === 'outgoing') {
        outElsewhere = true;
      } else if (type === 'lock') {
        outElsewhere = false;
        if (unlocked) lock(LOCKED_ELSEWHERE);
      } else if (type === 'out') {
        if (unlocked) lock(OUT_ELSEWHERE);
        else if (screen !== 'signin' && screen !== 'out') {
          // On its way to the list, or at the passphrase: the session it relies on is gone.
          leaving = true;
          dropVault();
          attempt(() => flags.set('gclone.note', OUT_ELSEWHERE));
          location.reload();
        }
      }
    };
  }

  /** The Lock button: this tab, and every other tab of the viewer. (A lock by the clock is each tab's own.) */
  function lockEverywhere() {
    tellTabs('lock');
    lock();
  }

  async function signOut() {
    if (leaving) return;
    leaving = true;
    unlocked = false;
    dropVault();
    attempt(() => { document.body.hidden = true; });
    attempt(() => history.replaceState(null, '', '/'));
    tellTabs('outgoing');
    let failure = null;
    try {
      await token.post('/web/logout', {});
    } catch (error) {
      failure = error;
    }
    // Whatever the steps below do, the page loads again: each on its own.
    if (!failure) {
      // The answer cleared this site's storage; what a browser left is removed here.
      attempt(() => { localStorage.clear(); sessionStorage.clear(); });
      attempt(() => flags.set('gclone.out', '1'));
      // The cookie is gone: the other tabs forget the vault and go to the sign-in screen.
      tellTabs('out');
    } else {
      attempt(() => flags.set('gclone.note', `The sign-out did not reach the server, so this browser is still signed in: ${failure.message}`));
      // Still signed in — but no tab keeps the vault open after "Sign out".
      tellTabs('lock');
    }
    location.reload();
  }

  /** An event that may find the vault overdue: then it locks, and the event reaches nothing. */
  function check(event) {
    if (!unlocked) return false;
    if (!due(Date.now())) return false;
    if (event) event.stopImmediatePropagation();
    lock();
    return true;
  }

  function input(event) {
    if (!unlocked || check(event)) return;
    lastInput = Date.now();
  }

  // Registered before app.js exists, in the capture phase: the shell sees every event first.
  for (const type of ['pointerdown', 'keydown', 'touchstart', 'wheel']) {
    window.addEventListener(type, input, { capture: true, passive: true });
  }
  // A playing media element counts as use; in the background it holds the vault open, and
  // five minutes after it stops the rule applies.
  window.addEventListener('timeupdate', (event) => {
    if (!unlocked || check(event)) return;
    const now = Date.now();
    lastInput = now;
    if (hiddenAt !== null) hiddenAt = now;
  }, { capture: true });
  document.addEventListener('visibilitychange', (event) => {
    if (document.visibilityState === 'hidden') {
      if (unlocked && hiddenAt === null) hiddenAt = Date.now();
    } else if (!check(event)) {
      hiddenAt = null;
    }
  }, { capture: true });
  window.addEventListener('pageshow', (event) => {
    // A page out of the back/forward cache comes back as it was left — unlocked, or in the
    // middle of a step. Not here: it starts again, whatever the clock says.
    if (event.persisted) {
      event.stopImmediatePropagation();
      leaving = false;
      lock();
    } else {
      check(event);
    }
  }, { capture: true });
  window.addEventListener('focus', check, { capture: true });
  document.addEventListener('resume', check, { capture: true });
  setInterval(() => check(null), LOCK_CHECK);

  window.addEventListener('pagehide', () => {
    endKdf();
    // A tab that goes — closed, reloaded, or taken to another address — leaves neither a
    // ticket nor the token behind in the Service Worker. (Streams that are open finish.)
    if (unlocked) forgetInServiceWorker();
    // A page that leaves in the ordinary way was not killed in the middle of anything.
    flags.remove('gclone.kdf');
    flags.remove('gclone.load');
  });

  if (navigator.serviceWorker) {
    navigator.serviceWorker.addEventListener('message', (event) => {
      const data = event.data || {};
      // The Service Worker belongs to another build than this page: load that build. (It
      // names its build: a page that already runs it has nothing to do.)
      if (data.type === 'reload' && data.build !== BUILD && unlocked) lock('The viewer was updated. Unlock the vault again.');
      // The Service Worker could not read a file because the sign-in is over.
      else if (data.type === 'session-ended') sessionOver(data);
    });
    // Without its Service Worker the viewer reads no file: said on the passphrase screen,
    // not as a failure of every file that is opened.
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (unlocked && !navigator.serviceWorker.controller) lock(outElsewhere ? OUT_ELSEWHERE : NO_SERVICE_WORKER);
    });
  }

  // ---- start ----------------------------------------------------------------------------------

  async function boot() {
    // From here on the first screen's "did not start" line has nothing to say.
    work('Starting…');
    $('signin-address').textContent = `https://${location.host}/`;
    $('signin-address-rest').hidden = true;
    $('signin-go').addEventListener('click', beginSignIn);
    $('unlock-form').addEventListener('submit', unlock);
    $('unlock-out').addEventListener('click', signOut);
    $('stop-out').addEventListener('click', signOut);
    $('stop-reload').addEventListener('click', () => location.reload());
    $('out-again').addEventListener('click', () => showSignIn());
    killed = { kdf: flags.take('gclone.kdf'), load: flags.take('gclone.load') };

    if (flags.take('gclone.out') !== null) {
      history.replaceState(null, '', '/');
      show('out');
      return;
    }
    let arrived = null;
    if (location.pathname === '/callback') arrived = await finishSignIn();
    else if (location.search || location.hash) history.replaceState(history.state, '', '/');

    if (!('serviceWorker' in navigator)) {
      stop('This browser does not offer Service Workers to this page (a private window in Firefox does not). The viewer decrypts files in one and cannot work without it.', { title: 'Not in this browser', noReload: true, noSignOut: true });
      return;
    }
    try {
      await startServiceWorker();
    } catch (error) {
      stop(error.message);
      return;
    }
    if (arrived && arrived.problem) {
      showSignIn(arrived.problem);
      return;
    }
    work('Checking the sign-in…');
    try {
      await token.get(false);
    } catch (error) {
      if (error.code === 'no_session' || error.code === 'email_not_allowed' || error.code === 'invalid_grant') fail(error);
      else stop(error.message, { title: 'The sign-in service did not answer as expected' });
      return;
    }
    await findVault();
  }

  boot().catch((error) => stop((error && error.message) || String(error)));
})();
