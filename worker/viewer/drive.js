// gclone viewer — Google Drive, read-only. Runs in the vault worker and the Service Worker.
//
// Three calls: list (`files.list`), metadata (`files.get`) and content (`files.get?alt=media`,
// whole or a byte range). Everything read here is ciphertext or an unauthenticated listing;
// the callers bound what a listing can make them download. Errors follow the CLI's rules
// (SPEC §6.5): 401 → one fresh token, one retry; 429 and Drive's rate-limit 403s → backoff;
// 5xx and connection errors → backoff; 404 → "not found" (the caller looks a blob up by name);
// a 403 that says "Abusive" on a download → once more with `acknowledgeAbuse=true`.
//
// How long a request keeps trying is the caller's choice (`patience`): the index load follows
// the CLI's schedule (six attempts, up to half a minute of pauses); a read that someone is
// looking at — a file, a refresh — gives up after about ten seconds and says why. A failed
// request in a browser that reports itself offline is not tried again at all.
//
// Requests use the default cache mode on purpose: `no-store` makes Chrome repeat the CORS
// preflight for every request.
'use strict';
(() => {
  const gclone = (self.gclone = self.gclone || {});
  // The one place the Drive host is named. `connect-src` of the page's policy allows it.
  const ORIGIN = 'https://www.googleapis.com';
  const FILES = `${ORIGIN}/drive/v3/files`;
  const FOLDER = 'application/vnd.google-apps.folder';
  const PAGE_SIZE = '1000';
  const LIST_FIELDS = 'nextPageToken,files(id,name,size,createdTime,mimeType,parents)';
  const META_FIELDS = 'id,name,size,createdTime,mimeType,parents,trashed';
  const ATTEMPTS = 6; // of one request, throttled or failing
  const LIST_RESTARTS = 2; // of a listing whose page token was refused
  const BACKOFF_MAX_MS = 32000;

  /** `kind`: not-found | too-large | auth | rate | unreachable | quota | fatal. */
  class DriveError extends Error {
    constructor(kind, message, status) {
      super(message);
      this.name = 'DriveError';
      this.kind = kind;
      this.status = status || 0;
    }
  }

  const qEscape = (text) => String(text).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  // Ids are URL-safe as issued; anything else is escaped rather than trusted.
  const segment = (id) => encodeURIComponent(String(id));

  /** What an error answer says: `{ reasons, message, status }` (empty for a body that is not Drive's JSON). */
  async function explain(res) {
    const out = { reasons: [], message: '', status: '' };
    try {
      const error = (await res.json()).error;
      if (error && typeof error === 'object') {
        if (typeof error.message === 'string') out.message = error.message;
        if (typeof error.status === 'string') out.status = error.status;
        if (Array.isArray(error.errors)) {
          out.reasons = error.errors.map((e) => e && e.reason).filter((r) => typeof r === 'string');
        }
      }
    } catch (_) { /* a front end's HTML or nothing: only the status counts */ }
    return out;
  }

  /** `backend/drive/errors.rs`, the rows a reader can meet, in its order. */
  function classify(status, info) {
    const has = (reason) => info.reasons.includes(reason);
    const mentions = (needle) => info.message.includes(needle) || info.reasons.some((r) => r.includes(needle));
    if (status === 401) return 'unauthorized';
    if (status === 404) return 'not-found';
    if (status === 403 && mentions('downloadQuota')) return 'download-quota';
    if (status === 403 && has('dailyLimitExceeded')) return 'project-quota';
    if (status === 403 && has('appNotAuthorizedToFile')) return 'not-authorized';
    if (status === 403 && mentions('Abusive')) return 'abuse';
    if (status === 429) return 'throttle';
    if (status === 403 && (has('rateLimitExceeded') || has('userRateLimitExceeded') || info.status === 'RESOURCE_EXHAUSTED')) return 'throttle';
    if (status === 403 && /rate limit|quota/i.test(info.message)) return 'throttle';
    if (status === 500 || status === 502 || status === 503 || status === 504) return 'transient';
    return 'fatal';
  }

  function retryAfterMs(res) {
    const seconds = Number(res.headers.get('retry-after'));
    return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, 64000) : 0;
  }

  const UNREACHABLE = 'Google Drive does not answer. Check the connection and try again.';
  const OFFLINE = 'This browser is offline: Google Drive cannot be reached. Check the connection and try again.';

  /**
   * `token`: `{ get(force) }` (token.js). `patience`: the milliseconds one request may spend
   * pausing between its attempts (default: no bound but the number of attempts); changed
   * later with `patience(ms)`. The rest is for the tests: `fetch`, `sleep(ms)`, `random()`,
   * `offline()`.
   */
  function create(options) {
    const token = options.token;
    const doFetch = options.fetch || ((url, init) => fetch(url, init));
    const sleep = options.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    const random = options.random || Math.random;
    // "Offline" is the one thing a browser knows for certain about its connection.
    const offline = options.offline || (() => typeof navigator !== 'undefined' && navigator.onLine === false);
    let patience = options.patience > 0 ? options.patience : Infinity;
    const backoff = (attempt) => Math.min(BACKOFF_MAX_MS, 1000 * 2 ** attempt + Math.floor(random() * 1000));

    /** One request, with the retries above. Returns a response whose status is 200 or 206. */
    async function call(url, init, media) {
      let refreshed = false;
      let acknowledged = false;
      let wait = 0; // attempts that ended in a pause
      let paused = 0; // milliseconds of those pauses
      /** Pauses before the next attempt — or gives up with `error()` when that is past the attempts or the patience. */
      const pause = async (ms, error) => {
        wait += 1;
        if (wait >= ATTEMPTS || paused + ms > patience) throw error();
        paused += ms;
        await sleep(ms);
      };
      for (;;) {
        const bearer = await token.get(false);
        let res;
        try {
          res = await doFetch(acknowledged ? `${url}&acknowledgeAbuse=true` : url, {
            ...init,
            headers: { ...(init && init.headers), Authorization: `Bearer ${bearer}` },
          });
        } catch (error) {
          if (init && init.signal && init.signal.aborted) throw error;
          if (offline()) throw new DriveError('unreachable', OFFLINE);
          await pause(backoff(wait), () => new DriveError('unreachable', UNREACHABLE));
          continue;
        }
        if (res.status === 200 || res.status === 206) return res;
        const info = await explain(res);
        const what = classify(res.status, info);
        const said = info.message ? `: ${info.message}` : '';
        if (what === 'unauthorized') {
          if (refreshed) throw new DriveError('auth', 'Google no longer accepts this sign-in. Sign out and sign in again.', 401);
          refreshed = true;
          await token.get(true);
        } else if (what === 'abuse' && media && !acknowledged) {
          acknowledged = true;
        } else if (what === 'throttle' || what === 'transient') {
          await pause(Math.max(retryAfterMs(res), backoff(wait)), () => (what === 'throttle'
            ? new DriveError('rate', 'Google Drive is limiting requests. Try again in a few minutes.', res.status)
            : new DriveError('unreachable', `Google Drive keeps failing (status ${res.status}). Try again later.`, res.status)));
        } else if (what === 'not-found') {
          throw new DriveError('not-found', 'Google Drive has no such object.', 404);
        } else if (what === 'download-quota') {
          throw new DriveError('quota', "Google's download quota for today is used up. Try again tomorrow.", 403);
        } else if (what === 'project-quota') {
          throw new DriveError('quota', 'The API quota of the Google Cloud project is used up.', 403);
        } else if (what === 'not-authorized') {
          throw new DriveError('fatal', 'This sign-in may not read the vault: it was not created through this sign-in.', 403);
        } else {
          throw new DriveError('fatal', `Google Drive refused the request (status ${res.status})${said}`, res.status);
        }
      }
    }

    /** Every object a query matches: all pages, `pageSize=1000`. A 404 (the folder is gone) is an empty listing. */
    async function list(q) {
      let restarts = 0;
      listing: for (;;) {
        const files = [];
        let pageToken = '';
        for (;;) {
          const query = new URLSearchParams({ q, pageSize: PAGE_SIZE, spaces: 'drive', fields: LIST_FIELDS });
          if (pageToken) query.set('pageToken', pageToken);
          let page;
          try {
            page = await (await call(`${FILES}?${query}`)).json();
          } catch (error) {
            if (error instanceof DriveError && error.kind === 'not-found') return [];
            if (error instanceof DriveError && error.status === 400 && pageToken && restarts < LIST_RESTARTS) {
              restarts += 1;
              continue listing;
            }
            throw error;
          }
          for (const file of Array.isArray(page.files) ? page.files : []) {
            if (file && typeof file.id === 'string' && typeof file.name === 'string') files.push(shape(file));
          }
          if (typeof page.nextPageToken === 'string' && page.nextPageToken) pageToken = page.nextPageToken;
          else return files;
        }
      }
    }

    /** `{ id, name, size, createdTime, folder, parent }` — `size` 0 where Drive gives none. */
    function shape(file) {
      const size = Number(file.size);
      return {
        id: file.id,
        name: file.name,
        size: Number.isSafeInteger(size) && size >= 0 ? size : 0,
        createdTime: typeof file.createdTime === 'string' ? file.createdTime : '',
        folder: file.mimeType === FOLDER,
        parent: Array.isArray(file.parents) && typeof file.parents[0] === 'string' ? file.parents[0] : '',
      };
    }

    return {
      list,
      /** From now on a request pauses at most `ms` in all between its attempts (`Infinity`: the attempts alone decide). */
      patience(ms) {
        patience = ms > 0 ? ms : Infinity;
      },
      /** The objects in a folder that are not in the trash. */
      children: (id) => list(`'${qEscape(id)}' in parents and trashed = false`),
      /** The objects of exactly this name, anywhere this sign-in can see. */
      async named(name) {
        // Whatever Drive's `name =` matches, the contract is byte-exact.
        return (await list(`name = '${qEscape(name)}' and trashed = false`)).filter((file) => file.name === name);
      },
      /** One object's metadata; throws `not-found`. */
      async meta(id) {
        const file = await (await call(`${FILES}/${segment(id)}?fields=${encodeURIComponent(META_FIELDS)}`)).json();
        if (!file || typeof file.id !== 'string' || typeof file.name !== 'string') {
          throw new DriveError('fatal', 'Google Drive answered with something that is not an object.', 200);
        }
        return { ...shape(file), trashed: file.trashed === true };
      },
      /**
       * An object's bytes, at most `max`: the body is counted while it arrives and the request is
       * given up when it passes `max` (`too-large`) — a listed size is only the store's claim.
       * `progress(bytes)` is called with each piece's length.
       */
      async get(id, max, progress) {
        const abort = new AbortController();
        const res = await call(`${FILES}/${segment(id)}?alt=media`, { signal: abort.signal }, true);
        const declared = Number(res.headers.get('content-length'));
        if (Number.isFinite(declared) && declared > max) {
          abort.abort();
          throw new DriveError('too-large', `The object is larger than the ${max} bytes it may have.`);
        }
        const reader = res.body.getReader();
        const pieces = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > max) {
            abort.abort();
            throw new DriveError('too-large', `The object is larger than the ${max} bytes it may have.`);
          }
          pieces.push(value);
          if (progress) progress(value.length);
        }
        if (pieces.length === 1) return pieces[0];
        const out = new Uint8Array(total);
        let at = 0;
        for (const piece of pieces) {
          out.set(piece, at);
          at += piece.length;
        }
        return out;
      },
      /** The bytes `[start, end)` of an object as a streaming response (`206`). */
      async getRange(id, start, end, signal) {
        const res = await call(`${FILES}/${segment(id)}?alt=media`, { headers: { Range: `bytes=${start}-${end - 1}` }, signal }, true);
        if (res.status !== 206) {
          try { await res.body.cancel(); } catch (_) { /* nothing to cancel */ }
          throw new DriveError('fatal', 'Google Drive ignored the byte range of a download.', res.status);
        }
        return res;
      },
    };
  }

  gclone.DriveError = DriveError;
  gclone.createDrive = create;
})();
