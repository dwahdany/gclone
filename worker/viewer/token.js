// gclone viewer — access tokens. Runs in the page, the vault worker and the Service Worker.
//
// An access token (about an hour) comes from `POST /web/refresh`: the Worker opens the sealed
// session cookie, asks Google and answers the token. The cookie is HttpOnly; no script ever
// sees the refresh token. A token is kept in a variable of this context until 60 s before it
// runs out, never in storage and never in a URL. One request at a time (single flight).
'use strict';
(() => {
  const gclone = (self.gclone = self.gclone || {});
  const EARLY_MS = 60 * 1000;

  /** `code`: the Worker's error code (`no_session`, `email_not_allowed`, …), or `unreachable`. */
  class TokenError extends Error {
    constructor(code, message, status) {
      super(message);
      this.name = 'TokenError';
      this.code = code;
      this.status = status || 0;
    }
  }

  /** `options.fetch`, `options.now`: for the tests; a context uses its own. */
  function create(options) {
    const doFetch = (options && options.fetch) || ((url, init) => fetch(url, init));
    const now = (options && options.now) || (() => Date.now());
    let token = null;
    let expires = 0; // ms since the epoch
    let flight = null;
    const session = { email: null, expires: 0 };

    function take(body) {
      token = body.access_token;
      const seconds = Number(body.expires_in);
      expires = now() + (Number.isFinite(seconds) && seconds > 0 ? seconds : 0) * 1000;
      if (typeof body.email === 'string') session.email = body.email;
      const left = Number(body.session_expires_in);
      if (Number.isFinite(left)) session.expires = now() + left * 1000;
      return token;
    }

    /** One of the Worker's JSON routes; the answer of a `200`, else a `TokenError`. */
    async function post(path, payload) {
      let res;
      try {
        res = await doFetch(path, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload || {}),
          credentials: 'same-origin',
          cache: 'no-store',
        });
      } catch (_) {
        throw new TokenError('unreachable', 'The sign-in service does not answer. Check the connection and try again.');
      }
      let body = null;
      try { body = await res.json(); } catch (_) { /* not JSON: only the status counts */ }
      if (res.status === 200 && body && typeof body === 'object') return body;
      const code = body && typeof body.error === 'string' ? body.error : `http_${res.status}`;
      const message = body && typeof body.message === 'string' && body.message
        ? body.message : `The sign-in service answered with status ${res.status}.`;
      throw new TokenError(code, message, res.status);
    }

    async function refresh() {
      const body = await post('/web/refresh', {});
      if (typeof body.access_token !== 'string' || !body.access_token) {
        throw new TokenError('bad_answer', 'The sign-in service answered without a token.', 200);
      }
      return take(body);
    }

    return {
      /** A token that is good for at least a minute. `force`: the store refused the one in hand. */
      get(force) {
        if (!force && token && now() < expires - EARLY_MS) return Promise.resolve(token);
        if (!flight) {
          flight = refresh().finally(() => { flight = null; });
        }
        return flight;
      },
      /** A token another context obtained (`exp` in ms since the epoch). Never replaces a newer one. */
      seed(value, exp) {
        if (typeof value !== 'string' || !value || !(exp > expires)) return;
        token = value;
        expires = exp;
      },
      /** The answer of `/web/token` or `/web/refresh`, taken as this context's token. */
      take,
      /** `{ token, exp }` to hand to another context, or `null`. */
      peek() {
        return token && now() < expires - EARLY_MS ? { token, exp: expires } : null;
      },
      /** Who is signed in and until when, as the last answer said. */
      session() {
        return { email: session.email, expires: session.expires };
      },
      forget() {
        token = null;
        expires = 0;
      },
      post,
    };
  }

  gclone.TokenError = TokenError;
  gclone.createToken = create;
  gclone.token = create();
})();
