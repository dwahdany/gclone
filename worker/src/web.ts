// The browser sign-in of the hosted viewer: Google's authorization-code flow with PKCE, through the "Web application"
// client. The page keeps the PKCE verifier and `state` in its tab; the Worker keeps nothing: the refresh token goes
// back to the browser sealed (seal.ts) in an HttpOnly cookie that only POST /web/refresh reads. No route hands a
// refresh token of this client out, and no other route accepts one.
//
// index.ts has already checked, for every route here: POST, the request's Origin, the rate limit and the configuration
// (neither for /web/logout) and the JSON body.

import {
  CODE_RE,
  REFRESH_TOKEN_RE,
  SCOPE_DRIVE_FILE,
  authorizationUrl,
  claimsFromGoogle,
  emailAllowed,
  excessScopes,
  exchangeCode,
  grantUnusable,
  idTokenClaims,
  refreshAccessToken,
  revokeToken,
  type Client,
} from "./google";
import type { Deps, Env } from "./index";
import { fail, googleFailure, json, notAllowed, scopeNotAllowed, type Reply } from "./reply";
import { b64urlDecode, b64urlEncode, loginNonce, openSession, pkceChallenge, sealSession } from "./seal";

export const WEB_COOKIE = "__Host-gclone-web";
/** How long the Worker honours a sealed session, counted from the sign-in and never extended: on a device the user
 *  did not mark as their own, and on one they did ("Stay signed in on this device"). */
export const WEB_SESSION_TTL_S = 12 * 3600;
export const WEB_SESSION_REMEMBER_TTL_S = 30 * 86400;

/** 32 bytes in base64url (RFC 7636 §4.2, S256). */
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
/** The page sends 16 random bytes (22 characters); anything of that alphabet up to 128 is passed on. */
const STATE_RE = /^[A-Za-z0-9_-]{22,128}$/;
/** RFC 7636 §4.1. */
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;
const COOKIE_ATTRS = "Path=/; Secure; HttpOnly; SameSite=Strict";
/** What every answer that ends a session carries. */
export const CLEAR_COOKIE = `${WEB_COOKIE}=; ${COOKIE_ATTRS}; Max-Age=0`;
const CLEAR = { "Set-Cookie": CLEAR_COOKIE };
const SIGN_IN_AGAIN = "sign in again";

/** The "Web application" client and the key of the session seal: what the four routes need to work. */
export interface WebConfig {
  client: Client;
  sealKey: Uint8Array;
}

export interface WebCtx {
  request: Request;
  /** `https://<host>`: the redirect URI is `<origin>/callback`. */
  origin: string;
  env: Env;
  deps: Deps;
  web: WebConfig;
}

/** Every /web route is called by the viewer's own page and by nothing else: `Origin` is this origin, and a browser
 *  that says where the request came from (`Sec-Fetch-Site`) says "same-origin". A request without `Origin` is refused. */
export function fromOwnPage(request: Request, origin: string): boolean {
  const site = request.headers.get("sec-fetch-site");
  return request.headers.get("origin") === origin && (site === null || site === "same-origin");
}

/** The value of the session cookie, or null when the request carries none.
 *  Pairs are split at `;` **and at `,`**: a browser sends one `Cookie` field per cookie over HTTP/2 and HTTP/3, and
 *  `Headers.get` joins several fields with ", ". Split at `;` alone, a second cookie on the host would hide the
 *  session (not found) or be glued to its value (the blob does not open, and the answer clears a good session).
 *  Neither character can be part of the blob, which is base64url. */
function sessionCookie(request: Request): string | null {
  for (const part of (request.headers.get("cookie") ?? "").split(/[;,]/)) {
    const at = part.indexOf("=");
    if (at > 0 && part.slice(0, at).trim() === WEB_COOKIE) return part.slice(at + 1).trim();
  }
  return null;
}

const nowS = (deps: Deps) => Math.floor(deps.now() / 1000);

// ---------- POST /web/start ----------

/** Formats the address at Google that the page then navigates to. Google is not contacted, nothing is remembered. */
export async function webStart({ origin, deps, web }: WebCtx, body: Record<string, unknown>): Promise<Reply> {
  const { challenge, state } = body;
  const bytes = typeof challenge === "string" && CHALLENGE_RE.test(challenge) ? b64urlDecode(challenge) : null;
  // The canonical spelling only: /web/token recomputes the challenge text from the verifier, and the nonce is derived
  // from that text.
  if (typeof challenge !== "string" || bytes === null || b64urlEncode(bytes) !== challenge || typeof state !== "string" || !STATE_RE.test(state)) {
    return fail(400, "invalid_request", "The request needs a well-formed challenge and state.");
  }
  return json(200, { authorization_url: authorizationUrl(web.client, deps, `${origin}/callback`, challenge, state, await loginNonce(challenge)) });
}

// ---------- POST /web/token ----------

export async function webToken({ origin, env, deps, web }: WebCtx, body: Record<string, unknown>): Promise<Reply> {
  const { code, verifier, remember } = body;
  if (typeof code !== "string" || !CODE_RE.test(code) || typeof verifier !== "string" || !VERIFIER_RE.test(verifier) || (remember !== undefined && typeof remember !== "boolean")) {
    return fail(400, "invalid_request", "The request needs a well-formed code and verifier.");
  }
  const exchanged = await exchangeCode(web.client, deps, `${origin}/callback`, code, verifier);
  if (!exchanged.ok) return googleFailure(exchanged);
  // From here on Google has consumed the code: whatever is refused below ends this sign-in for good.
  const tokens = exchanged.value;
  const claims = idTokenClaims(tokens.id_token);
  if (claims === null) return googleFailure(grantUnusable("the ID token in its answer could not be read", "sign-in code"));
  if (!claimsFromGoogle(web.client, claims)) {
    return googleFailure(grantUnusable("the ID token in its answer was not issued by Google for this Worker's web client", "sign-in code"));
  }
  // The Worker's own binding of Google's code to this tab's verifier: the code was issued for an address that
  // /web/start built for this verifier's challenge. No revoke: the grant belongs to whoever consented, and that may
  // be the owner.
  if (claims.nonce === undefined || claims.nonce !== (await loginNonce(await pkceChallenge(verifier)))) {
    return fail(400, "invalid_grant", "The sign-in code does not belong to this sign-in. Start again.");
  }
  if (!emailAllowed(env, claims)) {
    await revokeToken(deps, tokens.refresh_token); // leave no grant behind for a stranger's account
    return notAllowed(claims.email);
  }
  // Exactly the access /web/start asks for, or nothing (as /device/poll). The tokens are dropped, not revoked: a
  // revoke is grant-wide and would sign the owner's devices out.
  const excess = excessScopes(tokens.scope);
  if (excess.length > 0) return scopeNotAllowed(excess, SIGN_IN_AGAIN);
  if (!tokens.scope.split(" ").includes(SCOPE_DRIVE_FILE)) {
    return fail(403, "scope_missing", "Google did not grant access to Google Drive files; approve every permission on the consent screen.");
  }
  if (!REFRESH_TOKEN_RE.test(tokens.refresh_token)) {
    return googleFailure(grantUnusable("its refresh token has a form this Worker cannot keep", "sign-in code"));
  }
  const iat = nowS(deps);
  const ttl = remember === true ? WEB_SESSION_REMEMBER_TTL_S : WEB_SESSION_TTL_S;
  // emailAllowed has checked the address: verified, printable ASCII, at most 254 characters.
  const email = claims.email!;
  const sealed = await sealSession(web.sealKey, { iat, exp: iat + ttl, email, refreshToken: tokens.refresh_token });
  // "remember": a persistent cookie; otherwise one the browser drops with its session. The sealed expiry holds either way.
  const cookie = `${WEB_COOKIE}=${sealed}; ${COOKIE_ATTRS}${remember === true ? `; Max-Age=${ttl}` : ""}`;
  return json(200, { access_token: tokens.access_token, expires_in: tokens.expires_in, scope: tokens.scope, email, session_expires_in: ttl }, { "Set-Cookie": cookie });
}

// ---------- POST /web/refresh ----------

export async function webRefresh({ request, env, deps, web }: WebCtx): Promise<Reply> {
  const blob = sessionCookie(request);
  if (blob === null) return fail(401, "no_session", "Not signed in.");
  const now = nowS(deps);
  // Not a blob of this Worker's key, tampered with, or past its sealed expiry: Google is not asked.
  const session = await openSession(web.sealKey, blob, now);
  if (session === null) return fail(401, "no_session", "The sign-in has expired. Sign in again.", CLEAR);
  // The allowlist as it is now, not as it was at the sign-in — without depending on an ID token in Google's answer.
  if (!emailAllowed(env, { email: session.email, email_verified: true })) {
    await revokeToken(deps, session.refreshToken);
    return notAllowed(session.email, CLEAR);
  }
  const refreshed = await refreshAccessToken(web.client, deps, session.refreshToken);
  if (!refreshed.ok) {
    // Only Google's "this token is dead" ends the session; a failure of Google or of the Worker's client keeps the cookie.
    return googleFailure(refreshed, refreshed.error === "invalid_grant" ? CLEAR : {});
  }
  const { access_token, expires_in, scope, id_token } = refreshed.value;
  if (id_token !== undefined) {
    const claims = idTokenClaims(id_token);
    if (claims !== null && claimsFromGoogle(web.client, claims) && !emailAllowed(env, claims)) {
      await revokeToken(deps, session.refreshToken);
      return notAllowed(claims.email, CLEAR);
    }
  }
  const excess = excessScopes(scope);
  if (excess.length > 0) return scopeNotAllowed(excess, SIGN_IN_AGAIN);
  return json(200, { access_token, expires_in, scope, email: session.email, session_expires_in: session.exp - now });
}

// ---------- POST /web/logout ----------

/** Forgets the session in this browser: the cookie, and everything the origin stored. Needs no secret, so it works
 *  while the viewer is not configured. The grant at Google is not revoked (that would sign every device out).
 *  Not `"cookies"`: that directive clears the cookies of the whole registrable domain, other sites of the owner included. */
export function webLogout(): Reply {
  return json(200, {}, { ...CLEAR, "Clear-Site-Data": '"storage"' });
}
