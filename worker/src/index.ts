// gclone's auth Worker: the one OAuth client of one person's gclone devices.
// Stateless: a login is carried from /login to /callback (twice: Google's redirect, then the user's confirmation) to /token
// inside sealed blobs (seal.ts); nothing is stored.

import {
  CODE_RE,
  REFRESH_TOKEN_RE,
  SCOPE_DRIVE_FILE,
  authorizationUrl,
  claimsFromGoogle,
  emailAllowed,
  excessScopes,
  exchangeCode,
  idTokenClaims,
  refreshAccessToken,
  revokeToken,
  type GoogleResult,
} from "./google";
import { codePage, confirmPage, errorPage, finishPage, homePage, privacyPage } from "./pages";
import {
  b64urlDecode,
  b64urlEncode,
  checkCode,
  decodeSealKey,
  loginNonce,
  openGrant,
  openPending,
  openState,
  sealGrant,
  sealPending,
  sealState,
  sha256,
} from "./seal";

/** The shape of a Workers rate-limit binding. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  SEAL_KEY: string;
  /** A secret; undefined (not yet put) = empty = nobody. */
  ALLOWED_EMAILS?: string;
  /** Absent in unit tests and outside Workers: then nothing is limited. */
  RATE_LIMIT?: RateLimiter;
}

export interface Deps {
  /** Every request to Google goes through this. */
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  /** Milliseconds. */
  now: () => number;
  google: { authUrl: string; tokenUrl: string; revokeUrl: string };
}

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth",
  GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token",
  GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";

/** The production wiring. `fetch` and `now` MUST be wrappers: under workerd a bare `fetch` stored in an object is later
 *  called with `this = deps` and throws "TypeError: Illegal invocation" — every /token and /refresh would answer 502. */
export const defaultDeps: Deps = {
  fetch: (input, init) => fetch(input, init),
  now: () => Date.now(),
  google: { authUrl: GOOGLE_AUTH_URL, tokenUrl: GOOGLE_TOKEN_URL, revokeUrl: GOOGLE_REVOKE_URL },
};

export const STATE_TTL_S = 600,
  GRANT_TTL_S = 120,
  BODY_MAX = 8192,
  PASTE_PREFIX = "gclone-code1_",
  RATE_LIMIT_RETRY_AFTER_S = 60;

const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const PORT_RE = /^[1-9][0-9]{3,4}$/;
const DEVICE_STATE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;
const GRANT_TEXT_MAX = 1024;
const GOOGLE_ERROR_RE = /^[a-z_]{1,64}$/;
const INVALID_LINK = "This sign-in link is invalid or has expired. Run `gclone login` again.";

interface Route {
  method: "GET" | "POST";
  /** HTML routes answer errors with a page, the others with JSON. */
  html: boolean;
  /** Rate-limited, and refused while the Worker's secrets are missing. */
  guarded: boolean;
}

const ROUTES = new Map<string, Route>([
  ["/", { method: "GET", html: true, guarded: false }],
  ["/privacy", { method: "GET", html: true, guarded: false }],
  ["/login", { method: "GET", html: true, guarded: true }],
  ["/callback", { method: "GET", html: true, guarded: true }],
  ["/token", { method: "POST", html: false, guarded: true }],
  ["/refresh", { method: "POST", html: false, guarded: true }],
]);

/** An answer plus the error code that goes into the log line. */
interface Reply {
  response: Response;
  error?: string;
}

/** What a guarded route works with once the configuration has been checked. */
interface Ctx {
  url: URL;
  env: Env;
  deps: Deps;
  sealKey: Uint8Array;
  nowS: number;
}

/** The whole Worker. Pure in (request, env, deps): no globals, no storage. Never throws. */
export async function handle(request: Request, env: Env, deps: Deps): Promise<Response> {
  let path = "other";
  let html = false;
  let reply: Reply;
  try {
    const url = new URL(request.url);
    const route = ROUTES.get(url.pathname);
    if (route !== undefined) {
      path = url.pathname;
      html = route.html;
    }
    reply = await dispatch(request, url, route, env, deps);
  } catch {
    reply = fail(html, 500, "internal_error", "The sign-in helper failed unexpectedly.");
  }
  // The only log line: never a body, a query string, a header or a secret.
  console.log(JSON.stringify({ route: path, status: reply.response.status, error: reply.error }));
  return reply.response;
}

export default { fetch: (request: Request, env: Env) => handle(request, env, defaultDeps) } satisfies ExportedHandler<Env>;

async function dispatch(request: Request, url: URL, route: Route | undefined, env: Env, deps: Deps): Promise<Reply> {
  if (route === undefined) return fail(false, 404, "not_found", "There is nothing at this address.");
  if (request.method !== route.method) {
    return fail(route.html, 405, "method_not_allowed", `This address only answers ${route.method} requests.`, { Allow: route.method });
  }
  const sealKey = configuredSealKey(env);
  if (!route.guarded) return { response: url.pathname === "/" ? homePage(sealKey !== null) : privacyPage() };

  if (await overLimit(request, env)) {
    return fail(route.html, 429, "rate_limited", "Too many requests from this address. Wait a minute, then try again.", {
      "Retry-After": String(RATE_LIMIT_RETRY_AFTER_S),
    });
  }
  if (sealKey === null) {
    return fail(route.html, 500, "server_misconfigured", "This sign-in helper is not configured yet: its secrets are missing or malformed.");
  }
  const ctx: Ctx = { url, env, deps, sealKey, nowS: Math.floor(deps.now() / 1000) };
  if (url.pathname === "/login") return login(ctx);
  if (url.pathname === "/callback") return callback(ctx);

  const body = await readJsonObject(request);
  if ("reply" in body) return body.reply;
  return url.pathname === "/token" ? token(ctx, body.json) : refresh(ctx, body.json);
}

/** The decoded SEAL_KEY when all three required secrets are usable, else null. */
function configuredSealKey(env: Env): Uint8Array | null {
  const present = (v: unknown) => typeof v === "string" && v !== "";
  if (!present(env.GOOGLE_CLIENT_ID) || !present(env.GOOGLE_CLIENT_SECRET) || !present(env.SEAL_KEY)) return null;
  return decodeSealKey(env.SEAL_KEY);
}

async function overLimit(request: Request, env: Env): Promise<boolean> {
  if (env.RATE_LIMIT === undefined) return false;
  try {
    const { success } = await env.RATE_LIMIT.limit({ key: rateLimitKey(request.headers.get("cf-connecting-ip")) });
    return !success;
  } catch {
    return false; // a failing limiter must not lock the owner out
  }
}

/** The rate-limit key of a client address (the `cf-connecting-ip` value): an IPv4 address as it is, an IPv6 address as its
 *  /64 prefix — one IPv6 host owns at least a whole /64, so a per-address key would give it 2^64 budgets. */
export function rateLimitKey(address: string | null): string {
  if (address === null || address === "") return "unknown";
  const groups = ipv6Groups(address);
  if (groups === null) return address; // IPv4, or nothing this code understands: the value itself
  // An IPv4-mapped address (::ffff:a.b.c.d) is that IPv4 address.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return `${groups[6]! >> 8}.${groups[6]! & 255}.${groups[7]! >> 8}.${groups[7]! & 255}`;
  }
  return `${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(":")}::/64`;
}

/** The eight 16-bit groups of an IPv6 address in any textual form (RFC 4291 §2.2), or null when `text` is not one. */
function ipv6Groups(text: string): number[] | null {
  let address = text.split("%")[0]!; // a zone index is not part of the address
  if (!address.includes(":")) return null;
  const tail: number[] = [];
  const lastColon = address.lastIndexOf(":");
  if (address.includes(".")) {
    // a dotted IPv4 tail stands for the last two groups
    const dotted = address.slice(lastColon + 1).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (dotted === null) return null;
    const bytes = dotted.slice(1).map(Number);
    if (bytes.some((b) => b > 255)) return null;
    tail.push((bytes[0]! << 8) | bytes[1]!, (bytes[2]! << 8) | bytes[3]!);
    // keep the colon in front of the tail so that "::1.2.3.4" still ends in "::"
    address = address.slice(0, lastColon + 1);
    address = address.endsWith("::") ? address : address.slice(0, -1);
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const group of part.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      out.push(parseInt(group, 16));
    }
    return out;
  };
  const head = parse(halves[0]!);
  const rest = halves.length === 2 ? parse(halves[1]!) : [];
  if (head === null || rest === null) return null;
  const given = head.length + rest.length + tail.length;
  if (halves.length === 1 ? given !== 8 : given > 7) return null;
  return [...head, ...new Array<number>(8 - given).fill(0), ...rest, ...tail];
}

// ---------- GET /login ----------

async function login({ url, env, deps, sealKey, nowS }: Ctx): Promise<Reply> {
  const q = url.searchParams;
  const challenge = q.get("challenge") ?? "";
  const challengeBytes = CHALLENGE_RE.test(challenge) ? b64urlDecode(challenge) : null;
  // The canonical spelling only: /token recomputes the challenge text from the verifier, and the nonce is derived from that text.
  if (challengeBytes === null || b64urlEncode(challengeBytes) !== challenge) {
    return fail(true, 400, "invalid_request", "This sign-in link is malformed. Run `gclone login` again.");
  }
  const loopback = q.has("port");
  let port = 0;
  let deviceState = "";
  if (loopback) {
    const portText = q.get("port") ?? "";
    port = PORT_RE.test(portText) ? Number(portText) : 0;
    deviceState = q.get("state") ?? "";
    if (port < 1024 || port > 65535 || !DEVICE_STATE_RE.test(deviceState)) {
      return fail(true, 400, "invalid_request", "This sign-in link is malformed. Run `gclone login` again.");
    }
  }
  const state = await sealState(sealKey, { exp: nowS + STATE_TTL_S, port, challenge: challengeBytes, deviceState });
  const google = authorizationUrl(env, deps, callbackUrl(url), challenge, state, await loginNonce(challenge));
  // Never a redirect: the user sees the check code before Google's consent screen. (A courtesy — the link can be lifted
  // from this page and sent to someone else; the confirmation that cannot be skipped is the one /callback shows.)
  return { response: confirmPage(await checkCode(challenge), google, loopback) };
}

// ---------- GET /callback ----------

/** Two visits per login. Google's redirect (`state` + `code` | `error`) is answered with the confirmation page — never with a
 *  grant: `/login` is unauthenticated and its link to Google can be sent to anyone, so the check code the user has to compare
 *  is shown here, where every consent ends up. Only that page's link (`confirmed`) releases the grant to the device. */
async function callback({ url, sealKey, nowS }: Ctx): Promise<Reply> {
  const q = url.searchParams;

  // The one redirect target the Worker has: the literal loopback host with the port from an authenticated blob.
  const toDevice = (to: { port: number; deviceState: string }, param: "code" | "error", value: string): Reply => ({
    response: new Response(null, {
      status: 302,
      headers: {
        Location: `http://127.0.0.1:${to.port}/?${param}=${value}&state=${to.deviceState}`,
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
      },
    }),
    ...(param === "error" ? { error: "access_denied" } : {}),
  });

  // Second visit: the user compared the check code and followed the confirmation page's link.
  const confirmed = q.get("confirmed");
  if (confirmed !== null) {
    const pending = await openPending(sealKey, confirmed, nowS);
    if (pending === null) return fail(true, 400, "invalid_request", INVALID_LINK);
    // The grant keeps the pending blob's expiry: Google's code is redeemed at most GRANT_TTL after the confirmation page was served.
    const grant = await sealGrant(sealKey, pending.challenge, pending.exp, pending.googleCode);
    if (pending.port !== 0) return toDevice(pending, "code", grant);
    return { response: codePage(PASTE_PREFIX + grant) };
  }

  // First visit: Google's redirect.
  const state = await openState(sealKey, q.get("state") ?? "", nowS);
  if (state === null) return fail(true, 400, "invalid_request", INVALID_LINK);

  const googleError = q.get("error");
  if (googleError !== null) {
    const reason = GOOGLE_ERROR_RE.test(googleError) ? googleError : "error";
    if (state.port !== 0) return toDevice(state, "error", reason);
    return { response: errorPage(200, `Google did not grant access (${reason}).`), error: "access_denied" };
  }
  const code = q.get("code") ?? "";
  if (!CODE_RE.test(code)) return fail(true, 400, "invalid_request", INVALID_LINK);

  // No request to Google here, and no grant yet: its code is sealed, with everything the second visit needs, into the
  // confirmation page's link. Whoever was sent straight to Google's consent screen sees the check code here for the first time.
  const pending = await sealPending(sealKey, { ...state, exp: nowS + GRANT_TTL_S, googleCode: code });
  return { response: finishPage(await checkCode(b64urlEncode(state.challenge)), `/callback?confirmed=${pending}`, state.port !== 0) };
}

// ---------- POST /token ----------

async function token({ url, env, deps, sealKey, nowS }: Ctx, body: Record<string, unknown>): Promise<Reply> {
  const { code, verifier } = body;
  if (typeof code !== "string" || code.length > GRANT_TEXT_MAX || typeof verifier !== "string" || !VERIFIER_RE.test(verifier)) {
    return fail(false, 400, "invalid_request", "The request needs a code and a verifier.");
  }
  const challengeBytes = await sha256(new TextEncoder().encode(verifier));
  const googleCode = await openGrant(sealKey, code, challengeBytes, nowS);
  if (googleCode === null) return invalidGrant();

  const exchanged = await exchangeCode(env, deps, callbackUrl(url), googleCode, verifier);
  if (!exchanged.ok) return googleFailure(exchanged);
  const tokens = exchanged.value;
  const claims = idTokenClaims(tokens.id_token);
  if (claims === null || !claimsFromGoogle(env, claims)) {
    return fail(false, 502, "upstream_error", "Google's answer did not identify the account.");
  }
  // The Worker's own binding of Google's code to this device: the code must have been issued for the login that carried
  // this device's challenge. No revoke — the grant belongs to whoever consented, possibly the owner.
  if (claims.nonce !== (await loginNonce(b64urlEncode(challengeBytes)))) return invalidGrant();
  if (!emailAllowed(env, claims)) {
    await revokeToken(deps, tokens.refresh_token); // leave no grant behind for a stranger's account
    return notAllowed(claims.email);
  }
  // Exactly the access /login asks for, or nothing: a tampered authorization URL (another `scope`, `include_granted_scopes`)
  // must not turn this client's secret into a refresh token for the whole Drive. The tokens are dropped, not revoked
  // (a revoke is grant-wide and would sign the owner's devices out).
  const excess = excessScopes(tokens.scope);
  if (excess.length > 0) return scopeNotAllowed(excess);
  if (!tokens.scope.split(" ").includes(SCOPE_DRIVE_FILE)) {
    return fail(false, 403, "scope_missing", "Google did not grant access to Google Drive files; approve every permission on the consent screen.");
  }
  return json(200, {
    refresh_token: tokens.refresh_token,
    access_token: tokens.access_token,
    expires_in: tokens.expires_in,
    scope: tokens.scope,
    email: claims.email,
    ...(tokens.refresh_token_expires_in !== undefined ? { refresh_token_expires_in: tokens.refresh_token_expires_in } : {}),
  });
}

// ---------- POST /refresh ----------

async function refresh({ env, deps }: Ctx, body: Record<string, unknown>): Promise<Reply> {
  const refreshToken = body.refresh_token;
  if (typeof refreshToken !== "string" || !REFRESH_TOKEN_RE.test(refreshToken)) {
    return fail(false, 400, "invalid_request", "The request needs a well-formed refresh_token.");
  }
  const refreshed = await refreshAccessToken(env, deps, refreshToken);
  if (!refreshed.ok) return googleFailure(refreshed);
  const { access_token, expires_in, scope, id_token } = refreshed.value;
  if (id_token !== undefined) {
    // Allowlist re-check: an address removed from ALLOWED_EMAILS is cut off at its next refresh.
    const claims = idTokenClaims(id_token);
    if (claims !== null && claimsFromGoogle(env, claims) && !emailAllowed(env, claims)) {
      await revokeToken(deps, refreshToken);
      return notAllowed(claims.email);
    }
  }
  // A refresh token with more than gclone's scopes (it cannot have come out of /token as it is now) gets no access token.
  const excess = excessScopes(scope);
  if (excess.length > 0) return scopeNotAllowed(excess);
  return json(200, { access_token, expires_in, scope });
}

// ---------- answers ----------

function callbackUrl(url: URL): string {
  return `${url.origin}/callback`;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Reply {
  return {
    response: new Response(JSON.stringify(body), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        ...headers,
      },
    }),
  };
}

function fail(html: boolean, status: number, error: string, message: string, headers: Record<string, string> = {}): Reply {
  if (!html) return { ...json(status, { error, message }, headers), error };
  const response = errorPage(status, message);
  for (const [name, value] of Object.entries(headers)) response.headers.set(name, value);
  return { response, error };
}

function invalidGrant(): Reply {
  return fail(false, 400, "invalid_grant", "The sign-in code is invalid, expired or already used.");
}

function notAllowed(email: string | undefined): Reply {
  const who = email === undefined ? "This Google account" : `The Google account ${email.slice(0, 254)}`;
  return fail(false, 403, "email_not_allowed", `${who} is not allowed to sign in here.`);
}

function scopeNotAllowed(excess: string[]): Reply {
  // Scope names are not secrets, but they are Google's text: only plain ones are echoed, and only a few. They come last,
  // so a client that shortens the message keeps the remedy.
  const named = excess.filter((entry) => /^[A-Za-z0-9:\/._-]{1,100}$/.test(entry)).slice(0, 3);
  const what = named.length > 0 ? ` Not asked for: ${named.join(", ")}${named.length < excess.length ? ", ..." : ""}` : "";
  return fail(
    false,
    403,
    "scope_not_allowed",
    `Google granted more access than gclone asks for, so nothing was handed out. If you did not expect this, remove gclone at https://myaccount.google.com/permissions; then run \`gclone login\` again.${what}`,
  );
}

function googleFailure(r: Exclude<GoogleResult<unknown>, { ok: true }>): Reply {
  return fail(false, r.status, r.error, r.message);
}

// ---------- request bodies ----------

/** A POST body: `application/json`, at most BODY_MAX bytes, a JSON object. */
async function readJsonObject(request: Request): Promise<{ json: Record<string, unknown> } | { reply: Reply }> {
  const tooLarge = () => ({ reply: fail(false, 413, "payload_too_large", `The request body is larger than ${BODY_MAX} bytes.`) });
  const invalid = () => ({ reply: fail(false, 400, "invalid_request", "The request body must be a JSON object.") });

  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (mediaType !== "application/json") {
    return { reply: fail(false, 415, "unsupported_media_type", "The request body must be application/json.") };
  }
  const declared = request.headers.get("content-length");
  if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > BODY_MAX) return tooLarge();
  try {
    const bytes = await readCapped(request, BODY_MAX);
    if (bytes === null) return tooLarge();
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return invalid();
    return { json: parsed as Record<string, unknown> };
  } catch {
    return invalid(); // unreadable body, invalid UTF-8 or invalid JSON
  }
}

/** The body, or null as soon as it exceeds `max` bytes — a body without Content-Length is never buffered beyond that. */
async function readCapped(request: Request, max: number): Promise<Uint8Array | null> {
  if (request.body === null) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}
