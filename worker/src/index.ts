// gclone's auth Worker: the OAuth clients of one person's gclone, and the only holder of their secrets. Stateless.
//   - A device logs in with Google's device authorization grant (RFC 8628): Google keeps the pending login, the device
//     carries its device code from /device/start to /device/poll, and /refresh turns its refresh token into access tokens.
//   - The hosted viewer's page signs in with the authorization-code flow and PKCE (web.ts): the browser keeps the
//     refresh token, sealed, in an HttpOnly cookie.
// Nothing is stored here. The viewer's static files (/a/<build>/*, /sw.js) are served by the asset layer and never
// reach this code (wrangler.jsonc, "assets").

import {
  DEVICE_CODE_RE,
  REFRESH_TOKEN_RE,
  SCOPE_DRIVE_FILE,
  claimsFromGoogle,
  configuredClients,
  emailAllowed,
  excessScopes,
  grantUnusable,
  idTokenClaims,
  pollDeviceCode,
  refreshAccessToken,
  requestDeviceCode,
  revokeToken,
  type Clients,
} from "./google";
import { homePage, privacyPage, viewerPage, type Status } from "./pages";
import { fail, googleFailure, json, notAllowed, scopeNotAllowed, type Reply } from "./reply";
import { decodeSealKey } from "./seal";
import { fromOwnPage, webLogout, webRefresh, webStart, webToken, type WebConfig, type WebCtx } from "./web";

/** The shape of a Workers rate-limit binding. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** The shape of the static-assets binding: read-only, part of the deployment. */
export interface AssetFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  /** The "TVs and Limited Input devices" client: every `gclone login`, and the refresh tokens those logins issue. */
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  /** Optional: the "Web application" client, the hosted viewer's sign-in (`/web/*`). The names date from the time this
   *  client served the browser sign-in of gclone before 0.2.0. No other route uses it: `/refresh` serves the device
   *  client only. */
  GOOGLE_LEGACY_CLIENT_ID?: string;
  GOOGLE_LEGACY_CLIENT_SECRET?: string;
  /** Optional: 32 random bytes in base64 (`openssl rand -base64 32`), the key of the viewer's session cookie. With the
   *  web client pair it switches the viewer's sign-in on; replacing it ends every browser session and no device login. */
  SEAL_KEY?: string;
  /** A secret; undefined (not yet put) = empty = nobody. */
  ALLOWED_EMAILS?: string;
  /** Absent in unit tests and outside Workers: then nothing is limited. */
  RATE_LIMIT?: RateLimiter;
  /** The viewer's files (`dist/`). The Worker reads `index.html` from it and nothing else. Absent: no viewer page. */
  ASSETS?: AssetFetcher;
}

export interface Deps {
  /** Every request to Google goes through this. */
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  /** The time in milliseconds: when a web session starts and when it has run out. */
  now: () => number;
  google: { deviceCodeUrl: string; tokenUrl: string; revokeUrl: string; authUrl: string };
}

export const GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code",
  GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token",
  GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke",
  GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";

/** The production wiring. `fetch` MUST be a wrapper: under workerd a bare `fetch` stored in an object is later called
 *  with `this = deps` and throws "TypeError: Illegal invocation" — every route that asks Google would answer 502. */
export const defaultDeps: Deps = {
  fetch: (input, init) => fetch(input, init),
  now: () => Date.now(),
  google: { deviceCodeUrl: GOOGLE_DEVICE_CODE_URL, tokenUrl: GOOGLE_TOKEN_URL, revokeUrl: GOOGLE_REVOKE_URL, authUrl: GOOGLE_AUTH_URL },
};

export const BODY_MAX = 8192,
  RATE_LIMIT_RETRY_AFTER_S = 60;

/** The only Service Worker this origin has: the viewer's, a static file that the asset layer serves. */
export const SERVICE_WORKER_PATH = "/sw.js";
/** What a request for any other Service Worker's script is answered with, besides its 404 (or whatever the path
 *  answers): the browser is told to drop this site's storage — which includes its Service Worker registrations — and
 *  its cache. Not `"cookies"`: that would clear the whole registrable domain (as in `/web/logout`). */
export const CLEAR_SITE_DATA = '"cache", "storage"';

/** Hosts that are served over plain http: development only. A network attacker cannot make a browser reach the
 *  deployed page under one of these names. */
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];
/** `index.html` of the assets binding. The host is never contacted; nothing of the request goes into this URL. */
const VIEWER_INDEX_URL = "https://assets.invalid/index.html";

/** What a device route works with once the configuration has been checked. */
interface Ctx {
  env: Env;
  deps: Deps;
  clients: Clients;
}

/** A route is one of:
 *  - `page`: an HTML page (GET; never limited, served without secrets);
 *  - `device`: a JSON route of the devices (POST; never a browser's request; rate-limited; refused while the device
 *    client's secrets are missing);
 *  - `web`: a JSON route of the viewer's own page (POST; same-origin only; rate-limited; refused while the viewer's
 *    three secrets are missing) — `logout` needs no secret, is never refused for a missing one and is not limited.
 *  Every error answer is JSON. */
type Route =
  | { page: "viewer" | "privacy" }
  | { device: (ctx: Ctx, body: Record<string, unknown>) => Promise<Reply> }
  | { web: (ctx: WebCtx, body: Record<string, unknown>) => Promise<Reply> }
  | { logout: true };

const ROUTES = new Map<string, Route>([
  ["/", { page: "viewer" }],
  // The redirect URI registered at Google. The same bytes as `/`: the page reads `code` and `state` from its own address.
  ["/callback", { page: "viewer" }],
  ["/privacy", { page: "privacy" }],
  ["/device/start", { device: deviceStart }],
  ["/device/poll", { device: devicePoll }],
  ["/refresh", { device: refresh }],
  ["/web/start", { web: webStart }],
  ["/web/token", { web: webToken }],
  ["/web/refresh", { web: webRefresh }],
  ["/web/logout", { logout: true }],
]);

/** The whole Worker. Pure in (request, env, deps): no globals, no storage. Never throws. */
export async function handle(request: Request, env: Env, deps: Deps): Promise<Response> {
  let path = "other";
  let reply: Reply;
  try {
    const url = new URL(request.url);
    const route = ROUTES.get(url.pathname);
    if (route !== undefined) path = url.pathname;
    reply = await dispatch(request, url, route, env, deps);
  } catch {
    reply = fail(500, "internal_error", "The sign-in helper failed unexpectedly.");
  }
  if (foreignServiceWorker(request)) reply.response.headers.set("Clear-Site-Data", CLEAR_SITE_DATA);
  // The only log line: never a body, a query string, a header, a cookie or a secret.
  console.log(JSON.stringify({ route: path, status: reply.response.status, error: reply.error }));
  return reply.response;
}

/** A browser fetching the script of a Service Worker that is not the viewer's: it installs or — far more likely —
 *  checks for an update of one that was registered while someone else served this origin (README.md, "After a change
 *  of hands"). The honest deployment registers `/sw.js` and nothing else, and that file never reaches this code.
 *  Browsers send `Service-Worker: script` with the request for a Service Worker's own script; Firefox sends it for
 *  the scripts that one imports as well, which `Sec-Fetch-Dest` tells apart (`script`, not `serviceworker`) — the
 *  viewer's Service Worker imports its files, and a file of a deployment that has not arrived yet must not clear
 *  anything. A request without `Sec-Fetch-Dest` is taken by the first header alone.
 *  What the answer achieves depends on the browser (measured, §17.27): Chrome drops the registration and the site's
 *  data; Firefox ignores `Clear-Site-Data` on this request; WebKit clears storage and keeps the registration. It is an
 *  aid, not the remedy — that is clearing the site's data by hand in every browser. */
function foreignServiceWorker(request: Request): boolean {
  if (request.headers.get("service-worker") !== "script") return false;
  const destination = request.headers.get("sec-fetch-dest");
  if (destination !== null && destination !== "serviceworker") return false;
  try {
    return new URL(request.url).pathname !== SERVICE_WORKER_PATH;
  } catch {
    return true;
  }
}

async function dispatch(request: Request, url: URL, route: Route | undefined, env: Env, deps: Deps): Promise<Reply> {
  // Before anything else: nothing is served over plain http. (The zone's "Always Use HTTPS" does the same one layer
  // earlier; this is for when it is off.)
  if (url.protocol !== "https:" && !LOOPBACK_HOSTS.includes(url.hostname)) return httpsOnly(request, url);
  if (route === undefined) return fail(404, "not_found", "There is nothing at this address.");
  const method = "page" in route ? "GET" : "POST";
  if (request.method !== method) {
    return fail(405, "method_not_allowed", `This address only answers ${method} requests.`, { Allow: method });
  }
  const clients = configuredClients(env);
  const web = viewerConfig(env, clients);
  if ("page" in route) {
    if (route.page === "privacy") return { response: privacyPage() };
    return { response: await viewer(env, clients === null ? "not_configured" : web === null ? "viewer_not_configured" : "ready") };
  }

  // What is refused below this line without being counted are requests that do no work — no secret is used, Google is
  // not asked — and that a web page somewhere else can send without anyone's permission (a "no-cors" POST). Counted,
  // any page open in the owner's browser could keep the budget of the owner's address used up: no access token for
  // the viewer, no refresh for the devices behind the same address, and a sign-out that never arrives.
  if ("device" in route) {
    // A device is the gclone command. It is never a web page, and a browser says of every request a page makes
    // where it came from.
    if (request.headers.has("origin") || request.headers.has("sec-fetch-site")) {
      return fail(403, "cross_origin", "This address answers the gclone command on a device, not a web page.");
    }
    if (await overLimit(request, env)) return rateLimited();
    if (clients === null) {
      return fail(500, "server_misconfigured", "This sign-in helper is not configured yet: its secrets are missing or incomplete.");
    }
    const body = await readJsonObject(request);
    return "reply" in body ? body.reply : route.device({ env, deps, clients }, body.json);
  }

  // The viewer's own page, and nothing else, calls these. No CORS header is ever answered.
  if (!fromOwnPage(request, url.origin)) {
    return fail(403, "cross_origin", "This address only answers the gclone viewer's own page.");
  }
  if ("web" in route) {
    if (await overLimit(request, env)) return rateLimited();
    if (web === null) {
      return fail(
        500,
        "server_misconfigured",
        "The web viewer's sign-in is not configured on this sign-in helper: it needs GOOGLE_LEGACY_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET and SEAL_KEY (32 random bytes in base64).",
      );
    }
  }
  // Sign-out is not limited: it uses no secret, asks nobody and answers a constant — and a sign-out that is turned
  // away leaves the session cookie in a browser its owner believes signed out.
  const body = await readJsonObject(request);
  if ("reply" in body) return body.reply;
  if ("web" in route) return route.web({ request, origin: url.origin, env, deps, web: web! }, body.json);
  return webLogout();
}

function rateLimited(): Reply {
  return fail(429, "rate_limited", "Too many requests from this address. Wait a minute, then try again.", {
    "Retry-After": String(RATE_LIMIT_RETRY_AFTER_S),
  });
}

/** `GET` and `HEAD` are sent to the same address under https. Anything else is refused and not redirected: a POST
 *  has sent its body in the clear already, and a redirect would only make the client do so again. (The session
 *  cookie is `Secure`: a browser does not send it here.) */
function httpsOnly(request: Request, url: URL): Reply {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return fail(400, "https_required", "This address is served over https only.");
  }
  const secure = new URL(url);
  secure.protocol = "https:";
  return { response: new Response(null, { status: 308, headers: { Location: secure.toString(), "Cache-Control": "no-store" } }) };
}

/** What the viewer's sign-in needs: the web client's pair and a SEAL_KEY of 32 bytes. Null: `/web/*` is switched off. */
function viewerConfig(env: Env, clients: Clients | null): WebConfig | null {
  if (clients === null || clients.web === null) return null;
  const sealKey = decodeSealKey(env.SEAL_KEY);
  return sealKey === null ? null : { client: clients.web, sealKey };
}

/** The page of `/` and `/callback`. */
async function viewer(env: Env, status: Status): Promise<Response> {
  if (env.ASSETS !== undefined) {
    try {
      const file = await env.ASSETS.fetch(new Request(VIEWER_INDEX_URL));
      if (file.status === 200) return viewerPage(await file.text(), status);
      await file.body?.cancel();
    } catch {
      // the home page below
    }
  }
  return homePage(status);
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

// ---------- POST /device/start ----------

/** Starts a login at Google and hands its answer to the device: the user code to show, the device code to poll with.
 *  Unauthenticated by nature — see README.md, "Device-code phishing". Nothing in the request is used. */
async function deviceStart({ deps, clients }: Ctx): Promise<Reply> {
  const started = await requestDeviceCode(clients.device, deps);
  return started.ok ? json(200, started.value) : googleFailure(started);
}

// ---------- POST /device/poll ----------

async function devicePoll({ env, deps, clients }: Ctx, body: Record<string, unknown>): Promise<Reply> {
  const deviceCode = body.device_code;
  if (typeof deviceCode !== "string" || !DEVICE_CODE_RE.test(deviceCode)) {
    return fail(400, "invalid_request", "The request needs a well-formed device_code.");
  }
  const polled = await pollDeviceCode(clients.device, deps, deviceCode);
  if (!polled.ok) return googleFailure(polled);
  // From here on Google has consumed the device code: whatever is refused below ends this login for good, and is
  // answered with a code the device does not poll again on (never 5xx).
  const tokens = polled.value;
  const claims = idTokenClaims(tokens.id_token);
  if (claims === null) return googleFailure(grantUnusable("the ID token in its answer could not be read"));
  if (!claimsFromGoogle(clients.device, claims)) {
    return googleFailure(grantUnusable("the ID token in its answer was not issued by Google for this Worker's OAuth client"));
  }
  if (!emailAllowed(env, claims)) {
    await revokeToken(deps, tokens.refresh_token); // leave no grant behind for a stranger's account
    return notAllowed(claims.email);
  }
  // Exactly the access /device/start asks for, or nothing: this client's secret must never turn into a refresh token for
  // more than gclone's own files (an older, wider grant of the same account to this project). The tokens are dropped,
  // not revoked (a revoke is grant-wide and would sign the owner's devices out).
  const excess = excessScopes(tokens.scope);
  if (excess.length > 0) return scopeNotAllowed(excess);
  if (!tokens.scope.split(" ").includes(SCOPE_DRIVE_FILE)) {
    return fail(403, "scope_missing", "Google did not grant access to Google Drive files; approve every permission on the consent screen.");
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

async function refresh({ env, deps, clients }: Ctx, body: Record<string, unknown>): Promise<Reply> {
  const refreshToken = body.refresh_token;
  if (typeof refreshToken !== "string" || !REFRESH_TOKEN_RE.test(refreshToken)) {
    return fail(400, "invalid_request", "The request needs a well-formed refresh_token.");
  }
  // Which client issued the token: a device that signed in through /device/poll says "device", and that is the only
  // client this route serves. One that says nothing signed in before gclone 0.2.0, through the Web application client
  // — whose refresh tokens are honoured in the viewer's sealed cookie only (/web/refresh): there they have an end, the
  // allowlist is applied on every use, and replacing SEAL_KEY cuts them all off. Google is not asked.
  if (body.client === undefined) {
    return fail(400, "invalid_grant", "This login was made with gclone's earlier browser sign-in, which this sign-in helper no longer serves. Run `gclone login` again.");
  }
  if (body.client !== "device") {
    return fail(400, "invalid_request", 'The "client" of a refresh request is "device".');
  }
  const client = clients.device;
  const refreshed = await refreshAccessToken(client, deps, refreshToken);
  if (!refreshed.ok) return googleFailure(refreshed);
  const { access_token, expires_in, scope, id_token } = refreshed.value;
  if (id_token !== undefined) {
    // Allowlist re-check: an address removed from ALLOWED_EMAILS is cut off at its next refresh.
    const claims = idTokenClaims(id_token);
    if (claims !== null && claimsFromGoogle(client, claims) && !emailAllowed(env, claims)) {
      await revokeToken(deps, refreshToken);
      return notAllowed(claims.email);
    }
  }
  // A refresh token with more than gclone's scopes (it cannot have come out of this Worker as it is now) gets no access token.
  const excess = excessScopes(scope);
  if (excess.length > 0) return scopeNotAllowed(excess);
  return json(200, { access_token, expires_in, scope });
}

// ---------- request bodies ----------

/** A POST body: `application/json`, at most BODY_MAX bytes, a JSON object. */
async function readJsonObject(request: Request): Promise<{ json: Record<string, unknown> } | { reply: Reply }> {
  const tooLarge = () => ({ reply: fail(413, "payload_too_large", `The request body is larger than ${BODY_MAX} bytes.`) });
  const invalid = () => ({ reply: fail(400, "invalid_request", "The request body must be a JSON object.") });

  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (mediaType !== "application/json") {
    return { reply: fail(415, "unsupported_media_type", "The request body must be application/json.") };
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
