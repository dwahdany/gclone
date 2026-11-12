// gclone's auth Worker: the OAuth clients of one person's gclone devices, and the only holder of their secrets.
// Stateless: a login is Google's device authorization grant (RFC 8628) — Google keeps the pending login, the device
// carries its device code from /device/start to /device/poll, and nothing is stored here.

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
  maskedEmail,
  pollDeviceCode,
  refreshAccessToken,
  requestDeviceCode,
  revokeToken,
  type Clients,
  type GoogleFailure,
} from "./google";
import { homePage, privacyPage, type Status } from "./pages";

/** The shape of a Workers rate-limit binding. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  /** The "TVs and Limited Input devices" client: every login, and the refresh tokens those logins issue. */
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  /** Optional: the "Web application" client of the browser sign-in before gclone 0.2.0. Only /refresh uses it, for
   *  refresh tokens that client issued, and only when both are set; delete both once every device has run
   *  `gclone login` again. */
  GOOGLE_LEGACY_CLIENT_ID?: string;
  GOOGLE_LEGACY_CLIENT_SECRET?: string;
  /** A secret; undefined (not yet put) = empty = nobody. */
  ALLOWED_EMAILS?: string;
  /** Absent in unit tests and outside Workers: then nothing is limited. */
  RATE_LIMIT?: RateLimiter;
}

export interface Deps {
  /** Every request to Google goes through this. */
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  google: { deviceCodeUrl: string; tokenUrl: string; revokeUrl: string };
}

export const GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code",
  GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token",
  GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";

/** The production wiring. `fetch` MUST be a wrapper: under workerd a bare `fetch` stored in an object is later called
 *  with `this = deps` and throws "TypeError: Illegal invocation" — every route that asks Google would answer 502. */
export const defaultDeps: Deps = {
  fetch: (input, init) => fetch(input, init),
  google: { deviceCodeUrl: GOOGLE_DEVICE_CODE_URL, tokenUrl: GOOGLE_TOKEN_URL, revokeUrl: GOOGLE_REVOKE_URL },
};

export const BODY_MAX = 8192,
  RATE_LIMIT_RETRY_AFTER_S = 60;

/** What a JSON route works with once the configuration has been checked. */
interface Ctx {
  env: Env;
  deps: Deps;
  clients: Clients;
}

/** A route is either one of the two HTML pages (GET; never limited, served without secrets) or a JSON route (POST;
 *  rate-limited, refused while the Worker's secrets are missing). Every error answer is JSON. */
type Route = { page: (status: Status) => Response } | { post: (ctx: Ctx, body: Record<string, unknown>) => Promise<Reply> };

const ROUTES = new Map<string, Route>([
  ["/", { page: homePage }],
  ["/privacy", { page: privacyPage }],
  ["/device/start", { post: deviceStart }],
  ["/device/poll", { post: devicePoll }],
  ["/refresh", { post: refresh }],
]);

/** An answer plus the error code that goes into the log line. */
interface Reply {
  response: Response;
  error?: string;
}

/** The whole Worker. Pure in (request, env, deps): no globals, no storage. Never throws. */
export async function handle(request: Request, env: Env, deps: Deps): Promise<Response> {
  let path = "other";
  let reply: Reply;
  try {
    const url = new URL(request.url);
    const route = ROUTES.get(url.pathname);
    if (route !== undefined) path = url.pathname;
    reply = await dispatch(request, route, env, deps);
  } catch {
    reply = fail(500, "internal_error", "The sign-in helper failed unexpectedly.");
  }
  // The only log line: never a body, a query string, a header or a secret.
  console.log(JSON.stringify({ route: path, status: reply.response.status, error: reply.error }));
  return reply.response;
}

export default { fetch: (request: Request, env: Env) => handle(request, env, defaultDeps) } satisfies ExportedHandler<Env>;

async function dispatch(request: Request, route: Route | undefined, env: Env, deps: Deps): Promise<Reply> {
  if (route === undefined) return fail(404, "not_found", "There is nothing at this address.");
  const method = "page" in route ? "GET" : "POST";
  if (request.method !== method) {
    return fail(405, "method_not_allowed", `This address only answers ${method} requests.`, { Allow: method });
  }
  const clients = configuredClients(env);
  if ("page" in route) {
    return { response: route.page(clients === null ? "not_configured" : clients.legacyIncomplete ? "legacy_incomplete" : "ready") };
  }

  if (await overLimit(request, env)) {
    return fail(429, "rate_limited", "Too many requests from this address. Wait a minute, then try again.", {
      "Retry-After": String(RATE_LIMIT_RETRY_AFTER_S),
    });
  }
  if (clients === null) {
    return fail(500, "server_misconfigured", "This sign-in helper is not configured yet: its secrets are missing or incomplete.");
  }
  const body = await readJsonObject(request);
  if ("reply" in body) return body.reply;
  return route.post({ env, deps, clients }, body.json);
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
  // Which client issued the token: a device that signed in through /device/poll says "device"; one that says nothing
  // signed in before gclone 0.2.0, through the legacy client.
  if (body.client !== undefined && body.client !== "device") {
    return fail(400, "invalid_request", 'The "client" of a refresh request is "device" or absent.');
  }
  const client = body.client === "device" ? clients.device : clients.legacy;
  if (client === null) {
    if (clients.legacyIncomplete) {
      // Not "log in again": the owner is in the middle of setting or removing the pair, and the login may be fine.
      return fail(
        500,
        "server_misconfigured",
        "Only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set on this sign-in helper, so it cannot refresh a login made before gclone 0.2.0: set both, or delete both.",
      );
    }
    // Google is not asked: with the device client's credentials it could only refuse a token of another client.
    return fail(400, "invalid_grant", "This login was made with gclone's earlier browser sign-in, which this sign-in helper no longer serves. Run `gclone login` again.");
  }
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

// ---------- answers ----------

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

function fail(status: number, error: string, message: string, headers: Record<string, string> = {}): Reply {
  return { ...json(status, { error, message }, headers), error };
}

/** The address is masked (`s***@example.net`): `/device/poll` is open to anyone, and whoever entered a caller's user
 *  code at Google agreed to show the address to the app, not to that caller. */
function notAllowed(email: string | undefined): Reply {
  const masked = maskedEmail(email);
  const who = masked === null ? "This Google account" : `The Google account ${masked}`;
  return fail(403, "email_not_allowed", `${who} is not allowed to sign in here.`);
}

function scopeNotAllowed(excess: string[]): Reply {
  // Scope names are not secrets, but they are Google's text: only plain ones are echoed, and only a few. They come last,
  // so a client that shortens the message keeps the remedy.
  const named = excess.filter((entry) => /^[A-Za-z0-9:\/._-]{1,100}$/.test(entry)).slice(0, 3);
  const what = named.length > 0 ? ` Not asked for: ${named.join(", ")}${named.length < excess.length ? ", ..." : ""}` : "";
  return fail(
    403,
    "scope_not_allowed",
    `Google granted more access than gclone asks for, so nothing was handed out. If you did not expect this, remove gclone at https://myaccount.google.com/permissions; then run \`gclone login\` again.${what}`,
  );
}

function googleFailure(r: GoogleFailure): Reply {
  return fail(r.status, r.error, r.message);
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
