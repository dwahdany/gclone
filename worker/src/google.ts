// Everything the Worker says to Google: the device-code request, the two token-endpoint calls, revoke, and the ID-token payload.

import type { Deps, Env } from "./index";

/** What `/device/start` asks Google for. Nothing a device sends can change it. */
export const SCOPES = "openid email https://www.googleapis.com/auth/drive.file";
export const SCOPE_DRIVE_FILE = "https://www.googleapis.com/auth/drive.file";
/** Every scope a grant of this Worker's clients may carry: SCOPES, plus Google's own spelling of the granted `email` scope. */
export const ALLOWED_SCOPES: readonly string[] = ["openid", "email", "https://www.googleapis.com/auth/userinfo.email", SCOPE_DRIVE_FILE];
// Pre-filters: malformed input never reaches Google. They deliberately do not assume today's "AH-1…" and "1//…" prefixes.
export const DEVICE_CODE_RE = /^[A-Za-z0-9_\/.~+=-]{16,512}$/;
export const REFRESH_TOKEN_RE = /^[A-Za-z0-9_\/.~+=-]{20,512}$/;
/** What a user code from Google may look like before it is passed on to a terminal: printable ASCII, short. */
const USER_CODE_RE = /^[\x21-\x7e][\x20-\x7e]{0,62}[\x21-\x7e]$/;
const VERIFICATION_URL_RE = /^https:\/\/[\x21-\x7e]{1,200}$/;
/** An e-mail address the allowlist can hold or match: printable ASCII without a space. Anything else never matches —
 *  the comparison folds the case of ASCII letters and nothing more. */
const EMAIL_RE = /^[\x21-\x7e]{3,254}$/;
/** RFC 8628 §3.2 makes `interval` optional; §3.5: "clients MUST use 5 as the default". */
export const DEFAULT_POLL_INTERVAL_S = 5;

const GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
const GOOGLE_TIMEOUT_MS = 10_000;
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const CLIENT_ERRORS = ["invalid_client", "deleted_client", "unauthorized_client", "invalid_scope"];
const DENIED_ERRORS = ["access_denied", "admin_policy_enforced", "org_internal"];
/** The states of a device code that is not (or no longer) redeemable, passed on under Google's own names (RFC 8628 §3.5). */
const DEVICE_CODE_STATES: Record<string, string> = {
  authorization_pending: "Nobody has entered the code at Google yet.",
  slow_down: "Polling too fast: wait 5 seconds longer between requests.",
  expired_token: "The code expired before it was entered at Google. Run `gclone login` again.",
};

/** One OAuth client of the Worker's Cloud project. */
export interface Client {
  id: string;
  secret: string;
}

/** `device`: the "TVs and Limited Input devices" client every login uses. `legacy`: the "Web application" client of the
 *  browser sign-in before gclone 0.2.0, kept only so that `/refresh` still serves the refresh tokens it issued.
 *  `legacyIncomplete`: exactly one of the two legacy secrets is set — the legacy client cannot be used (`legacy` is
 *  null), and nothing else is affected. */
export interface Clients {
  device: Client;
  legacy: Client | null;
  legacyIncomplete: boolean;
}

/** The configured clients, or null when the device client's secrets are missing. A half-set legacy pair is not a
 *  reason to stop serving the device client: the documented way to remove the pair is two `wrangler secret delete`
 *  commands, each deployed at once, so every Worker passes through that state. */
export function configuredClients(env: Env): Clients | null {
  const text = (v: unknown) => (typeof v === "string" ? v : "");
  const [id, secret] = [text(env.GOOGLE_CLIENT_ID), text(env.GOOGLE_CLIENT_SECRET)];
  const [legacyId, legacySecret] = [text(env.GOOGLE_LEGACY_CLIENT_ID), text(env.GOOGLE_LEGACY_CLIENT_SECRET)];
  if (id === "" || secret === "") return null;
  const legacy = legacyId !== "" && legacySecret !== "" ? { id: legacyId, secret: legacySecret } : null;
  return { device: { id, secret }, legacy, legacyIncomplete: (legacyId === "") !== (legacySecret === "") };
}

/** The entries of a space-separated `scope` answer that are outside ALLOWED_SCOPES; empty = nothing beyond what
 *  `/device/start` asks for. Checked on Google's token answers: what was granted, not what was requested. */
export function excessScopes(scope: string): string[] {
  return scope.split(" ").filter((entry) => entry !== "" && !ALLOWED_SCOPES.includes(entry));
}

export type GoogleResult<T> = { ok: true; value: T } | { ok: false; status: 400 | 403 | 500 | 502; error: string; message: string };
export type GoogleFailure = Exclude<GoogleResult<unknown>, { ok: true }>;

/** Google's answer to a device-code request, passed on to the device as it is (`interval`: 5 when Google named none). */
export interface DeviceCode {
  device_code: string;
  user_code: string;
  verification_url: string;
  expires_in: number;
  interval: number;
}

export async function requestDeviceCode(client: Client, deps: Deps): Promise<GoogleResult<DeviceCode>> {
  const answer = await googleRequest(deps, deps.google.deviceCodeUrl, { client_id: client.id, scope: SCOPES });
  if (!answer.ok) return answer;
  const { device_code, user_code, verification_url, expires_in } = answer.value;
  // Absent is the default; a value that is present and not a positive number is still not a device code.
  const interval = answer.value.interval === undefined ? DEFAULT_POLL_INTERVAL_S : answer.value.interval;
  if (
    typeof device_code !== "string" ||
    !DEVICE_CODE_RE.test(device_code) ||
    typeof user_code !== "string" ||
    !USER_CODE_RE.test(user_code) ||
    typeof verification_url !== "string" ||
    !VERIFICATION_URL_RE.test(verification_url) ||
    !positiveNumber(expires_in) ||
    !positiveNumber(interval)
  ) {
    return UPSTREAM;
  }
  return { ok: true, value: { device_code, user_code, verification_url, expires_in, interval } };
}

export interface DeviceTokens {
  refresh_token: string;
  access_token: string;
  expires_in: number;
  scope: string;
  id_token: string;
  refresh_token_expires_in?: number;
}

/** A grant Google has issued — the device code is consumed — but that cannot be handed out. Final for the device: a
 *  further poll could only get `invalid_grant`. `what` completes "Google approved the sign-in, but …". */
export function grantUnusable(what: string): GoogleFailure {
  return {
    ok: false,
    status: 403,
    error: "grant_unusable",
    message: `Google approved the sign-in, but ${what}, so nothing was handed out and the code is used up. If this happens on every login, see "Troubleshooting" in worker/README.md.`,
  };
}

/** One poll of the token endpoint for a device code. `authorization_pending`, `slow_down` and `expired_token` come back as
 *  400 with Google's code; a refused consent as 403 `access_denied`; a used or unknown code as 400 `invalid_grant`; a
 *  token answer that lacks a part the Worker needs as 403 `grant_unusable`. */
export async function pollDeviceCode(client: Client, deps: Deps, deviceCode: string): Promise<GoogleResult<DeviceTokens>> {
  const answer = await tokenRequest(client, deps, { grant_type: GRANT_DEVICE_CODE, device_code: deviceCode }, DEVICE_CODE_STATES);
  if (!answer.ok) return answer;
  // From here on Google has consumed the device code: nothing below may look like "try again".
  const { refresh_token, access_token, expires_in, scope, id_token, refresh_token_expires_in } = answer.value;
  if (!nonEmptyString(refresh_token)) return grantUnusable("its answer carried no refresh token");
  if (!nonEmptyString(access_token) || !finiteNumber(expires_in)) return grantUnusable("its answer carried no usable access token");
  if (!nonEmptyString(id_token)) return grantUnusable("its answer carried no ID token (the account cannot be checked without one)");
  const value: DeviceTokens = { refresh_token, access_token, expires_in, scope: typeof scope === "string" ? scope : "", id_token };
  if (finiteNumber(refresh_token_expires_in)) value.refresh_token_expires_in = refresh_token_expires_in;
  return { ok: true, value };
}

/** `id_token` is passed through when Google sent one, for the caller's allowlist re-check. */
export async function refreshAccessToken(
  client: Client,
  deps: Deps,
  refreshToken: string,
): Promise<GoogleResult<{ access_token: string; expires_in: number; scope: string; id_token?: string }>> {
  const answer = await tokenRequest(client, deps, { grant_type: "refresh_token", refresh_token: refreshToken });
  if (!answer.ok) return answer;
  const { access_token, expires_in, scope, id_token } = answer.value;
  if (!nonEmptyString(access_token) || !finiteNumber(expires_in)) return UPSTREAM;
  const value: { access_token: string; expires_in: number; scope: string; id_token?: string } = {
    access_token,
    expires_in,
    scope: typeof scope === "string" ? scope : "",
  };
  if (nonEmptyString(id_token)) value.id_token = id_token;
  return { ok: true, value };
}

/** Best effort, never throws. Google revokes the whole grant, not one token. */
export async function revokeToken(deps: Deps, token: string): Promise<void> {
  try {
    const res = await postForm(deps, deps.google.revokeUrl, { token });
    await res.body?.cancel();
  } catch {
    // nothing to do: the caller refuses the login either way
  }
}

export interface IdClaims {
  aud?: string;
  iss?: string;
  email?: string;
  email_verified?: boolean;
}

/** Payload only, no signature check: the token is only ever taken from Google's token endpoint, over TLS, in answer to a
 *  request that carried the client secret. An ID token from any other source must never be passed here. */
export function idTokenClaims(idToken: string): IdClaims | null {
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  const payload = b64urlDecode(parts[1]!.replace(/=+$/, ""));
  if (payload === null) return null;
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(payload));
  } catch {
    return null;
  }
  if (!isRecord(json)) return null;
  const claims: IdClaims = {};
  if (typeof json.aud === "string") claims.aud = json.aud;
  if (typeof json.iss === "string") claims.iss = json.iss;
  if (typeof json.email === "string") claims.email = json.email;
  if (typeof json.email_verified === "boolean") claims.email_verified = json.email_verified;
  return claims;
}

/** The token was issued by Google for `client`. */
export function claimsFromGoogle(client: Client, c: IdClaims | null): boolean {
  return c !== null && c.aud === client.id && c.iss !== undefined && GOOGLE_ISSUERS.includes(c.iss);
}

/** Lower case for the 26 ASCII letters only. `String.prototype.toLowerCase` also maps other code points onto ASCII
 *  letters (U+212A KELVIN SIGN → "k"), which would let an address that is not the listed one pass. */
function asciiLower(text: string): string {
  return text.replace(/[A-Z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 32));
}

/** The verified address of the ID token is an entry of ALLOWED_EMAILS: byte for byte, but for the case of ASCII
 *  letters. A claim that is not printable ASCII matches nothing. */
export function emailAllowed(env: Env, c: IdClaims): boolean {
  return c.email_verified === true && c.email !== undefined && EMAIL_RE.test(c.email) && allowedEmails(env).has(asciiLower(c.email));
}

/** Undefined or empty = nobody (fail closed). Entries that are not printable ASCII are dropped: they could never match. */
export function allowedEmails(env: Env): Set<string> {
  const list = typeof env.ALLOWED_EMAILS === "string" ? env.ALLOWED_EMAILS : "";
  return new Set(
    list
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => EMAIL_RE.test(entry))
      .map(asciiLower),
  );
}

/** An address as an error answer may show it: the first character and the domain (`s***@example.net`). Enough for the
 *  owner to see which account was chosen by mistake; not the address itself, because the caller of `/device/poll` is
 *  anonymous and the account's holder agreed to show it to the app, not to that caller. Null: nothing presentable. */
export function maskedEmail(email: string | undefined): string | null {
  if (email === undefined || !EMAIL_RE.test(email)) return null;
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) return null;
  return `${email[0]}***${email.slice(at)}`;
}

export function b64urlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const UPSTREAM = { ok: false, status: 502, error: "upstream_error", message: "Google's sign-in service did not give a usable answer." } as const;

function postForm(deps: Deps, url: string, form: Record<string, string>): Promise<Response> {
  return deps.fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(form).toString(),
    redirect: "manual", // the client secret is never re-sent to another address
    signal: AbortSignal.timeout(GOOGLE_TIMEOUT_MS),
  });
}

function tokenRequest(client: Client, deps: Deps, form: Record<string, string>, passedOn: Record<string, string> = {}): Promise<GoogleResult<Record<string, unknown>>> {
  return googleRequest(deps, deps.google.tokenUrl, { ...form, client_id: client.id, client_secret: client.secret }, passedOn);
}

/** One form POST to Google; error answers already mapped. `passedOn`: Google error codes that are answered 400 under their
 *  own name, with the given message. Google's own status is not looked at below 500 (it uses 428 and 403 for the states
 *  of a device code): the `error` code decides. */
async function googleRequest(
  deps: Deps,
  url: string,
  form: Record<string, string>,
  passedOn: Record<string, string> = {},
): Promise<GoogleResult<Record<string, unknown>>> {
  let status: number;
  let body: unknown;
  try {
    const res = await postForm(deps, url, form);
    status = res.status;
    body = JSON.parse(await res.text());
  } catch {
    return UPSTREAM; // network failure, timeout, or a body that is not JSON
  }
  if (!isRecord(body) || status >= 500) return UPSTREAM;
  // An answer that names an error is an error answer, whatever its status — 200 included.
  if (status === 200 && body.error === undefined) return { ok: true, value: body };
  const code = typeof body.error === "string" ? body.error : "";
  if (Object.hasOwn(passedOn, code)) return { ok: false, status: 400, error: code, message: passedOn[code]! };
  if (code === "invalid_grant") {
    return { ok: false, status: 400, error: "invalid_grant", message: "Google rejected the sign-in code or refresh token: it is expired, revoked or already used." };
  }
  if (CLIENT_ERRORS.includes(code)) {
    return { ok: false, status: 500, error: "client_invalid", message: `Google does not accept this Worker's OAuth client (${code}).` };
  }
  if (DENIED_ERRORS.includes(code)) {
    return { ok: false, status: 403, error: "access_denied", message: `Google denied access (${code}).` };
  }
  return UPSTREAM; // also Google's own rate limit on device codes: 403 {"error_code": "rate_limit_exceeded"}
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v !== "";
}

function finiteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function positiveNumber(v: unknown): v is number {
  return finiteNumber(v) && v > 0;
}
