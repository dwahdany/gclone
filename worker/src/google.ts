// Everything the Worker says to Google: the authorization URL, the two token-endpoint calls, revoke, and the ID-token payload.

import type { Deps, Env } from "./index";
import { b64urlDecode } from "./seal";

export const SCOPES = "openid email https://www.googleapis.com/auth/drive.file";
export const SCOPE_DRIVE_FILE = "https://www.googleapis.com/auth/drive.file";
/** Every scope a grant of this client may carry: SCOPES, plus Google's own spelling of the granted `email` scope. */
export const ALLOWED_SCOPES: readonly string[] = ["openid", "email", "https://www.googleapis.com/auth/userinfo.email", SCOPE_DRIVE_FILE];
// Pre-filters: malformed input never reaches Google. They deliberately do not assume today's "4/…" and "1//…" prefixes.
export const CODE_RE = /^[A-Za-z0-9_\/.~+=-]{8,512}$/;
export const REFRESH_TOKEN_RE = /^[A-Za-z0-9_\/.~+=-]{20,512}$/;

const GOOGLE_TIMEOUT_MS = 10_000;
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const CLIENT_ERRORS = ["invalid_client", "deleted_client", "unauthorized_client", "redirect_uri_mismatch"];
const DENIED_ERRORS = ["access_denied", "admin_policy_enforced", "org_internal"];

/** `nonce` = loginNonce(challenge), computed by the caller. No login_hint, nothing derived from ALLOWED_EMAILS. */
export function authorizationUrl(env: Env, deps: Deps, redirectUri: string, challenge: string, state: string, nonce: string): string {
  const query = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: SCOPES,
    access_type: "offline", // with prompt=consent: a refresh token on every login, not only the first
    prompt: "consent",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return `${deps.google.authUrl}?${query}`;
}

/** The entries of a space-separated `scope` answer that are outside ALLOWED_SCOPES; empty = nothing beyond what /login asks for.
 *  The scope of the authorization URL is not under the Worker's control once the URL has left /login (anyone can rewrite it,
 *  or add `include_granted_scopes`), so what Google actually granted is checked here, on its token answers. */
export function excessScopes(scope: string): string[] {
  return scope.split(" ").filter((entry) => entry !== "" && !ALLOWED_SCOPES.includes(entry));
}

export type GoogleResult<T> ={ ok: true; value: T } | { ok: false; status: 400 | 403 | 500 | 502; error: string; message: string };

export interface CodeTokens {
  refresh_token: string;
  access_token: string;
  expires_in: number;
  scope: string;
  id_token: string;
  refresh_token_expires_in?: number;
}

export async function exchangeCode(env: Env, deps: Deps, redirectUri: string, code: string, verifier: string): Promise<GoogleResult<CodeTokens>> {
  const answer = await tokenRequest(env, deps, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  if (!answer.ok) return answer;
  const { refresh_token, access_token, expires_in, scope, id_token, refresh_token_expires_in } = answer.value;
  if (!nonEmptyString(refresh_token) || !nonEmptyString(access_token) || !finiteNumber(expires_in) || !nonEmptyString(id_token)) {
    return UPSTREAM;
  }
  const value: CodeTokens = { refresh_token, access_token, expires_in, scope: typeof scope === "string" ? scope : "", id_token };
  if (finiteNumber(refresh_token_expires_in)) value.refresh_token_expires_in = refresh_token_expires_in;
  return { ok: true, value };
}

/** `id_token` is passed through when Google sent one, for the caller's allowlist re-check. */
export async function refreshAccessToken(
  env: Env,
  deps: Deps,
  refreshToken: string,
): Promise<GoogleResult<{ access_token: string; expires_in: number; scope: string; id_token?: string }>> {
  const answer = await tokenRequest(env, deps, { grant_type: "refresh_token", refresh_token: refreshToken });
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
  nonce?: string;
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
  if (typeof json.nonce === "string") claims.nonce = json.nonce;
  return claims;
}

/** The token was issued by Google for this client. */
export function claimsFromGoogle(env: Env, c: IdClaims | null): boolean {
  return c !== null && c.aud === env.GOOGLE_CLIENT_ID && c.iss !== undefined && GOOGLE_ISSUERS.includes(c.iss);
}

export function emailAllowed(env: Env, c: IdClaims): boolean {
  return c.email_verified === true && c.email !== undefined && allowedEmails(env).has(c.email.toLowerCase());
}

/** Undefined or empty = nobody (fail closed). */
export function allowedEmails(env: Env): Set<string> {
  const list = typeof env.ALLOWED_EMAILS === "string" ? env.ALLOWED_EMAILS : "";
  return new Set(
    list
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry !== ""),
  );
}

const UPSTREAM = { ok: false, status: 502, error: "upstream_error", message: "Google's token service did not give a usable answer." } as const;

function postForm(deps: Deps, url: string, form: Record<string, string>): Promise<Response> {
  return deps.fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(form).toString(),
    redirect: "manual", // the client secret is never re-sent to another address
    signal: AbortSignal.timeout(GOOGLE_TIMEOUT_MS),
  });
}

/** One call to the token endpoint, with the client's credentials added; error answers already mapped. */
async function tokenRequest(env: Env, deps: Deps, form: Record<string, string>): Promise<GoogleResult<Record<string, unknown>>> {
  let status: number;
  let body: unknown;
  try {
    const res = await postForm(deps, deps.google.tokenUrl, {
      ...form,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
    });
    status = res.status;
    body = JSON.parse(await res.text());
  } catch {
    return UPSTREAM; // network failure, timeout, or a body that is not JSON
  }
  if (!isRecord(body) || status >= 500) return UPSTREAM;
  if (status === 200) return { ok: true, value: body };
  const code = typeof body.error === "string" ? body.error : "";
  if (code === "invalid_grant") {
    return { ok: false, status: 400, error: "invalid_grant", message: "Google rejected the sign-in code or refresh token: it is expired, revoked or already used." };
  }
  if (CLIENT_ERRORS.includes(code)) {
    return { ok: false, status: 500, error: "client_invalid", message: `Google does not accept this Worker's OAuth client (${code}).` };
  }
  if (DENIED_ERRORS.includes(code)) {
    return { ok: false, status: 403, error: "access_denied", message: `Google denied access (${code}).` };
  }
  return UPSTREAM;
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
