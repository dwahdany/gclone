// Test support: a literal Env, a fake Google behind the injected fetch, a settable clock, a fake rate limiter,
// a console spy that enforces the logging rules after every test, and the runner for the contract fixture.

import { afterEach, beforeEach, expect, vi } from "vitest";
import { GRANT_TTL_S, handle, type Deps, type Env, type RateLimiter } from "../src/index";
import { b64urlEncode, sha256 } from "../src/seal";

// The shared test vector (SPEC §2.3, §2.4; also the `vector` of contract.json).
export const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
export const CHECK_CODE = "D2KC-JCJY";
export const NONCE = "mKAL8fUxkA1kKo1N1fGpkTPlTwOW8hTa0YuYssR4ouw";
export const DEVICE_STATE = "AAAAAAAAAAAAAAAAAAAAAA";
export const PORT = 8123;
export const OTHER_VERIFIER = "another-device-verifier_0123456789.0123456789~";

export const ORIGIN = "https://auth.test";
export const CLIENT_ID = "cid.apps.googleusercontent.com";
export const CLIENT_SECRET = "test-secret";
export const SEAL_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // bytes 0..31
export const EMAIL = "me@example.com";
export const GOOGLE = { authUrl: "https://google.test/auth", tokenUrl: "https://google.test/token", revokeUrl: "https://google.test/revoke" };
export const GRANTED_SCOPE = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file";
/** What Google grants when the `scope` of the authorization URL was widened to the whole Drive on its way to the user. */
export const WIDE_SCOPE = `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive`;
export const T0_MS = 1_794_400_000_000;

export function testEnv(over: Partial<Env> = {}): Env {
  return { GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: CLIENT_SECRET, SEAL_KEY, ALLOWED_EMAILS: EMAIL, ...over };
}

export async function challengeOf(verifier: string): Promise<string> {
  return b64urlEncode(await sha256(new TextEncoder().encode(verifier)));
}

// ---------- fake Google ----------

export function makeIdToken(claims: Record<string, unknown>): string {
  const part = (v: unknown) => b64urlEncode(new TextEncoder().encode(JSON.stringify(v)));
  return `${part({ alg: "RS256", kid: "test", typ: "JWT" })}.${part(claims)}.c2lnbmF0dXJl`;
}

export interface Consent {
  /** The nonce of the authorization request this code is "issued" for; null = the ID token has no nonce claim. */
  nonce: string | null;
  email?: string;
  emailVerified?: boolean;
  scope?: string;
  aud?: string;
  iss?: string;
  refreshTokenExpiresIn?: number;
  /** Fields left out of the token answer. */
  omit?: Array<"id_token" | "refresh_token" | "access_token" | "expires_in" | "scope">;
  /** Replaces the generated ID token verbatim. */
  idToken?: string;
}

export interface GoogleCall {
  kind: "token" | "revoke";
  url: string;
  method: string;
  contentType: string | null;
  form: Record<string, string>;
  hasTimeout: boolean;
}

/** Google's token and revoke endpoints with the wire shapes of SPEC §16.4. It answers only what a test set up:
 *  a consented code, a known refresh token, or a scripted answer. Anything else is recorded in `unexpected`,
 *  which fails the test in the harness's afterEach. */
export class FakeGoogle {
  readonly calls: GoogleCall[] = [];
  readonly unexpected: string[] = [];
  /** Every refresh token this fake issued or was told about — none may show up outside a /token body. */
  readonly refreshTokens = new Set<string>();
  readonly accessTokens = new Set<string>();
  readonly idTokens = new Set<string>();
  readonly codes = new Map<string, Consent & { used: boolean }>();
  private readonly live = new Map<string, { revoked: boolean; idToken?: string }>();
  private readonly script: Array<() => Response> = [];
  private counter = 0;

  /** The user approved the consent screen: `code` is what Google sends to /callback. */
  consent(code: string, consent: Consent): void {
    this.codes.set(code, { ...consent, used: false });
  }

  /** A live refresh token without a login; `idToken` is what Google adds to refresh answers for it. */
  addRefreshToken(idToken?: string): string {
    const token = `1//fake-refresh-token-${++this.counter}`;
    this.refreshTokens.add(token);
    this.live.set(token, idToken === undefined ? { revoked: false } : { revoked: false, idToken });
    if (idToken !== undefined) this.idTokens.add(idToken);
    return token;
  }

  /** Revocation is grant-wide: every refresh token dies. */
  revokeAll(): void {
    for (const entry of this.live.values()) entry.revoked = true;
  }

  /** The next call to the token endpoint gets this answer, whatever it asks. */
  nextTokenAnswer(status: number, body: unknown): void {
    this.script.push(
      () =>
        new Response(typeof body === "string" ? body : JSON.stringify(body), {
          status,
          headers: { "content-type": typeof body === "string" ? "text/html" : "application/json; charset=utf-8" },
        }),
    );
  }

  /** The next call to the token endpoint fails like a network error or a timeout. */
  nextTokenThrows(error: Error): void {
    this.script.push(() => {
      throw error;
    });
  }

  kinds(): string[] {
    return this.calls.map((c) => c.kind);
  }

  revokes(): GoogleCall[] {
    return this.calls.filter((c) => c.kind === "revoke");
  }

  readonly fetch: Deps["fetch"] = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const kind = url === GOOGLE.tokenUrl ? "token" : url === GOOGLE.revokeUrl ? "revoke" : null;
    if (kind === null) return this.fail(`request to ${url}`);
    const body = init?.body;
    if (typeof body !== "string") return this.fail(`${kind} request without a text body`);
    const call: GoogleCall = {
      kind,
      url,
      method: init?.method ?? "GET",
      contentType: new Headers(init?.headers).get("content-type"),
      form: Object.fromEntries(new URLSearchParams(body)),
      hasTimeout: init?.signal instanceof AbortSignal,
    };
    this.calls.push(call);
    if (call.method !== "POST" || call.contentType !== "application/x-www-form-urlencoded") {
      return this.fail(`${kind} request is not a form POST`);
    }
    return kind === "token" ? this.token(call.form) : this.revoke(call.form);
  };

  private token(form: Record<string, string>): Response {
    const scripted = this.script.shift();
    if (scripted !== undefined) return scripted();
    if (form.client_id !== CLIENT_ID || form.client_secret !== CLIENT_SECRET) {
      return answer(401, { error: "invalid_client", error_description: "Unauthorized" });
    }
    if (form.grant_type === "authorization_code") {
      const consent = this.codes.get(form.code ?? "");
      if (consent === undefined) return this.fail(`code exchange for an unknown code`);
      if (consent.used) return answer(400, { error: "invalid_grant", error_description: "Bad Request" });
      consent.used = true;
      const n = ++this.counter;
      const refreshToken = `1//fake-refresh-token-${n}`;
      const accessToken = `ya29.fake-access-token-${n}`;
      const idToken =
        consent.idToken ??
        makeIdToken({
          iss: consent.iss ?? "https://accounts.google.com",
          aud: consent.aud ?? CLIENT_ID,
          sub: "1234567890",
          email: consent.email ?? EMAIL,
          email_verified: consent.emailVerified ?? true,
          ...(consent.nonce === null ? {} : { nonce: consent.nonce }),
          iat: 1794400000,
          exp: 1794403600,
        });
      this.refreshTokens.add(refreshToken);
      this.accessTokens.add(accessToken);
      this.idTokens.add(idToken);
      this.live.set(refreshToken, { revoked: false });
      const body: Record<string, unknown> = {
        access_token: accessToken,
        expires_in: 3599,
        refresh_token: refreshToken,
        token_type: "Bearer",
        scope: consent.scope ?? GRANTED_SCOPE,
        id_token: idToken,
      };
      if (consent.refreshTokenExpiresIn !== undefined) body.refresh_token_expires_in = consent.refreshTokenExpiresIn;
      for (const field of consent.omit ?? []) delete body[field];
      return answer(200, body);
    }
    if (form.grant_type === "refresh_token") {
      const entry = this.live.get(form.refresh_token ?? "");
      if (entry === undefined) return this.fail("refresh with an unknown refresh token");
      if (entry.revoked) return answer(400, { error: "invalid_grant", error_description: "Token has been expired or revoked." });
      const accessToken = `ya29.fake-access-token-${++this.counter}`;
      this.accessTokens.add(accessToken);
      const body: Record<string, unknown> = { access_token: accessToken, expires_in: 3599, scope: GRANTED_SCOPE, token_type: "Bearer" };
      if (entry.idToken !== undefined) body.id_token = entry.idToken;
      return answer(200, body);
    }
    return this.fail(`token request with grant_type ${form.grant_type}`);
  }

  private revoke(form: Record<string, string>): Response {
    if (!this.live.has(form.token ?? "")) return this.fail("revoke of an unknown token");
    this.revokeAll();
    return answer(200, {});
  }

  private fail(what: string): never {
    this.unexpected.push(what);
    throw new TypeError(`fake Google: unscripted ${what}`);
  }
}

function answer(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

// ---------- fake rate limiter ----------

export class FakeRateLimiter implements RateLimiter {
  readonly keys: string[] = [];
  constructor(
    public success = true,
    private readonly broken = false,
  ) {}
  async limit(options: { key: string }): Promise<{ success: boolean }> {
    this.keys.push(options.key);
    if (this.broken) throw new Error("rate limiter unavailable");
    return { success: this.success };
  }
}

// ---------- harness ----------

interface Recorded {
  path: string;
  status: number;
  headers: string;
  body: string;
}

export interface CallInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** The origin the request arrives at; default ORIGIN. */
  origin?: string;
}

export class Harness {
  env: Env = testEnv();
  clock = { ms: T0_MS };
  google = new FakeGoogle();
  deps: Deps = { fetch: this.google.fetch, now: () => this.clock.ms, google: GOOGLE };
  readonly logs: string[] = [];
  readonly strayConsole: string[] = [];
  readonly recorded: Recorded[] = [];
  /** Further strings that must never leave the Worker (other SEAL_KEY spellings, client secrets of a test's own env). */
  readonly secrets = new Set<string>();

  reset(): void {
    this.env = testEnv();
    this.clock = { ms: T0_MS };
    this.google = new FakeGoogle();
    this.deps = { fetch: this.google.fetch, now: () => this.clock.ms, google: GOOGLE };
    this.logs.length = 0;
    this.strayConsole.length = 0;
    this.recorded.length = 0;
    this.secrets.clear();
  }

  /** One request through handle() with the harness's env and deps. */
  async call(path: string, init: CallInit = {}): Promise<Response> {
    const { origin = ORIGIN, ...requestInit } = init;
    const response = await handle(new Request(origin + path, requestInit), this.env, this.deps);
    await this.record(path, response);
    return response;
  }

  get(path: string, headers: Record<string, string> = {}): Promise<Response> {
    return this.call(path, { headers });
  }

  post(path: string, json: unknown, headers: Record<string, string> = {}): Promise<Response> {
    return this.call(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(json) });
  }

  /** Keeps a copy of an answer for the secret-hygiene check. */
  async record(path: string, response: Response): Promise<void> {
    const headers = [...response.headers].map(([k, v]) => `${k}: ${v}`).join("\n");
    this.recorded.push({ path, status: response.status, headers, body: await response.clone().text() });
  }

  /** SPEC §2.3 "nothing secret is ever logged or echoed", checked over everything the test produced. */
  verify(): void {
    expect(this.google.unexpected, "unscripted calls to Google").toEqual([]);
    expect(this.strayConsole, "console output other than console.log").toEqual([]);
    expect(this.logs.length, "at most one log line per request").toBeLessThanOrEqual(this.recorded.length);

    const routes = ["/", "/privacy", "/login", "/callback", "/token", "/refresh", "other"];
    for (const line of this.logs) {
      const entry = JSON.parse(line) as Record<string, unknown>;
      expect(Object.keys(entry).filter((k) => !["route", "status", "error"].includes(k)), `log line ${line}`).toEqual([]);
      expect(routes, `log line ${line}`).toContain(entry.route);
      expect(typeof entry.status, `log line ${line}`).toBe("number");
      if (entry.error !== undefined) expect(entry.error, `log line ${line}`).toMatch(/^[a-z_]{1,40}$/);
    }

    const neverAnywhere = [CLIENT_SECRET, ...this.secrets, ...sealKeySpellings(SEAL_KEY)];
    if (this.env.GOOGLE_CLIENT_SECRET) neverAnywhere.push(this.env.GOOGLE_CLIENT_SECRET);
    if (this.env.SEAL_KEY) neverAnywhere.push(this.env.SEAL_KEY);
    const neverLogged = [...this.google.refreshTokens, ...this.google.accessTokens, ...this.google.idTokens, ...this.google.codes.keys()];
    for (const line of this.logs) {
      for (const secret of [...neverAnywhere, ...neverLogged]) expect(line.includes(secret), `a secret in log line ${line}`).toBe(false);
    }
    for (const r of this.recorded) {
      const where = `${r.status} answer of ${r.path.split("?")[0]}`;
      for (const secret of neverAnywhere) {
        expect(r.headers.includes(secret) || r.body.includes(secret), `a Worker secret in the ${where}`).toBe(false);
      }
      for (const token of this.google.refreshTokens) {
        expect(r.headers.includes(token), `a refresh token in a header of the ${where}`).toBe(false);
        if (!r.path.startsWith("/token")) expect(r.body.includes(token), `a refresh token in the ${where}`).toBe(false);
      }
      expect(r.headers.toLowerCase(), `CORS header on the ${where}`).not.toContain("access-control-");
      expect(r.headers.toLowerCase(), `cookie on the ${where}`).not.toContain("set-cookie");
    }
  }
}

function sealKeySpellings(base64: string): string[] {
  const unpadded = base64.replace(/=+$/, "");
  return [unpadded, unpadded.replace(/\+/g, "-").replace(/\//g, "_")];
}

/** Call once at the top of a test file: a fresh harness state per test, the console spy, and the hygiene check after each test. */
export function useHarness(): Harness {
  const h = new Harness();
  beforeEach(() => {
    h.reset();
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      h.logs.push(args.map(String).join(" "));
    });
    for (const level of ["info", "warn", "error", "debug", "trace"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        h.strayConsole.push(`${level}: ${args.map(String).join(" ")}`);
      });
    }
  });
  afterEach(() => {
    vi.restoreAllMocks();
    h.verify();
  });
  return h;
}

// ---------- the browser's and the device's part of a login ----------

export function loginPath(opts: { challenge?: string; paste?: boolean; port?: number | string; state?: string } = {}): string {
  const q = new URLSearchParams({ challenge: opts.challenge ?? CHALLENGE });
  if (!opts.paste) {
    q.set("port", String(opts.port ?? PORT));
    q.set("state", opts.state ?? DEVICE_STATE);
  }
  return `/login?${q}`;
}

export function unescapeHtml(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

export function links(html: string): string[] {
  return [...html.matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((m) => unescapeHtml(m[1]!));
}

/** GET /login and read the confirmation page the way a browser user would: the one link is what Google receives. */
export async function startLogin(h: Harness, opts: Parameters<typeof loginPath>[0] = {}): Promise<{ page: string; link: URL; state: string; nonce: string }> {
  const res = await h.get(loginPath(opts));
  expect(res.status).toBe(200);
  const page = await res.text();
  const found = links(page);
  expect(found).toHaveLength(1);
  const link = new URL(found[0]!);
  return { page, link, state: link.searchParams.get("state") ?? "", nonce: link.searchParams.get("nonce") ?? "" };
}

let codeCounter = 0;
export function newGoogleCode(): string {
  return `4/0AfakeGoogleCode-${++codeCounter}_x`;
}

export function grantFromLocation(response: Response): string {
  const location = new URL(response.headers.get("location") ?? "");
  return location.searchParams.get("code") ?? "";
}

/** The one link of the confirmation page that /callback answers to Google's redirect — never a redirect, never a grant. */
export async function finishLink(response: Response): Promise<string> {
  expect(response.status, "Google's redirect is answered with the confirmation page").toBe(200);
  expect(response.headers.get("location"), "no redirect before the user confirmed").toBeNull();
  const page = await response.text();
  expect(page, "no paste code before the user confirmed").not.toContain("gclone-code1_");
  const found = links(page);
  expect(found).toHaveLength(1);
  expect(found[0]).toMatch(/^\/callback\?confirmed=[A-Za-z0-9_-]+$/);
  return found[0]!;
}

/** The browser's whole visit to /callback after Google: the confirmation page, then its link. Returns the last answer
 *  (loopback mode: the 302 to the device; paste mode: the page with the code). */
export async function callbackAndConfirm(h: Harness, query: string, init: CallInit = {}): Promise<Response> {
  return h.call(await finishLink(await h.call(`/callback?${query}`, init)), init);
}

/** /login → consent at the fake Google (the code is issued for the nonce on the Continue link) → /callback → the
 *  confirmation page → its link → the grant. */
export async function obtainGrant(h: Harness, opts: { verifier?: string; consent?: Partial<Consent> } = {}): Promise<string> {
  const { state, nonce } = await startLogin(h, { challenge: await challengeOf(opts.verifier ?? VERIFIER) });
  const code = newGoogleCode();
  h.google.consent(code, { nonce, ...opts.consent });
  const res = await callbackAndConfirm(h, String(new URLSearchParams({ code, state })));
  expect(res.status).toBe(302);
  return grantFromLocation(res);
}

/** A whole login; returns what the device would store. */
export async function obtainRefreshToken(h: Harness): Promise<string> {
  const res = await h.post("/token", { code: await obtainGrant(h), verifier: VERIFIER });
  expect(res.status).toBe(200);
  return ((await res.json()) as { refresh_token: string }).refresh_token;
}

export async function errorOf(res: Response): Promise<{ status: number; error: string }> {
  const body = (await res.clone().json()) as { error?: unknown; message?: unknown };
  expect(Object.keys(body).sort()).toEqual(["error", "message"]);
  expect(typeof body.message).toBe("string");
  expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
  expect(res.headers.get("cache-control")).toBe("no-store");
  return { status: res.status, error: String(body.error) };
}

// ---------- contract fixture ----------

export interface ContractCase {
  name: string;
  given: string;
  request: { method: string; path: string; headers?: Record<string, string>; query?: Record<string, string>; json?: unknown; body?: string };
  response: { status: number; headers?: Record<string, string>; json?: Record<string, unknown>; location?: string; body_contains?: string[] };
}

export interface Contract {
  version: number;
  vector: { verifier: string; challenge: string; state: string; port: number; check_code: string; email: string };
  cases: ContractCase[];
}

/** The closed list of SPEC §16.5. */
export const GIVEN = [
  "none",
  "consent_ok",
  "consent_denied",
  "grant",
  "grant_expired",
  "grant_other_account",
  "grant_no_drive_scope",
  "grant_wide_scope",
  "grant_expiring",
  "refresh_token",
  "refresh_revoked",
  "refresh_wide_scope",
  "client_broken",
  "google_down",
  "rate_limited",
  "unconfigured",
] as const;

export const REQUIRED_CASES = [
  "login_loopback",
  "login_paste",
  "login_bad_challenge",
  "loopback_grant",
  "loopback_denied",
  "paste_code",
  "token_ok",
  "token_expiring",
  "token_wrong_verifier",
  "token_expired_grant",
  "token_email_not_allowed",
  "token_scope_missing",
  "token_scope_not_allowed",
  "token_client_invalid",
  "token_upstream",
  "token_rate_limited",
  "token_unconfigured",
  "token_wrong_content_type",
  "token_too_large",
  "token_not_json",
  "token_missing_field",
  "token_get",
  "refresh_ok",
  "refresh_invalid_grant",
  "refresh_malformed_token",
  "refresh_scope_not_allowed",
  "refresh_client_invalid",
  "refresh_upstream",
  "refresh_rate_limited",
  "not_found",
];

function onlyKeys(what: string, value: object, allowed: string[]): void {
  const unknown = Object.keys(value).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) throw new Error(`${what}: unknown key(s) ${unknown.join(", ")}`);
}

/** Reproduces one fixture case with the real handle(). Throws on an unknown `given` keyword, matcher or placeholder. */
export async function runContractCase(h: Harness, contract: Contract, c: ContractCase): Promise<void> {
  onlyKeys(`case ${c.name}`, c, ["name", "given", "request", "response"]);
  onlyKeys(`case ${c.name} request`, c.request, ["method", "path", "headers", "query", "json", "body"]);
  onlyKeys(`case ${c.name} response`, c.response, ["status", "headers", "json", "location", "body_contains"]);
  if (!(GIVEN as readonly string[]).includes(c.given)) throw new Error(`case ${c.name}: unknown given "${c.given}"`);
  if (c.request.json !== undefined && c.request.body !== undefined) throw new Error(`case ${c.name}: both json and body`);
  const { vector } = contract;

  // Placeholders the harness has to produce from its own implementation — before the `given` state can get in the way.
  const requestText = JSON.stringify(c.request);
  const values: Record<string, string> = {
    "<verifier>": vector.verifier,
    "<challenge>": vector.challenge,
    "<state>": vector.state,
    "<port>": String(vector.port),
    "<other_verifier>": OTHER_VERIFIER,
  };
  if (requestText.includes("<grant>")) {
    const consents: Record<string, Partial<Consent>> = {
      grant_other_account: { email: "stranger@example.com" },
      grant_no_drive_scope: { scope: "openid https://www.googleapis.com/auth/userinfo.email" },
      grant_wide_scope: { scope: WIDE_SCOPE },
      grant_expiring: { refreshTokenExpiresIn: 604799 },
    };
    const consent = consents[c.given] ?? {};
    values["<grant>"] = await obtainGrant(h, { verifier: vector.verifier, consent });
    if (c.given === "grant_expired") h.clock.ms += GRANT_TTL_S * 1000;
  }
  if (requestText.includes("<refresh_token>")) {
    values["<refresh_token>"] = await obtainRefreshToken(h);
    if (c.given === "refresh_revoked") h.google.revokeAll();
    if (c.given === "refresh_wide_scope") {
      // The grant behind this refresh token covers more than gclone's scopes: Google says so on every refresh.
      h.google.accessTokens.add("ya29.wide-access-token");
      h.google.nextTokenAnswer(200, { access_token: "ya29.wide-access-token", expires_in: 3599, scope: WIDE_SCOPE, token_type: "Bearer" });
    }
  }
  const unknownPlaceholder = requestText.match(/<[a-z_]+>/g)?.find((p) => !(p in values));
  if (unknownPlaceholder !== undefined) throw new Error(`case ${c.name}: unknown placeholder ${unknownPlaceholder}`);
  const fill = (text: string) => text.replace(/<[a-z_]+>/g, (p) => values[p] ?? p);

  if (c.given === "client_broken") h.google.nextTokenAnswer(401, { error: "invalid_client", error_description: "The OAuth client was not found." });
  if (c.given === "google_down") h.google.nextTokenAnswer(503, "<html><title>503 Service Unavailable</title></html>");
  if (c.given === "rate_limited") h.env.RATE_LIMIT = new FakeRateLimiter(false);
  if (c.given === "unconfigured") h.env = { GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "", SEAL_KEY: "" };

  const query = c.request.query === undefined ? "" : `?${new URLSearchParams(Object.entries(c.request.query).map(([k, v]) => [k, fill(v)]))}`;
  const init: CallInit = { method: c.request.method, headers: c.request.headers ?? {} };
  if (c.request.json !== undefined) init.body = fill(JSON.stringify(c.request.json));
  if (c.request.body !== undefined) init.body = fill(c.request.body);
  let res = await h.call(c.request.path + query, init);

  if (c.given === "consent_ok" || c.given === "consent_denied") {
    // The request was the device's /login URL; the expected response is where the browser ends up after the user
    // followed the confirmation page's link, Google sent them back and — when Google granted access — they followed
    // the link of the second confirmation page.
    expect(res.status, "confirmation page").toBe(200);
    const found = links(await res.text());
    expect(found).toHaveLength(1);
    const link = new URL(found[0]!);
    const back = new URLSearchParams({ state: link.searchParams.get("state") ?? "" });
    if (c.given === "consent_ok") {
      const code = newGoogleCode();
      h.google.consent(code, { nonce: link.searchParams.get("nonce") });
      back.set("code", code);
    } else {
      back.set("error", "access_denied");
    }
    res = await h.get(`/callback?${back}`);
    if (c.given === "consent_ok") {
      expect(await res.clone().text(), "the post-consent confirmation page shows the check code").toContain(vector.check_code);
      res = await h.get(await finishLink(res));
    }
  }

  const want = c.response;
  expect(res.status, "status").toBe(want.status);
  for (const [name, value] of Object.entries(want.headers ?? {})) {
    if (name !== name.toLowerCase()) throw new Error(`case ${c.name}: header name ${name} is not lower-case`);
    const got = res.headers.get(name);
    expect(got, `header ${name}`).not.toBeNull();
    if (value !== "<string>") expect(got, `header ${name}`).toBe(value);
  }
  if (want.location === undefined) {
    expect(res.headers.get("location"), "no Location header").toBeNull();
  } else {
    expect(res.headers.get("location") ?? "", "Location header").toMatch(new RegExp(`^(?:${want.location})$`));
  }
  const text = await res.text();
  for (const part of want.body_contains ?? []) expect(text, "body").toContain(part);
  if (want.json !== undefined) {
    const got = JSON.parse(text) as Record<string, unknown>;
    expect(Object.keys(got).sort(), "exact key set").toEqual(Object.keys(want.json).sort());
    for (const [key, expected] of Object.entries(want.json)) {
      if (expected === "<string>") expect(typeof got[key], `json.${key}`).toBe("string");
      else if (expected === "<number>") expect(typeof got[key], `json.${key}`).toBe("number");
      else expect(got[key], `json.${key}`).toEqual(expected);
    }
  }
}
