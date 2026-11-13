// Test support: a literal Env, a fake Google behind the injected fetch, a fake rate limiter, a console spy that
// enforces the logging rules after every test, and the runner for the contract fixture.

import { afterEach, beforeEach, expect, vi } from "vitest";
import { handle, type AssetFetcher, type Deps, type Env, type RateLimiter } from "../src/index";
import { STATUS_MARKER } from "../src/pages";
import { b64urlEncode, pkceChallenge, sealSession } from "../src/seal";
import { WEB_COOKIE } from "../src/web";

export const ORIGIN = "https://auth.test";
export const CLIENT_ID = "device-cid.apps.googleusercontent.com";
export const CLIENT_SECRET = "test-device-secret";
/** The "Web application" client: the secrets GOOGLE_LEGACY_CLIENT_ID / GOOGLE_LEGACY_CLIENT_SECRET. */
export const WEB_CLIENT_ID = "web-cid.apps.googleusercontent.com";
export const WEB_CLIENT_SECRET = "test-web-secret";
export const SEAL_KEY_BYTES = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
/** As `openssl rand -base64 32` prints it. */
export const SEAL_KEY = btoa(String.fromCharCode(...SEAL_KEY_BYTES));
export const EMAIL = "me@example.com";
export const GOOGLE = {
  deviceCodeUrl: "https://google.test/device/code",
  tokenUrl: "https://google.test/token",
  revokeUrl: "https://google.test/revoke",
  authUrl: "https://google.test/auth",
};
export const REDIRECT_URI = `${ORIGIN}/callback`;
/** Where the harness's clock starts (milliseconds). */
export const T0 = 1_794_500_000_000;
export const SCOPES = "openid email https://www.googleapis.com/auth/drive.file";
export const GRANTED_SCOPE = "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file";
/** A grant that covers the whole Drive (an older, wider grant of the same account to the same project). */
export const WIDE_SCOPE = `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive`;
export const VERIFICATION_URL = "https://www.google.com/device";
export const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

/** The device client only: a Worker without the hosted viewer. `withWeb()` adds what the viewer needs. */
export function testEnv(over: Partial<Env> = {}): Env {
  return { GOOGLE_CLIENT_ID: CLIENT_ID, GOOGLE_CLIENT_SECRET: CLIENT_SECRET, ALLOWED_EMAILS: EMAIL, ...over };
}

/** The web client's pair, SEAL_KEY and the viewer's files. */
export function withWeb(over: Partial<Env> = {}): Env {
  return testEnv({ GOOGLE_LEGACY_CLIENT_ID: WEB_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET: WEB_CLIENT_SECRET, SEAL_KEY, ASSETS: new FakeAssets(), ...over });
}

// ---------- fake assets binding ----------

/** `index.html` of a built viewer as far as the Worker is concerned: some markup around the status marker. */
export const VIEWER_INDEX = `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>gclone</title><script src="/a/0123456789abcdef/shell.js" defer></script></head>\n<body><p class="status">${STATUS_MARKER}</p></body></html>\n`;

/** The assets binding: `dist/` as a map of path → text. Everything the Worker asks it for is recorded. */
export class FakeAssets implements AssetFetcher {
  readonly requests: Array<{ method: string; url: string; headers: string[] }> = [];
  constructor(public files: Record<string, string> = { "/index.html": VIEWER_INDEX, "/sw.js": "// sw", "/a/0123456789abcdef/shell.js": "// shell" }) {}
  async fetch(request: Request): Promise<Response> {
    this.requests.push({ method: request.method, url: request.url, headers: [...request.headers.keys()] });
    const body = this.files[new URL(request.url).pathname];
    if (body === undefined) return new Response(null, { status: 404 });
    return new Response(body, { status: 200, headers: { "content-type": "text/html; charset=utf-8", etag: '"abc"', "cache-control": "public, max-age=0, must-revalidate" } });
  }
}

// ---------- fake Google ----------

/** base64url of the UTF-8 bytes (`btoa` alone refuses anything beyond Latin-1). */
function b64url(text: string): string {
  let binary = "";
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function makeIdToken(claims: Record<string, unknown>): string {
  const part = (v: unknown) => b64url(JSON.stringify(v));
  return `${part({ alg: "RS256", kid: "test", typ: "JWT" })}.${part(claims)}.c2lnbmF0dXJl`;
}

/** What the user did at Google (google.com/device, or the consent page of the browser sign-in), and what Google then
 *  answers to the poll or to the code exchange. */
export interface Consent {
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
  /** Browser sign-in only: the `nonce` claim (default: the one of the authorization URL); null = no such claim. */
  nonce?: string | null;
  /** Browser sign-in only: the refresh token Google issues (default: a generated one). */
  refreshToken?: string;
}

/** An authorization code of the browser sign-in, as Google remembers it. */
interface AuthCode {
  clientId: string;
  redirectUri: string;
  challenge: string;
  nonce: string | null;
  consent: Consent;
  used: boolean;
}

export interface GoogleCall {
  kind: "device_code" | "token" | "revoke";
  url: string;
  method: string;
  contentType: string | null;
  form: Record<string, string>;
  hasTimeout: boolean;
}

type DeviceState = "pending" | "slow_down" | "approved" | "denied" | "expired" | "used";

/** Google's device-code, token and revoke endpoints with the wire shapes of SPEC §16.4. It answers only what a test set
 *  up: a started device code, a known refresh token, or a scripted answer. Anything else is recorded in `unexpected`,
 *  which fails the test in the harness's afterEach. */
export class FakeGoogle {
  readonly calls: GoogleCall[] = [];
  readonly unexpected: string[] = [];
  /** Every refresh token this fake issued or was told about — none may show up outside a /device/poll body. */
  readonly refreshTokens = new Set<string>();
  /** Those of the web client: they show up nowhere at all (the browser gets them sealed). */
  readonly webRefreshTokens = new Set<string>();
  /** Authorization codes of the browser sign-in, and the verifiers they were redeemed with: never in an answer or a log. */
  readonly codes = new Map<string, AuthCode>();
  readonly verifiers = new Set<string>();
  readonly accessTokens = new Set<string>();
  readonly idTokens = new Set<string>();
  /** device code → the login it stands for. Neither a device code nor a user code may show up outside a /device/start body. */
  readonly devices = new Map<string, { userCode: string; state: DeviceState; consent: Consent }>();
  private readonly live = new Map<string, { clientId: string; revoked: boolean; idToken?: string }>();
  private readonly script: Array<() => Response> = [];
  private counter = 0;

  private device(userCode: string): { userCode: string; state: DeviceState; consent: Consent } {
    const found = [...this.devices.values()].find((d) => d.userCode === userCode);
    if (found === undefined) throw new Error(`fake Google: no login with user code ${userCode}`);
    return found;
  }

  /** The user entered `userCode` at google.com/device and approved. */
  approve(userCode: string, consent: Consent = {}): void {
    Object.assign(this.device(userCode), { state: "approved", consent });
  }

  /** The user entered the code and refused; or the code ran out; or the device polls too fast. */
  set(userCode: string, state: "denied" | "expired" | "slow_down" | "pending"): void {
    this.device(userCode).state = state;
  }

  /** The user consented at Google's page for `authorizationUrl` (what /web/start built — or what someone else did):
   *  the code Google then sends to the redirect URI. */
  consent(authorizationUrl: string, consent: Consent = {}): string {
    const q = new URL(authorizationUrl).searchParams;
    const code = `4/0Afake-auth_code.${++this.counter}`;
    this.codes.set(code, {
      clientId: q.get("client_id") ?? "",
      redirectUri: q.get("redirect_uri") ?? "",
      challenge: q.get("code_challenge") ?? "",
      nonce: q.get("nonce"),
      consent,
      used: false,
    });
    return code;
  }

  /** A live refresh token without a login, issued to `clientId`; `idToken` is what Google adds to refresh answers for it. */
  addRefreshToken(idToken?: string, clientId = CLIENT_ID): string {
    const token = `1//fake-refresh-token-${++this.counter}`;
    this.refreshTokens.add(token);
    if (clientId === WEB_CLIENT_ID) this.webRefreshTokens.add(token);
    this.live.set(token, idToken === undefined ? { clientId, revoked: false } : { clientId, revoked: false, idToken });
    if (idToken !== undefined) this.idTokens.add(idToken);
    return token;
  }

  /** Revocation is grant-wide: every refresh token dies. */
  revokeAll(): void {
    for (const entry of this.live.values()) entry.revoked = true;
  }

  /** What Google adds to the refresh answers of `token` from now on (undefined: no ID token). */
  setIdToken(token: string, idToken: string | undefined): void {
    const entry = this.live.get(token);
    if (entry === undefined) throw new Error("fake Google: no such refresh token");
    if (idToken === undefined) delete entry.idToken;
    else {
      entry.idToken = idToken;
      this.idTokens.add(idToken);
    }
  }

  /** The next call to Google (device-code or token endpoint) gets this answer, whatever it asks. */
  nextAnswer(status: number, body: unknown): void {
    this.script.push(
      () =>
        new Response(typeof body === "string" ? body : JSON.stringify(body), {
          status,
          headers: { "content-type": typeof body === "string" ? "text/html" : "application/json; charset=utf-8" },
        }),
    );
  }

  /** The next call to Google fails like a network error or a timeout. */
  nextThrows(error: Error): void {
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
    const kind = url === GOOGLE.deviceCodeUrl ? "device_code" : url === GOOGLE.tokenUrl ? "token" : url === GOOGLE.revokeUrl ? "revoke" : null;
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
    if (kind === "revoke") return this.revoke(call.form);
    const scripted = this.script.shift();
    if (scripted !== undefined) return scripted();
    return kind === "device_code" ? this.deviceCode(call.form) : this.token(call.form);
  };

  private deviceCode(form: Record<string, string>): Response {
    if (form.client_id !== CLIENT_ID) return answer(401, { error: "invalid_client", error_description: "Invalid client type." });
    if (form.scope !== SCOPES) return this.fail(`device-code request for the scope ${form.scope}`);
    const n = ++this.counter;
    const deviceCode = `AH-1Ng-fake_device.code/${n}`;
    const userCode = `FAKE-${String(n).padStart(4, "0")}`;
    this.devices.set(deviceCode, { userCode, state: "pending", consent: {} });
    return answer(200, { device_code: deviceCode, user_code: userCode, expires_in: 1800, interval: 5, verification_url: VERIFICATION_URL });
  }

  private token(form: Record<string, string>): Response | Promise<Response> {
    const secrets: Record<string, string> = { [CLIENT_ID]: CLIENT_SECRET, [WEB_CLIENT_ID]: WEB_CLIENT_SECRET };
    if (form.client_id === undefined || secrets[form.client_id] !== form.client_secret) {
      return answer(401, { error: "invalid_client", error_description: "Unauthorized" });
    }
    if (form.grant_type === DEVICE_GRANT) {
      // The statuses are Google's (428 and 403), not RFC 8628's 400.
      if (form.client_id !== CLIENT_ID) return answer(401, { error: "invalid_client", error_description: "Invalid client type." });
      const device = this.devices.get(form.device_code ?? "");
      if (device === undefined) return this.fail("poll for an unknown device code");
      if (device.state === "pending") return answer(428, { error: "authorization_pending", error_description: "Precondition Required" });
      if (device.state === "slow_down") return answer(403, { error: "slow_down", error_description: "Forbidden" });
      if (device.state === "denied") return answer(403, { error: "access_denied", error_description: "Forbidden" });
      if (device.state === "expired") return answer(400, { error: "expired_token", error_description: "Expired token" });
      if (device.state === "used") return answer(400, { error: "invalid_grant", error_description: "Malformed auth code." });
      device.state = "used";
      const { consent } = device;
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
          iat: 1794400000,
          exp: 1794403600,
        });
      this.refreshTokens.add(refreshToken);
      this.accessTokens.add(accessToken);
      this.idTokens.add(idToken);
      this.live.set(refreshToken, { clientId: CLIENT_ID, revoked: false });
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
    if (form.grant_type === "authorization_code") return this.exchange(form);
    if (form.grant_type === "refresh_token") {
      const entry = this.live.get(form.refresh_token ?? "");
      if (entry === undefined) return this.fail("refresh with an unknown refresh token");
      // What Google really answers to a refresh token presented by another client of the project is unverified.
      if (entry.clientId !== form.client_id) return this.fail("refresh with the credentials of another client");
      if (entry.revoked) return answer(400, { error: "invalid_grant", error_description: "Token has been expired or revoked." });
      const accessToken = `ya29.fake-access-token-${++this.counter}`;
      this.accessTokens.add(accessToken);
      const body: Record<string, unknown> = { access_token: accessToken, expires_in: 3599, scope: GRANTED_SCOPE, token_type: "Bearer" };
      if (entry.idToken !== undefined) body.id_token = entry.idToken;
      return answer(200, body);
    }
    return this.fail(`token request with grant_type ${form.grant_type}`);
  }

  /** The code of the browser sign-in for tokens. Google checks the client, the redirect URI and the PKCE verifier. */
  private async exchange(form: Record<string, string>): Promise<Response> {
    if (form.code_verifier !== undefined) this.verifiers.add(form.code_verifier);
    const entry = this.codes.get(form.code ?? "");
    if (entry === undefined || entry.used || entry.clientId !== form.client_id) return answer(400, { error: "invalid_grant", error_description: "Malformed auth code." });
    if (entry.redirectUri !== form.redirect_uri) return answer(400, { error: "redirect_uri_mismatch", error_description: "Bad Request" });
    if ((await pkceChallenge(form.code_verifier ?? "")) !== entry.challenge) return answer(400, { error: "invalid_grant", error_description: "Invalid code verifier." });
    entry.used = true;
    const { consent } = entry;
    const n = ++this.counter;
    const refreshToken = consent.refreshToken ?? `1//fake-web-refresh-token-${n}`;
    const accessToken = `ya29.fake-web-access-token-${n}`;
    const claims: Record<string, unknown> = {
      iss: consent.iss ?? "https://accounts.google.com",
      aud: consent.aud ?? form.client_id,
      sub: "1234567890",
      email: consent.email ?? EMAIL,
      email_verified: consent.emailVerified ?? true,
      iat: 1794400000,
      exp: 1794403600,
    };
    const nonce = consent.nonce === undefined ? entry.nonce : consent.nonce;
    if (nonce !== null) claims.nonce = nonce;
    const idToken = consent.idToken ?? makeIdToken(claims);
    this.refreshTokens.add(refreshToken);
    this.webRefreshTokens.add(refreshToken);
    this.accessTokens.add(accessToken);
    this.idTokens.add(idToken);
    this.live.set(refreshToken, { clientId: form.client_id!, revoked: false });
    const body: Record<string, unknown> = {
      access_token: accessToken,
      expires_in: 3599,
      refresh_token: refreshToken,
      token_type: "Bearer",
      scope: consent.scope ?? GRANTED_SCOPE,
      id_token: idToken,
    };
    for (const field of consent.omit ?? []) delete body[field];
    return answer(200, body);
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
}

export const ROUTES = ["/", "/callback", "/privacy", "/device/start", "/device/poll", "/refresh", "/web/start", "/web/token", "/web/refresh", "/web/logout"];
/** The only answers that may carry a cookie. */
const COOKIE_ROUTES = ["/web/token", "/web/refresh", "/web/logout"];
/** What the viewer's page sends with every request to a /web route. */
export const SAME_ORIGIN = { origin: ORIGIN, "sec-fetch-site": "same-origin" };

export class Harness {
  env: Env = testEnv();
  google = new FakeGoogle();
  /** The Worker's clock, in milliseconds; a test moves it forward. */
  now = T0;
  deps: Deps = { fetch: this.google.fetch, now: () => this.now, google: GOOGLE };
  readonly logs: string[] = [];
  readonly strayConsole: string[] = [];
  readonly recorded: Recorded[] = [];

  reset(): void {
    this.env = testEnv();
    this.google = new FakeGoogle();
    this.now = T0;
    this.deps = { fetch: this.google.fetch, now: () => this.now, google: GOOGLE };
    this.logs.length = 0;
    this.strayConsole.length = 0;
    this.recorded.length = 0;
  }

  /** One request through handle() with the harness's env and deps. `path` may be a whole URL (another scheme or host). */
  async call(path: string, init: CallInit = {}): Promise<Response> {
    const url = /^https?:\/\//.test(path) ? path : ORIGIN + path;
    const response = await handle(new Request(url, init), this.env, this.deps);
    await this.record(new URL(url).pathname, response);
    return response;
  }

  get(path: string, headers: Record<string, string> = {}): Promise<Response> {
    return this.call(path, { headers });
  }

  post(path: string, json: unknown, headers: Record<string, string> = {}): Promise<Response> {
    return this.call(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(json) });
  }

  /** A POST as the viewer's own page sends it: same origin. `headers` are added (a cookie) or replace those. */
  web(path: string, json: unknown = {}, headers: Record<string, string> = {}): Promise<Response> {
    return this.post(path, json, { ...SAME_ORIGIN, ...headers });
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

    for (const line of this.logs) {
      const entry = JSON.parse(line) as Record<string, unknown>;
      expect(Object.keys(entry).filter((k) => !["route", "status", "error"].includes(k)), `log line ${line}`).toEqual([]);
      expect([...ROUTES, "other"], `log line ${line}`).toContain(entry.route);
      expect(typeof entry.status, `log line ${line}`).toBe("number");
      if (entry.error !== undefined) expect(entry.error, `log line ${line}`).toMatch(/^[a-z_]{1,40}$/);
    }

    // The client secrets, SEAL_KEY, the web client's refresh tokens (the browser holds them sealed, never as they
    // are), the authorization codes of the browser sign-in and their verifiers: in no answer and in no log line.
    const neverAnywhere = [CLIENT_SECRET, WEB_CLIENT_SECRET, SEAL_KEY, ...this.google.webRefreshTokens, ...this.google.codes.keys(), ...this.google.verifiers];
    for (const secret of [this.env.GOOGLE_CLIENT_SECRET, this.env.GOOGLE_LEGACY_CLIENT_SECRET, this.env.SEAL_KEY]) if (secret) neverAnywhere.push(secret);
    const deviceCodes = [...this.google.devices.keys()];
    const userCodes = [...this.google.devices.values()].map((d) => d.userCode);
    // Every session cookie the Worker set.
    const cookies = this.recorded.flatMap((r) => [...r.headers.matchAll(new RegExp(`^set-cookie: ${WEB_COOKIE}=([^;\\n]+)`, "gm"))].map((m) => m[1]!));
    const neverLogged = [...this.google.refreshTokens, ...this.google.accessTokens, ...this.google.idTokens, ...deviceCodes, ...userCodes, ...cookies, WEB_COOKIE];
    for (const line of this.logs) {
      for (const secret of [...neverAnywhere, ...neverLogged]) expect(line.includes(secret), `a secret in log line ${line}`).toBe(false);
    }
    for (const r of this.recorded) {
      const where = `${r.status} answer of ${r.path}`;
      for (const secret of neverAnywhere) {
        expect(r.headers.includes(secret) || r.body.includes(secret), `a Worker secret in the ${where}`).toBe(false);
      }
      // A refresh token leaves the Worker only in a /device/poll body; a device or user code only in a /device/start body.
      for (const [tokens, path, what] of [
        [[...this.google.refreshTokens], "/device/poll", "a refresh token"],
        [[...deviceCodes, ...userCodes], "/device/start", "a device or user code"],
      ] as const) {
        for (const token of tokens) {
          expect(r.headers.includes(token), `${what} in a header of the ${where}`).toBe(false);
          if (r.path !== path) expect(r.body.includes(token), `${what} in the ${where}`).toBe(false);
        }
      }
      // An access token leaves the Worker only in the body of the four routes that exist to hand one out.
      for (const token of this.google.accessTokens) {
        expect(r.headers.includes(token), `an access token in a header of the ${where}`).toBe(false);
        if (!["/device/poll", "/refresh", "/web/token", "/web/refresh"].includes(r.path)) expect(r.body.includes(token), `an access token in the ${where}`).toBe(false);
      }
      expect(r.headers.toLowerCase(), `CORS header on the ${where}`).not.toContain("access-control-");
      // Cookies: the session cookie, on the three web routes that set or clear it, with every attribute — and nowhere else.
      const setCookies = [...r.headers.matchAll(/^set-cookie: (.*)$/gm)].map((m) => m[1]!);
      if (!COOKIE_ROUTES.includes(r.path)) expect(setCookies, `cookie on the ${where}`).toEqual([]);
      expect(setCookies.length, `cookies on the ${where}`).toBeLessThanOrEqual(1);
      for (const cookie of setCookies) {
        expect(cookie, `cookie on the ${where}`).toMatch(new RegExp(`^${WEB_COOKIE}=[A-Za-z0-9_-]*; Path=/; Secure; HttpOnly; SameSite=Strict(; Max-Age=(0|2592000))?$`));
      }
      expect(r.headers, `no-store on the ${where}`).toContain("cache-control: no-store");
    }
  }
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

// ---------- the device's part of a login ----------

export interface Started {
  device_code: string;
  user_code: string;
  verification_url: string;
  expires_in: number;
  interval: number;
}

/** POST /device/start: what the device shows (user code) and polls with (device code). */
export async function startLogin(h: Harness): Promise<Started> {
  const res = await h.post("/device/start", {});
  expect(res.status).toBe(200);
  return (await res.json()) as Started;
}

export function poll(h: Harness, deviceCode: string): Promise<Response> {
  return h.post("/device/poll", { device_code: deviceCode });
}

/** A login whose user approved at Google with `consent`; the answer to the device's next poll. */
export async function login(h: Harness, consent: Consent = {}): Promise<Response> {
  const started = await startLogin(h);
  h.google.approve(started.user_code, consent);
  return poll(h, started.device_code);
}

/** A whole login; returns what the device would store. */
export async function obtainRefreshToken(h: Harness): Promise<string> {
  const res = await login(h);
  expect(res.status).toBe(200);
  return ((await res.json()) as { refresh_token: string }).refresh_token;
}

// ---------- the page's part of a browser sign-in ----------

export interface Pkce {
  verifier: string;
  challenge: string;
  state: string;
}

/** What the page makes before it leaves for Google: a verifier, its S256 challenge and a `state`. */
export async function pkce(): Promise<Pkce> {
  const verifier = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: await pkceChallenge(verifier), state: b64urlEncode(crypto.getRandomValues(new Uint8Array(16))) };
}

/** POST /web/start: the address at Google. */
export async function webStart(h: Harness, p: Pkce): Promise<string> {
  const res = await h.web("/web/start", { challenge: p.challenge, state: p.state });
  expect(res.status).toBe(200);
  return ((await res.json()) as { authorization_url: string }).authorization_url;
}

export interface SignedIn {
  res: Response;
  /** The whole `Set-Cookie` value, and its `name=value` pair as the browser sends it back; null when none was set. */
  setCookie: string | null;
  cookie: string | null;
  pkce: Pkce;
  code: string;
}

/** A whole browser sign-in (the env must have the web client): /web/start, the user's consent at Google, /web/token. */
export async function webSignIn(h: Harness, over: { consent?: Consent; remember?: boolean } = {}): Promise<SignedIn> {
  const p = await pkce();
  const code = h.google.consent(await webStart(h, p), over.consent);
  const res = await h.web("/web/token", { code, verifier: p.verifier, ...(over.remember === undefined ? {} : { remember: over.remember }) });
  const setCookie = res.headers.get("set-cookie");
  return { res, setCookie, cookie: setCookie === null ? null : setCookie.split(";")[0]!, pkce: p, code };
}

/** A session cookie (`name=value`) sealed under `key`: what a browser would hold after a sign-in with this outcome. */
export async function sealedCookie(session: { iat: number; exp: number; email?: string; refreshToken: string }, key: Uint8Array = SEAL_KEY_BYTES): Promise<string> {
  return `${WEB_COOKIE}=${await sealSession(key, { email: EMAIL, ...session })}`;
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
  request: { method: string; path: string; headers?: Record<string, string>; json?: unknown; body?: string };
  response: { status: number; headers?: Record<string, string>; json?: Record<string, unknown> };
}

export interface Contract {
  version: number;
  cases: ContractCase[];
}

/** The closed list of SPEC §16.5: the state a case starts from. `<device_code>` is a started login in that state;
 *  `<refresh_token>` a refresh token of the device client (`legacy_token`: of the web client, as a device that signed
 *  in before gclone 0.2.0 holds one — on a Worker that has that client's secrets).
 *  The `web…` states are the hosted viewer's: a Worker with the web client, SEAL_KEY and the viewer's files.
 *  `<challenge>` and `<state>` are a tab's PKCE challenge and state; `<code>` and `<verifier>` an authorization code
 *  after the consent at Google and the verifier it belongs to; `<cookie>` the session cookie of a finished sign-in;
 *  `<origin>` the Worker's own origin. */
export const GIVEN = [
  "none",
  "pending",
  "slow_down",
  "denied",
  "expired",
  "used",
  "approved",
  "approved_expiring",
  "approved_other_account",
  "approved_no_drive_scope",
  "approved_wide_scope",
  "approved_no_id_token",
  "refresh_token",
  "refresh_revoked",
  "refresh_wide_scope",
  "legacy_token",
  "legacy_half_set_device_token",
  "client_broken",
  "google_down",
  "rate_limited",
  "unconfigured",
  "web",
  "web_consented",
  "web_other_verifier",
  "web_foreign_code",
  "web_consented_other_account",
  "web_consented_wide_scope",
  "web_consented_no_drive_scope",
  "web_session",
  "web_session_remembered",
  "web_session_expired",
  "web_session_other_key",
  "web_session_revoked",
  "web_session_removed",
  "web_session_google_down",
] as const;

export const REQUIRED_CASES = [
  "start_ok",
  "start_client_invalid",
  "start_upstream",
  "start_rate_limited",
  "start_unconfigured",
  "start_wrong_content_type",
  "start_get",
  "poll_pending",
  "poll_slow_down",
  "poll_denied",
  "poll_expired",
  "poll_used",
  "poll_ok",
  "poll_expiring",
  "poll_email_not_allowed",
  "poll_scope_missing",
  "poll_scope_not_allowed",
  "poll_grant_unusable",
  "poll_client_invalid",
  "poll_upstream",
  "poll_rate_limited",
  "poll_unconfigured",
  "poll_wrong_content_type",
  "poll_too_large",
  "poll_not_json",
  "poll_missing_field",
  "poll_malformed_code",
  "poll_get",
  "refresh_ok",
  "refresh_no_client",
  "refresh_legacy_gone",
  "refresh_half_set_device_ok",
  "refresh_bad_client",
  "refresh_invalid_grant",
  "refresh_malformed_token",
  "refresh_scope_not_allowed",
  "refresh_client_invalid",
  "refresh_upstream",
  "refresh_rate_limited",
  "refresh_unconfigured",
  "refresh_get",
  "not_found",
  "login_gone",
  "token_gone",
  // the hosted viewer: its page and the four routes of its sign-in
  "page_home",
  "page_callback",
  "page_unconfigured",
  "web_start_ok",
  "web_start_malformed",
  "web_start_cross_origin",
  "web_start_no_origin",
  "web_start_unconfigured",
  "web_start_rate_limited",
  "web_start_get",
  "web_token_ok",
  "web_token_remember",
  "web_token_other_verifier",
  "web_token_foreign_code",
  "web_token_email_not_allowed",
  "web_token_scope_not_allowed",
  "web_token_scope_missing",
  "web_token_malformed",
  "web_token_cross_origin",
  "web_refresh_ok",
  "web_refresh_remembered",
  "web_refresh_no_session",
  "web_refresh_bad_cookie",
  "web_refresh_other_key",
  "web_refresh_expired",
  "web_refresh_invalid_grant",
  "web_refresh_email_not_allowed",
  "web_refresh_upstream",
  "web_refresh_cross_origin",
  "web_refresh_wrong_content_type",
  "web_logout_ok",
  "web_logout_no_session",
  "web_logout_unconfigured",
  "web_logout_cross_origin",
  // what is refused, or answered, without being counted by the rate limiter
  "web_logout_over_limit",
  "web_refresh_cross_origin_over_limit",
  "start_from_a_page",
  "refresh_from_a_page_over_limit",
];

function onlyKeys(what: string, value: object, allowed: string[]): void {
  const unknown = Object.keys(value).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) throw new Error(`${what}: unknown key(s) ${unknown.join(", ")}`);
}

/** Reproduces one fixture case with the real handle(). Throws on an unknown `given` keyword, matcher or placeholder. */
export async function runContractCase(h: Harness, c: ContractCase): Promise<void> {
  onlyKeys(`case ${c.name}`, c, ["name", "given", "request", "response"]);
  onlyKeys(`case ${c.name} request`, c.request, ["method", "path", "headers", "json", "body"]);
  onlyKeys(`case ${c.name} response`, c.response, ["status", "headers", "json"]);
  if (!(GIVEN as readonly string[]).includes(c.given)) throw new Error(`case ${c.name}: unknown given "${c.given}"`);
  if (c.request.json !== undefined && c.request.body !== undefined) throw new Error(`case ${c.name}: both json and body`);

  // Placeholders the harness has to produce from its own implementation — before the `given` state can get in the way.
  const requestText = JSON.stringify(c.request);
  const values: Record<string, string> = {};
  if (requestText.includes("<device_code>")) {
    const started = await startLogin(h);
    values["<device_code>"] = started.device_code;
    const consents: Record<string, Consent> = {
      approved: {},
      used: {},
      approved_expiring: { refreshTokenExpiresIn: 604799 },
      approved_other_account: { email: "stranger@example.com" },
      approved_no_drive_scope: { scope: "openid https://www.googleapis.com/auth/userinfo.email" },
      approved_wide_scope: { scope: WIDE_SCOPE },
      approved_no_id_token: { omit: ["id_token"] },
    };
    const consent = consents[c.given];
    if (consent !== undefined) h.google.approve(started.user_code, consent);
    if (c.given === "slow_down" || c.given === "denied" || c.given === "expired") h.google.set(started.user_code, c.given);
    if (c.given === "used") expect((await poll(h, started.device_code)).status).toBe(200);
  }
  if (requestText.includes("<refresh_token>")) {
    if (c.given === "legacy_token") {
      // The Worker has the web client's secrets, and the token is one of that client: /refresh still does not serve it.
      h.env = withWeb();
      values["<refresh_token>"] = h.google.addRefreshToken(undefined, WEB_CLIENT_ID);
    } else {
      // Exactly one of the two web-client secrets: the state between two `wrangler secret put` / `delete` commands.
      if (c.given === "legacy_half_set_device_token") h.env = testEnv({ GOOGLE_LEGACY_CLIENT_ID: WEB_CLIENT_ID });
      values["<refresh_token>"] = await obtainRefreshToken(h);
    }
    if (c.given === "refresh_revoked") h.google.revokeAll();
    if (c.given === "refresh_wide_scope") {
      // The grant behind this refresh token covers more than gclone's scopes: Google says so on every refresh.
      h.google.accessTokens.add("ya29.wide-access-token");
      h.google.nextAnswer(200, { access_token: "ya29.wide-access-token", expires_in: 3599, scope: WIDE_SCOPE, token_type: "Bearer" });
    }
  }
  // The hosted viewer's states.
  if (c.given.startsWith("web")) h.env = withWeb();
  values["<origin>"] = ORIGIN;
  if (/<challenge>|<state>|<code>|<verifier>/.test(requestText)) {
    const tab = await pkce();
    values["<challenge>"] = tab.challenge;
    values["<state>"] = tab.state;
    values["<verifier>"] = tab.verifier;
    if (requestText.includes("<code>")) {
      const consents: Record<string, Consent> = {
        web_consented: {},
        web_other_verifier: {},
        web_consented_other_account: { email: "stranger@example.com" },
        web_consented_wide_scope: { scope: WIDE_SCOPE },
        web_consented_no_drive_scope: { scope: "openid https://www.googleapis.com/auth/userinfo.email" },
      };
      if (c.given === "web_foreign_code") {
        // A code Google issued for an address that /web/start did not build: the right challenge, another nonce.
        const url = new URL(await webStart(h, tab));
        url.searchParams.set("nonce", "not-this-workers-nonce");
        values["<code>"] = h.google.consent(url.toString());
      } else {
        const consent = consents[c.given];
        if (consent === undefined) throw new Error(`case ${c.name}: <code> needs a web_consented… state`);
        values["<code>"] = h.google.consent(await webStart(h, tab), consent);
        // Another tab's verifier: well-formed, and not the one the code was issued for.
        if (c.given === "web_other_verifier") values["<verifier>"] = (await pkce()).verifier;
      }
    }
  }
  if (requestText.includes("<cookie>")) {
    if (!c.given.startsWith("web_session")) throw new Error(`case ${c.name}: <cookie> needs a web_session… state`);
    if (c.given === "web_session_other_key") {
      // Sealed by someone who does not have this Worker's SEAL_KEY (or before the key was replaced).
      values["<cookie>"] = await sealedCookie({ iat: T0 / 1000, exp: T0 / 1000 + 3600, refreshToken: h.google.addRefreshToken(undefined, WEB_CLIENT_ID) }, new Uint8Array(32).fill(9));
    } else {
      const signedIn = await webSignIn(h, { remember: c.given === "web_session_remembered" });
      expect(signedIn.res.status).toBe(200);
      values["<cookie>"] = signedIn.cookie!;
    }
    if (c.given === "web_session_expired") h.now += 12 * 3600 * 1000;
    if (c.given === "web_session_revoked") h.google.revokeAll();
    if (c.given === "web_session_removed") h.env.ALLOWED_EMAILS = "someone-else@example.com";
    if (c.given === "web_session_google_down") h.google.nextAnswer(503, "<html><title>503 Service Unavailable</title></html>");
  }
  const unknownPlaceholder = requestText.match(/<[a-z_]+>/g)?.find((p) => !(p in values));
  if (unknownPlaceholder !== undefined) throw new Error(`case ${c.name}: unknown placeholder ${unknownPlaceholder}`);
  const fill = (text: string) => text.replace(/<[a-z_]+>/g, (p) => values[p] ?? p);

  if (c.given === "client_broken") h.google.nextAnswer(401, { error: "invalid_client", error_description: "The OAuth client was not found." });
  if (c.given === "google_down") h.google.nextAnswer(503, "<html><title>503 Service Unavailable</title></html>");
  if (c.given === "rate_limited") h.env.RATE_LIMIT = new FakeRateLimiter(false);
  if (c.given === "unconfigured") h.env = { GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "" };

  const init: CallInit = { method: c.request.method, headers: c.request.headers ?? {} };
  if (c.request.json !== undefined) init.body = fill(JSON.stringify(c.request.json));
  if (c.request.body !== undefined) init.body = fill(c.request.body);
  if (init.headers !== undefined) init.headers = Object.fromEntries(Object.entries(init.headers).map(([name, value]) => [name, fill(value)]));
  const res = await h.call(c.request.path, init);

  const want = c.response;
  expect(res.status, "status").toBe(want.status);
  for (const [name, value] of Object.entries(want.headers ?? {})) {
    if (name !== name.toLowerCase()) throw new Error(`case ${c.name}: header name ${name} is not lower-case`);
    const got = res.headers.get(name);
    expect(got, `header ${name}`).not.toBeNull();
    if (value !== "<string>") expect(got, `header ${name}`).toBe(value);
  }
  expect(res.headers.get("location"), "no Location header").toBeNull();
  if (want.json !== undefined) {
    const got = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(got).sort(), "exact key set").toEqual(Object.keys(want.json).sort());
    for (const [key, expected] of Object.entries(want.json)) {
      if (expected === "<string>") expect(typeof got[key], `json.${key}`).toBe("string");
      else if (expected === "<number>") expect(typeof got[key], `json.${key}`).toBe("number");
      else expect(got[key], `json.${key}`).toEqual(expected);
    }
  }
}
