import { describe, expect, it } from "vitest";
import worker, { BODY_MAX, GOOGLE_DEVICE_CODE_URL, GOOGLE_REVOKE_URL, GOOGLE_TOKEN_URL, RATE_LIMIT_RETRY_AFTER_S, defaultDeps, handle, rateLimitKey, type Env } from "../src/index";
import { REFRESH_TOKEN_RE, revokeToken } from "../src/google";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  EMAIL,
  FakeRateLimiter,
  GOOGLE,
  GRANTED_SCOPE,
  LEGACY_CLIENT_ID,
  LEGACY_CLIENT_SECRET,
  ORIGIN,
  ROUTES,
  WIDE_SCOPE,
  errorOf,
  makeIdToken,
  obtainRefreshToken,
  poll,
  startLogin,
  testEnv,
  useHarness,
  withLegacy,
} from "./helpers";

const h = useHarness();
const HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const WELL_FORMED = "1//0abcdefghijklmnopqrstuv";
const JUNK_DEVICE_CODE = "AH-1Ng-junk-junk-junk-junk";

function idTokenFor(email: string, over: Record<string, unknown> = {}): string {
  return makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "1234567890", email, email_verified: true, ...over });
}

/** POST /refresh the way a device that signed in through /device/poll does. */
function refresh(refreshToken: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return h.post("/refresh", { refresh_token: refreshToken, client: "device" }, headers);
}

describe("POST /refresh", () => {
  it("happy path: the exact form goes to Google and the exact JSON comes back", async () => {
    const refreshToken = h.google.addRefreshToken();
    const res = await h.post("/refresh", { refresh_token: refreshToken, client: "device", unknown: 1 });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ access_token: "ya29.fake-access-token-2", expires_in: 3599, scope: GRANTED_SCOPE });
    expect(h.google.calls).toHaveLength(1);
    const call = h.google.calls[0]!;
    expect(call).toMatchObject({ kind: "token", url: GOOGLE.tokenUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    expect(call.form).toEqual({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
  });

  it("the full flow: /device/start → the user enters the code at Google → /device/poll → /refresh", async () => {
    // the device: start, show the user code, poll
    const started = await startLogin(h);
    expect((await errorOf(await poll(h, started.device_code))).error).toBe("authorization_pending");
    // the user: google.com/device, the code from the terminal, consent
    h.google.approve(started.user_code);
    // the device's next poll carries the tokens
    const tokenRes = await poll(h, started.device_code);
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { refresh_token: string; email: string };
    expect(tokens.email).toBe(EMAIL);
    expect(REFRESH_TOKEN_RE.test(tokens.refresh_token)).toBe(true);
    const refreshRes = await refresh(tokens.refresh_token);
    expect(refreshRes.status).toBe(200);
    expect(Object.keys((await refreshRes.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
    expect(h.google.kinds()).toEqual(["device_code", "token", "token", "token"]);
  });

  it("two logins yield two refresh tokens that both refresh", async () => {
    const first = await obtainRefreshToken(h);
    const second = await obtainRefreshToken(h);
    expect(second).not.toBe(first);
    expect((await refresh(first)).status).toBe(200);
    expect((await refresh(second)).status).toBe(200);
  });

  it("maps Google's error answers", async () => {
    const table: Array<[number, unknown, number, string]> = [
      [400, { error: "invalid_grant", error_description: "Token has been expired or revoked." }, 400, "invalid_grant"],
      [401, { error: "invalid_client" }, 500, "client_invalid"],
      [401, { error: "deleted_client" }, 500, "client_invalid"],
      [401, { error: "unauthorized_client" }, 500, "client_invalid"],
      [403, { error: "access_denied" }, 403, "access_denied"],
      [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
      [403, { error: "org_internal" }, 403, "access_denied"],
      [400, { error: "redirect_uri_mismatch" }, 502, "upstream_error"],
      [503, { error: "backend_error" }, 502, "upstream_error"],
      [500, "Internal Server Error", 502, "upstream_error"],
      [200, "<html></html>", 502, "upstream_error"],
      [200, { expires_in: 3599, scope: GRANTED_SCOPE }, 502, "upstream_error"],
      [200, { access_token: "ya29.x", expires_in: "3599" }, 502, "upstream_error"],
      // the states of a device code are not answers to a refresh
      [428, { error: "authorization_pending" }, 502, "upstream_error"],
      [403, { error: "slow_down" }, 502, "upstream_error"],
      [400, { error: "expired_token" }, 502, "upstream_error"],
    ];
    for (const [googleStatus, googleBody, status, error] of table) {
      const refreshToken = h.google.addRefreshToken();
      h.google.nextAnswer(googleStatus, googleBody);
      expect(await errorOf(await refresh(refreshToken)), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
    }
    const refreshToken = h.google.addRefreshToken();
    h.google.nextThrows(new TypeError("network connection lost"));
    expect(await errorOf(await refresh(refreshToken))).toEqual({ status: 502, error: "upstream_error" });
    expect(h.google.revokes()).toEqual([]);
  });

  it("a revoked refresh token → 400 invalid_grant", async () => {
    const refreshToken = await obtainRefreshToken(h);
    h.google.revokeAll();
    expect(await errorOf(await refresh(refreshToken))).toEqual({ status: 400, error: "invalid_grant" });
  });

  it("a malformed refresh token → 400 invalid_request with zero calls to Google", async () => {
    const bad: unknown[] = [
      {},
      { refresh_token: 5 },
      { refresh_token: null },
      { refresh_token: [WELL_FORMED] },
      { refresh_token: "" },
      { refresh_token: "r".repeat(19) },
      { refresh_token: "r".repeat(513) },
      { refresh_token: "1//0abcdefghij klmnopqrstuv" },
      { refresh_token: '1//0abcdefghij"klmnopqrstuv' },
      { refresh_token: "1//0abcdefghij'klmnopqrstuv" },
      { refresh_token: "1//0abcdefghij&client_id=x" },
      { refresh_token: "1//0abcdefghij\nklmnopqrstuv" },
      { refresh_token: "1//0abcdefghij%20klmnopqrst" },
      { token: WELL_FORMED },
    ];
    for (const body of bad) {
      for (const client of [{}, { client: "device" }]) {
        const res = await h.post("/refresh", { ...(body as object), ...client });
        expect(await errorOf(res), JSON.stringify(body).slice(0, 60)).toEqual({ status: 400, error: "invalid_request" });
      }
    }
    expect(h.google.calls).toEqual([]);
    // 20 and 512 characters of the allowed set do reach Google
    for (const token of ["r".repeat(20), "r".repeat(512), "1//0A_-.~+=/abcdefghijklm"]) {
      expect(REFRESH_TOKEN_RE.test(token)).toBe(true);
      h.google.nextAnswer(400, { error: "invalid_grant" });
      expect(await errorOf(await refresh(token))).toEqual({ status: 400, error: "invalid_grant" });
    }
    expect(h.google.kinds()).toEqual(["token", "token", "token"]);
  });

  describe("scope re-check", () => {
    const refreshWith = async (scope: unknown): Promise<Response> => {
      const refreshToken = h.google.addRefreshToken();
      const body: Record<string, unknown> = { access_token: "ya29.scoped-access-token", expires_in: 3599, token_type: "Bearer" };
      if (scope !== undefined) body.scope = scope;
      h.google.accessTokens.add("ya29.scoped-access-token");
      h.google.nextAnswer(200, body);
      return refresh(refreshToken);
    };

    it("a refresh token whose grant covers more than gclone's scopes gets no access token: 403 scope_not_allowed, no revoke", async () => {
      for (const scope of [WIDE_SCOPE, "https://www.googleapis.com/auth/drive", `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive.readonly`, "profile"]) {
        const res = await refreshWith(scope);
        expect(await errorOf(res), scope).toEqual({ status: 403, error: "scope_not_allowed" });
        const text = await res.text();
        expect(text).not.toContain("ya29.");
        expect(text).toContain("https://myaccount.google.com/permissions");
      }
      expect(h.google.revokes()).toEqual([]);
    });

    it("gclone's own scopes in any spelling and order, or no scope field at all → 200", async () => {
      for (const scope of [GRANTED_SCOPE, "https://www.googleapis.com/auth/drive.file", "email openid https://www.googleapis.com/auth/drive.file", "openid", "", undefined, 7]) {
        const res = await refreshWith(scope);
        expect(res.status, String(scope)).toBe(200);
        expect(((await res.json()) as { scope: string }).scope).toBe(typeof scope === "string" ? scope : "");
      }
    });

    it("the allowlist is checked first: a removed address is revoked even when the scope is wide", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor("removed@example.net"));
      h.google.accessTokens.add("ya29.scoped-access-token");
      h.google.nextAnswer(200, { access_token: "ya29.scoped-access-token", expires_in: 3599, scope: WIDE_SCOPE, id_token: idTokenFor("removed@example.net") });
      expect(await errorOf(await refresh(refreshToken))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });
  });

  describe("allowlist re-check", () => {
    it("an id_token for an address outside ALLOWED_EMAILS → 403 email_not_allowed plus one revoke", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor("removed@example.net"));
      const res = await refresh(refreshToken);
      expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
      const text = await res.text();
      // masked, as on /device/poll
      expect(text).toContain("r***@example.net");
      expect(text).not.toContain("removed@example.net");
      expect(text).not.toContain("fake-access-token");
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
      expect(h.google.revokes()[0]!.form).toEqual({ token: refreshToken });
    });

    it("an id_token whose e-mail is not verified → the same", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor(EMAIL, { email_verified: false }));
      expect(await errorOf(await refresh(refreshToken))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });

    it("removing an address from the allowlist cuts it off at the next refresh", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor(EMAIL));
      expect((await refresh(refreshToken)).status).toBe(200);
      h.env.ALLOWED_EMAILS = "someone-else@example.org";
      expect(await errorOf(await refresh(refreshToken))).toEqual({ status: 403, error: "email_not_allowed" });
      delete h.env.ALLOWED_EMAILS;
      const again = h.google.addRefreshToken(idTokenFor(EMAIL));
      expect(await errorOf(await refresh(again))).toEqual({ status: 403, error: "email_not_allowed" });
    });

    it("an allowed address, or no id_token → 200 and no revoke", async () => {
      const withToken = h.google.addRefreshToken(idTokenFor("ME@example.com"));
      const res = await refresh(withToken);
      expect(res.status).toBe(200);
      expect(Object.keys((await res.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
      expect((await refresh(h.google.addRefreshToken())).status).toBe(200);
      // without an id_token there is nothing to check — also with an empty allowlist
      h.env.ALLOWED_EMAILS = "";
      expect((await refresh(h.google.addRefreshToken())).status).toBe(200);
      expect(h.google.revokes()).toEqual([]);
    });

    it("an id_token that is not Google's for the client that refreshed is ignored", async () => {
      for (const idToken of [
        idTokenFor("removed@example.net", { aud: "another-client" }),
        idTokenFor("removed@example.net", { aud: LEGACY_CLIENT_ID }),
        idTokenFor("removed@example.net", { iss: "https://evil.example" }),
        "garbage",
      ]) {
        expect((await refresh(h.google.addRefreshToken(idToken))).status).toBe(200);
      }
      expect(h.google.revokes()).toEqual([]);
    });
  });

  describe("which client: the device client, or the legacy client of the browser sign-in before 0.2.0", () => {
    const legacyToken = (idToken?: string) => h.google.addRefreshToken(idToken, LEGACY_CLIENT_ID);

    it("no `client` field + legacy secrets → the legacy client's credentials go to Google", async () => {
      h.env = withLegacy();
      const refreshToken = legacyToken();
      const res = await h.post("/refresh", { refresh_token: refreshToken });
      expect(res.status).toBe(200);
      expect(Object.keys((await res.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
      expect(h.google.calls[0]!.form).toEqual({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: LEGACY_CLIENT_ID, client_secret: LEGACY_CLIENT_SECRET });
    });

    it('`client: "device"` → the device client, with or without legacy secrets', async () => {
      h.env = withLegacy();
      const refreshToken = await obtainRefreshToken(h);
      expect((await refresh(refreshToken)).status).toBe(200);
      expect(h.google.calls.at(-1)!.form).toMatchObject({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
    });

    it("no `client` field and no legacy secrets → 400 invalid_grant that says to log in again; Google is not asked", async () => {
      const refreshToken = legacyToken();
      const res = await h.post("/refresh", { refresh_token: refreshToken });
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_grant" });
      expect(((await res.json()) as { message: string }).message).toContain("Run `gclone login` again.");
      // also for a token that is not a legacy one at all: nothing says which client issued it
      expect(await errorOf(await h.post("/refresh", { refresh_token: h.google.addRefreshToken() }))).toEqual({ status: 400, error: "invalid_grant" });
      expect(h.google.calls).toEqual([]);
    });

    it("any other `client` value → 400 invalid_request with zero calls to Google", async () => {
      h.env = withLegacy();
      const refreshToken = legacyToken();
      for (const client of ["legacy", "web", "", "Device", null, 1, true, ["device"], {}]) {
        const res = await h.post("/refresh", { refresh_token: refreshToken, client });
        expect(await errorOf(res), JSON.stringify(client)).toEqual({ status: 400, error: "invalid_request" });
      }
      expect(h.google.calls).toEqual([]);
    });

    it("the allowlist re-check reads an ID token issued for the legacy client", async () => {
      h.env = withLegacy();
      const removed = legacyToken(idTokenFor("removed@example.net", { aud: LEGACY_CLIENT_ID }));
      expect(await errorOf(await h.post("/refresh", { refresh_token: removed }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
      // … and ignores one issued for the device client
      const other = legacyToken(idTokenFor("removed@example.net"));
      expect((await h.post("/refresh", { refresh_token: other })).status).toBe(200);
    });

    it("a login never uses the legacy client", async () => {
      h.env = withLegacy();
      await obtainRefreshToken(h);
      for (const call of h.google.calls) expect(call.form.client_id).toBe(CLIENT_ID);
    });
  });
});

describe("rate limit", () => {
  const limited = async (): Promise<Response[]> => [
    await h.post("/device/start", {}, { "cf-connecting-ip": "203.0.113.7" }),
    await h.post("/device/poll", { device_code: "malformed" }, { "cf-connecting-ip": "203.0.113.7" }),
    await h.post("/refresh", { refresh_token: "malformed" }, { "cf-connecting-ip": "203.0.113.7" }),
  ];

  it("over the limit: the three routes answer 429 with Retry-After: 60 and Google is not contacted", async () => {
    const started = await startLogin(h);
    h.google.approve(started.user_code);
    const refreshToken = h.google.addRefreshToken();
    const callsBefore = h.google.calls.length;
    const limiter = new FakeRateLimiter(false);
    h.env.RATE_LIMIT = limiter;

    // requests that would otherwise succeed and reach Google
    for (const res of [await h.post("/device/start", {}), await poll(h, started.device_code), await refresh(refreshToken)]) {
      expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited" });
      expect(res.headers.get("retry-after")).toBe(String(RATE_LIMIT_RETRY_AFTER_S));
    }
    expect(RATE_LIMIT_RETRY_AFTER_S).toBe(60);
    expect(h.google.calls.length).toBe(callsBefore);
    expect(limiter.keys).toHaveLength(3);

    // the limit comes before the route's own checks, but after path and method
    expect((await errorOf(await h.call("/device/poll", { method: "POST", headers: { "content-type": "text/plain" }, body: "x" }))).error).toBe("rate_limited");
    expect((await errorOf(await h.call("/device/poll", { method: "GET" }))).error).toBe("method_not_allowed");
    expect((await errorOf(await h.get("/nowhere"))).error).toBe("not_found");
    expect(limiter.keys).toHaveLength(4);

    // the login is still there once the limit lets the device through again
    h.env.RATE_LIMIT = new FakeRateLimiter(true);
    expect((await poll(h, started.device_code)).status).toBe(200);
  });

  it("/ and /privacy are never limited", async () => {
    const limiter = new FakeRateLimiter(false);
    h.env.RATE_LIMIT = limiter;
    expect((await h.get("/")).status).toBe(200);
    expect((await h.get("/privacy")).status).toBe(200);
    expect(limiter.keys).toEqual([]);
  });

  it("the binding is asked with a key made from cf-connecting-ip: the IPv4 address, the IPv6 /64, or \"unknown\"", async () => {
    const limiter = new FakeRateLimiter(true);
    h.env.RATE_LIMIT = limiter;
    const answers = await limited();
    expect(answers.map((r) => r.status)).toEqual([200, 400, 400]);
    expect(limiter.keys).toEqual(["203.0.113.7", "203.0.113.7", "203.0.113.7"]);
    await h.post("/refresh", {}, { "cf-connecting-ip": "2001:db8::1", "x-forwarded-for": "198.51.100.1" });
    await h.post("/refresh", {}, { "x-forwarded-for": "198.51.100.1" });
    expect(limiter.keys.slice(3)).toEqual(["2001:db8:0:0::/64", "unknown"]);
  });

  it("one IPv6 host cannot multiply its budget: every address of a /64 shares one key", async () => {
    const limiter = new FakeRateLimiter(true);
    h.env.RATE_LIMIT = limiter;
    // what a VPS with a routed /64 sends: a new source address per request
    const sources = ["2001:db8:5:6::1", "2001:db8:5:6::2", "2001:db8:5:6:ffff:ffff:ffff:ffff", "2001:0db8:0005:0006:1234:5678:9abc:def0", "2001:DB8:5:6:a::"];
    for (const source of sources) {
      await h.post("/device/poll", { device_code: "malformed" }, { "cf-connecting-ip": source });
    }
    expect(new Set(limiter.keys)).toEqual(new Set(["2001:db8:5:6::/64"]));
    expect(limiter.keys).toHaveLength(sources.length);
    // the neighbouring /64 is someone else
    await h.post("/device/poll", { device_code: "malformed" }, { "cf-connecting-ip": "2001:db8:5:7::1" });
    expect(limiter.keys.at(-1)).toBe("2001:db8:5:7::/64");
  });

  it("rateLimitKey: IPv4 as it is, IPv6 as its /64 in one spelling, anything else unchanged", () => {
    const table: Array<[string | null, string]> = [
      [null, "unknown"],
      ["", "unknown"],
      ["203.0.113.7", "203.0.113.7"],
      ["2001:db8::1", "2001:db8:0:0::/64"],
      ["2001:db8:0:0:0:0:0:1", "2001:db8:0:0::/64"],
      ["2001:0DB8:0000:0000:ffff::1", "2001:db8:0:0::/64"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
      ["2001:db8:1:2::", "2001:db8:1:2::/64"],
      ["::1", "0:0:0:0::/64"],
      ["::", "0:0:0:0::/64"],
      ["fe80::1%eth0", "fe80:0:0:0::/64"],
      ["2001:db8:1:2:3:4:192.0.2.1", "2001:db8:1:2::/64"],
      ["64:ff9b::192.0.2.1", "64:ff9b:0:0::/64"],
      ["::ffff:203.0.113.7", "203.0.113.7"], // an IPv4-mapped address is that IPv4 address
      ["::ffff:cb00:7107", "203.0.113.7"],
      // not addresses: the value itself is the key
      ["2001:db8::1::2", "2001:db8::1::2"],
      ["2001:db8:1:2:3:4:5:6:7", "2001:db8:1:2:3:4:5:6:7"],
      ["2001:db8:1:2:3:4:5", "2001:db8:1:2:3:4:5"],
      ["2001:db8::12345", "2001:db8::12345"],
      ["2001:db8::g", "2001:db8::g"],
      ["::ffff:999.0.0.1", "::ffff:999.0.0.1"],
      [":1:2:3:4:5:6:7", ":1:2:3:4:5:6:7"],
      ["unknown", "unknown"],
    ];
    for (const [address, key] of table) expect(rateLimitKey(address), String(address)).toBe(key);
  });

  it("is checked before the configuration", async () => {
    h.env = { GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "", RATE_LIMIT: new FakeRateLimiter(false) };
    expect((await errorOf(await refresh(WELL_FORMED))).error).toBe("rate_limited");
  });

  it("without the binding, or with a binding that throws, nothing is limited", async () => {
    expect(h.env.RATE_LIMIT).toBeUndefined();
    expect((await h.post("/device/start", {})).status).toBe(200);
    const broken = new FakeRateLimiter(false, true);
    h.env.RATE_LIMIT = broken;
    expect((await h.post("/device/start", {})).status).toBe(200);
    expect((await refresh(h.google.addRefreshToken())).status).toBe(200);
    expect(broken.keys).toHaveLength(2);
  });
});

describe("transport rules", () => {
  it("another method on a known path → 405 with Allow, as JSON", async () => {
    for (const path of ["/device/start", "/device/poll", "/refresh"]) {
      for (const method of ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]) {
        const res = await h.call(path, { method });
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("POST");
        if (method !== "HEAD") expect((await errorOf(res)).error).toBe("method_not_allowed");
      }
    }
    for (const path of ["/", "/privacy"]) {
      for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
        const res = await h.call(path, { method, headers: { "content-type": "application/json" }, ...(method === "OPTIONS" ? {} : { body: "{}" }) });
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("GET");
        expect((await errorOf(res)).error).toBe("method_not_allowed");
      }
    }
    expect(h.google.calls).toEqual([]);
    expect(ROUTES).toEqual(["/", "/privacy", "/device/start", "/device/poll", "/refresh"]);
  });

  it("unknown path → 404 not_found — the routes of the browser sign-in included", async () => {
    for (const path of ["/nowhere", "/refresh/", "/device", "/device/", "/device/start/", "/Device/Start", "/device/poll.php", "//", "/favicon.ico", "/.well-known/openid-configuration"]) {
      expect(await errorOf(await h.get(path)), path).toEqual({ status: 404, error: "not_found" });
    }
    for (const path of ["/login", "/login?challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "/callback", "/callback?code=4/0Ajunk&state=x", "/callback?confirmed=x"]) {
      expect(await errorOf(await h.get(path)), path).toEqual({ status: 404, error: "not_found" });
    }
    expect(await errorOf(await h.post("/token", { code: "x", verifier: "y" }))).toEqual({ status: 404, error: "not_found" });
    expect(await errorOf(await h.post("/revoke", { token: "x" }))).toEqual({ status: 404, error: "not_found" });
    expect(h.google.calls).toEqual([]);
  });

  it("a body that is not application/json → 415", async () => {
    const body = JSON.stringify({ refresh_token: h.google.addRefreshToken(), client: "device" });
    for (const contentType of ["text/plain", "application/x-www-form-urlencoded", "application/jsonx", "text/json", "multipart/form-data; boundary=x", ""]) {
      for (const path of ["/refresh", "/device/start", "/device/poll"]) {
        const res = await h.call(path, { method: "POST", headers: contentType === "" ? {} : { "content-type": contentType }, body });
        // a string body without a content type gets text/plain from the Request constructor: 415 either way
        expect(await errorOf(res), `${path} ${contentType}`).toEqual({ status: 415, error: "unsupported_media_type" });
      }
    }
    for (const contentType of ["application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;charset=UTF-8"]) {
      const res = await h.call("/refresh", { method: "POST", headers: { "content-type": contentType }, body });
      expect(res.status, contentType).toBe(200);
    }
    // /device/start reads nothing from its body, and still wants one: a cross-site form cannot start a login
    expect(await errorOf(await h.call("/device/start", { method: "POST" }))).toEqual({ status: 415, error: "unsupported_media_type" });
  });

  it("a body over 8 KiB → 413, by its declared and by its real size", async () => {
    expect(BODY_MAX).toBe(8192);
    const nineKib = { refresh_token: WELL_FORMED, client: "device", device_code: JUNK_DEVICE_CODE, pad: "p".repeat(9 * 1024) };
    for (const path of ["/device/start", "/device/poll", "/refresh"]) {
      expect(await errorOf(await h.post(path, nineKib)), path).toEqual({ status: 413, error: "payload_too_large" });
    }

    // exactly BODY_MAX bytes is read, one more is not; multi-byte characters count as bytes
    const exact = (bytes: number, filler: string) => {
      const frame = JSON.stringify({ refresh_token: WELL_FORMED, client: "device", pad: "" });
      const padBytes = bytes - new TextEncoder().encode(frame).length;
      return JSON.stringify({ refresh_token: WELL_FORMED, client: "device", pad: filler.repeat(padBytes / new TextEncoder().encode(filler).length) });
    };
    h.google.nextAnswer(400, { error: "invalid_grant" });
    const atLimit = exact(BODY_MAX, "p");
    expect(new TextEncoder().encode(atLimit).length).toBe(BODY_MAX);
    expect((await errorOf(await h.call("/refresh", { method: "POST", headers: { "content-type": "application/json" }, body: atLimit }))).error).toBe("invalid_grant");
    const over = exact(BODY_MAX + 1, "p");
    expect((await errorOf(await h.call("/refresh", { method: "POST", headers: { "content-type": "application/json" }, body: over }))).status).toBe(413);
    const multibyte = exact(BODY_MAX + 4, "ü");
    expect(multibyte.length).toBeLessThan(BODY_MAX);
    expect((await errorOf(await h.call("/refresh", { method: "POST", headers: { "content-type": "application/json" }, body: multibyte }))).status).toBe(413);

    // a declared Content-Length over the limit is refused without reading the body
    const declared = await h.call("/refresh", { method: "POST", headers: { "content-type": "application/json", "content-length": "9000" }, body: "{}" });
    expect(await errorOf(declared)).toEqual({ status: 413, error: "payload_too_large" });
    expect(h.google.kinds()).toEqual(["token"]);
  });

  it("invalid JSON, or JSON that is not an object → 400 invalid_request", async () => {
    for (const body of ["", "not json", "{", '{"refresh_token":', "[]", '["a"]', "null", "5", '"text"', "true", "refresh_token=abc"]) {
      for (const path of ["/device/start", "/device/poll", "/refresh"]) {
        const res = await h.call(path, { method: "POST", headers: { "content-type": "application/json" }, body });
        expect(await errorOf(res), `${path} ${JSON.stringify(body)}`).toEqual({ status: 400, error: "invalid_request" });
      }
    }
    const res = await handle(new Request(`${ORIGIN}/refresh`, { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0x7b, 0xff, 0x7d]) }), h.env, h.deps);
    await h.record("/refresh", res);
    expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_request" });
    expect(h.google.calls).toEqual([]);
  });

  it("missing secrets of the device client → 500 server_misconfigured on every route except / and /privacy", async () => {
    const broken: Env[] = [
      testEnv({ GOOGLE_CLIENT_ID: "" }),
      testEnv({ GOOGLE_CLIENT_SECRET: "" }),
      testEnv({ GOOGLE_CLIENT_ID: undefined as unknown as string }),
      testEnv({ GOOGLE_CLIENT_SECRET: undefined as unknown as string }),
      // the legacy pair does not stand in for the device client
      withLegacy({ GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "" }),
      withLegacy({ GOOGLE_CLIENT_SECRET: "" }),
    ];
    for (const env of broken) {
      h.env = env;
      expect(await errorOf(await h.post("/device/start", {}))).toEqual({ status: 500, error: "server_misconfigured" });
      expect(await errorOf(await poll(h, JUNK_DEVICE_CODE))).toEqual({ status: 500, error: "server_misconfigured" });
      expect(await errorOf(await refresh(WELL_FORMED))).toEqual({ status: 500, error: "server_misconfigured" });
      expect(await errorOf(await h.post("/refresh", { refresh_token: WELL_FORMED }))).toEqual({ status: 500, error: "server_misconfigured" });
      // the configuration is checked before the body: also for a request that would be refused anyway
      expect((await errorOf(await h.call("/device/poll", { method: "POST", headers: { "content-type": "text/plain" }, body: "x" }))).error).toBe("server_misconfigured");
      const home = await h.get("/");
      expect(home.status).toBe(200);
      const page = await home.text();
      expect(page).toContain("Status: not configured");
      expect(page).not.toContain("Status: ready");
      expect((await h.get("/privacy")).status).toBe(200);
      // path and method still come first
      expect((await errorOf(await h.get("/nowhere"))).error).toBe("not_found");
      expect((await errorOf(await h.get("/device/poll"))).error).toBe("method_not_allowed");
    }
    expect(h.google.calls).toEqual([]);
    // ALLOWED_EMAILS is not part of "configured", and a SEAL_KEY of an older deployment is simply ignored
    h.env = { ...testEnv(), SEAL_KEY: "left-over" } as Env;
    delete h.env.ALLOWED_EMAILS;
    expect(await (await h.get("/")).text()).toContain("Status: ready");
    expect(await (await handleHome(withLegacy())).text()).toContain("Status: ready");
  });

  it("a half-set legacy pair takes only the legacy client away: logins and device-client refreshes go on", async () => {
    // The state between the two `wrangler secret delete` commands that end the transition from the browser sign-in
    // (each is deployed at once) — and between the two `secret put` commands that begin it.
    const halfSet: Env[] = [
      testEnv({ GOOGLE_LEGACY_CLIENT_ID: LEGACY_CLIENT_ID }),
      testEnv({ GOOGLE_LEGACY_CLIENT_SECRET: LEGACY_CLIENT_SECRET }),
      testEnv({ GOOGLE_LEGACY_CLIENT_ID: LEGACY_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET: "" }),
    ];
    for (const env of halfSet) {
      h.reset();
      h.env = env;
      // a whole login and a refresh of its token: the device client is not affected
      const refreshToken = await obtainRefreshToken(h);
      expect((await refresh(refreshToken)).status).toBe(200);
      for (const call of h.google.calls) expect(call.form.client_id).toBe(CLIENT_ID);
      const before = h.google.calls.length;

      // a login from before 0.2.0 (no `client` field): refused as a misconfiguration that names the pair — not as
      // "log in again", and without asking Google with half a credential
      const legacy = h.google.addRefreshToken(undefined, LEGACY_CLIENT_ID);
      const res = await h.post("/refresh", { refresh_token: legacy });
      expect(await errorOf(res)).toEqual({ status: 500, error: "server_misconfigured" });
      const { message } = (await res.json()) as { message: string };
      expect(message).toContain("GOOGLE_LEGACY_CLIENT_ID");
      expect(message).toContain("GOOGLE_LEGACY_CLIENT_SECRET");
      expect(message).toContain("set both, or delete both");
      expect(message).not.toContain("gclone login");
      expect(h.google.calls.length).toBe(before);
      // the pre-filter and the `client` check still come first
      expect((await errorOf(await h.post("/refresh", { refresh_token: "malformed" }))).error).toBe("invalid_request");
      expect((await errorOf(await h.post("/refresh", { refresh_token: legacy, client: "web" }))).error).toBe("invalid_request");

      // the home page: ready, with a warning that names the half-set pair
      const page = await (await h.get("/")).text();
      expect(page).toContain("Status: ready");
      expect(page).toContain("Warning: only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set");
      expect(page).not.toContain("not configured");
      expect(page).not.toContain(LEGACY_CLIENT_ID);
    }
    // a complete pair, or none: no warning
    for (const env of [testEnv(), withLegacy()]) {
      const page = await (await handleHome(env)).text();
      expect(page).toContain("Status: ready");
      expect(page).not.toContain("Warning");
    }
  });

  it("no CORS, no cookies; every answer is no-store; the two pages carry the CSP and nothing dynamic", async () => {
    const refreshToken = await obtainRefreshToken(h);
    const started = await startLogin(h);
    const cors = { origin: "https://evil.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type" };
    const answers = [
      await h.get("/", cors),
      await h.get("/privacy", cors),
      await h.get("/?user_code=<script>alert(1)</script>", cors),
      await h.get("/nowhere", cors),
      await h.get("/login", cors),
      await h.call("/device/start", { method: "OPTIONS", headers: cors }),
      await h.call("/device/poll", { method: "OPTIONS", headers: cors }),
      await h.call("/refresh", { method: "OPTIONS", headers: cors }),
      await h.post("/device/start", {}, cors),
      await h.post("/device/poll", { device_code: started.device_code }, cors),
      await h.post("/refresh", { refresh_token: refreshToken, client: "device" }, cors),
      await h.post("/refresh", {}, cors),
    ];
    for (const res of answers) {
      const names = [...res.headers.keys()];
      expect(names.filter((n) => n.startsWith("access-control-"))).toEqual([]);
      expect(names).not.toContain("set-cookie");
      expect(names).not.toContain("vary");
      expect(names).not.toContain("location");
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      const type = res.headers.get("content-type");
      if (type === "text/html; charset=utf-8") {
        expect(res.headers.get("content-security-policy")).toBe(HTML_CSP);
        expect(res.headers.get("x-frame-options")).toBe("DENY");
        expect(res.headers.get("referrer-policy")).toBe("no-referrer");
        const page = await res.text();
        expect(page).not.toContain("<script");
        expect(page).not.toContain("<form");
        expect(page).not.toContain("user_code");
      } else {
        expect(type).toBe("application/json; charset=utf-8");
      }
    }
    expect(answers.map((r) => r.status)).toEqual([200, 200, 200, 404, 404, 405, 405, 405, 200, 400, 200, 400]);
    expect(answers.slice(0, 3).map((r) => r.headers.get("content-type"))).toEqual(Array(3).fill("text/html; charset=utf-8"));
  });

  it("never throws: an unexpected failure becomes a 500 without detail", async () => {
    const exploding = new Proxy(testEnv(), {
      get(target, key) {
        if (key === "ALLOWED_EMAILS") throw new Error("env exploded: test-detail");
        return Reflect.get(target, key);
      },
    });
    h.env = exploding;
    const started = await startLogin(h);
    h.google.approve(started.user_code);
    const res = await poll(h, started.device_code);
    expect(res.status).toBe(500);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(JSON.stringify(await res.json())).not.toContain("test-detail");
    expect(h.logs.map((l) => JSON.parse(l))).toEqual([
      { route: "/device/start", status: 200 },
      { route: "/device/poll", status: 500, error: "internal_error" },
    ]);
  });
});

/** GET / with an env of its own (the harness's env stays as it is). */
async function handleHome(env: Env): Promise<Response> {
  const res = await handle(new Request(`${ORIGIN}/`), env, h.deps);
  await h.record("/", res);
  return res;
}

describe("logging", () => {
  it("one line per request with route, status and error code — and nothing else", async () => {
    const refreshToken = await obtainRefreshToken(h); // /device/start, /device/poll
    await refresh(refreshToken);
    await h.get("/");
    await h.get(`/some/secret/path?device_code=${JUNK_DEVICE_CODE}`);
    const started = await startLogin(h);
    await poll(h, started.device_code);
    h.google.set(started.user_code, "denied");
    await poll(h, started.device_code);
    await h.post("/device/poll", { device_code: "x" });
    await h.get("/device/poll");
    h.google.nextAnswer(503, "down");
    await refresh(refreshToken);
    await h.post("/refresh", { refresh_token: refreshToken });
    expect(h.logs.map((l) => JSON.parse(l))).toEqual([
      { route: "/device/start", status: 200 },
      { route: "/device/poll", status: 200 },
      { route: "/refresh", status: 200 },
      { route: "/", status: 200 },
      { route: "other", status: 404, error: "not_found" },
      { route: "/device/start", status: 200 },
      { route: "/device/poll", status: 400, error: "authorization_pending" },
      { route: "/device/poll", status: 403, error: "access_denied" },
      { route: "/device/poll", status: 400, error: "invalid_request" },
      { route: "/device/poll", status: 405, error: "method_not_allowed" },
      { route: "/refresh", status: 502, error: "upstream_error" },
      { route: "/refresh", status: 400, error: "invalid_grant" },
    ]);
  });

  it("revokeToken never throws and never logs", async () => {
    const failing = { ...h.deps, fetch: async () => Promise.reject(new TypeError("down")) };
    await expect(revokeToken(failing, WELL_FORMED)).resolves.toBeUndefined();
    const throwing = {
      ...h.deps,
      fetch: () => {
        throw new TypeError("down");
      },
    };
    await expect(revokeToken(throwing, WELL_FORMED)).resolves.toBeUndefined();
    expect(h.logs).toEqual([]);
  });
});

// The only tests that do not inject `deps`: they must run in the Workers runtime, where `fetch` checks its `this`.
describe("the production wiring", () => {
  it("defaultDeps.google is the three Google URLs of §2.2", () => {
    expect(defaultDeps.google).toEqual({
      deviceCodeUrl: "https://oauth2.googleapis.com/device/code",
      tokenUrl: "https://oauth2.googleapis.com/token",
      revokeUrl: "https://oauth2.googleapis.com/revoke",
    });
    expect([GOOGLE_DEVICE_CODE_URL, GOOGLE_TOKEN_URL, GOOGLE_REVOKE_URL]).toEqual(Object.values(defaultDeps.google));
  });

  it("defaultDeps.fetch can be called as a property: no 'Illegal invocation'", async () => {
    const outcome = async (call: () => Promise<Response>): Promise<string> => {
      try {
        const res = await call();
        await res.body?.cancel();
        return `answered ${res.status}`;
      } catch (e) {
        return `failed: ${e instanceof Error ? e.message : String(e)}`;
      }
    };
    // Nothing listens on the discard port: the request fails in the network, not in the call.
    // (workerd reports that failure on stderr as "uncaught exception … Network connection lost" — expected noise.)
    const viaDeps = await outcome(() => defaultDeps.fetch("http://127.0.0.1:9/"));
    expect(viaDeps).toMatch(/^failed: /);
    expect(viaDeps).not.toContain("Illegal invocation");
    // The control: this runtime does reject a bare `fetch` stored in an object — the mistake the wrapper prevents.
    const bare = { fetch };
    expect(await outcome(async () => bare.fetch("http://127.0.0.1:9/"))).toContain("Illegal invocation");
  });

  it("one request through the default export returns the home page", async () => {
    const res = await worker.fetch(new Request("https://auth.test/"), testEnv());
    await h.record("/", res);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toContain("Status: ready");
  });
});
