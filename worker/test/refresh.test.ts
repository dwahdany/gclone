import { describe, expect, it } from "vitest";
import worker, {
  BODY_MAX,
  GOOGLE_AUTH_URL,
  GOOGLE_REVOKE_URL,
  GOOGLE_TOKEN_URL,
  GRANT_TTL_S,
  RATE_LIMIT_RETRY_AFTER_S,
  STATE_TTL_S,
  defaultDeps,
  handle,
  rateLimitKey,
  type Env,
} from "../src/index";
import { REFRESH_TOKEN_RE, revokeToken } from "../src/google";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  EMAIL,
  FakeRateLimiter,
  GOOGLE,
  GRANTED_SCOPE,
  ORIGIN,
  VERIFIER,
  WIDE_SCOPE,
  callbackAndConfirm,
  errorOf,
  finishLink,
  loginPath,
  makeIdToken,
  newGoogleCode,
  obtainGrant,
  obtainRefreshToken,
  startLogin,
  testEnv,
  useHarness,
} from "./helpers";

const h = useHarness();
const HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const JUNK_CODE = "4/0AjunkjunkjunkjunkjunkjunkQ";

function idTokenFor(email: string, over: Record<string, unknown> = {}): string {
  return makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "1234567890", email, email_verified: true, ...over });
}

describe("POST /refresh", () => {
  it("happy path: the exact form goes to Google and the exact JSON comes back", async () => {
    const refreshToken = h.google.addRefreshToken();
    const res = await h.post("/refresh", { refresh_token: refreshToken, unknown: 1 });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({ access_token: "ya29.fake-access-token-2", expires_in: 3599, scope: GRANTED_SCOPE });
    expect(h.google.calls).toHaveLength(1);
    const call = h.google.calls[0]!;
    expect(call).toMatchObject({ kind: "token", url: GOOGLE.tokenUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    expect(call.form).toEqual({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
  });

  it("the full flow: /login → confirmation page → Google → /callback → second confirmation page → /token → /refresh", async () => {
    // the browser: the device's URL, then the one link on the confirmation page
    const { link, state, nonce } = await startLogin(h);
    expect(link.origin + link.pathname).toBe(GOOGLE.authUrl);
    // Google: the user consents; the code is issued for the nonce Google received
    const code = newGoogleCode();
    h.google.consent(code, { nonce });
    // Google redirects the browser back; the Worker shows the check code again and hands out nothing yet
    const confirmation = await h.get(`/callback?${new URLSearchParams({ code, state })}`);
    expect(await confirmation.clone().text()).toContain("D2KC-JCJY");
    // the user compares it with the terminal and follows the page's link: now the Worker redirects to the device's loopback listener
    const back = await h.get(await finishLink(confirmation));
    expect(back.status).toBe(302);
    const loopback = new URL(back.headers.get("location")!);
    expect(loopback.origin).toBe("http://127.0.0.1:8123");
    // the device: redeem the grant with its verifier, then use the refresh token
    const tokenRes = await h.post("/token", { code: loopback.searchParams.get("code"), verifier: VERIFIER });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { refresh_token: string; email: string };
    expect(tokens.email).toBe(EMAIL);
    expect(REFRESH_TOKEN_RE.test(tokens.refresh_token)).toBe(true);
    const refreshRes = await h.post("/refresh", { refresh_token: tokens.refresh_token });
    expect(refreshRes.status).toBe(200);
    expect(Object.keys((await refreshRes.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
    expect(h.google.kinds()).toEqual(["token", "token"]);
  });

  it("two logins yield two refresh tokens that both refresh", async () => {
    const first = await obtainRefreshToken(h);
    const second = await obtainRefreshToken(h);
    expect(second).not.toBe(first);
    expect((await h.post("/refresh", { refresh_token: first })).status).toBe(200);
    expect((await h.post("/refresh", { refresh_token: second })).status).toBe(200);
  });

  it("maps Google's error answers", async () => {
    const table: Array<[number, unknown, number, string]> = [
      [400, { error: "invalid_grant", error_description: "Token has been expired or revoked." }, 400, "invalid_grant"],
      [401, { error: "invalid_client" }, 500, "client_invalid"],
      [401, { error: "deleted_client" }, 500, "client_invalid"],
      [401, { error: "unauthorized_client" }, 500, "client_invalid"],
      [400, { error: "redirect_uri_mismatch" }, 500, "client_invalid"],
      [403, { error: "access_denied" }, 403, "access_denied"],
      [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
      [403, { error: "org_internal" }, 403, "access_denied"],
      [400, { error: "invalid_scope" }, 502, "upstream_error"],
      [503, { error: "backend_error" }, 502, "upstream_error"],
      [500, "Internal Server Error", 502, "upstream_error"],
      [200, "<html></html>", 502, "upstream_error"],
      [200, { expires_in: 3599, scope: GRANTED_SCOPE }, 502, "upstream_error"],
      [200, { access_token: "ya29.x", expires_in: "3599" }, 502, "upstream_error"],
    ];
    for (const [googleStatus, googleBody, status, error] of table) {
      const refreshToken = h.google.addRefreshToken();
      h.google.nextTokenAnswer(googleStatus, googleBody);
      const res = await h.post("/refresh", { refresh_token: refreshToken });
      expect(await errorOf(res), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
    }
    const refreshToken = h.google.addRefreshToken();
    h.google.nextTokenThrows(new TypeError("network connection lost"));
    expect(await errorOf(await h.post("/refresh", { refresh_token: refreshToken }))).toEqual({ status: 502, error: "upstream_error" });
    expect(h.google.revokes()).toEqual([]);
  });

  it("a revoked refresh token → 400 invalid_grant", async () => {
    const refreshToken = await obtainRefreshToken(h);
    h.google.revokeAll();
    expect(await errorOf(await h.post("/refresh", { refresh_token: refreshToken }))).toEqual({ status: 400, error: "invalid_grant" });
  });

  it("a malformed refresh token → 400 invalid_request with zero calls to Google", async () => {
    const bad: unknown[] = [
      {},
      { refresh_token: 5 },
      { refresh_token: null },
      { refresh_token: ["1//0abcdefghijklmnopqrstuv"] },
      { refresh_token: "" },
      { refresh_token: "r".repeat(19) },
      { refresh_token: "r".repeat(513) },
      { refresh_token: "1//0abcdefghij klmnopqrstuv" },
      { refresh_token: '1//0abcdefghij"klmnopqrstuv' },
      { refresh_token: "1//0abcdefghij'klmnopqrstuv" },
      { refresh_token: "1//0abcdefghij&client_id=x" },
      { refresh_token: "1//0abcdefghij\nklmnopqrstuv" },
      { refresh_token: "1//0abcdefghij%20klmnopqrst" },
      { token: "1//0abcdefghijklmnopqrstuv" },
    ];
    for (const body of bad) {
      expect(await errorOf(await h.post("/refresh", body)), JSON.stringify(body).slice(0, 60)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect(h.google.calls).toEqual([]);
    // 20 and 512 characters of the allowed set do reach Google
    for (const token of ["r".repeat(20), "r".repeat(512), "1//0A_-.~+=/abcdefghijklm"]) {
      expect(REFRESH_TOKEN_RE.test(token)).toBe(true);
      h.google.nextTokenAnswer(400, { error: "invalid_grant" });
      expect(await errorOf(await h.post("/refresh", { refresh_token: token }))).toEqual({ status: 400, error: "invalid_grant" });
    }
    expect(h.google.kinds()).toEqual(["token", "token", "token"]);
  });

  describe("scope re-check", () => {
    const refreshWith = async (scope: unknown): Promise<Response> => {
      const refreshToken = h.google.addRefreshToken();
      const body: Record<string, unknown> = { access_token: "ya29.scoped-access-token", expires_in: 3599, token_type: "Bearer" };
      if (scope !== undefined) body.scope = scope;
      h.google.accessTokens.add("ya29.scoped-access-token");
      h.google.nextTokenAnswer(200, body);
      return h.post("/refresh", { refresh_token: refreshToken });
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
      h.google.nextTokenAnswer(200, { access_token: "ya29.scoped-access-token", expires_in: 3599, scope: WIDE_SCOPE, id_token: idTokenFor("removed@example.net") });
      expect(await errorOf(await h.post("/refresh", { refresh_token: refreshToken }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });
  });

  describe("allowlist re-check", () => {
    it("an id_token for an address outside ALLOWED_EMAILS → 403 email_not_allowed plus one revoke", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor("removed@example.net"));
      const res = await h.post("/refresh", { refresh_token: refreshToken });
      expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
      const text = await res.text();
      expect(text).toContain("removed@example.net");
      expect(text).not.toContain("fake-access-token");
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
      expect(h.google.revokes()[0]!.form).toEqual({ token: refreshToken });
    });

    it("an id_token whose e-mail is not verified → the same", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor(EMAIL, { email_verified: false }));
      expect(await errorOf(await h.post("/refresh", { refresh_token: refreshToken }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });

    it("removing an address from the allowlist cuts it off at the next refresh", async () => {
      const refreshToken = h.google.addRefreshToken(idTokenFor(EMAIL));
      expect((await h.post("/refresh", { refresh_token: refreshToken })).status).toBe(200);
      h.env.ALLOWED_EMAILS = "someone-else@example.org";
      expect(await errorOf(await h.post("/refresh", { refresh_token: refreshToken }))).toEqual({ status: 403, error: "email_not_allowed" });
      delete h.env.ALLOWED_EMAILS;
      const again = h.google.addRefreshToken(idTokenFor(EMAIL));
      expect(await errorOf(await h.post("/refresh", { refresh_token: again }))).toEqual({ status: 403, error: "email_not_allowed" });
    });

    it("an allowed address, or no id_token → 200 and no revoke", async () => {
      const withToken = h.google.addRefreshToken(idTokenFor("ME@example.com"));
      const res = await h.post("/refresh", { refresh_token: withToken });
      expect(res.status).toBe(200);
      expect(Object.keys((await res.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
      expect((await h.post("/refresh", { refresh_token: h.google.addRefreshToken() })).status).toBe(200);
      // without an id_token there is nothing to check — also with an empty allowlist
      h.env.ALLOWED_EMAILS = "";
      expect((await h.post("/refresh", { refresh_token: h.google.addRefreshToken() })).status).toBe(200);
      expect(h.google.revokes()).toEqual([]);
    });

    it("an id_token that is not Google's for this client is ignored", async () => {
      for (const idToken of [
        idTokenFor("removed@example.net", { aud: "another-client" }),
        idTokenFor("removed@example.net", { iss: "https://evil.example" }),
        "garbage",
      ]) {
        expect((await h.post("/refresh", { refresh_token: h.google.addRefreshToken(idToken) })).status).toBe(200);
      }
      expect(h.google.revokes()).toEqual([]);
    });
  });
});

describe("rate limit", () => {
  const limited = async (): Promise<Response[]> => [
    await h.get(loginPath(), { "cf-connecting-ip": "203.0.113.7" }),
    await h.get(`/callback?code=${JUNK_CODE}&state=x`, { "cf-connecting-ip": "203.0.113.7" }),
    await h.post("/token", { code: "x", verifier: VERIFIER }, { "cf-connecting-ip": "203.0.113.7" }),
    await h.post("/refresh", { refresh_token: "malformed" }, { "cf-connecting-ip": "203.0.113.7" }),
  ];

  it("over the limit: the four routes answer 429 with Retry-After: 60 and Google is not contacted", async () => {
    const grant = await obtainGrant(h);
    const refreshToken = await obtainRefreshToken(h);
    const callsBefore = h.google.calls.length;
    const limiter = new FakeRateLimiter(false);
    h.env.RATE_LIMIT = limiter;

    const [login, callback] = await limited();
    for (const res of [login!, callback!]) {
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe("60");
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(res.headers.get("content-security-policy")).toBe(HTML_CSP);
      expect(res.headers.get("location")).toBeNull();
      expect(await res.text()).not.toContain("href=");
    }
    // requests that would otherwise succeed and reach Google
    for (const res of [await h.post("/token", { code: grant, verifier: VERIFIER }), await h.post("/refresh", { refresh_token: refreshToken })]) {
      expect(await errorOf(res)).toEqual({ status: 429, error: "rate_limited" });
      expect(res.headers.get("retry-after")).toBe(String(RATE_LIMIT_RETRY_AFTER_S));
    }
    expect(RATE_LIMIT_RETRY_AFTER_S).toBe(60);
    expect(h.google.calls.length).toBe(callsBefore);
    expect(limiter.keys).toHaveLength(6);

    // the limit comes before the method's own checks, but after path and method
    expect((await errorOf(await h.call("/token", { method: "POST", headers: { "content-type": "text/plain" }, body: "x" }))).error).toBe("rate_limited");
    expect((await errorOf(await h.call("/token", { method: "GET" }))).error).toBe("method_not_allowed");
    expect((await errorOf(await h.get("/nowhere"))).error).toBe("not_found");
    expect(limiter.keys).toHaveLength(7);
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
    expect(answers.map((r) => r.status)).toEqual([200, 400, 400, 400]);
    expect(limiter.keys).toEqual(["203.0.113.7", "203.0.113.7", "203.0.113.7", "203.0.113.7"]);
    await h.get(loginPath(), { "cf-connecting-ip": "2001:db8::1", "x-forwarded-for": "198.51.100.1" });
    await h.get(loginPath(), { "x-forwarded-for": "198.51.100.1" });
    expect(limiter.keys.slice(4)).toEqual(["2001:db8:0:0::/64", "unknown"]);
  });

  it("one IPv6 host cannot multiply its budget: every address of a /64 shares one key", async () => {
    const limiter = new FakeRateLimiter(true);
    h.env.RATE_LIMIT = limiter;
    // what a VPS with a routed /64 sends: a new source address per request, each one a well-formed junk refresh token
    const sources = ["2001:db8:5:6::1", "2001:db8:5:6::2", "2001:db8:5:6:ffff:ffff:ffff:ffff", "2001:0db8:0005:0006:1234:5678:9abc:def0", "2001:DB8:5:6:a::"];
    for (const source of sources) {
      await h.post("/refresh", { refresh_token: "malformed" }, { "cf-connecting-ip": source });
    }
    expect(new Set(limiter.keys)).toEqual(new Set(["2001:db8:5:6::/64"]));
    expect(limiter.keys).toHaveLength(sources.length);
    // the neighbouring /64 is someone else
    await h.post("/refresh", { refresh_token: "malformed" }, { "cf-connecting-ip": "2001:db8:5:7::1" });
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
    h.env = { GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "", SEAL_KEY: "", RATE_LIMIT: new FakeRateLimiter(false) };
    expect((await errorOf(await h.post("/refresh", { refresh_token: "1//0abcdefghijklmnopqrstuv" }))).error).toBe("rate_limited");
  });

  it("without the binding, or with a binding that throws, nothing is limited", async () => {
    expect(h.env.RATE_LIMIT).toBeUndefined();
    expect((await h.get(loginPath())).status).toBe(200);
    const broken = new FakeRateLimiter(false, true);
    h.env.RATE_LIMIT = broken;
    expect((await h.get(loginPath())).status).toBe(200);
    expect((await h.post("/refresh", { refresh_token: h.google.addRefreshToken() })).status).toBe(200);
    expect(broken.keys).toHaveLength(2);
  });
});

describe("transport rules", () => {
  it("another method on a known path → 405 with Allow", async () => {
    for (const path of ["/token", "/refresh"]) {
      for (const method of ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]) {
        const res = await h.call(path, { method });
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("POST");
        if (method !== "HEAD") expect((await errorOf(res)).error).toBe("method_not_allowed");
      }
    }
    for (const path of ["/", "/privacy", "/login", "/callback"]) {
      for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) {
        const res = await h.call(path, { method, headers: { "content-type": "application/json" }, ...(method === "OPTIONS" ? {} : { body: "{}" }) });
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("GET");
        expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      }
    }
    expect(h.google.calls).toEqual([]);
  });

  it("unknown path → 404 not_found", async () => {
    for (const path of ["/nowhere", "/token/", "/login/x", "/Token", "/callback.php", "//", "/favicon.ico", "/.well-known/openid-configuration"]) {
      expect(await errorOf(await h.get(path)), path).toEqual({ status: 404, error: "not_found" });
    }
    expect(await errorOf(await h.post("/revoke", { token: "x" }))).toEqual({ status: 404, error: "not_found" });
  });

  it("a body that is not application/json → 415", async () => {
    const body = JSON.stringify({ refresh_token: h.google.addRefreshToken() });
    for (const contentType of ["text/plain", "application/x-www-form-urlencoded", "application/jsonx", "text/json", "multipart/form-data; boundary=x", ""]) {
      const res = await h.call("/refresh", { method: "POST", headers: contentType === "" ? {} : { "content-type": contentType }, body });
      // a string body without a content type gets text/plain from the Request constructor: 415 either way
      expect(await errorOf(res), contentType).toEqual({ status: 415, error: "unsupported_media_type" });
    }
    for (const contentType of ["application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;charset=UTF-8"]) {
      const res = await h.call("/refresh", { method: "POST", headers: { "content-type": contentType }, body });
      expect(res.status, contentType).toBe(200);
    }
  });

  it("a body over 8 KiB → 413, by its declared and by its real size", async () => {
    expect(BODY_MAX).toBe(8192);
    const nineKib = JSON.stringify({ refresh_token: "1//0abcdefghijklmnopqrstuv", pad: "p".repeat(9 * 1024) });
    expect(await errorOf(await h.post("/token", JSON.parse(nineKib)))).toEqual({ status: 413, error: "payload_too_large" });
    expect(await errorOf(await h.post("/refresh", JSON.parse(nineKib)))).toEqual({ status: 413, error: "payload_too_large" });

    // exactly BODY_MAX bytes is read, one more is not; multi-byte characters count as bytes
    const exact = (bytes: number, filler: string) => {
      const frame = JSON.stringify({ refresh_token: "1//0abcdefghijklmnopqrstuv", pad: "" });
      const padBytes = bytes - new TextEncoder().encode(frame).length;
      return JSON.stringify({ refresh_token: "1//0abcdefghijklmnopqrstuv", pad: filler.repeat(padBytes / new TextEncoder().encode(filler).length) });
    };
    h.google.nextTokenAnswer(400, { error: "invalid_grant" });
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
    for (const body of ["", "not json", "{", '{"refresh_token":', "[]", '["a"]', "null", "5", '"text"', "true", "refresh_token=abc", "﻿{}"]) {
      for (const path of ["/token", "/refresh"]) {
        const res = await h.call(path, { method: "POST", headers: { "content-type": "application/json" }, body });
        expect(await errorOf(res), `${path} ${JSON.stringify(body)}`).toEqual({ status: 400, error: "invalid_request" });
      }
    }
    const res = await handle(new Request(`${ORIGIN}/refresh`, { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([0x7b, 0xff, 0x7d]) }), h.env, h.deps);
    await h.record("/refresh", res);
    expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_request" });
    expect(h.google.calls).toEqual([]);
  });

  it("missing secrets → 500 server_misconfigured on every route except / and /privacy", async () => {
    const broken: Array<Partial<Env>> = [
      { GOOGLE_CLIENT_ID: "" },
      { GOOGLE_CLIENT_SECRET: "" },
      { SEAL_KEY: "" },
      { SEAL_KEY: "not-a-key" },
      { GOOGLE_CLIENT_ID: undefined as unknown as string },
      { GOOGLE_CLIENT_SECRET: undefined as unknown as string },
      { SEAL_KEY: undefined as unknown as string },
    ];
    for (const over of broken) {
      h.env = testEnv(over);
      for (const res of [await h.get(loginPath()), await h.get(`/callback?code=${JUNK_CODE}&state=x`)]) {
        expect(res.status).toBe(500);
        expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
        expect(res.headers.get("location")).toBeNull();
      }
      expect(await errorOf(await h.post("/token", { code: "x", verifier: VERIFIER }))).toEqual({ status: 500, error: "server_misconfigured" });
      expect(await errorOf(await h.post("/refresh", { refresh_token: "1//0abcdefghijklmnopqrstuv" }))).toEqual({ status: 500, error: "server_misconfigured" });
      // the configuration is checked before the body: also for a request that would be refused anyway
      expect((await errorOf(await h.call("/token", { method: "POST", headers: { "content-type": "text/plain" }, body: "x" }))).error).toBe("server_misconfigured");
      const home = await h.get("/");
      expect(home.status).toBe(200);
      const page = await home.text();
      expect(page).toContain("Status: not configured");
      expect(page).not.toContain("Status: ready");
      expect((await h.get("/privacy")).status).toBe(200);
      // path and method still come first
      expect((await errorOf(await h.get("/nowhere"))).error).toBe("not_found");
      expect((await errorOf(await h.get("/token"))).error).toBe("method_not_allowed");
    }
    expect(h.google.calls).toEqual([]);
  });

  it("no CORS, no cookies; JSON answers are no-store; HTML answers carry the CSP", async () => {
    const refreshToken = await obtainRefreshToken(h);
    const { state } = await startLogin(h);
    const pasteState = (await startLogin(h, { paste: true })).state;
    const cors = { origin: "https://evil.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type" };
    const answers = [
      await h.get("/", cors),
      await h.get("/privacy", cors),
      await h.get(loginPath(), cors),
      await h.get("/login", cors),
      await h.get(`/callback?${new URLSearchParams({ code: JUNK_CODE, state })}`, cors),
      await callbackAndConfirm(h, String(new URLSearchParams({ code: JUNK_CODE, state })), { headers: cors }),
      await callbackAndConfirm(h, String(new URLSearchParams({ code: JUNK_CODE, state: pasteState })), { headers: cors }),
      await h.get("/callback?state=x", cors),
      await h.get("/callback?confirmed=x", cors),
      await h.get("/nowhere", cors),
      await h.call("/token", { method: "OPTIONS", headers: cors }),
      await h.call("/refresh", { method: "OPTIONS", headers: cors }),
      await h.post("/token", { code: "x", verifier: VERIFIER }, cors),
      await h.post("/refresh", { refresh_token: refreshToken }, cors),
      await h.post("/refresh", {}, cors),
    ];
    for (const res of answers) {
      const names = [...res.headers.keys()];
      expect(names.filter((n) => n.startsWith("access-control-"))).toEqual([]);
      expect(names).not.toContain("set-cookie");
      expect(names).not.toContain("vary");
      expect(res.headers.get("cache-control")).toBe("no-store");
      const type = res.headers.get("content-type");
      if (res.status === 302) {
        expect(type).toBeNull();
        expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      } else if (type === "text/html; charset=utf-8") {
        expect(res.headers.get("content-security-policy")).toBe(HTML_CSP);
        expect(res.headers.get("x-frame-options")).toBe("DENY");
        expect(res.headers.get("x-content-type-options")).toBe("nosniff");
        expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      } else {
        expect(type).toBe("application/json; charset=utf-8");
      }
    }
    expect(answers.map((r) => r.status)).toEqual([200, 200, 200, 400, 200, 302, 200, 400, 400, 404, 405, 405, 400, 200, 400]);
  });

  it("never throws: an unexpected failure becomes a 500 without detail", async () => {
    h.deps.now = () => {
      throw new Error("clock exploded: test-detail");
    };
    const page = await h.get(loginPath());
    expect(page.status).toBe(500);
    expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await page.text()).not.toContain("test-detail");
    const res = await h.post("/refresh", { refresh_token: "1//0abcdefghijklmnopqrstuv" });
    expect(res.status).toBe(500);
    expect(JSON.stringify(await res.json())).not.toContain("test-detail");
    expect(h.logs.map((l) => JSON.parse(l))).toEqual([
      { route: "/login", status: 500, error: "internal_error" },
      { route: "/refresh", status: 500, error: "internal_error" },
    ]);
  });
});

describe("logging", () => {
  it("one line per request with route, status and error code — and nothing else", async () => {
    const refreshToken = await obtainRefreshToken(h); // /login, /callback twice, /token
    await h.post("/refresh", { refresh_token: refreshToken });
    await h.get("/");
    await h.get(`/some/secret/path?code=${JUNK_CODE}`);
    await h.get(`/callback?code=${JUNK_CODE}&state=bad`);
    await h.post("/token", { code: "x", verifier: VERIFIER });
    await h.get("/token");
    h.google.nextTokenAnswer(503, "down");
    await h.post("/refresh", { refresh_token: refreshToken });
    expect(h.logs.map((l) => JSON.parse(l))).toEqual([
      { route: "/login", status: 200 },
      { route: "/callback", status: 200 },
      { route: "/callback", status: 302 },
      { route: "/token", status: 200 },
      { route: "/refresh", status: 200 },
      { route: "/", status: 200 },
      { route: "other", status: 404, error: "not_found" },
      { route: "/callback", status: 400, error: "invalid_request" },
      { route: "/token", status: 400, error: "invalid_grant" },
      { route: "/token", status: 405, error: "method_not_allowed" },
      { route: "/refresh", status: 502, error: "upstream_error" },
    ]);
  });

  it("revokeToken never throws and never logs", async () => {
    const failing = { ...h.deps, fetch: async () => Promise.reject(new TypeError("down")) };
    await expect(revokeToken(failing, "1//0abcdefghijklmnopqrstuv")).resolves.toBeUndefined();
    const throwing = {
      ...h.deps,
      fetch: () => {
        throw new TypeError("down");
      },
    };
    await expect(revokeToken(throwing, "1//0abcdefghijklmnopqrstuv")).resolves.toBeUndefined();
    expect(h.logs).toEqual([]);
  });
});

// The only tests that do not inject `deps`: they must run in the Workers runtime, where `fetch` checks its `this`.
describe("the production wiring", () => {
  it("defaultDeps.google is the three Google URLs of §2.2", () => {
    expect(defaultDeps.google).toEqual({
      authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenUrl: "https://oauth2.googleapis.com/token",
      revokeUrl: "https://oauth2.googleapis.com/revoke",
    });
    expect([GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL, GOOGLE_REVOKE_URL]).toEqual(Object.values(defaultDeps.google));
    expect([STATE_TTL_S, GRANT_TTL_S]).toEqual([600, 120]);
  });

  it("defaultDeps.now() is the wall clock", () => {
    expect(Math.abs(defaultDeps.now() - Date.now())).toBeLessThan(1000);
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
