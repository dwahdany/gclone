import { describe, expect, it } from "vitest";
import {
  ALLOWED_SCOPES,
  DEFAULT_POLL_INTERVAL_S,
  DEVICE_CODE_RE,
  SCOPES as WORKER_SCOPES,
  allowedEmails,
  claimsFromGoogle,
  configuredClients,
  emailAllowed,
  excessScopes,
  idTokenClaims,
  maskedEmail,
} from "../src/google";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  DEVICE_GRANT,
  EMAIL,
  GOOGLE,
  GRANTED_SCOPE,
  WEB_CLIENT_ID,
  SCOPES,
  VERIFICATION_URL,
  WIDE_SCOPE,
  errorOf,
  login,
  makeIdToken,
  poll,
  startLogin,
  testEnv,
  useHarness,
  withWeb,
  type Consent,
} from "./helpers";

const h = useHarness();

describe("POST /device/start", () => {
  it("happy path: the exact form goes to Google and Google's answer comes back", async () => {
    const res = await h.post("/device/start", { scope: "https://www.googleapis.com/auth/drive", client_id: "x", anything: 1 });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      device_code: "AH-1Ng-fake_device.code/1",
      user_code: "FAKE-0001",
      verification_url: VERIFICATION_URL,
      expires_in: 1800,
      interval: 5,
    });
    expect(h.google.calls).toHaveLength(1);
    const call = h.google.calls[0]!;
    expect(call).toMatchObject({ kind: "device_code", url: GOOGLE.deviceCodeUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    // Nothing of the request reaches Google: the client and the scope are the Worker's own, and no secret is sent.
    expect(call.form).toEqual({ client_id: CLIENT_ID, scope: SCOPES });
    expect(WORKER_SCOPES).toBe("openid email https://www.googleapis.com/auth/drive.file");
  });

  it("every start is a login of its own", async () => {
    const [a, b] = [await startLogin(h), await startLogin(h)];
    expect(a.device_code).not.toBe(b.device_code);
    expect(a.user_code).not.toBe(b.user_code);
    expect(DEVICE_CODE_RE.test(a.device_code)).toBe(true);
  });

  it("the web client is never used to start a login", async () => {
    h.env = withWeb();
    await startLogin(h);
    expect(h.google.calls[0]!.form.client_id).toBe(CLIENT_ID);
  });

  it("an answer of Google that is not a device code → 502, and nothing of it is passed on", async () => {
    const good = { device_code: "AH-1Ng-fake_device.code/9", user_code: "ABCD-EFGH", verification_url: VERIFICATION_URL, expires_in: 1800, interval: 5 };
    const bad: unknown[] = [
      { ...good, device_code: undefined },
      { ...good, device_code: "short" },
      { ...good, device_code: "has spaces in the device code" },
      { ...good, user_code: undefined },
      { ...good, user_code: "" },
      { ...good, user_code: "A" },
      { ...good, user_code: "ABCD\u001b[2JEFGH" },
      { ...good, user_code: "ABCD\nEFGH" },
      { ...good, user_code: " ABCD-EFGH" },
      { ...good, user_code: "x".repeat(65) },
      { ...good, verification_url: undefined },
      { ...good, verification_url: "http://www.google.com/device" },
      { ...good, verification_url: "javascript:alert(1)" },
      { ...good, verification_url: "https://www.google.com/device\nhttps://evil.example" },
      { ...good, verification_url: `https://${"g".repeat(201)}` },
      { ...good, expires_in: "1800" },
      { ...good, expires_in: 0 },
      { ...good, interval: null },
      { ...good, interval: "5" },
      { ...good, interval: 0 },
      { ...good, interval: -5 },
      [good],
      "<html>not json</html>",
    ];
    for (const body of bad) {
      h.google.nextAnswer(200, body);
      const res = await h.post("/device/start", {});
      expect(await errorOf(res), JSON.stringify(body).slice(0, 120)).toEqual({ status: 502, error: "upstream_error" });
      expect(await res.text()).not.toContain("ABCD");
    }
    // the shapes Google documents pass: a user code with a space, a fractional interval
    h.google.nextAnswer(200, { ...good, user_code: "ABCD EFGH", interval: 0.5, extra: "dropped" });
    const res = await h.post("/device/start", {});
    expect(await res.json()).toEqual({ ...good, user_code: "ABCD EFGH", interval: 0.5 });
  });

  it("an answer without `interval` is a device code: the device is told the default of RFC 8628 §3.5, 5 seconds", async () => {
    const withoutInterval = { device_code: "AH-1Ng-fake_device.code/9", user_code: "ABCD-EFGH", verification_url: VERIFICATION_URL, expires_in: 1800 };
    h.google.nextAnswer(200, withoutInterval);
    const res = await h.post("/device/start", {});
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ...withoutInterval, interval: 5 });
    expect(DEFAULT_POLL_INTERVAL_S).toBe(5);
  });

  it("the verification URL is Google's to choose: any https address is passed on, and the device decides whether to open it", async () => {
    // The Worker's upstream is Google's own endpoint, so a host check here would only break logins the day Google
    // moves the page. The check that matters is the device's (it does not trust the Worker): it opens google.com only.
    const good = { device_code: "AH-1Ng-fake_device.code/9", user_code: "ABCD-EFGH", expires_in: 1800, interval: 5 };
    for (const verification_url of ["https://g.co/device", "https://accounts.example.net/device?x=1", "https://www.google.com.evil.example/device"]) {
      h.google.nextAnswer(200, { ...good, verification_url });
      const res = await h.post("/device/start", {});
      expect(await res.json(), verification_url).toEqual({ ...good, verification_url });
    }
  });

  it("maps Google's error answers", async () => {
    const table: Array<[number, unknown, number, string]> = [
      [401, { error: "invalid_client", error_description: "Invalid client type." }, 500, "client_invalid"],
      [401, { error: "deleted_client" }, 500, "client_invalid"],
      [400, { error: "unauthorized_client" }, 500, "client_invalid"],
      [400, { error: "invalid_scope", error_description: "Invalid device flow scope." }, 500, "client_invalid"],
      [403, { error: "org_internal" }, 403, "access_denied"],
      [403, { error_code: "rate_limit_exceeded" }, 502, "upstream_error"],
      [400, { error: "invalid_request" }, 502, "upstream_error"],
      [503, { error: "invalid_client" }, 502, "upstream_error"],
      [500, "Internal Server Error", 502, "upstream_error"],
      [302, "", 502, "upstream_error"],
      // the states of a device code mean nothing here
      [428, { error: "authorization_pending" }, 502, "upstream_error"],
    ];
    for (const [googleStatus, googleBody, status, error] of table) {
      h.google.nextAnswer(googleStatus, googleBody);
      expect(await errorOf(await h.post("/device/start", {})), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
    }
    for (const failure of [new TypeError("network connection lost"), new DOMException("The operation timed out.", "TimeoutError")]) {
      h.google.nextThrows(failure);
      expect(await errorOf(await h.post("/device/start", {}))).toEqual({ status: 502, error: "upstream_error" });
    }
  });
});

describe("POST /device/poll", () => {
  it("happy path: the exact form goes to Google and the exact JSON comes back", async () => {
    const started = await startLogin(h);
    h.google.approve(started.user_code);
    const res = await h.post("/device/poll", { device_code: started.device_code, extra: "unknown fields are ignored" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      refresh_token: "1//fake-refresh-token-2",
      access_token: "ya29.fake-access-token-2",
      expires_in: 3599,
      scope: GRANTED_SCOPE,
      email: EMAIL,
    });
    expect(h.google.kinds()).toEqual(["device_code", "token"]);
    const call = h.google.calls[1]!;
    expect(call).toMatchObject({ kind: "token", url: GOOGLE.tokenUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    expect(call.form).toEqual({ grant_type: DEVICE_GRANT, device_code: started.device_code, client_id: CLIENT_ID, client_secret: CLIENT_SECRET });
    expect(DEVICE_GRANT).toBe("urn:ietf:params:oauth:grant-type:device_code");
  });

  it("the states of a device code are passed on under Google's names, whatever status Google used", async () => {
    const started = await startLogin(h);
    const next = async () => errorOf(await poll(h, started.device_code));
    expect(await next()).toEqual({ status: 400, error: "authorization_pending" }); // Google: 428
    h.google.set(started.user_code, "slow_down");
    expect(await next()).toEqual({ status: 400, error: "slow_down" }); // Google: 403
    h.google.set(started.user_code, "pending");
    expect(await next()).toEqual({ status: 400, error: "authorization_pending" });
    h.google.set(started.user_code, "expired");
    expect(await next()).toEqual({ status: 400, error: "expired_token" });
    h.google.set(started.user_code, "denied");
    expect(await next()).toEqual({ status: 403, error: "access_denied" });
    expect(h.google.revokes()).toEqual([]);
    // every poll was one request to Google, and none of them handed anything out
    expect(h.google.kinds()).toEqual(["device_code", "token", "token", "token", "token", "token"]);
    for (const r of h.recorded.slice(1)) expect(r.body).not.toContain("token-");
  });

  it("a device code is single-use because Google's is: the second poll after a login gets invalid_grant", async () => {
    const started = await startLogin(h);
    h.google.approve(started.user_code);
    expect((await poll(h, started.device_code)).status).toBe(200);
    expect(await errorOf(await poll(h, started.device_code))).toEqual({ status: 400, error: "invalid_grant" });
  });

  it("two logins side by side do not mix", async () => {
    const [a, b] = [await startLogin(h), await startLogin(h)];
    h.google.approve(b.user_code, { email: "stranger@example.net" });
    expect(await errorOf(await poll(h, a.device_code))).toEqual({ status: 400, error: "authorization_pending" });
    expect(await errorOf(await poll(h, b.device_code))).toEqual({ status: 403, error: "email_not_allowed" });
    h.google.approve(a.user_code);
    expect((await poll(h, a.device_code)).status).toBe(200);
  });

  it("malformed requests → 400 invalid_request with zero calls to Google", async () => {
    const bad: unknown[] = [
      {},
      { device_code: 5 },
      { device_code: null },
      { device_code: ["AH-1Ng-well-formed-device-code"] },
      { device_code: "" },
      { device_code: "d".repeat(15) },
      { device_code: "d".repeat(513) },
      { device_code: "AH-1Ng well formed device code" },
      { device_code: "AH-1Ng-device-code&client_id=x" },
      { device_code: 'AH-1Ng-device-code"' },
      { device_code: "AH-1Ng-device-code\n" },
      { device_code: "AH-1Ng-device-code%20" },
      { code: "AH-1Ng-well-formed-device-code" },
      { user_code: "FAKE-0001" },
    ];
    for (const body of bad) {
      expect(await errorOf(await h.post("/device/poll", body)), JSON.stringify(body).slice(0, 80)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect(h.google.calls).toEqual([]);
    // the bounds themselves reach Google
    for (const code of ["d".repeat(16), "d".repeat(512), "4/A_-.~+=/abcdefghijklm"]) {
      expect(DEVICE_CODE_RE.test(code)).toBe(true);
      h.google.nextAnswer(400, { error: "invalid_grant" });
      expect(await errorOf(await poll(h, code))).toEqual({ status: 400, error: "invalid_grant" });
    }
    expect(h.google.kinds()).toEqual(["token", "token", "token"]);
  });

  describe("allowlist", () => {
    it("an address outside ALLOWED_EMAILS → 403 email_not_allowed and one revoke carrying the refresh token", async () => {
      const res = await login(h, { email: "stranger@example.net" });
      expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
      const body = (await res.json()) as { message: string };
      // The caller is anonymous: it learns the first character and the domain, never the address.
      expect(body.message).toBe("The Google account s***@example.net is not allowed to sign in here.");
      expect(body.message).not.toContain("stranger");
      expect(JSON.stringify(body)).not.toContain("fake-refresh-token");
      expect(h.google.kinds()).toEqual(["device_code", "token", "revoke"]);
      const revoke = h.google.revokes()[0]!;
      expect(revoke).toMatchObject({ url: GOOGLE.revokeUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
      expect(revoke.form).toEqual({ token: "1//fake-refresh-token-2" });
    });

    it("no answer carries the full address of an account that is not allowed, whatever the claim looks like", async () => {
      const table: Array<[string, string]> = [
        ["someone.else@corp.example.org", "The Google account s***@corp.example.org is not allowed to sign in here."],
        ["a@b", "The Google account a***@b is not allowed to sign in here."],
        // nothing presentable: no address at all
        ["no-at-sign", "This Google account is not allowed to sign in here."],
        ["@example.net", "This Google account is not allowed to sign in here."],
        ["x@", "This Google account is not allowed to sign in here."],
        ["esc\u001b[31m@example.net", "This Google account is not allowed to sign in here."],
        ["two words@example.net", "This Google account is not allowed to sign in here."],
        ["\u00fcn\u00ef@example.net", "This Google account is not allowed to sign in here."],
        [`${"l".repeat(250)}@example.net`, "This Google account is not allowed to sign in here."],
      ];
      for (const [email, message] of table) {
        const res = await login(h, { email });
        expect(await errorOf(res), email).toEqual({ status: 403, error: "email_not_allowed" });
        expect(((await res.json()) as { message: string }).message, email).toBe(message);
      }
      expect(maskedEmail("me@example.com")).toBe("m***@example.com");
      expect(maskedEmail("first@second@example.com")).toBe("f***@example.com");
      expect(maskedEmail(undefined)).toBeNull();
      expect(maskedEmail("")).toBeNull();
    });

    it("email_verified: false → the same, also for a listed address", async () => {
      expect(await errorOf(await login(h, { emailVerified: false }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["device_code", "token", "revoke"]);
    });

    it("an ID token without an e-mail claim → 403 and a revoke", async () => {
      const idToken = makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "1" });
      expect(await errorOf(await login(h, { idToken }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["device_code", "token", "revoke"]);
    });

    it("a failing revoke does not change the answer", async () => {
      const fetch = h.deps.fetch;
      h.deps.fetch = async (input, init) => {
        if (String(input) === GOOGLE.revokeUrl) throw new TypeError("network down");
        return fetch(input, init);
      };
      expect(await errorOf(await login(h, { email: "stranger@example.net" }))).toEqual({ status: 403, error: "email_not_allowed" });
    });

    it("matching is case-insensitive and trims spaces", async () => {
      h.env.ALLOWED_EMAILS = "  Other@Example.org ,\tME@Example.COM  ,, ";
      expect((await login(h, { email: "me@example.com" })).status).toBe(200);
      expect((await login(h, { email: "Me@EXAMPLE.com" })).status).toBe(200);
      expect((await login(h, { email: "other@example.org" })).status).toBe(200);
      expect((await login(h, { email: "me@example.co" })).status).toBe(403);
      expect((await login(h, { email: "xme@example.com" })).status).toBe(403);
      expect(allowedEmails(h.env)).toEqual(new Set(["other@example.org", "me@example.com"]));
    });

    it("only the case of ASCII letters is folded: a look-alike address is not the listed one", async () => {
      // U+212A KELVIN SIGN looks like "K", and String.prototype.toLowerCase() turns it into an ASCII "k".
      const KELVIN = "\u212a";
      expect(KELVIN).not.toBe("K");
      expect(KELVIN.toLowerCase()).toBe("k");
      h.env.ALLOWED_EMAILS = "mak@example.com";
      expect(await errorOf(await login(h, { email: `ma${KELVIN}@example.com` }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.revokes()).toHaveLength(1);
      expect((await login(h, { email: "maK@example.com" })).status).toBe(200); // the ASCII letter
      // other code points whose lower case is, or contains, an ASCII letter; and anything else outside printable ASCII
      const lookAlikes = [
        `ma${KELVIN}@EXAMPLE.com`,
        `mak@example.${KELVIN}om`,
        "\u0130ak@example.com", // LATIN CAPITAL LETTER I WITH DOT ABOVE
        "mak@exa\u0131mple.com", // LATIN SMALL LETTER DOTLESS I
        "mak@example.com\u00a0",
        "mak@example.com\n",
        " mak@example.com",
        "m\u00e4k@example.com",
      ];
      for (const email of lookAlikes) {
        expect((await login(h, { email })).status, JSON.stringify(email)).toBe(403);
      }
      // … and the same from the other side: an entry with such a character matches nothing, also not its ASCII twin
      h.env.ALLOWED_EMAILS = `ma${KELVIN}@example.com, \u0130@example.com, ok@example.com`;
      expect(allowedEmails(h.env)).toEqual(new Set(["ok@example.com"]));
      expect((await login(h, { email: "mak@example.com" })).status).toBe(403);
      expect((await login(h, { email: `ma${KELVIN}@example.com` })).status).toBe(403);
      expect((await login(h, { email: "OK@example.com" })).status).toBe(200);
    });

    it("empty or undefined ALLOWED_EMAILS allows nobody", async () => {
      for (const value of ["", " ", ",", " , ,", undefined]) {
        if (value === undefined) delete h.env.ALLOWED_EMAILS;
        else h.env.ALLOWED_EMAILS = value;
        expect(allowedEmails(h.env).size).toBe(0);
        expect(await errorOf(await login(h)), JSON.stringify(value)).toEqual({ status: 403, error: "email_not_allowed" });
        expect(await errorOf(await login(h, { email: "" }))).toEqual({ status: 403, error: "email_not_allowed" });
      }
      // not a misconfiguration: the Worker still reports ready
      expect(await (await h.get("/")).text()).toContain("Status: ready");
    });
  });

  describe("Google's answer", () => {
    it("a grant Google issued but the Worker cannot use → 403 grant_unusable that says what was missing; no revoke, and the code is spent", async () => {
      const cases: Array<[Consent, string]> = [
        [{ aud: "someone-else.apps.googleusercontent.com" }, "not issued by Google for this Worker's OAuth client"],
        [{ aud: WEB_CLIENT_ID }, "not issued by Google for this Worker's OAuth client"],
        [{ iss: "https://accounts.evil.example" }, "not issued by Google for this Worker's OAuth client"],
        [{ omit: ["id_token"] }, "no ID token"],
        [{ omit: ["refresh_token"] }, "no refresh token"],
        [{ omit: ["access_token"] }, "no usable access token"],
        [{ omit: ["expires_in"] }, "no usable access token"],
        [{ idToken: "not-a-jwt" }, "could not be read"],
        [{ idToken: "a.b" }, "could not be read"],
        [{ idToken: "aGVhZGVy.!!!.c2ln" }, "could not be read"],
        [{ idToken: `aGVhZGVy.${btoa("[1,2]")}.c2ln` }, "could not be read"],
        [{ idToken: `aGVhZGVy.${btoa("not json")}.c2ln` }, "could not be read"],
        [{ idToken: makeIdToken({ aud: CLIENT_ID, email: EMAIL, email_verified: true }) }, "not issued by Google"], // no iss
        [{ idToken: makeIdToken({ iss: "https://accounts.google.com", aud: [CLIENT_ID], email: EMAIL, email_verified: true }) }, "not issued by Google"],
      ];
      for (const [consent, what] of cases) {
        const started = await startLogin(h);
        h.google.approve(started.user_code, consent);
        const res = await poll(h, started.device_code);
        // Not 502: the device would poll a consumed code again and report "the code is no longer valid" instead.
        expect(await errorOf(res), JSON.stringify(consent)).toEqual({ status: 403, error: "grant_unusable" });
        const { message } = (await res.json()) as { message: string };
        expect(message, JSON.stringify(consent)).toContain(what);
        expect(message).toMatch(/^Google approved the sign-in, but /);
        expect(message.length).toBeLessThanOrEqual(300); // the device shows at most that much
        expect(message).not.toContain("fake-");
        // Google has consumed the code: this is what a further poll gets.
        expect(await errorOf(await poll(h, started.device_code))).toEqual({ status: 400, error: "invalid_grant" });
      }
      expect(h.google.revokes()).toEqual([]);
    });

    it("accepts both issuer spellings", async () => {
      expect((await login(h, { iss: "accounts.google.com" })).status).toBe(200);
      expect((await login(h, { iss: "https://accounts.google.com" })).status).toBe(200);
    });

    it("scope without drive.file → 403 scope_missing and no revoke", async () => {
      for (const scope of ["openid https://www.googleapis.com/auth/userinfo.email", "", "openid email", " "]) {
        expect(await errorOf(await login(h, { scope })), scope).toEqual({ status: 403, error: "scope_missing" });
      }
      expect(await errorOf(await login(h, { omit: ["scope"] }))).toEqual({ status: 403, error: "scope_missing" });
      expect(h.google.revokes()).toEqual([]);
      for (const scope of ["https://www.googleapis.com/auth/drive.file openid", SCOPES, "https://www.googleapis.com/auth/drive.file", ALLOWED_SCOPES.join(" ")]) {
        const res = await login(h, { scope });
        expect(res.status, scope).toBe(200);
        expect(((await res.json()) as { scope: string }).scope).toBe(scope);
      }
    });

    it("any scope beyond gclone's own → 403 scope_not_allowed: no token leaves the Worker, no revoke", async () => {
      const drive = "https://www.googleapis.com/auth/drive";
      const widened = [
        WIDE_SCOPE,
        `${drive} openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file`,
        drive, // without drive.file as well: the excess is what is reported
        `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive.readonly`,
        `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive.appdata`,
        `${GRANTED_SCOPE} profile`,
        "openid https://www.googleapis.com/auth/drive.file.extra",
        `${GRANTED_SCOPE} HTTPS://www.googleapis.com/auth/drive.file`, // scopes are compared exactly
      ];
      for (const scope of widened) {
        const res = await login(h, { scope });
        expect(await errorOf(res), scope).toEqual({ status: 403, error: "scope_not_allowed" });
        const text = await res.text();
        expect(text).not.toContain("fake-refresh-token");
        expect(text).not.toContain("fake-access-token");
        expect(text).toContain("https://myaccount.google.com/permissions");
      }
      // Nothing was revoked: the grant is the owner's.
      expect(h.google.revokes()).toEqual([]);
      // The message names what was granted in excess.
      const message = ((await (await login(h, { scope: WIDE_SCOPE })).json()) as { message: string }).message;
      expect(message).toMatch(/ Not asked for: https:\/\/www\.googleapis\.com\/auth\/drive$/);
    });

    it("a hostile scope text is not echoed", async () => {
      const res = await login(h, { scope: `${GRANTED_SCOPE} <script>alert(1)</script> a b c d ${"x".repeat(200)}` });
      expect(await errorOf(res)).toEqual({ status: 403, error: "scope_not_allowed" });
      const { message } = (await res.json()) as { message: string };
      expect(message).not.toContain("<");
      expect(message).not.toContain("xxxx");
      expect(message).toMatch(/ Not asked for: a, b, c, \.\.\.$/);
      expect(message.length).toBeLessThan(400);
    });

    it("excessScopes: everything outside openid, email, userinfo.email and drive.file", () => {
      expect(ALLOWED_SCOPES).toEqual(["openid", "email", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/drive.file"]);
      for (const scope of SCOPES.split(" ")) expect(ALLOWED_SCOPES).toContain(scope);
      expect(excessScopes(GRANTED_SCOPE)).toEqual([]);
      expect(excessScopes(SCOPES)).toEqual([]);
      expect(excessScopes("")).toEqual([]);
      expect(excessScopes("  openid  ")).toEqual([]);
      expect(excessScopes(WIDE_SCOPE)).toEqual(["https://www.googleapis.com/auth/drive"]);
      expect(excessScopes("a openid b")).toEqual(["a", "b"]);
      expect(excessScopes("openid\thttps://www.googleapis.com/auth/drive")).toHaveLength(1);
    });

    it("checks in the order of §2.3: an unusable grant before allowlist before scope", async () => {
      let revokes = 0;
      for (const scope of ["openid", WIDE_SCOPE]) {
        const stranger = { email: "stranger@example.net", scope };
        expect((await errorOf(await login(h, { ...stranger, aud: "x" }))).error).toBe("grant_unusable");
        expect(h.google.revokes()).toHaveLength(revokes);
        expect((await errorOf(await login(h, stranger))).error).toBe("email_not_allowed");
        expect(h.google.revokes()).toHaveLength(++revokes);
      }
      // an allowed account: too much before too little
      expect((await errorOf(await login(h, { scope: "https://www.googleapis.com/auth/drive" }))).error).toBe("scope_not_allowed");
    });

    it("maps Google's error answers", async () => {
      const table: Array<[number, unknown, number, string]> = [
        [428, { error: "authorization_pending", error_description: "Precondition Required" }, 400, "authorization_pending"],
        [400, { error: "authorization_pending" }, 400, "authorization_pending"],
        // an answer that names an error is that error under any status — never a grant with parts missing
        [200, { error: "authorization_pending" }, 400, "authorization_pending"],
        [200, { error: "slow_down" }, 400, "slow_down"],
        [200, { error: "something_new" }, 502, "upstream_error"],
        [200, { error: 7 }, 502, "upstream_error"],
        [403, { error: "slow_down", error_description: "Forbidden" }, 400, "slow_down"],
        [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
        [403, { error: "org_internal" }, 403, "access_denied"],
        [400, { error: "invalid_grant", error_description: "Malformed auth code." }, 400, "invalid_grant"],
        [401, { error: "invalid_client", error_description: "Unauthorized" }, 500, "client_invalid"],
        [401, { error: "deleted_client", error_description: "The OAuth client was deleted." }, 500, "client_invalid"],
        [400, { error: "unauthorized_client" }, 500, "client_invalid"],
        [400, { error: "invalid_request" }, 502, "upstream_error"],
        [400, { error: "unsupported_grant_type" }, 502, "upstream_error"],
        [400, { error: 7 }, 502, "upstream_error"],
        [400, {}, 502, "upstream_error"],
        [403, { error_code: "rate_limit_exceeded" }, 502, "upstream_error"],
        [503, "<html>Service Unavailable</html>", 502, "upstream_error"],
        [500, { error: "authorization_pending" }, 502, "upstream_error"],
        [502, { error: "internal_failure" }, 502, "upstream_error"],
        [200, "<html>not json</html>", 502, "upstream_error"],
        [200, [1, 2, 3], 502, "upstream_error"],
        [200, "null", 502, "upstream_error"],
        [302, "", 502, "upstream_error"],
        [429, { error: "rate_limit_exceeded" }, 502, "upstream_error"],
      ];
      const started = await startLogin(h);
      for (const [googleStatus, googleBody, status, error] of table) {
        h.google.nextAnswer(googleStatus, googleBody);
        const res = await poll(h, started.device_code);
        expect(await errorOf(res), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
        if (error === "access_denied") expect(((await res.json()) as { message: string }).message).toContain((googleBody as { error: string }).error);
      }
      expect(h.google.revokes()).toEqual([]);
      // the login itself is untouched by all of that
      h.google.approve(started.user_code);
      expect((await poll(h, started.device_code)).status).toBe(200);
    });

    it("a thrown fetch (network failure, timeout) → 502", async () => {
      const started = await startLogin(h);
      for (const failure of [new TypeError("network connection lost"), new DOMException("The operation timed out.", "TimeoutError")]) {
        h.google.nextThrows(failure);
        expect(await errorOf(await poll(h, started.device_code))).toEqual({ status: 502, error: "upstream_error" });
      }
    });

    it("passes refresh_token_expires_in through exactly when Google sent it", async () => {
      const expiring = (await (await login(h, { refreshTokenExpiresIn: 604799 })).json()) as Record<string, unknown>;
      expect(expiring.refresh_token_expires_in).toBe(604799);
      expect(Object.keys(expiring).sort()).toEqual(["access_token", "email", "expires_in", "refresh_token", "refresh_token_expires_in", "scope"]);
      const lasting = (await (await login(h)).json()) as Record<string, unknown>;
      expect("refresh_token_expires_in" in lasting).toBe(false);
      expect(Object.keys(lasting).sort()).toEqual(["access_token", "email", "expires_in", "refresh_token", "scope"]);
    });
  });
});

describe("ID-token and configuration helpers", () => {
  it("idTokenClaims reads the payload only and keeps well-typed claims", () => {
    const claims = idTokenClaims(makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, email: EMAIL, email_verified: true, nonce: "n", sub: "1", hd: "x" }));
    expect(claims).toEqual({ iss: "https://accounts.google.com", aud: CLIENT_ID, email: EMAIL, email_verified: true, nonce: "n" });
    expect(idTokenClaims(makeIdToken({ aud: 5, iss: null, email: ["a"], email_verified: "true", nonce: 7 }))).toEqual({});
    for (const bad of ["", "a", "a.b", "a.b.c.d", "a.%%%.c", `a.${btoa("5")}.c`, `a.${btoa("null")}.c`]) {
      expect(idTokenClaims(bad), bad).toBeNull();
    }
  });

  it("claimsFromGoogle and emailAllowed", () => {
    const env = testEnv();
    const client = { id: CLIENT_ID, secret: CLIENT_SECRET };
    expect(claimsFromGoogle(client, null)).toBe(false);
    expect(claimsFromGoogle(client, {})).toBe(false);
    expect(claimsFromGoogle(client, { aud: CLIENT_ID })).toBe(false);
    expect(claimsFromGoogle(client, { aud: CLIENT_ID, iss: "accounts.google.com" })).toBe(true);
    expect(claimsFromGoogle(client, { aud: CLIENT_ID, iss: "https://accounts.google.com" })).toBe(true);
    expect(claimsFromGoogle(client, { aud: CLIENT_ID, iss: "http://accounts.google.com" })).toBe(false);
    expect(claimsFromGoogle(client, { aud: `${CLIENT_ID}x`, iss: "accounts.google.com" })).toBe(false);
    expect(emailAllowed(env, { email: EMAIL, email_verified: true })).toBe(true);
    expect(emailAllowed(env, { email: EMAIL.toUpperCase(), email_verified: true })).toBe(true);
    expect(emailAllowed(env, { email: EMAIL })).toBe(false);
    expect(emailAllowed(env, { email: EMAIL, email_verified: false })).toBe(false);
    expect(emailAllowed(env, { email_verified: true })).toBe(false);
    expect(emailAllowed(testEnv({ ALLOWED_EMAILS: "" }), { email: "", email_verified: true })).toBe(false);
    // ASCII case only
    expect(emailAllowed(testEnv({ ALLOWED_EMAILS: "mak@example.com" }), { email: "MAK@Example.COM", email_verified: true })).toBe(true);
    expect(emailAllowed(testEnv({ ALLOWED_EMAILS: "mak@example.com" }), { email: "ma\u212a@example.com", email_verified: true })).toBe(false);
    expect(emailAllowed(testEnv({ ALLOWED_EMAILS: "ma\u212a@example.com" }), { email: "mak@example.com", email_verified: true })).toBe(false);
  });

  it("configuredClients: the device pair is required; the web client is there when both of its secrets are, and its absence takes nothing else away", () => {
    expect(configuredClients(testEnv())).toEqual({ device: { id: CLIENT_ID, secret: CLIENT_SECRET }, web: null });
    expect(configuredClients(withWeb())).toEqual({
      device: { id: CLIENT_ID, secret: CLIENT_SECRET },
      web: { id: WEB_CLIENT_ID, secret: "test-web-secret" },
    });
    for (const halfSet of [
      testEnv({ GOOGLE_LEGACY_CLIENT_ID: "", GOOGLE_LEGACY_CLIENT_SECRET: "" }),
      testEnv({ GOOGLE_LEGACY_CLIENT_ID: WEB_CLIENT_ID }),
      testEnv({ GOOGLE_LEGACY_CLIENT_SECRET: "only-the-secret" }),
      testEnv({ GOOGLE_LEGACY_CLIENT_ID: WEB_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET: "" }),
    ]) {
      expect(configuredClients(halfSet)).toEqual({ device: { id: CLIENT_ID, secret: CLIENT_SECRET }, web: null });
    }
    for (const broken of [
      testEnv({ GOOGLE_CLIENT_ID: "" }),
      testEnv({ GOOGLE_CLIENT_SECRET: "" }),
      testEnv({ GOOGLE_CLIENT_ID: undefined as unknown as string }),
      withWeb({ GOOGLE_CLIENT_SECRET: "" }),
    ]) {
      expect(configuredClients(broken)).toBeNull();
    }
  });
});
