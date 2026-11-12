import { describe, expect, it } from "vitest";
import { GRANT_TTL_S } from "../src/index";
import { ALLOWED_SCOPES, SCOPES, allowedEmails, claimsFromGoogle, emailAllowed, excessScopes, idTokenClaims } from "../src/google";
import { loginNonce } from "../src/seal";
import {
  CHALLENGE,
  CLIENT_ID,
  CLIENT_SECRET,
  DEVICE_STATE,
  EMAIL,
  GOOGLE,
  GRANTED_SCOPE,
  NONCE,
  ORIGIN,
  OTHER_VERIFIER,
  T0_MS,
  VERIFIER,
  WIDE_SCOPE,
  callbackAndConfirm,
  challengeOf,
  errorOf,
  grantFromLocation,
  makeIdToken,
  newGoogleCode,
  obtainGrant,
  startLogin,
  testEnv,
  useHarness,
  type Consent,
} from "./helpers";

const h = useHarness();

/** A login up to the grant, then POST /token with the matching verifier. */
async function redeem(consent: Partial<Consent> = {}): Promise<Response> {
  return h.post("/token", { code: await obtainGrant(h, { consent }), verifier: VERIFIER });
}

describe("POST /token", () => {
  it("happy path: the exact form goes to Google and the exact JSON comes back", async () => {
    const { state, nonce } = await startLogin(h);
    const code = newGoogleCode();
    h.google.consent(code, { nonce });
    const grant = grantFromLocation(await callbackAndConfirm(h, String(new URLSearchParams({ code, state }))));
    expect(h.google.calls).toEqual([]);

    const res = await h.post("/token", { code: grant, verifier: VERIFIER, extra: "unknown fields are ignored" });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      refresh_token: "1//fake-refresh-token-1",
      access_token: "ya29.fake-access-token-1",
      expires_in: 3599,
      scope: GRANTED_SCOPE,
      email: EMAIL,
    });

    expect(h.google.calls).toHaveLength(1);
    const call = h.google.calls[0]!;
    expect(call).toMatchObject({ kind: "token", url: GOOGLE.tokenUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    expect(call.form).toEqual({
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: `${ORIGIN}/callback`,
      code_verifier: VERIFIER,
    });
  });

  it("a grant is single-use because Google's code is: the second redemption gets invalid_grant from Google", async () => {
    const grant = await obtainGrant(h);
    expect((await h.post("/token", { code: grant, verifier: VERIFIER })).status).toBe(200);
    expect(await errorOf(await h.post("/token", { code: grant, verifier: VERIFIER }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(h.google.kinds()).toEqual(["token", "token"]);
  });

  it("a wrong verifier, an expired grant, a state blob or junk as code → 400 invalid_grant with zero calls to Google", async () => {
    const grant = await obtainGrant(h);
    const { state } = await startLogin(h);
    expect(await errorOf(await h.post("/token", { code: grant, verifier: OTHER_VERIFIER }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(await errorOf(await h.post("/token", { code: state, verifier: VERIFIER }))).toEqual({ status: 400, error: "invalid_grant" });
    for (const junk of ["", "g-1", grant.slice(0, -2), `${grant}AA`, `gclone-code1_${grant}`, "x".repeat(1024)]) {
      expect(await errorOf(await h.post("/token", { code: junk, verifier: VERIFIER })), junk).toEqual({ status: 400, error: "invalid_grant" });
    }

    h.clock.ms = T0_MS + (GRANT_TTL_S - 1) * 1000;
    const late = await obtainGrant(h);
    h.clock.ms += GRANT_TTL_S * 1000;
    expect(await errorOf(await h.post("/token", { code: late, verifier: VERIFIER }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(h.google.calls).toEqual([]);

    // the first grant was still alive one second before GRANT_TTL
    h.clock.ms = T0_MS + (GRANT_TTL_S - 1) * 1000;
    expect((await h.post("/token", { code: grant, verifier: VERIFIER })).status).toBe(200);
  });

  it("malformed requests → 400 invalid_request with zero calls to Google", async () => {
    const grant = await obtainGrant(h);
    const bad: unknown[] = [
      {},
      { code: grant },
      { verifier: VERIFIER },
      { code: 5, verifier: VERIFIER },
      { code: grant, verifier: 5 },
      { code: grant, verifier: null },
      { code: [grant], verifier: VERIFIER },
      { code: grant, verifier: VERIFIER.slice(0, 42) },
      { code: grant, verifier: "v".repeat(129) },
      { code: grant, verifier: `${VERIFIER.slice(0, 42)}+` },
      { code: grant, verifier: `${VERIFIER.slice(0, 42)} ` },
      { code: "x".repeat(1025), verifier: VERIFIER },
    ];
    for (const body of bad) {
      expect(await errorOf(await h.post("/token", body)), JSON.stringify(body).slice(0, 80)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect(h.google.calls).toEqual([]);
    // the bounds themselves are accepted
    expect((await h.post("/token", { code: grant, verifier: VERIFIER })).status).toBe(200);
    const longVerifier = "aZ09._~-".repeat(16);
    const res = await h.post("/token", { code: await obtainGrant(h, { verifier: longVerifier }), verifier: longVerifier });
    expect(res.status).toBe(200);
  });

  describe("nonce binding", () => {
    it("an ID token with the nonce of another challenge → 400 invalid_grant, no revoke, no token", async () => {
      const res = await redeem({ nonce: await loginNonce(await challengeOf(OTHER_VERIFIER)) });
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_grant" });
      const text = await res.text();
      expect(text).not.toContain("fake-refresh-token");
      expect(text).not.toContain("fake-access-token");
      expect(h.google.kinds()).toEqual(["token"]);
    });

    it("an ID token without a nonce → 400 invalid_grant, no revoke", async () => {
      expect(await errorOf(await redeem({ nonce: null }))).toEqual({ status: 400, error: "invalid_grant" });
      expect(await errorOf(await redeem({ nonce: "" }))).toEqual({ status: 400, error: "invalid_grant" });
      expect(h.google.kinds()).toEqual(["token", "token"]);
    });

    it("code injection: Google's code issued for challenge A, sent through B's state, redeemed with B's verifier → 400 invalid_grant", async () => {
      const [verifierA, verifierB] = [VERIFIER, OTHER_VERIFIER];
      const a = await startLogin(h, { challenge: await challengeOf(verifierA) });
      const b = await startLogin(h, { challenge: await challengeOf(verifierB) });
      expect(a.nonce).toBe(NONCE);
      expect(b.nonce).not.toBe(a.nonce);

      // The owner consents to A's login: Google issues the code for A's authorization request (A's nonce).
      const code = newGoogleCode();
      h.google.consent(code, { nonce: a.nonce });
      // The attacker lifts that code and feeds it to /callback together with the state of their own login B …
      const hijacked = await callbackAndConfirm(h, String(new URLSearchParams({ code, state: b.state })));
      expect(hijacked.status).toBe(302);
      const grant = grantFromLocation(hijacked);
      // … and redeems the grant, which opens fine under B's verifier.
      const res = await h.post("/token", { code: grant, verifier: verifierB });
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_grant" });
      expect(await res.text()).not.toContain("fake-refresh-token");
      // Google was asked (the grant itself was valid) — but nothing was revoked: the grant is the owner's.
      expect(h.google.kinds()).toEqual(["token"]);
      expect(h.google.calls[0]!.form.code_verifier).toBe(verifierB);
    });

    it("the legitimate device still completes its own login afterwards", async () => {
      const a = await startLogin(h);
      const code = newGoogleCode();
      h.google.consent(code, { nonce: a.nonce });
      const grant = grantFromLocation(await callbackAndConfirm(h, String(new URLSearchParams({ code, state: a.state }))));
      expect((await h.post("/token", { code: grant, verifier: VERIFIER })).status).toBe(200);
    });
  });

  describe("allowlist", () => {
    it("an address outside ALLOWED_EMAILS → 403 email_not_allowed and one revoke carrying the refresh token", async () => {
      const res = await redeem({ email: "stranger@example.net" });
      expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
      const body = (await res.json()) as { message: string };
      expect(body.message).toContain("stranger@example.net");
      expect(JSON.stringify(body)).not.toContain("fake-refresh-token");
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
      const revoke = h.google.revokes()[0]!;
      expect(revoke).toMatchObject({ url: GOOGLE.revokeUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
      expect(revoke.form).toEqual({ token: "1//fake-refresh-token-1" });
    });

    it("email_verified: false → the same, also for a listed address", async () => {
      expect(await errorOf(await redeem({ emailVerified: false }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });

    it("an ID token without an e-mail claim → 403 and a revoke", async () => {
      const idToken = makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "1", nonce: NONCE });
      expect(await errorOf(await redeem({ idToken }))).toEqual({ status: 403, error: "email_not_allowed" });
      expect(h.google.kinds()).toEqual(["token", "revoke"]);
    });

    it("a failing revoke does not change the answer", async () => {
      const grant = await obtainGrant(h, { consent: { email: "stranger@example.net" } });
      const fetch = h.deps.fetch;
      h.deps.fetch = async (input, init) => {
        if (String(input) === GOOGLE.revokeUrl) throw new TypeError("network down");
        return fetch(input, init);
      };
      expect(await errorOf(await h.post("/token", { code: grant, verifier: VERIFIER }))).toEqual({ status: 403, error: "email_not_allowed" });
    });

    it("matching is case-insensitive and trims spaces", async () => {
      h.env.ALLOWED_EMAILS = "  Other@Example.org ,\tME@Example.COM  ,, ";
      expect((await redeem({ email: "me@example.com" })).status).toBe(200);
      expect((await redeem({ email: "Me@EXAMPLE.com" })).status).toBe(200);
      expect((await redeem({ email: "other@example.org" })).status).toBe(200);
      expect((await redeem({ email: "me@example.co" })).status).toBe(403);
      expect((await redeem({ email: "xme@example.com" })).status).toBe(403);
      expect(allowedEmails(h.env)).toEqual(new Set(["other@example.org", "me@example.com"]));
    });

    it("empty or undefined ALLOWED_EMAILS allows nobody", async () => {
      for (const value of ["", " ", ",", " , ,", undefined]) {
        if (value === undefined) delete h.env.ALLOWED_EMAILS;
        else h.env.ALLOWED_EMAILS = value;
        expect(allowedEmails(h.env).size).toBe(0);
        expect(await errorOf(await redeem()), JSON.stringify(value)).toEqual({ status: 403, error: "email_not_allowed" });
        expect(await errorOf(await redeem({ email: "" }))).toEqual({ status: 403, error: "email_not_allowed" });
      }
      // not a misconfiguration: the Worker still reports ready
      expect(await (await h.get("/")).text()).toContain("Status: ready");
    });
  });

  describe("Google's answer", () => {
    it("wrong aud or iss, a missing or unreadable id_token, a missing refresh_token → 502, no revoke", async () => {
      const cases: Array<Partial<Consent>> = [
        { aud: "someone-else.apps.googleusercontent.com" },
        { iss: "https://accounts.evil.example" },
        { omit: ["id_token"] },
        { omit: ["refresh_token"] },
        { omit: ["access_token"] },
        { omit: ["expires_in"] },
        { idToken: "not-a-jwt" },
        { idToken: "a.b" },
        { idToken: "aGVhZGVy.!!!.c2ln" },
        { idToken: `aGVhZGVy.${btoa("[1,2]")}.c2ln` },
        { idToken: `aGVhZGVy.${btoa("not json")}.c2ln` },
        { idToken: makeIdToken({ aud: CLIENT_ID, email: EMAIL, email_verified: true, nonce: NONCE }) }, // no iss
        { idToken: makeIdToken({ iss: "https://accounts.google.com", aud: [CLIENT_ID], email: EMAIL, email_verified: true, nonce: NONCE }) },
      ];
      for (const consent of cases) {
        expect(await errorOf(await redeem(consent)), JSON.stringify(consent)).toEqual({ status: 502, error: "upstream_error" });
      }
      expect(h.google.revokes()).toEqual([]);
    });

    it("accepts both issuer spellings", async () => {
      expect((await redeem({ iss: "accounts.google.com" })).status).toBe(200);
      expect((await redeem({ iss: "https://accounts.google.com" })).status).toBe(200);
    });

    it("scope without drive.file → 403 scope_missing and no revoke", async () => {
      for (const scope of ["openid https://www.googleapis.com/auth/userinfo.email", "", "openid email", " "]) {
        expect(await errorOf(await redeem({ scope })), scope).toEqual({ status: 403, error: "scope_missing" });
      }
      expect(await errorOf(await redeem({ omit: ["scope"] }))).toEqual({ status: 403, error: "scope_missing" });
      expect(h.google.revokes()).toEqual([]);
      for (const scope of ["https://www.googleapis.com/auth/drive.file openid", SCOPES, "https://www.googleapis.com/auth/drive.file", ALLOWED_SCOPES.join(" ")]) {
        const res = await redeem({ scope });
        expect(res.status, scope).toBe(200);
        expect(((await res.json()) as { scope: string }).scope).toBe(scope);
      }
    });

    it("any scope beyond gclone's own → 403 scope_not_allowed: no token leaves the Worker, no revoke", async () => {
      const drive = "https://www.googleapis.com/auth/drive";
      const widened = [
        WIDE_SCOPE, // the authorization URL's scope was rewritten on its way to the user
        `${drive} openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file`,
        drive, // without drive.file as well: the excess is what is reported
        `${GRANTED_SCOPE} https://www.googleapis.com/auth/drive.readonly`,
        `${GRANTED_SCOPE} https://www.googleapis.com/auth/gmail.readonly`, // include_granted_scopes=true pulled in an older grant
        `${GRANTED_SCOPE} profile`,
        "openid https://www.googleapis.com/auth/drive.file.extra",
        `${GRANTED_SCOPE} HTTPS://www.googleapis.com/auth/drive.file`, // scopes are compared exactly
      ];
      for (const scope of widened) {
        const res = await redeem({ scope });
        expect(await errorOf(res), scope).toEqual({ status: 403, error: "scope_not_allowed" });
        const text = await res.text();
        expect(text).not.toContain("fake-refresh-token");
        expect(text).not.toContain("fake-access-token");
        expect(text).toContain("https://myaccount.google.com/permissions");
      }
      // Google was asked once per login and nothing was revoked: the grant is the owner's.
      expect(h.google.kinds()).toEqual(widened.map(() => "token"));
      // The message names what was granted in excess, so the owner can see what the consent screen asked for.
      const message = ((await (await redeem({ scope: WIDE_SCOPE })).json()) as { message: string }).message;
      expect(message).toMatch(/ Not asked for: https:\/\/www\.googleapis\.com\/auth\/drive$/);
    });

    it("a hostile scope text is not echoed", async () => {
      const res = await redeem({ scope: `${GRANTED_SCOPE} <script>alert(1)</script> a b c d ${"x".repeat(200)}` });
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

    it("checks in the order of §2.3: 502 before nonce before allowlist before scope", async () => {
      let revokes = 0;
      for (const scope of ["openid", WIDE_SCOPE]) {
        const stranger = { email: "stranger@example.net", scope };
        expect((await errorOf(await redeem({ ...stranger, nonce: "wrong", aud: "x" }))).error).toBe("upstream_error");
        expect((await errorOf(await redeem({ ...stranger, nonce: "wrong" }))).error).toBe("invalid_grant");
        expect(h.google.revokes()).toHaveLength(revokes);
        expect((await errorOf(await redeem(stranger))).error).toBe("email_not_allowed");
        expect(h.google.revokes()).toHaveLength(++revokes);
      }
      // an allowed account: too much before too little
      expect((await errorOf(await redeem({ scope: "https://www.googleapis.com/auth/drive" }))).error).toBe("scope_not_allowed");
    });

    it("maps Google's error answers", async () => {
      const table: Array<[number, unknown, number, string]> = [
        [400, { error: "invalid_grant", error_description: "Bad Request" }, 400, "invalid_grant"],
        [401, { error: "invalid_client", error_description: "Unauthorized" }, 500, "client_invalid"],
        [401, { error: "deleted_client", error_description: "The OAuth client was deleted." }, 500, "client_invalid"],
        [400, { error: "unauthorized_client" }, 500, "client_invalid"],
        [400, { error: "redirect_uri_mismatch", error_description: "Bad Request" }, 500, "client_invalid"],
        [403, { error: "access_denied" }, 403, "access_denied"],
        [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
        [403, { error: "org_internal" }, 403, "access_denied"],
        [400, { error: "invalid_request" }, 502, "upstream_error"],
        [400, { error: "unsupported_grant_type" }, 502, "upstream_error"],
        [400, { error: 7 }, 502, "upstream_error"],
        [400, {}, 502, "upstream_error"],
        [503, "<html>Service Unavailable</html>", 502, "upstream_error"],
        [500, { error: "invalid_grant" }, 502, "upstream_error"],
        [502, { error: "internal_failure" }, 502, "upstream_error"],
        [200, "<html>not json</html>", 502, "upstream_error"],
        [200, [1, 2, 3], 502, "upstream_error"],
        [200, "null", 502, "upstream_error"],
        [302, "", 502, "upstream_error"],
        [429, { error: "rate_limit_exceeded" }, 502, "upstream_error"],
      ];
      for (const [googleStatus, googleBody, status, error] of table) {
        const grant = await obtainGrant(h);
        h.google.nextTokenAnswer(googleStatus, googleBody);
        const res = await h.post("/token", { code: grant, verifier: VERIFIER });
        expect(await errorOf(res), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
        if (error === "access_denied") expect(((await res.json()) as { message: string }).message).toContain((googleBody as { error: string }).error);
      }
      expect(h.google.revokes()).toEqual([]);
    });

    it("a thrown fetch (network failure, timeout) → 502", async () => {
      for (const failure of [new TypeError("network connection lost"), new DOMException("The operation timed out.", "TimeoutError")]) {
        const grant = await obtainGrant(h);
        h.google.nextTokenThrows(failure);
        expect(await errorOf(await h.post("/token", { code: grant, verifier: VERIFIER }))).toEqual({ status: 502, error: "upstream_error" });
      }
    });

    it("passes refresh_token_expires_in through exactly when Google sent it", async () => {
      const expiring = (await (await redeem({ refreshTokenExpiresIn: 604799 })).json()) as Record<string, unknown>;
      expect(expiring.refresh_token_expires_in).toBe(604799);
      expect(Object.keys(expiring).sort()).toEqual(["access_token", "email", "expires_in", "refresh_token", "refresh_token_expires_in", "scope"]);
      const lasting = (await (await redeem()).json()) as Record<string, unknown>;
      expect("refresh_token_expires_in" in lasting).toBe(false);
      expect(Object.keys(lasting).sort()).toEqual(["access_token", "email", "expires_in", "refresh_token", "scope"]);
    });
  });

  it("redirect_uri follows the origin the device talks to", async () => {
    const origin = "https://auth.example.org";
    const { state, nonce } = await (async () => {
      const page = await (await h.call(`/login?challenge=${CHALLENGE}&port=8123&state=${DEVICE_STATE}`, { origin })).text();
      const link = new URL(page.match(/href="([^"]+)"/)![1]!.replace(/&amp;/g, "&"));
      expect(link.searchParams.get("redirect_uri")).toBe(`${origin}/callback`);
      return { state: link.searchParams.get("state")!, nonce: link.searchParams.get("nonce")! };
    })();
    const code = newGoogleCode();
    h.google.consent(code, { nonce });
    const grant = grantFromLocation(await callbackAndConfirm(h, String(new URLSearchParams({ code, state })), { origin }));
    const res = await h.call("/token", { origin, method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: grant, verifier: VERIFIER }) });
    expect(res.status).toBe(200);
    expect(h.google.calls[0]!.form.redirect_uri).toBe(`${origin}/callback`);
  });
});

describe("ID-token helpers", () => {
  it("idTokenClaims reads the payload only and keeps well-typed claims", () => {
    const claims = idTokenClaims(makeIdToken({ iss: "https://accounts.google.com", aud: CLIENT_ID, email: EMAIL, email_verified: true, nonce: "n", sub: "1", hd: "x" }));
    expect(claims).toEqual({ iss: "https://accounts.google.com", aud: CLIENT_ID, email: EMAIL, email_verified: true, nonce: "n" });
    expect(idTokenClaims(makeIdToken({ aud: 5, iss: null, email: ["a"], email_verified: "true", nonce: 1 }))).toEqual({});
    for (const bad of ["", "a", "a.b", "a.b.c.d", "a.%%%.c", `a.${btoa("5")}.c`, `a.${btoa("null")}.c`]) {
      expect(idTokenClaims(bad), bad).toBeNull();
    }
  });

  it("claimsFromGoogle and emailAllowed", () => {
    const env = testEnv();
    expect(claimsFromGoogle(env, null)).toBe(false);
    expect(claimsFromGoogle(env, {})).toBe(false);
    expect(claimsFromGoogle(env, { aud: CLIENT_ID })).toBe(false);
    expect(claimsFromGoogle(env, { aud: CLIENT_ID, iss: "accounts.google.com" })).toBe(true);
    expect(claimsFromGoogle(env, { aud: CLIENT_ID, iss: "https://accounts.google.com" })).toBe(true);
    expect(claimsFromGoogle(env, { aud: CLIENT_ID, iss: "http://accounts.google.com" })).toBe(false);
    expect(claimsFromGoogle(env, { aud: `${CLIENT_ID}x`, iss: "accounts.google.com" })).toBe(false);
    expect(emailAllowed(env, { email: EMAIL, email_verified: true })).toBe(true);
    expect(emailAllowed(env, { email: EMAIL.toUpperCase(), email_verified: true })).toBe(true);
    expect(emailAllowed(env, { email: EMAIL })).toBe(false);
    expect(emailAllowed(env, { email: EMAIL, email_verified: false })).toBe(false);
    expect(emailAllowed(env, { email_verified: true })).toBe(false);
    expect(emailAllowed(testEnv({ ALLOWED_EMAILS: "" }), { email: "", email_verified: true })).toBe(false);
  });
});
