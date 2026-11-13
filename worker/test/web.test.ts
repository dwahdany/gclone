// The hosted viewer's part of the Worker: its page (`/`, `/callback`), the four routes of its sign-in (`/web/start`,
// `/web/token`, `/web/refresh`, `/web/logout`) and the https rule. Everything runs through the real handle() with
// the shared fake Google, a literal env and the harness's clock; the harness checks after every test that no secret
// — client secret, SEAL_KEY, authorization code, verifier, refresh token, cookie — got into an answer or a log line.

import { beforeEach, describe, expect, it } from "vitest";
import { handle, type Env } from "../src/index";
import { STATUS_MARKER, VIEWER_CSP, VIEWER_HEADERS } from "../src/pages";
import { b64urlDecode, b64urlEncode, loginNonce, openSession, pkceChallenge } from "../src/seal";
import { CLEAR_COOKIE, WEB_COOKIE, WEB_SESSION_REMEMBER_TTL_S, WEB_SESSION_TTL_S } from "../src/web";
import headersJson from "../src/headers.json";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  EMAIL,
  FakeAssets,
  FakeRateLimiter,
  GOOGLE,
  GRANTED_SCOPE,
  ORIGIN,
  REDIRECT_URI,
  SAME_ORIGIN,
  SEAL_KEY_BYTES,
  T0,
  VIEWER_INDEX,
  WEB_CLIENT_ID,
  WEB_CLIENT_SECRET,
  WIDE_SCOPE,
  errorOf,
  makeIdToken,
  obtainRefreshToken,
  pkce,
  sealedCookie,
  testEnv,
  useHarness,
  webSignIn,
  webStart,
  withWeb,
} from "./helpers";

const h = useHarness();
beforeEach(() => {
  h.env = withWeb();
});

const NOW_S = T0 / 1000;
const SESSION_COOKIE_RE = new RegExp(`^${WEB_COOKIE}=[A-Za-z0-9_-]+; Path=/; Secure; HttpOnly; SameSite=Strict$`);
const WEB_ROUTES = ["/web/start", "/web/token", "/web/refresh", "/web/logout"];
/** Everything that is not the viewer's own page, as a browser or anything else would announce itself. */
const FOREIGN: Array<Record<string, string>> = [
  { origin: "https://evil.example", "sec-fetch-site": "cross-site" },
  { origin: "https://evil.example" },
  // a sibling host of the same site, and this host under another scheme or port
  { origin: "https://other.auth.test", "sec-fetch-site": "same-site" },
  { origin: ORIGIN, "sec-fetch-site": "same-site" },
  { origin: ORIGIN, "sec-fetch-site": "cross-site" },
  { origin: ORIGIN, "sec-fetch-site": "none" },
  { origin: "http://auth.test" },
  { origin: `${ORIGIN}:8443` },
  { origin: `${ORIGIN}/` },
  { origin: ORIGIN.toUpperCase() },
  { origin: "null" },
  { origin: "" },
  // no Origin header at all: curl, a script, an old browser
  {},
  { "sec-fetch-site": "same-origin" },
  { referer: `${ORIGIN}/` },
];

/** A POST with exactly these headers (h.web would add the same-origin pair). */
function rawPost(path: string, json: unknown, headers: Record<string, string>): Promise<Response> {
  return h.call(path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(json) });
}

const refreshWith = (cookie: string | null, headers: Record<string, string> = {}) => h.web("/web/refresh", {}, cookie === null ? headers : { cookie, ...headers });
const tokenForms = () => h.google.calls.filter((c) => c.kind === "token").map((c) => c.form);
const sessionOf = (cookie: string, nowS = NOW_S) => openSession(SEAL_KEY_BYTES, cookie.slice(WEB_COOKIE.length + 1), nowS);

describe("POST /web/start", () => {
  it("builds the authorization URL from constants, the challenge and the state; Google is not contacted", async () => {
    const p = await pkce();
    const res = await h.web("/web/start", { challenge: p.challenge, state: p.state });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { authorization_url: string };
    expect(Object.keys(body)).toEqual(["authorization_url"]);
    const url = new URL(body.authorization_url);
    expect(url.origin + url.pathname).toBe(GOOGLE.authUrl);
    // exactly these parameters, in this order
    expect([...url.searchParams]).toEqual([
      ["client_id", WEB_CLIENT_ID],
      ["redirect_uri", REDIRECT_URI],
      ["response_type", "code"],
      ["scope", "openid email https://www.googleapis.com/auth/drive.file"],
      ["access_type", "offline"],
      ["prompt", "consent"],
      ["code_challenge", p.challenge],
      ["code_challenge_method", "S256"],
      ["state", p.state],
      ["nonce", await loginNonce(p.challenge)],
    ]);
    expect(body.authorization_url).not.toContain("include_granted_scopes");
    expect(body.authorization_url).not.toContain("login_hint");
    expect(body.authorization_url).not.toContain(encodeURIComponent(EMAIL));
    expect(h.google.calls).toEqual([]);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("the production address is Google's authorization endpoint, which the page checks before it navigates", async () => {
    const p = await pkce();
    const res = await handle(
      new Request(`${ORIGIN}/web/start`, { method: "POST", headers: { "content-type": "application/json", ...SAME_ORIGIN }, body: JSON.stringify({ challenge: p.challenge, state: p.state }) }),
      h.env,
      { ...h.deps, google: { ...GOOGLE, authUrl: "https://accounts.google.com/o/oauth2/v2/auth" } },
    );
    await h.record("/web/start", res);
    expect(((await res.json()) as { authorization_url: string }).authorization_url.startsWith("https://accounts.google.com/o/oauth2/v2/auth?client_id=")).toBe(true);
  });

  it("nothing a page sends changes the URL beyond challenge and state: no redirect, scope, client or hint from the request", async () => {
    const p = await pkce();
    const extra = { redirect_uri: "https://evil.example/callback", scope: "https://www.googleapis.com/auth/drive", client_id: "evil", login_hint: "x@example.com", prompt: "none", nonce: "mine", include_granted_scopes: "true" };
    const res = await h.call("/web/start?redirect_uri=https://evil.example/&scope=drive", {
      method: "POST",
      headers: { "content-type": "application/json", ...SAME_ORIGIN, host: "evil.example", "x-forwarded-host": "evil.example", "x-forwarded-proto": "http" },
      body: JSON.stringify({ challenge: p.challenge, state: p.state, ...extra }),
    });
    const url = new URL(((await res.json()) as { authorization_url: string }).authorization_url);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("scope")).toBe("openid email https://www.googleapis.com/auth/drive.file");
    expect(url.searchParams.get("client_id")).toBe(WEB_CLIENT_ID);
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("nonce")).toBe(await loginNonce(p.challenge));
    expect([...url.searchParams.keys()]).toHaveLength(10);
  });

  it("a malformed challenge or state → 400 invalid_request: nothing can be smuggled into the URL", async () => {
    const p = await pkce();
    // 43 characters whose last one carries bits that are not part of 32 bytes: not the canonical spelling
    const stray = p.challenge.slice(0, -1) + (p.challenge.endsWith("B") ? "C" : "B");
    expect(b64urlDecode(stray)).toHaveLength(32);
    const challenges = ["", "short", p.challenge.slice(1), `${p.challenge}A`, `${p.challenge.slice(0, -1)}=`, `${p.challenge.slice(0, -1)}+`, p.challenge.replace(/.$/, "&"), stray, null, 7, [p.challenge], undefined];
    for (const challenge of challenges) {
      expect(await errorOf(await h.web("/web/start", { challenge, state: p.state })), JSON.stringify(challenge)).toEqual({ status: 400, error: "invalid_request" });
    }
    const states = ["", "x", "A".repeat(21), "A".repeat(129), `${p.state}&prompt=none`, `${p.state} `, `${p.state}#`, `${p.state}%26`, "ä".repeat(22), null, 7, undefined];
    for (const state of states) {
      expect(await errorOf(await h.web("/web/start", { challenge: p.challenge, state })), JSON.stringify(state)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect((await h.web("/web/start", { challenge: p.challenge, state: "A".repeat(128) })).status).toBe(200);
    expect(h.google.calls).toEqual([]);
  });
});

describe("POST /web/token", () => {
  it("hands the access token to the page and the refresh token, sealed, to an HttpOnly cookie", async () => {
    const { res, setCookie, cookie, pkce: p, code } = await webSignIn(h);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ access_token: expect.stringMatching(/^ya29\./), expires_in: 3599, scope: GRANTED_SCOPE, email: EMAIL, session_expires_in: WEB_SESSION_TTL_S });
    expect(Object.keys(body)).toEqual(["access_token", "expires_in", "scope", "email", "session_expires_in"]);
    // a session cookie: no Max-Age, no Expires, no Domain
    expect(setCookie).toMatch(SESSION_COOKIE_RE);
    const session = await sessionOf(cookie!);
    expect(session).toEqual({ iat: NOW_S, exp: NOW_S + WEB_SESSION_TTL_S, email: EMAIL, refreshToken: expect.stringMatching(/^1\/\/fake-web-refresh-token-/) });
    // the refresh token is in the seal and nowhere else (the harness checks every answer for it as well)
    expect(JSON.stringify(body)).not.toContain(session!.refreshToken);
    expect(setCookie).not.toContain(session!.refreshToken);
    // exactly one request to Google: the code, the verifier, the web client's credentials, this origin's redirect URI
    expect(h.google.calls).toHaveLength(1);
    expect(h.google.calls[0]).toMatchObject({ kind: "token", url: GOOGLE.tokenUrl, method: "POST", contentType: "application/x-www-form-urlencoded", hasTimeout: true });
    expect(h.google.calls[0]!.form).toEqual({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: p.verifier, client_id: WEB_CLIENT_ID, client_secret: WEB_CLIENT_SECRET });
  });

  it("remember: true → a persistent cookie and a session of 30 days; anything else → a session cookie and 12 hours", async () => {
    const remembered = await webSignIn(h, { remember: true });
    expect(remembered.setCookie).toMatch(new RegExp(`^${WEB_COOKIE}=[A-Za-z0-9_-]+; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${WEB_SESSION_REMEMBER_TTL_S}$`));
    expect(((await remembered.res.json()) as { session_expires_in: number }).session_expires_in).toBe(WEB_SESSION_REMEMBER_TTL_S);
    expect((await sessionOf(remembered.cookie!))!.exp).toBe(NOW_S + WEB_SESSION_REMEMBER_TTL_S);
    expect([WEB_SESSION_TTL_S, WEB_SESSION_REMEMBER_TTL_S]).toEqual([12 * 3600, 30 * 86400]);

    const not = await webSignIn(h, { remember: false });
    expect(not.setCookie).toMatch(SESSION_COOKIE_RE);
    expect((await sessionOf(not.cookie!))!.exp).toBe(NOW_S + WEB_SESSION_TTL_S);
    // not a boolean: refused before Google is asked, so the code is not spent
    const p = await pkce();
    const code = h.google.consent(await webStart(h, p));
    const before = h.google.calls.length;
    for (const remember of ["true", 1, null, {}]) {
      expect(await errorOf(await h.web("/web/token", { code, verifier: p.verifier, remember })), JSON.stringify(remember)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect(h.google.calls.length).toBe(before);
    expect((await h.web("/web/token", { code, verifier: p.verifier })).status).toBe(200);
  });

  it("the cookie has every attribute a __Host- cookie needs, and none it must not have", async () => {
    for (const remember of [false, true]) {
      const { setCookie } = await webSignIn(h, { remember });
      const [pair, ...attributes] = setCookie!.split("; ");
      expect(pair!.startsWith("__Host-gclone-web=")).toBe(true);
      expect(attributes.slice(0, 4)).toEqual(["Path=/", "Secure", "HttpOnly", "SameSite=Strict"]);
      expect(attributes.slice(4)).toEqual(remember ? ["Max-Age=2592000"] : []);
      expect(setCookie).not.toMatch(/domain|expires|samesite=(lax|none)/i);
    }
  });

  it("another tab's verifier does not redeem the code (Google's PKCE check), and sets no cookie", async () => {
    const [mine, other] = [await pkce(), await pkce()];
    const code = h.google.consent(await webStart(h, mine));
    const res = await h.web("/web/token", { code, verifier: other.verifier });
    expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_grant" });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(h.google.revokes()).toEqual([]);
  });

  it("two tabs side by side: each code goes with its own verifier only", async () => {
    const [a, b] = [await pkce(), await pkce()];
    const [codeA, codeB] = [h.google.consent(await webStart(h, a)), h.google.consent(await webStart(h, b))];
    expect(await errorOf(await h.web("/web/token", { code: codeA, verifier: b.verifier }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(await errorOf(await h.web("/web/token", { code: codeB, verifier: a.verifier }))).toEqual({ status: 400, error: "invalid_grant" });
    expect((await h.web("/web/token", { code: codeA, verifier: a.verifier })).status).toBe(200);
    expect((await h.web("/web/token", { code: codeB, verifier: b.verifier })).status).toBe(200);
    // a code is single-use because Google's is
    expect(await errorOf(await h.web("/web/token", { code: codeA, verifier: a.verifier }))).toEqual({ status: 400, error: "invalid_grant" });
  });

  it("a code for an authorization URL that /web/start did not build is refused by the nonce — whatever Google does with PKCE; no revoke, no cookie", async () => {
    const p = await pkce();
    const built = new URL(await webStart(h, p));
    // An attacker-made URL for this client: the right challenge for a verifier he knows, but not this Worker's nonce …
    const foreign = new URL(built);
    foreign.searchParams.set("nonce", "attacker-chosen");
    // … or none at all …
    const none = new URL(built);
    none.searchParams.delete("nonce");
    // … or the nonce of another challenge (a URL /web/start built for another tab, with the challenge swapped)
    const swapped = new URL(built);
    swapped.searchParams.set("nonce", await loginNonce((await pkce()).challenge));
    for (const url of [foreign, none, swapped]) {
      const res = await h.web("/web/token", { code: h.google.consent(url.toString()), verifier: p.verifier });
      expect(await errorOf(res)).toEqual({ status: 400, error: "invalid_grant" });
      expect(((await res.json()) as { message: string }).message).toContain("does not belong to this sign-in");
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    // Google redeemed all three (its PKCE check passed): it was the Worker that refused. The grant may be the owner's: not revoked.
    expect(h.google.calls.map((c) => c.kind)).toEqual(["token", "token", "token"]);
    // The same when Google does not check the verifier at all: an ID token whose nonce is not this verifier's.
    const verifier = (await pkce()).verifier;
    h.google.nextAnswer(200, {
      access_token: "ya29.unchecked",
      expires_in: 3599,
      refresh_token: "1//0unchecked-refresh-token",
      scope: GRANTED_SCOPE,
      id_token: makeIdToken({ iss: "https://accounts.google.com", aud: WEB_CLIENT_ID, email: EMAIL, email_verified: true, nonce: await loginNonce(p.challenge) }),
    });
    h.google.accessTokens.add("ya29.unchecked");
    h.google.webRefreshTokens.add("1//0unchecked-refresh-token");
    expect(await errorOf(await h.web("/web/token", { code: "4/0Aany-code-at-all", verifier }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(h.google.revokes()).toEqual([]);
  });

  it("login CSRF: a code that another page plants is never redeemed — the request is refused before Google is asked, and no cookie is set", async () => {
    // The attacker completed a sign-in of his own up to the code, and makes the victim's browser send it.
    const attacker = await pkce();
    const code = h.google.consent(await webStart(h, attacker), { email: "attacker@example.net" });
    const before = h.google.calls.length;
    for (const headers of FOREIGN) {
      const res = await rawPost("/web/token", { code, verifier: attacker.verifier }, headers);
      expect(await errorOf(res), JSON.stringify(headers)).toEqual({ status: 403, error: "cross_origin" });
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    // what a cross-site form can send without a preflight is not JSON
    for (const type of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"]) {
      const res = await h.call("/web/token", { method: "POST", headers: { "content-type": type, ...SAME_ORIGIN }, body: JSON.stringify({ code, verifier: attacker.verifier }) });
      expect(res.status, type).toBe(415);
    }
    expect(h.google.calls.length).toBe(before);
    // And through the victim's own page (which would have to send it — it does not, the `state` is not its own): the
    // account is not the owner's, so nothing is handed out and the grant is revoked.
    const res = await h.web("/web/token", { code, verifier: attacker.verifier });
    expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("an account outside ALLOWED_EMAILS gets nothing, its grant is revoked, and the address is masked", async () => {
    const { res, setCookie } = await webSignIn(h, { consent: { email: "stranger@example.net" } });
    expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
    const { message } = (await res.json()) as { message: string };
    expect(message).toContain("s***@example.net");
    expect(message).not.toContain("stranger");
    expect(setCookie).toBeNull();
    expect(h.google.kinds()).toEqual(["token", "revoke"]);
    expect(h.google.revokes()[0]!.form.token).toMatch(/^1\/\/fake-web-refresh-token-/);
    // an address that is not verified, no address, an empty allowlist: the same
    for (const [consent, allowed] of [[{ emailVerified: false }, EMAIL], [{ email: undefined, idToken: makeIdToken({ iss: "accounts.google.com", aud: WEB_CLIENT_ID, nonce: "x" }) }, EMAIL], [{}, ""]] as const) {
      h.reset();
      h.env = withWeb({ ALLOWED_EMAILS: allowed });
      const p = await pkce();
      const url = await webStart(h, p);
      const idToken = "idToken" in consent ? makeIdToken({ iss: "accounts.google.com", aud: WEB_CLIENT_ID, nonce: await loginNonce(p.challenge) }) : undefined;
      const code = h.google.consent(url, idToken === undefined ? consent : { idToken });
      const refused = await h.web("/web/token", { code, verifier: p.verifier });
      expect(await errorOf(refused)).toEqual({ status: 403, error: "email_not_allowed" });
      expect(refused.headers.get("set-cookie")).toBeNull();
      expect(h.google.revokes()).toHaveLength(1);
    }
  });

  it("a grant wider than gclone's scopes, or without drive.file, gets nothing and sets no cookie; no revoke", async () => {
    const wide = await webSignIn(h, { consent: { scope: WIDE_SCOPE } });
    expect(await errorOf(wide.res)).toEqual({ status: 403, error: "scope_not_allowed" });
    const { message } = (await wide.res.json()) as { message: string };
    expect(message).toContain("https://myaccount.google.com/permissions");
    expect(message).toContain("sign in again");
    expect(message).not.toContain("gclone login");
    expect(message).toContain("Not asked for: https://www.googleapis.com/auth/drive");
    expect(wide.setCookie).toBeNull();
    const narrow = await webSignIn(h, { consent: { scope: "openid https://www.googleapis.com/auth/userinfo.email" } });
    expect(await errorOf(narrow.res)).toEqual({ status: 403, error: "scope_missing" });
    expect(narrow.setCookie).toBeNull();
    expect(h.google.revokes()).toEqual([]);
    // the allowlist comes first: a stranger's wide grant is revoked
    const stranger = await webSignIn(h, { consent: { scope: WIDE_SCOPE, email: "stranger@example.net" } });
    expect(await errorOf(stranger.res)).toEqual({ status: 403, error: "email_not_allowed" });
    expect(h.google.revokes()).toHaveLength(1);
  });

  it("a grant Google issued but the Worker cannot use → 403 grant_unusable; nothing is sealed", async () => {
    const cases: Array<[Parameters<typeof webSignIn>[1], string]> = [
      [{ consent: { omit: ["id_token"] } }, "no ID token"],
      [{ consent: { omit: ["refresh_token"] } }, "no refresh token"],
      [{ consent: { omit: ["access_token"] } }, "no usable access token"],
      [{ consent: { idToken: "garbage" } }, "could not be read"],
      // an ID token for the device client, or from another issuer: not this sign-in's
      [{ consent: { aud: CLIENT_ID } }, "not issued by Google for this Worker's web client"],
      [{ consent: { iss: "https://evil.example" } }, "not issued by Google for this Worker's web client"],
      // a refresh token the seal cannot hold
      [{ consent: { refreshToken: `1//0${"r".repeat(509)}` } }, "a form this Worker cannot keep"],
      [{ consent: { refreshToken: "1//0has space in the token" } }, "a form this Worker cannot keep"],
    ];
    for (const [over, what] of cases) {
      const { res, setCookie } = await webSignIn(h, over);
      expect(await errorOf(res), what).toEqual({ status: 403, error: "grant_unusable" });
      const { message } = (await res.json()) as { message: string };
      expect(message).toContain(what);
      expect(message).toContain("the sign-in code is used up");
      expect(setCookie).toBeNull();
    }
    expect(h.google.revokes()).toEqual([]);
  });

  it("the longest address and the longest refresh token still fit: a cookie pair of 1092 bytes that /web/refresh opens", async () => {
    const email = `${"x".repeat(242)}@example.com`;
    h.env = withWeb({ ALLOWED_EMAILS: email });
    const { res, cookie } = await webSignIn(h, { consent: { email, refreshToken: `1//0${"r".repeat(508)}` } });
    expect(res.status).toBe(200);
    expect(cookie).toHaveLength(1092);
    const refreshed = await refreshWith(cookie);
    expect(refreshed.status).toBe(200);
    expect(((await refreshed.json()) as { email: string }).email).toBe(email);
  });

  it("maps Google's answers to the code exchange", async () => {
    const table: Array<[number, unknown, number, string]> = [
      [400, { error: "invalid_grant", error_description: "Malformed auth code." }, 400, "invalid_grant"],
      [400, { error: "invalid_grant", error_description: "Invalid code verifier." }, 400, "invalid_grant"],
      [400, { error: "redirect_uri_mismatch", error_description: "Bad Request" }, 500, "client_invalid"],
      [401, { error: "invalid_client", error_description: "The OAuth client was not found." }, 500, "client_invalid"],
      [401, { error: "deleted_client" }, 500, "client_invalid"],
      [400, { error: "unauthorized_client" }, 500, "client_invalid"],
      [400, { error: "invalid_scope" }, 500, "client_invalid"],
      [403, { error: "access_denied" }, 403, "access_denied"],
      [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
      [400, { error: "invalid_request" }, 502, "upstream_error"],
      [400, { error: "authorization_pending" }, 502, "upstream_error"],
      [500, { error: "internal_failure" }, 502, "upstream_error"],
      [503, "<html>down</html>", 502, "upstream_error"],
      [200, "not json", 502, "upstream_error"],
      [200, [], 502, "upstream_error"],
      [200, { error: "invalid_grant" }, 400, "invalid_grant"],
    ];
    const p = await pkce();
    for (const [googleStatus, googleBody, status, error] of table) {
      h.google.nextAnswer(googleStatus, googleBody);
      const res = await h.web("/web/token", { code: "4/0Awell-formed-code", verifier: p.verifier });
      expect(await errorOf(res), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    h.google.nextThrows(new TypeError("network down"));
    expect(await errorOf(await h.web("/web/token", { code: "4/0Awell-formed-code", verifier: p.verifier }))).toEqual({ status: 502, error: "upstream_error" });
    // the redirect URI the web client does not list: the message names Google's code, as for every client error
    h.google.nextAnswer(400, { error: "redirect_uri_mismatch" });
    const res = await h.web("/web/token", { code: "4/0Awell-formed-code", verifier: p.verifier });
    expect(((await res.json()) as { message: string }).message).toContain("redirect_uri_mismatch");
  });

  it("the redirect URI sent to Google is this origin's /callback — the one a code was issued for, or Google refuses", async () => {
    const p = await pkce();
    const url = new URL(await webStart(h, p));
    url.searchParams.set("redirect_uri", "https://other.example/callback");
    const res = await h.web("/web/token", { code: h.google.consent(url.toString()), verifier: p.verifier, redirect_uri: "https://other.example/callback" });
    expect(await errorOf(res)).toEqual({ status: 500, error: "client_invalid" });
    expect(tokenForms().at(-1)!.redirect_uri).toBe(REDIRECT_URI);
  });

  it("malformed requests → 400 invalid_request with zero calls to Google", async () => {
    const p = await pkce();
    const code = "4/0Awell-formed-code";
    const bodies: unknown[] = [
      {},
      { code },
      { verifier: p.verifier },
      { code: "x y", verifier: p.verifier },
      { code: "short", verifier: p.verifier },
      { code: `${code}\n`, verifier: p.verifier },
      { code: `${code}&client_id=evil`, verifier: p.verifier },
      { code: "c".repeat(513), verifier: p.verifier },
      { code: 7, verifier: p.verifier },
      { code, verifier: "short" },
      { code, verifier: "v".repeat(42) },
      { code, verifier: "v".repeat(129) },
      { code, verifier: `${"v".repeat(43)}&x=1` },
      { code, verifier: `${"v".repeat(43)}+` },
      { code, verifier: null },
      { code: [code], verifier: [p.verifier] },
    ];
    for (const body of bodies) {
      expect(await errorOf(await h.web("/web/token", body)), JSON.stringify(body)).toEqual({ status: 400, error: "invalid_request" });
    }
    expect(h.google.calls).toEqual([]);
  });
});

describe("POST /web/refresh", () => {
  it("turns the cookie into an access token; the refresh token never shows, and the cookie is not set again", async () => {
    const { cookie } = await webSignIn(h);
    const sealed = (await sessionOf(cookie!))!;
    h.now += 3_600_000;
    const res = await refreshWith(`other=1; ${cookie}; theme=dark`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ access_token: expect.stringMatching(/^ya29\./), expires_in: 3599, scope: GRANTED_SCOPE, email: EMAIL, session_expires_in: WEB_SESSION_TTL_S - 3600 });
    expect(Object.keys(body)).toEqual(["access_token", "expires_in", "scope", "email", "session_expires_in"]);
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(h.google.calls.at(-1)!.form).toEqual({ grant_type: "refresh_token", refresh_token: sealed.refreshToken, client_id: WEB_CLIENT_ID, client_secret: WEB_CLIENT_SECRET });
  });

  it("the whole round: start, consent, token, refreshes, sign out", async () => {
    const { res, cookie } = await webSignIn(h, { remember: true });
    const first = ((await res.json()) as { access_token: string }).access_token;
    const second = ((await (await refreshWith(cookie)).json()) as { access_token: string }).access_token;
    const third = ((await (await refreshWith(cookie)).json()) as { access_token: string }).access_token;
    expect(new Set([first, second, third]).size).toBe(3);
    const out = await h.web("/web/logout", {}, { cookie: cookie! });
    expect(out.status).toBe(200);
    // the browser has dropped the cookie
    expect(await errorOf(await refreshWith(null))).toEqual({ status: 401, error: "no_session" });
    expect(h.google.kinds()).toEqual(["token", "token", "token"]);
  });

  it("the lifetime is in the seal, counted from the sign-in and never extended — however often the session is used", async () => {
    const { cookie } = await webSignIn(h);
    for (let hour = 1; hour < 12; hour++) {
      h.now += 3_600_000;
      const res = await refreshWith(cookie);
      expect(res.status).toBe(200);
      expect(((await res.json()) as { session_expires_in: number }).session_expires_in).toBe(WEB_SESSION_TTL_S - hour * 3600);
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    // one second before the end it still works; at the end it does not, and Google is not asked
    h.now = T0 + WEB_SESSION_TTL_S * 1000 - 1000;
    const last = await refreshWith(cookie);
    expect(((await last.json()) as { session_expires_in: number }).session_expires_in).toBe(1);
    const asked = h.google.calls.length;
    h.now += 1000;
    const over = await refreshWith(cookie);
    expect(await errorOf(over)).toEqual({ status: 401, error: "no_session" });
    expect(over.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
    expect(h.google.calls.length).toBe(asked);
    // 30 days for "stay signed in": the persistent cookie outlives nothing either
    h.now = T0;
    const remembered = await webSignIn(h, { remember: true });
    h.now = T0 + WEB_SESSION_REMEMBER_TTL_S * 1000 - 1000;
    expect((await refreshWith(remembered.cookie)).status).toBe(200);
    h.now += 1000;
    expect(await errorOf(await refreshWith(remembered.cookie))).toEqual({ status: 401, error: "no_session" });
  });

  it("no cookie → 401 no_session and nothing to clear; Google is not asked — a refresh token in the body is not looked at", async () => {
    const { cookie } = await webSignIn(h);
    const sealed = (await sessionOf(cookie!))!;
    const asked = h.google.calls.length;
    for (const headers of [{}, { cookie: "" }, { cookie: "other=1; theme=dark" }, { cookie: `gclone-web=${cookie!.split("=")[1]}` }, { cookie: `__Secure-gclone-web=${cookie!.split("=")[1]}` }, { cookie: `${WEB_COOKIE}2=${cookie!.split("=")[1]}` }, { authorization: `Bearer ${cookie!.split("=")[1]}` }]) {
      const res = await h.web("/web/refresh", { refresh_token: sealed.refreshToken, client: "device", cookie: cookie }, headers as Record<string, string>);
      expect(await errorOf(res), JSON.stringify(Object.keys(headers))).toEqual({ status: 401, error: "no_session" });
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    expect(h.google.calls.length).toBe(asked);
  });

  it("the session cookie is found among other cookies, however the browser sends them: one Cookie field or one per cookie (HTTP/2, HTTP/3), in any order", async () => {
    const { cookie } = await webSignIn(h);
    const others = ["theme=dark", "_ga=GA1.2.3; other=a=b", "x=1"];
    // Several `Cookie` fields: the runtime hands them over joined with ", ".
    const fields = async (cookies: string[]) => {
      const headers = new Headers({ "content-type": "application/json", ...SAME_ORIGIN });
      for (const value of cookies) headers.append("cookie", value);
      expect(headers.get("cookie")).toBe(cookies.join(", "));
      const response = await handle(new Request(`${ORIGIN}/web/refresh`, { method: "POST", headers, body: "{}" }), h.env, h.deps);
      await h.record("/web/refresh", response);
      return response;
    };
    const ways: Array<[string, () => Promise<Response>]> = [
      ["one field, the session last", () => refreshWith(`${others.join("; ")}; ${cookie}`)],
      ["one field, the session first", () => refreshWith(`${cookie}; ${others.join("; ")}`)],
      ["one field, no space after the semicolon", () => refreshWith(`x=1;${cookie};y=2`)],
      ["two fields, the session second", () => fields([others[0]!, cookie!])],
      ["two fields, the session first", () => fields([cookie!, others[0]!])],
      ["four fields, the session in the middle", () => fields([others[0]!, others[1]!, cookie!, others[2]!])],
    ];
    for (const [what, send] of ways) {
      const res = await send();
      expect(res.status, what).toBe(200);
      expect(res.headers.get("set-cookie"), what).toBeNull();
      expect(((await res.json()) as { email: string }).email).toBe(EMAIL);
    }
    // No session among them: nothing to clear either.
    const none = await fields(others);
    expect(await errorOf(none)).toEqual({ status: 401, error: "no_session" });
    expect(none.headers.get("set-cookie")).toBeNull();
  });

  it("a cookie that does not open — tampered, truncated, of another key, of another kind, expired — → 401 no_session, the browser is told to drop it, and Google is not asked", async () => {
    const { cookie } = await webSignIn(h);
    const blob = cookie!.slice(WEB_COOKIE.length + 1);
    const raw = b64urlDecode(blob)!;
    const flip = (at: number) => {
      const copy = raw.slice();
      copy[at]! ^= 0x01;
      return `${WEB_COOKIE}=${b64urlEncode(copy)}`;
    };
    const asked = h.google.calls.length;
    const bad = [
      flip(0), // version
      flip(1), // kind
      flip(5), // nonce
      flip(14), // sealed iat
      flip(20), // sealed exp: a longer life is not for the browser to choose
      flip(30), // the address
      flip(raw.length - 20), // the refresh token
      flip(raw.length - 1), // tag
      `${WEB_COOKIE}=${blob.slice(0, -8)}`,
      `${WEB_COOKIE}=${blob}AAAA`,
      `${WEB_COOKIE}=AAAA`,
      `${WEB_COOKIE}=`,
      `${WEB_COOKIE}="${blob}"`,
      `${WEB_COOKIE}=${"A".repeat(5000)}`,
      // sealed by someone without this Worker's key: any lifetime, any address, any token
      await sealedCookie({ iat: 1, exp: 0xffff_fff0, refreshToken: "1//0forged-refresh-token-xyz" }, new Uint8Array(32).fill(9)),
      await sealedCookie({ iat: 1, exp: 0xffff_fff0, refreshToken: "1//0forged-refresh-token-xyz" }, new Uint8Array(32)),
      // sealed under this key, and over
      await sealedCookie({ iat: NOW_S - 100, exp: NOW_S, refreshToken: "1//0expired-refresh-token-xyz" }),
      await sealedCookie({ iat: 0, exp: 1, refreshToken: "1//0expired-refresh-token-xyz" }),
    ];
    for (const value of bad) {
      const res = await refreshWith(value);
      expect(await errorOf(res), value.slice(0, 40)).toEqual({ status: 401, error: "no_session" });
      expect(res.headers.get("set-cookie")).toBe(`${WEB_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    }
    expect(h.google.calls.length).toBe(asked);
    expect(h.google.revokes()).toEqual([]);
    // the first cookie of that name counts: a second one cannot stand in for it
    expect((await errorOf(await refreshWith(`${WEB_COOKIE}=AAAA; ${cookie}`))).error).toBe("no_session");
    expect((await refreshWith(`${cookie}; ${WEB_COOKIE}=AAAA`)).status).toBe(200);
  });

  it("replacing SEAL_KEY ends every browser session at once — and no device login", async () => {
    const deviceToken = await obtainRefreshToken(h);
    const { cookie } = await webSignIn(h, { remember: true });
    expect((await refreshWith(cookie)).status).toBe(200);
    const asked = h.google.calls.length;
    h.env = withWeb({ SEAL_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(0x5a))) });
    const res = await refreshWith(cookie);
    expect(await errorOf(res)).toEqual({ status: 401, error: "no_session" });
    expect(res.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
    expect(h.google.calls.length).toBe(asked);
    // nothing else takes that refresh token: not /refresh, under any client name
    const sealed = (await sessionOf(cookie!))!;
    for (const client of [undefined, "web", "legacy"]) {
      const refused = await h.post("/refresh", { refresh_token: sealed.refreshToken, ...(client === undefined ? {} : { client }) });
      expect(refused.status, String(client)).toBe(400);
    }
    expect(h.google.calls.length).toBe(asked);
    // a new sign-in under the new key works, and the devices never noticed
    const again = await webSignIn(h);
    expect((await refreshWith(again.cookie)).status).toBe(200);
    expect((await h.post("/refresh", { refresh_token: deviceToken, client: "device" })).status).toBe(200);
  });

  it("an address taken off ALLOWED_EMAILS is cut off at the next refresh — from the sealed address, no ID token needed", async () => {
    const { cookie } = await webSignIn(h);
    const sealed = (await sessionOf(cookie!))!;
    h.env.ALLOWED_EMAILS = "someone-else@example.com";
    const res = await refreshWith(cookie);
    expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
    expect(((await res.json()) as { message: string }).message).toContain("m***@example.com");
    expect(res.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
    // revoked, and Google was not asked for an access token first
    expect(h.google.kinds()).toEqual(["token", "revoke"]);
    expect(h.google.revokes()[0]!.form).toEqual({ token: sealed.refreshToken });
  });

  it("an ID token in Google's refresh answer is checked as well: an address that is no longer allowed, or no longer verified, ends the session", async () => {
    const idToken = (claims: Record<string, unknown>) => makeIdToken({ iss: "https://accounts.google.com", aud: WEB_CLIENT_ID, email: EMAIL, email_verified: true, ...claims });
    for (const claims of [{ email: "renamed@example.net" }, { email_verified: false }]) {
      h.reset();
      h.env = withWeb();
      const { cookie } = await webSignIn(h);
      h.google.setIdToken((await sessionOf(cookie!))!.refreshToken, idToken(claims));
      const res = await refreshWith(cookie);
      expect(await errorOf(res)).toEqual({ status: 403, error: "email_not_allowed" });
      expect(res.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
      expect(h.google.kinds()).toEqual(["token", "token", "revoke"]);
    }
    // the allowed address, or an ID token that is not Google's for the web client: nothing happens
    for (const token of [idToken({}), idToken({ email: "renamed@example.net", aud: CLIENT_ID }), idToken({ email: "renamed@example.net", iss: "https://evil.example" }), "garbage"]) {
      h.reset();
      h.env = withWeb();
      const { cookie } = await webSignIn(h);
      h.google.setIdToken((await sessionOf(cookie!))!.refreshToken, token);
      expect((await refreshWith(cookie)).status).toBe(200);
      expect(h.google.revokes()).toEqual([]);
    }
  });

  it("a token Google no longer honours ends the session; a failure of Google or of the Worker's client does not", async () => {
    const { cookie } = await webSignIn(h);
    const kept: Array<[number, unknown, number, string]> = [
      [503, "<html>oops</html>", 502, "upstream_error"],
      [200, "not json", 502, "upstream_error"],
      [200, { expires_in: 3599 }, 502, "upstream_error"],
      [401, { error: "invalid_client" }, 500, "client_invalid"],
      [400, { error: "unauthorized_client" }, 500, "client_invalid"],
      [400, { error: "admin_policy_enforced" }, 403, "access_denied"],
      [400, { error: "something_new" }, 502, "upstream_error"],
    ];
    for (const [googleStatus, googleBody, status, error] of kept) {
      h.google.nextAnswer(googleStatus, googleBody);
      const res = await refreshWith(cookie);
      expect(await errorOf(res), `${googleStatus} ${JSON.stringify(googleBody)}`).toEqual({ status, error });
      expect(res.headers.get("set-cookie"), "the cookie is kept").toBeNull();
    }
    h.google.nextThrows(new TypeError("network down"));
    const down = await refreshWith(cookie);
    expect(await errorOf(down)).toEqual({ status: 502, error: "upstream_error" });
    expect(down.headers.get("set-cookie")).toBeNull();
    // still signed in once Google answers again
    expect((await refreshWith(cookie)).status).toBe(200);
    // revoked at Google (the app was removed, or another sign-in was refused and revoked the grant)
    h.google.revokeAll();
    const dead = await refreshWith(cookie);
    expect(await errorOf(dead)).toEqual({ status: 400, error: "invalid_grant" });
    expect(dead.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
  });

  it("a grant that has become wider than gclone's scopes gets no access token: 403 scope_not_allowed, no revoke", async () => {
    const { cookie } = await webSignIn(h);
    h.google.accessTokens.add("ya29.wide-access-token");
    h.google.nextAnswer(200, { access_token: "ya29.wide-access-token", expires_in: 3599, scope: WIDE_SCOPE, token_type: "Bearer" });
    const res = await refreshWith(cookie);
    expect(await errorOf(res)).toEqual({ status: 403, error: "scope_not_allowed" });
    expect(await res.text()).not.toContain("ya29.");
    expect(h.google.revokes()).toEqual([]);
    // no scope field at all (Google leaves it out at times) is not "wider"
    h.google.accessTokens.add("ya29.plain-access-token");
    h.google.nextAnswer(200, { access_token: "ya29.plain-access-token", expires_in: 3599 });
    const plain = await refreshWith(cookie);
    expect(await plain.json()).toEqual({ access_token: "ya29.plain-access-token", expires_in: 3599, scope: "", email: EMAIL, session_expires_in: WEB_SESSION_TTL_S });
  });
});

describe("POST /web/logout", () => {
  it("drops the cookie and the origin's storage; Google is not asked and nothing is revoked", async () => {
    const { cookie } = await webSignIn(h);
    const asked = h.google.calls.length;
    const res = await h.web("/web/logout", {}, { cookie: cookie! });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({});
    expect(res.headers.get("set-cookie")).toBe(`${WEB_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    // "storage", not "cookies": that directive would clear the cookies of the whole registrable domain
    expect(res.headers.get("clear-site-data")).toBe('"storage"');
    expect(h.google.calls.length).toBe(asked);
    // the cookie itself is not invalidated (the Worker keeps no list): a copy of it works until its sealed end
    expect((await refreshWith(cookie)).status).toBe(200);
  });

  it("there is no revoke parameter: whatever the body says, Google is not asked", async () => {
    const { cookie } = await webSignIn(h);
    const asked = h.google.calls.length;
    for (const body of [{ revoke: true }, { revoke: "true" }, { everything: true }]) {
      const res = await h.web("/web/logout", body, { cookie: cookie! });
      expect(await res.json()).toEqual({});
    }
    expect(h.google.calls.length).toBe(asked);
  });

  it("works without a cookie, with a cookie that does not open, and while the viewer or the whole Worker is not configured", async () => {
    for (const env of [withWeb(), testEnv(), withWeb({ SEAL_KEY: "left-over" }), { GOOGLE_CLIENT_ID: "", GOOGLE_CLIENT_SECRET: "" } as Env]) {
      h.env = env;
      for (const headers of [{}, { cookie: `${WEB_COOKIE}=AAAA` }]) {
        const res = await h.web("/web/logout", {}, headers as Record<string, string>);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({});
        expect(res.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
        expect(res.headers.get("clear-site-data")).toBe('"storage"');
      }
    }
    expect(h.google.calls).toEqual([]);
  });
});

describe("only the viewer's own page may call the web routes", () => {
  it("another origin, a sibling host, another scheme or port, `null`, no Origin: 403 cross_origin on all four routes — with a valid cookie too, which is neither used nor cleared", async () => {
    const { cookie } = await webSignIn(h);
    const p = await pkce();
    const code = h.google.consent(await webStart(h, p));
    const asked = h.google.calls.length;
    const bodies: Record<string, unknown> = { "/web/start": { challenge: p.challenge, state: p.state }, "/web/token": { code, verifier: p.verifier }, "/web/refresh": {}, "/web/logout": {} };
    for (const path of WEB_ROUTES) {
      for (const headers of FOREIGN) {
        const res = await rawPost(path, bodies[path], { ...headers, cookie: cookie! });
        expect(await errorOf(res), `${path} ${JSON.stringify(headers)}`).toEqual({ status: 403, error: "cross_origin" });
        expect(res.headers.get("set-cookie")).toBeNull();
        expect(res.headers.get("clear-site-data")).toBeNull();
      }
    }
    expect(h.google.calls.length).toBe(asked);
    // the session and the code are untouched
    expect((await refreshWith(cookie)).status).toBe(200);
    expect((await h.web("/web/token", { code, verifier: p.verifier })).status).toBe(200);
    // a browser without Sec-Fetch-Site (an old one) passes on the Origin header alone
    expect((await rawPost("/web/refresh", {}, { origin: ORIGIN, cookie: cookie! })).status).toBe(200);
  });

  it("no CORS: no route answers a preflight or an access-control header, so another origin could not even read a refusal", async () => {
    const { cookie } = await webSignIn(h);
    const preflight = { origin: "https://evil.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type" };
    for (const path of WEB_ROUTES) {
      const options = await h.call(path, { method: "OPTIONS", headers: preflight });
      expect(options.status).toBe(405);
      expect(options.headers.get("allow")).toBe("POST");
      const refused = await rawPost(path, {}, { ...preflight, cookie: cookie! });
      const allowed = await h.web(path, {}, { cookie: cookie! });
      for (const res of [options, refused, allowed]) {
        expect([...res.headers.keys()].filter((name) => name.startsWith("access-control-") || name === "vary")).toEqual([]);
      }
    }
  });

  it("the origin is the request's own: a Host or X-Forwarded-Host header does not move it", async () => {
    const res = await rawPost("/web/refresh", {}, { origin: "https://evil.example", "sec-fetch-site": "same-origin", host: "evil.example", "x-forwarded-host": "evil.example" });
    expect(await errorOf(res)).toEqual({ status: 403, error: "cross_origin" });
  });

  it("the order of the checks: path, method, origin, rate limit, configuration, body, the route's own", async () => {
    const limiter = new FakeRateLimiter(false);
    h.env = testEnv({ RATE_LIMIT: limiter });
    const junk = { method: "POST", headers: { "content-type": "text/plain", origin: "https://evil.example" }, body: "x" };
    expect((await errorOf(await h.call("/web/token", { method: "GET" }))).error).toBe("method_not_allowed");
    // another site's request is refused before it is counted
    expect((await errorOf(await h.call("/web/token", junk))).error).toBe("cross_origin");
    expect(limiter.keys).toEqual([]);
    expect((await errorOf(await h.call("/web/token", { ...junk, headers: { "content-type": "text/plain", ...SAME_ORIGIN } }))).error).toBe("rate_limited");
    expect(limiter.keys).toHaveLength(1);
    h.env = testEnv();
    expect((await errorOf(await h.call("/web/token", { ...junk, headers: { "content-type": "text/plain", ...SAME_ORIGIN } }))).error).toBe("server_misconfigured");
    h.env = withWeb();
    expect((await errorOf(await h.call("/web/token", { ...junk, headers: { "content-type": "text/plain", ...SAME_ORIGIN } }))).error).toBe("unsupported_media_type");
    expect((await errorOf(await h.call("/web/token", { ...junk, headers: { "content-type": "application/json", ...SAME_ORIGIN } }))).error).toBe("invalid_request");
    expect(h.google.calls).toEqual([]);
  });

  it("requests of another site are never counted: a page open in the owner's browser cannot use up the owner's budget", async () => {
    // What `fetch(url, { method: "POST", mode: "no-cors", body: "x" })` sends from any page, without a preflight.
    const foreign = { method: "POST", headers: { "content-type": "text/plain;charset=UTF-8", origin: "https://evil.example", "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors", "cf-connecting-ip": "203.0.113.7" }, body: "x" };
    const { cookie } = await webSignIn(h);
    const deviceToken = await obtainRefreshToken(h);
    // A limiter with the real binding's budget of 30: it refuses the 31st request of a key.
    const counts = new Map<string, number>();
    h.env.RATE_LIMIT = {
      async limit({ key }) {
        counts.set(key, (counts.get(key) ?? 0) + 1);
        return { success: counts.get(key)! <= 30 };
      },
    };
    const asked = h.google.calls.length;
    for (let i = 0; i < 40; i += 1) {
      for (const path of [...WEB_ROUTES, "/device/start", "/device/poll", "/refresh"]) {
        const res = await h.call(path, foreign);
        expect(await errorOf(res), path).toEqual({ status: 403, error: "cross_origin" });
        expect(res.headers.get("set-cookie")).toBeNull();
      }
    }
    expect(counts.size).toBe(0);
    expect(h.google.calls.length).toBe(asked);
    // The owner, from the same address: a token for the viewer, a refresh for a device, and a sign-out that arrives.
    const own = { "cf-connecting-ip": "203.0.113.7" };
    expect((await refreshWith(cookie, own)).status).toBe(200);
    expect((await h.post("/refresh", { refresh_token: deviceToken, client: "device" }, own)).status).toBe(200);
    const out = await h.web("/web/logout", {}, { cookie: cookie!, ...own });
    expect(out.status).toBe(200);
    expect(out.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
    expect(counts.get("203.0.113.7")).toBe(2);
  });
});

describe("transport rules of the web routes", () => {
  it("POST only: 405 with Allow, as JSON", async () => {
    for (const path of WEB_ROUTES) {
      for (const method of ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]) {
        const res = await h.call(path, { method, headers: SAME_ORIGIN });
        expect(res.status, `${method} ${path}`).toBe(405);
        expect(res.headers.get("allow")).toBe("POST");
        if (method !== "HEAD") expect((await errorOf(res)).error).toBe("method_not_allowed");
      }
    }
  });

  it("application/json bodies of at most 8 KiB that are a JSON object", async () => {
    const { cookie } = await webSignIn(h);
    const send = (path: string, type: string, body: string) => h.call(path, { method: "POST", headers: { "content-type": type, ...SAME_ORIGIN, cookie: cookie! }, body });
    for (const path of WEB_ROUTES) {
      expect((await send(path, "text/plain", "{}")).status, path).toBe(415);
      expect((await send(path, "application/x-www-form-urlencoded", "a=b")).status, path).toBe(415);
      expect((await errorOf(await send(path, "application/json", `{"pad":"${"x".repeat(8192)}"}`))).error, path).toBe("payload_too_large");
      for (const body of ["", "x", "[]", "null", '"{}"', "7"]) {
        expect(await errorOf(await send(path, "application/json", body)), `${path} ${body}`).toEqual({ status: 400, error: "invalid_request" });
      }
      expect((await send(path, "application/json; charset=utf-8", "{}")).status, path).not.toBe(415);
    }
    // none of these touched the cookie
    expect((await refreshWith(cookie)).status).toBe(200);
  });

  it("the rate limit covers start, token and refresh: 429 with Retry-After: 60, Google is not contacted, the cookie is neither used nor cleared", async () => {
    const { cookie } = await webSignIn(h);
    const p = await pkce();
    const code = h.google.consent(await webStart(h, p));
    const asked = h.google.calls.length;
    const limiter = new FakeRateLimiter(false);
    h.env.RATE_LIMIT = limiter;
    const bodies: Record<string, unknown> = { "/web/start": { challenge: p.challenge, state: p.state }, "/web/token": { code, verifier: p.verifier }, "/web/refresh": {} };
    for (const path of Object.keys(bodies)) {
      const res = await h.web(path, bodies[path], { cookie: cookie!, "cf-connecting-ip": "203.0.113.7" });
      expect(await errorOf(res), path).toEqual({ status: 429, error: "rate_limited" });
      expect(res.headers.get("retry-after")).toBe("60");
      expect(res.headers.get("set-cookie")).toBeNull();
    }
    expect(limiter.keys).toEqual(Array(3).fill("203.0.113.7"));
    expect(h.google.calls.length).toBe(asked);
    // the limiter is shared with the device routes: one budget per address
    await h.post("/device/start", {}, { "cf-connecting-ip": "203.0.113.7" });
    await h.web("/web/refresh", {}, { "cf-connecting-ip": "2001:db8:1:2:3:4:5:6" });
    expect(limiter.keys.slice(3)).toEqual(["203.0.113.7", "2001:db8:1:2::/64"]);
    // the pages are never limited
    expect((await h.get("/")).status).toBe(200);
    expect((await h.get("/callback?code=x")).status).toBe(200);
    expect(limiter.keys).toHaveLength(5);
    // through again: the sign-in that was under way goes on
    h.env.RATE_LIMIT = new FakeRateLimiter(true);
    expect((await h.web("/web/token", { code, verifier: p.verifier })).status).toBe(200);
    expect((await refreshWith(cookie)).status).toBe(200);
    // a limiter that fails must not lock the owner out
    h.env.RATE_LIMIT = new FakeRateLimiter(true, true);
    expect((await refreshWith(cookie)).status).toBe(200);
  });

  it("sign-out is never limited: over the limit it still clears the cookie and the storage, and is not counted", async () => {
    const { cookie } = await webSignIn(h);
    const limiter = new FakeRateLimiter(false);
    h.env.RATE_LIMIT = limiter;
    expect(await errorOf(await refreshWith(cookie))).toEqual({ status: 429, error: "rate_limited" });
    for (const headers of [{ cookie: cookie! }, {}]) {
      const res = await h.web("/web/logout", {}, headers as Record<string, string>);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({});
      expect(res.headers.get("set-cookie")).toBe(CLEAR_COOKIE);
      expect(res.headers.get("clear-site-data")).toBe('"storage"');
    }
    expect(limiter.keys).toHaveLength(1);
    // its other checks stand: another site cannot sign the owner out, and the body is still a JSON object
    expect(await errorOf(await rawPost("/web/logout", {}, { origin: "https://evil.example", cookie: cookie! }))).toEqual({ status: 403, error: "cross_origin" });
    expect((await h.call("/web/logout", { method: "POST", headers: { "content-type": "text/plain", ...SAME_ORIGIN }, body: "{}" })).status).toBe(415);
    expect(limiter.keys).toHaveLength(1);
  });

  it("never throws: an unexpected failure becomes a 500 without detail, and sets no cookie", async () => {
    const p = await pkce();
    const code = h.google.consent(await webStart(h, p));
    h.env = new Proxy(withWeb(), {
      get(target, key) {
        if (key === "ALLOWED_EMAILS") throw new Error("env exploded: test-detail");
        return Reflect.get(target, key);
      },
    });
    const res = await h.web("/web/token", { code, verifier: p.verifier });
    expect(await errorOf(res)).toEqual({ status: 500, error: "internal_error" });
    expect(await res.text()).not.toContain("test-detail");
    expect(res.headers.get("set-cookie")).toBeNull();
  });
});

describe("the device routes and the viewer", () => {
  it("a device is not a web page: a request that names where a page sent it from (Origin, Sec-Fetch-Site) is refused before it is counted or Google is asked", async () => {
    const refreshToken = await obtainRefreshToken(h);
    const asked = h.google.calls.length;
    const limiter = new FakeRateLimiter(true);
    h.env.RATE_LIMIT = limiter;
    const bodies: Record<string, unknown> = { "/device/start": {}, "/device/poll": { device_code: "x".repeat(40) }, "/refresh": { refresh_token: refreshToken, client: "device" } };
    for (const browser of [{ origin: "https://evil.example", "sec-fetch-site": "cross-site" }, { origin: "https://evil.example" }, { "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "none" }, SAME_ORIGIN, { origin: "null" }]) {
      for (const [path, body] of Object.entries(bodies)) {
        const res = await h.post(path, body, browser as Record<string, string>);
        expect(await errorOf(res), `${path} ${JSON.stringify(browser)}`).toEqual({ status: 403, error: "cross_origin" });
        expect([...res.headers.keys()].filter((name) => name.startsWith("access-control-"))).toEqual([]);
      }
      // as a browser sends it from another site without a preflight: a body that is not JSON
      const simple = await h.call("/device/start", { method: "POST", headers: { "content-type": "text/plain;charset=UTF-8", ...(browser as Record<string, string>) }, body: "x" });
      expect((await errorOf(simple)).error).toBe("cross_origin");
    }
    expect(limiter.keys).toEqual([]);
    expect(h.google.calls.length).toBe(asked);
    // the gclone command sends neither header
    expect((await h.post("/refresh", { refresh_token: refreshToken, client: "device" })).status).toBe(200);
    expect(limiter.keys).toHaveLength(1);
  });

  it("a cookie means nothing to them", async () => {
    const { cookie } = await webSignIn(h);
    const withCookie = { cookie: cookie! };
    const started = await h.post("/device/start", {}, withCookie);
    expect(started.status).toBe(200);
    const { device_code, user_code } = (await started.json()) as { device_code: string; user_code: string };
    h.google.approve(user_code);
    const polled = await h.post("/device/poll", { device_code }, withCookie);
    expect(polled.status).toBe(200);
    const { refresh_token } = (await polled.json()) as { refresh_token: string };
    const refreshed = await h.post("/refresh", { refresh_token, client: "device" }, withCookie);
    expect(refreshed.status).toBe(200);
    expect(Object.keys((await refreshed.json()) as object).sort()).toEqual(["access_token", "expires_in", "scope"]);
    for (const res of [started, polled, refreshed]) expect(res.headers.get("set-cookie")).toBeNull();
    // every device request went to Google under the device client
    for (const form of h.google.calls.slice(1).map((c) => c.form)) expect(form.client_id).toBe(CLIENT_ID);
    // /refresh without a refresh token is malformed, cookie or not: the cookie is not a credential there
    expect(await errorOf(await h.post("/refresh", { client: "device" }, { cookie: cookie! }))).toEqual({ status: 400, error: "invalid_request" });
  });

  it("a device login's refresh token does not open a web session, and the web session's does not refresh a device", async () => {
    const deviceToken = await obtainRefreshToken(h);
    // a cookie made of the bare token, and one sealed by someone else around it
    for (const value of [`${WEB_COOKIE}=${deviceToken}`, await sealedCookie({ iat: NOW_S, exp: NOW_S + 3600, refreshToken: deviceToken }, new Uint8Array(32).fill(3))]) {
      expect(await errorOf(await refreshWith(value))).toEqual({ status: 401, error: "no_session" });
    }
    const { cookie } = await webSignIn(h);
    const sealed = (await sessionOf(cookie!))!;
    const asked = h.google.calls.length;
    expect(await errorOf(await h.post("/refresh", { refresh_token: sealed.refreshToken }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(h.google.calls.length).toBe(asked);
  });
});

describe("the viewer's page", () => {
  it("/ and /callback are the same bytes — index.html with the status line — whatever the query says, with the header set of src/headers.json", async () => {
    const home = await h.get("/");
    const callback = await h.get("/callback?state=AAAAAAAAAAAAAAAAAAAAAA&code=4/0Asecret-code_of.google&scope=email%20openid&iss=https://accounts.google.com&authuser=0");
    const junk = await h.get("/?<script>alert(1)</script>&Status:%20hacked&x=<!--gclone-status-->");
    const text = await home.text();
    expect(text).toBe(VIEWER_INDEX.replace(STATUS_MARKER, "Status: ready"));
    for (const res of [callback, junk]) expect(await res.text()).toBe(text);
    expect(text).not.toContain("4/0Asecret");
    expect(text).not.toContain(STATUS_MARKER);
    for (const res of [home, callback, junk]) {
      expect(res.status).toBe(200);
      expect(Object.fromEntries(res.headers)).toEqual({
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        ...Object.fromEntries(Object.entries(headersJson).map(([name, value]) => [name.toLowerCase(), value])),
      });
    }
    expect(home.headers.get("content-security-policy")).toBe(VIEWER_CSP);
  });

  it("the header set is the one of the design", () => {
    expect(VIEWER_HEADERS).toEqual({
      "Content-Security-Policy":
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; worker-src 'self'; " +
        "connect-src 'self' https://www.googleapis.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types gclone",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    });
    // no inline or foreign script, no blob:, no eval beyond wasm compilation, nothing third-party
    expect(VIEWER_CSP).not.toMatch(/'unsafe-inline'|'unsafe-eval'|blob:|data:|\*|http:/);
    expect(VIEWER_CSP.match(/https:\/\/[^ ;]+/g)).toEqual(["https://www.googleapis.com"]);
  });

  it("the Worker asks the assets binding for /index.html and nothing else, and passes nothing of the request on", async () => {
    const assets = new FakeAssets();
    h.env = withWeb({ ASSETS: assets });
    await h.get("/callback?code=4/0Asecret-code_of.google&state=x", { cookie: `${WEB_COOKIE}=AAAA`, authorization: "Bearer x", "if-none-match": '"abc"' });
    await h.get("/?q=1");
    expect(assets.requests).toEqual([
      { method: "GET", url: "https://assets.invalid/index.html", headers: [] },
      { method: "GET", url: "https://assets.invalid/index.html", headers: [] },
    ]);
    // no other route touches it
    await h.get("/privacy");
    await h.get("/index.html");
    await h.get("/a/0123456789abcdef/shell.js");
    await h.web("/web/refresh", {});
    await h.post("/device/start", {});
    expect(assets.requests).toHaveLength(2);
  });

  it("the status line: ready, the viewer not configured, nothing configured — put in once, and never interpreted", async () => {
    const page = async (env: Env) => (await handle(new Request(`${ORIGIN}/`), env, h.deps)).text();
    const index = (line: string) => VIEWER_INDEX.replace(STATUS_MARKER, line);
    expect(await page(withWeb())).toBe(index("Status: ready"));
    for (const env of [testEnv({ ASSETS: new FakeAssets() }), withWeb({ SEAL_KEY: "nope" }), withWeb({ GOOGLE_LEGACY_CLIENT_SECRET: "" })]) {
      expect(await page(env)).toBe(index("Status: ready. The web viewer is not configured: it needs GOOGLE_LEGACY_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET and SEAL_KEY."));
    }
    expect(await page(withWeb({ GOOGLE_CLIENT_ID: "" }))).toBe(index("Status: not configured"));
    // a page with the marker twice gets the line once (check-dist refuses such a page); one without it is served as it is
    const twice = `<p>${STATUS_MARKER}</p><p>${STATUS_MARKER}</p>`;
    expect(await page(withWeb({ ASSETS: new FakeAssets({ "/index.html": twice }) }))).toBe(`<p>Status: ready</p><p>${STATUS_MARKER}</p>`);
    expect(await page(withWeb({ ASSETS: new FakeAssets({ "/index.html": "<p>$&$1$`</p>" }) }))).toBe("<p>$&$1$`</p>");
    h.logs.length = 0; // these went past the harness's record
  });

  it("a deployment without the viewer's files — no binding, no index.html, a binding that fails — serves the Worker's own home page on both paths", async () => {
    const failing = { fetch: async () => Promise.reject(new Error("assets down")) };
    for (const env of [withWeb({ ASSETS: undefined as unknown as FakeAssets }), withWeb({ ASSETS: new FakeAssets({}) }), withWeb({ ASSETS: failing }), testEnv()]) {
      h.env = env;
      for (const path of ["/", "/callback?code=4/0Asecret-code_of.google"]) {
        const res = await h.get(path);
        expect(res.status).toBe(200);
        expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
        expect(res.headers.get("cache-control")).toBe("no-store");
        expect(res.headers.get("content-security-policy")).toBe("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        expect(res.headers.get("strict-transport-security")).toBe("max-age=63072000; includeSubDomains");
        const text = await res.text();
        expect(text).toContain("gclone sign-in helper");
        expect(text).toContain("The web viewer's files are not part of this deployment.");
        expect(text).toContain("Status: ready");
        expect(text).not.toContain("4/0Asecret");
        expect(text).not.toContain("<script");
      }
    }
  });

  it("GET only, never limited, and no cookie is read or set", async () => {
    h.env.RATE_LIMIT = new FakeRateLimiter(false);
    for (const path of ["/", "/callback"]) {
      const res = await h.get(path, { cookie: `${WEB_COOKIE}=AAAA` });
      expect(res.status).toBe(200);
      expect(res.headers.get("set-cookie")).toBeNull();
      for (const method of ["POST", "HEAD", "PUT", "DELETE"]) {
        const refused = await h.call(path, { method });
        expect(refused.status, `${method} ${path}`).toBe(405);
        expect(refused.headers.get("allow")).toBe("GET");
      }
    }
    expect((h.env.RATE_LIMIT as FakeRateLimiter).keys).toEqual([]);
  });

  it("the privacy page says what the cookie is", async () => {
    const text = await (await h.get("/privacy")).text();
    expect(text).toContain("__Host-gclone-web");
    expect(text).not.toContain("sets no cookies");
    expect(text).toContain("12 hours");
    expect(text).toContain("30 days");
  });
});

describe("https only", () => {
  it("GET and HEAD over http → 308 to the same address under https, path and query unchanged, no body", async () => {
    const urls = [
      ["http://auth.test/", "https://auth.test/"],
      ["http://auth.test/callback?code=4/0Ax&state=y%20z&iss=https://accounts.google.com", "https://auth.test/callback?code=4/0Ax&state=y%20z&iss=https://accounts.google.com"],
      ["http://auth.test/privacy", "https://auth.test/privacy"],
      // before routing: also a path the Worker does not know, and the paths of the JSON routes
      ["http://auth.test/nowhere?x=1", "https://auth.test/nowhere?x=1"],
      ["http://auth.test/web/refresh", "https://auth.test/web/refresh"],
      ["http://auth.test:8080/?a=b", "https://auth.test:8080/?a=b"],
      ["http://sub.auth.test/", "https://sub.auth.test/"],
      ["http://203.0.113.9/", "https://203.0.113.9/"],
    ] as const;
    for (const [url, location] of urls) {
      for (const method of ["GET", "HEAD"]) {
        const res = await h.call(url, { method, headers: { cookie: `${WEB_COOKIE}=AAAA` } });
        expect(res.status, `${method} ${url}`).toBe(308);
        expect(res.headers.get("location")).toBe(location);
        expect(await res.text()).toBe("");
        expect(res.headers.get("set-cookie")).toBeNull();
        expect(res.headers.get("content-type")).toBeNull();
      }
    }
    expect(h.logs.slice(0, 4).map((l) => JSON.parse(l))).toEqual([
      { route: "/", status: 308 },
      { route: "/", status: 308 },
      { route: "/callback", status: 308 },
      { route: "/callback", status: 308 },
    ]);
  });

  it("any other method over http → 400 https_required: not redirected, Google not asked, the cookie untouched", async () => {
    const { cookie } = await webSignIn(h);
    const deviceToken = await obtainRefreshToken(h);
    const asked = h.google.calls.length;
    const limiter = new FakeRateLimiter(true);
    h.env.RATE_LIMIT = limiter;
    const posts: Array<[string, unknown, Record<string, string>]> = [
      ["http://auth.test/web/refresh", {}, { origin: "http://auth.test", "sec-fetch-site": "same-origin", cookie: cookie! }],
      ["http://auth.test/web/logout", {}, { origin: "http://auth.test", cookie: cookie! }],
      ["http://auth.test/web/token", { code: "4/0Awell-formed-code", verifier: "v".repeat(43) }, { origin: "http://auth.test" }],
      ["http://auth.test/device/start", {}, {}],
      ["http://auth.test/refresh", { refresh_token: deviceToken, client: "device" }, {}],
      ["http://auth.test/nowhere", {}, {}],
      ["http://auth.test/", {}, {}],
    ];
    for (const [url, body, headers] of posts) {
      const res = await h.post(url, body, headers);
      expect(await errorOf(res), url).toEqual({ status: 400, error: "https_required" });
      expect(res.headers.get("location")).toBeNull();
      expect(res.headers.get("set-cookie")).toBeNull();
      expect(res.headers.get("clear-site-data")).toBeNull();
    }
    for (const method of ["PUT", "DELETE", "OPTIONS", "PATCH"]) {
      expect((await h.call("http://auth.test/", { method })).status, method).toBe(400);
    }
    expect(h.google.calls.length).toBe(asked);
    expect(limiter.keys).toEqual([]);
    expect(h.logs.slice(-5)[0]).toBe(JSON.stringify({ route: "/", status: 400, error: "https_required" }));
    // the session is as it was
    expect((await refreshWith(cookie)).status).toBe(200);
  });

  it("localhost, 127.0.0.1 and [::1] are served over http (development) — and are origins of their own", async () => {
    for (const origin of ["http://localhost", "http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"]) {
      const home = await h.call(`${origin}/`);
      expect(home.status, origin).toBe(200);
      expect(await home.text()).toContain("Status: ready");
      expect((await h.call(`${origin}/callback?code=x`)).status).toBe(200);
      // a sign-in under that origin: the redirect URI is its own
      const p = await pkce();
      const started = await h.call(`${origin}/web/start`, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify({ challenge: p.challenge, state: p.state }) });
      expect(started.status).toBe(200);
      const url = new URL(((await started.json()) as { authorization_url: string }).authorization_url);
      expect(url.searchParams.get("redirect_uri")).toBe(`${origin}/callback`);
      // … and the deployed origin is another origin there
      expect((await h.call(`${origin}/web/refresh`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: "{}" })).status).toBe(403);
    }
    // a name that only looks like one of them is not exempt
    for (const url of ["http://localhost.evil.example/", "http://127.0.0.1.evil.example/", "http://127.0.0.2/", "http://[::2]/", "http://0.0.0.0/"]) {
      expect((await h.call(url)).status, url).toBe(308);
    }
  });
});

describe("logging of the web routes", () => {
  it("one line per request with route, status and error code — never a query string, a cookie, a code, a verifier, a token or an address", async () => {
    await h.get("/");
    await h.get("/callback?state=AAAAAAAAAAAAAAAAAAAAAA&code=4/0Asecret-code_of.google&iss=https://accounts.google.com");
    const { cookie } = await webSignIn(h); // /web/start, /web/token
    await refreshWith(cookie);
    await refreshWith(null);
    await refreshWith(`${WEB_COOKIE}=AAAA`);
    await rawPost("/web/refresh", {}, { origin: "https://evil.example", cookie: cookie! });
    await h.web("/web/token", { code: "x y", verifier: "short" });
    const stranger = await webSignIn(h, { consent: { email: "stranger@example.net" } }); // /web/start, /web/token (+ revoke)
    expect(stranger.res.status).toBe(403);
    h.google.nextAnswer(503, "down");
    await refreshWith(cookie);
    await h.call("/web/logout", { method: "GET" });
    await h.web("/web/logout", {}, { cookie: cookie! });
    await h.get("/v/AAAAAAAAAAAAAAAAAAAAAA?dl=1");
    await h.get("/a/0123456789abcdef/core.wasm");
    await h.call("http://auth.test/callback?code=4/0Asecret-code_of.google");
    expect(h.logs.map((l) => JSON.parse(l))).toEqual([
      { route: "/", status: 200 },
      { route: "/callback", status: 200 },
      { route: "/web/start", status: 200 },
      { route: "/web/token", status: 200 },
      { route: "/web/refresh", status: 200 },
      { route: "/web/refresh", status: 401, error: "no_session" },
      { route: "/web/refresh", status: 401, error: "no_session" },
      { route: "/web/refresh", status: 403, error: "cross_origin" },
      { route: "/web/token", status: 400, error: "invalid_request" },
      { route: "/web/start", status: 200 },
      { route: "/web/token", status: 403, error: "email_not_allowed" },
      { route: "/web/refresh", status: 502, error: "upstream_error" },
      { route: "/web/logout", status: 405, error: "method_not_allowed" },
      { route: "/web/logout", status: 200 },
      { route: "other", status: 404, error: "not_found" },
      { route: "other", status: 404, error: "not_found" },
      { route: "/callback", status: 308 },
    ]);
    for (const line of h.logs) {
      for (const secret of ["4/0A", "secret-code", "AAAAAAAAAA", "stranger", EMAIL, "example", "accounts.google", "ya29", "1//", "dl=1", "wasm", "?"]) expect(line).not.toContain(secret);
    }
  });
});

describe("pkce helper", () => {
  it("the page's challenge is b64url(SHA-256(verifier)), which is what the Worker recomputes", async () => {
    const p = await pkce();
    expect(p.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.state).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(await pkceChallenge(p.verifier)).toBe(p.challenge);
    expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});
