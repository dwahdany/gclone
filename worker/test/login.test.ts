import { describe, expect, it } from "vitest";
import { GOOGLE_AUTH_URL, GRANT_TTL_S, PASTE_PREFIX, STATE_TTL_S, defaultDeps } from "../src/index";
import { CODE_RE, SCOPES, authorizationUrl } from "../src/google";
import { escapeHtml } from "../src/pages";
import { b64urlDecode, b64urlEncode, decodeSealKey, openGrant, openPending, openState, sealGrant, sealPending, sealState } from "../src/seal";
import {
  CHALLENGE,
  CHECK_CODE,
  CLIENT_ID,
  DEVICE_STATE,
  EMAIL,
  GOOGLE,
  NONCE,
  ORIGIN,
  OTHER_VERIFIER,
  PORT,
  SEAL_KEY,
  T0_MS,
  VERIFIER,
  callbackAndConfirm,
  challengeOf,
  errorOf,
  finishLink,
  links,
  loginPath,
  startLogin,
  testEnv,
  useHarness,
} from "./helpers";

const h = useHarness();
const KEY = decodeSealKey(SEAL_KEY)!;
const NOW_S = T0_MS / 1000;
const CODE = "4/0AeaYSHDfakefakefakefakefakefakefakefake_Qg";
const HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function expectHtmlHeaders(res: Response): void {
  expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
  expect(res.headers.get("cache-control")).toBe("no-store");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("x-frame-options")).toBe("DENY");
  expect(res.headers.get("content-security-policy")).toBe(HTML_CSP);
}

/** No script, no form, nothing loaded from anywhere. */
function expectInertPage(page: string): void {
  expect(page.toLowerCase()).not.toContain("<script");
  expect(page.toLowerCase()).not.toContain("<form");
  expect(page).not.toMatch(/<(img|link|iframe|object|embed|video|audio|source)\b/i);
  expect(page).not.toMatch(/\bsrc=|url\(|@import|\bon[a-z]+=/i);
}

async function callbackState(opts: Parameters<typeof loginPath>[0] = {}): Promise<string> {
  return (await startLogin(h, opts)).state;
}

describe("GET /login", () => {
  it("loopback mode: 200 confirmation page with the check code — never a redirect", async () => {
    const res = await h.get(loginPath());
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    expectHtmlHeaders(res);
    const page = await res.text();
    expect(page).toContain(CHECK_CODE);
    expect(page).toContain("gclone on this computer wants to sign in to Google Drive");
    expect(page).toContain("If someone sent you this link, close this page.");
    expect(page).toContain("Continue with Google");
    expect(page).not.toContain("without a browser");
    expectInertPage(page);
    expect(h.google.calls).toEqual([]);
  });

  it("paste mode: the same page with the other text; `state` is ignored", async () => {
    const res = await h.get(`${loginPath({ paste: true })}&state=x`);
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    expectHtmlHeaders(res);
    const page = await res.text();
    expect(page).toContain(CHECK_CODE);
    expect(page).toContain("A gclone device without a browser wants to sign in to Google Drive");
    expect(page).toContain("If someone sent you this link, close this page.");
    expect(page).not.toContain("on this computer");
    expectInertPage(page);
    expect(h.google.calls).toEqual([]);
  });

  it("has exactly one link: Google's authorization endpoint with exactly the parameters of §2.3", async () => {
    for (const paste of [false, true]) {
      const { link, page } = await startLogin(h, { paste });
      expect(links(page)).toHaveLength(1);
      expect(link.origin + link.pathname).toBe(GOOGLE.authUrl);
      const params = Object.fromEntries(link.searchParams);
      expect([...link.searchParams.keys()].sort()).toEqual(
        ["access_type", "client_id", "code_challenge", "code_challenge_method", "nonce", "prompt", "redirect_uri", "response_type", "scope", "state"].sort(),
      );
      expect(params).toMatchObject({
        client_id: CLIENT_ID,
        redirect_uri: `${ORIGIN}/callback`,
        response_type: "code",
        scope: "openid email https://www.googleapis.com/auth/drive.file",
        access_type: "offline",
        prompt: "consent",
        code_challenge: CHALLENGE,
        code_challenge_method: "S256",
        nonce: NONCE,
      });
      expect(params.login_hint).toBeUndefined();
      // `state` is the sealed request: what /callback will act on.
      const sealed = await openState(KEY, params.state!, NOW_S);
      expect(sealed).toEqual({
        exp: NOW_S + STATE_TTL_S,
        port: paste ? 0 : PORT,
        challenge: b64urlDecode(CHALLENGE),
        deviceState: paste ? "" : DEVICE_STATE,
      });
      expect(params.state!.length).toBeLessThanOrEqual(176);
    }
  });

  it("links to the real Google endpoint under the production wiring", () => {
    const url = new URL(authorizationUrl(testEnv(), defaultDeps, "https://gclone-auth.example.workers.dev/callback", CHALLENGE, "S", NONCE));
    expect(url.origin + url.pathname).toBe(GOOGLE_AUTH_URL);
    expect(GOOGLE_AUTH_URL).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(url.searchParams.get("redirect_uri")).toBe("https://gclone-auth.example.workers.dev/callback");
    expect(url.searchParams.get("scope")).toBe(SCOPES);
  });

  it("takes redirect_uri from the origin of the request", async () => {
    const res = await h.call(loginPath(), { origin: "https://auth.example.org" });
    expect(new URL(links(await res.text())[0]!).searchParams.get("redirect_uri")).toBe("https://auth.example.org/callback");
  });

  it("never discloses an allowlisted address — no login_hint, nothing in pages or headers", async () => {
    h.env.ALLOWED_EMAILS = EMAIL; // a single allowed address is still not a hint
    const state = await callbackState();
    const pasteState = await callbackState({ paste: true });
    const answers = [
      await h.get("/"),
      await h.get("/privacy"),
      await h.get(loginPath()),
      await h.get(loginPath({ paste: true })),
      await h.get("/login"),
      await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`),
      await h.get(`/callback?${new URLSearchParams({ code: CODE, state: pasteState })}`),
      await callbackAndConfirm(h, String(new URLSearchParams({ code: CODE, state }))),
      await callbackAndConfirm(h, String(new URLSearchParams({ code: CODE, state: pasteState }))),
      await h.get(`/callback?${new URLSearchParams({ error: "access_denied", state })}`),
      await h.get(`/callback?${new URLSearchParams({ error: "access_denied", state: pasteState })}`),
      await h.get("/callback?state=nope&code=12345678"),
      await h.get("/nowhere"),
      await h.post("/token", { code: "x", verifier: OTHER_VERIFIER }),
      await h.post("/refresh", { refresh_token: "short" }),
    ];
    for (const res of answers) {
      const everything = `${[...res.headers].flat().join("\n")}\n${await res.text()}`.toLowerCase();
      expect(everything).not.toContain(EMAIL);
      expect(everything).not.toContain("example.com");
      expect(everything).not.toContain("login_hint");
    }
    expect(h.google.calls).toEqual([]);
  });

  it("refuses an invalid challenge", async () => {
    const bad = [
      CHALLENGE.slice(0, 42),
      `${CHALLENGE}A`,
      `${CHALLENGE.slice(0, 42)}+`,
      `${CHALLENGE.slice(0, 42)}=`,
      `${CHALLENGE.slice(0, 42)}/`,
      `${CHALLENGE.slice(0, 20)} ${CHALLENGE.slice(21)}`,
      `${CHALLENGE.slice(0, 42)}N`, // 43 characters, but not the canonical encoding of 32 bytes
      "",
    ];
    for (const challenge of bad) {
      for (const paste of [false, true]) {
        const res = await h.get(loginPath({ challenge, paste }));
        expect(res.status, challenge).toBe(400);
        expectHtmlHeaders(res);
        expect(res.headers.get("location")).toBeNull();
        expect(links(await res.text())).toEqual([]);
      }
    }
    expect((await h.get("/login")).status).toBe(400);
    expect((await h.get(`/login?port=${PORT}&state=${DEVICE_STATE}`)).status).toBe(400);
  });

  it("refuses an invalid port", async () => {
    for (const port of ["0", "80", "1023", "65536", "08080", "-1", "+8080", "1e4", "8080.0", " 8080", "0x1f90", "99999", ""]) {
      const res = await h.get(loginPath({ port }));
      expect(res.status, `port ${JSON.stringify(port)}`).toBe(400);
      expect(links(await res.text())).toEqual([]);
    }
    for (const port of ["1024", "8080", "65535"]) {
      expect((await h.get(loginPath({ port }))).status, `port ${port}`).toBe(200);
    }
  });

  it("refuses loopback mode without a well-formed state", async () => {
    expect((await h.get(`/login?challenge=${CHALLENGE}&port=${PORT}`)).status).toBe(400);
    for (const state of ["", "short", "a".repeat(15), "a".repeat(65), "has space 0123456789", "state+with/base64chars", "ümlaut-0123456789abc"]) {
      expect((await h.get(loginPath({ state }))).status, state).toBe(400);
    }
    for (const state of ["a".repeat(16), "a".repeat(64), "A-Z_a-z0123456789"]) {
      expect((await h.get(loginPath({ state }))).status, state).toBe(200);
    }
  });

  it("shows the device's own check code for any challenge", async () => {
    const challenge = await challengeOf(OTHER_VERIFIER);
    const { page, nonce } = await startLogin(h, { challenge });
    expect(page).not.toContain(CHECK_CODE);
    expect(page).toMatch(/[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}/);
    expect(nonce).not.toBe(NONCE);
  });
});

describe("GET /callback", () => {
  const CHECK_RE = /[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}/;

  it("Google's redirect, loopback mode: 200 confirmation page with the check code — never a redirect, never a grant", async () => {
    const state = await callbackState();
    const res = await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}&scope=email&authuser=0&prompt=consent`);
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    expectHtmlHeaders(res);
    const page = await res.text();
    expect(page).toContain(CHECK_CODE);
    expect(page).toContain("gclone on this computer is waiting for the last step");
    expect(page).toContain("nothing is signed in yet");
    expect(page).toContain("if someone sent you the link that led here, close this page");
    expect(page).toContain("Never send the address of this page to anyone.");
    expect(page).toContain("Finish signing in");
    expect(page).not.toContain("without a browser");
    expect(page).not.toContain(PASTE_PREFIX);
    expect(page).not.toContain("127.0.0.1");
    expect(page).not.toContain(CODE);
    expectInertPage(page);

    // Its one link carries a pending blob: Google's code and the sealed request, valid for GRANT_TTL — not a grant.
    const found = links(page);
    expect(found).toHaveLength(1);
    const blob = found[0]!.match(/^\/callback\?confirmed=([A-Za-z0-9_-]+)$/)?.[1];
    expect(blob, found[0]).toBeDefined();
    expect(await openPending(KEY, blob!, NOW_S)).toEqual({
      exp: NOW_S + GRANT_TTL_S,
      port: PORT,
      challenge: b64urlDecode(CHALLENGE),
      deviceState: DEVICE_STATE,
      googleCode: CODE,
    });
    expect(await openGrant(KEY, blob!, b64urlDecode(CHALLENGE)!, NOW_S)).toBeNull();
    expect(blob!.length).toBeLessThanOrEqual(860);
    expect(h.google.calls).toEqual([]);
  });

  it("Google's redirect, paste mode: the same page with the other text", async () => {
    const state = await callbackState({ paste: true });
    const res = await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`);
    expect(res.status).toBe(200);
    expectHtmlHeaders(res);
    const page = await res.text();
    expect(page).toContain(CHECK_CODE);
    expect(page).toContain("A gclone device without a browser is waiting for the last step");
    expect(page).toContain("Never send the address of this page to anyone.");
    expect(page).not.toContain("on this computer");
    expect(page).not.toContain(PASTE_PREFIX);
    expect(page).not.toContain("<textarea");
    expectInertPage(page);
    expect(links(page)).toHaveLength(1);
    expect(h.google.calls).toEqual([]);
  });

  it("the confirmation cannot be skipped: a state fetched by someone else still leads the consenting browser to the check code", async () => {
    // The phisher fetches /login himself (his own verifier, a port of his choosing) and mails only the link to Google.
    const attackerVerifier = OTHER_VERIFIER;
    const attackerChallenge = await challengeOf(attackerVerifier);
    const { link, page: attackersPage } = await startLogin(h, { challenge: attackerChallenge, port: 4444 });
    const attackersCheckCode = attackersPage.match(CHECK_RE)![0];
    h.clock.ms += 9 * 60 * 1000;

    // The owner never saw /login. Google sends their browser — another address, no cookie, no referrer — to /callback.
    const code = "4/0AownersConsent-code_1";
    h.google.consent(code, { nonce: link.searchParams.get("nonce") });
    const landed = await h.get(`/callback?${new URLSearchParams({ code, state: link.searchParams.get("state")! })}`, { "cf-connecting-ip": "198.51.100.77" });
    expect(landed.status).toBe(200);
    expect(landed.headers.get("location")).toBeNull();
    const page = await landed.clone().text();
    expect(page).toContain(attackersCheckCode); // a code the owner's terminal does not show
    expect(page).toContain("if someone sent you the link that led here, close this page");
    expect(page).not.toContain(PASTE_PREFIX);
    expect(page).not.toContain("127.0.0.1");

    // Closing the page ends it: no grant exists anywhere, so the attacker's verifier redeems nothing …
    for (const guess of [code, link.searchParams.get("state")!, "x"]) {
      expect(await errorOf(await h.post("/token", { code: guess, verifier: attackerVerifier }))).toEqual({ status: 400, error: "invalid_grant" });
    }
    // … not even with the pending blob itself, had he got hold of the page: it is not a grant.
    const pendingBlob = (await finishLink(landed)).split("=")[1]!;
    expect(await errorOf(await h.post("/token", { code: pendingBlob, verifier: attackerVerifier }))).toEqual({ status: 400, error: "invalid_grant" });
    expect(h.google.calls).toEqual([]);
  });

  it("the confirmation link, loopback mode: 302 to exactly http://127.0.0.1:<port>/?code=<grant>&state=<device state>", async () => {
    const state = await callbackState();
    const res = await callbackAndConfirm(h, String(new URLSearchParams({ code: CODE, state })));
    expect(res.status).toBe(302);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(await res.text()).toBe("");
    const location = res.headers.get("location")!;
    const match = location.match(/^http:\/\/127\.0\.0\.1:8123\/\?code=([A-Za-z0-9_-]+)&state=AAAAAAAAAAAAAAAAAAAAAA$/);
    expect(match, location).not.toBeNull();
    // The grant holds Google's code, sealed for the device's challenge, valid for GRANT_TTL.
    const grant = match![1]!;
    expect(await openGrant(KEY, grant, b64urlDecode(CHALLENGE)!, NOW_S + GRANT_TTL_S - 1)).toBe(CODE);
    expect(await openGrant(KEY, grant, b64urlDecode(CHALLENGE)!, NOW_S + GRANT_TTL_S)).toBeNull();
    expect(grant.length).toBeLessThanOrEqual(728);
    expect(location).not.toContain(CODE);
    expect(h.google.calls).toEqual([]);
  });

  it("the confirmation link, paste mode: 200 page with gclone-code1_<grant> in a read-only box", async () => {
    const state = await callbackState({ paste: true });
    const res = await callbackAndConfirm(h, String(new URLSearchParams({ code: CODE, state })));
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
    expectHtmlHeaders(res);
    const page = await res.text();
    const box = page.match(/<textarea readonly[^>]*>([^<]*)<\/textarea>/);
    expect(box).not.toBeNull();
    expect(box![1]!.startsWith(PASTE_PREFIX)).toBe(true);
    expect(PASTE_PREFIX).toBe("gclone-code1_");
    expect(await openGrant(KEY, box![1]!.slice(PASTE_PREFIX.length), b64urlDecode(CHALLENGE)!, NOW_S)).toBe(CODE);
    expect(page).toContain("2 minutes");
    expect(page).toContain("Never send it");
    expect(page).not.toContain(CODE);
    expect(links(page)).toEqual([]);
    expectInertPage(page);
    expect(h.google.calls).toEqual([]);
  });

  it("the grant keeps the confirmation page's clock: GRANT_TTL runs from that page, not from the click", async () => {
    const state = await callbackState();
    const link = await finishLink(await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`));
    h.clock.ms += 100 * 1000;
    const res = await h.get(link);
    expect(res.status).toBe(302);
    const grant = new URL(res.headers.get("location")!).searchParams.get("code")!;
    expect(await openGrant(KEY, grant, b64urlDecode(CHALLENGE)!, NOW_S + GRANT_TTL_S - 1)).toBe(CODE);
    expect(await openGrant(KEY, grant, b64urlDecode(CHALLENGE)!, NOW_S + GRANT_TTL_S)).toBeNull();

    // one second before the end it still works; at GRANT_TTL the page's link has expired
    h.clock.ms = T0_MS + (GRANT_TTL_S - 1) * 1000;
    expect((await h.get(link)).status).toBe(302);
    h.clock.ms = T0_MS + GRANT_TTL_S * 1000;
    const late = await h.get(link);
    expect(late.status).toBe(400);
    expect(late.headers.get("location")).toBeNull();
    expect(await late.text()).toContain("This sign-in link is invalid or has expired.");
  });

  it("refuses an unknown, tampered or foreign `confirmed` value", async () => {
    const state = await callbackState();
    const link = await finishLink(await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`));
    const blob = link.split("=")[1]!;
    const raw = b64urlDecode(blob)!;
    raw[20]! ^= 1;
    const challenge = b64urlDecode(CHALLENGE)!;
    const bad: Array<[string, string]> = [
      ["empty", ""],
      ["garbage", "not-a-pending-blob"],
      ["tampered", b64urlEncode(raw)],
      ["truncated", blob.slice(0, -3)],
      ["a state, not a pending blob", state],
      ["a grant, not a pending blob", await sealGrant(KEY, challenge, NOW_S + 60, CODE)],
      ["Google's code", CODE],
      ["expired when sealed", await sealPending(KEY, { exp: NOW_S, port: PORT, challenge, deviceState: DEVICE_STATE, googleCode: CODE })],
    ];
    for (const [what, value] of bad) {
      // a valid state and code next to it do not help: `confirmed` decides alone
      for (const extra of ["", `&${new URLSearchParams({ code: CODE, state })}`]) {
        const res = await h.get(`/callback?confirmed=${encodeURIComponent(value)}${extra}`);
        expect(res.status, what).toBe(400);
        expectHtmlHeaders(res);
        expect(res.headers.get("location"), what).toBeNull();
        const page = await res.text();
        expect(page).toContain("This sign-in link is invalid or has expired. Run <code>gclone login</code> again.");
        expect(page).not.toContain(PASTE_PREFIX);
        expect(links(page)).toEqual([]);
      }
    }
    // sealed under another SEAL_KEY
    h.env = testEnv({ SEAL_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))) });
    expect((await h.get(link)).status).toBe(400);
    h.env = testEnv();
    expect((await h.get(link)).status).toBe(302);
    expect(h.google.calls).toEqual([]);
  });

  it("refuses an unknown, tampered or expired state", async () => {
    const state = await callbackState();
    const raw = b64urlDecode(state)!;
    raw[20]! ^= 1;
    const foreign = await callbackState();
    const otherKeyEnv = testEnv({ SEAL_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))) });
    const challenge = b64urlDecode(CHALLENGE)!;
    const bad: Array<[string, string | null]> = [
      ["missing", null],
      ["empty", ""],
      ["garbage", "not-a-state-blob"],
      ["tampered", b64urlEncode(raw)],
      ["truncated", state.slice(0, -3)],
      ["a grant, not a state", await sealGrant(KEY, challenge, NOW_S + 60, CODE)],
      ["a pending blob, not a state", await sealPending(KEY, { exp: NOW_S + 60, port: PORT, challenge, deviceState: DEVICE_STATE, googleCode: CODE })],
      ["the device's own state value", DEVICE_STATE],
    ];
    for (const [what, value] of bad) {
      const q = new URLSearchParams({ code: CODE });
      if (value !== null) q.set("state", value);
      const res = await h.get(`/callback?${q}`);
      expect(res.status, what).toBe(400);
      expectHtmlHeaders(res);
      expect(res.headers.get("location")).toBeNull();
      const page = await res.text();
      expect(page).toContain("This sign-in link is invalid or has expired. Run <code>gclone login</code> again.");
      expect(links(page)).toEqual([]);
    }
    // sealed under another SEAL_KEY
    h.env = otherKeyEnv;
    expect((await h.get(`/callback?${new URLSearchParams({ code: CODE, state: foreign })}`)).status).toBe(400);
    h.env = testEnv();

    // one second before the end of STATE_TTL it still works; at STATE_TTL it has expired
    h.clock.ms = T0_MS + (STATE_TTL_S - 1) * 1000;
    const inTime = await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`);
    h.clock.ms = T0_MS + STATE_TTL_S * 1000;
    expect((await h.get(`/callback?${new URLSearchParams({ code: CODE, state })}`)).status).toBe(400);
    expect((await h.get(`/callback?${new URLSearchParams({ error: "access_denied", state })}`)).status).toBe(400);
    // … while the confirmation page that was served in time has its own two minutes
    expect((await h.get(await finishLink(inTime))).status).toBe(302);
    expect(h.google.calls).toEqual([]);
  });

  it("refuses a malformed code before anything else happens", async () => {
    const state = await callbackState();
    const bad = ["", "1234567", "c".repeat(513), "4/0Ae aYSHD", "4/0Ae%00aYSHD", "4/0Ae%0AaYSHD", "4/0Ae%7FaYSHD", "4/0Ae\"aYSHD", "4/0Ae<b>aYSHD", "4/0Ae&aYSHD", "4/0Aé-aYSHD", "4/0Ae%25aYSHD"];
    for (const code of bad) {
      // codes are given percent-encoded where needed: the Worker sees the decoded value
      const res = await h.get(`/callback?state=${state}&code=${code.replace(/[ "<>&é]/g, encodeURIComponent)}`);
      expect(res.status, JSON.stringify(code)).toBe(400);
      expect(res.headers.get("location")).toBeNull();
      expect(links(await res.text())).toEqual([]);
    }
    expect((await h.get(`/callback?state=${state}`)).status).toBe(400);
    for (const code of ["12345678", "c".repeat(512), "4/0A_-.~+=/z"]) {
      expect(CODE_RE.test(code)).toBe(true);
      const res = await callbackAndConfirm(h, String(new URLSearchParams({ code, state })));
      expect(res.status, code).toBe(302);
      expect(await openGrant(KEY, new URL(res.headers.get("location")!).searchParams.get("code")!, b64urlDecode(CHALLENGE)!, NOW_S), code).toBe(code);
    }
    expect(h.google.calls).toEqual([]);
  });

  it("the longest state with the longest code still fits the confirmation link", async () => {
    const deviceState = "s".repeat(64);
    const code = "c".repeat(512);
    const state = await sealState(KEY, { exp: NOW_S + 60, port: 65535, challenge: b64urlDecode(CHALLENGE)!, deviceState });
    const link = await finishLink(await h.get(`/callback?${new URLSearchParams({ code, state })}`));
    expect(link.length).toBeLessThanOrEqual("/callback?confirmed=".length + 860);
    const res = await h.get(link);
    expect(res.headers.get("location")).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:65535/\\?code=[A-Za-z0-9_-]+&state=${deviceState}$`));
  });

  it("error=access_denied: loopback mode redirects with the error, paste mode shows a page", async () => {
    const state = await callbackState();
    const res = await h.get(`/callback?${new URLSearchParams({ error: "access_denied", state })}`);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`http://127.0.0.1:${PORT}/?error=access_denied&state=${DEVICE_STATE}`);

    const pasteRes = await h.get(`/callback?${new URLSearchParams({ error: "access_denied", state: await callbackState({ paste: true }) })}`);
    expect(pasteRes.status).toBe(200);
    expect(pasteRes.headers.get("location")).toBeNull();
    expectHtmlHeaders(pasteRes);
    const page = await pasteRes.text();
    expect(page).toContain("Google did not grant access (access_denied).");
    expect(page).not.toContain(PASTE_PREFIX);

    // an error wins over a code that came along
    const both = await h.get(`/callback?${new URLSearchParams({ error: "access_denied", code: CODE, state })}`);
    expect(both.headers.get("location")).toBe(`http://127.0.0.1:${PORT}/?error=access_denied&state=${DEVICE_STATE}`);
    expect(h.google.calls).toEqual([]);
  });

  it("sanitises a hostile error value", async () => {
    const hostile = ['"><script>alert(1)</script>', "access_denied&code=stolen", "Access_Denied", "a".repeat(65), "x\r\nSet-Cookie: a=b", "", "http://evil.example/"];
    for (const error of hostile) {
      const loop = await h.get(`/callback?${new URLSearchParams({ error, state: await callbackState() })}`);
      expect(loop.status).toBe(302);
      expect(loop.headers.get("location"), error).toBe(`http://127.0.0.1:${PORT}/?error=error&state=${DEVICE_STATE}`);

      const paste = await h.get(`/callback?${new URLSearchParams({ error, state: await callbackState({ paste: true }) })}`);
      expect(paste.status).toBe(200);
      const page = await paste.text();
      expect(page).toContain("Google did not grant access (error).");
      expectInertPage(page);
      expect(page).not.toContain("evil.example");
    }
    const fine = await h.get(`/callback?${new URLSearchParams({ error: "interaction_required", state: await callbackState() })}`);
    expect(fine.headers.get("location")).toBe(`http://127.0.0.1:${PORT}/?error=interaction_required&state=${DEVICE_STATE}`);
  });

  it("takes no part of the redirect target from the callback request", async () => {
    const state = await callbackState({ port: 40123, state: "device-state-0123456789" });
    const hostile = { headers: { host: "evil.example", "x-forwarded-host": "evil.example", origin: "https://evil.example" } };
    const first = await h.call(
      `/callback?${new URLSearchParams({ code: CODE, state })}&port=9999&redirect_uri=https://evil.example/&host=evil.example&state2=x`,
      hostile,
    );
    const link = await finishLink(first);
    const res = await h.call(`${link}&port=9999&redirect_uri=https://evil.example/&host=evil.example&state=${DEVICE_STATE}`, hostile);
    expect(res.headers.get("location")).toMatch(/^http:\/\/127\.0\.0\.1:40123\/\?code=[A-Za-z0-9_-]+&state=device-state-0123456789$/);
  });

  it("shows the check code of the login the state was sealed for", async () => {
    const challenge = await challengeOf(OTHER_VERIFIER);
    const login = await startLogin(h, { challenge });
    const expected = login.page.match(CHECK_RE)![0];
    expect(expected).not.toBe(CHECK_CODE);
    const page = await (await h.get(`/callback?${new URLSearchParams({ code: CODE, state: login.state })}`)).text();
    expect(page).toContain(expected);
    expect(page).not.toContain(CHECK_CODE);
    expect(VERIFIER).not.toBe(OTHER_VERIFIER);
  });
});

describe("pages", () => {
  it("escapeHtml covers the five special characters", () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe("&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
    expect(escapeHtml("plain text 123")).toBe("plain text 123");
  });

  it("home: what this is, the privacy link and the status line", async () => {
    const res = await h.get("/");
    expect(res.status).toBe(200);
    expectHtmlHeaders(res);
    const page = await res.text();
    expect(page).toContain("Status: ready");
    expect(page).toContain("gclone");
    expect(page).toContain("only its owner can sign in");
    expect(links(page)).toEqual(["/privacy"]);
    expectInertPage(page);
  });

  it("privacy: the required statements, and no claim that nothing is logged", async () => {
    const res = await h.get("/privacy");
    expect(res.status).toBe(200);
    expectHtmlHeaders(res);
    const page = (await res.text()).replace(/\s+/g, " ");
    for (const part of [
      "e-mail address",
      "drive.file",
      "files that gclone itself created",
      "What it stores.</strong> Nothing",
      "only the route, the status and an error code",
      "Cloudflare",
      "IP address, time, URL path",
      "only to the owner's own devices",
      "https://myaccount.google.com/permissions",
    ]) {
      expect(page, part).toContain(part);
    }
    expect(page.toLowerCase()).not.toContain("nothing is logged");
    expectInertPage(page);
  });
});
