// The sealed web session (src/seal.ts): what the viewer's cookie holds, and the nonce that binds a sign-in to its tab.

import { describe, expect, it } from "vitest";
import { SESSION_BLOB_MAX, SESSION_BLOB_MAX_CHARS, b64urlDecode, b64urlEncode, decodeSealKey, loginNonce, openSession, pkceChallenge, sealSession, sha256, type WebSession } from "../src/seal";
import { EMAIL, SEAL_KEY, SEAL_KEY_BYTES, useHarness } from "./helpers";

useHarness();

const KEY = SEAL_KEY_BYTES;
const OTHER_KEY = new Uint8Array(32).fill(7);
const NOW = 1_794_400_000;
const REFRESH_TOKEN = "1//0fake-refresh-token_of-the.web~client";
const session: WebSession = { iat: NOW, exp: NOW + 43200, email: EMAIL, refreshToken: REFRESH_TOKEN };
// RFC 7636, appendix B.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function patched(blob: string, change: (raw: Uint8Array) => Uint8Array | void): string {
  const raw = b64urlDecode(blob)!;
  return b64urlEncode(change(raw) ?? raw);
}

/** A blob of any version and kind, sealed the way seal.ts seals — with nothing but WebCrypto. */
async function sealRaw(key: Uint8Array, head: [number, number], info: string, plain: Uint8Array): Promise<string> {
  const ikm = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveKey"]);
  const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode(info) }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new Uint8Array(head) }, aes, plain));
  const blob = new Uint8Array(14 + sealed.length);
  blob.set(head, 0);
  blob.set(iv, 2);
  blob.set(sealed, 14);
  return b64urlEncode(blob);
}

/** The plaintext of a session blob: iat u32 ‖ exp u32 ‖ len(email) u8 ‖ email ‖ refresh token. */
function plainOf(s: WebSession, emailLength = s.email.length): Uint8Array {
  const text = new TextEncoder().encode(s.email + s.refreshToken);
  const plain = new Uint8Array(9 + text.length);
  const view = new DataView(plain.buffer);
  view.setUint32(0, s.iat);
  view.setUint32(4, s.exp);
  plain[8] = emailLength;
  plain.set(text, 9);
  return plain;
}

describe("base64url", () => {
  it("round-trips every length and uses the URL alphabet without padding", () => {
    for (let n = 0; n < 70; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 251) & 0xff);
      const text = b64urlEncode(bytes);
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(b64urlDecode(text)).toEqual(bytes);
    }
    expect(b64urlEncode(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe("-__-");
  });

  it("rejects every invalid character and an impossible length", () => {
    for (const bad of ["+/+/", "AAA=", "AA==", "AAAA AAAA", "AAAA\n", "A", "AAAAA", "AÄAA", "AA.A", "%41AA"]) {
      expect(b64urlDecode(bad), bad).toBeNull();
    }
    expect(b64urlDecode("")).toEqual(new Uint8Array(0));
  });
});

describe("SEAL_KEY", () => {
  it("is 32 bytes in base64 or base64url, with or without padding and a line end", () => {
    const standard = btoa(String.fromCharCode(...new Uint8Array(32).fill(0xfb))); // has "+" and "/" and "="
    expect(standard).toMatch(/[+/]/);
    const url = standard.replace(/\+/g, "-").replace(/\//g, "_");
    for (const text of [standard, url, url.replace(/=+$/, ""), `${standard}\n`, `  ${standard}  `]) {
      expect(decodeSealKey(text), JSON.stringify(text)).toEqual(new Uint8Array(32).fill(0xfb));
    }
    expect(decodeSealKey(SEAL_KEY)).toEqual(SEAL_KEY_BYTES);
  });

  it("anything else is no key", () => {
    const of = (n: number) => btoa("k".repeat(n));
    for (const bad of [undefined, null, 7, "", "left-over", of(31), of(33), of(16), of(64), `${of(32)} x`, `x${of(32)}`, "0".repeat(64)]) {
      expect(decodeSealKey(bad), JSON.stringify(bad)).toBeNull();
    }
    // (64 hex digits are 48 bytes of base64, not 32: a hex key is refused rather than misread)
  });
});

describe("the login nonce", () => {
  it("is b64url(SHA-256('gclone-auth/v2/nonce' ‖ challenge)): the vector, and the definition", async () => {
    expect(await pkceChallenge(VERIFIER)).toBe(CHALLENGE);
    expect(await loginNonce(CHALLENGE)).toBe("YQJeKmue5eKT9odFimja-gbHcv9JumCLiMpCdH_fGsg");
    expect(await loginNonce(CHALLENGE)).toBe(b64urlEncode(await sha256(new TextEncoder().encode(`gclone-auth/v2/nonce${CHALLENGE}`))));
    expect(await loginNonce(CHALLENGE)).toHaveLength(43);
  });

  it("differs for every challenge, and from the nonce of the sign-in before 0.2.0", async () => {
    const other = await pkceChallenge(`${VERIFIER}x`);
    expect(await loginNonce(other)).not.toBe(await loginNonce(CHALLENGE));
    expect(await loginNonce(CHALLENGE)).not.toBe(b64urlEncode(await sha256(new TextEncoder().encode(`gclone-auth/v1/nonce${CHALLENGE}`))));
  });
});

describe("session blobs", () => {
  it("round-trip", async () => {
    expect(await openSession(KEY, await sealSession(KEY, session), NOW)).toEqual(session);
    const others: WebSession[] = [
      { ...session, iat: 0, exp: 0xffff_ffff },
      { ...session, email: "a@b" },
      { ...session, email: `${"x".repeat(242)}@example.com`, refreshToken: "r".repeat(512) },
      { ...session, refreshToken: "1//0A_-.~+=/zzzzzzzzzzzz" },
    ];
    for (const s of others) expect(await openSession(KEY, await sealSession(KEY, s), NOW)).toEqual(s);
  });

  it("have the byte layout of the design: 0x02 ‖ 0x04 ‖ nonce(12) ‖ AES-256-GCM(aad = the first two bytes) — opened here with nothing but WebCrypto", async () => {
    const raw = b64urlDecode(await sealSession(KEY, session))!;
    expect([raw[0], raw[1]]).toEqual([2, 4]);
    const ikm = await crypto.subtle.importKey("raw", KEY, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("gclone-auth/v2/web-session") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(2, 14), additionalData: new Uint8Array([2, 4]) }, key, raw.slice(14)));
    expect(plain).toEqual(plainOf(session));
    const view = new DataView(plain.buffer);
    expect(view.getUint32(0)).toBe(NOW);
    expect(view.getUint32(4)).toBe(NOW + 43200);
    expect(plain[8]).toBe(EMAIL.length);
    expect(new TextDecoder().decode(plain.slice(9, 9 + EMAIL.length))).toBe(EMAIL);
    expect(new TextDecoder().decode(plain.slice(9 + EMAIL.length))).toBe(REFRESH_TOKEN);
    expect(raw.length).toBe(2 + 12 + 9 + EMAIL.length + REFRESH_TOKEN.length + 16);
    // … and a blob made that way opens
    expect(await openSession(KEY, await sealRaw(KEY, [2, 4], "gclone-auth/v2/web-session", plainOf(session)), NOW)).toEqual(session);
  });

  it("use a fresh nonce every time, and show nothing of their content", async () => {
    const [a, b] = [await sealSession(KEY, session), await sealSession(KEY, session)];
    expect(a).not.toBe(b);
    expect(b64urlDecode(a)!.slice(2, 14)).not.toEqual(b64urlDecode(b)!.slice(2, 14));
    const visible = new TextDecoder("latin1").decode(b64urlDecode(a)!);
    expect(visible).not.toContain(REFRESH_TOKEN.slice(0, 8));
    expect(visible).not.toContain(EMAIL);
    expect(a).not.toContain(REFRESH_TOKEN.slice(0, 8));
  });

  it("a flipped bit anywhere — version, kind, nonce, content, tag — does not open", async () => {
    const blob = await sealSession(KEY, session);
    const length = b64urlDecode(blob)!.length;
    for (let at = 0; at < length; at++) {
      const flipped = patched(blob, (raw) => {
        raw[at]! ^= 1 << (at % 8);
      });
      expect(await openSession(KEY, flipped, NOW), `byte ${at}`).toBeNull();
    }
    expect(await openSession(KEY, blob, NOW)).toEqual(session);
  });

  it("truncated, extended, or not a blob at all: null, never a throw", async () => {
    const blob = await sealSession(KEY, session);
    for (const bad of [
      "",
      "AAAA",
      "not base64url!",
      blob.slice(0, -1),
      blob.slice(0, -4),
      blob.slice(4),
      `${blob}AAAA`,
      `${blob}=`,
      patched(blob, (raw) => raw.slice(0, 14)),
      patched(blob, (raw) => raw.slice(0, 30)),
      "A".repeat(SESSION_BLOB_MAX_CHARS),
      "A".repeat(SESSION_BLOB_MAX_CHARS + 1),
      "A".repeat(100_000),
    ]) {
      expect(await openSession(KEY, bad, NOW), bad.slice(0, 30)).toBeNull();
    }
    expect(await openSession(KEY, 7 as unknown as string, NOW)).toBeNull();
  });

  it("another key does not open: replacing SEAL_KEY ends every session", async () => {
    const blob = await sealSession(KEY, session);
    expect(await openSession(OTHER_KEY, blob, NOW)).toBeNull();
    expect(await openSession(KEY, await sealSession(OTHER_KEY, session), NOW)).toBeNull();
    // the HKDF info is part of the key: the same SEAL_KEY under another label is another key
    expect(await openSession(KEY, await sealRaw(KEY, [2, 4], "gclone-auth/v2/web-sessio", plainOf(session)), NOW)).toBeNull();
    await expect(openSession(new Uint8Array(31), blob, NOW)).resolves.toBeNull();
  });

  it("expire by the sealed time: exp <= now fails, exp = now + 1 opens", async () => {
    const blob = await sealSession(KEY, { ...session, exp: NOW + 1 });
    expect(await openSession(KEY, blob, NOW)).not.toBeNull();
    expect(await openSession(KEY, blob, NOW + 1)).toBeNull();
    expect(await openSession(KEY, blob, NOW + 2)).toBeNull();
    // the clock of whoever holds the blob changes nothing: only the Worker's `now` is asked
    expect(await openSession(KEY, await sealSession(KEY, { ...session, exp: 0 }), 0)).toBeNull();
  });

  it("the blobs of the browser sign-in before gclone 0.2.0 (version 1: state, grant, pending) are refused — also under this key", async () => {
    const old = [
      { kind: 1, info: "gclone-auth/v1/state" },
      { kind: 2, info: "gclone-auth/v1/grant" },
      { kind: 3, info: "gclone-auth/v1/pending" },
    ];
    for (const { kind, info } of old) {
      // as that version sealed them, and with a session's content inside
      expect(await openSession(KEY, await sealRaw(KEY, [1, kind], info, plainOf(session)), NOW), `v1 kind ${kind}`).toBeNull();
      expect(await openSession(KEY, await sealRaw(KEY, [1, kind], "gclone-auth/v2/web-session", plainOf(session)), NOW), `v1 kind ${kind}`).toBeNull();
      // the old kinds under the new version number
      expect(await openSession(KEY, await sealRaw(KEY, [2, kind], "gclone-auth/v2/web-session", plainOf(session)), NOW), `v2 kind ${kind}`).toBeNull();
    }
    // a session's kind under the old version, a version of the future, a kind of the future
    for (const head of [[1, 4], [3, 4], [2, 5], [0, 0], [4, 2]] as Array<[number, number]>) {
      expect(await openSession(KEY, await sealRaw(KEY, head, "gclone-auth/v2/web-session", plainOf(session)), NOW), String(head)).toBeNull();
    }
    // a real session blob whose two head bytes were rewritten: they are authenticated
    const blob = await sealSession(KEY, session);
    expect(
      await openSession(
        KEY,
        patched(blob, (raw) => {
          raw[0] = 1;
        }),
        NOW,
      ),
    ).toBeNull();
  });

  it("content that is authentic but out of range does not open", async () => {
    const seal = (plain: Uint8Array) => sealRaw(KEY, [2, 4], "gclone-auth/v2/web-session", plain);
    // the e-mail length points beyond the content
    expect(await openSession(KEY, await seal(plainOf(session, 255)), NOW)).toBeNull();
    // an address or a token that is too short, or not printable ASCII
    expect(await openSession(KEY, await seal(plainOf({ ...session, email: "a@" })), NOW)).toBeNull();
    expect(await openSession(KEY, await seal(plainOf({ ...session, refreshToken: "short" })), NOW)).toBeNull();
    expect(await openSession(KEY, await seal(plainOf({ ...session, email: "a b@example.com" })), NOW)).toBeNull();
    expect(await openSession(KEY, await seal(plainOf({ ...session, refreshToken: `${REFRESH_TOKEN}\n` })), NOW)).toBeNull();
    // everything read as the address, nothing left for the token
    expect(await openSession(KEY, await seal(plainOf(session, EMAIL.length + REFRESH_TOKEN.length)), NOW)).toBeNull();
    expect(await openSession(KEY, await seal(new Uint8Array(0)), NOW)).toBeNull();
  });

  it("stay within 805 bytes / 1074 characters — 1092 with the cookie's name; typical ones are a quarter of that", async () => {
    const longest = await sealSession(KEY, { ...session, email: `${"x".repeat(242)}@example.com`, refreshToken: "r".repeat(512) });
    expect(SESSION_BLOB_MAX).toBe(805);
    expect(SESSION_BLOB_MAX_CHARS).toBe(1074);
    expect(b64urlDecode(longest)).toHaveLength(805);
    expect(longest).toHaveLength(1074);
    expect(`__Host-gclone-web=${longest}`).toHaveLength(1092);
    // a refresh token of today's length (103 characters) and an ordinary address
    const typical = await sealSession(KEY, { ...session, email: "someone.with.a.name@example.com", refreshToken: `1//0${"t".repeat(99)}` });
    expect(typical.length).toBeGreaterThan(200);
    expect(typical.length).toBeLessThan(260);
  });

  it("cannot be sealed out of range", async () => {
    await expect(sealSession(KEY, { ...session, email: `${"x".repeat(243)}@example.com` })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, email: "a@" })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, email: "has space@example.com" })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, email: "ümlaut@example.com" })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, refreshToken: "r".repeat(513) })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, refreshToken: "r".repeat(19) })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, refreshToken: "has a space in it, twenty+" })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, exp: 2 ** 32 })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, iat: -1 })).rejects.toThrow(RangeError);
    await expect(sealSession(KEY, { ...session, exp: 1.5 })).rejects.toThrow(RangeError);
    await expect(sealSession(new Uint8Array(31), session)).rejects.toThrow(RangeError);
  });
});
