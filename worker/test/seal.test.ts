import { describe, expect, it } from "vitest";
import {
  b64urlDecode,
  b64urlEncode,
  checkCode,
  decodeSealKey,
  loginNonce,
  openGrant,
  openPending,
  openState,
  sealGrant,
  sealPending,
  sealState,
  sha256,
  type PendingData,
  type StateData,
} from "../src/seal";
import { CHALLENGE, CHECK_CODE, DEVICE_STATE, NONCE, SEAL_KEY, VERIFIER, errorOf, finishLink, loginPath, useHarness } from "./helpers";

const h = useHarness();

const KEY = decodeSealKey(SEAL_KEY)!;
const OTHER_KEY = new Uint8Array(32).fill(7);
const NOW = 1_794_400_000;
const CHALLENGE_BYTES = b64urlDecode(CHALLENGE)!;
const OTHER_CHALLENGE = new Uint8Array(32).fill(9);
const GOOGLE_CODE = "4/0AeaYSHDfakefakefakefakefakefakefakefakefakefakefakefakefakefakefake_Qg";

const loopbackState: StateData = { exp: NOW + 600, port: 8123, challenge: CHALLENGE_BYTES, deviceState: DEVICE_STATE };
const pasteState: StateData = { exp: NOW + 600, port: 0, challenge: CHALLENGE_BYTES, deviceState: "" };
const loopbackPending: PendingData = { exp: NOW + 120, port: 8123, challenge: CHALLENGE_BYTES, deviceState: DEVICE_STATE, googleCode: GOOGLE_CODE };
const pastePending: PendingData = { exp: NOW + 120, port: 0, challenge: CHALLENGE_BYTES, deviceState: "", googleCode: GOOGLE_CODE };

function patched(blob: string, change: (raw: Uint8Array) => void): string {
  const raw = b64urlDecode(blob)!;
  change(raw);
  return b64urlEncode(raw);
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

describe("vectors", () => {
  it("challenge, check code and login nonce of SPEC §2.3 / §2.4", async () => {
    expect(b64urlEncode(await sha256(new TextEncoder().encode(VERIFIER)))).toBe(CHALLENGE);
    expect(await checkCode(CHALLENGE)).toBe(CHECK_CODE);
    expect(await loginNonce(CHALLENGE)).toBe(NONCE);
    expect(await loginNonce(CHALLENGE)).toHaveLength(43);
  });

  it("the check code is XXXX-XXXX in Crockford base32", async () => {
    for (const verifier of ["a", "b", "c", "d", "e", "f"]) {
      const challenge = b64urlEncode(await sha256(new TextEncoder().encode(verifier)));
      expect(await checkCode(challenge)).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    }
  });
});

describe("state blobs", () => {
  it("round-trip in loopback and in paste mode", async () => {
    expect(await openState(KEY, await sealState(KEY, loopbackState), NOW)).toEqual(loopbackState);
    expect(await openState(KEY, await sealState(KEY, pasteState), NOW)).toEqual(pasteState);
    const longest = { ...loopbackState, port: 65535, deviceState: "z".repeat(64) };
    expect(await openState(KEY, await sealState(KEY, longest), NOW)).toEqual(longest);
  });

  it("have the byte layout of SPEC §2.3.1 (opened here with nothing but WebCrypto)", async () => {
    const raw = b64urlDecode(await sealState(KEY, loopbackState))!;
    expect([raw[0], raw[1]]).toEqual([1, 1]);
    const ikm = await crypto.subtle.importKey("raw", KEY, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("gclone-auth/v1/state") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(2, 14), additionalData: new Uint8Array([1, 1]) }, key, raw.slice(14)),
    );
    const view = new DataView(plain.buffer);
    expect(view.getUint32(0)).toBe(NOW + 600);
    expect(view.getUint16(4)).toBe(8123);
    expect(plain.slice(6, 38)).toEqual(CHALLENGE_BYTES);
    expect(new TextDecoder().decode(plain.slice(38))).toBe(DEVICE_STATE);
    expect(raw.length).toBe(2 + 12 + 38 + DEVICE_STATE.length + 16);
  });

  it("use a fresh nonce every time", async () => {
    const a = b64urlDecode(await sealState(KEY, loopbackState))!;
    const b = b64urlDecode(await sealState(KEY, loopbackState))!;
    expect(a.slice(2, 14)).not.toEqual(b.slice(2, 14));
  });

  it("expire: exp <= now fails, exp = now + 1 opens", async () => {
    const blob = await sealState(KEY, { ...loopbackState, exp: NOW + 1 });
    expect(await openState(KEY, blob, NOW)).not.toBeNull();
    expect(await openState(KEY, blob, NOW + 1)).toBeNull();
    expect(await openState(KEY, blob, NOW + 2)).toBeNull();
  });

  it("stay within 132 bytes / 176 characters", async () => {
    const blob = await sealState(KEY, { ...loopbackState, deviceState: "a".repeat(64) });
    expect(blob).toHaveLength(176);
    expect(b64urlDecode(blob)).toHaveLength(132);
  });

  it("cannot be sealed out of range", async () => {
    await expect(sealState(KEY, { ...loopbackState, deviceState: "a".repeat(65) })).rejects.toThrow();
    await expect(sealState(KEY, { ...loopbackState, deviceState: "has space 0123456789" })).rejects.toThrow();
    await expect(sealState(KEY, { ...loopbackState, port: 80 })).rejects.toThrow();
    await expect(sealState(KEY, { ...loopbackState, port: 65536 })).rejects.toThrow();
    await expect(sealState(KEY, { ...loopbackState, challenge: new Uint8Array(31) })).rejects.toThrow();
    await expect(sealState(new Uint8Array(31), loopbackState)).rejects.toThrow();
  });
});

describe("grant blobs", () => {
  it("round-trip", async () => {
    const blob = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    expect(await openGrant(KEY, blob, CHALLENGE_BYTES, NOW)).toBe(GOOGLE_CODE);
    for (const code of ["12345678", "x".repeat(512), "4/0A_-.~+=/z"]) {
      expect(await openGrant(KEY, await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, code), CHALLENGE_BYTES, NOW)).toBe(code);
    }
  });

  it("have the byte layout of SPEC §2.3.1: the challenge is associated data, not content", async () => {
    const raw = b64urlDecode(await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE))!;
    expect([raw[0], raw[1]]).toEqual([1, 2]);
    const ikm = await crypto.subtle.importKey("raw", KEY, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("gclone-auth/v1/grant") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const aad = new Uint8Array(34);
    aad.set([1, 2]);
    aad.set(CHALLENGE_BYTES, 2);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(2, 14), additionalData: aad }, key, raw.slice(14)));
    expect(new DataView(plain.buffer).getUint32(0)).toBe(NOW + 120);
    expect(new TextDecoder().decode(plain.slice(4))).toBe(GOOGLE_CODE);
  });

  it("open only with the challenge they were sealed for", async () => {
    const blob = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    expect(await openGrant(KEY, blob, OTHER_CHALLENGE, NOW)).toBeNull();
    const oneBitOff = CHALLENGE_BYTES.slice();
    oneBitOff[31]! ^= 1;
    expect(await openGrant(KEY, blob, oneBitOff, NOW)).toBeNull();
    expect(await openGrant(KEY, blob, CHALLENGE_BYTES.slice(0, 31), NOW)).toBeNull();
  });

  it("expire: exp <= now fails, exp = now + 1 opens", async () => {
    const blob = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 1, GOOGLE_CODE);
    expect(await openGrant(KEY, blob, CHALLENGE_BYTES, NOW)).toBe(GOOGLE_CODE);
    expect(await openGrant(KEY, blob, CHALLENGE_BYTES, NOW + 1)).toBeNull();
  });

  it("stay within 546 bytes / 728 characters, typically about 145", async () => {
    const largest = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, "c".repeat(512));
    expect(largest).toHaveLength(728);
    expect(b64urlDecode(largest)).toHaveLength(546);
    const typical = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    expect(typical.length).toBeGreaterThan(100);
    expect(typical.length).toBeLessThan(160);
  });

  it("cannot be sealed out of range", async () => {
    await expect(sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, "c".repeat(513))).rejects.toThrow();
    await expect(sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, "1234567")).rejects.toThrow();
    await expect(sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, "with space 123")).rejects.toThrow();
    await expect(sealGrant(KEY, new Uint8Array(33), NOW + 120, GOOGLE_CODE)).rejects.toThrow();
  });
});

describe("pending blobs", () => {
  it("round-trip in loopback and in paste mode", async () => {
    expect(await openPending(KEY, await sealPending(KEY, loopbackPending), NOW)).toEqual(loopbackPending);
    expect(await openPending(KEY, await sealPending(KEY, pastePending), NOW)).toEqual(pastePending);
    for (const googleCode of ["12345678", "x".repeat(512), "4/0A_-.~+=/z"]) {
      for (const deviceState of ["a".repeat(16), "a".repeat(64)]) {
        const data = { ...loopbackPending, deviceState, googleCode };
        expect(await openPending(KEY, await sealPending(KEY, data), NOW)).toEqual(data);
      }
    }
  });

  it("have the byte layout of SPEC §2.3.1 (opened here with nothing but WebCrypto)", async () => {
    const raw = b64urlDecode(await sealPending(KEY, loopbackPending))!;
    expect([raw[0], raw[1]]).toEqual([1, 3]);
    const ikm = await crypto.subtle.importKey("raw", KEY, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("gclone-auth/v1/pending") },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(2, 14), additionalData: new Uint8Array([1, 3]) }, key, raw.slice(14)));
    const view = new DataView(plain.buffer);
    expect(view.getUint32(0)).toBe(NOW + 120);
    expect(view.getUint16(4)).toBe(8123);
    expect(plain.slice(6, 38)).toEqual(CHALLENGE_BYTES);
    expect(plain[38]).toBe(DEVICE_STATE.length);
    expect(new TextDecoder().decode(plain.slice(39, 39 + DEVICE_STATE.length))).toBe(DEVICE_STATE);
    expect(new TextDecoder().decode(plain.slice(39 + DEVICE_STATE.length))).toBe(GOOGLE_CODE);
  });

  it("expire: exp <= now fails, exp = now + 1 opens", async () => {
    const blob = await sealPending(KEY, { ...loopbackPending, exp: NOW + 1 });
    expect(await openPending(KEY, blob, NOW)).not.toBeNull();
    expect(await openPending(KEY, blob, NOW + 1)).toBeNull();
    expect(await openPending(KEY, blob, NOW + 1000)).toBeNull();
  });

  it("stay within 645 bytes / 860 characters", async () => {
    const largest = await sealPending(KEY, { ...loopbackPending, port: 65535, deviceState: "s".repeat(64), googleCode: "c".repeat(512) });
    expect(largest).toHaveLength(860);
    expect(b64urlDecode(largest)).toHaveLength(645);
    expect((await sealPending(KEY, pastePending)).length).toBeLessThan(200);
  });

  it("cannot be sealed out of range", async () => {
    await expect(sealPending(KEY, { ...loopbackPending, googleCode: "c".repeat(513) })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, googleCode: "1234567" })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, googleCode: "with space 123" })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, port: 80 })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, deviceState: "s".repeat(65) })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, deviceState: "short" })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, challenge: new Uint8Array(31) })).rejects.toThrow();
    await expect(sealPending(KEY, { ...loopbackPending, exp: -1 })).rejects.toThrow();
  });

  it("every single-byte flip, a wrong ver or kind, and another SEAL_KEY fail to open", async () => {
    const blob = await sealPending(KEY, loopbackPending);
    for (const mask of [0x01, 0x80, 0xff]) {
      for (let i = 0; i < b64urlDecode(blob)!.length; i++) {
        expect(await openPending(KEY, patched(blob, (raw) => (raw[i]! ^= mask)), NOW), `byte ${i} ^ ${mask}`).toBeNull();
      }
    }
    for (const bad of ["", blob.slice(0, -1), blob.slice(0, 20), `${blob}AAAA`, `${blob}=`, "x".repeat(4000)]) {
      expect(await openPending(KEY, bad, NOW), bad).toBeNull();
    }
    expect(await openPending(OTHER_KEY, blob, NOW)).toBeNull();
  });

  it("are neither states nor grants, and neither of those is a pending blob — also with `kind` patched", async () => {
    const pending = await sealPending(KEY, loopbackPending);
    const state = await sealState(KEY, loopbackState);
    const grant = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    // what matters most: /token opens grants only, so a pending blob redeems nothing before the user confirmed
    expect(await openGrant(KEY, pending, CHALLENGE_BYTES, NOW)).toBeNull();
    expect(await openGrant(KEY, patched(pending, (raw) => (raw[1] = 2)), CHALLENGE_BYTES, NOW)).toBeNull();
    expect(await openState(KEY, pending, NOW)).toBeNull();
    expect(await openState(KEY, patched(pending, (raw) => (raw[1] = 1)), NOW)).toBeNull();
    for (const other of [state, grant]) {
      expect(await openPending(KEY, other, NOW)).toBeNull();
      expect(await openPending(KEY, patched(other, (raw) => (raw[1] = 3)), NOW)).toBeNull();
    }
  });
});

describe("tampering", () => {
  it("every single-byte flip fails to open", async () => {
    const state = await sealState(KEY, loopbackState);
    const grant = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    for (const mask of [0x01, 0x80, 0xff]) {
      for (let i = 0; i < b64urlDecode(state)!.length; i++) {
        expect(await openState(KEY, patched(state, (raw) => (raw[i]! ^= mask)), NOW), `state byte ${i} ^ ${mask}`).toBeNull();
      }
      for (let i = 0; i < b64urlDecode(grant)!.length; i++) {
        expect(await openGrant(KEY, patched(grant, (raw) => (raw[i]! ^= mask)), CHALLENGE_BYTES, NOW), `grant byte ${i} ^ ${mask}`).toBeNull();
      }
    }
  });

  it("a wrong ver or kind fails", async () => {
    const state = await sealState(KEY, loopbackState);
    const grant = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    for (const ver of [0, 2, 255]) {
      expect(await openState(KEY, patched(state, (raw) => (raw[0] = ver)), NOW)).toBeNull();
      expect(await openGrant(KEY, patched(grant, (raw) => (raw[0] = ver)), CHALLENGE_BYTES, NOW)).toBeNull();
    }
    for (const kind of [0, 3, 4, 255]) {
      expect(await openState(KEY, patched(state, (raw) => (raw[1] = kind)), NOW)).toBeNull();
      expect(await openGrant(KEY, patched(grant, (raw) => (raw[1] = kind)), CHALLENGE_BYTES, NOW)).toBeNull();
    }
  });

  it("a state blob never opens as a grant, nor a grant as a state — also with `kind` patched", async () => {
    const state = await sealState(KEY, loopbackState);
    const grant = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    expect(await openGrant(KEY, state, CHALLENGE_BYTES, NOW)).toBeNull();
    expect(await openGrant(KEY, patched(state, (raw) => (raw[1] = 2)), CHALLENGE_BYTES, NOW)).toBeNull();
    expect(await openState(KEY, grant, NOW)).toBeNull();
    expect(await openState(KEY, patched(grant, (raw) => (raw[1] = 1)), NOW)).toBeNull();
  });

  it("truncated, extended and non-base64url text fails", async () => {
    const state = await sealState(KEY, loopbackState);
    const grant = await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE);
    for (const blob of [state, grant]) {
      const variants = [
        "",
        blob.slice(0, -1),
        blob.slice(0, -4),
        blob.slice(0, blob.length / 2),
        blob.slice(0, 20),
        blob.slice(4),
        blob + "AAAA",
        blob + "=",
        `+${blob.slice(1)}`,
        `${blob.slice(0, -2)}/=`,
        `${blob.slice(0, 10)} ${blob.slice(10)}`,
        `${blob.slice(0, 10)}!${blob.slice(11)}`,
        b64urlEncode(b64urlDecode(blob)!.slice(0, -1)),
        b64urlEncode(b64urlDecode(blob)!.slice(0, 29)),
        "x".repeat(4000),
      ];
      for (const bad of variants) {
        expect(await openState(KEY, bad, NOW), bad).toBeNull();
        expect(await openGrant(KEY, bad, CHALLENGE_BYTES, NOW), bad).toBeNull();
      }
    }
  });

  it("another SEAL_KEY fails", async () => {
    expect(await openState(OTHER_KEY, await sealState(KEY, loopbackState), NOW)).toBeNull();
    expect(await openGrant(OTHER_KEY, await sealGrant(KEY, CHALLENGE_BYTES, NOW + 120, GOOGLE_CODE), CHALLENGE_BYTES, NOW)).toBeNull();
  });
});

describe("SEAL_KEY", () => {
  // 32 bytes whose base64 text has both '+' and '/', and needs one '=' of padding.
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => (i % 2 === 0 ? 0xfb : 0xff));
  const base64 = btoa(String.fromCharCode(...bytes));

  it("decodes from base64 and base64url, padded and unpadded", () => {
    expect(base64).toMatch(/\+/);
    expect(base64).toMatch(/\//);
    expect(base64).toMatch(/=$/);
    const url = base64.replace(/\+/g, "-").replace(/\//g, "_");
    for (const text of [base64, base64.replace(/=+$/, ""), url, url.replace(/=+$/, ""), `${base64}\n`]) {
      expect(decodeSealKey(text), text).toEqual(bytes);
    }
    expect(decodeSealKey(SEAL_KEY)).toEqual(Uint8Array.from({ length: 32 }, (_, i) => i));
  });

  it("is refused unless it is exactly 32 bytes", () => {
    for (const n of [0, 16, 31, 33, 64]) {
      expect(decodeSealKey(btoa(String.fromCharCode(...new Uint8Array(n).fill(1)))), `${n} bytes`).toBeNull();
    }
    expect(decodeSealKey("not base64 at all !!")).toBeNull();
    expect(decodeSealKey(`${base64.slice(0, 20)}*${base64.slice(21)}`)).toBeNull();
  });

  it("of 31 or 33 bytes makes the Worker answer server_misconfigured", async () => {
    for (const n of [31, 33]) {
      h.env.SEAL_KEY = btoa(String.fromCharCode(...new Uint8Array(n).fill(1)));
      expect(await errorOf(await h.post("/token", { code: "x", verifier: VERIFIER }))).toEqual({ status: 500, error: "server_misconfigured" });
      expect((await h.get(loginPath())).status).toBe(500);
      expect(await (await h.get("/")).text()).toContain("Status: not configured");
    }
  });

  it("works in every spelling: a login started under one spelling completes under another", async () => {
    const url = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    h.secrets.add(base64).add(url);
    h.env.SEAL_KEY = base64;
    const page = await (await h.get(loginPath())).text();
    const state = new URL(page.match(/href="([^"]+)"/)![1]!.replace(/&amp;/g, "&")).searchParams.get("state")!;
    h.env.SEAL_KEY = url;
    const link = await finishLink(await h.get(`/callback?${new URLSearchParams({ code: GOOGLE_CODE, state })}`));
    h.env.SEAL_KEY = base64;
    expect((await h.get(link)).status).toBe(302);
  });
});
