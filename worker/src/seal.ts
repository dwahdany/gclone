// The sealed web session: the one thing the Worker hands to a browser for safe keeping. AES-256-GCM under a key derived
// from SEAL_KEY; the browser stores the blob in an HttpOnly cookie and can neither read nor change it. The session's
// lifetime is inside the seal, so the cookie's own lifetime decides nothing.
// WebCrypto only: runs unchanged under workerd and under Node >= 20.

/** 0x01 were the state / grant / pending blobs of the browser sign-in before gclone 0.2.0 (kinds 0x01 to 0x03). */
const VER = 0x02;
const KIND_WEB_SESSION = 0x04;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const HEAD_LEN = 2 + NONCE_LEN; // ver, kind, nonce
const FIXED = 4 + 4 + 1; // iat, exp, length of the e-mail address
const EMAIL_MIN = 3;
const EMAIL_MAX = 254;
const TOKEN_MIN = 20;
const TOKEN_MAX = 512;
/** The largest blob: 805 bytes, 1074 characters — with the cookie's name a pair of 1092 bytes. */
export const SESSION_BLOB_MAX = HEAD_LEN + FIXED + EMAIL_MAX + TOKEN_MAX + TAG_LEN;
export const SESSION_BLOB_MAX_CHARS = Math.ceil((SESSION_BLOB_MAX * 4) / 3);
const SESSION_BLOB_MIN = HEAD_LEN + FIXED + EMAIL_MIN + TOKEN_MIN + TAG_LEN;
const INFO = "gclone-auth/v2/web-session";
const NONCE_LABEL = "gclone-auth/v2/nonce";
const PRINTABLE_RE = /^[\x21-\x7e]+$/;

const utf8 = new TextEncoder();

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** SEAL_KEY as `openssl rand -base64 32` prints it, or its base64url form: exactly 32 bytes, else null. */
export function decodeSealKey(text: unknown): Uint8Array | null {
  if (typeof text !== "string") return null;
  const key = b64urlDecode(text.trim().replace(/\+/g, "-").replace(/\//g, "_").replace(/={1,2}$/, ""));
  return key !== null && key.length === 32 ? key : null;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/** The PKCE challenge of a verifier (RFC 7636, S256), in the one spelling everything here uses. */
export async function pkceChallenge(verifier: string): Promise<string> {
  return b64urlEncode(await sha256(utf8.encode(verifier)));
}

/** The OIDC nonce that ties Google's authorization code to the PKCE challenge of the tab that started the sign-in:
 *  the Worker's own binding, independent of whether Google enforces the code verifier for this client type.
 *  b64url(SHA-256("gclone-auth/v2/nonce" ‖ challenge text)). */
export async function loginNonce(challenge: string): Promise<string> {
  return b64urlEncode(await sha256(utf8.encode(NONCE_LABEL + challenge)));
}

export interface WebSession {
  /** Seconds since the epoch: when the sign-in happened, and when the Worker stops honouring the blob. */
  iat: number;
  exp: number;
  email: string;
  refreshToken: string;
}

function valid(s: WebSession): boolean {
  const u32 = (n: number) => Number.isInteger(n) && n >= 0 && n <= 0xffff_ffff;
  return (
    u32(s.iat) &&
    u32(s.exp) &&
    typeof s.email === "string" &&
    s.email.length >= EMAIL_MIN &&
    s.email.length <= EMAIL_MAX &&
    PRINTABLE_RE.test(s.email) &&
    typeof s.refreshToken === "string" &&
    s.refreshToken.length >= TOKEN_MIN &&
    s.refreshToken.length <= TOKEN_MAX &&
    PRINTABLE_RE.test(s.refreshToken)
  );
}

async function sessionKey(sealKey: Uint8Array): Promise<CryptoKey> {
  if (sealKey.length !== 32) throw new RangeError("SEAL_KEY must be 32 bytes");
  const ikm = await crypto.subtle.importKey("raw", sealKey, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: utf8.encode(INFO) }, ikm, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** 0x02 ‖ 0x04 ‖ nonce(12) ‖ AES-256-GCM(key, nonce, aad = the first two bytes,
 *  iat u32 ‖ exp u32 ‖ len(email) u8 ‖ email ‖ refresh token), base64url. Throws when a field is out of range. */
export async function sealSession(sealKey: Uint8Array, s: WebSession): Promise<string> {
  if (!valid(s)) throw new RangeError("web session out of range");
  const plain = new Uint8Array(FIXED + s.email.length + s.refreshToken.length);
  const view = new DataView(plain.buffer);
  view.setUint32(0, s.iat);
  view.setUint32(4, s.exp);
  plain[8] = s.email.length;
  plain.set(utf8.encode(s.email), FIXED);
  plain.set(utf8.encode(s.refreshToken), FIXED + s.email.length);
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const head = new Uint8Array([VER, KIND_WEB_SESSION]);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: head, tagLength: TAG_LEN * 8 }, await sessionKey(sealKey), plain));
  const blob = new Uint8Array(HEAD_LEN + sealed.length);
  blob.set(head, 0);
  blob.set(iv, 2);
  blob.set(sealed, HEAD_LEN);
  return b64urlEncode(blob);
}

/** The session, or null for every kind of failure alike: not a blob, another key, another kind or version, tampered,
 *  out of range, expired (`exp <= nowS`). */
export async function openSession(sealKey: Uint8Array, blob: string, nowS: number): Promise<WebSession | null> {
  if (typeof blob !== "string" || blob.length > SESSION_BLOB_MAX_CHARS) return null;
  const raw = b64urlDecode(blob);
  if (raw === null || raw.length < SESSION_BLOB_MIN || raw.length > SESSION_BLOB_MAX) return null;
  if (raw[0] !== VER || raw[1] !== KIND_WEB_SESSION) return null;
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(2, HEAD_LEN), additionalData: raw.subarray(0, 2), tagLength: TAG_LEN * 8 }, await sessionKey(sealKey), raw.subarray(HEAD_LEN)),
    );
  } catch {
    return null;
  }
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const tokenAt = FIXED + plain[8]!;
  if (tokenAt > plain.length) return null;
  const ascii = (bytes: Uint8Array) => String.fromCharCode(...bytes);
  const s: WebSession = { iat: view.getUint32(0), exp: view.getUint32(4), email: ascii(plain.subarray(FIXED, tokenAt)), refreshToken: ascii(plain.subarray(tokenAt)) };
  return valid(s) && s.exp > nowS ? s : null;
}
