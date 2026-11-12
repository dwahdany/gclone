// Sealed state / pending / grant blobs (what keeps the Worker stateless), base64url, the check code and the login nonce.
// WebCrypto only: runs unchanged under workerd and under Node >= 20.

const VER = 0x01;
const KIND_STATE = 0x01;
const KIND_GRANT = 0x02;
const KIND_PENDING = 0x03;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const HEAD_LEN = 2 + NONCE_LEN; // ver, kind, nonce
const CHALLENGE_LEN = 32;
const STATE_FIXED = 4 + 2 + CHALLENGE_LEN; // exp, port, challenge
const DEVICE_STATE_MAX = 64;
const CODE_MIN = 8;
const CODE_MAX = 512;
const STATE_BLOB_MAX = HEAD_LEN + STATE_FIXED + DEVICE_STATE_MAX + TAG_LEN; // 132 bytes
const GRANT_BLOB_MAX = HEAD_LEN + 4 + CODE_MAX + TAG_LEN; // 546 bytes
const PENDING_FIXED = STATE_FIXED + 1; // exp, port, challenge, length of the device state
const PENDING_BLOB_MAX = HEAD_LEN + PENDING_FIXED + DEVICE_STATE_MAX + CODE_MAX + TAG_LEN; // 645 bytes

const DEVICE_STATE_RE = /^[A-Za-z0-9_-]{0,64}$/;
const GOOGLE_CODE_RE = /^[\x21-\x7e]{8,512}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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

export function decodeSealKey(text: string): Uint8Array | null {
  if (typeof text !== "string") return null;
  const unpadded = text.trim().replace(/\+/g, "-").replace(/\//g, "_").replace(/={1,2}$/, "");
  const key = b64urlDecode(unpadded);
  return key !== null && key.length === 32 ? key : null;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/** "XXXX-XXXX": the first 40 bits of SHA-256("gclone-auth/v1/check" ‖ challenge text) in Crockford base32. */
export async function checkCode(challenge: string): Promise<string> {
  const h = await sha256(utf8.encode("gclone-auth/v1/check" + challenge));
  let bits = 0n;
  for (let i = 0; i < 5; i++) bits = (bits << 8n) | BigInt(h[i]!);
  let out = "";
  for (let shift = 35n; shift >= 0n; shift -= 5n) out += CROCKFORD[Number((bits >> shift) & 31n)];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

/** The OIDC nonce that ties Google's authorization code to the device's challenge. */
export async function loginNonce(challenge: string): Promise<string> {
  return b64urlEncode(await sha256(utf8.encode("gclone-auth/v1/nonce" + challenge)));
}

export interface StateData {
  exp: number;
  port: number;
  challenge: Uint8Array /* 32 */;
  deviceState: string;
}

export async function sealState(key: Uint8Array, d: StateData): Promise<string> {
  if (!validState(d)) throw new RangeError("state out of range");
  const plain = new Uint8Array(STATE_FIXED + d.deviceState.length);
  const view = new DataView(plain.buffer);
  view.setUint32(0, d.exp);
  view.setUint16(4, d.port);
  plain.set(d.challenge, 6);
  plain.set(utf8.encode(d.deviceState), STATE_FIXED);
  return seal(key, KIND_STATE, new Uint8Array(0), plain);
}

export async function openState(key: Uint8Array, blob: string, nowS: number): Promise<StateData | null> {
  const plain = await open(key, KIND_STATE, new Uint8Array(0), blob, STATE_BLOB_MAX);
  if (plain === null || plain.length < STATE_FIXED) return null;
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const d: StateData = {
    exp: view.getUint32(0),
    port: view.getUint16(4),
    challenge: plain.slice(6, STATE_FIXED),
    deviceState: ascii(plain.subarray(STATE_FIXED)),
  };
  return validState(d) && d.exp > nowS ? d : null;
}

export async function sealGrant(key: Uint8Array, challenge: Uint8Array, exp: number, googleCode: string): Promise<string> {
  if (challenge.length !== CHALLENGE_LEN || !validExp(exp) || !GOOGLE_CODE_RE.test(googleCode)) {
    throw new RangeError("grant out of range");
  }
  const plain = new Uint8Array(4 + googleCode.length);
  new DataView(plain.buffer).setUint32(0, exp);
  plain.set(utf8.encode(googleCode), 4);
  return seal(key, KIND_GRANT, challenge, plain);
}

/** Returns Google's authorization code, or null for every kind of failure alike. */
export async function openGrant(key: Uint8Array, blob: string, challenge: Uint8Array, nowS: number): Promise<string | null> {
  if (challenge.length !== CHALLENGE_LEN) return null;
  const plain = await open(key, KIND_GRANT, challenge, blob, GRANT_BLOB_MAX);
  if (plain === null || plain.length < 4 + CODE_MIN) return null;
  const exp = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0);
  const code = ascii(plain.subarray(4));
  return exp > nowS && GOOGLE_CODE_RE.test(code) ? code : null;
}

/** What /callback knows once Google has sent its code: everything the last step of the login needs. */
export interface PendingData extends StateData {
  googleCode: string;
}

/** A pending blob travels only in the Continue link of the post-consent confirmation page. It is not a grant: /token refuses it. */
export async function sealPending(key: Uint8Array, d: PendingData): Promise<string> {
  if (!validState(d) || !GOOGLE_CODE_RE.test(d.googleCode)) throw new RangeError("pending out of range");
  const plain = new Uint8Array(PENDING_FIXED + d.deviceState.length + d.googleCode.length);
  const view = new DataView(plain.buffer);
  view.setUint32(0, d.exp);
  view.setUint16(4, d.port);
  plain.set(d.challenge, 6);
  plain[STATE_FIXED] = d.deviceState.length;
  plain.set(utf8.encode(d.deviceState), PENDING_FIXED);
  plain.set(utf8.encode(d.googleCode), PENDING_FIXED + d.deviceState.length);
  return seal(key, KIND_PENDING, new Uint8Array(0), plain);
}

export async function openPending(key: Uint8Array, blob: string, nowS: number): Promise<PendingData | null> {
  const plain = await open(key, KIND_PENDING, new Uint8Array(0), blob, PENDING_BLOB_MAX);
  if (plain === null || plain.length < PENDING_FIXED) return null;
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const codeAt = PENDING_FIXED + plain[STATE_FIXED]!;
  if (codeAt > plain.length) return null;
  const d: PendingData = {
    exp: view.getUint32(0),
    port: view.getUint16(4),
    challenge: plain.slice(6, STATE_FIXED),
    deviceState: ascii(plain.subarray(PENDING_FIXED, codeAt)),
    googleCode: ascii(plain.subarray(codeAt)),
  };
  return validState(d) && GOOGLE_CODE_RE.test(d.googleCode) && d.exp > nowS ? d : null;
}

function validExp(exp: number): boolean {
  return Number.isInteger(exp) && exp >= 0 && exp <= 0xffff_ffff;
}

function validState(d: StateData): boolean {
  const loopback = d.port !== 0;
  return (
    validExp(d.exp) &&
    Number.isInteger(d.port) &&
    (!loopback || (d.port >= 1024 && d.port <= 65535)) &&
    d.challenge.length === CHALLENGE_LEN &&
    DEVICE_STATE_RE.test(d.deviceState) &&
    (!loopback || d.deviceState.length >= 16)
  );
}

function ascii(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const KIND_INFO: Record<number, string> = {
  [KIND_STATE]: "gclone-auth/v1/state",
  [KIND_GRANT]: "gclone-auth/v1/grant",
  [KIND_PENDING]: "gclone-auth/v1/pending",
};

/** K_state / K_grant / K_pending: one AES-256-GCM key per blob kind, so a blob of one kind can never open as another. */
async function kindKey(sealKey: Uint8Array, kind: number): Promise<CryptoKey> {
  if (sealKey.length !== 32) throw new RangeError("SEAL_KEY must be 32 bytes");
  const label = KIND_INFO[kind];
  if (label === undefined) throw new RangeError("unknown blob kind");
  const info = utf8.encode(label);
  const ikm = await crypto.subtle.importKey("raw", sealKey, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(sealKey: Uint8Array, kind: number, aadTail: Uint8Array, plain: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const head = new Uint8Array([VER, kind]);
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: concat(head, aadTail), tagLength: TAG_LEN * 8 },
    await kindKey(sealKey, kind),
    plain,
  );
  return b64urlEncode(concat(head, iv, new Uint8Array(sealed)));
}

async function open(sealKey: Uint8Array, kind: number, aadTail: Uint8Array, blob: string, maxLen: number): Promise<Uint8Array | null> {
  if (typeof blob !== "string" || blob.length > Math.ceil((maxLen * 4) / 3)) return null;
  const raw = b64urlDecode(blob);
  if (raw === null || raw.length < HEAD_LEN + TAG_LEN || raw.length > maxLen) return null;
  if (raw[0] !== VER || raw[1] !== kind) return null;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.subarray(2, HEAD_LEN), additionalData: concat(raw.subarray(0, 2), aadTail), tagLength: TAG_LEN * 8 },
      await kindKey(sealKey, kind),
      raw.subarray(HEAD_LEN),
    );
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}
