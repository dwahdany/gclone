// gclone viewer — the seal of the ticket port: how a ticket (the key of one file's stream)
// gets from the vault worker to the Service Worker without being readable on the way.
//
// The way is a MessageChannel that the page creates and hands to both sides, so the page — and
// any script that runs in it — can keep an end of it, or sit in the middle. A key agreement
// over that port would be the page's to intercept. So the vault worker takes the Service
// Worker's public key from somewhere the page is not: it asks for `GET /seal-key` with its
// own fetch(), which the Service Worker that controls it answers out of its memory. A script in
// the page can neither answer that request nor change the answer. (When no Service Worker
// answers, the request reaches the host, which has no such address: no key, no ticket.)
//
//   Service Worker   one ECDH P-256 key pair per instance, private key not extractable, never
//                    stored; dropped with every `forget` (Lock, sign-out, a page that leaves)
//   vault worker     one key pair per ticket channel; ECDH with the public key it fetched
//   both             HKDF-SHA-256 over the shared secret, bound to both public keys
//                    → AES-256-GCM, a random 96-bit nonce per ticket, the file's id as
//                    associated data
//
// The vault worker's public key travels with each sealed ticket. Whoever replaces it on the way
// agrees a key of their own with the Service Worker and can then hand it tickets of their own
// making — which opens nothing — but cannot open one the vault worker sealed.
//
// What this does not change: the page asks for a ticket by id and path, and reads the file
// through `/v/<id>`. It gets the plaintext of what it asks for while the vault is unlocked;
// it does not get the keys.
'use strict';
(() => {
  const gclone = (self.gclone = self.gclone || {});
  const subtle = self.crypto.subtle;
  const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
  const PUBLIC_LEN = 65; // an uncompressed point
  const NONCE_LEN = 12;
  const LABEL = 'gclone-viewer/ticket-seal/1';
  const encoder = new TextEncoder();

  /** A public key as it travels: 65 bytes. */
  const isPublic = (value) => value instanceof Uint8Array && value.length === PUBLIC_LEN;

  function same(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  /** A fresh key pair: `{ secret, raw }`. The private half cannot be exported. */
  async function generate() {
    const pair = await subtle.generateKey(CURVE, false, ['deriveBits']);
    return { secret: pair.privateKey, raw: new Uint8Array(await subtle.exportKey('raw', pair.publicKey)) };
  }

  /**
   * The key of one channel, from my private key and the other side's public key. `sw` and
   * `vault` are the two public keys by role: both sides derive with the same pair, in this order.
   */
  async function agree(secret, peer, sw, vault, usage) {
    const theirs = await subtle.importKey('raw', peer, CURVE, false, []);
    const shared = await subtle.deriveBits({ name: 'ECDH', public: theirs }, secret, 256);
    const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    new Uint8Array(shared).fill(0);
    const label = encoder.encode(LABEL);
    const info = new Uint8Array(label.length + 1 + 2 * PUBLIC_LEN);
    info.set(label, 0);
    info.set(sw, label.length + 1);
    info.set(vault, label.length + 1 + PUBLIC_LEN);
    return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info }, material, { name: 'AES-GCM', length: 256 }, false, [usage]);
  }

  const bound = (id) => encoder.encode(`${LABEL}\0${id}`);

  /** `text`, readable only with this channel's key and only as the ticket of `id`. */
  async function close(key, id, text) {
    const iv = self.crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const data = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: bound(id) }, key, encoder.encode(text)));
    return { iv, data };
  }

  /** The text `close` was given; throws for anything else. */
  async function open(key, id, iv, data) {
    if (!(iv instanceof Uint8Array) || iv.length !== NONCE_LEN || !(data instanceof Uint8Array)) throw new TypeError('not a sealed ticket');
    return new TextDecoder('utf-8', { fatal: true }).decode(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: bound(id) }, key, data));
  }

  gclone.seal = { PATH: '/seal-key', BUILD_HEADER: 'X-Gclone-Build', PUBLIC_LEN, isPublic, same, generate, agree, close, open };
})();
