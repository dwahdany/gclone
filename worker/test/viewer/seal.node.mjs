// seal.js in Node (`node --test`): the seal of the ticket port. What the vault worker closes,
// the Service Worker opens — and nobody who has only the public keys, another key pair, or
// the port.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { test } from 'node:test';
import { VIEWER } from './env.mjs';

globalThis.self = globalThis;
vm.runInThisContext(fs.readFileSync(path.join(VIEWER, 'seal.js'), 'utf8'), { filename: path.join(VIEWER, 'seal.js') });
const { seal } = globalThis.gclone;

const TICKET = JSON.stringify({ ticket: '{"v":1,"name":"a.txt","key":"c2VjcmV0"}', token: 'access', exp: 1 });
const ID = 'AAAAAAAAAAAAAAAAAAAAAA';

/** Both sides of one channel, as the two workers make them. */
async function channel() {
  const sw = await seal.generate();
  const vault = await seal.generate();
  return {
    sw, vault,
    close: await seal.agree(vault.secret, sw.raw, sw.raw, vault.raw, 'encrypt'),
    open: await seal.agree(sw.secret, vault.raw, sw.raw, vault.raw, 'decrypt'),
  };
}

test('what the vault worker closes, the Service Worker opens', async () => {
  const c = await channel();
  const sealed = await seal.close(c.close, ID, TICKET);
  assert.equal(sealed.iv.length, 12);
  assert.equal(sealed.data.length, Buffer.byteLength(TICKET) + 16);
  assert.equal(Buffer.from(sealed.data).includes('c2VjcmV0'), false, 'the ticket is not readable in what crosses the port');
  assert.equal(await seal.open(c.open, ID, sealed.iv, sealed.data), TICKET);
  // A nonce of its own for every ticket.
  const again = await seal.close(c.close, ID, TICKET);
  assert.notDeepEqual(again.iv, sealed.iv);
  assert.notDeepEqual(again.data, sealed.data);
});

test('it opens as the ticket of its id only, and not when a bit changed', async () => {
  const c = await channel();
  const sealed = await seal.close(c.close, ID, TICKET);
  await assert.rejects(seal.open(c.open, 'BAAAAAAAAAAAAAAAAAAAAA', sealed.iv, sealed.data));
  for (const part of ['iv', 'data']) {
    for (const at of [0, sealed[part].length - 1]) {
      const changed = { iv: sealed.iv.slice(), data: sealed.data.slice() };
      changed[part][at] ^= 1;
      await assert.rejects(seal.open(c.open, ID, changed.iv, changed.data), `${part}[${at}]`);
    }
  }
  await assert.rejects(seal.open(c.open, ID, sealed.iv, sealed.data.subarray(0, sealed.data.length - 1)));
  await assert.rejects(seal.open(c.open, ID, sealed.iv.subarray(0, 8), sealed.data), /not a sealed ticket/);
  await assert.rejects(seal.open(c.open, ID, Array.from(sealed.iv), sealed.data), /not a sealed ticket/);
});

test('someone in the middle of the port — both public keys, a key pair of their own — opens nothing', async () => {
  const c = await channel();
  const sealed = await seal.close(c.close, ID, TICKET);
  const eve = await seal.generate();
  const keys = [
    // with the Service Worker's public key, as the vault worker would
    await seal.agree(eve.secret, c.sw.raw, c.sw.raw, c.vault.raw, 'decrypt'),
    await seal.agree(eve.secret, c.sw.raw, c.sw.raw, eve.raw, 'decrypt'),
    // with the vault worker's public key, as the Service Worker would
    await seal.agree(eve.secret, c.vault.raw, c.sw.raw, c.vault.raw, 'decrypt'),
    await seal.agree(eve.secret, c.vault.raw, eve.raw, c.vault.raw, 'decrypt'),
  ];
  for (const key of keys) await assert.rejects(seal.open(key, ID, sealed.iv, sealed.data));
  // The vault worker's public key replaced on the way: the Service Worker then agrees a key
  // with the replacement, which does not open what the vault worker sealed.
  const replaced = await seal.agree(c.sw.secret, eve.raw, c.sw.raw, eve.raw, 'decrypt');
  await assert.rejects(seal.open(replaced, ID, sealed.iv, sealed.data));
  // …and lets the one in the middle hand over tickets of their own making, which was never a secret.
  const own = await seal.agree(eve.secret, c.sw.raw, c.sw.raw, eve.raw, 'encrypt');
  const forged = await seal.close(own, ID, '{"ticket":"{}"}');
  assert.equal(await seal.open(replaced, ID, forged.iv, forged.data), '{"ticket":"{}"}');
});

test('the key is bound to both public keys, by role, and to the Service Worker instance', async () => {
  const c = await channel();
  const sealed = await seal.close(c.close, ID, TICKET);
  // The same shared secret with the roles the other way round is another key.
  const swapped = await seal.agree(c.sw.secret, c.vault.raw, c.vault.raw, c.sw.raw, 'decrypt');
  await assert.rejects(seal.open(swapped, ID, sealed.iv, sealed.data));
  // A Service Worker that was restarted, or told to forget, has another key pair.
  const next = await seal.generate();
  const later = await seal.agree(next.secret, c.vault.raw, next.raw, c.vault.raw, 'decrypt');
  await assert.rejects(seal.open(later, ID, sealed.iv, sealed.data));
});

test('no key can be taken out: private halves and channel keys are not extractable', async () => {
  const c = await channel();
  assert.equal(c.sw.secret.extractable, false);
  assert.deepEqual(c.sw.secret.usages, ['deriveBits']);
  for (const format of ['pkcs8', 'jwk']) await assert.rejects(crypto.subtle.exportKey(format, c.sw.secret));
  for (const key of [c.close, c.open]) {
    assert.equal(key.extractable, false);
    assert.deepEqual([key.algorithm.name, key.algorithm.length], ['AES-GCM', 256]);
    await assert.rejects(crypto.subtle.exportKey('raw', key));
  }
  assert.deepEqual(c.close.usages, ['encrypt']);
  assert.deepEqual(c.open.usages, ['decrypt']);
});

test('a public key is 65 bytes of a point on the curve', async () => {
  const pair = await seal.generate();
  assert.equal(pair.raw.length, 65);
  assert.equal(pair.raw[0], 4);
  assert.equal(seal.isPublic(pair.raw), true);
  for (const not of [pair.raw.subarray(1), Array.from(pair.raw), pair.raw.buffer, null, 'x'.repeat(65)]) assert.equal(seal.isPublic(not), false);
  assert.equal(seal.same(pair.raw, pair.raw.slice()), true);
  const other = pair.raw.slice();
  other[64] ^= 1;
  assert.equal(seal.same(pair.raw, other), false);
  assert.equal(seal.same(pair.raw, pair.raw.subarray(1)), false);
  // 65 bytes that are no point: refused before any key is derived.
  const mine = await seal.generate();
  const junk = new Uint8Array(65).fill(7);
  junk[0] = 4;
  await assert.rejects(seal.agree(mine.secret, junk, junk, mine.raw, 'encrypt'));
  await assert.rejects(seal.agree(mine.secret, other, other, mine.raw, 'encrypt'));
  assert.equal(seal.PATH, '/seal-key');
});
