// The wasm module on an index of the size of a large vault: how long the time machine's
// questions take, and how much memory the module needs (design §10 of the time machine).
// Not part of any suite: the index is made by
//
//   cd web-core && GCLONE_WEB_CORE_SCALE=<dir> cargo test --release --test parity -- \
//       --ignored --nocapture the_time_machine_at_scale
//
// and then, with the module to measure (default ../pkg; an older build has no time machine
// and is measured for its load and its present-day questions only):
//
//   GCLONE_WEB_CORE_SCALE=<dir> [GCLONE_WEB_CORE_PKG=<pkg>] node web-core/test/scale.mjs
import fs from 'node:fs';
import path from 'node:path';
import { loadCore, wasmBytes } from './core.mjs';

const dir = process.env.GCLONE_WEB_CORE_SCALE;
if (!dir) throw new Error('GCLONE_WEB_CORE_SCALE names the directory the scale test exported to');
const facts = JSON.parse(fs.readFileSync(path.join(dir, 'scale.json'), 'utf8'));
const { core } = loadCore();
const mib = (n) => `${(n / 1048576).toFixed(0)} MiB`;
const timed = (what, fn) => {
  const start = performance.now();
  const out = fn();
  console.log(`${what.padEnd(34)} ${(performance.now() - start).toFixed(1).padStart(9)} ms`);
  return out;
};
const unhex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));

console.log(`core ${core.core_version()}, ${facts.files} files; wasm memory at start ${mib(wasmBytes())}`);
const vault = core.Vault.from_keys(unhex(facts.bundle));
const names = JSON.stringify(facts.listing.map((o) => o.name));
const created = new Map(facts.listing.map((o) => [o.name, o.created_ms]));
const object = (name) => new Uint8Array(fs.readFileSync(path.join(dir, 'index', name)));
timed('load (snapshot, segments, finish)', () => {
  for (const name of JSON.parse(vault.snapshot_candidates(names))) if (vault.load_snapshot(name, object(name))) break;
  for (const name of JSON.parse(vault.needed_segments(names))) vault.add_segment(name, object(name), created.get(name));
  const report = JSON.parse(vault.finish());
  if (report.files !== facts.files) throw new Error(`loaded ${report.files} files`);
});
const loaded = wasmBytes();
console.log(`wasm memory after the load:        ${mib(loaded)}`);
timed('list, root, now', () => vault.list(''));
timed('list, old/d000, now', () => vault.list('old/d000'));
timed('search "f0500", now', () => vault.search('f0500'));
timed('search, no match, now', () => vault.search('no-such-name'));

if (typeof vault.timeline === 'function') {
  const { now, at, before } = facts;
  timed('history (first timeline)', () => vault.timeline(now));
  timed('timeline again', () => vault.timeline(now));
  timed('list at T, root, first', () => vault.list('', undefined, undefined, undefined, undefined, at, now));
  timed('list at T, root, again', () => vault.list('', undefined, undefined, undefined, undefined, at, now));
  const again = (what, fn) => {
    const start = performance.now();
    fn();
    const took = performance.now() - start;
    console.log(`${what.padEnd(34)} ${took.toFixed(1).padStart(9)} ms`);
    if (took > 100) throw new Error(`${what}: ${took.toFixed(1)} ms — a listing that was asked before takes at most 100 ms`);
  };
  again('list at T, root, a third time', () => vault.list('', undefined, undefined, undefined, undefined, at, now));
  timed('list at T, photos, first', () => vault.list('photos', undefined, undefined, undefined, undefined, at, now));
  again('list at T, photos, again', () => vault.list('photos', undefined, undefined, undefined, undefined, at, now));
  timed('list at T, mixed (a page)', () => vault.list('mixed', undefined, undefined, undefined, undefined, at, now));
  timed('list just before now, mixed (page)', () => vault.list('mixed', undefined, undefined, undefined, undefined, now - 1, now));
  timed('list now, mixed (a page)', () => vault.list('mixed'));
  timed('list at T, old', () => vault.list('old', undefined, undefined, undefined, undefined, at, now));
  timed('list at T, old/d000', () => vault.list('old/d000', undefined, undefined, undefined, undefined, at, now));
  timed('list at T, young (absent)', () => vault.list('young', undefined, undefined, undefined, undefined, at, now));
  timed('list before the deletion, gone', () => vault.list('gone', undefined, undefined, undefined, undefined, before, now));
  timed('search "f0500" at T', () => vault.search('f0500', undefined, undefined, undefined, at, now));
  timed('search, no match, at T', () => vault.search('no-such-name', undefined, undefined, undefined, at, now));
  timed('versions of one file', () => vault.versions('edit/d000/f0000.bin', undefined, now));
  timed('deleted from the root', () => vault.deleted('', undefined, undefined, undefined, undefined, now));
  // A tour through other moments: nothing is kept per moment.
  timed('forty other moments, root', () => {
    for (let i = 1; i <= 40; i += 1) vault.list('', undefined, undefined, undefined, undefined, now - i * 14 * 3600 * 1000, now);
  });
  console.log(`wasm memory after the tour:        ${mib(wasmBytes())} (grew by ${mib(wasmBytes() - loaded)})`);
}
vault.free();
