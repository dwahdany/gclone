// The cross-implementation suite (design §11): the wasm module, loaded as the viewer's
// workers load it, against (1) what the native viewer rules answer about a vault built with
// the main library (`tests/parity.rs` exports it) and (2) directory vaults made by the native
// `gclone` binary of this tree. Everything is asserted; the script exits non-zero on the
// first difference.
//
//   node e2e.mjs            env: GCLONE_BIN (the native binary), GCLONE_WEB_CORE_EXPORT (the
//                           directory tests/parity.rs exported to), GCLONE_WEB_CORE_PKG
//                           (default ../pkg), GCLONE_WEB_CORE_WORK (a scratch directory;
//                           default: a new temporary one, removed afterwards)
//
// `test/run.sh` sets all of it up. Nothing here touches a real vault, a real login or the
// network: every device is a pair of temporary directories, every vault a directory.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadCore, wasmBytes, codeOf, thrown, PKG } from './core.mjs';
import { DirStore } from './store.mjs';
import { Viewer, Unlocker, lsRecursive, lsLong, tree, humanSize } from './viewer.mjs';

const BIN = process.env.GCLONE_BIN;
const EXPORT = process.env.GCLONE_WEB_CORE_EXPORT;
const keepWork = !!process.env.GCLONE_WEB_CORE_WORK;
const WORK = process.env.GCLONE_WEB_CORE_WORK || fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-web-core-'));
const { core } = loadCore();
const mib = (n) => `${(n / 1048576).toFixed(1)} MiB`;
const summary = [];
const note = (line) => { summary.push(line); console.log(line); };
const section = (title) => console.log(`\n== ${title}`);
const kdfTimings = [];
const startBytes = wasmBytes();

// ---------------------------------------------------------------------------------------------
// 0. The module
// ---------------------------------------------------------------------------------------------
section('module');
{
  const build = JSON.parse(fs.readFileSync(path.join(PKG, 'build.json'), 'utf8'));
  assert.equal(core.core_version(), build.version);
  // The API of design §5, by name: nothing missing, nothing else.
  const functions = ['core_version', 'parse_rfc3339_ms', 'parse_descriptor', 'keyfile_candidates', 'keyfile_cost', 'unlock', 'served', 'parse_range'];
  const exported = Object.keys(core).filter((k) => k !== 'initSync').sort();
  assert.deepEqual(exported, [...functions, 'Vault', 'FileReader'].sort());
  const methods = (cls) => Object.getOwnPropertyNames(cls.prototype).filter((n) => !n.startsWith('__') && n !== 'constructor' && n !== 'free').sort();
  assert.deepEqual(methods(core.Vault), ['add_segment', 'finish', 'info', 'list', 'load_snapshot', 'needed_segments', 'reset', 'search', 'snapshot_candidates', 'stat', 'ticket', 'vault_id'].sort());
  assert.equal(typeof core.Vault.from_keys, 'function');
  assert.deepEqual(methods(core.FileReader), ['cipher_end', 'cipher_start', 'push', 'remaining', 'resume_at']);
  assert.equal(core.parse_rfc3339_ms('2026-11-13T10:14:00.250Z'), Date.parse('2026-11-13T10:14:00.250Z'));
  assert.equal(core.parse_rfc3339_ms('2026-11-13T10:14:00Z'), Date.parse('2026-11-13T10:14:00Z'));
  assert.equal(core.parse_rfc3339_ms('yesterday'), undefined);
  // Numbers that cross the boundary are whole and exact, or refused.
  assert.equal(thrown(() => core.parse_range(undefined, 1.5)), 'bad-input');
  assert.equal(thrown(() => core.parse_range(undefined, -1)), 'bad-input');
  assert.equal(thrown(() => core.parse_range(undefined, 2 ** 53)), 'bad-input');
  assert.equal(thrown(() => core.parse_range(undefined, NaN)), 'bad-input');
  assert.deepEqual(JSON.parse(core.parse_range(undefined, 2 ** 53 - 1)), { kind: 'whole', start: 0, end: 2 ** 53 - 1 });
  // Offsets beyond 4 GiB: the module is a 32-bit program, its file arithmetic is not.
  {
    const size = 10 * 2 ** 30 + 123;
    const chunks = Math.ceil(size / 65536);
    const header = Buffer.concat([Buffer.from('GCS1'), Buffer.from([1, 16, 1, 0, 0, 0, 0, 1]), Buffer.alloc(48)]);
    const ticket = JSON.stringify({
      v: 1, name: 'big.iso', size, file_id: 'id', blob_name: '00'.repeat(16), off: 5 * 2 ** 30,
      clen: 60 + size + 16 * chunks, chunk_log2: 16, key: Buffer.alloc(32).toString('base64url'), header: header.toString('base64url'),
    });
    const at = (plain) => 5 * 2 ** 30 + 60 + Math.floor(plain / 65536) * 65552;
    const a = 9 * 2 ** 30 + 5;
    let r = new core.FileReader(ticket, a, a + 100000);
    assert.deepEqual([r.cipher_start(), r.cipher_end(), r.remaining(), r.resume_at()], [at(a), at(a + 99999) + 65552, 100000, at(a)]);
    assert.equal(thrown(() => r.push(new Uint8Array(65552))), 'corrupt', 'zeros are not a chunk');
    r.free();
    // The last chunk is the short one, and the end is clamped to the size.
    r = new core.FileReader(ticket, size - 10, Number.MAX_SAFE_INTEGER);
    assert.deepEqual([r.cipher_start(), r.cipher_end(), r.remaining()], [at(size - 1), 5 * 2 ** 30 + 60 + size + 16 * chunks, 10]);
    assert.equal(r.cipher_end() - r.cipher_start(), (size % 65536) + 16);
    r.free();
    r = new core.FileReader(ticket, 0, size);
    assert.deepEqual([r.cipher_start(), r.cipher_end(), r.remaining()], [5 * 2 ** 30 + 60, 5 * 2 ** 30 + 60 + size + 16 * chunks, size]);
    r.free();
    assert.deepEqual(JSON.parse(core.parse_range(`bytes=${a}-`, size)), { kind: 'range', start: a, end: size });
  }
  note(`module: gclone-web-core ${build.version} (${build.rustc}, wasm-bindgen ${build.wasm_bindgen}); wasm memory at start ${mib(startBytes)}`);
}

// ---------------------------------------------------------------------------------------------
// 1. The native viewer rules, replayed (tests/parity.rs `export_for_the_wasm_suite`)
// ---------------------------------------------------------------------------------------------
const unhex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));

async function replayNative() {
  section('native rules replayed through the wasm');
  const busy = JSON.parse(fs.readFileSync(path.join(EXPORT, 'busy/expect.json'), 'utf8'));
  assert.equal(core.core_version(), busy.version);
  const object = (name) => new Uint8Array(fs.readFileSync(path.join(EXPORT, 'busy/index', name)));
  const names = JSON.stringify(busy.listing.map((o) => o.name));
  const created = new Map(busy.listing.map((o) => [o.name, o.created_ms]));

  const bundle = unhex(busy.bundle);
  const vault = core.Vault.from_keys(bundle);
  assert.ok(bundle.every((b) => b === 0));
  assert.equal(vault.vault_id(), busy.vault_id);
  // The loader's steps (design §6, step 5).
  const snapshots = JSON.parse(vault.snapshot_candidates(names));
  assert.ok(snapshots.length >= 1);
  assert.equal(vault.load_snapshot(snapshots[0], object(snapshots[0])), true);
  const needed = JSON.parse(vault.needed_segments(names));
  for (const name of needed) assert.equal(vault.add_segment(name, object(name), created.get(name)), true);
  const report = JSON.parse(vault.finish());
  // The wasm build of the reader reports what its native build reported.
  assert.deepEqual(report, busy.report);
  assert.equal(report.head, busy.head);
  // A refresh over the unchanged listing asks for nothing, and changes nothing.
  assert.deepEqual(JSON.parse(vault.needed_segments(names)), []);
  assert.deepEqual(JSON.parse(vault.finish()), busy.report);

  // Every answer: the same bytes as the SQL replica's rows through `gclone::web::rules`.
  const counts = {};
  for (const call of busy.calls) {
    const args = call.args.map((a) => (a === null ? undefined : a));
    let got;
    let failed;
    try { got = vault[call.fn](...args); } catch (error) { failed = error.message; }
    const what = `${call.fn}(${JSON.stringify(call.args)})`;
    if ('ok' in call) assert.equal(got, call.ok, `${what}${failed ? ` threw ${failed}` : ''}`);
    else assert.equal(failed, call.err, what);
    counts[call.fn] = (counts[call.fn] || 0) + 1;
  }
  // Numbers given as text (a query string's) are numbers.
  assert.equal(vault.list('', 'name', 'asc', '1', '2'), vault.list('', 'name', 'asc', 1, 2));
  assert.equal(thrown(() => vault.list('', 'name', 'asc', 'x', 2)), 'bad-input');
  assert.equal(thrown(() => vault.info('{}')), 'bad-input');
  assert.equal(thrown(() => vault.snapshot_candidates('{"not":"an array"}')), 'bad-input');

  // Without the snapshot: the same tree from the segments alone.
  const young = core.Vault.from_keys(unhex(busy.bundle));
  for (const name of JSON.parse(young.needed_segments(names))) young.add_segment(name, object(name), created.get(name));
  const fromSegments = JSON.parse(young.finish());
  assert.equal(fromSegments.snapshot, null);
  assert.equal(fromSegments.head, busy.head);
  for (const call of busy.calls.filter((c) => c.fn === 'list' && 'ok' in c)) {
    assert.equal(young.list(...call.args.map((a) => (a === null ? undefined : a))), call.ok);
  }
  // reset(): no index, the same keys; loading again gives the same report.
  young.reset();
  assert.equal(JSON.parse(young.finish()).files, 0);
  assert.equal(young.load_snapshot(snapshots[0], object(snapshots[0])), true);
  assert.equal(thrown(() => young.load_snapshot(snapshots[0], object(snapshots[0]))), 'bad-input');
  for (const name of JSON.parse(young.needed_segments(names))) young.add_segment(name, object(name), created.get(name));
  assert.deepEqual(JSON.parse(young.finish()), busy.report);
  young.free();

  // Files: the ticket points where the native build's ticket points, and decrypts to the
  // plaintext — whole and in ranges, in network pieces of any size.
  let ranges = 0;
  let seed = 4242;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % Math.max(1, n); };
  for (const file of busy.files) {
    const plain = fs.readFileSync(path.join(EXPORT, 'busy', file.plain));
    const ticketJson = vault.ticket(file.path);
    const ticket = JSON.parse(ticketJson);
    assert.deepEqual(Object.keys(ticket), ['v', 'name', 'size', 'file_id', 'blob_name', 'off', 'clen', 'chunk_log2', 'key', 'header']);
    const { v, key, header, ...where } = ticket;
    assert.equal(v, 1);
    assert.deepEqual(where, file.ticket);
    if (ticket.size === 0) {
      assert.deepEqual([key, header], [null, null]);
      const empty = new core.FileReader(ticketJson, 0, 10);
      assert.deepEqual([empty.cipher_start(), empty.cipher_end(), empty.remaining()], [0, 0, 0]);
      empty.free();
      continue;
    }
    assert.equal(Buffer.from(key, 'base64url').length, 32);
    assert.equal(Buffer.from(header, 'base64url').length, 60);
    const blob = fs.readFileSync(path.join(EXPORT, 'busy/blobs', ticket.file_id));
    const read = (start, end, piece) => {
      const reader = new core.FileReader(ticketJson, start, end);
      const out = [];
      for (let pos = reader.cipher_start(); pos < reader.cipher_end(); pos += piece) {
        out.push(reader.push(blob.subarray(pos, Math.min(pos + piece, reader.cipher_end()))));
      }
      assert.equal(reader.remaining(), 0);
      reader.free();
      return Buffer.concat(out);
    };
    for (const piece of [1 << 20, 65552, 65551, 1000]) assert.ok(read(0, ticket.size, piece).equals(plain), file.path);
    for (let i = 0; i < 25; i++) {
      const a = rnd(ticket.size);
      const b = a + 1 + rnd(ticket.size - a);
      assert.ok(read(a, b, 1 + rnd(90000)).equals(plain.subarray(a, b)), `${file.path} ${a}..${b}`);
      ranges++;
    }
  }
  for (const [p, code] of [['docs', 'not-a-file'], ['empty-dir', 'not-a-file'], ['nothing', 'not-found'], ['', 'bad-input'], ['a//b', 'bad-input']]) {
    assert.equal(thrown(() => vault.ticket(p)), code, p);
  }

  // What the Service Worker asks.
  for (const s of busy.served) {
    assert.deepEqual(JSON.parse(core.served(s.name, false)), s.shown, s.name);
    assert.deepEqual(JSON.parse(core.served(s.name, true)), s.saved, s.name);
  }
  for (const r of busy.ranges) {
    const got = JSON.parse(core.parse_range(r.header === null ? undefined : r.header, r.size));
    assert.deepEqual(got, { kind: r.kind, start: r.start, end: r.end }, JSON.stringify(r));
  }
  vault.free();
  note(`native rules: ${Object.entries(counts).map(([k, n]) => `${n} ${k}`).join(', ')} answers byte-identical; ${busy.files.length} files and ${ranges} ranges decrypted; ${busy.served.length} names served, ${busy.ranges.length} Range headers`);

  // --- format gates: fail closed, in the wasm, with the right code ---------------------------
  const gates = JSON.parse(fs.readFileSync(path.join(EXPORT, 'gates/expect.json'), 'utf8'));
  let closed = 0;
  for (const gate of gates.gates) {
    const bytes = new Uint8Array(fs.readFileSync(path.join(EXPORT, 'gates', gate.name)));
    const v = core.Vault.from_keys(unhex(gates.bundle));
    let got;
    try {
      if (gate.call === 'load_snapshot') got = String(v.load_snapshot(gate.name, bytes));
      else if (gate.call === 'add_segment') got = String(v.add_segment(gate.name, bytes, 7));
      else {
        assert.equal(v.add_segment(gate.name, bytes, 7), true);
        JSON.parse(v.finish());
        got = 'ok';
      }
    } catch (error) {
      got = codeOf(error) ?? `threw ${error.message}`;
    }
    assert.equal(got, gate.expect, `${gate.call} ${gate.name}`);
    if (gate.expect === 'needs-newer') {
      closed++;
      // Nothing of a refused object is shown: no snapshot, no file, however often asked.
      let after;
      try { after = JSON.parse(v.finish()); } catch (error) { after = codeOf(error); }
      if (after !== 'needs-newer') assert.deepEqual([after.snapshot, after.files, after.applied], [null, 0, 0]);
    }
    v.free();
  }
  for (const d of gates.descriptors) {
    const parsed = JSON.parse(core.parse_descriptor(Buffer.from(d.text)));
    assert.deepEqual([parsed.readable, parsed.min_reader], [d.readable, d.min_reader]);
  }
  for (const junk of ['', '{}', 'not json']) assert.equal(thrown(() => core.parse_descriptor(Buffer.from(junk))), 'damaged');
  for (const k of gates.keyfiles) {
    const bytes = new Uint8Array(fs.readFileSync(path.join(EXPORT, 'keyfiles', k.name)));
    let cost;
    try { cost = JSON.parse(core.keyfile_cost(k.name, bytes)); } catch (error) { cost = codeOf(error); }
    if (typeof k.cost === 'object') assert.deepEqual(cost, k.cost);
    else if (k.cost !== 'ok') assert.equal(cost, k.cost, `cost of ${k.name}`);
    let got;
    try {
      const bundle = core.unlock(k.name, bytes, k.pass, k.vault_id);
      assert.equal(Buffer.from(bundle).toString('hex'), gates.bundle);
      got = 'ok';
    } catch (error) {
      got = codeOf(error) ?? `threw ${error.message}`;
    }
    assert.equal(got, k.expect, `unlock ${k.name} with ${JSON.stringify(k.pass)}`);
  }
  note(`format gates: ${closed} objects of a newer format refused with needs-newer; ${gates.descriptors.length} descriptors, ${gates.keyfiles.length} keyfile cases`);
}

// ---------------------------------------------------------------------------------------------
// 2. Vaults made by the native binary
// ---------------------------------------------------------------------------------------------
const PASS = 'correct horse battery staple';
const PASS2 = 'a brand new passphrase, longer';
const PASS3 = 'the third passphrase of this vault';
const PASS4 = 'passphrase number four, set elsewhere';
const ATTACKER = 'not the owner at all, but well-formed';

function pattern(seed, len) {
  // Deterministic bytes without any dependency: a xorshift stream.
  const out = Buffer.alloc(len);
  let x = (seed * 2654435761 + 1) >>> 0 || 1;
  for (let i = 0; i < len; i++) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

function write(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

const passFiles = new Map();
function passFile(text) {
  if (!passFiles.has(text)) {
    const file = path.join(WORK, `passphrase-${passFiles.size + 1}`);
    fs.writeFileSync(file, `${text}\n`, { mode: 0o600 });
    passFiles.set(text, file);
  }
  return passFiles.get(text);
}

/** One device: a config and a state directory of its own. */
class Device {
  constructor(name) {
    this.name = name;
    this.env = {
      PATH: process.env.PATH,
      HOME: path.join(WORK, 'home'),
      TZ: 'UTC',
      GCLONE_CONFIG_DIR: path.join(WORK, `${name}-config`),
      GCLONE_STATE_DIR: path.join(WORK, `${name}-state`),
    };
    fs.mkdirSync(this.env.HOME, { recursive: true });
  }

  /** Runs the native binary; returns `{ code, stdout, stderr }`. Never inherits a login. */
  try(...args) {
    const out = spawnSync(BIN, args, { env: this.env, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
    if (out.error) throw out.error;
    const stderr = out.stderr.toString();
    assert.ok(!stderr.includes('panicked'), `gclone ${args.join(' ')} panicked:\n${stderr}`);
    return { code: out.status, stdout: out.stdout, stderr };
  }

  run(...args) {
    const out = this.try(...args);
    assert.equal(out.code, 0, `gclone ${args.join(' ')} (${this.name}) exited ${out.code}:\n${out.stderr}`);
    return out.stdout;
  }

  text(...args) {
    return this.run(...args).toString();
  }

  lines(...args) {
    return this.text(...args).split('\n').filter((l, i, all) => i < all.length - 1 || l !== '');
  }

  login(vaultDir, pass, deviceName = this.name) {
    return this.text('login', '--vault-dir', vaultDir, '--passphrase-file', passFile(pass), '--device-name', deviceName);
  }

  head() {
    const match = /^Head\s+(\S+) \(([\d,]+) files\)/m.exec(this.text('status'));
    assert.ok(match, 'status prints the head');
    return { head: match[1], files: Number(match[2].replace(/,/g, '')) };
  }
}

/** A second writer that does not see the first (two devices offline from each other):
 *  `first()` runs on the vault, `second()` on a copy taken before; what the copy gained is
 *  then put into the vault, as a store that both wrote to would hold it. */
function concurrently(vaultDir, first, second) {
  const fork = `${vaultDir}.fork`;
  const real = `${vaultDir}.real`;
  fs.cpSync(vaultDir, fork, { recursive: true, preserveTimestamps: true });
  first();
  fs.renameSync(vaultDir, real);
  fs.renameSync(fork, vaultDir);
  second();
  const merge = (rel) => {
    for (const entry of fs.readdirSync(path.join(vaultDir, rel), { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const child = path.join(rel, entry.name);
      const [from, to] = [path.join(vaultDir, child), path.join(real, child)];
      if (entry.isDirectory()) {
        fs.mkdirSync(to, { recursive: true });
        merge(child);
      } else if (!fs.existsSync(to)) {
        fs.copyFileSync(from, to);
        const st = fs.statSync(from);
        fs.utimesSync(to, st.atime, st.mtime);
      }
    }
  };
  merge('');
  fs.rmSync(vaultDir, { recursive: true });
  fs.renameSync(real, vaultDir);
}

/** The native view of the vault from a device, and the wasm view: they must be the same.
 *  `hidden`: files that share their path with a folder (an unresolved conflict between a file
 *  and a directory). Both viewers show the folder, as `gclone ls` does; only the CLI's
 *  recursive walk also names the file. */
function assertSameTree(device, viewer, label, hidden = []) {
  const vault = viewer.vault;
  const rows = viewer.walk(vault);
  const bytewise = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
  const native = { ls: device.lines('ls', '-R', ':'), tree: device.lines('tree') };
  assert.deepEqual([...lsRecursive(rows), ...hidden].sort(bytewise), [...native.ls].sort(bytewise), `${label}: ls -R`);
  assert.deepEqual(tree(rows), native.tree, `${label}: tree`);
  // Sizes and times: `ls -l` of every directory.
  const dirs = ['', ...rows.filter((r) => r.dir).map((r) => r.path)];
  for (const dir of dirs) {
    const ours = lsLong(rows, dir);
    const theirs = device.lines('ls', '-l', `:${dir}`);
    assert.equal(ours.length, theirs.length, `${label}: ls -l :${dir}`);
    ours.forEach((line, i) => {
      const name = line.slice(31).replace(/\/$/, '');
      const at = dir ? `${dir}/${name}` : name;
      if (hidden.includes(at)) {
        // The CLI prints the hidden file's size and time on the folder's line.
        const size = JSON.parse(vault.ticket(at)).size;
        assert.match(theirs[i], new RegExp(`^ *${humanSize(size)}  \\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d  `), `${label}: ls -l :${dir}`);
        assert.equal(theirs[i].slice(31), `${name}/`);
      } else {
        assert.equal(line, theirs[i], `${label}: ls -l :${dir}`);
      }
    });
  }
  // stat agrees with the listing it came from; search finds every name by itself.
  for (const row of rows) {
    const stat = JSON.parse(vault.stat(row.path));
    assert.deepEqual([stat.path, stat.name, stat.dir, stat.kind, stat.size, stat.mtime_ms], [row.path, row.name, row.dir, row.kind, row.size, row.mtime_ms]);
  }
  const { head, files } = device.head();
  return { rows, dirs, head, files };
}

async function nativeVaults() {
  section('a vault written by the native binary');
  const vaultDir = path.join(WORK, 'vault');
  const src = path.join(WORK, 'src');
  const d1 = new Device('laptop');
  const d2 = new Device('phone');

  // --- the tree: packed files, multi-chunk files, a blob of its own, exact chunk sizes, an
  //     empty file, an empty directory, names outside ASCII in both normal forms ---------------
  const files = {
    'docs/small.md': pattern(1, 400),
    'docs/deep/er/multi-chunk.bin': pattern(2, 307217),
    'docs/readme': Buffer.from('plain text without an extension\n'),
    'big-own-blob.bin': pattern(3, 3158073),
    'Fotos été/exact-two-chunks.bin': pattern(4, 131072),
    'Fotos été/IMG_0010.jpg': pattern(5, 20000),
    'Fotos été/img_2.jpg': pattern(6, 70000),
    'one-chunk.bin': pattern(7, 65536),
    'one-chunk-plus-one.bin': pattern(8, 65537),
    'empty.bin': Buffer.alloc(0),
    'größe 🎉/ünï cödé.txt': Buffer.from('unicode\n'),
    'café.md': Buffer.from('decomposed\n'),
    'to-delete.txt': Buffer.from('gone after the sync\n'),
    'to-rename.pdf': pattern(9, 150000),
    'page.html': Buffer.from('<script>alert(1)</script>\n'),
  };
  for (let i = 1; i <= 12; i++) files[`notes/note${i}.txt`] = Buffer.from(`note ${i}\n`);
  for (const [rel, content] of Object.entries(files)) write(path.join(src, rel), content);
  fs.mkdirSync(path.join(src, 'hollow'), { recursive: true });

  d1.login(vaultDir, PASS, 'laptop');
  d1.run('copy', src, ':');
  // One added, one deleted, by a sync.
  files['docs/added.md'] = Buffer.from('added before the sync\n');
  write(path.join(src, 'docs/added.md'), files['docs/added.md']);
  fs.rmSync(path.join(src, 'to-delete.txt'));
  delete files['to-delete.txt'];
  d1.run('sync', src, ':', '--yes');
  // A snapshot: everything so far is covered.
  d1.run('repair');
  // A second device: more files, a rename, a delete.
  d2.login(vaultDir, PASS, 'phone-sim');
  const src2 = path.join(WORK, 'src2');
  const phone = { 'camera/VID_0001.mp4': pattern(10, 200000), 'camera/IMG_0002.heic': pattern(11, 1234), 'camera/song.mp3': pattern(12, 66000) };
  for (const [rel, content] of Object.entries(phone)) { write(path.join(src2, rel), content); files[`phone/${rel}`] = content; }
  d2.run('copy', src2, ':phone');
  d2.run('mv', ':to-rename.pdf', ':renamed/now.pdf');
  files['renamed/now.pdf'] = files['to-rename.pdf'];
  delete files['to-rename.pdf'];
  d2.run('rm', ':notes/note3.txt');
  delete files['notes/note3.txt'];
  // Both devices write without seeing each other: one path with two versions (a conflict),
  // and a file where the other device has a folder.
  const srcA = path.join(WORK, 'src-a');
  const srcB = path.join(WORK, 'src-b');
  write(path.join(srcA, 'shared/note.txt'), 'the laptop\'s version\n');
  write(path.join(srcA, 'shared/only-laptop.txt'), 'laptop\n');
  write(path.join(srcA, 'clash'), 'a file called clash\n');
  write(path.join(srcB, 'shared/note.txt'), 'the phone\'s version, longer\n');
  write(path.join(srcB, 'shared/only-phone.txt'), 'phone\n');
  write(path.join(srcB, 'clash/inner.txt'), 'a folder called clash\n');
  concurrently(vaultDir, () => d1.run('copy', srcA, ':'), () => d2.run('copy', srcB, ':'));

  // --- the viewer: discover, keyfile, unlock in a worker ------------------------------------
  const store = new DirStore(vaultDir);
  const viewer = new Viewer(store);
  const found = viewer.discover();
  assert.equal(found.length, 1);
  assert.equal(found[0].descriptor.readable, true);
  assert.equal(found[0].descriptor.min_reader, 1);
  const candidates = viewer.open(found[0]);
  assert.equal(candidates.length, 1);
  // The CLI's real KDF cost: 256 MiB, three passes.
  assert.deepEqual(candidates[0].cost, { gen: 1, m_kib: 262144, t: 3, p: 1 });

  const unlocker = new Unlocker(candidates.map(({ name, bytes }) => ({ name, bytes })));
  const rssBefore = process.memoryUsage().rss;
  // Three wrong attempts, then the right one, in one worker: its memory is one working set.
  for (const wrong of ['not the passphrase', PASS.toUpperCase(), `${PASS} `]) {
    const answer = await viewer.unlock(wrong, unlocker);
    assert.equal(answer.outcome, 'wrong-passphrase');
    assert.deepEqual(answer.left, [candidates[0].name], 'a wrong passphrase keeps the candidate');
    assert.ok(answer.wasmBytes < 300 * 1048576, `KDF worker at ${mib(answer.wasmBytes)}`);
  }
  // As the CLI normalises it: a line break at the end is not part of the passphrase.
  const opened = await viewer.unlock(`${PASS}\n`, unlocker);
  assert.equal(opened.outcome, 'opened');
  assert.ok(opened.wasmBytes > 256 * 1048576 && opened.wasmBytes < 300 * 1048576, mib(opened.wasmBytes));
  assert.equal(unlocker.timings.length, 4);
  kdfTimings.push(...unlocker.timings);
  await unlocker.close();
  await new Promise((r) => setTimeout(r, 200));
  note(`unlock: 4 derivations (256 MiB, t=3) in one KDF worker, ${unlocker.timings.map((t) => t.toFixed(0)).join(' / ')} ms; worker wasm memory ${mib(opened.wasmBytes)}, this thread's ${mib(wasmBytes())}; rss ${mib(rssBefore)} before, ${mib(process.memoryUsage().rss)} after the worker is gone`);
  assert.ok(wasmBytes() < 16 * 1048576, 'the instance that will hold the vault never ran its KDF');
  // The native client refuses the same wrong passphrase.
  const stranger = new Device('stranger');
  const refused = stranger.try('login', '--vault-dir', vaultDir, '--passphrase-file', passFile('not the passphrase'));
  assert.notEqual(refused.code, 0);
  assert.match(refused.stderr, /passphrase/i);

  // --- the index: a snapshot and the segments after it, two devices, a conflict ---------------
  const loaded = viewer.loadIndex();
  assert.ok(loaded.snapshot, 'based on the snapshot `repair` wrote');
  assert.ok(loaded.report.applied >= 4, JSON.stringify(loaded.report));
  assert.deepEqual([loaded.report.blocked, loaded.report.missing, loaded.report.corrupt], [[], [], []]);
  assert.ok(loaded.report.conflicts >= 1, 'two versions of shared/note.txt');
  assert.equal(loaded.report.vault_name, 'gclone');
  // The native client's read-only commands show the same vault: the same head, the same
  // tree. (They resolve nothing and publish nothing: the store stays as the viewer loaded it.)
  const objects = () => viewer.listing().map((o) => o.name).sort();
  const loadedFrom = objects();
  const first = assertSameTree(d1, viewer, 'with an unresolved conflict', ['clash']);
  // The file behind the folder is still a file of the vault: it has a ticket and its content.
  assert.ok(viewer.read('clash').equals(d1.run('cat', ':clash')));
  assert.equal(viewer.read('clash').toString(), 'a file called clash\n');
  assert.equal(loaded.report.head, first.head, 'the head fingerprint is `gclone status`\'s');
  assert.equal(loaded.report.files, first.files);
  assert.equal(JSON.parse(viewer.vault.info('{"at_ms":1,"ok":true,"applied":0,"note":null}')).head, first.head);
  const info = JSON.parse(viewer.vault.info('{"at_ms":1,"ok":true,"applied":0,"note":null}'));
  assert.deepEqual([info.backend, info.device, info.read_only, info.version, info.vault, info.files], ['drive', 'this browser', true, core.core_version(), 'gclone', first.files]);
  // The last change is the one the native client names (`gclone about` on a device that is up to date).
  const lastChangeBy = (device) => {
    const match = /last change .* from "([^"]*)"/.exec(device.text('about'));
    assert.ok(match, `gclone about (${device.name}) names the last change`);
    return match[1];
  };
  assert.equal(info.last_change_by, lastChangeBy(d1));
  assert.equal(info.last_change_by, lastChangeBy(d2));
  // The fixture holds what it is meant to hold.
  const byPath = new Map(first.rows.map((r) => [r.path, r]));
  assert.equal(byPath.get('clash').dir, true, 'a folder wins over a file of its name in a listing');
  assert.equal(byPath.get('hollow').empty, true);
  assert.equal(byPath.get('empty.bin').size, 0);
  assert.ok(!byPath.has('to-delete.txt') && !byPath.has('to-rename.pdf') && !byPath.has('notes/note3.txt'));
  assert.ok(byPath.has('renamed/now.pdf') && byPath.has('café.md') && byPath.has('größe 🎉/ünï cödé.txt'));
  assert.deepEqual([byPath.get('page.html').kind, byPath.get('docs/readme').kind, byPath.get('phone/camera/VID_0001.mp4').kind], ['text', 'text', 'video']);
  // Natural order, folders first, in the default listing.
  const notes = JSON.parse(viewer.vault.list('notes')).entries.map((e) => e.name);
  assert.deepEqual(notes, [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12].map((i) => `note${i}.txt`));
  const found2 = JSON.parse(viewer.vault.search('ÉTÉ'));
  assert.deepEqual(found2.hits.map((h) => h.path), ['Fotos été']);
  assert.deepEqual(JSON.parse(viewer.vault.search('café')).hits.map((h) => h.path), ['café.md']);
  assert.deepEqual(JSON.parse(viewer.vault.search('café')).hits.map((h) => h.path), ['café.md'], 'NFC and NFD find each other');

  // --- content: byte-identical to `gclone cat`, whole, by range, by id and by name ------------
  let checked = 0;
  let bytes = 0;
  const shapes = { packed: 0, packedMultiChunk: 0, ownBlob: 0, empty: 0 };
  const plain = new Map();
  for (const row of first.rows.filter((r) => !r.dir)) {
    const native = d1.run('cat', `:${row.path}`);
    const got = viewer.read(row.path, { piece: [1 << 20, 70000, 65552, 4096][checked % 4] });
    assert.ok(got.equals(native), `${row.path} differs from gclone cat`);
    assert.equal(native.length, row.size);
    // Where a local original exists, it is that — except the path both devices wrote.
    if (files[row.path]) assert.ok(got.equals(files[row.path]), `${row.path} differs from the source`);
    plain.set(row.path, native);
    const ticket = JSON.parse(viewer.vault.ticket(row.path));
    if (ticket.size === 0) shapes.empty++;
    else {
      const blobSize = store.stat(viewer.blobId(ticket)).size;
      if (ticket.clen === blobSize) shapes.ownBlob++;
      else if (ticket.size > 65536) shapes.packedMultiChunk++;
      else shapes.packed++;
      assert.ok(ticket.off + ticket.clen <= blobSize);
    }
    checked++;
    bytes += native.length;
  }
  assert.ok(shapes.packed && shapes.packedMultiChunk && shapes.ownBlob && shapes.empty, JSON.stringify(shapes));
  assert.ok(['the laptop\'s version\n', 'the phone\'s version, longer\n'].includes(plain.get('shared/note.txt').toString()));
  // By name only (SPEC §3.2): as if every id the index recorded were unknown.
  for (const p of ['big-own-blob.bin', 'docs/small.md', 'shared/only-phone.txt', 'phone/camera/VID_0001.mp4']) {
    assert.ok(viewer.read(p, { by: 'name' }).equals(plain.get(p)), `${p} by name`);
  }
  // The second device's blobs came into this store by a copy: their recorded ids are unknown
  // here, and the reader found them by name without being told.
  assert.equal(store.resolve(JSON.parse(viewer.vault.ticket('shared/only-phone.txt')).file_id), null);
  // Ranges: against `gclone cat --offset --count`, and 600 random ones against the plaintext.
  for (const [p, offset, count] of [['big-own-blob.bin', 3158000, 73], ['big-own-blob.bin', 65535, 2], ['docs/deep/er/multi-chunk.bin', 131072, 65536], ['one-chunk.bin', 0, 65536], ['one-chunk-plus-one.bin', 65536, 1]]) {
    const native = d1.run('cat', `:${p}`, '--offset', String(offset), '--count', String(count));
    assert.ok(viewer.read(p, { start: offset, end: offset + count }).equals(native), `${p} @${offset}+${count}`);
  }
  let seed = 12345;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % Math.max(1, n); };
  let ranges = 0;
  for (const p of ['big-own-blob.bin', 'docs/deep/er/multi-chunk.bin', 'Fotos été/exact-two-chunks.bin', 'one-chunk-plus-one.bin', 'phone/camera/VID_0001.mp4', 'docs/small.md']) {
    const want = plain.get(p);
    for (let i = 0; i < 100; i++) {
      const a = rnd(want.length);
      const b = a + 1 + rnd(Math.min(want.length - a, 300000));
      const got = viewer.read(p, { start: a, end: b, piece: 1 + rnd(200000) });
      assert.ok(got.equals(want.subarray(a, b)), `${p} [${a},${b})`);
      ranges++;
    }
  }
  // A ranged read asks the store for the chunks it needs and nothing else.
  store.ranges.length = 0;
  viewer.read('big-own-blob.bin', { start: 70000, end: 70010 });
  assert.equal(store.ranges.length, 1);
  assert.equal(store.ranges[0][2] - store.ranges[0][1], 65536 + 16, 'one chunk, not the file');
  note(`content: ${checked} files (${bytes} bytes) byte-identical to gclone cat — ${JSON.stringify(shapes)}; ${ranges} random ranges; 4 files found by name`);

  // --- tampering with the ciphertext is refused ------------------------------------------------
  {
    const ticketJson = viewer.vault.ticket('big-own-blob.bin');
    const ticket = JSON.parse(ticketJson);
    const other = JSON.parse(viewer.vault.ticket('docs/deep/er/multi-chunk.bin'));
    const blob = Buffer.from(store.get(viewer.blobId(ticket)));
    const otherBlob = Buffer.from(store.get(viewer.blobId(other)));
    const full = 65536 + 16;
    const reader = () => new core.FileReader(ticketJson, 0, ticket.size);
    const start = ticket.off + 60;
    let r = reader();
    assert.equal(r.push(blob.subarray(start, start + full)).length, 65536);
    const flipped = Buffer.from(blob.subarray(start + full, start + 2 * full));
    flipped[100] ^= 1;
    assert.equal(thrown(() => r.push(flipped)), 'corrupt', 'a flipped bit');
    assert.equal(thrown(() => r.push(blob.subarray(start + 2 * full, start + 3 * full))), 'corrupt', 'nothing after a failure');
    r = reader();
    assert.equal(thrown(() => r.push(blob.subarray(start + full, start + 2 * full))), 'corrupt', 'a chunk at another position');
    r = reader();
    assert.equal(thrown(() => r.push(otherBlob.subarray(other.off + 60, other.off + 60 + full))), 'corrupt', 'a chunk of another file');
    r = reader();
    const cut = r.push(blob.subarray(start, start + full + 1000));
    assert.deepEqual([cut.length, r.remaining()], [65536, ticket.size - 65536], 'a cut stream stays owed');
    assert.equal(r.resume_at(), start + full, 'and continues at the chunk that did not verify');
    const rest = r.push(blob.subarray(start + full, ticket.off + ticket.clen));
    assert.equal(r.remaining(), 0);
    assert.ok(Buffer.concat([cut, rest]).equals(plain.get('big-own-blob.bin')));
    assert.equal(thrown(() => r.push(Buffer.from([0]))), 'corrupt', 'bytes after the end');
    // The last chunk, cut by one byte and completed with a wrong one.
    const lastAt = ticket.off + ticket.clen - ((ticket.size % 65536) + 16);
    r = new core.FileReader(ticketJson, ticket.size - 10, ticket.size);
    assert.equal(r.cipher_start(), lastAt);
    assert.equal(r.push(blob.subarray(lastAt, ticket.off + ticket.clen - 1)).length, 0);
    assert.equal(thrown(() => r.push(Buffer.from([blob[ticket.off + ticket.clen - 1] ^ 1]))), 'corrupt', 'a cut chunk');
    // Another file's key opens nothing of this one.
    r = new core.FileReader(JSON.stringify({ ...ticket, key: other.key }), 0, 10);
    assert.equal(thrown(() => r.push(blob.subarray(start, start + full))), 'corrupt', 'another key');
    assert.equal(thrown(() => new core.FileReader(JSON.stringify({ ...ticket, size: ticket.size + 1 }), 0, 1)), 'bad-input');
    assert.equal(thrown(() => new core.FileReader('{}', 0, 1)), 'bad-input');
    assert.equal(thrown(() => new core.FileReader(ticketJson, 5, 4)), 'bad-input');
    assert.equal(thrown(() => new core.FileReader(ticketJson, 0.5, 4)), 'bad-input');
    note('tamper: flipped bit, moved chunk, foreign chunk, cut chunk, trailing bytes, foreign key all refused; a broken stream resumes at the unverified chunk');
  }

  // --- damaged index objects (in memory: the store is not changed) ----------------------------
  {
    const flip = (bytes, at) => { const copy = Uint8Array.from(bytes); copy[at ?? (copy.length >> 1)] ^= 1; return copy; };
    // Every snapshot damaged: the loader stops (design §6) — nothing is shown.
    const none = viewer.secondVault();
    assert.throws(() => viewer.loadIndex(none, (name, bytes) => (name.startsWith('c-') ? flip(bytes) : bytes)), /No snapshot of this vault's index could be read/);
    assert.equal(JSON.parse(none.finish()).corrupt.length, loaded.snapshotsTried.length);
    none.free();
    // A young vault's way — from the segments alone — gives the same head and the same tree
    // (the covered segments are still listed).
    const young = viewer.secondVault();
    const listing = viewer.listing();
    for (const o of listing.filter((o) => o.name.startsWith('s-'))) assert.equal(young.add_segment(o.name, store.get(o.id), o.createdMs), true);
    const fromSegments = JSON.parse(young.finish());
    assert.deepEqual([fromSegments.snapshot, fromSegments.head, fromSegments.files, fromSegments.blocked], [null, first.head, first.files, []]);
    assert.deepEqual(lsRecursive(viewer.walk(young)), lsRecursive(first.rows));
    young.free();
    // One segment after the snapshot damaged: refused and recorded; what depends on it is
    // blocked and named with the id to fetch it by; the intact bytes cure it.
    const hurt = viewer.secondVault();
    const names = JSON.stringify(listing.map((o) => o.name));
    const snap = JSON.parse(hurt.snapshot_candidates(names))[0];
    assert.equal(hurt.load_snapshot(snap, store.get(listing.find((o) => o.name === snap).id)), true);
    const needed = JSON.parse(hurt.needed_segments(names));
    // The first of several segments one device wrote after the snapshot: the next names it.
    const victim = needed.find((name) => needed.some((other) => other > name && other.slice(0, 18) === name.slice(0, 18)));
    assert.ok(victim, 'a device wrote two segments after the snapshot');
    const object = (name) => listing.find((o) => o.name === name);
    for (const name of needed) {
      const good = store.get(object(name).id);
      assert.equal(hurt.add_segment(name, name === victim ? flip(good) : good, object(name).createdMs), name !== victim);
    }
    const partial = JSON.parse(hurt.finish());
    assert.equal(partial.corrupt.length, 1);
    assert.ok(partial.corrupt[0].startsWith(`${victim}: `));
    assert.ok(partial.blocked.length >= 1, 'later segments of that device wait');
    assert.ok(partial.missing.length >= 1 && partial.missing.every((m) => m.length === 4));
    assert.ok(JSON.parse(hurt.needed_segments(names)).includes(victim), 'still asked for');
    assert.notEqual(partial.head, first.head);
    assert.equal(hurt.add_segment(victim, store.get(object(victim).id), object(victim).createdMs), true);
    const cured = JSON.parse(hurt.finish());
    assert.deepEqual([cured.blocked, cured.missing, cured.corrupt, cured.head], [[], [], [], first.head]);
    hurt.free();
    // A listing that lags behind: a segment that is not listed is named by the one that
    // follows it, with the id its writer recorded, and fetched by that id (design §6).
    let byId = 0;
    for (const hidden of needed.filter((name) => needed.some((other) => other > name && other.slice(0, 18) === name.slice(0, 18)))) {
      const lagging = viewer.secondVault();
      const got = viewer.loadIndex(lagging, undefined, new Set([hidden]));
      if (got.byId) {
        // Found by id: everything applies, and the head is the vault's.
        assert.deepEqual([got.report.blocked, got.report.missing, got.report.head], [[], [], first.head]);
        byId += got.byId;
      } else {
        // Its id is not one this store knows (the object came here by a copy): it stays
        // missing, with what waits for it, and the viewer says so.
        assert.ok(got.report.blocked.length >= 1 && got.report.missing.length >= 1);
        assert.notEqual(got.report.head, first.head);
      }
      lagging.free();
    }
    assert.ok(byId >= 1, 'a segment the listing did not show was fetched by its id');
    // A truncated keyfile and a descriptor of the future.
    const kf = candidates[0];
    assert.equal(thrown(() => core.keyfile_cost(kf.name, kf.bytes.subarray(0, kf.bytes.length - 1))), 'damaged');
    assert.equal(thrown(() => core.unlock(kf.name, flip(kf.bytes, 50), PASS, found[0].descriptor.vault_id)), 'damaged');
    const descriptor = JSON.parse(fs.readFileSync(path.join(vaultDir, found[0].root, 'gclone-vault.json'), 'utf8'));
    const future = JSON.parse(core.parse_descriptor(Buffer.from(JSON.stringify({ ...descriptor, gclone_vault: 2, min_reader: 2 }))));
    assert.equal(future.readable, false);
    note(`damage: every snapshot damaged stops the load; from the segments alone the same head; a damaged segment blocks its successors, is named, and is cured by the intact bytes; ${byId} unlisted segment(s) fetched by id`);
  }

  // --- a refresh: a device attaches (which resolves the conflicts: the losers get names of
  //     their own), the laptop adds a file, the phone removes one --------------------------------
  assert.deepEqual(objects(), loadedFrom, 'reading with the native client changed nothing at the store');
  const before = viewer.refresh();
  assert.equal(before.fetched, 0, 'nothing changed at the store: nothing is fetched');
  assert.equal(before.report.head, first.head);
  const d3 = new Device('fresh');
  d3.login(vaultDir, PASS, 'fresh');
  const src3 = path.join(WORK, 'src3');
  write(path.join(src3, 'later/after-the-conflict.txt'), 'written by the laptop, later\n');
  d1.run('copy', src3, ':');
  d2.run('rm', ':phone/camera/song.mp3');
  const after = viewer.refresh();
  assert.ok(after.fetched >= 3, 'the new segments, and only those');
  assert.equal(after.fetched, objects().length - loadedFrom.length);
  assert.deepEqual([after.report.blocked, after.report.missing], [[], []]);
  const second = assertSameTree(d3, viewer, 'after a refresh');
  assert.equal(after.report.head, second.head);
  assert.notEqual(second.head, first.head);
  assert.ok(second.rows.some((r) => r.path === 'later/after-the-conflict.txt') && !second.rows.some((r) => r.path === 'phone/camera/song.mp3'));
  // The conflicts are resolved: the file that lost to a folder, and the version that lost,
  // are there under conflict names, with their content.
  assert.equal(after.report.conflicts, 0);
  const renamed = second.rows.filter((r) => /\.conflict-/.test(r.path)).map((r) => r.path);
  assert.equal(renamed.length, 2, renamed.join(', '));
  assert.ok(renamed.some((p) => p.startsWith('clash.conflict-')) && renamed.some((p) => p.startsWith('shared/note.conflict-')));
  assert.equal(second.rows.find((r) => r.path === 'clash').dir, true);
  for (const row of second.rows.filter((r) => !r.dir && !plain.has(r.path))) {
    assert.ok(viewer.read(row.path).equals(d3.run('cat', `:${row.path}`)), `${row.path} after the refresh`);
  }
  assert.equal(viewer.refresh().fetched, 0);
  // reset() and a full load end where the incremental refresh ended.
  viewer.vault.reset();
  const again = viewer.loadIndex();
  assert.equal(again.report.head, second.head);
  assert.deepEqual(lsRecursive(viewer.walk()), lsRecursive(second.rows));
  // The last change, when a snapshot is the newest index object — the state after every
  // compaction and every `gclone repair`. The phone wrote last; then the laptop repairs. A
  // snapshot records only when each device joined: without the snapshot's own writer and time
  // a fresh load would name the device that joined last ("fresh"), at the time it joined.
  const infoNow = () => JSON.parse(viewer.vault.info('{"at_ms":1,"ok":true,"applied":0,"note":null}'));
  assert.equal(infoNow().last_change_by, 'phone-sim');
  assert.equal(lastChangeBy(d3), 'phone-sim');
  const repairedAt = Date.now();
  d1.run('repair');
  viewer.vault.reset();
  const compacted = viewer.loadIndex();
  assert.ok(compacted.snapshot, 'based on the new snapshot');
  assert.equal(compacted.report.applied, 0, 'the snapshot covers every segment');
  assert.equal(compacted.report.head, second.head);
  const fromSnapshot = infoNow();
  assert.equal(fromSnapshot.last_change_by, 'laptop', 'the snapshot\'s writer, not the device that joined last');
  assert.ok(fromSnapshot.last_change_ms >= repairedAt - 2000 && fromSnapshot.last_change_ms <= Date.now() + 2000, `the snapshot's time: ${fromSnapshot.last_change_ms}`);
  // Every native replica agrees: the writer, one that takes the snapshot for its base, a new one.
  for (const device of [d1, d2, d3]) assert.equal(lastChangeBy(device), 'laptop', device.name);
  note(`tree: ${first.rows.length} entries (${first.files} files) with an unresolved conflict, ${second.rows.length} (${second.files} files) after a refresh — identical to gclone ls -R, ls -l and tree; heads ${first.head} and ${second.head} equal gclone status`);

  // --- gclone passwd: a new keyfile, the old one gone ------------------------------------------
  section('keyfiles');
  d1.run('passwd', '--passphrase-file', passFile(PASS2));
  const afterPasswd = new Viewer(new DirStore(vaultDir));
  const two = afterPasswd.open(afterPasswd.discover()[0]);
  assert.deepEqual(two.map((c) => c.cost.gen), [2], 'the keyfile of generation 1 is trashed');
  assert.equal((await afterPasswd.unlock(PASS)).outcome, 'wrong-passphrase');
  const reopened = await afterPasswd.unlock(PASS2);
  assert.equal(reopened.outcome, 'opened');
  // The same keys as before: the index opens and shows the same vault.
  assert.equal(afterPasswd.loadIndex().report.head, second.head);
  kdfTimings.push(...reopened.tried.filter((t) => t.ms > 20).map((t) => t.ms));

  // Two `passwd` runs that did not see each other (SPEC §2.7): two keyfiles of one generation,
  // two passphrases — each unlocks, here as in the CLI.
  concurrently(vaultDir,
    () => d1.run('passwd', '--passphrase-file', passFile(PASS3)),
    () => d2.run('passwd', '--passphrase-file', passFile(PASS4)));
  const forked = new Viewer(new DirStore(vaultDir));
  const twins = forked.open(forked.discover()[0]);
  assert.deepEqual(twins.map((c) => c.cost.gen), [3, 3]);
  // The CLI attaches a new device with either passphrase (an attach publishes the device, so
  // the head moves: the viewer, loading afterwards, must arrive at the head that device shows).
  let attached = 0;
  const attachNatively = (pass) => {
    const device = new Device(`attach-${++attached}`);
    device.login(vaultDir, pass, `attach-${attached}`);
    return device.head().head;
  };
  for (const pass of [PASS3, PASS4]) {
    const head = attachNatively(pass);
    const answer = await forked.unlock(pass);
    assert.equal(answer.outcome, 'opened', 'the passphrase of one of two concurrent passwd runs');
    kdfTimings.push(...answer.tried.filter((t) => t.ms > 20).map((t) => t.ms));
    assert.equal(forked.loadIndex().report.head, head);
  }
  assert.equal((await forked.unlock(PASS2)).outcome, 'wrong-passphrase', 'the replaced passphrase');

  // Planted keyfiles of higher generations (anyone who can write to the folder can do that):
  // one of another vault under the owner's passphrase, one under a passphrase of its own.
  const plant = (label, pass, generation) => {
    const dir = path.join(WORK, `foreign-${label}`);
    const device = new Device(`foreign-${label}`);
    device.login(dir, pass, 'foreign');
    for (let g = 2; g <= generation; g++) device.run('passwd', '--passphrase-file', passFile(pass));
    const foreign = new Viewer(new DirStore(dir));
    const top = foreign.open(foreign.discover()[0])[0];
    assert.equal(top.cost.gen, generation);
    fs.writeFileSync(path.join(vaultDir, forked.found.root, top.name), top.bytes);
    return top.name;
  };
  const sameWords = plant('same-words', PASS3, 5);
  const otherWords = plant('other-words', ATTACKER, 4);
  const planted = new Viewer(new DirStore(vaultDir));
  const four = planted.open(planted.discover()[0]);
  assert.deepEqual(four.map((c) => c.cost.gen), [5, 4, 3, 3]);
  assert.deepEqual(four.slice(0, 2).map((c) => c.name), [sameWords, otherWords]);
  {
    const unlocker = new Unlocker(four.map(({ name, bytes }) => ({ name, bytes })));
    // A wrong passphrase is reported as wrong, and costs one derivation per candidate.
    let answer = await planted.unlock('wrong, whatever is planted', unlocker);
    assert.equal(answer.outcome, 'wrong-passphrase');
    assert.deepEqual(answer.tried.map((t) => t.outcome), ['wrong-passphrase', 'wrong-passphrase', 'wrong-passphrase', 'wrong-passphrase']);
    // The planted keyfile's own passphrase opens it — and it is not this vault's: dropped.
    answer = await planted.unlock(ATTACKER, unlocker);
    assert.equal(answer.outcome, 'wrong-passphrase');
    assert.equal(answer.tried.find((t) => t.name === otherWords).outcome, 'other-vault');
    assert.ok(!answer.left.includes(otherWords), 'a keyfile of another vault is not tried again');
    // The owner's passphrase: the planted keyfile of the same words is another vault's; the
    // real one, two generations below, still opens.
    answer = await planted.unlock(PASS3, unlocker);
    assert.equal(answer.outcome, 'opened');
    assert.equal(answer.tried[0].outcome, 'other-vault');
    assert.equal(answer.tried.at(-1).outcome, 'opened');
    assert.ok(!answer.tried.some((t) => t.name === otherWords), 'dropped candidates cost nothing more');
    planted.loadIndex();
    answer = await planted.unlock(PASS4, unlocker);
    assert.equal(answer.outcome, 'opened', 'and so does the other real one');
    kdfTimings.push(...unlocker.timings);
    await unlocker.close();
    planted.loadIndex();
    // The CLI, with the same folder: both real passphrases attach, the planted one does not.
    for (const pass of [PASS3, PASS4]) {
      const head = attachNatively(pass);
      assert.equal(planted.refresh().report.head, head);
    }
    const intruder = new Device('planted-wrong').try('login', '--vault-dir', vaultDir, '--passphrase-file', passFile(ATTACKER));
    assert.notEqual(intruder.code, 0);
    assert.equal(planted.refresh().fetched, 0, 'a refused login published nothing');
  }
  // Junk under a keyfile's name, and a keyfile format of the future: no cost is shown for
  // either, and neither is ever "wrong passphrase".
  {
    const real = four[2];
    const junk = { name: 'gclone-key-00000009-00000000', bytes: Buffer.from('junk') };
    assert.equal(thrown(() => core.keyfile_cost(junk.name, junk.bytes)), 'damaged');
    const unlocker = new Unlocker([junk, { name: real.name, bytes: real.bytes }]);
    const answer = await unlocker.attempt('wrong again', planted.found.descriptor.vault_id);
    assert.deepEqual([answer.outcome, answer.tried.map((t) => t.outcome), answer.left], ['wrong-passphrase', ['damaged', 'wrong-passphrase'], [real.name]]);
    await unlocker.close();
    const only = new Unlocker([junk]);
    assert.equal((await only.attempt(PASS3, planted.found.descriptor.vault_id)).outcome, 'no-usable-keyfile');
    await only.close();
  }
  note('keyfiles: after passwd the old passphrase is wrong and the new one opens; two concurrent passwd runs: both passphrases open (wasm and CLI); planted keyfiles of generations 5 and 4 lock nobody out; a foreign keyfile is skipped as other-vault; junk is damage');
}

// ---------------------------------------------------------------------------------------------
try {
  if (EXPORT) await replayNative();
  else console.log('\n(GCLONE_WEB_CORE_EXPORT is not set: the native rules are not replayed)');
  if (BIN) await nativeVaults();
  else console.log('\n(GCLONE_BIN is not set: no vault of the native binary is read)');
  assert.ok(EXPORT || BIN, 'nothing was tested: set GCLONE_WEB_CORE_EXPORT and GCLONE_BIN (test/run.sh does)');

  section('summary');
  if (kdfTimings.length) {
    const sorted = [...kdfTimings].sort((a, b) => a - b);
    note(`Argon2id (256 MiB, t=3, p=1) under Node ${process.version}: ${sorted.length} derivations, median ${sorted[sorted.length >> 1].toFixed(0)} ms (min ${sorted[0].toFixed(0)}, max ${sorted.at(-1).toFixed(0)})`);
  }
  note(`wasm memory of this thread at the end: ${mib(wasmBytes())} (the vault's KDF ran in workers only)`);
  console.log('\nOK');
} finally {
  if (!keepWork) fs.rmSync(WORK, { recursive: true, force: true });
}
