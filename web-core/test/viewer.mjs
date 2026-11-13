// What the hosted viewer's JavaScript does around the core (design §6), over a `DirStore`:
// discover the vault, pick the keyfiles, unlock in a worker that is thrown away, load the
// index, list, and read files through tickets. The browser app does the same against Drive;
// this is the reference the tests drive, and it holds no gclone logic of its own — every
// decision (which keyfiles, which snapshots, which segments, which bytes) is the core's.
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { loadCore, codeOf } from './core.mjs';

const SMALL_MAX = 64 * 1024;
const utf8 = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** One unlock screen: a KDF worker that lives until `close()`. */
export class Unlocker {
  constructor(candidates) {
    this.worker = new Worker(new URL('./kdf-worker.mjs', import.meta.url), { workerData: { candidates } });
    this.ready = new Promise((resolve, reject) => {
      this.worker.once('message', resolve);
      this.worker.once('error', reject);
    });
    /** Milliseconds of every derivation this worker ran. */
    this.timings = [];
    this.attempts = 0;
  }

  /** `{ outcome, bundle, tried, left, wasmBytes }` — see kdf-worker.mjs. */
  async attempt(passphrase, vaultId) {
    await this.ready;
    this.attempts++;
    const answer = await new Promise((resolve, reject) => {
      this.worker.once('message', resolve);
      this.worker.once('error', reject);
      this.worker.postMessage({ passphrase, vaultId });
    });
    // A candidate that is refused before the key derivation (damage, a newer version) costs
    // nothing; the others cost one Argon2id each.
    for (const t of answer.tried) if (t.ms > 20) this.timings.push(t.ms);
    return answer;
  }

  async close() {
    await this.worker.terminate();
  }
}

export class Viewer {
  constructor(store) {
    this.store = store;
    this.core = loadCore().core;
    this.vault = null;
  }

  /** Step 1: every `gclone-vault.json` the store shows, with what the core says about it. */
  discover() {
    return this.store.findByName('gclone-vault.json').map((hit) => {
      const bytes = this.store.get(hit.id, 0, SMALL_MAX + 1);
      const root = hit.rel.slice(0, -'/gclone-vault.json'.length);
      try {
        return { root, descriptor: JSON.parse(this.core.parse_descriptor(bytes)) };
      } catch (error) {
        return { root, error: codeOf(error) };
      }
    });
  }

  /** Steps 2 and 3: the root's folders and the keyfile candidates, each with its cost. */
  open(found) {
    this.found = found;
    const children = this.store.list(found.root);
    const folder = (name) => {
      const hits = children.filter((c) => c.isFolder && c.name === name);
      assert.equal(hits.length, 1, `exactly one ${name} folder`);
      return hits[0];
    };
    this.index = folder('index');
    this.data = folder('data');
    const files = children.filter((c) => !c.isFolder);
    const names = JSON.parse(this.core.keyfile_candidates(JSON.stringify(files.map((c) => c.name))));
    this.candidates = names.map((name) => {
      const object = files.find((c) => c.name === name);
      const bytes = this.store.get(object.id, 0, SMALL_MAX + 1);
      let cost = null;
      let refused = null;
      try { cost = JSON.parse(this.core.keyfile_cost(name, bytes)); } catch (error) { refused = codeOf(error); }
      return { name, bytes, cost, refused };
    });
    return this.candidates;
  }

  /** Step 4, then `Vault.from_keys`. Returns the worker's answer; `this.vault` on success. */
  async unlock(passphrase, unlocker) {
    const own = !unlocker;
    unlocker ??= new Unlocker(this.candidates.map(({ name, bytes }) => ({ name, bytes })));
    try {
      const answer = await unlocker.attempt(passphrase, this.found.descriptor.vault_id);
      if (answer.outcome === 'opened') {
        /** Kept by the tests that open a second `Vault`; the app keeps no copy. */
        this.bundleForTests = answer.bundle.slice();
        this.vault = this.core.Vault.from_keys(answer.bundle);
        // The call wiped the caller's copy.
        assert.ok(answer.bundle.every((b) => b === 0), 'from_keys zero-fills the bundle');
        assert.equal(this.vault.vault_id(), this.found.descriptor.vault_id);
      }
      return answer;
    } finally {
      if (own) await unlocker.close();
    }
  }

  /** Another `Vault` with the same keys (for the tests that load damaged objects). */
  secondVault() {
    return this.core.Vault.from_keys(this.bundleForTests.slice());
  }

  listing() {
    return this.store.list(this.index.rel).filter((o) => !o.isFolder);
  }

  /** Step 5. `tamper(name, bytes)` may replace an object's bytes, and `hide` holds names the
   *  listing does not show (a listing that lags behind) — both for the tests. Returns
   *  `{ report, fetched, bytes, snapshot, snapshotsTried, byId }`. */
  loadIndex(vault = this.vault, tamper = (name, bytes) => bytes, hide = new Set()) {
    const listing = this.listing().filter((o) => !hide.has(o.name));
    const byName = new Map(listing.map((o) => [o.name, o]));
    const names = JSON.stringify(listing.map((o) => o.name));
    const stats = { fetched: 0, bytes: 0, snapshot: null, snapshotsTried: [], byId: 0 };
    const get = (name) => {
      const bytes = tamper(name, this.store.get(byName.get(name).id));
      stats.fetched++;
      stats.bytes += bytes.length;
      return bytes;
    };
    const snapshots = JSON.parse(vault.snapshot_candidates(names));
    for (const name of snapshots) {
      stats.snapshotsTried.push(name);
      if (vault.load_snapshot(name, get(name))) {
        stats.snapshot = name;
        break;
      }
    }
    if (snapshots.length && !stats.snapshot) {
      throw new Error(`No snapshot of this vault's index could be read: ${snapshots.join(', ')}`);
    }
    for (const name of JSON.parse(vault.needed_segments(names))) {
      vault.add_segment(name, get(name), byName.get(name).createdMs);
    }
    let report = JSON.parse(vault.finish());
    // References the listing did not satisfy: fetch by the id they carry, at most three rounds.
    for (let round = 0; round < 3 && report.missing.some((m) => m[3] !== ''); round++) {
      let added = 0;
      for (const [, , , fileId] of report.missing) {
        if (fileId === '') continue;
        const object = this.store.stat?.(fileId);
        if (!object) continue;
        vault.add_segment(object.name, this.store.get(fileId), object.createdMs);
        added++;
        stats.byId++;
      }
      if (!added) break;
      report = JSON.parse(vault.finish());
    }
    return { report, ...stats };
  }

  /** Step 6: list again, fetch what is new, apply. */
  refresh(vault = this.vault) {
    const listing = this.listing();
    const byName = new Map(listing.map((o) => [o.name, o]));
    const needed = JSON.parse(vault.needed_segments(JSON.stringify(listing.map((o) => o.name))));
    for (const name of needed) {
      vault.add_segment(name, this.store.get(byName.get(name).id), byName.get(name).createdMs);
    }
    return { report: JSON.parse(vault.finish()), fetched: needed.length };
  }

  /** Every entry of the tree: `{ path, dir, kind, size, mtime_ms, empty }`, parents first.
   *  Lists each directory in pages of `page` entries, to exercise the paging. */
  walk(vault = this.vault, page = 7) {
    const out = [];
    const visit = (dir) => {
      const entries = [];
      for (let offset = 0; ; offset += page) {
        const answer = JSON.parse(vault.list(dir, 'name', 'asc', offset, page));
        assert.equal(answer.offset, offset);
        entries.push(...answer.entries);
        if (entries.length >= answer.total) {
          assert.equal(entries.length, answer.total, `${dir}: pages add up`);
          break;
        }
      }
      // One page with everything is the same list.
      assert.deepEqual(JSON.parse(vault.list(dir)).entries, entries, `${dir}: paged = whole`);
      for (const entry of entries) {
        const path = dir ? `${dir}/${entry.name}` : entry.name;
        const row = { path, name: entry.name, dir: entry.dir, kind: entry.kind, size: entry.size, mtime_ms: entry.mtime_ms };
        out.push(row);
        if (entry.dir) row.empty = visit(path) === 0;
      }
      return entries.length;
    };
    visit('');
    return out;
  }

  /** Where a ticket's blob is: by the id the index recorded, else by its name (§3.2). */
  blobId(ticket, by = 'id') {
    if (by === 'id' && this.store.resolve(ticket.file_id) !== null) return ticket.file_id;
    const hits = this.store.findByName(ticket.blob_name).filter((o) => !o.isFolder);
    if (hits.length !== 1) throw new Error(`blob ${ticket.blob_name} is missing`);
    return hits[0].id;
  }

  /** Plaintext `[start, end)` of a file, as the Service Worker produces it: a ticket, one
   *  ranged request for exactly the chunks needed, pieces of `piece` bytes pushed through a
   *  `FileReader`. */
  read(path, { start = 0, end = Number.MAX_SAFE_INTEGER, piece = 1 << 20, by = 'id', vault = this.vault } = {}) {
    const ticketJson = vault.ticket(path);
    const ticket = JSON.parse(ticketJson);
    const reader = new this.core.FileReader(ticketJson, start, Math.min(end, Number.MAX_SAFE_INTEGER));
    try {
      const [from, to] = [reader.cipher_start(), reader.cipher_end()];
      const owed = reader.remaining();
      assert.equal(owed, Math.max(0, Math.min(end, ticket.size) - start));
      const out = [];
      if (from < to) {
        const id = this.blobId(ticket, by);
        for (let pos = from; pos < to;) {
          const bytes = this.store.get(id, pos, Math.min(to, pos + piece));
          assert.ok(bytes.length > 0, 'the store answers the range');
          out.push(reader.push(bytes));
          pos += bytes.length;
        }
      }
      assert.equal(reader.remaining(), 0, `${path}: complete`);
      const plain = Buffer.concat(out);
      assert.equal(plain.length, owed);
      return plain;
    } finally {
      reader.free();
    }
  }
}

// --- how the CLI prints a tree (cli/ls.rs), from what the viewer's API answers -----------------

/** `gclone ls -R :`: every file, and every directory that has an entry of its own (the empty
 *  ones), by path. */
export function lsRecursive(rows) {
  return rows.filter((r) => !r.dir || r.empty).map((r) => (r.dir ? `${r.path}/` : r.path)).sort(utf8);
}

/** `util::human_size`. */
export function humanSize(n) {
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
  if (n < 1024) return `${n} B`;
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  let r = Math.round(v * 10) / 10;
  if (r >= 1024 && u < units.length - 1) { r = 1; u++; }
  return Number.isInteger(r) ? `${r} ${units[u]}` : `${r.toFixed(1)} ${units[u]}`;
}

/** `gclone ls -l :<dir>` with `TZ=UTC`: the direct children, by name. */
export function lsLong(rows, dir) {
  const prefix = dir ? `${dir}/` : '';
  return rows
    .filter((r) => r.path.startsWith(prefix) && !r.path.slice(prefix.length).includes('/'))
    .sort((a, b) => utf8(a.name, b.name))
    .map((r) => {
      const size = r.dir ? '-' : humanSize(r.size);
      const time = r.dir ? '' : new Date(Math.max(0, r.mtime_ms)).toISOString().slice(0, 16).replace('T', ' ');
      return `${size.padStart(11)}  ${time.padEnd(16)}  ${r.name}${r.dir ? '/' : ''}`;
    });
}

/** `gclone tree`: the drawing and the counts. */
export function tree(rows) {
  const root = { children: new Map() };
  for (const row of rows) {
    let node = root;
    for (const part of row.path.split('/')) {
      if (!node.children.has(part)) node.children.set(part, { children: new Map(), dir: false });
      node = node.children.get(part);
    }
    node.dir ||= row.dir;
  }
  const lines = [':'];
  const counts = { dirs: 0, files: 0 };
  const draw = (node, indent) => {
    const names = [...node.children.keys()].sort(utf8);
    names.forEach((name, i) => {
      const child = node.children.get(name);
      const last = i === names.length - 1;
      lines.push(`${indent}${last ? '└── ' : '├── '}${name}`);
      if (child.dir || child.children.size) {
        counts.dirs++;
        draw(child, `${indent}${last ? '    ' : '│   '}`);
      } else {
        counts.files++;
      }
    });
  };
  draw(root, '');
  const group = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const plural = (n, one, many) => `${group(n)} ${n === 1 ? one : many}`;
  lines.push('', `${plural(counts.dirs, 'directory', 'directories')}, ${plural(counts.files, 'file', 'files')}`);
  return lines;
}
