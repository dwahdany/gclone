// A directory vault (`gclone login --vault-dir`) seen the way the hosted viewer sees Google
// Drive: folders are listed, objects are fetched whole or by byte range, by id — or, when the
// id is unknown, found by name (SPEC §3.2). No gclone code in here.
import fs from 'node:fs';
import path from 'node:path';

export class DirStore {
  constructor(dir) {
    this.dir = dir;
    this.gets = 0;
    this.lists = 0;
    this.bytes = 0;
    /** Ranged requests, for the tests that count them: `[id, start, end]`. */
    this.ranges = [];
  }

  /** id → relative path, from the directory backend's journal (ids of objects that were
   *  copied in from elsewhere are not in it: they are found by name). */
  ids() {
    const map = new Map();
    let text = '';
    try { text = fs.readFileSync(path.join(this.dir, '.gclone-dir-ids.json'), 'utf8'); } catch { return map; }
    const under = (p, root) => p === root || p.startsWith(`${root}/`);
    for (const line of text.split('\n').filter(Boolean)) {
      const rec = JSON.parse(line);
      if (rec.op === 'bind') map.set(rec.id, rec.path);
      else if (rec.op === 'move') {
        for (const [id, p] of map) if (under(p, rec.from)) map.set(id, rec.to + p.slice(rec.from.length));
      } else if (rec.op === 'drop') {
        for (const [id, p] of map) if (under(p, rec.path)) map.delete(id);
      }
    }
    return map;
  }

  meta(rel) {
    const st = fs.statSync(path.join(this.dir, rel));
    const map = this.ids();
    const id = [...map].find(([, p]) => p === rel)?.[0] ?? `p:${rel}`;
    return {
      id, rel, name: path.basename(rel), isFolder: st.isDirectory(), size: st.isDirectory() ? 0 : st.size,
      // The directory backend's creation time of an object is its mtime, in milliseconds.
      createdMs: Math.floor(st.mtimeMs),
    };
  }

  /** Every object called `name` (`files.list` with `name = '…'`), anywhere in the store. */
  findByName(name) {
    this.lists++;
    const found = [];
    const walk = (rel) => {
      for (const entry of fs.readdirSync(path.join(this.dir, rel), { withFileTypes: true })) {
        if (entry.name.startsWith('.')) continue;
        const child = rel ? `${rel}/${entry.name}` : entry.name;
        if (entry.name === name) found.push(this.meta(child));
        if (entry.isDirectory()) walk(child);
      }
    };
    walk('');
    return found;
  }

  /** The children of a folder (by its relative path), in directory order. */
  list(rel) {
    this.lists++;
    return fs.readdirSync(path.join(this.dir, rel), { withFileTypes: true })
      .filter((entry) => !entry.name.startsWith('.') && (entry.isFile() || entry.isDirectory()))
      .map((entry) => this.meta(rel ? `${rel}/${entry.name}` : entry.name));
  }

  /** `null`: no object has this id (Drive's 404). */
  resolve(id) {
    const rel = id.startsWith('p:') ? id.slice(2) : this.ids().get(id);
    if (!rel || rel.startsWith('.trash/') || !fs.existsSync(path.join(this.dir, rel))) return null;
    return rel;
  }

  /** Name and creation time of the object with this id (`files.get`); `null` if unknown. */
  stat(id) {
    const rel = this.resolve(id);
    return rel === null ? null : this.meta(rel);
  }

  /** The object's bytes `[start, end)`; `null` for an unknown id. */
  get(id, start, end) {
    const rel = this.resolve(id);
    if (rel === null) return null;
    this.gets++;
    const fd = fs.openSync(path.join(this.dir, rel), 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const from = Math.min(start ?? 0, size);
      const to = Math.min(end ?? size, size);
      const buf = Buffer.alloc(to - from);
      fs.readSync(fd, buf, 0, buf.length, from);
      this.bytes += buf.length;
      if (start !== undefined) this.ranges.push([id, from, to]);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
    } finally {
      fs.closeSync(fd);
    }
  }
}
