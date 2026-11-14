// The fixture of the hosted viewer's tests: a directory vault written by the NATIVE `gclone`
// binary of this tree (`gclone login --vault-dir`, `copy`, …), holding files of every kind
// the viewer treats differently. Nothing here uses a real vault, a login or the network:
// a device is a pair of temporary directories (GCLONE_CONFIG_DIR / GCLONE_STATE_DIR).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.join(HERE, 'fixtures');
export const PASS = 'correct horse battery staple';

/** Deterministic bytes without a dependency: a xorshift stream. */
export function pattern(seed, len) {
  const out = Buffer.alloc(len);
  let x = (seed * 2654435761 + 1) >>> 0 || 1;
  for (let i = 0; i < len; i += 1) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

/** A PNG of `width` x `height`: a colour gradient, written with zlib and nothing else. */
export function png(width, height) {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (buf) => {
    let c = 0xffffffff;
    for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const head = Buffer.alloc(8);
    head.writeUInt32BE(data.length, 0);
    head.write(type, 4, 'latin1');
    const tail = Buffer.alloc(4);
    tail.writeUInt32BE(crc(Buffer.concat([head.subarray(4), data])), 0);
    return Buffer.concat([head, data, tail]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, 2, 0, 0, 0], 8); // 8 bits, RGB
  const raw = Buffer.alloc((width * 3 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const row = y * (width * 3 + 1);
    for (let x = 0; x < width; x += 1) {
      const at = row + 1 + x * 3;
      raw[at] = Math.round((x / width) * 255);
      raw[at + 1] = Math.round((y / height) * 255);
      raw[at + 2] = (Math.floor(x / 16) + Math.floor(y / 16)) % 2 ? 200 : 90;
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** A one-page PDF that says `text`, with a correct cross-reference table. */
export function pdf(text) {
  const stream = `BT /F1 24 Tf 72 720 Td (${text.replace(/[()\\]/g, '\\$&')}) Tj ET`;
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) out += `${String(offset).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

// A page and a drawing that would act if a browser ran them in the viewer's origin: each
// tries to leave a mark where the test looks (the opener or parent window, the title,
// storage, a request to the origin).
const MARK = "try{top.__ran=(top.__ran||0)+1}catch(e){};try{parent.postMessage('gclone-script-ran','*')}catch(e){};try{opener&&opener.postMessage('gclone-script-ran','*')}catch(e){};try{localStorage.setItem('gclone.ran','1')}catch(e){};try{fetch('/web/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})}catch(e){};try{new Image().src='/script-ran'}catch(e){}";
export const HOSTILE_HTML = `<!doctype html>\n<html><head><title>hostile</title>\n<script>${MARK}</script>\n</head><body onload="${MARK.replace(/"/g, '&quot;')}">\n<h1>This is markup, shown as text</h1>\n<img src="x" onerror="${MARK.replace(/"/g, '&quot;')}">\n</body></html>\n`;
// (Well-formed XML: an engine that would run it must be able to parse it.)
const xmlAttribute = (text) => text.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
export const HOSTILE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80" viewBox="0 0 120 80" onload="${xmlAttribute(MARK)}">\n<rect width="120" height="80" fill="#c23b2e"/>\n<circle cx="60" cy="40" r="24" fill="#fff"/>\n<script><![CDATA[${MARK}]]></script>\n</svg>\n`;
const PLAIN_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="80" viewBox="0 0 120 80">\n<rect width="120" height="80" fill="#1a5fd0"/>\n<path d="M20 60 L60 20 L100 60 Z" fill="#fff"/>\n</svg>\n';

/** Names that an address, a header or markup could trip over. */
export const ODD_NAMES = [
  '#hash ?question %percent.txt',
  'it\'s "quoted" & <tagged>.txt',
  'percent%20encoded%2Fslash.txt',
  'ünïcödé — 日本語 🙂.txt',
  'semi;colon,comma=equals+plus.txt',
  ' leading and trailing spaces .txt',
];

/** A name that reads as another: U+202E turns the rest around, so that it is drawn "invoiceexe.pdf". */
export const BIDI_NAME = 'invoice\u202efdp.exe';
export const BIDI_DIR = 'deep/a';

/** Writes the fixture's files below `dir`; returns `Map(path in the vault → Buffer)`. `big`: an optional large video file. */
export function makeSource(dir, { big, many = 250 } = {}) {
  const files = new Map();
  const put = (rel, content) => {
    const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
    files.set(rel, bytes);
    const file = path.join(dir, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
  };
  put('docs/notes.txt', 'These are the notes.\nSecond line, with an umlaut: Grüße.\n');
  put('docs/long.txt', Array.from({ length: 16000 }, (_, i) => `line ${String(i).padStart(5, '0')} of a long text file that is cut in the preview`).join('\n'));
  put('docs/page.html', HOSTILE_HTML);
  put('docs/empty.txt', '');
  put('docs/report.pdf', pdf('gclone fixture, page one'));
  put('pics/photo.png', png(480, 320));
  put('pics/drawing.svg', PLAIN_SVG);
  put('pics/scripted.svg', HOSTILE_SVG);
  put('media/tone.mp3', fs.readFileSync(path.join(FIXTURES, 'tone.mp3')));
  put('media/clip-faststart.mp4', fs.readFileSync(path.join(FIXTURES, 'clip-faststart.mp4')));
  put('media/clip-moov-at-end.mp4', fs.readFileSync(path.join(FIXTURES, 'clip-moov-at-end.mp4')));
  if (big) put('media/big.mp4', fs.readFileSync(big));
  put('bin/pattern-3m.bin', pattern(7, 3 * 1024 * 1024 + 4321));
  put('bin/archive.zip', pattern(8, 70000));
  put('bin/empty.dat', '');
  for (const [i, name] of ODD_NAMES.entries()) put(`names/${name}`, `file ${i}: ${name}\n`);
  put('deep/a/b/c/d/leaf.txt', 'at the bottom\n');
  put(`${BIDI_DIR}/${BIDI_NAME}`, 'not a PDF\n');
  for (let i = 1; i <= many; i += 1) put(`many/file-${i}.txt`, `number ${i}\n`.repeat(i % 7 + 1));
  put('README.md', '# The fixture vault\n');
  return files;
}

/** One device: a config and a state directory of its own, and the native binary. */
export class Device {
  constructor(bin, work, name) {
    this.bin = bin;
    this.name = name;
    this.work = work;
    this.env = {
      PATH: process.env.PATH,
      HOME: path.join(work, 'home'),
      TZ: 'UTC',
      GCLONE_CONFIG_DIR: path.join(work, `${name}-config`),
      GCLONE_STATE_DIR: path.join(work, `${name}-state`),
    };
    fs.mkdirSync(this.env.HOME, { recursive: true });
  }

  /** Runs the native binary; never inherits a login, an auth Worker or the switch for live tests. */
  try(...args) {
    const out = spawnSync(this.bin, args, { env: this.env, encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
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
    return this.text(...args).split('\n').filter((line, i, all) => i < all.length - 1 || line !== '');
  }

  login(vaultDir, pass = PASS) {
    const file = path.join(this.work, `${this.name}-passphrase`);
    fs.writeFileSync(file, `${pass}\n`, { mode: 0o600 });
    return this.text('login', '--vault-dir', vaultDir, '--passphrase-file', file, '--device-name', this.name);
  }

  head() {
    const match = /^Head\s+(\S+) \(([\d,]+) files\)/m.exec(this.text('status'));
    assert.ok(match, 'status prints the head');
    return match[1];
  }
}

/**
 * A well-formed keyfile of ANOTHER vault, under another passphrase — what someone with the
 * Drive account can put into a vault's folder. Returns `{ bytes, h8, name(generation) }`:
 * `name(g)` is the name such a file has to carry (the generation is free; the hash part is
 * the content's).
 */
export function foreignKeyfile(work, pass = 'the passphrase of somebody else') {
  const dir = path.join(work, `foreign-${fs.readdirSync(work).length}`);
  const store = path.join(dir, 'store');
  fs.mkdirSync(store, { recursive: true });
  new Device(nativeBinary(), dir, 'stranger').login(store, pass);
  const listed = fs.readdirSync(path.join(store, 'gclone')).find((n) => n.startsWith('gclone-key-'));
  const h8 = listed.split('-')[3];
  return {
    bytes: fs.readFileSync(path.join(store, 'gclone', listed)),
    h8,
    name: (generation) => `gclone-key-${generation.toString(16).padStart(8, '0')}-${h8}`,
  };
}

/** The native binary of this tree: GCLONE_BIN, else target/release, else target/debug. */
export function nativeBinary() {
  const repo = path.resolve(HERE, '..', '..', '..');
  const candidates = [process.env.GCLONE_BIN, path.join(repo, 'target/release/gclone'), path.join(repo, 'target/debug/gclone')].filter(Boolean);
  const bin = candidates.find((candidate) => fs.existsSync(candidate));
  if (!bin) throw new Error('no native gclone binary: cargo build --release --locked, or set GCLONE_BIN');
  return bin;
}

/**
 * A vault in `work/store` with the fixture's files, written by one device.
 * Returns `{ vaultDir, device, files, src }`.
 */
export function buildVault(work, options = {}) {
  const bin = nativeBinary();
  const vaultDir = path.join(work, 'store');
  const src = path.join(work, 'src');
  fs.mkdirSync(vaultDir, { recursive: true });
  const files = makeSource(src, options);
  const device = new Device(bin, work, 'laptop');
  device.login(vaultDir);
  // A part first, then a snapshot (`repair` writes one), then the rest: the index the viewer
  // loads is a snapshot and the segments after it.
  device.run('copy', path.join(src, 'docs'), ':docs');
  device.run('repair');
  device.run('copy', src, ':');
  return { vaultDir, device, files, src, bin };
}

/** Waits, without a timer: the runs of gclone that make history must be at different times. */
function pause(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * History for the time machine, on a vault of `buildVault`: runs of the native binary more
 * than a second apart — two more versions of `docs/notes.txt` (and one of a file with an odd
 * name), a deleted file, a deleted folder, a moved file, a new folder and a late upload.
 * `vault.files` follows. Returns what the viewer has to show:
 *
 *   stages    [{ label, tree, files }]: `gclone tree` and the files after each run, oldest first
 *   notes     the versions of `docs/notes.txt`, oldest first (Buffers)
 *   odd       the path of the file with the odd name that has two versions, and both
 */
export function addHistory(vault, gapMs = 1100) {
  const { device, src, files } = vault;
  const put = (rel, content) => {
    const bytes = Buffer.from(content);
    files.set(rel, bytes);
    fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
    fs.writeFileSync(path.join(src, rel), bytes);
    return bytes;
  };
  const drop = (rel) => {
    for (const name of [...files.keys()]) if (name === rel || name.startsWith(`${rel}/`)) files.delete(name);
    fs.rmSync(path.join(src, rel), { recursive: true, force: true });
  };
  const stages = [];
  const stage = (label) => stages.push({ label, tree: device.lines('tree'), files: new Map(files) });
  const odd = `names/${ODD_NAMES[1]}`;
  const notes = [files.get('docs/notes.txt')];
  const odds = [files.get(odd)];
  stage('as built');

  pause(gapMs);
  notes.push(put('docs/notes.txt', 'These are the notes, in their second version.\nThe umlaut stayed: Grüße.\n'));
  device.run('copy', src, ':');
  stage('the notes changed');

  pause(gapMs);
  notes.push(put('docs/notes.txt', 'The notes as they are now: the third version.\n'));
  odds.push(put(odd, 'the odd name, written again\n'));
  device.run('copy', src, ':');
  stage('the notes and an odd name changed');

  pause(gapMs);
  device.run('rm', ':docs/long.txt');
  drop('docs/long.txt');
  device.run('rm', '-r', ':deep');
  drop('deep');
  stage('a file and a folder deleted');

  pause(gapMs);
  device.run('mv', ':README.md', ':docs/README.md');
  const readme = files.get('README.md');
  drop('README.md');
  put('docs/README.md', readme);
  stage('a file moved');

  pause(gapMs);
  device.run('mkdir', ':plans');
  put('plans/2027.txt', 'next year\n');
  device.run('copy', src, ':');
  stage('a late upload');
  return { stages, notes, odd: { path: odd, versions: odds } };
}

/** `gclone tree`: the drawing and the counts, from `[{ path, dir }]` (as the CLI draws it). */
export function tree(rows) {
  const utf8 = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
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
        counts.dirs += 1;
        draw(child, `${indent}${last ? '    ' : '│   '}`);
      } else {
        counts.files += 1;
      }
    });
  };
  draw(root, '');
  const group = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const plural = (n, one, many) => `${group(n)} ${n === 1 ? one : many}`;
  lines.push('', `${plural(counts.dirs, 'directory', 'directories')}, ${plural(counts.files, 'file', 'files')}`);
  return lines;
}
