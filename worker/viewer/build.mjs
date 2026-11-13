// Builds the hosted viewer's bundle: `worker/dist/`, the directory wrangler uploads as the
// Worker's static assets.
//
//   node worker/viewer/build.mjs [--out <dir>] [--pkg <dir>]
//
// Inputs: the shared page of `gclone web` (src/web/assets/{app.js,app.css,icon.svg} verbatim,
// and the markup between <body> and </body> of its index.html, which becomes the hosted
// page's <template id="app">), the hosted-only sources next to this file, and the built core
// (web-core/pkg/{core.js,core.wasm,build.json}, from web-core/build.sh).
//
// Output:
//   index.html            the page; the Worker serves it for `/` and `/callback`
//   sw.js                 the Service Worker, with the build id stamped in
//   _headers              the header set of worker/src/headers.json for `/a/*` and `/sw.js`
//   a/<build>/…           every other file, verbatim, and manifest.json
//
// The build id is the first 16 hex digits of a SHA-256 over every input, so a loaded page
// never mixes the files of two builds. Deterministic: no time stamps, sorted keys, `\n`.
// Plain Node, no dependency, no network.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { headersFile } from '../scripts/headers-file.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');

/** Files of the build directory, by where they come from. Order does not matter. */
export const SHARED = ['app.js', 'app.css', 'icon.svg']; // src/web/assets/, byte for byte
export const HOSTED = ['token.js', 'provider.js', 'shell.js', 'drive.js', 'loader.js', 'seal.js', 'vault-worker.js', 'kdf-worker.js', 'shell.css', 'noscript.css'];
export const CORE = ['core.js', 'core.wasm']; // web-core/pkg/

export const BUILD_MARK = '__GCLONE_BUILD__';
export const APP_MARK = '<!--gclone-app-->';
export const STATUS_MARK = '<!--gclone-status-->';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function fail(message) {
  throw new Error(`build.mjs: ${message}`);
}

/** The markup the two viewers share: what is between <body> and </body> of the local page. */
export function sharedBody(html) {
  const open = html.indexOf('<body>');
  const close = html.lastIndexOf('</body>');
  if (open < 0 || close < open) fail('src/web/assets/index.html has no <body>…</body>');
  const body = html.slice(open + '<body>'.length, close);
  const lower = body.toLowerCase();
  // The hosted page's policy allows no inline script, style or handler; the shared markup has none.
  if (lower.includes('<script')) fail('the shared body contains a <script element');
  if (lower.includes('<style') || /\sstyle\s*=/.test(lower)) fail('the shared body contains inline style');
  if (/\son[a-z]+\s*=/.test(lower)) fail('the shared body contains an inline event handler');
  if (lower.includes('javascript:')) fail('the shared body contains a javascript: address');
  if (lower.includes('<template') || body.includes(APP_MARK) || body.includes(STATUS_MARK)) fail('the shared body contains a template or a marker of the hosted page');
  return body;
}

function gitInfo() {
  const git = (...args) => execFileSync('git', ['-C', REPO, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  try {
    const commit = git('rev-parse', 'HEAD');
    return git('status', '--porcelain') ? `${commit}+changes` : commit;
  } catch {
    return '';
  }
}

/**
 * Builds into `out` and returns `{ build, files }`. `out` must be absent, empty, or hold
 * nothing but an earlier bundle (or the placeholder of scripts/stub-dist.mjs).
 */
export function build({ out = join(REPO, 'worker', 'dist'), pkg = join(REPO, 'web-core', 'pkg'), commit, tag } = {}) {
  const assets = join(REPO, 'src', 'web', 'assets');
  const files = new Map();
  const take = (name, dir) => {
    const file = join(dir, name);
    if (!existsSync(file)) fail(`${file} is missing${dir === pkg ? ' (run web-core/build.sh first)' : ''}`);
    files.set(name, readFileSync(file));
  };
  for (const name of SHARED) take(name, assets);
  for (const name of HOSTED) take(name, HERE);
  for (const name of CORE) take(name, pkg);
  const core = JSON.parse(readFileSync(join(pkg, 'build.json'), 'utf8'));

  // The two files outside the build directory, before the build id is known.
  const template = readFileSync(join(HERE, 'index.html'), 'utf8');
  const count = (text, part) => text.split(part).length - 1;
  if (count(template, APP_MARK) !== 1) fail(`viewer/index.html must hold ${APP_MARK} exactly once`);
  if (count(template, STATUS_MARK) !== 1) fail(`viewer/index.html must hold ${STATUS_MARK} exactly once`);
  const page = template.replace(APP_MARK, () => sharedBody(readFileSync(join(assets, 'index.html'), 'utf8')));
  const worker = readFileSync(join(HERE, 'sw.js'), 'utf8');
  if (count(worker, BUILD_MARK) !== 1) fail(`viewer/sw.js must hold ${BUILD_MARK} exactly once`);
  const headers = headersFile();

  // The build id: every input, by name and content.
  const inputs = [...files].map(([name, bytes]) => [name, sha256(bytes)]);
  inputs.push(['/index.html', sha256(page)], ['/sw.js', sha256(worker)], ['/_headers', sha256(headers)]);
  inputs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const id = sha256(inputs.map(([name, hash]) => `${name}\0${hash}\n`).join('')).slice(0, 16);

  const manifest = {
    build: id,
    commit: commit ?? process.env.GCLONE_VIEWER_COMMIT ?? gitInfo(),
    files: Object.fromEntries([...files].map(([name, bytes]) => [name, sha256(bytes)]).sort(([a], [b]) => (a < b ? -1 : 1))),
    rustc: String(core.rustc ?? ''),
    tag: tag ?? process.env.GCLONE_VIEWER_TAG ?? '',
    version: String(core.version ?? ''),
    wasm_bindgen: String(core.wasm_bindgen ?? ''),
  };

  // Only what a bundle consists of is ever removed.
  if (existsSync(out)) {
    for (const entry of readdirSync(out)) {
      if (!['index.html', 'sw.js', '_headers', 'a'].includes(entry)) fail(`${out} holds ${entry}, which is not part of a bundle; remove it or choose another --out`);
    }
    for (const entry of ['index.html', 'sw.js', '_headers', 'a']) rmSync(join(out, entry), { recursive: true, force: true });
  }
  const dir = join(out, 'a', id);
  mkdirSync(dir, { recursive: true });
  for (const [name, bytes] of files) writeFileSync(join(dir, name), bytes);
  writeFileSync(join(dir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(out, 'index.html'), page.split(BUILD_MARK).join(id));
  writeFileSync(join(out, 'sw.js'), worker.split(BUILD_MARK).join(id));
  writeFileSync(join(out, '_headers'), headers);
  return { build: id, out, files: [...files.keys()].sort(), manifest };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const option = (name) => {
    const at = args.indexOf(name);
    return at >= 0 ? args[at + 1] : undefined;
  };
  try {
    const done = build({ out: option('--out') && resolve(option('--out')), pkg: option('--pkg') && resolve(option('--pkg')) });
    console.log(`viewer: build ${done.build} in ${done.out} (${done.files.length + 1} files in a/${done.build}/; core ${done.manifest.version}, ${done.manifest.rustc || 'unknown rustc'})`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
