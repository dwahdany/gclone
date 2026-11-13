// Loads the viewer's scripts into Node the way a worker of the viewer loads them: they are
// classic scripts that attach to `self.gclone` (`importScripts` there, `vm.runInThisContext`
// here), and the core is wasm-bindgen's `--target no-modules` glue that defines the global
// `wasm_bindgen`. One instance per process.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..', '..');
export const VIEWER = path.join(REPO, 'worker', 'viewer');
export const PKG = process.env.GCLONE_WEB_CORE_PKG || path.join(REPO, 'web-core', 'pkg');

let loaded = null;

/** `{ gclone, core }`: the namespace the scripts attach to, and the initialised core. */
export function loadViewer() {
  if (loaded) return loaded;
  globalThis.self = globalThis;
  for (const name of ['token.js', 'drive.js', 'loader.js']) {
    const file = path.join(VIEWER, name);
    vm.runInThisContext(fs.readFileSync(file, 'utf8'), { filename: file });
  }
  const glue = path.join(PKG, 'core.js');
  if (!fs.existsSync(glue)) throw new Error(`${PKG} holds no core.js: run web-core/build.sh first`);
  vm.runInThisContext(fs.readFileSync(glue, 'utf8'), { filename: glue });
  const core = vm.runInThisContext('wasm_bindgen');
  core.initSync({ module: fs.readFileSync(path.join(PKG, 'core.wasm')) });
  loaded = { gclone: globalThis.gclone, core };
  return loaded;
}

/** The viewer's drive.js pointed at a fake Drive: the same one constant the test server swaps. */
export function driveFor(origin, token, options = {}) {
  const { gclone } = loadViewer();
  const real = 'https://www.googleapis.com';
  return gclone.createDrive({
    token,
    sleep: options.sleep ?? (async () => {}),
    random: () => 0,
    patience: options.patience,
    offline: options.offline ?? (() => false),
    fetch: (url, init) => {
      if (!String(url).startsWith(real)) throw new Error(`drive.js asked for ${url}`);
      if (options.onFetch) options.onFetch(String(url), init);
      return fetch(origin + String(url).slice(real.length), init);
    },
  });
}
