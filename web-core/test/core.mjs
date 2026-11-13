// Loads web-core/pkg/core.js the way a worker of the hosted viewer does: the file is a classic
// script (wasm-bindgen `--target no-modules`) that defines the global `wasm_bindgen`;
// `importScripts('core.js')` there, `vm.runInThisContext` here. One instance per thread.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

export const PKG = process.env.GCLONE_WEB_CORE_PKG
  || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'pkg');

let loaded;
/** `{ core, wasm }`: the API object (`wasm_bindgen`) and the instance's raw exports. */
export function loadCore() {
  if (!loaded) {
    const file = path.join(PKG, 'core.js');
    vm.runInThisContext(fs.readFileSync(file, 'utf8'), { filename: file });
    const core = vm.runInThisContext('wasm_bindgen');
    const wasm = core.initSync({ module: fs.readFileSync(path.join(PKG, 'core.wasm')) });
    loaded = { core, wasm };
  }
  return loaded;
}

/** Bytes of this thread's wasm memory: it only ever grows. */
export const wasmBytes = () => loadCore().wasm.memory.buffer.byteLength;

/** `"<code>: <sentence>"` → the code; `null` for an error that is not the API's. */
export function codeOf(error) {
  const match = /^([a-z-]+): /.exec(String(error && error.message));
  const codes = ['wrong-passphrase', 'damaged', 'other-vault', 'needs-newer', 'not-found', 'not-a-file', 'corrupt', 'bad-input'];
  return match && codes.includes(match[1]) ? match[1] : null;
}

/** Runs `fn` and returns the code it threw with; fails if it did not throw one. */
export function thrown(fn) {
  try {
    fn();
  } catch (error) {
    const code = codeOf(error);
    if (!code) throw error;
    return code;
  }
  throw new Error('expected the call to throw');
}
