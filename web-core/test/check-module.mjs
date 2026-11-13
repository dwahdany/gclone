// node check-module.mjs <core.wasm> <core.js>
// What build.sh checks about its output (design §5, §15 P2b): the module imports nothing but
// wasm-bindgen's own intrinsics — no clock, no randomness, no network —, it is not larger than
// the limit, and the glue has no eval. Prints the sizes raw and compressed.
import fs from 'node:fs';
import zlib from 'node:zlib';

const [wasmPath, gluePath] = process.argv.slice(2);
const WASM_MAX = 800 * 1024;
const fail = (text) => { console.error(`check-module: ${text}`); process.exit(1); };

const wasm = fs.readFileSync(wasmPath);
const glue = fs.readFileSync(gluePath);
const module = new WebAssembly.Module(wasm);

// Every import must be a function the glue itself defines (`__wbg_…` / `__wbindgen_…`): what
// the glue's functions call is checked below, by name.
const imports = WebAssembly.Module.imports(module);
const foreign = imports.filter((i) => i.kind !== 'function' || !/^__wb(g|indgen)_/.test(i.name));
if (foreign.length) fail(`unexpected imports: ${JSON.stringify(foreign)}`);
// The intrinsics a module without I/O needs: throwing an Error, describing a value in an
// error message, the externref table. A clock (Date, performance), randomness (crypto,
// getRandomValues, Math.random) or the network (fetch, XMLHttpRequest) would show here.
const banned = /(Date|now|performance|crypto|random|Random|fetch|XMLHttpRequest|WebSocket|setTimeout|Storage|document|window|navigator|eval|Function)/;
const suspicious = imports.filter((i) => banned.test(i.name.replace(/^__wb(g|indgen)_/, '')));
if (suspicious.length) fail(`imports that reach outside the module: ${suspicious.map((i) => i.name).join(', ')}`);

const text = glue.toString('utf8');
for (const sink of ['eval(', 'new Function', 'importScripts(', 'XMLHttpRequest', 'Math.random', 'getRandomValues', 'Date.now', 'performance.now']) {
  if (text.includes(sink)) fail(`the glue uses ${sink}`);
}
if (wasm.length > WASM_MAX) fail(`the module is ${wasm.length} bytes, more than the ${WASM_MAX} allowed`);

const sizes = (bytes) => ({
  raw: bytes.length,
  gzip: zlib.gzipSync(bytes, { level: 9 }).length,
  brotli: zlib.brotliCompressSync(bytes, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11, [zlib.constants.BROTLI_PARAM_SIZE_HINT]: bytes.length } }).length,
});
const line = (name, s) => console.log(`${name.padEnd(10)} raw ${String(s.raw).padStart(7)}  gzip-9 ${String(s.gzip).padStart(7)}  brotli-11 ${String(s.brotli).padStart(7)}`);
line('wasm', sizes(wasm));
line('glue (js)', sizes(glue));
console.log(`imports: ${imports.length} (${imports.map((i) => i.name).join(', ')})`);
console.log(`exports: ${WebAssembly.Module.exports(module).length}`);
