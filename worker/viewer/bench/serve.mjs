// The device test of design package P0, served for a phone on the same network.
//
//   FEATURES=bench sh web-core/build.sh . worker/viewer/bench/pkg     (once: the core with kdf_bench)
//   node worker/viewer/bench/serve.mjs [port] [address]               (default 8787 on 127.0.0.1)
//
// To reach it from a phone, give the computer's LAN address (or 0.0.0.0) as the second
// argument and open http://<that address>:<port>/ on the phone. The page runs by itself after
// "Start" and posts its result here, where it is printed. The files are served with the
// Content-Security-Policy of the hosted viewer. Nothing else is served; nothing is stored.
//
// This page is not part of the deployed bundle (`worker/dist/` holds no HTML but index.html).
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const headers = JSON.parse(fs.readFileSync(path.join(root, '..', '..', 'src', 'headers.json'), 'utf8'));
// Served over plain http on a LAN: the transport rule does not apply here.
delete headers['Strict-Transport-Security'];
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm' };
const FILES = new Set(['index.html', 'bench.js', 'bench.css', 'bench-worker.js', 'pkg/core.js', 'pkg/core.wasm']);

/** Serves the page on `address:port` (0: a free port); resolves to the listening server. */
export function start(port, address) {
  if (!fs.existsSync(path.join(root, 'pkg', 'core.wasm'))) {
    throw new Error('worker/viewer/bench/pkg holds no core: FEATURES=bench sh web-core/build.sh . worker/viewer/bench/pkg');
  }
  const server = http.createServer(serve);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, address, () => resolve(server));
  });
}

function serve(req, res) {
  const url = new URL(req.url, 'http://bench');
  if (req.method === 'POST' && url.pathname === '/result') {
    let body = '';
    req.on('data', (chunk) => { if (body.length < 65536) body += chunk; });
    req.on('end', () => {
      console.log(`RESULT-BEGIN\n${body}\nRESULT-END`);
      res.writeHead(204, headers);
      res.end();
    });
    return;
  }
  if (url.pathname === '/favicon.ico') {
    res.writeHead(204, headers);
    res.end();
    return;
  }
  const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  if (req.method !== 'GET' || !FILES.has(rel)) {
    res.writeHead(404, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
    return;
  }
  res.writeHead(200, { ...headers, 'Content-Type': TYPES[path.extname(rel)], 'Cache-Control': 'no-store' });
  fs.createReadStream(path.join(root, rel)).pipe(res);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const server = await start(Number(process.argv[2] ?? 8787), process.argv[3] ?? '127.0.0.1');
    const { address, port } = server.address();
    console.log(`gclone device test: http://${address}:${port}/`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
