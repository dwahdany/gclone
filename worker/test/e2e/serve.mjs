// The hosted viewer on this machine, for looking at it: a fixture vault written by the native
// binary, the fake Drive, the fake Worker routes and the built bundle.
//
//   node worker/test/e2e/serve.mjs [port]
//
// Then open the printed address and unlock with the passphrase it prints. Nothing real is involved: no Google, no Cloudflare, no vault
// of yours. GCLONE_BIN names the native binary (default: target/release/gclone).
import { startStack } from './harness.mjs';
import { PASS } from './vault.mjs';

const stack = await startStack({ port: Number(process.argv[2]) || 8787, big: process.env.GCLONE_E2E_BIG || undefined });
// Nobody answers for Google here: /dev/signin signs in at once.
stack.server.dev = true;
console.log(`viewer:     ${stack.origin}/dev/signin   (signed in), or ${stack.origin}/ (the sign-in screen)`);
console.log(`fake Drive: ${stack.drive.origin}`);
console.log(`passphrase: ${PASS}`);
console.log('Ctrl-C ends it.');
process.on('SIGINT', async () => { await stack.close(); process.exit(0); });
