// The KDF worker (design §2, §6 step 4), as a worker_thread: its own instance of the module,
// whose memory grows by the keyfile's cost and goes away with the worker. One worker serves
// every attempt of an unlock screen, so that a retry reuses the memory of the last one.
//
// The candidate loop is the CLI's (`cli::login::unlock`): the passphrase is tried on each
// candidate, highest generation first. `wrong-passphrase` keeps the candidate; `damaged`,
// `other-vault` and `needs-newer` drop it for good. Nothing opened: "wrong passphrase" if a
// candidate is left, otherwise "no usable keyfile" — or "needs a newer viewer" when a keyfile
// version was the reason.
import { parentPort, workerData } from 'node:worker_threads';
import { loadCore, wasmBytes, codeOf } from './core.mjs';

const { core } = loadCore();
/** `[{ name, bytes }]`, as `keyfile_candidates` ordered them. */
let candidates = workerData.candidates;
let newer = false;

parentPort.on('message', ({ passphrase, vaultId }) => {
  const tried = [];
  const kept = [];
  let bundle = null;
  for (const candidate of candidates) {
    if (bundle) {
      kept.push(candidate);
      continue;
    }
    const t0 = performance.now();
    try {
      bundle = core.unlock(candidate.name, candidate.bytes, passphrase, vaultId);
      kept.push(candidate);
      tried.push({ name: candidate.name, outcome: 'opened', ms: performance.now() - t0 });
    } catch (error) {
      const code = codeOf(error);
      if (!code) throw error;
      tried.push({ name: candidate.name, outcome: code, ms: performance.now() - t0 });
      if (code === 'wrong-passphrase') kept.push(candidate);
      else if (code === 'needs-newer') newer = true;
    }
  }
  candidates = kept;
  const outcome = bundle ? 'opened'
    : candidates.length ? 'wrong-passphrase'
    : newer ? 'needs-newer' : 'no-usable-keyfile';
  const answer = { outcome, bundle, tried, left: candidates.map((c) => c.name), wasmBytes: wasmBytes() };
  parentPort.postMessage(answer, bundle ? [bundle.buffer] : []);
});
parentPort.postMessage({ ready: true, wasmBytes: wasmBytes() });
