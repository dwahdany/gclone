// What the Node tests of the viewer's data layer share: a directory vault made by the native
// binary, the fake Drive over it, and the viewer's own scripts pointed at that.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FakeDrive } from '../e2e/fake-drive.mjs';
import { Device, PASS, nativeBinary } from '../e2e/vault.mjs';
import { driveFor, loadViewer } from './env.mjs';

export { PASS };

/** A token source that counts: `get(force)` hands out `tok-<n>`, which the fake Drive accepts. */
export function tokens(drive) {
  const state = { n: 0, forced: 0, current: null };
  const mint = () => {
    state.n += 1;
    state.current = `tok-${state.n}`;
    drive.tokens.add(state.current);
    return state.current;
  };
  return {
    state,
    async get(force) {
      if (force) state.forced += 1;
      return force || !state.current ? mint() : state.current;
    },
  };
}

/**
 * A new vault with `files` (`{ path: content }`), written by one device.
 * Returns `{ work, vaultDir, device, drive, token, viewerDrive, write(files), close() }`.
 */
export async function makeVault(files, { repair = false } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-viewer-test-'));
  const vaultDir = path.join(work, 'store');
  fs.mkdirSync(vaultDir);
  const device = new Device(nativeBinary(), work, 'laptop');
  device.login(vaultDir);
  let round = 0;
  const write = (more, target = ':') => {
    round += 1;
    const src = path.join(work, `src-${round}`);
    for (const [rel, content] of Object.entries(more)) {
      fs.mkdirSync(path.dirname(path.join(src, rel)), { recursive: true });
      fs.writeFileSync(path.join(src, rel), content);
    }
    device.run('copy', src, target);
  };
  write(files);
  if (repair) device.run('repair');
  const drive = new FakeDrive(vaultDir);
  await drive.listen();
  const token = tokens(drive);
  const sleeps = [];
  const viewerDrive = driveFor(drive.origin, token, { sleep: async (ms) => { sleeps.push(ms); } });
  return {
    work, vaultDir, device, drive, token, viewerDrive, write, sleeps,
    async close() {
      await drive.close();
      fs.rmSync(work, { recursive: true, force: true });
    },
  };
}

/** Steps 1–4 of the loader with the passphrase: `{ vault, found, opened }` — the core's Vault, unlocked. */
export async function unlock(viewerDrive, pass = PASS) {
  const { gclone, core } = loadViewer();
  const found = await gclone.loader.discover(core, viewerDrive);
  if (found.vaults.length !== 1) throw new Error(`expected one vault, found ${found.vaults.length}`);
  const opened = await gclone.loader.open(core, viewerDrive, found.vaults[0].root);
  let bundle = null;
  for (const candidate of opened.candidates) {
    if (!candidate.bytes) continue;
    try {
      bundle = core.unlock(candidate.name, candidate.bytes, pass, found.vaults[0].vault_id);
      break;
    } catch (error) {
      if (gclone.loader.codeOf(error) !== 'wrong-passphrase') throw error;
    }
  }
  if (!bundle) throw new Error('wrong passphrase');
  return { vault: core.Vault.from_keys(bundle), found, opened };
}

/** Every path of the tree the core holds, as `gclone ls -R :` prints it. */
export function lsRecursive(vault) {
  const out = [];
  const visit = (dir) => {
    let offset = 0;
    let count = 0;
    for (;;) {
      const page = JSON.parse(vault.list(dir, 'name', 'asc', offset, 5000));
      for (const entry of page.entries) {
        const p = dir ? `${dir}/${entry.name}` : entry.name;
        if (entry.dir) {
          if (visit(p) === 0) out.push(`${p}/`);
        } else out.push(p);
      }
      count += page.entries.length;
      offset += page.entries.length;
      if (offset >= page.total || page.entries.length === 0) break;
    }
    return count;
  };
  visit('');
  return out.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}
