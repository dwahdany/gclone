// The README's terminal pictures: what the native binary prints, run against a directory
// vault in a temporary directory and drawn as a terminal window by Chrome.
//
//   node worker/test/e2e/readme/terminal.mjs <output directory> [<demo content, made before>]
//
// Needs the native binary (GCLONE_BIN, else target/release), playwright-core
// (GCLONE_PLAYWRIGHT_CORE) and Google Chrome; and ffmpeg when the content is made here.
//
// Every line under a prompt is the output of the command above it, unchanged but for two
// things: the temporary directory is cut off the front of the paths, so that the vault is at
// /mnt/vault, and `gclone status` is drawn without its `Key store` line. A device is a home
// directory of its own below that directory, and no run tries the Secure Enclave
// (GCLONE_KEYSTORE_TRIAL=0, then `gclone keystore use file`) — which is why that line would
// read "plain file … kept by choice" here, and say nothing about a reader's machine.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ENGINES, loadPlaywright } from '../harness.mjs';
import { PASS, nativeBinary } from '../vault.mjs';
import { makeDemo } from './content.mjs';

const out = path.resolve(process.argv[2] || 'shots');
fs.mkdirSync(out, { recursive: true });
const lab = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-readme-'));
const vault = path.join(lab, 'mnt', 'vault');
const bin = path.join(lab, 'bin');
const passphrase = path.join(lab, 'passphrase');
fs.mkdirSync(vault, { recursive: true });
fs.mkdirSync(bin);
fs.symlinkSync(nativeBinary(), path.join(bin, 'gclone'));
fs.writeFileSync(passphrase, `${PASS}\n`, { mode: 0o600 });

/** A device: its home directory, and `run(line)`, which gives what a shell there prints for `line`. */
function device(name) {
  const home = path.join(lab, 'home', name);
  fs.mkdirSync(home, { recursive: true });
  const run = (line) => {
    const done = spawnSync('/bin/sh', ['-c', `${line} 2>&1`], {
      cwd: home, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: `${bin}:/usr/bin:/bin`, HOME: home, TZ: 'UTC', GCLONE_KEYSTORE_TRIAL: '0' },
    });
    if (done.error) throw done.error;
    assert.equal(done.status, 0, `${line} exited ${done.status}:\n${done.stdout}`);
    return done.stdout.split(lab).join('').replace(/\n+$/, '');
  };
  run(`gclone login --vault-dir '${vault}' --passphrase-file '${passphrase}' --device-name ${name}`);
  run('gclone keystore use file');
  return { home, run };
}

const laptop = device('laptop');
const mine = (rel) => (rel.startsWith('Documents/') || rel.startsWith('Photos/')) && !rel.endsWith('.mp4');
if (process.argv[3]) {
  for (const dir of ['Documents', 'Photos']) {
    fs.cpSync(path.join(path.resolve(process.argv[3]), dir), path.join(laptop.home, dir), { recursive: true, preserveTimestamps: true, filter: (from) => !from.endsWith('.mp4') });
  }
} else {
  await makeDemo(laptop.home, mine);
}

/** What `gclone status` printed, without the one line that is about this lab (see the top). */
const withoutKeyStore = (text) => {
  const rows = text.split('\n');
  const kept = rows.filter((row) => !row.startsWith('Key store'));
  assert.equal(kept.length, rows.length - 1, `gclone status has no single "Key store" line:\n${text}`);
  return kept.join('\n');
};

/** One picture: the commands as typed, each with what it printed (and the same on stdout, to read). */
const scene = (...lines) => lines.map((line) => {
  const printed = laptop.run(line);
  const text = line === 'gclone status' ? withoutKeyStore(printed) : printed;
  console.log(`$ ${line}\n${text}\n`);
  return { line, text };
});

const scenes = {};
scenes['terminal-sync'] = scene('gclone sync -v ~/Documents :Documents', 'gclone sync ~/Photos :Photos');

// A second device, and a file that is changed and one that is removed.
const desktop = device('desktop');
desktop.run('mkdir Documents && gclone copy :Documents ~/Documents');
fs.appendFileSync(path.join(laptop.home, 'Documents/Recipes/sourdough.md'), '- 2026-11-08: half rye. Dense, and good with cheese.\n');
laptop.run('gclone sync ~/Documents :Documents');
scenes['terminal-restore'] = scene('gclone rm :Documents/Travel/tickets.pdf', 'gclone restore --list :Documents', 'gclone restore :Documents/Travel/tickets.pdf');
scenes['terminal-status'] = scene('gclone status', 'gclone about');
scenes['terminal-ls'] = scene('gclone ls -l :Documents/Recipes', 'gclone tree :Documents');

// --- drawing -------------------------------------------------------------------------------

const COLUMNS = 100;
const escape = (text) => text.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
/** A line that is longer than the window is wide goes on in the next one, from a space on. */
const wrap = (text) => text.split('\n').map((line) => {
  const rows = [];
  let rest = line;
  while (rest.length > COLUMNS && rest.lastIndexOf(' ', COLUMNS) > 0) {
    const at = rest.lastIndexOf(' ', COLUMNS);
    rows.push(rest.slice(0, at));
    rest = rest.slice(at + 1);
  }
  return [...rows, rest].join('\n');
}).join('\n');
const page = (commands) => `<!doctype html>
<meta charset="utf-8">
<style>
  :root { color-scheme: light dark; --bg: #ffffff; --bar: #f5f6f8; --line: #d5d9df; --text: #1c2025; --muted: #606873; --accent: #1a5fd0; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14171b; --bar: #1b1f25; --line: #2a2f37; --text: #e5e8ec; --muted: #99a2ad; --accent: #8ab4f8; }
  }
  body { margin: 0; background: transparent; }
  .window { display: inline-block; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; background: var(--bg); }
  .bar { position: relative; height: 34px; background: var(--bar); border-bottom: 1px solid var(--line); font: 12px/34px system-ui, sans-serif; color: var(--muted); text-align: center; }
  .dots { position: absolute; left: 13px; top: 11px; display: flex; gap: 8px; }
  .dots i { width: 12px; height: 12px; border-radius: 50%; background: var(--line); }
  pre { margin: 0; padding: 16px 20px 18px; width: ${COLUMNS}ch; white-space: pre-wrap; overflow-wrap: anywhere; font: 13px/1.5 ui-monospace, "SF Mono", Menlo, Consolas, monospace; color: var(--text); }
  .prompt { color: var(--muted); }
  .line { color: var(--accent); font-weight: 600; }
</style>
<div class="window">
  <div class="bar"><span class="dots"><i></i><i></i><i></i></span>laptop</div>
  <pre>${commands.map(({ line, text }) => `<span class="prompt">$</span> <span class="line">${escape(line)}</span>\n${escape(wrap(text))}`).join('\n\n')}</pre>
</div>`;

const playwright = await loadPlaywright();
const browser = await ENGINES.chrome(playwright);
try {
  for (const scheme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: { width: 1000, height: 900 }, colorScheme: scheme, deviceScaleFactor: 2 });
    const tab = await context.newPage();
    for (const [name, commands] of Object.entries(scenes)) {
      await tab.setContent(page(commands));
      await tab.locator('.window').screenshot({ path: path.join(out, `${name}-${scheme}.png`), omitBackground: true });
    }
    await context.close();
  }
  console.log(`terminal pictures in ${out}`);
} finally {
  await browser.close();
  fs.rmSync(lab, { recursive: true, force: true });
}
