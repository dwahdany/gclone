// What the browser tests share: the bundle, the fixture vault, the two servers, the engines.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from '../../viewer/build.mjs';
import { FakeDrive } from './fake-drive.mjs';
import { ViewerServer } from './server.mjs';
import { buildVault } from './vault.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..', '..');

/** `playwright-core`: from GCLONE_PLAYWRIGHT_CORE (the package's directory), else by name. It is not a dependency of the repository. */
export async function loadPlaywright() {
  const dir = process.env.GCLONE_PLAYWRIGHT_CORE;
  try {
    return await import(dir ? pathToFileURL(path.join(dir, 'index.mjs')).href : 'playwright-core');
  } catch (error) {
    throw new Error(`playwright-core is not available (${error.message}). Install it somewhere (npm install playwright-core) and set GCLONE_PLAYWRIGHT_CORE to its directory; its WebKit and Firefox come with \`npx playwright-core install webkit firefox\` (PLAYWRIGHT_BROWSERS_PATH).`);
  }
}

/** Chrome is the installed Google Chrome, never Playwright's Chromium (which has no H.264 and AAC). */
export const ENGINES = {
  chrome: (playwright, options = {}) => playwright.chromium.launch({ headless: true, channel: 'chrome', ...options }),
  webkit: (playwright, options = {}) => playwright.webkit.launch({ headless: true, ...options }),
  firefox: (playwright, options = {}) => playwright.firefox.launch({ headless: true, ...options }),
};

/**
 * Chrome for a picture, British. The page's dates follow the context's `locale`; the
 * browser's own controls (a date field) follow the browser's language, which `--lang` sets
 * — on Linux and Windows. On a Mac Chrome takes language and region from the system's
 * settings and nothing short of changing those moves it: there the date field of a picture
 * is written the way the machine's region writes dates.
 */
export const britishChrome = (playwright) => ENGINES.chrome(playwright, { args: ['--lang=en-GB'] });

/**
 * The bundle to test: GCLONE_VIEWER_DIST (a built `dist/`, used as it is), else a fresh build
 * into `work/dist` from this tree and web-core/pkg.
 */
export function bundle(work) {
  if (process.env.GCLONE_VIEWER_DIST) return path.resolve(process.env.GCLONE_VIEWER_DIST);
  const out = path.join(work, 'dist');
  build({ out, pkg: process.env.GCLONE_WEB_CORE_PKG || undefined });
  return out;
}

/**
 * A fixture vault, the fake Drive over it and the viewer's origin.
 * Returns `{ work, dist, vault, drive, server, origin, close() }`.
 */
export async function startStack(options = {}) {
  const work = options.work || fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-viewer-e2e-'));
  const dist = bundle(work);
  const vault = buildVault(work, { big: options.big, many: options.many });
  const drive = new FakeDrive(vault.vaultDir, { latencyMs: options.latencyMs, bitsPerSecond: options.bitsPerSecond });
  await drive.listen(options.drivePort);
  const server = new ViewerServer({ dist, drive });
  await server.listen(options.port);
  return {
    work, dist, vault, drive, server, origin: server.origin,
    async close() {
      await server.close();
      await drive.close();
      if (!options.work) fs.rmSync(work, { recursive: true, force: true });
    },
  };
}
