// The README's screenshots of the viewer: the demo vault of content.mjs, written by the
// native binary, behind the fake Drive and the fake Worker routes of the browser suite.
//
//   node worker/test/e2e/readme/viewer.mjs <output directory> [<demo content, made before>]
//
// Needs what the browser suite needs (see ../harness.mjs): the native binary (GCLONE_BIN,
// else target/release), the built core (GCLONE_WEB_CORE_PKG, else web-core/pkg),
// playwright-core (GCLONE_PLAYWRIGHT_CORE) and Google Chrome; and ffmpeg when the content is
// made here. Nothing real is involved: no Google account, no vault of yours.
//
// Writes viewer-<what>-<light|dark>.png: list, text, image, video, phone, phone-image.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { FakeDrive } from '../fake-drive.mjs';
import { ENGINES, bundle, loadPlaywright } from '../harness.mjs';
import { ViewerServer } from '../server.mjs';
import { Device, PASS, nativeBinary } from '../vault.mjs';
import { makeDemo } from './content.mjs';

const out = path.resolve(process.argv[2] || 'shots');
fs.mkdirSync(out, { recursive: true });
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gclone-readme-'));
let src = process.argv[3] && path.resolve(process.argv[3]);
if (!src) {
  src = path.join(work, 'src');
  await makeDemo(src);
}

// The vault: one device, one copy. (No Secure Enclave trial in a run like this one.)
const vaultDir = path.join(work, 'store');
fs.mkdirSync(vaultDir);
const device = new Device(nativeBinary(), work, 'laptop');
device.env.GCLONE_KEYSTORE_TRIAL = '0';
device.login(vaultDir);
device.run('copy', src, ':');

const drive = new FakeDrive(vaultDir);
await drive.listen();
const server = new ViewerServer({ dist: bundle(work), drive, email: 'you@example.com' });
await server.listen();
const playwright = await loadPlaywright();
const browser = await ENGINES.chrome(playwright);

const DESKTOP = { width: 1280, height: 800 };
const PHONE = { width: 390, height: 844 };
// Two device pixels to one of the page; a picture of a photograph is kept smaller (it is
// shown about 880 wide, and its file grows with every pixel of sky).
const SHARP = 2;
const PHOTO = 1.375;

/** A signed-in page at the unlock screen, and `shot(name)` for it. */
async function open(viewport, scheme, scale) {
  const phone = viewport === PHONE;
  const context = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: scale, isMobile: phone, hasTouch: phone, locale: 'en-GB', timezoneId: 'UTC' });
  await context.addCookies([{ ...server.signIn(), url: server.origin, httpOnly: true, sameSite: 'Strict' }]);
  const page = await context.newPage();
  await page.goto(`${server.origin}/`);
  await page.waitForSelector('#shell[data-screen="unlock"]:not([hidden])');
  const shot = async (name) => {
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(out, `viewer-${name}-${scheme}.png`) });
  };
  return { page, shot, close: () => context.close() };
}

async function unlock(page) {
  await page.fill('#unlock-pass', PASS);
  await page.click('#unlock-go');
  await page.waitForSelector('#rows .row');
  await page.waitForFunction(() => /files/.test(document.getElementById('summary').textContent));
  await page.mouse.move(0, 0);
}

/** Opens the folder or the file `name` of the list, once the list shows it; the pointer does not stay on a row. */
async function click(page, name) {
  const row = await page.waitForFunction((wanted) => [...document.querySelectorAll('#rows .row')].find((r) => r.querySelector('.name').title === wanted), name);
  await row.asElement().click();
  await page.mouse.move(0, 0);
}

async function enter(page, ...folders) {
  for (const folder of folders) {
    await click(page, folder);
    await page.waitForFunction((wanted) => {
      const current = document.querySelector('#crumbs [aria-current]');
      return current && current.title === wanted && !document.body.classList.contains('busy');
    }, folder);
  }
}

async function picture(page, name) {
  await click(page, name);
  await page.waitForFunction(() => {
    const img = document.querySelector('#viewer-body img');
    return img && img.complete && img.naturalWidth > 0;
  });
}

try {
  for (const scheme of ['light', 'dark']) {
    // The list, a text file.
    let tab = await open(DESKTOP, scheme, SHARP);
    await unlock(tab.page);
    await tab.shot('list');
    await enter(tab.page, 'Documents', 'Recipes');
    await click(tab.page, 'sourdough.md');
    await tab.page.waitForSelector('#viewer-body pre');
    await tab.shot('text');
    await tab.close();

    // A photograph and a film.
    tab = await open(DESKTOP, scheme, PHOTO);
    await unlock(tab.page);
    await enter(tab.page, 'Photos', '2026', 'Norway');
    await picture(tab.page, 'northern-lights.jpg');
    await tab.shot('image');
    await tab.page.click('#viewer-close');
    await click(tab.page, 'fjord-timelapse.mp4');
    await tab.page.waitForFunction(() => {
      const video = document.querySelector('#viewer-body video');
      return video && video.readyState >= 1;
    });
    // Somewhere in the middle, standing still, with its controls.
    await tab.page.evaluate(() => new Promise((resolve) => {
      const video = document.querySelector('#viewer-body video');
      video.addEventListener('seeked', resolve, { once: true });
      video.currentTime = 6.5;
    }));
    await tab.page.waitForFunction(() => {
      const video = document.querySelector('#viewer-body video');
      return !video.seeking && video.readyState >= 3;
    });
    await tab.page.mouse.move(640, 400);
    await tab.page.waitForTimeout(1500);
    await tab.shot('video');
    await tab.close();

    // A phone: a folder, and a photograph taken upright.
    tab = await open(PHONE, scheme, SHARP);
    await unlock(tab.page);
    await enter(tab.page, 'Photos', '2026', 'Norway');
    await tab.shot('phone');
    await picture(tab.page, 'night-lake.jpg');
    await tab.shot('phone-image');
    await tab.close();
  }
  console.log(`screenshots in ${out}`);
} finally {
  await browser.close();
  await server.close();
  await drive.close();
  fs.rmSync(work, { recursive: true, force: true });
}
