// Screenshots of the hosted viewer, for looking at: sign-in, unlock, the list, previews and
// the other screens, in a desktop and a phone-sized window, light and dark.
//
//   node worker/test/e2e/shots.mjs <output directory> [chrome|webkit|firefox]
//
// The same fixture, fake Drive and fake Worker routes as the browser suite (run.mjs).
import fs from 'node:fs';
import path from 'node:path';
import { ENGINES, loadPlaywright, startStack } from './harness.mjs';
import { BIDI_NAME, PASS, foreignKeyfile } from './vault.mjs';

const out = path.resolve(process.argv[2] || 'shots');
const engine = process.argv[3] || 'chrome';
fs.mkdirSync(out, { recursive: true });

const stack = await startStack({});
const playwright = await loadPlaywright();
const browser = await ENGINES[engine](playwright);
const SIZES = { desktop: { width: 1280, height: 800 }, phone: { width: 390, height: 844 } };

async function listed(page, dir) {
  await page.waitForFunction((wanted) => {
    const current = document.querySelector('#crumbs [aria-current]');
    return current && current.title === wanted && /items?$/.test(document.getElementById('count').textContent) && !document.body.classList.contains('busy');
  }, dir);
  await page.waitForTimeout(250);
}

async function clickRow(page, name) {
  const row = await page.evaluateHandle((wanted) => [...document.querySelectorAll('#rows .row')].find((r) => r.querySelector('.name').title === wanted), name);
  await row.asElement().click();
}

/** Shows one of the shell's screens, as shell.js does (the name, and the `hidden` of every other). */
const showScreen = (page, name) => page.evaluate((wanted) => {
  const shell = document.getElementById('shell');
  shell.dataset.screen = wanted;
  for (const section of shell.querySelectorAll('.screen')) section.hidden = section.dataset.screen !== wanted;
  shell.hidden = false;
}, name);

const foreign = foreignKeyfile(stack.work);

try {
  for (const [size, viewport] of Object.entries(SIZES)) {
    for (const scheme of ['light', 'dark']) {
      const context = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: 2, isMobile: size === 'phone' && engine !== 'firefox', hasTouch: size === 'phone' });
      const page = await context.newPage();
      const shot = (name) => page.screenshot({ path: path.join(out, `${name}-${size}-${scheme}.png`) });
      const screen = (name) => page.waitForSelector(`#shell[data-screen="${name}"]:not([hidden])`);

      // Sign-in.
      await page.goto(`${stack.origin}/`);
      await screen('signin');
      await shot('1-signin');

      // Unlock (signed in through the fake Worker's cookie).
      await context.addCookies([{ ...stack.server.signIn(), url: stack.origin, httpOnly: true, sameSite: 'Strict' }]);
      await page.goto(`${stack.origin}/`);
      await screen('unlock');
      await shot('2-unlock');
      await page.fill('#unlock-pass', 'not the passphrase');
      await page.click('#unlock-go');
      await page.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock' && !document.getElementById('unlock-problem').hidden);
      await page.fill('#unlock-pass', 'still typing');
      await shot('2-unlock-wrong');

      // The list.
      await page.fill('#unlock-pass', PASS);
      await page.click('#unlock-go');
      await page.waitForSelector('#rows .row');
      await page.waitForFunction(() => /files/.test(document.getElementById('summary').textContent));
      await page.waitForTimeout(300);
      await shot('3-listing');
      await page.click('#info-btn');
      await page.waitForTimeout(150);
      await shot('3-listing-info');
      await page.keyboard.press('Escape');
      await clickRow(page, 'docs');
      await listed(page, 'docs');
      await shot('3-listing-folder');

      // Previews.
      await clickRow(page, 'notes.txt');
      await page.waitForSelector('#viewer-body pre');
      await shot('4-preview-text');
      await page.click('#viewer-close');
      await page.click('#brand');
      await listed(page, 'Vault').catch(() => {});
      await clickRow(page, 'pics');
      await listed(page, 'pics');
      await clickRow(page, 'photo.png');
      await page.waitForFunction(() => { const img = document.querySelector('#viewer-body img'); return img && img.complete && img.naturalWidth > 0; });
      await page.waitForTimeout(200);
      await shot('4-preview-image');
      await page.click('#viewer-close');
      await page.click('#brand');
      await page.waitForTimeout(300);
      await clickRow(page, 'bin');
      await listed(page, 'bin');
      await clickRow(page, 'archive.zip');
      await page.waitForSelector('#viewer-body .card');
      await shot('4-preview-card');
      await page.click('#viewer-close');
      // A PDF: a card with "Open" (a tab of its own).
      await page.click('#brand');
      await page.waitForTimeout(300);
      await clickRow(page, 'docs');
      await listed(page, 'docs');
      await clickRow(page, 'report.pdf');
      await page.waitForSelector('#viewer-body .card a.btn[target="_blank"]');
      await shot('4-preview-pdf');
      await page.click('#viewer-close');
      // A name that turns its own end around: the row and the card.
      await page.click('#brand');
      await page.waitForTimeout(300);
      await clickRow(page, 'deep');
      await listed(page, 'deep');
      await clickRow(page, 'a');
      await listed(page, 'a');
      await shot('3-listing-bidi');
      await clickRow(page, BIDI_NAME);
      await page.waitForSelector('#viewer-body .card');
      await shot('4-preview-bidi');
      await page.click('#viewer-close');
      // What a refresh says when it left something where it is.
      await page.evaluate(() => {
        document.getElementById('notice-text').textContent = '1 new index object (300 MiB) was not loaded: a refresh downloads no more than 64 MiB without asking. Lock the vault and unlock it again to decide.';
        document.getElementById('notice').className = 'notice error';
        document.getElementById('notice').hidden = false;
      });
      await shot('3-listing-notice');
      await page.evaluate(() => { document.getElementById('notice').hidden = true; });
      await page.click('#brand');
      await page.waitForTimeout(300);
      await page.fill('#search', 'clip');
      await page.waitForFunction(() => /match/.test(document.getElementById('count').textContent));
      await page.waitForTimeout(200);
      await shot('3-listing-search');

      // Signed out.
      await page.click('#info-btn');
      await page.click('#session-out');
      await screen('out');
      await shot('5-signed-out');

      // A question and a stop.
      await page.evaluate(() => {
        document.getElementById('ask-title').textContent = 'A large index';
        document.getElementById('ask-text').textContent = 'The index of this vault is 96 MiB. Loading it needs several times that in memory and may not work in this browser.';
        const box = document.getElementById('ask-choices');
        box.className = 'choices';
        for (const [label, cls] of [['Load it', 'btn'], ['Skip c-00000000000000f1-0e960c48db3dc78e-7a629a0c', 'btn quiet'], ['Cancel', 'btn quiet']]) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = cls;
          const span = document.createElement('span');
          span.textContent = label;
          button.append(span);
          box.append(button);
        }
      });
      await showScreen(page, 'ask');
      await shot('6-ask');
      await page.evaluate(() => {
        document.getElementById('stop-title').textContent = 'A newer viewer is needed';
        document.getElementById('stop-text').textContent = 'This vault needs a newer viewer. It was written by a newer gclone than the one this site runs.';
      });
      await showScreen(page, 'stop');
      await shot('6-stop');
      await page.evaluate(() => {
        document.getElementById('stop-title').textContent = 'The viewer cannot go on';
        document.getElementById('stop-text').textContent = 'Too many requests from this address. Wait a minute, then try again.';
        const note = document.getElementById('stop-note');
        note.textContent = 'The sign-out did not reach the server, so this browser is still signed in: The sign-in service does not answer. Check the connection and try again.';
        note.hidden = false;
      });
      await shot('6-stop-note');
      await page.evaluate(() => {
        document.getElementById('work-text').textContent = 'Loading the index…';
        document.getElementById('work-detail').textContent = '11 MiB of 15 MiB';
        document.getElementById('work-meter').hidden = false;
        document.getElementById('work-bar').style.width = '73%';
      });
      await showScreen(page, 'work');
      await shot('6-work');
      await context.close();

      // The page whose scripts never arrived: the first screen, and after ten seconds what it says.
      const bare = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: 2, isMobile: size === 'phone' && engine !== 'firefox', hasTouch: size === 'phone' });
      await bare.route(`${stack.origin}/a/**/*.js`, (route) => route.fulfill({ status: 404, body: '' }));
      const stuck = await bare.newPage();
      await stuck.goto(`${stack.origin}/`);
      await stuck.locator('.late').evaluate((node) => { for (const animation of node.getAnimations()) animation.finish(); });
      await stuck.screenshot({ path: path.join(out, `0-not-started-${size}-${scheme}.png`) });
      await bare.close();
      // … and without its styles as well.
      const naked = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: 2 });
      await naked.route(`${stack.origin}/a/**`, (route) => route.fulfill({ status: 404, body: '' }));
      const plain = await naked.newPage();
      await plain.goto(`${stack.origin}/`);
      await plain.screenshot({ path: path.join(out, `0-no-files-${size}-${scheme}.png`) });
      await naked.close();

      // Four keyfiles of another vault in front of the real one: what the unlock screen says and offers.
      const rootId = stack.drive.idOf('gclone');
      stack.drive.planted.push(...[9, 8, 7, 6].map((g) => ({ id: `foreign-key-${g}`, name: foreign.name(g), parent: rootId, size: foreign.bytes.length, bytes: foreign.bytes })));
      try {
        const planted = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: 2, isMobile: size === 'phone' && engine !== 'firefox', hasTouch: size === 'phone' });
        await planted.addCookies([{ ...stack.server.signIn(), url: stack.origin, httpOnly: true, sameSite: 'Strict' }]);
        const locked = await planted.newPage();
        await locked.goto(`${stack.origin}/`);
        await locked.waitForSelector('#shell[data-screen="unlock"]:not([hidden])');
        await locked.fill('#unlock-pass', PASS);
        await locked.click('#unlock-go');
        await locked.waitForFunction(() => document.getElementById('shell').dataset.screen === 'unlock' && !document.getElementById('unlock-problem').hidden, null, { timeout: 60000 });
        await locked.check('#unlock-more');
        await locked.fill('#unlock-pass', 'typing it again');
        await locked.screenshot({ path: path.join(out, `2-unlock-more-keyfiles-${size}-${scheme}.png`) });
        await planted.close();
      } finally {
        stack.drive.planted.length = 0;
      }
    }
  }
  console.log(`screenshots in ${out}`);
} finally {
  await browser.close();
  await stack.close();
}
