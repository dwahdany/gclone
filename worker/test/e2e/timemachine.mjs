// The time machine, driven in a real browser — the same checks for both viewers, which share
// the page: versions of a file, what was deleted from a folder, the vault at an earlier moment.
// run.mjs (the hosted viewer) and local.mjs (`gclone web`) call it with a page at the root of
// a vault that has history (`addHistory` of vault.mjs) and with what differs between them.
//
//   env.page       a page at the vault's root, showing now
//   env.label      the engine, for messages
//   env.vault      the vault (`buildVault`): its device runs the commands the page shows
//   env.past       what `addHistory` returned
//   env.api        (name, params) -> the viewer's API, asked the way the page asks it
//   env.download   (click) -> { name, bytes } of what the browser saved
//   env.work       a directory for scratch files
//   env.slowLists  (ms) -> { calls(), stop() }: every `list` call of the page takes `ms`
//                  longer from here on; `calls()` gives their `[at, offset]`, in order
//   env.state      () -> the place the page is at, as the viewer keeps it (local viewer only)
//
// The vault's folder `many` must hold more than two pages of a list (`MANY` files).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ODD_NAMES, tree } from './vault.mjs';

/** Files in the fixture's folder `many`: three pages of 2,000. */
export const MANY = 4100;

const DAY = 86400000;

/** The rows that are drawn: `{ name, mark, gone, size }`, or `{ sep: true }` for the line between the sections. */
export const rows = (page) => page.$$eval('#rows .row', (nodes) => nodes.map((row) => (row.classList.contains('sep')
  ? { sep: true, text: row.textContent }
  : {
    name: row.querySelector('.name').title,
    mark: row.querySelector('.since') ? row.querySelector('.since').textContent : '',
    gone: row.classList.contains('gone'),
    size: row.querySelector('.c-size').textContent,
    said: row.querySelector('.name .sr').textContent,
  })));

const names = async (page) => (await rows(page)).filter((r) => !r.sep).map((r) => r.name);
const count = (page) => page.textContent('#count');
const crumb = (page) => page.$eval('#crumbs [aria-current]', (node) => node.title);

/** Waits until the list shows the rows of the moment `at` (`'now'`, or milliseconds), completely. */
async function shows(page, at) {
  await page.waitForFunction((wanted) => {
    const text = document.getElementById('count').textContent;
    return document.getElementById('list').dataset.at === String(wanted) && text !== '' && !/loaded…$/.test(text)
      && document.documentElement.classList.contains('past') === (wanted !== 'now');
  }, at);
}

async function clickRow(page, name) {
  for (let attempt = 0; ; attempt += 1) {
    const row = await page.evaluateHandle((wanted) => [...document.querySelectorAll('#rows .row:not(.sep)')].find((r) => r.querySelector('.name').title === wanted) || null, name);
    assert.ok(row.asElement(), `no row named ${JSON.stringify(name)}`);
    try {
      await row.asElement().click({ timeout: 2000 });
      return;
    } catch (error) {
      if (attempt >= 5) throw error;
    }
  }
}

/** How many lists the page has shown: a navigation that loads one adds to it. */
const lists = (page) => page.$eval('#list', (list) => Number(list.dataset.n || 0));

/** Waits for a list that was loaded after `before` lists (see `lists`), at the moment `at`. */
async function loaded(page, before, at) {
  await page.waitForFunction((n) => Number(document.getElementById('list').dataset.n || 0) > n, before);
  await shows(page, at);
}

/** Into the folder `name` of the list, at the moment `at`. */
async function enter(page, name, at) {
  const before = await lists(page);
  await clickRow(page, name);
  await loaded(page, before, at);
  assert.equal(await crumb(page), name);
}

async function toRoot(page, at) {
  if ((await page.$$('#crumbs li')).length > 1) {
    const before = await lists(page);
    await page.click('#crumbs li:first-child a');
    await loaded(page, before, at);
  }
  await shows(page, at);
  assert.equal((await page.$$('#crumbs li')).length, 1);
}

async function openFile(page, name) {
  await clickRow(page, name);
  await page.waitForFunction((wanted) => !document.getElementById('viewer').hidden && document.getElementById('viewer-name').title === wanted
    && document.getElementById('viewer-meta').textContent !== '', name);
}

async function closeFile(page) {
  await page.click('#viewer-close');
  await page.waitForSelector('#viewer', { state: 'hidden' });
}

const preText = async (page, expected) => {
  await page.waitForFunction((wanted) => {
    const pre = document.querySelector('#viewer-body pre');
    return !!pre && pre.textContent === wanted;
  }, expected.toString());
};

/** The versions panel's rows: `{ current, when, text, approx }`. */
const versionRows = (page) => page.$$eval('#versions-list button', (buttons) => buttons.map((b) => ({
  current: b.getAttribute('aria-current') === 'true',
  when: b.querySelector('.v-when span').textContent,
  text: b.textContent,
  approx: /written ≈/.test(b.textContent),
  then: !!b.querySelector('.v-then'),
})));

async function openVersions(page) {
  if (await page.getAttribute('#viewer-versions', 'aria-expanded') !== 'true') await page.click('#viewer-versions');
  await page.waitForSelector('#versions-list button');
}

/**
 * The vault at `at`, through the API the page uses: every file (`Map(path → size)`) and every
 * entry as `gclone tree` takes it (`[{ path, dir }]`). `known(path, dir)`: whether an entry
 * that the viewer marks as "may have come later" (`approx`) is to be counted — the viewer
 * does not claim that it was there.
 */
async function walk(env, at, known = () => true) {
  const files = new Map();
  const rows = [];
  const visit = async (dir) => {
    for (let offset = 0; ;) {
      const listed = await env.api('list', { path: dir, offset: String(offset), ...(at ? { at: String(at) } : {}) });
      assert.ok(!listed.absent, `${dir} was there`);
      for (const entry of listed.entries) {
        const full = dir ? `${dir}/${entry.name}` : entry.name;
        assert.ok(at || !entry.approx, `${full}: no doubt about the present`);
        if (entry.approx && !known(full, entry.dir)) continue;
        rows.push({ path: full, dir: entry.dir });
        if (entry.dir) await visit(full);
        else files.set(full, entry.size);
      }
      offset += listed.entries.length;
      if (listed.entries.length === 0 || offset >= listed.total) break;
    }
  };
  await visit('');
  return { files, rows };
}

/** The names at the root of a set of files, sorted. */
const top = (files) => [...new Set([...files.keys()].map((name) => name.split('/')[0]))].sort();
const sizes = (files) => new Map([...files].map(([name, bytes]) => [name, bytes.length]));
const sorted = (map) => [...map].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

/** Runs a command line as the page shows it, in a shell, with `gclone` being the fixture's device. */
function runShown(env, command) {
  assert.match(command, /^gclone restore /);
  const bin = path.join(env.work, 'bin-for-commands');
  fs.mkdirSync(bin, { recursive: true });
  const link = path.join(bin, 'gclone');
  if (!fs.existsSync(link)) fs.symlinkSync(env.vault.device.bin, link);
  const out = spawnSync('sh', ['-c', command], { env: { ...env.vault.device.env, PATH: `${bin}:${env.vault.device.env.PATH}` }, encoding: 'utf8' });
  assert.equal(out.status, 0, `${command}\n${out.stderr}`);
  return out.stdout;
}

export async function timeMachine(env) {
  const { page, past, vault } = env;
  const { stages, notes } = past;
  const label = env.label;

  // ---- the history the vault has, as the viewer's API tells it ---------------------------------
  const timeline = await env.api('timeline');
  assert.equal(timeline.now_ms - timeline.from_ms, 25 * DAY);
  assert.deepEqual(timeline.devices, ['laptop']);
  const exact = timeline.moments.filter((m) => m[3] === 0);
  // The runs that replaced or removed something: the notes, the notes and the odd name, a
  // file deleted, a folder deleted (two files), a file moved.
  assert.deepEqual(exact.map((m) => m[1]), [1, 2, 1, 2, 1], JSON.stringify(timeline.moments));
  const [second, third, removed, folderRemoved, moved] = exact.map((m) => m[0]);
  const late = timeline.moments.at(-1);
  assert.deepEqual([late[1], late[3]], [1, 1], 'the last upload replaced nothing: an estimate');
  assert.ok(late[0] > moved);
  // The vault at the stops, against what `gclone tree` printed after each run — folders
  // included — and against the files the source held then. An entry that the viewer marks as
  // "may have come later" (the folder made by `mkdir`, an empty file: nothing records when
  // they came) counts where the source of that run has it.
  const without = (files, ...gone) => new Map([...files].filter(([name]) => !gone.includes(name)));
  for (const [at, stage, files, what] of [
    [second - 1, stages[0], stages[0].files, 'as built'],
    [second, stages[1], stages[1].files, 'the second notes'],
    [third - 1, stages[1], stages[1].files, 'before the third notes'],
    [removed - 1, stages[2], stages[2].files, 'before the deletions'],
    [folderRemoved - 1, null, without(stages[2].files, 'docs/long.txt'), 'the file deleted, the folder not yet'],
    [moved - 1, stages[3], stages[3].files, 'before the move'],
    [moved, stages[4], stages[4].files, 'after the move'],
    [null, stages[5], stages[5].files, 'now'],
  ]) {
    const there = (name, dir) => (dir ? [...files.keys()].some((file) => file.startsWith(`${name}/`)) : files.has(name));
    const then = await walk(env, at, there);
    assert.deepEqual(sorted(then.files), sorted(sizes(files)), `${label}: the vault ${what}`);
    if (stage) assert.deepEqual(tree(then.rows), stage.tree, `${label}: the tree ${what} is what \`gclone tree\` printed`);
  }
  // The folder made by `mkdir` after the move has no time of its own: it shows from the
  // move on, and says that it may have come later.
  const early = (await env.api('list', { path: '', at: String(moved) })).entries.find((e) => e.name === 'plans');
  assert.deepEqual([early.dir, early.approx], [true, true], `${label}: an entry without a time is marked`);
  assert.equal((await env.api('list', { path: '', at: String(moved - 1) })).entries.some((e) => e.name === 'plans'), false);
  const current = stages[5].files;

  // ---- the bar, opened by keyboard for the first time ------------------------------------------
  // The slider cannot take the focus before the first timeline has come: it gets it then.
  assert.equal(await page.isHidden('#time'), true);
  await page.focus('#time-btn');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => !document.getElementById('time-range').disabled);
  await page.waitForFunction(() => document.activeElement.id === 'time-range');
  assert.equal(await page.getAttribute('#time-btn', 'aria-expanded'), 'true');
  assert.equal(await page.textContent('#time-hint'), 'Kept for 25 days. Changes and deletions are placed exactly. When a new file first appeared is estimated from its upload (≈); what came without one — a folder, an empty file, a restored file, a copy — is shown from the last its device was seen before, and marked.');
  await page.click('#time-close');
  assert.equal(await page.isHidden('#time'), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'time-btn');

  // ---- versions of a file -------------------------------------------------------------------
  await enter(page, 'docs', 'now');
  await openFile(page, 'notes.txt');
  await preText(page, notes[2]);
  assert.equal(await page.isHidden('#versions'), true);
  assert.equal(await page.getAttribute('#viewer-versions', 'aria-expanded'), 'false');
  assert.equal(await page.getAttribute('#viewer-versions', 'aria-controls'), 'versions');
  await page.click('#viewer-versions');
  await page.waitForSelector('#versions-list button');
  assert.equal(await page.getAttribute('#viewer-versions', 'aria-expanded'), 'true');
  assert.equal(await page.getAttribute('#versions', 'aria-label'), 'Versions of this file');
  assert.equal(await page.textContent('#versions-title'), 'Versions of notes.txt');
  // Opening the panel puts the focus on the version that is shown.
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-current')), 'true');
  let listed = await versionRows(page);
  assert.deepEqual(listed.map((r) => [r.current, r.when === 'Current', r.approx]), [[true, true, false], [false, false, false], [false, false, true]],
    `${label}: three versions, the first upload's time an estimate: ${JSON.stringify(listed)}`);
  assert.match(listed[1].text, /^until .*replaced by laptop.*written .* by laptop$/);
  assert.equal(await page.isHidden('#versions-restore'), true, 'the current version needs no command');
  assert.equal(await page.isHidden('#viewer-chip'), true);
  // The panel is part of the dialog: what is behind stays inert.
  assert.equal(await page.evaluate(() => document.getElementById('versions').closest('#viewer') !== null && document.getElementById('main').inert), true);
  const addresses = new Set([await page.getAttribute('#viewer-download', 'href')]);
  for (const [at, bytes] of [[1, notes[1]], [2, notes[0]]]) {
    await page.locator('#versions-list button').nth(at).click();
    await preText(page, bytes);
    listed = await versionRows(page);
    assert.deepEqual(listed.map((r) => r.current), [0, 1, 2].map((i) => i === at));
    assert.equal(await page.textContent('#viewer-chip'), 'Earlier version');
    assert.equal(await page.isVisible('#viewer-chip'), true);
    // Download and "open in a new tab" act on the version that is shown.
    const saved = await env.download(() => page.click('#viewer-download'));
    assert.deepEqual([saved.name, saved.bytes.equals(bytes)], ['notes.txt', true], `${label}: version ${at} downloaded`);
    addresses.add(await page.getAttribute('#viewer-download', 'href'));
    // The command that brings it back: one version, named by its id.
    await page.waitForSelector('#versions-restore:not([hidden])');
    assert.match(await page.textContent('#versions-cmd'), /^gclone restore :docs\/notes\.txt --version @[0-9a-f]{12}$/);
    assert.match(await page.textContent('#versions-how'), /^To bring this version back, on a device \(it is kept until /);
  }
  assert.equal(addresses.size, 3, 'every version has an address of its own');
  // Copy: to the clipboard, or — where the browser does not let a page write there — the
  // command is selected.
  const command = await page.textContent('#versions-cmd');
  await page.click('#versions-copy');
  await page.waitForFunction(() => document.getElementById('versions-said').textContent !== '');
  const said = await page.textContent('#versions-said');
  if (said !== 'Copied.') {
    assert.equal(said, 'The command is selected: copy it.');
    assert.equal(await page.evaluate(() => window.getSelection().toString()), command);
  }
  assert.equal(await page.getAttribute('#versions-said', 'role'), 'status');
  // By keyboard: the arrows move through the list (and do not turn the file's page), Enter
  // chooses, Escape closes the panel first — the focus returns to its button — then the file.
  await page.locator('#versions-list button').nth(2).focus();
  await page.keyboard.press('ArrowUp');
  await page.keyboard.press('ArrowUp');
  assert.equal(await page.evaluate(() => document.activeElement.textContent.startsWith('Current')), true);
  await page.keyboard.press('ArrowLeft');
  assert.equal(await page.$eval('#viewer-name', (n) => n.title), 'notes.txt', 'an arrow in the list belongs to the list');
  await page.keyboard.press('Enter');
  await preText(page, notes[2]);
  await page.waitForSelector('#viewer-chip', { state: 'hidden' });
  await page.keyboard.press('Escape');
  assert.equal(await page.isHidden('#versions'), true);
  assert.equal(await page.isVisible('#viewer'), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'viewer-versions');
  await page.keyboard.press('Escape');
  await page.waitForSelector('#viewer', { state: 'hidden' });
  // A file that never changed: one version, and words for it.
  await openFile(page, 'report.pdf');
  await openVersions(page);
  assert.equal((await versionRows(page)).length, 1);
  assert.match(await page.textContent('#versions-note'), /^No earlier versions are kept\. Replaced and deleted versions are kept for 25 days\.$/);
  await page.click('#versions-close');
  await closeFile(page);
  if (env.state) assert.deepEqual(await env.state(), { dir: 'docs', depth: 1, began: false }, 'the place of the present is what it always was');

  // ---- what was deleted from a folder ---------------------------------------------------------
  assert.equal(await page.getAttribute('#gone-btn', 'aria-pressed'), 'false');
  assert.deepEqual(await names(page), ['empty.txt', 'notes.txt', 'page.html', 'README.md', 'report.pdf']);
  await page.click('#gone-btn');
  await page.waitForSelector('#rows .row.sep');
  assert.equal(await page.getAttribute('#gone-btn', 'aria-pressed'), 'true');
  let drawn = await rows(page);
  assert.deepEqual(drawn.map((r) => (r.sep ? '—' : r.name)), ['empty.txt', 'notes.txt', 'page.html', 'README.md', 'report.pdf', '—', 'long.txt']);
  assert.equal(drawn[5].text, 'Deleted from this folder · kept for 25 days');
  const gone = drawn[6];
  assert.equal(gone.gone, true);
  assert.match(gone.mark, /^deleted .+ by laptop$/);
  assert.equal(gone.said, 'Deleted file: ', 'said in words, not by colour alone');
  assert.equal(await count(page), '6 items, 1 of them deleted');
  // The keyboard passes over the line between the sections.
  await page.focus('#list');
  for (let i = 0; i < 7; i += 1) await page.keyboard.press('ArrowDown');
  assert.equal(await page.$eval('#rows .row.active .name', (n) => n.title), 'long.txt');
  await page.keyboard.press('ArrowUp');
  assert.equal(await page.$eval('#rows .row.active .name', (n) => n.title), 'report.pdf');
  // A deleted file opens on its last version, with the versions beside it and the command.
  await openFile(page, 'long.txt');
  await page.waitForSelector('#viewer-body pre');
  await page.waitForSelector('#versions-list button');
  assert.equal(await page.textContent('#viewer-chip'), 'Earlier version');
  assert.match(await page.textContent('#versions-note'), /^Deleted .+ by laptop\.$/);
  listed = await versionRows(page);
  assert.deepEqual(listed.map((r) => [r.current, r.when.startsWith('until ')]), [[true, true]]);
  assert.match(await page.textContent('#versions-cmd'), /^gclone restore :docs\/long\.txt --version @[0-9a-f]{12}$/);
  const long = stages[2].files.get('docs/long.txt');
  const saved = await env.download(() => page.click('#viewer-download'));
  assert.deepEqual([saved.name, saved.bytes.equals(long)], ['long.txt', true], `${label}: the deleted file downloaded`);
  if (env.state) {
    const state = await env.state();
    assert.match(state.v, /^[0-9a-f]{12}$/);
    assert.deepEqual(state, { file: 'docs/long.txt', v: state.v, depth: 2, began: false });
  }
  await page.click('#versions-close');
  await closeFile(page);
  // At the root: a deleted folder with the number of its files, and the file that was moved away.
  await toRoot(page, 'now');
  await page.waitForSelector('#rows .row.sep');
  // A folder from which nothing was deleted says so: the switch is not one that does nothing.
  await enter(page, 'bin', 'now');
  await page.waitForFunction(() => /^\d+ items? · nothing deleted in the last 25 days$/.test(document.getElementById('count').textContent));
  assert.equal(await page.$('#rows .row.sep'), null);
  await toRoot(page, 'now');
  await page.waitForSelector('#rows .row.sep');
  // The switch says what it is in words (short ones on a phone), and by its name.
  assert.deepEqual(await page.$eval('#gone-btn', (b) => [b.getAttribute('aria-label'), [...b.querySelectorAll('span')].filter((s) => getComputedStyle(s).display !== 'none').map((s) => s.textContent)]), ['Show deleted', ['Show deleted']]);
  drawn = await rows(page);
  assert.deepEqual(drawn.filter((r) => r.gone).map((r) => [r.name, r.mark.replace(/^deleted .+ by /, 'deleted … by '), r.said]),
    [['deep', 'deleted · 2 files', 'Deleted folder: '], ['README.md', 'deleted … by laptop', 'Deleted file: ']]);
  assert.equal(await count(page), `${drawn.length - 1} items, 2 of them deleted`);
  // The deleted folder: what is kept of it, the command, the moment to see it at.
  await clickRow(page, 'deep');
  await page.waitForSelector('#gone-note:not([hidden])');
  await page.waitForFunction(() => document.getElementById('count').textContent === '1 deleted item');
  assert.equal(await crumb(page), 'deep');
  assert.equal(await page.$eval('#crumbs [aria-current] .sr', (n) => n.textContent), 'Deleted folder: ');
  assert.equal(await page.textContent('#gone-text'), 'This folder was deleted. Its files are kept for a while: on a device, gclone restore -r :deep brings them back.');
  assert.equal(await page.isHidden('#gone-btn'), true, 'nothing but deleted rows here');
  assert.deepEqual((await rows(page)).map((r) => [r.name, r.gone, r.mark]), [['a', true, 'deleted · 2 files']]);
  // (How deep in the browser's history the entry is depends on the way here: not compared.)
  const placed = async () => {
    const { depth, ...place } = await env.state();
    assert.ok(Number.isInteger(depth) && depth > 0);
    return place;
  };
  if (env.state) assert.deepEqual(await placed(), { dir: 'deep', gone: true, began: false });
  const folderCommand = await page.textContent('#gone-cmd');
  await page.click('#gone-copy');
  await page.waitForFunction(() => /^(Copied\.|The command is selected: copy it\.)$/.test(document.getElementById('notice-text').textContent));
  // "See it as it was": the last moment at which it held something.
  assert.match(await page.textContent('#gone-then'), /^See it as it was on /);
  await page.click('#gone-then');
  await shows(page, folderRemoved - 1);
  assert.deepEqual(await names(page), ['a']);
  assert.equal(await page.isHidden('#gone-note'), true);
  assert.equal(await page.isHidden('#gone-btn'), true, 'the switch belongs to the present');
  if (env.state) assert.deepEqual(await placed(), { dir: 'deep', at: folderRemoved - 1, began: false });
  // "Back to now" inside a folder that is gone now: what is kept of it — asked for first, so
  // that no request for a folder that is not there is made (and logged by the browser).
  await page.click('#time-now');
  await shows(page, 'now');
  await page.waitForSelector('#gone-note:not([hidden])');
  await page.waitForFunction(() => document.getElementById('count').textContent === '1 deleted item');
  assert.equal(await crumb(page), 'deep');
  if (env.state) assert.deepEqual(await placed(), { dir: 'deep', gone: true, began: false }, 'the place says that the folder is a deleted one');
  await page.click('#gone-then');
  await shows(page, folderRemoved - 1);
  assert.deepEqual(await names(page), ['a']);

  // ---- the past --------------------------------------------------------------------------------
  // Said in words, in every place that describes the list.
  const marked = () => page.evaluate(() => ({
    past: document.documentElement.classList.contains('past'),
    label: document.getElementById('time-label').textContent,
    count: document.getElementById('count').textContent,
    grid: document.getElementById('list').getAttribute('aria-label'),
    search: document.getElementById('search').placeholder,
    summary: !document.getElementById('summary').hidden,
    bar: !document.getElementById('time').hidden,
    now: !document.getElementById('time-now').hidden,
    close: !document.getElementById('time-close').hidden,
    said: document.getElementById('time-said').textContent,
    value: document.getElementById('time-range').getAttribute('aria-valuetext'),
  }));
  let state = await marked();
  assert.deepEqual([state.past, state.summary, state.bar, state.now, state.close], [true, false, true, true, false], JSON.stringify(state));
  assert.match(state.label, /^The vault as of .+ \(.+ ago\)$/);
  assert.match(state.count, /^As of .+ · 1 item$/);
  assert.match(state.grid, /^Files and folders as of /);
  assert.match(state.search, /^Search the vault as of /);
  assert.match(state.said, /^Showing the vault as of /);
  assert.match(state.value, / ago\)$/);
  assert.equal(await page.textContent('#time-step'), 'just before: laptop, 2 files replaced or removed');
  // The bar's button does not close it in the past: it leads to the slider.
  await page.click('#time-btn');
  assert.equal(await page.isVisible('#time'), true);
  assert.equal(await page.evaluate(() => document.activeElement.id), 'time-range');
  // A later moment, at which the folder was gone: the place stays, and says so.
  assert.match(await page.getAttribute('#time-next', 'aria-label'), /^Later change: .+ — laptop, 1 file replaced or removed$/);
  await page.click('#time-next');
  await shows(page, moved - 1);
  await page.waitForSelector('#empty:not([hidden])');
  assert.match(await page.textContent('#empty-title'), /^“deep” was not there on /);
  assert.match(await count(page), /^As of .+ · this folder was not there$/);
  assert.equal(await crumb(page), 'deep');
  assert.match(await page.textContent('#empty-open'), /^Open “.+”$/);
  // An earlier one brings it back, in the same place.
  await page.click('#time-prev');
  await shows(page, folderRemoved - 1);
  assert.deepEqual(await names(page), ['a']);
  await page.click('#time-next');
  await shows(page, moved - 1);
  const fromAbsent = await lists(page);
  await page.click('#empty-open');
  await loaded(page, fromAbsent, moved - 1);
  assert.equal((await page.$$('#crumbs li')).length, 1);
  // Before the move: the README is at the root (and says that it is not there any more).
  drawn = await rows(page);
  assert.deepEqual(drawn.filter((r) => r.mark).map((r) => [r.name, r.mark]), [['README.md', 'deleted since']]);
  assert.ok(!drawn.some((r) => r.name === 'deep' || r.name === 'plans'));

  // The step buttons, back through the changes; rows say what became of them.
  for (const [at, what] of [[folderRemoved - 1, /2 files replaced or removed$/], [removed - 1, /1 file replaced or removed$/], [third - 1, /2 files replaced or removed$/]]) {
    assert.match(await page.getAttribute('#time-prev', 'aria-label'), what);
    await page.click('#time-prev');
    await shows(page, at);
  }
  drawn = await rows(page);
  assert.deepEqual(drawn.filter((r) => r.mark).map((r) => [r.name, r.mark]), [['deep', 'deleted since'], ['README.md', 'deleted since']]);
  assert.deepEqual(drawn.map((r) => r.name).sort(), top(stages[1].files));
  await enter(page, 'docs', third - 1);
  drawn = await rows(page);
  assert.deepEqual(drawn.map((r) => [r.name, r.mark]), [['empty.txt', ''], ['long.txt', 'deleted since'], ['notes.txt', 'changed since'], ['page.html', ''], ['report.pdf', '']]);
  if (env.state) assert.deepEqual(await placed(), { dir: 'docs', at: third - 1, began: false });
  // A file then: the version of then, marked with its moment, and saved as that version.
  await openFile(page, 'notes.txt');
  await preText(page, notes[1]);
  assert.match(await page.textContent('#viewer-chip'), /^as of /);
  const then = await env.download(() => page.click('#viewer-download'));
  assert.deepEqual([then.name, then.bytes.equals(notes[1])], ['notes.txt', true]);
  await openVersions(page);
  listed = await versionRows(page);
  assert.deepEqual(listed.map((r) => [r.current, r.then]), [[false, false], [true, true], [false, false]], 'the version of the moment shown is marked');
  await page.click('#versions-close');
  await closeFile(page);
  // A search then finds what was there then.
  await page.fill('#search', 'leaf');
  await page.waitForFunction(() => /^As of .+ · 1 match$/.test(document.getElementById('count').textContent));
  drawn = await rows(page);
  assert.deepEqual(drawn.map((r) => [r.name, r.mark]), [['leaf.txt', 'deleted since']]);
  await openFile(page, 'leaf.txt');
  await preText(page, 'at the bottom\n');
  await closeFile(page);
  let before = await lists(page);
  await page.fill('#search', '');
  await loaded(page, before, third - 1);
  assert.equal(await crumb(page), 'docs');

  // One way back: the button — and the focus returns to the list.
  await page.click('#time-now');
  await shows(page, 'now');
  state = await marked();
  assert.deepEqual([state.past, state.summary, state.bar, state.now, state.close, state.label, state.value], [false, true, true, false, true, 'Now', 'Now']);
  assert.equal(state.said, 'Showing the vault as it is now.');
  assert.equal(state.grid, 'Files and folders');
  assert.equal(state.search, 'Search the vault');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'list');
  assert.equal(await crumb(page), 'docs');
  await page.fill('#search', 'leaf');
  await page.waitForFunction(() => document.getElementById('count').textContent === '0 matches');
  assert.equal(await page.textContent('#empty-title'), 'Nothing found');
  before = await lists(page);
  await page.fill('#search', '');
  await loaded(page, before, 'now');

  // By keyboard alone. The slider: an hour per arrow key, a day per page key; its label
  // follows at once, the list when it rests. An hour ago this vault did not exist yet.
  await toRoot(page, 'now');
  await page.focus('#time-btn');
  assert.equal(await page.getAttribute('#time-btn', 'aria-expanded'), 'true');
  await page.keyboard.press('Enter'); // closes the bar: it is open, and this is now
  assert.equal(await page.isHidden('#time'), true);
  assert.equal(await page.getAttribute('#time-btn', 'aria-expanded'), 'false');
  await page.keyboard.press('Enter');
  await page.waitForSelector('#time:not([hidden])');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'time-range', 'opening the bar puts the focus on the slider');
  assert.deepEqual(await page.$eval('#time-range', (r) => [r.type, r.min, r.max, r.value, r.getAttribute('aria-label')]), ['range', '0', '600', '600', 'Moment shown']);
  await page.keyboard.press('ArrowLeft');
  assert.equal(await page.$eval('#time-range', (r) => r.value), '599');
  assert.match(await page.textContent('#time-label'), /^The vault as of /);
  await page.waitForSelector('html.past');
  await page.waitForFunction(() => /^\d+$/.test(document.getElementById('list').dataset.at) && document.getElementById('count').textContent !== '');
  const hourAgo = Number(await page.$eval('#list', (l) => l.dataset.at));
  assert.ok(Math.abs(hourAgo - (Date.now() - 3600000)) < 400000, `${label}: one step is one hour`);
  assert.match(await count(page), /^As of .+ · 0 items$/);
  assert.equal(await page.textContent('#empty-title'), 'The vault was empty');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'time-range', 'the focus stays on the slider while it moves');
  await page.keyboard.press('PageDown');
  assert.equal(await page.$eval('#time-range', (r) => r.value), '575');
  await page.keyboard.press('PageUp');
  assert.equal(await page.$eval('#time-range', (r) => r.value), '599');
  await page.keyboard.press('Home');
  assert.equal(await page.$eval('#time-range', (r) => r.value), '0');
  await page.waitForFunction((from) => Math.abs(Number(document.getElementById('list').dataset.at) - from) < 600000, timeline.from_ms);
  // The slider's right end is now.
  await page.keyboard.press('End');
  await shows(page, 'now');
  assert.equal(await page.$eval('#time-range', (r) => r.value), '600');
  // (The deleted section is still switched on: its rows follow the folder's.)
  assert.deepEqual((await rows(page)).filter((r) => !r.sep && !r.gone).map((r) => r.name).sort(), top(current));
  // Tab order in the past: "Back to now" comes first in the bar.
  await page.click('#time-prev');
  await page.waitForSelector('html.past');
  assert.equal(await page.evaluate(() => {
    const bar = document.getElementById('time');
    const first = [...bar.querySelectorAll('button, input')].find((node) => !node.hidden && !node.disabled && node.offsetParent !== null);
    return first.id;
  }), 'time-now');
  assert.equal(await page.getAttribute('#time-now', 'aria-label'), 'Back to now');
  // Entering the past was one step of the browser's history; moving in it none: Back is now.
  await page.click('#time-prev');
  await shows(page, moved - 1);
  await page.goBack();
  await shows(page, 'now');
  // The date field: a moment to the minute.
  const minute = Math.floor((third - 1) / 60000) * 60000;
  assert.equal(await page.$eval('#time-when', (w) => w.type), 'datetime-local');
  await page.fill('#time-when', await page.evaluate((ms) => {
    const d = new Date(ms);
    const two = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}T${two(d.getHours())}:${two(d.getMinutes())}`;
  }, minute));
  await page.locator('#time-when').blur();
  await shows(page, minute);
  const atMinute = await env.api('list', { path: '', at: String(minute) });
  assert.deepEqual(await names(page), atMinute.entries.map((e) => e.name));
  await page.click('#time-now');
  await shows(page, 'now');

  // ---- a moment chosen while a long list is loading ----------------------------------------------
  // The list of the moment that nobody waits for any more ends with the request that is on
  // its way — not with its last page — and the moment chosen meanwhile is shown.
  await enter(page, 'many', 'now');
  const slow = await env.slowLists(600);
  const firstAt = late[0] - 1;
  await page.click('#time-prev');
  await page.waitForFunction((at) => document.getElementById('list').dataset.at === String(at) && /loaded…$/.test(document.getElementById('count').textContent), firstAt);
  await page.click('#time-prev');
  await shows(page, moved - 1);
  const asked = await slow.calls();
  await slow.stop();
  const stale = asked.filter(([at]) => at === String(firstAt)).map(([, offset]) => offset);
  assert.deepEqual(stale, ['0', '2000'], `${label}: the first page and the one on its way, and no third: ${JSON.stringify(asked)}`);
  assert.deepEqual(asked.filter(([at]) => at === String(moved - 1)).map(([, offset]) => offset), ['0', '2000', '4000']);
  assert.match(await count(page), new RegExp(`^As of .+ · ${MANY.toLocaleString('en-US')} items$`));
  await page.click('#time-now');
  await shows(page, 'now');
  await toRoot(page, 'now');

  // ---- the commands the page shows, run in a shell ----------------------------------------------
  // A name with a quote, a space and markup in it: the command restores exactly that version.
  const odd = past.odd;
  assert.equal(odd.path, `names/${ODD_NAMES[1]}`);
  await enter(page, 'names', 'now');
  await openFile(page, ODD_NAMES[1]);
  await openVersions(page);
  await page.locator('#versions-list button').nth(1).click();
  await preText(page, odd.versions[0]);
  await page.waitForSelector('#versions-restore:not([hidden])');
  const oddCommand = await page.textContent('#versions-cmd');
  assert.ok(oddCommand.startsWith("gclone restore ':names/it'\\''s "), oddCommand);
  await page.click('#versions-close');
  await closeFile(page);
  assert.ok(vault.device.run('cat', `:${odd.path}`).equals(odd.versions[1]));
  assert.match(runShown(env, oddCommand), /^Restored :names\//);
  assert.ok(vault.device.run('cat', `:${odd.path}`).equals(odd.versions[0]), `${label}: the command restored the earlier version`);
  // The deleted folder: its command brings back what was under it.
  assert.equal(folderCommand, 'gclone restore -r :deep');
  assert.match(runShown(env, folderCommand), /^Restored 2 files/);
  assert.ok(vault.device.run('cat', ':deep/a/b/c/d/leaf.txt').equals(Buffer.from('at the bottom\n')));
  // The viewer changed nothing by itself: after a refresh it shows what the commands did.
  await page.click('#refresh');
  await page.waitForFunction(() => /^(Refreshed: |Up to date\.)/.test(document.getElementById('notice-text').textContent));
  await toRoot(page, 'now');
  await page.waitForFunction(() => [...document.querySelectorAll('#rows .row:not(.sep)')].some((r) => !r.classList.contains('gone') && r.querySelector('.name').title === 'deep'));
  // The switch for the deleted section is this page's memory: it is still on.
  assert.equal(await page.getAttribute('#gone-btn', 'aria-pressed'), 'true');
  await page.click('#gone-btn');
  await page.waitForFunction(() => !document.querySelector('#rows .row.sep'));
  await page.click('#time-close');
  assert.equal(await page.isHidden('#time'), true);
}

/** What the phone-sized page is to show as well: a folder that is deleted (the one restored above goes again). */
export function beforePhone(vault) {
  vault.device.run('rm', '-r', ':deep');
}

/** The same page in a phone-sized window: nothing scrolls sideways, and a thumb can use the bar and the sheet. */
export async function timeMachinePhone(page, label) {
  const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth && document.body.scrollWidth <= window.innerWidth);
  assert.equal(await page.evaluate(() => window.innerWidth), 390);
  // The switch for the deleted section keeps a word, and its name.
  assert.deepEqual(await page.$eval('#gone-btn', (b) => [b.getAttribute('aria-label'), [...b.querySelectorAll('span')].filter((s) => getComputedStyle(s).display !== 'none').map((s) => s.textContent)]), ['Show deleted', ['Deleted']]);
  // A deleted folder: the sentence with its command is readable, and the list has its room.
  await page.click('#gone-btn');
  await page.waitForSelector('#rows .row.sep');
  await clickRow(page, 'deep');
  await page.waitForSelector('#gone-note:not([hidden])');
  await page.waitForFunction(() => document.getElementById('count').textContent === '1 deleted item');
  const note = await page.evaluate(() => {
    const box = (id) => document.getElementById(id).getBoundingClientRect();
    return { text: box('gone-text').width, note: box('gone-note').height, rows: document.getElementById('rows').clientHeight, command: document.getElementById('gone-cmd').textContent };
  });
  assert.ok(note.text > 250 && note.note < 220 && note.rows > 150, `${label}: the note of a deleted folder on a phone: ${JSON.stringify(note)}`);
  assert.equal(note.command, 'gclone restore -r :deep');
  assert.equal(await fits(), true, `${label}: a deleted folder fits a phone`);
  let back = await lists(page);
  await page.click('#crumbs li:first-child a');
  await loaded(page, back, 'now');
  await page.click('#gone-btn');
  await page.waitForFunction(() => !document.querySelector('#rows .row.sep'));
  await page.click('#time-btn');
  await page.waitForFunction(() => !document.getElementById('time-prev').disabled);
  await page.click('#time-prev');
  await page.waitForSelector('html.past');
  await page.waitForFunction(() => /^\d+$/.test(document.getElementById('list').dataset.at));
  assert.equal(await fits(), true, `${label}: the past fits a phone`);
  const boxes = await page.evaluate(() => ['time-now', 'time-prev', 'time-next', 'time-range', 'time-when'].map((id) => {
    const box = document.getElementById(id).getBoundingClientRect();
    return [id, Math.round(box.height), box.left >= 0 && box.right <= window.innerWidth];
  }));
  for (const [id, height, inside] of boxes) {
    assert.ok(height >= 44, `${label}: #${id} is ${height}px high`);
    assert.ok(inside, `${label}: #${id} is inside the window`);
  }
  // "Back to now" is short here, and still says what it is.
  assert.deepEqual(await page.evaluate(() => {
    const button = document.getElementById('time-now');
    const seen = [...button.children].filter((node) => getComputedStyle(node).display !== 'none').map((node) => node.textContent);
    return [seen, button.getAttribute('aria-label')];
  }), [['Now'], 'Back to now']);
  // Rows say what became of them on their second line.
  const before = await lists(page);
  await clickRow(page, 'docs');
  await page.waitForFunction((n) => Number(document.getElementById('list').dataset.n || 0) > n && /item/.test(document.getElementById('count').textContent), before);
  assert.equal(await crumb(page), 'docs');
  assert.equal(await fits(), true);
  // The versions: a sheet under the file, at most most of the screen, scrolling inside.
  await clickRow(page, 'notes.txt');
  await page.waitForSelector('#viewer-body pre');
  // The chip names the moment, all of it: a line under the bar, over nothing of the file,
  // and the title keeps to the bar's height.
  const chip = await page.evaluate(() => {
    const node = document.getElementById('viewer-chip');
    const box = node.getBoundingClientRect();
    const title = document.querySelector('.viewer-title').getBoundingClientRect();
    const bar = document.querySelector('.viewer-bar').getBoundingClientRect();
    const body = document.getElementById('viewer-body').getBoundingClientRect();
    return {
      text: node.textContent,
      whole: node.scrollWidth <= node.clientWidth,
      under: Math.abs(box.top - bar.bottom) <= 1.5 && box.left >= 0 && box.right <= window.innerWidth + 0.5,
      clear: body.top >= box.bottom - 0.5,
      fits: title.height <= bar.height,
      boxes: [Math.round(box.width), Math.round(box.height), Math.round(title.height), Math.round(bar.height)],
    };
  });
  assert.match(chip.text, /^as of .*\d[:.]\d\d/, `${label}: the moment: ${chip.text}`);
  assert.deepEqual([chip.whole, chip.under, chip.clear, chip.fits], [true, true, true, true], `${label}: the chip on a phone: ${JSON.stringify(chip)}`);
  await page.click('#viewer-versions');
  await page.waitForSelector('#versions-list button');
  const sheet = await page.evaluate(() => {
    const box = document.getElementById('versions').getBoundingClientRect();
    const body = document.getElementById('viewer-body').getBoundingClientRect();
    return { top: box.top, height: box.height, width: box.width, bodyBottom: body.bottom, overflow: getComputedStyle(document.getElementById('versions')).overflowY, window: [window.innerWidth, window.innerHeight] };
  });
  assert.ok(sheet.height <= sheet.window[1] * 0.6 + 1, `${label}: the sheet is ${sheet.height}px of ${sheet.window[1]}`);
  assert.ok(Math.abs(sheet.width - sheet.window[0]) < 1 && sheet.top >= sheet.bodyBottom - 1 && sheet.overflow === 'auto', JSON.stringify(sheet));
  assert.equal(await fits(), true, `${label}: the versions fit a phone`);
  await page.click('#versions-close');
  await page.click('#viewer-close');
  await page.waitForSelector('#viewer', { state: 'hidden' });
  // A low window (the phone on its side): in the past the bar cannot be closed, so it keeps
  // short — the list has room for three rows at least, and the way back stays in sight.
  await page.setViewportSize({ width: 844, height: 390 });
  await page.waitForFunction(() => window.innerHeight === 390 && !document.getElementById('list').classList.contains('two-line'));
  const low = await page.evaluate(() => ({
    rows: document.getElementById('rows').clientHeight,
    row: document.querySelector('#rows .row').getBoundingClientRect().height,
    bar: document.getElementById('time').getBoundingClientRect().height,
    now: document.getElementById('time-now').getBoundingClientRect(),
    range: document.getElementById('time-range').getBoundingClientRect().width,
    label: document.getElementById('time-label').getBoundingClientRect().width,
  }));
  assert.ok(low.rows >= 3 * low.row, `${label}: a low window leaves ${low.rows}px for rows of ${low.row}px (the bar takes ${low.bar}px)`);
  assert.ok(low.now.width > 0 && low.now.bottom <= 390 && low.range > 100 && low.label > 100, JSON.stringify(low));
  assert.equal(await fits(), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => window.innerHeight === 844);
  back = await lists(page);
  await page.click('#time-now');
  await page.waitForSelector('html:not(.past)');
  await loaded(page, back, 'now');
}
