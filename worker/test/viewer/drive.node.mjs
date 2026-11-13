// drive.js against the fake Drive, in Node (`node --test`): the request shapes, paging, and
// the CLI's error rules (SPEC §6.5).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { loadViewer } from './env.mjs';
import { makeVault } from './fixture.mjs';

const { gclone } = loadViewer();
let v;
let root;
let indexId;
let blob; // one data blob: { id, name, size, file }

before(async () => {
  v = await makeVault({ 'a.txt': 'alpha\n', 'b/c.txt': 'gamma\n', 'big.bin': Buffer.alloc(300000, 7) });
  root = v.drive.idOf('gclone');
  indexId = v.drive.idOf('gclone/index');
  blob = v.drive.objects().filter((o) => !o.folder && /^[0-9a-f]{32}$/.test(o.name)).sort((a, b) => b.size - a.size)[0];
});
after(() => v.close());

test('every listing sends pageSize=1000, the field list, spaces=drive and trashed = false', async () => {
  v.drive.resetLog();
  const children = await v.viewerDrive.children(root);
  assert.deepEqual(children.map((c) => c.name).sort(), fs.readdirSync(path.join(v.vaultDir, 'gclone')).sort());
  const named = await v.viewerDrive.named('gclone-vault.json');
  assert.equal(named.length, 1);
  assert.equal(named[0].parent, root);
  assert.equal(v.drive.log.lists.length, 2);
  for (const list of v.drive.log.lists) {
    assert.equal(list.pageSize, '1000');
    assert.equal(list.fields, 'nextPageToken,files(id,name,size,createdTime,mimeType,parents)');
    assert.equal(list.spaces, 'drive');
    assert.match(list.q, / and trashed = false$/);
  }
  assert.equal(v.drive.log.lists[0].q, `'${root}' in parents and trashed = false`);
  assert.equal(v.drive.log.lists[1].q, "name = 'gclone-vault.json' and trashed = false");
  // Shapes: sizes are numbers, folders are told apart, the creation time is Drive's text.
  const index = children.find((c) => c.name === 'index');
  assert.deepEqual([index.folder, index.size, index.id], [true, 0, indexId]);
  const descriptor = children.find((c) => c.name === 'gclone-vault.json');
  assert.equal(descriptor.size, fs.statSync(path.join(v.vaultDir, 'gclone/gclone-vault.json')).size);
  assert.match(descriptor.createdTime, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
});

test('a listing follows nextPageToken to the end', async () => {
  v.drive.pageMax = 2;
  v.drive.resetLog();
  try {
    const children = await v.viewerDrive.children(root);
    assert.equal(children.length, fs.readdirSync(path.join(v.vaultDir, 'gclone')).length);
    assert.ok(v.drive.log.lists.length >= 3, `${v.drive.log.lists.length} pages`);
    assert.deepEqual(v.drive.log.lists.map((l) => l.pageToken), [null, 'page-2', 'page-4'].slice(0, v.drive.log.lists.length));
  } finally {
    v.drive.pageMax = 1000;
  }
});

test('a quote or a backslash in a name cannot leave the query', async () => {
  v.drive.resetLog();
  assert.deepEqual(await v.viewerDrive.named("it's a \\ name' or name != '"), []);
  assert.equal(v.drive.log.lists[0].q, "name = 'it\\'s a \\\\ name\\' or name != \\'' and trashed = false");
});

test('the token travels in the Authorization header only; 401 → one fresh token, one retry', async () => {
  const seen = [];
  const drive = (await import('./env.mjs')).driveFor(v.drive.origin, v.token, { onFetch: (url, init) => seen.push({ url, init }) });
  await v.token.get(false);
  v.drive.tokens.clear(); // what the viewer holds is no longer accepted
  const forced = v.token.state.forced;
  v.drive.resetLog();
  const meta = await drive.meta(root);
  assert.equal(meta.name, 'gclone');
  assert.equal(v.token.state.forced, forced + 1, 'one forced refresh');
  assert.equal(v.drive.log.unauthorized, 1);
  assert.equal(seen.length, 2);
  for (const { url, init } of seen) {
    assert.ok(!/token|Bearer/i.test(url), url);
    assert.match(init.headers.Authorization, /^Bearer tok-\d+$/);
    assert.equal(init.cache, undefined, 'the default cache mode (no-store would repeat every preflight in Chrome)');
    assert.equal(init.credentials, undefined);
  }
  // A store that refuses the fresh token too: the sign-in is over, and it is said once.
  const dead = (await import('./env.mjs')).driveFor(v.drive.origin, { get: async () => 'never-accepted' });
  await assert.rejects(dead.meta(root), (e) => e instanceof gclone.DriveError && e.kind === 'auth');
});

test('rate limits and 5xx are retried with a growing pause; too many give up', async () => {
  v.sleeps.length = 0;
  v.drive.rateLimitNext = 2;
  assert.equal((await v.viewerDrive.meta(root)).name, 'gclone');
  assert.deepEqual(v.sleeps, [1000, 2000]);
  v.sleeps.length = 0;
  v.drive.failNext = 3;
  assert.equal((await v.viewerDrive.meta(root)).name, 'gclone');
  assert.deepEqual(v.sleeps, [1000, 2000, 4000]);
  v.sleeps.length = 0;
  v.drive.rateLimitNext = 100;
  await assert.rejects(v.viewerDrive.meta(root), (e) => e.kind === 'rate');
  assert.deepEqual(v.sleeps, [1000, 2000, 4000, 8000, 16000]);
  v.drive.rateLimitNext = 0;
});

test('a read that someone is waiting for gives up within its patience; offline, a failed request is not repeated', async () => {
  const { driveFor } = await import('./env.mjs');
  const sleeps = [];
  const sleep = async (ms) => { sleeps.push(ms); };
  // Ten seconds of patience: pauses of 1, 2 and 4 s; the fourth (8 s) would pass it.
  const impatient = driveFor(v.drive.origin, v.token, { sleep, patience: 10000 });
  v.drive.rateLimitNext = 100;
  await assert.rejects(impatient.meta(root), (e) => e instanceof gclone.DriveError && e.kind === 'rate' && /limiting requests/.test(e.message));
  assert.deepEqual(sleeps, [1000, 2000, 4000]);
  v.drive.rateLimitNext = 0;
  sleeps.length = 0;
  v.drive.failNext = 100;
  await assert.rejects(impatient.meta(root), (e) => e.kind === 'unreachable' && /keeps failing/.test(e.message));
  assert.deepEqual(sleeps, [1000, 2000, 4000]);
  v.drive.failNext = 0;
  // What passes within it is retried as before.
  sleeps.length = 0;
  v.drive.failNext = 2;
  assert.equal((await impatient.meta(root)).name, 'gclone');
  assert.deepEqual(sleeps, [1000, 2000]);
  // The patience can be changed (the index load has the CLI's; a refresh has the short one).
  sleeps.length = 0;
  impatient.patience(Infinity);
  v.drive.rateLimitNext = 100;
  await assert.rejects(impatient.meta(root), (e) => e.kind === 'rate');
  assert.deepEqual(sleeps, [1000, 2000, 4000, 8000, 16000]);
  v.drive.rateLimitNext = 0;
  // Nothing listens at this address: the request itself fails.
  const nowhere = 'http://127.0.0.1:1';
  sleeps.length = 0;
  let asked = 0;
  const offline = driveFor(nowhere, v.token, { sleep, offline: () => true, onFetch: () => { asked += 1; } });
  await assert.rejects(offline.meta(root), (e) => e instanceof gclone.DriveError && e.kind === 'unreachable' && /offline/.test(e.message));
  assert.deepEqual([asked, sleeps], [1, []], 'offline: one request, no pause');
  // The browser does not say it is offline: the pauses of the patience, then the reason.
  asked = 0;
  const unreachable = driveFor(nowhere, v.token, { sleep, patience: 10000, onFetch: () => { asked += 1; } });
  await assert.rejects(unreachable.meta(root), (e) => e.kind === 'unreachable' && e.message === 'Google Drive does not answer. Check the connection and try again.');
  assert.deepEqual([asked, sleeps], [4, [1000, 2000, 4000]]);
  // A browser that says "offline" although the request succeeds is not believed.
  const wrong = driveFor(v.drive.origin, v.token, { sleep, offline: () => true });
  assert.equal((await wrong.meta(root)).name, 'gclone');
});

test('404 is "not found"; the object is then found by its name', async () => {
  v.drive.unknownIds.add(blob.id);
  try {
    await assert.rejects(v.viewerDrive.get(blob.id, blob.size), (e) => e instanceof gclone.DriveError && e.kind === 'not-found');
    await assert.rejects(v.viewerDrive.getRange(blob.id, 0, 10), (e) => e.kind === 'not-found');
    const hits = await v.viewerDrive.named(blob.name);
    assert.deepEqual(hits.map((h) => [h.id, h.size, h.folder]), [[blob.id, blob.size, false]]);
    // A listing of a folder that is gone is empty, as in the CLI.
    assert.deepEqual(await v.viewerDrive.children('no-such-folder'), []);
  } finally {
    v.drive.unknownIds.clear();
  }
});

test('the abuse flag: one retry with acknowledgeAbuse=true, on downloads only', async () => {
  v.drive.abusiveIds.add(blob.id);
  try {
    const bytes = await v.viewerDrive.get(blob.id, blob.size);
    assert.ok(Buffer.from(bytes).equals(fs.readFileSync(blob.file)));
    const res = await v.viewerDrive.getRange(blob.id, 5, 25);
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(fs.readFileSync(blob.file).subarray(5, 25)));
  } finally {
    v.drive.abusiveIds.clear();
  }
});

test('get() is bounded: a body longer than allowed is given up, not read', async () => {
  // By what the answer declares …
  await assert.rejects(v.viewerDrive.get(blob.id, blob.size - 1), (e) => e.kind === 'too-large');
  // … and by what arrives: a planted object whose listing lies about its size.
  v.drive.planted.push({ id: 'planted-1', name: 'planted', parent: root, size: 40 * 1024 * 1024, fill: 0 });
  v.drive.listedSize.set('planted', 1000);
  v.drive.resetLog();
  try {
    const listed = (await v.viewerDrive.children(root)).find((c) => c.name === 'planted');
    assert.equal(listed.size, 1000);
    await assert.rejects(v.viewerDrive.get(listed.id, listed.size), (e) => e.kind === 'too-large');
    assert.ok(v.drive.log.bytes < 8 * 1024 * 1024, `the fake Drive sent ${v.drive.log.bytes} bytes before the viewer hung up`);
    // Within its bound an object is read whole, with its progress counted.
    let counted = 0;
    const bytes = await v.viewerDrive.get(blob.id, blob.size, (n) => { counted += n; });
    assert.equal(bytes.length, blob.size);
    assert.equal(counted, blob.size);
  } finally {
    v.drive.planted.length = 0;
    v.drive.listedSize.clear();
  }
});

test('getRange(): exactly the bytes asked for, as a 206', async () => {
  v.drive.resetLog();
  const res = await v.viewerDrive.getRange(blob.id, 100, 70000);
  assert.equal(res.status, 206);
  assert.ok(Buffer.from(await res.arrayBuffer()).equals(fs.readFileSync(blob.file).subarray(100, 70000)));
  assert.deepEqual(v.drive.log.gets.map((g) => g.range), [[100, 70000]]);
});
