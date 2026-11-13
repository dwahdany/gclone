// loader.js over the fake Drive, in Node (`node --test`): finding the vault, the keyfile
// candidates, and loading and refreshing the index — against vaults the native binary wrote,
// and against what an unauthenticated listing can claim.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { loadViewer } from './env.mjs';
import { foreignKeyfile } from '../e2e/vault.mjs';
import { PASS, lsRecursive, makeVault, unlock } from './fixture.mjs';

const { gclone, core } = loadViewer();
const { loader } = gclone;
const MIB = 1024 * 1024;
const contentGets = (drive) => drive.log.gets.map((g) => g.name);

describe('a young vault (segments only)', () => {
  let v;
  let session;
  let index;
  before(async () => {
    v = await makeVault({ 'a.txt': 'alpha\n', 'docs/b.txt': 'beta\n', 'docs/deep/c.bin': Buffer.alloc(200000, 3), 'empty-dir-holder/x': '' });
    session = await unlock(v.viewerDrive);
    index = loader.createIndex({ core, drive: v.viewerDrive, vault: session.vault, folder: session.opened.index });
  });
  after(() => v.close());

  test('discover and open: the root, its two folders, one keyfile with the CLI\'s cost', () => {
    assert.equal(session.found.vaults.length, 1);
    assert.deepEqual([session.found.unreadable, session.found.damaged], [0, 0]);
    const found = session.found.vaults[0];
    assert.equal(found.root, v.drive.idOf('gclone'));
    assert.equal(found.folder, 'gclone');
    assert.match(found.vault_id, /^[0-9a-f]{32}$/);
    assert.equal(session.opened.index, v.drive.idOf('gclone/index'));
    assert.equal(session.opened.data, v.drive.idOf('gclone/data'));
    assert.equal(session.opened.candidates.length, 1);
    const [candidate] = session.opened.candidates;
    assert.deepEqual(candidate.cost, { gen: 1, m_kib: 262144, t: 3, p: 1 });
    assert.deepEqual([session.opened.refused, session.opened.newer, session.opened.unseen], [0, 0, 0]);
    assert.equal(loader.expensive(candidate.cost), false);
    assert.equal(loader.expensive({ m_kib: 262145, t: 3 }), true);
    assert.equal(loader.expensive({ m_kib: 262144, t: 4 }), true);
  });

  test('load: no snapshot is listed, the tree comes from the segments and equals `gclone ls -R :`', async () => {
    v.drive.resetLog();
    const events = [];
    const hooked = loader.createIndex({
      core, drive: v.viewerDrive, vault: session.vault, folder: session.opened.index,
      hooks: { begin: (total) => events.push(['begin', total]), end: () => events.push(['end']), progress: (p) => events.push(['progress', p.phase, p.done, p.total]) },
    });
    const report = await hooked.load();
    index = hooked;
    assert.equal(report.snapshot, null);
    assert.deepEqual([report.blocked, report.missing, report.corrupt], [[], [], []]);
    assert.deepEqual(lsRecursive(session.vault), v.device.lines('ls', '-R', ':'));
    assert.equal(report.head, v.device.head());
    assert.deepEqual(index.state().ok, true);
    assert.equal(index.state().note, null);
    assert.equal(index.state().applied, report.applied);
    // What was fetched: the segments, each bounded by its listed size, and nothing else.
    const listed = fs.readdirSync(path.join(v.vaultDir, 'gclone/index'));
    assert.deepEqual(contentGets(v.drive).sort(), listed.sort());
    const total = listed.reduce((sum, name) => sum + fs.statSync(path.join(v.vaultDir, 'gclone/index', name)).size, 0);
    assert.deepEqual(events[0], ['begin', total]);
    assert.deepEqual(events.at(-1), ['end']);
    assert.deepEqual(events.filter((e) => e[0] === 'progress').at(-1), ['progress', 'segments', total, total]);
    // The summary the page shows.
    const info = JSON.parse(session.vault.info(JSON.stringify(index.state())));
    assert.deepEqual([info.backend, info.device, info.read_only, info.head], ['drive', 'this browser', true, report.head]);
  });

  test('a refresh over an unchanged listing requests no object', async () => {
    v.drive.resetLog();
    assert.deepEqual(await index.refresh(), { reload: false });
    assert.deepEqual(contentGets(v.drive), []);
    assert.equal(v.drive.log.lists.length, 1);
    assert.deepEqual([index.state().ok, index.state().applied, index.state().note], [true, 0, null]);
    await index.refresh();
    assert.deepEqual(contentGets(v.drive), []);
  });

  test('a refresh after a new upload fetches the new segments only', async () => {
    const before = new Set(fs.readdirSync(path.join(v.vaultDir, 'gclone/index')));
    v.write({ 'new/uploaded.txt': 'just arrived\n' });
    const fresh = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((name) => !before.has(name));
    assert.ok(fresh.length >= 1);
    v.drive.resetLog();
    await index.refresh();
    assert.deepEqual(contentGets(v.drive).sort(), fresh.sort());
    assert.equal(index.state().applied, fresh.length);
    assert.deepEqual(lsRecursive(session.vault), v.device.lines('ls', '-R', ':'));
    assert.equal(index.report().head, v.device.head());
  });

  test('a segment the listing does not show yet is fetched by the id its successor names', async () => {
    const mine = await unlock(v.viewerDrive);
    const names = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((n) => n.startsWith('s-')).sort();
    assert.ok(names.length >= 2);
    // Hide every segment but the newest: its predecessors are known by their ids only.
    for (const name of names.slice(0, -1)) v.drive.hidden.add(name);
    v.drive.resetLog();
    try {
      const lagging = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
      const report = await lagging.load();
      if (report.blocked.length === 0) {
        assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
        assert.ok(v.drive.log.metas.length >= 1, 'the missing segments were looked up by id');
      } else {
        // The chain was longer than three rounds follow: the vault is shown without them, and it says so.
        assert.equal(lagging.state().ok, false);
        assert.match(lagging.state().note, /cannot be read yet/);
      }
      assert.ok(v.drive.log.metas.every((m) => m.id !== ''), 'never an empty id');
    } finally {
      v.drive.hidden.clear();
      mine.vault.free();
    }
  });

  test('damage in the listing: a planted segment, an object above 16 MiB alone, one above 1 GiB not at all', async () => {
    const mine = await unlock(v.viewerDrive);
    const real = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((n) => n.startsWith('s-')).sort().at(-1);
    const [, device, seq] = /^s-([0-9a-f]{16})-([0-9a-f]{16})-/.exec(real);
    const next = (n) => (BigInt(`0x${seq}`) + BigInt(n)).toString(16).padStart(16, '0');
    const indexId = mine.opened.index;
    v.drive.planted.push(
      { id: 'planted-small', name: `s-${device}-${next(1)}-00000001`, parent: indexId, size: 5000, fill: 1 },
      { id: 'planted-large', name: `s-${device}-${next(2)}-00000002`, parent: indexId, size: 17 * MIB, fill: 2 },
      { id: 'planted-huge', name: `s-${device}-${next(3)}-00000003`, parent: indexId, size: 2048 * MIB, fill: 3 },
    );
    v.drive.resetLog();
    try {
      const planted = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: indexId });
      const report = await planted.load();
      const gets = v.drive.log.gets;
      assert.ok(!gets.some((g) => g.id === 'planted-huge'), 'an object above INDEX_OBJECT_MAX is never requested');
      const large = gets.find((g) => g.id === 'planted-large');
      assert.ok(large, 'the 17 MiB object was fetched');
      assert.equal(large.others, 0, 'and alone');
      assert.equal(large.bytes, 17 * MIB);
      assert.ok(gets.some((g) => g.id === 'planted-small'));
      // The real state is shown, and the damage is named.
      assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
      assert.equal(report.head, v.device.head());
      assert.match(planted.state().note, /Damaged index objects: /);
      assert.match(planted.state().note, /larger than an index object can be/);
      assert.equal(planted.state().ok, false, 'damage is said, although nothing is blocked');
    } finally {
      v.drive.planted.length = 0;
      mine.vault.free();
    }
  });

  test('a refresh never downloads more than 64 MiB: a planted segment is left where it is, and said', async () => {
    const mine = await unlock(v.viewerDrive);
    const indexId = mine.opened.index;
    const questions = [];
    const quietly = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: indexId, hooks: { confirm: async (q) => { questions.push(q); return 'load'; } } });
    await quietly.load();
    const head = quietly.report().head;
    const real = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((n) => n.startsWith('s-')).sort().at(-1);
    const [, device, seq] = /^s-([0-9a-f]{16})-([0-9a-f]{16})-/.exec(real);
    const next = (n) => (BigInt(`0x${seq}`) + BigInt(n)).toString(16).padStart(16, '0');
    try {
      // One object of 70 MiB: over the bound by itself.
      v.drive.planted.push({ id: 'planted-70', name: `s-${device}-${next(1)}-0badc0de`, parent: indexId, size: 70 * MIB, fill: 3 });
      v.drive.resetLog();
      assert.deepEqual(await quietly.refresh(), { reload: false });
      assert.deepEqual(contentGets(v.drive), [], 'nothing was downloaded');
      assert.deepEqual(questions, [], 'and nobody was asked: the list is on the screen');
      assert.equal(quietly.state().ok, false);
      assert.match(quietly.state().note, /^1 new index object \(70 MiB\) was not loaded: a refresh downloads no more than 64 MiB without asking\. Lock the vault and unlock it again to decide\.$/);
      assert.equal(quietly.report().head, head);
      // Many small ones that add up: what fits within 64 MiB is fetched (and found to be junk), the rest is left.
      v.drive.planted.length = 0;
      for (let i = 1; i <= 7; i += 1) v.drive.planted.push({ id: `planted-${i}`, name: `s-${device}-${next(i)}-0badc0d${i}`, parent: indexId, size: 12 * MIB, fill: i });
      v.drive.resetLog();
      await quietly.refresh();
      const fetched = v.drive.log.gets.filter((g) => g.id.startsWith('planted-'));
      assert.equal(fetched.length, 5, 'five of 12 MiB are 60 MiB; a sixth would pass 64 MiB');
      assert.ok(fetched.reduce((sum, g) => sum + g.bytes, 0) <= 64 * MIB);
      assert.match(quietly.state().note, /2 new index objects \(24 MiB\) were not loaded/);
      assert.match(quietly.state().note, /Damaged index objects: /);
      assert.equal(quietly.report().head, head);
      // A new upload next to the planted object still arrives.
      v.drive.planted.length = 0;
      v.drive.planted.push({ id: 'planted-70', name: `s-${device}-${next(9)}-0badc0de`, parent: indexId, size: 70 * MIB, fill: 3 });
      v.write({ 'beside/the-planted-one.txt': 'still arrives\n' });
      v.drive.resetLog();
      await quietly.refresh();
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'planted-70'));
      assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
      assert.equal(quietly.report().head, v.device.head());
      // The load that can ask does ask (on the next unlock).
      const again = await unlock(v.viewerDrive);
      const asked = [];
      const loud = loader.createIndex({ core, drive: v.viewerDrive, vault: again.vault, folder: indexId, hooks: { confirm: async (q) => { asked.push(q); return 'skip'; } } });
      v.drive.resetLog();
      await loud.load();
      assert.equal(asked.length, 1);
      assert.equal(asked[0].big.size, 70 * MIB);
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'planted-70'));
      again.vault.free();
    } finally {
      v.drive.planted.length = 0;
      mine.vault.free();
    }
  });

  test('a name out of the listing is shown only if it is a name gclone gives; the folder\'s name is cut', async () => {
    const mine = await unlock(v.viewerDrive);
    const sentence = 'SECURITY NOTICE — your session was moved. Sign in again at https://gclone-viewer.example/unlock and enter your passphrase';
    v.drive.planted.push(
      { id: 'planted-sentence', name: sentence, parent: mine.opened.index, size: 2048 * MIB, fill: 1 },
      { id: 'planted-named', name: 's-ffffffffffffffff-0000000000000001-0badc0de', parent: mine.opened.index, size: 2048 * MIB, fill: 1 },
    );
    try {
      const index = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
      await index.load();
      const note = index.state().note;
      assert.ok(!/SECURITY|session|Sign in|passphrase|https/.test(note), note);
      assert.match(note, /an object that is not gclone's \(2,048 MiB\): larger than an index object can be/);
      assert.match(note, /s-ffffffffffffffff-0000000000000001-0badc0de: larger than an index object can be/);
      await index.refresh();
      assert.ok(!/SECURITY|passphrase|https/.test(index.state().note), index.state().note);
    } finally {
      v.drive.planted.length = 0;
      mine.vault.free();
    }
    // Text that is shown although someone else chose it: one line, 64 characters.
    assert.equal(loader.screenText('gclone', 64), 'gclone');
    assert.equal(loader.screenText('x'.repeat(65), 64), `${'x'.repeat(64)}…`);
    assert.equal(loader.screenText('a\nb\u202ec\u0000d\u2028e', 64), 'a b c d e');
    assert.equal(loader.screenText('日本語'.repeat(30), 64).length, 65);
    const longName = `Sign in again at https://gclone-viewer.example/unlock ${'and enter your passphrase '.repeat(8)}`;
    v.drive.planted.push(
      { id: 'd-long', name: 'gclone-vault.json', parent: 'folder-long', size: 0, bytes: Buffer.from(JSON.stringify({ ...JSON.parse(fs.readFileSync(path.join(v.vaultDir, 'gclone/gclone-vault.json'), 'utf8')), vault_id: 'ef'.repeat(16) })) },
      { id: 'folder-long', name: longName, parent: 'root-of-my-drive', size: 0, folder: true },
    );
    v.drive.planted[0].size = v.drive.planted[0].bytes.length;
    try {
      const found = await loader.discover(core, v.viewerDrive);
      const folder = found.vaults.find((x) => x.root === 'folder-long').folder;
      assert.equal(folder, `${longName.slice(0, 64)}…`);
    } finally {
      v.drive.planted.length = 0;
    }
  });

  test('a listed size that lies makes an object damage, not memory', async () => {
    const mine = await unlock(v.viewerDrive);
    const names = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).sort();
    v.drive.listedSize.set(names[0], 10);
    v.drive.resetLog();
    try {
      const lied = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
      const report = await lied.load();
      assert.match(lied.state().note, new RegExp(`${names[0]}: longer than listed`));
      assert.ok(report.blocked.length > 0 || report.missing.length > 0 || report.files >= 0);
      assert.equal(lied.state().ok, false);
    } finally {
      v.drive.listedSize.clear();
      mine.vault.free();
    }
  });
});

describe('a vault with a snapshot', () => {
  let v;
  let snapshot;
  before(async () => {
    v = await makeVault({ 'one.txt': '1\n', 'dir/two.txt': '2\n' }, { repair: true });
    v.write({ 'after/three.txt': '3\n' });
    snapshot = fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((n) => n.startsWith('c-')).sort().at(-1);
    assert.ok(snapshot, '`gclone repair` wrote a snapshot');
  });
  after(() => v.close());

  test('the newest snapshot is loaded, then the segments it leaves', async () => {
    const mine = await unlock(v.viewerDrive);
    v.drive.resetLog();
    const index = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
    const report = await index.load();
    assert.equal(report.snapshot, snapshot);
    assert.equal(contentGets(v.drive)[0], snapshot);
    assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
    assert.equal(report.head, v.device.head());
    mine.vault.free();
  });

  test('an index above 64 MiB asks first; a planted object can be skipped, and is then never requested', async () => {
    const mine = await unlock(v.viewerDrive);
    const device = /^c-[0-9a-f]{16}-([0-9a-f]{16})-/.exec(snapshot)[1];
    const name = `c-ffffffffffffffff-${device}-0badc0de`;
    v.drive.planted.push({ id: 'planted-snapshot', name, parent: mine.opened.index, size: 70 * MIB, fill: 9 });
    v.drive.resetLog();
    const questions = [];
    try {
      const index = loader.createIndex({
        core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index,
        hooks: { confirm: async (question) => { questions.push(question); return 'skip'; } },
      });
      const report = await index.load();
      assert.deepEqual(questions, [{ total: 70 * MIB, big: { name, size: 70 * MIB } }]);
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'planted-snapshot'), 'the skipped object was not requested');
      assert.equal(report.snapshot, snapshot);
      assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
      assert.match(index.state().note, new RegExp(`Not loaded, as you chose: ${name}`));
      assert.equal(index.state().ok, false);
    } finally {
      mine.vault.free();
    }

    // "Load it": the object is downloaded (bounded by its listed size), turns out to be
    // damage, and the next snapshot is the one.
    const second = await unlock(v.viewerDrive);
    v.drive.resetLog();
    const asked = [];
    try {
      const index = loader.createIndex({
        core, drive: v.viewerDrive, vault: second.vault, folder: second.opened.index,
        hooks: { confirm: async (question) => { asked.push(question.total); return 'load'; } },
      });
      const report = await index.load();
      assert.deepEqual(asked, [70 * MIB]);
      assert.equal(v.drive.log.gets.find((g) => g.id === 'planted-snapshot').bytes, 70 * MIB);
      assert.equal(report.snapshot, snapshot);
      assert.equal(report.head, v.device.head());
    } finally {
      second.vault.free();
    }

    // "Cancel": nothing is downloaded and the load ends.
    const third = await unlock(v.viewerDrive);
    v.drive.resetLog();
    try {
      const index = loader.createIndex({ core, drive: v.viewerDrive, vault: third.vault, folder: third.opened.index, hooks: { confirm: async () => 'cancel' } });
      await assert.rejects(index.load(), (e) => e instanceof loader.LoadError && e.code === 'cancelled');
      assert.deepEqual(contentGets(v.drive), []);
    } finally {
      v.drive.planted.length = 0;
      third.vault.free();
    }
  });

  test('snapshots are listed and none can be read: the load stops, and no tree is shown', async () => {
    const mine = await unlock(v.viewerDrive);
    for (const name of fs.readdirSync(path.join(v.vaultDir, 'gclone/index')).filter((n) => n.startsWith('c-'))) v.drive.listedSize.set(name, 12);
    try {
      const index = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
      await assert.rejects(index.load(), (e) => e instanceof loader.LoadError && e.code === 'no-snapshot' && e.message.includes(snapshot));
      assert.equal(index.report(), null);
    } finally {
      v.drive.listedSize.clear();
      mine.vault.free();
    }
  });
});

describe('what the listing can claim about a vault', () => {
  let v;
  before(async () => { v = await makeVault({ 'x.txt': 'x\n' }); });
  after(() => v.close());

  test('descriptors: a newer format, damage, an oversized one, a second vault', async () => {
    const root = v.drive.idOf('gclone');
    const real = JSON.parse(fs.readFileSync(path.join(v.vaultDir, 'gclone/gclone-vault.json'), 'utf8'));
    v.drive.planted.push(
      { id: 'd-newer', name: 'gclone-vault.json', parent: 'folder-newer', size: 0, bytes: Buffer.from(JSON.stringify({ ...real, min_reader: 2, vault_id: 'ab'.repeat(16) })) },
      { id: 'd-junk', name: 'gclone-vault.json', parent: 'folder-junk', size: 0, bytes: Buffer.from('not json at all') },
      { id: 'd-huge', name: 'gclone-vault.json', parent: 'folder-huge', size: 70000, fill: 0x20 },
      { id: 'd-second', name: 'gclone-vault.json', parent: 'folder-second', size: 0, bytes: Buffer.from(JSON.stringify({ ...real, vault_id: 'cd'.repeat(16), created_ms: 1790000000000 })) },
      { id: 'folder-second', name: 'Second vault', parent: 'root-of-my-drive', size: 0, folder: true },
    );
    for (const planted of v.drive.planted) if (planted.bytes) planted.size = planted.bytes.length;
    v.drive.resetLog();
    try {
      const found = await loader.discover(core, v.viewerDrive);
      assert.deepEqual([found.unreadable, found.damaged], [1, 2]);
      assert.deepEqual(found.vaults.map((x) => [x.root, x.folder, x.vault_id, x.created_ms]).sort(), [
        ['folder-second', 'Second vault', 'cd'.repeat(16), 1790000000000],
        [root, 'gclone', real.vault_id, real.created_ms],
      ].sort());
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'd-huge'), 'a descriptor listed above 64 KiB is not fetched');
    } finally {
      v.drive.planted.length = 0;
    }
  });

  test('the root: exactly one index and one data folder, else an error that names the stray one', async () => {
    const root = v.drive.idOf('gclone');
    v.drive.planted.push({ id: 'stray-index', name: 'index', parent: root, size: 0, folder: true });
    try {
      await assert.rejects(loader.open(core, v.viewerDrive, root), (e) => e instanceof loader.LoadError && e.code === 'layout' && /two folders named index/.test(e.message));
    } finally {
      v.drive.planted.length = 0;
    }
    await assert.rejects(loader.open(core, v.viewerDrive, v.drive.idOf('gclone/index')), (e) => e.code === 'layout' && /no folder named index/.test(e.message));
  });

  test('keyfiles: what is no keyfile is refused before any derivation, and takes no place among the candidates', async () => {
    const root = v.drive.idOf('gclone');
    const real = fs.readdirSync(path.join(v.vaultDir, 'gclone')).find((n) => n.startsWith('gclone-key-'));
    v.drive.planted.push(
      { id: 'k-junk', name: 'gclone-key-00000009-0badc0de', parent: root, size: 300, fill: 7 },
      { id: 'k-huge', name: 'gclone-key-00000008-0badc0de', parent: root, size: 70000, fill: 7 },
      { id: 'k-other', name: 'gclone-key-0000000z-0badc0de', parent: root, size: 300, fill: 7 },
    );
    v.drive.resetLog();
    try {
      const opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates.map((c) => [c.name, c.bytes.length > 0, c.cost.gen]), [[real, true, 1]]);
      assert.deepEqual([opened.refused, opened.newer, opened.unseen], [2, 0, 0]);
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'k-huge'), 'a keyfile listed above 64 KiB is not fetched');
      assert.ok(!v.drive.log.gets.some((g) => g.id === 'k-other'), 'a name that is no keyfile name is not fetched');
      // The planted ones lock nobody out.
      const session = await unlock(v.viewerDrive, PASS);
      session.vault.free();
    } finally {
      v.drive.planted.length = 0;
    }
  });

  test('keyfiles: four planted names of higher generations do not push the real keyfile out — nor do thirty', async () => {
    const root = v.drive.idOf('gclone');
    const real = fs.readdirSync(path.join(v.vaultDir, 'gclone')).find((n) => n.startsWith('gclone-key-'));
    const junk = (n) => Array.from({ length: n }, (_, i) => ({ id: `junk-key-${i}`, name: `gclone-key-${(0x10 + i).toString(16).padStart(8, '0')}-0badc0de`, parent: root, size: 300, fill: 7 }));
    try {
      // Four: the number the core names at a time (the CLI's KEYFILE_TRY_MAX).
      v.drive.planted.push(...junk(4));
      let opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates.map((c) => c.name), [real]);
      assert.deepEqual([opened.refused, opened.unseen], [4, 0]);
      (await unlock(v.viewerDrive, PASS)).vault.free();
      // Thirty-one: all looked at (32 objects of at most 64 KiB), the real one among them.
      v.drive.planted.length = 0;
      v.drive.planted.push(...junk(31));
      v.drive.resetLog();
      opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates.map((c) => c.name), [real]);
      assert.deepEqual([opened.refused, opened.unseen], [31, 0]);
      assert.equal(v.drive.log.gets.length, 32);
      // Beyond that the viewer stops looking, and says how many it did not look at.
      v.drive.planted.length = 0;
      v.drive.planted.push(...junk(40));
      v.drive.resetLog();
      opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates, []);
      assert.deepEqual([opened.refused, opened.unseen], [32, 9]);
      assert.equal(v.drive.log.gets.length, loader.KEYFILE_LOOK_MAX);
      // Planted names that claim to be large cost no request at all.
      v.drive.planted.length = 0;
      v.drive.planted.push(...junk(200).map((object) => ({ ...object, size: 70000 })));
      v.drive.resetLog();
      opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates.map((c) => c.name), [real]);
      assert.equal(v.drive.log.gets.length, 1);
    } finally {
      v.drive.planted.length = 0;
    }
  });

  test('keyfiles: well-formed keyfiles of another vault are candidates like any — in order, the real one after them', async () => {
    const root = v.drive.idOf('gclone');
    const real = fs.readdirSync(path.join(v.vaultDir, 'gclone')).find((n) => n.startsWith('gclone-key-'));
    const foreign = foreignKeyfile(v.work);
    v.drive.planted.push(...[9, 8, 7, 6].map((g) => ({ id: `foreign-key-${g}`, name: foreign.name(g), parent: root, size: foreign.bytes.length, bytes: foreign.bytes })));
    try {
      const opened = await loader.open(core, v.viewerDrive, root);
      assert.deepEqual(opened.candidates.map((c) => c.name), [...[9, 8, 7, 6].map((g) => foreign.name(g)), real]);
      assert.deepEqual([opened.refused, opened.unseen], [0, 0]);
      // The owner's passphrase is wrong for each of the four, and opens the fifth: the candidate
      // loop (kdf-worker.js) goes on to it when it is asked to try the others too.
      const vaultId = (await loader.discover(core, v.viewerDrive)).vaults[0].vault_id;
      const outcomes = [];
      for (const candidate of opened.candidates) {
        try {
          core.unlock(candidate.name, candidate.bytes, PASS, vaultId);
          outcomes.push('opened');
        } catch (error) {
          outcomes.push(loader.codeOf(error));
        }
      }
      assert.deepEqual(outcomes, ['wrong-passphrase', 'wrong-passphrase', 'wrong-passphrase', 'wrong-passphrase', 'opened']);
    } finally {
      v.drive.planted.length = 0;
    }
  });
});

describe('the loader\'s own rules, with a core that says what the test wants', () => {
  const fakeDrive = (objects) => {
    const calls = [];
    return {
      calls,
      children: async () => objects,
      meta: async (id) => { calls.push(['meta', id]); throw new gclone.DriveError('not-found', 'gone'); },
      get: async (id) => { calls.push(['get', id]); return new Uint8Array(4); },
    };
  };
  const fakeVault = (reports, extra = {}) => ({
    snapshot_candidates: () => '[]',
    needed_segments: () => '[]',
    add_segment: () => true,
    load_snapshot: () => true,
    finish: () => JSON.stringify(reports.length > 1 ? reports.shift() : reports[0]),
    ...extra,
  });
  const report = (over) => ({ snapshot: null, applied: 1, blocked: [], missing: [], corrupt: [], files: 1, dirs: 0, bytes: 1, conflicts: 0, head: 'h', vault_name: 'v', ...over });

  test('a missing reference without a file id is never requested, and is reported', async () => {
    const drive = fakeDrive([]);
    const index = loader.createIndex({ core, drive, vault: fakeVault([report({ blocked: ['s-x'], missing: [['dev', 4, 'hash', ''], ['dev', 5, 'hash', '']] })]), folder: 'f' });
    const result = await index.load();
    assert.deepEqual(drive.calls, []);
    assert.equal(result.blocked.length, 1);
    assert.deepEqual([index.state().ok, /1 change set of other devices cannot be read yet/.test(index.state().note)], [false, true]);
  });

  test('a missing reference with an id is asked once, in at most three rounds', async () => {
    const drive = fakeDrive([]);
    let n = 0;
    drive.meta = async (id) => { drive.calls.push(['meta', id]); return { id, name: `s-00000000000000aa-000000000000000${id.slice(-1)}-0badc0de`, size: 4, folder: false, createdTime: '2026-11-01T00:00:00.000Z' }; };
    // Every round names a new predecessor: the chain is followed three times, then it stops.
    const vault = fakeVault([], { finish: () => { n += 1; return JSON.stringify(report({ blocked: ['s-x'], missing: [['dev', 9 - n, 'hash', `id-${n}`]] })); } });
    const index = loader.createIndex({ core, drive, vault, folder: 'f' });
    await index.load();
    assert.deepEqual(drive.calls.filter((c) => c[0] === 'meta').map((c) => c[1]), ['id-1', 'id-2', 'id-3']);
    assert.equal(n, 4);
  });

  test('what an id leads to is bounded like a listing: a name that is no index object\'s is not fetched, a large one is asked about or left', async () => {
    const missing = (id) => report({ blocked: ['s-x'], missing: [['dev', 4, 'hash', id]] });
    const named = (name, size) => async (id) => ({ id, name, size, folder: false, createdTime: '' });
    const good = 's-00000000000000aa-0000000000000004-0badc0de';
    // A sentence under the id: never fetched, never shown.
    let drive = fakeDrive([]);
    drive.meta = named('Your session was moved: enter your passphrase at https://example.invalid', 4);
    let index = loader.createIndex({ core, drive, vault: fakeVault([missing('id-1')]), folder: 'f' });
    await index.load();
    assert.deepEqual(drive.calls, []);
    assert.ok(!/passphrase|https/.test(index.state().note), index.state().note);
    // 70 MiB under the id, while loading: asked about; "skip" leaves it.
    drive = fakeDrive([]);
    drive.meta = named(good, 70 * MIB);
    const questions = [];
    index = loader.createIndex({ core, drive, vault: fakeVault([missing('id-1')]), folder: 'f', hooks: { confirm: async (q) => { questions.push(q); return 'skip'; } } });
    await index.load();
    assert.deepEqual(questions, [{ total: 70 * MIB, big: { name: good, size: 70 * MIB } }]);
    assert.deepEqual(drive.calls, []);
    // … and in a refresh, where nobody can be asked: left, and said.
    drive = fakeDrive([]);
    drive.meta = named(good, 70 * MIB);
    index = loader.createIndex({ core, drive, vault: fakeVault([missing('id-1')]), folder: 'f', hooks: { confirm: async () => { throw new Error('asked during a refresh'); } } });
    await index.refresh();
    assert.deepEqual(drive.calls, []);
    assert.match(index.state().note, /1 new index object \(70 MiB\) was not loaded/);
    // Above an index object's size: never, in either.
    drive = fakeDrive([]);
    drive.meta = named(good, 2048 * MIB);
    index = loader.createIndex({ core, drive, vault: fakeVault([missing('id-1')]), folder: 'f' });
    await index.load();
    assert.deepEqual(drive.calls, []);
    assert.match(index.state().note, /larger than an index object can be/);
  });

  test('a newer format anywhere stops the load with one sentence', async () => {
    const newer = () => { throw new Error('needs-newer: index object x is in a format this gclone cannot read'); };
    for (const extra of [{ finish: newer }, { needed_segments: () => '["s-a"]', add_segment: newer }, { snapshot_candidates: () => '["c-a"]', load_snapshot: newer }]) {
      const objects = [{ id: '1', name: 's-a', size: 4, folder: false, createdTime: '' }, { id: '2', name: 'c-a', size: 4, folder: false, createdTime: '' }];
      const index = loader.createIndex({ core, drive: fakeDrive(objects), vault: fakeVault([report({})], extra), folder: 'f' });
      await assert.rejects(index.load(), (e) => e instanceof loader.LoadError && e.code === 'needs-newer' && e.message === 'This vault needs a newer viewer.');
    }
  });

  test('segments stay blocked while a newer snapshot is listed: the refresh asks for a fresh load', async () => {
    const objects = [{ id: '1', name: 'c-new', size: 4, folder: false, createdTime: '' }];
    const vault = fakeVault([report({ snapshot: 'c-old', blocked: ['s-b'] })], { snapshot_candidates: () => '["c-new"]' });
    const index = loader.createIndex({ core, drive: fakeDrive(objects), vault, folder: 'f' });
    assert.deepEqual(await index.refresh(), { reload: true });
    // … unless the newer snapshot is a download someone has to be asked about: the loaded state stays, with a note.
    const large = [{ id: '1', name: 'c-new', size: 70 * MIB, folder: false, createdTime: '' }];
    const kept = loader.createIndex({ core, drive: fakeDrive(large), vault: fakeVault([report({ snapshot: 'c-old', blocked: ['s-b'] })], { snapshot_candidates: () => '["c-new"]' }), folder: 'f' });
    assert.deepEqual(await kept.refresh(), { reload: false });
    assert.match(kept.state().note, /The index was rewritten on the store \(70 MiB\), which a refresh does not download without asking\. Lock the vault and unlock it again to load it\./);
    // The fresh load a refresh starts is quiet too: a snapshot above the bound is left, and the load says why it ends.
    const quiet = loader.createIndex({ core, drive: fakeDrive(large), vault: fakeVault([report({})], { snapshot_candidates: () => '["c-new"]' }), folder: 'f', hooks: { confirm: async () => { throw new Error('asked'); } } });
    await assert.rejects(quiet.load({ quiet: true }), (e) => e instanceof loader.LoadError && e.code === 'no-snapshot' && /too large to load without asking/.test(e.message));
    // Blocked, and the snapshot in use is the newest one: nothing to gain from a reload.
    const same = fakeVault([report({ snapshot: 'c-new', blocked: ['s-b'] })], { snapshot_candidates: () => '["c-new"]' });
    assert.deepEqual(await loader.createIndex({ core, drive: fakeDrive(objects), vault: same, folder: 'f' }).refresh(), { reload: false });
  });

  test('two objects under one name: the first the core takes is the one', async () => {
    const objects = [
      { id: 'impostor', name: 's-a', size: 4, folder: false, createdTime: '' },
      { id: 'real', name: 's-a', size: 4, folder: false, createdTime: '' },
    ];
    const drive = fakeDrive(objects);
    const taken = [];
    const vault = fakeVault([report({})], { needed_segments: () => '["s-a"]', add_segment: () => { taken.push(drive.calls.at(-1)[1]); return taken.length === 2; } });
    await loader.createIndex({ core, drive, vault, folder: 'f' }).load();
    assert.deepEqual(taken, ['impostor', 'real']);
  });
});

describe('ten thousand files', () => {
  let v;
  before(async () => {
    const files = {};
    for (let i = 0; i < 10000; i += 1) files[`d${String(i % 40).padStart(2, '0')}/s${i % 7}/file-${i}.txt`] = `n${i}\n`;
    v = await makeVault(files, { repair: true });
  });
  after(() => v.close());

  test('the index loads and its tree equals `gclone ls -R :`', async () => {
    const mine = await unlock(v.viewerDrive);
    const index = loader.createIndex({ core, drive: v.viewerDrive, vault: mine.vault, folder: mine.opened.index });
    const report = await index.load();
    assert.equal(report.files, 10000);
    assert.deepEqual(lsRecursive(mine.vault), v.device.lines('ls', '-R', ':'));
    assert.equal(report.head, v.device.head());
    mine.vault.free();
  });
});
