// gclone viewer — finding a vault on Drive and loading its index. Runs in the vault worker.
//
// No gclone logic lives here: which keyfiles, which snapshots, which segments and which bytes
// are the core's decisions (`core` is the wasm module). This file fetches what the core names
// and bounds what an unauthenticated listing can make the tab do:
//   SMALL_MAX           descriptor and keyfiles
//   KEYFILE_LOOK_MAX    keyfile-named objects that are fetched and looked at
//   INDEX_OBJECT_MAX    an index object larger than this is not requested at all
//   INDEX_PARALLEL_MAX  larger index objects are fetched one at a time
//   INDEX_CONFIRM       above this much index to download, the person is asked first — and
//                       where nobody can be asked (a refresh), no more than this is downloaded
// (SMALL_MAX and the two after KEYFILE_LOOK_MAX are the CLI's values, `src/consts.rs`).
//
// A listing is also text that someone else chose. No name out of it is shown unless it has
// the form of a name gclone gives (hex digits and dashes: it cannot be a sentence), and the
// one free text that is shown, the vault folder's name, is cut short.
'use strict';
(() => {
  const gclone = (self.gclone = self.gclone || {});
  const KIB = 1024;
  const MIB = 1024 * KIB;
  const SMALL_MAX = 64 * KIB;
  const INDEX_PARALLEL_MAX = 16 * MIB;
  const INDEX_OBJECT_MAX = 1024 * MIB;
  const INDEX_CONFIRM = 64 * MIB;
  const KEYFILE_LOOK_MAX = 32;
  const FOLDER_NAME_MAX = 64; // characters of the vault folder's name on a screen
  const PARALLEL = 6;
  const MISSING_ROUNDS = 3;
  const DESCRIPTOR = 'gclone-vault.json';
  // What a keyfile may ask for without a question: the CLI's own parameters.
  const KDF_M_KIB = 262144;
  const KDF_T = 3;
  const CODES = ['wrong-passphrase', 'damaged', 'other-vault', 'needs-newer', 'not-found', 'not-a-file', 'corrupt', 'bad-input'];
  const NEWER = 'This vault needs a newer viewer.';

  /** `code`: needs-newer | no-vault | layout | no-snapshot | cancelled. */
  class LoadError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'LoadError';
      this.code = code;
    }
  }

  /** The core throws `"<code>: <sentence>"`. `null`: not an error of the core's API. */
  function codeOf(error) {
    const match = /^([a-z-]+): /.exec(String(error && error.message));
    return match && CODES.includes(match[1]) ? match[1] : null;
  }
  const sentenceOf = (error) => String((error && error.message) || error).replace(/^[a-z-]+: /, '');
  /** A core call whose `needs-newer` ends the load. */
  function gate(call) {
    try {
      return call();
    } catch (error) {
      if (codeOf(error) === 'needs-newer') throw new LoadError('needs-newer', NEWER);
      throw error;
    }
  }
  const lost = (error) => error instanceof gclone.DriveError && (error.kind === 'too-large' || error.kind === 'not-found');
  const expensive = (cost) => !!cost && (cost.m_kib > KDF_M_KIB || cost.t > KDF_T);
  const mib = (bytes) => `${Math.max(1, Math.round(bytes / MIB)).toLocaleString('en-US')} MiB`;

  // The form of an index object's name (`s-<device>-<seq>-<h8>`, `c-<lamport>-<device>-<h8>`).
  // A rule for the screen, not for the vault: which objects are the vault's is the core's call.
  const INDEX_NAME = /^[cs]-[0-9a-fA-F]{16}-[0-9a-fA-F]{16}-[0-9a-fA-F]{8}$/;
  /** How an object of a listing is named on a screen: by its name only if that is a name gclone gives. */
  const label = (object) => (INDEX_NAME.test(object.name) ? object.name : `an object that is not gclone's (${mib(object.size)})`);
  /**
   * A text from a listing as it may be shown: one line, at most `max` characters; control
   * characters and the characters that turn text around are blanks.
   */
  function screenText(text, max) {
    const clean = Array.from(String(text).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' '));
    return clean.length > max ? `${clean.slice(0, max).join('')}…` : clean.join('');
  }

  /**
   * Step 1: every `gclone-vault.json` this sign-in sees. Returns
   * `{ vaults: [{ root, folder, vault_id, created_ms }], unreadable, damaged }` — `unreadable`
   * counts descriptors that ask for a newer reader.
   */
  async function discover(core, drive) {
    const vaults = [];
    let unreadable = 0;
    let damaged = 0;
    for (const hit of await drive.named(DESCRIPTOR)) {
      if (hit.folder) continue;
      if (!hit.parent || hit.size > SMALL_MAX) {
        damaged += 1;
        continue;
      }
      let descriptor;
      try {
        descriptor = JSON.parse(core.parse_descriptor(await drive.get(hit.id, SMALL_MAX)));
      } catch (error) {
        if (!lost(error) && codeOf(error) !== 'damaged') throw error;
        damaged += 1;
        continue;
      }
      if (!descriptor.readable) {
        unreadable += 1;
        continue;
      }
      vaults.push({ root: hit.parent, folder: '', vault_id: descriptor.vault_id, created_ms: descriptor.created_ms });
    }
    for (const vault of vaults) {
      // The folder's name is for the screen only — and it is whatever the account holds.
      try { vault.folder = screenText((await drive.meta(vault.root)).name, FOLDER_NAME_MAX); } catch (error) {
        if (!(error instanceof gclone.DriveError) || error.kind === 'auth') throw error;
      }
    }
    return { vaults, unreadable, damaged };
  }

  /**
   * Steps 2 and 3: the root's `index` and `data` folders, and the keyfiles with what each
   * would cost. Returns `{ index, data, candidates: [{ name, bytes, cost }], refused, newer,
   * unseen }`.
   *
   * `candidates` are the keyfiles that can be tried, highest generation first (the core's
   * order). An object under a keyfile's name that is no keyfile — junk, another name's
   * content, parameters out of bounds, larger than a keyfile can be — is refused here, before
   * any derivation, and takes no place among them: planted names of higher generations do not
   * push the real keyfile out. At most KEYFILE_LOOK_MAX objects are fetched (64 KiB each);
   * `unseen` counts the keyfile names beyond that, `refused` the objects that were refused,
   * `newer` those among them that a newer viewer could read.
   */
  async function open(core, drive, root) {
    const children = await drive.children(root);
    const folder = (name) => {
      const hits = children.filter((child) => child.folder && child.name === name);
      if (hits.length === 0) throw new LoadError('layout', `The vault's folder holds no folder named ${name}.`);
      if (hits.length > 1) {
        throw new LoadError('layout', `There are two folders named ${name} in the vault. Remove the stray one in drive.google.com.`);
      }
      return hits[0].id;
    };
    const index = folder('index');
    const data = folder('data');
    const pool = children.filter((child) => !child.folder);
    const candidates = [];
    let refused = 0;
    let newer = 0;
    let unseen = 0;
    let fetched = 0;
    for (;;) {
      // The core names the keyfiles among the names, four at a time, highest generation first.
      const names = JSON.parse(core.keyfile_candidates(JSON.stringify(pool.map((file) => file.name))));
      let taken = 0;
      for (const name of names) {
        // A name that is listed twice comes back twice: one object each.
        const at = pool.findIndex((file) => file.name === name);
        if (at < 0) continue;
        const [object] = pool.splice(at, 1);
        taken += 1;
        if (object.size > SMALL_MAX) {
          refused += 1; // a keyfile is small: not fetched
          continue;
        }
        if (fetched >= KEYFILE_LOOK_MAX) {
          unseen += 1;
          continue;
        }
        fetched += 1;
        try {
          const bytes = await drive.get(object.id, SMALL_MAX);
          candidates.push({ name, bytes, cost: JSON.parse(core.keyfile_cost(name, bytes)) });
        } catch (error) {
          const code = lost(error) ? 'damaged' : codeOf(error);
          if (!code) throw error;
          refused += 1;
          if (code === 'needs-newer') newer += 1;
        }
      }
      if (taken === 0) break;
    }
    return { index, data, candidates, refused, newer, unseen };
  }

  /**
   * Steps 5 and 6 over one unlocked `vault` (the core's `Vault`) and the id of its `index`
   * folder. `hooks.confirm({ total, big })` resolves to 'load', 'skip' (leave `big` out) or
   * anything else (give up); `hooks.progress({ phase, done, total })`; `hooks.begin(total)` /
   * `hooks.end()` bracket a download.
   *
   * Nothing above INDEX_CONFIRM is downloaded without a "load" from `confirm`. A pass that
   * cannot ask — `refresh()`, and `load({ quiet: true })`, the fresh load a refresh may need
   * while the file list is on the screen — downloads at most INDEX_CONFIRM in all and leaves
   * the rest where it is, with a note: an object planted in the listing costs a question or a
   * sentence, never the tab's memory.
   */
  function createIndex({ core, drive, vault, folder, hooks }) {
    const confirm = (hooks && hooks.confirm) || (async () => 'load');
    const progress = (hooks && hooks.progress) || (() => {});
    const begin = (hooks && hooks.begin) || (() => {});
    const end = (hooks && hooks.end) || (() => {});
    const now = (hooks && hooks.now) || (() => Date.now());
    /** Ids of objects the person chose not to load. */
    const skipped = new Map();
    /** Ids fetched for a `missing` reference: asked once. */
    const asked = new Set();
    /** id → size of the objects a quiet pass left where they are. */
    const deferred = new Map();
    let approved = 0;
    let quiet = false;
    /** Listed bytes this pass has asked of the store. */
    let spent = 0;
    let report = null;
    let state = { at_ms: 0, ok: false, applied: 0, note: null };
    /** What went wrong with single objects during the last pass: `"<name>: <why>"`. */
    let problems = [];
    /** Said in the note of a refresh that could not start over from a newer snapshot. */
    let newerBase = 0;

    function pass(silent) {
      problems = [];
      deferred.clear();
      spent = 0;
      quiet = silent;
      newerBase = 0;
    }

    async function listing() {
      const byName = new Map();
      for (const object of await drive.children(folder)) {
        if (object.folder || skipped.has(object.id)) continue;
        if (object.size > INDEX_OBJECT_MAX) {
          problems.push(`${label(object)}: larger than an index object can be`);
          continue;
        }
        if (!byName.has(object.name)) byName.set(object.name, []);
        byName.get(object.name).push(object);
      }
      return { byName, names: JSON.stringify([...byName.keys()]) };
    }

    /** An object's bytes, bounded by its listed size; `null` when it is not what was listed. */
    async function fetchObject(object, count) {
      try {
        return await drive.get(object.id, object.size, count);
      } catch (error) {
        if (!lost(error)) throw error;
        problems.push(`${label(object)}: ${error.kind === 'too-large' ? 'longer than listed' : 'gone from the store'}`);
        return null;
      }
    }

    /** Asks before more than INDEX_CONFIRM is downloaded. Returns 'skipped' when `big` was left out. */
    async function ask(total, objects) {
      if (total <= INDEX_CONFIRM || total <= approved) return 'load';
      const big = objects.find((object) => object.size * 2 > total) || null;
      const answer = await confirm({ total, big: big ? { name: label(big), size: big.size } : null });
      if (answer === 'skip' && big) {
        skipped.set(big.id, label(big));
        return 'skipped';
      }
      if (answer !== 'load') throw new LoadError('cancelled', 'The index was not loaded.');
      approved = total;
      return 'load';
    }

    /**
     * Whether `object` may be fetched now, beyond what was asked about before the download
     * began. A quiet pass: only within INDEX_CONFIRM in all — the object is left otherwise.
     */
    async function permit(object) {
      const total = spent + object.size;
      if (quiet) {
        if (total > INDEX_CONFIRM) {
          deferred.set(object.id, object.size);
          return false;
        }
      } else if ((await ask(total, [object])) !== 'load') {
        return false;
      }
      spent += object.size;
      return true;
    }

    /** Fetches the segments `names` and hands them to the core: large ones alone, the rest six at a time. */
    async function addSegments(names, byName, done, total) {
      let got = done;
      const count = (bytes) => {
        got += bytes;
        progress({ phase: 'segments', done: got, total });
      };
      const add = async (name) => {
        // Several objects may carry one name on Drive: the first the core takes is the one.
        for (const object of byName.get(name) || []) {
          // (Not quiet: the whole of this download was asked about before it began.)
          if (quiet) {
            if (!(await permit(object))) continue;
          } else {
            spent += object.size;
          }
          const bytes = await fetchObject(object, count);
          if (!bytes) continue;
          const created = core.parse_rfc3339_ms(object.createdTime);
          if (gate(() => vault.add_segment(name, bytes, created))) return;
        }
      };
      const sizeOf = (name) => Math.max(...(byName.get(name) || []).map((object) => object.size), 0);
      const large = names.filter((name) => sizeOf(name) > INDEX_PARALLEL_MAX);
      const small = names.filter((name) => sizeOf(name) <= INDEX_PARALLEL_MAX);
      let next = 0;
      const lane = async () => {
        while (next < small.length) {
          const name = small[next];
          next += 1;
          await add(name);
        }
      };
      await Promise.all(Array.from({ length: Math.min(PARALLEL, small.length) }, lane));
      for (const name of large) await add(name);
    }

    /** `finish()`, then the references the listing did not satisfy, by the id they carry. */
    async function finish() {
      let result = JSON.parse(gate(() => vault.finish()));
      for (let round = 0; round < MISSING_ROUNDS; round += 1) {
        // A reference without an id is never requested: `files/?alt=media` would be a listing.
        const ids = [...new Set(result.missing.map((reference) => reference[3]))]
          .filter((id) => typeof id === 'string' && id !== '' && !asked.has(id));
        let added = 0;
        for (const id of ids) {
          asked.add(id);
          let object;
          try {
            object = await drive.meta(id);
          } catch (error) {
            if (!lost(error)) throw error;
            continue;
          }
          if (object.folder || skipped.has(object.id)) continue;
          // What an id leads to is the store's to say: its name and its size are bounded as
          // those of a listing are.
          if (!INDEX_NAME.test(object.name)) continue;
          if (object.size > INDEX_OBJECT_MAX) {
            problems.push(`${label(object)}: larger than an index object can be`);
            continue;
          }
          if (!(await permit(object))) continue;
          const bytes = await fetchObject(object);
          if (!bytes) continue;
          gate(() => vault.add_segment(object.name, bytes, core.parse_rfc3339_ms(object.createdTime)));
          added += 1;
        }
        if (!added) break;
        result = JSON.parse(gate(() => vault.finish()));
      }
      return result;
    }

    function noteOf(result) {
      const parts = [];
      if (result.blocked.length) {
        const n = result.blocked.length;
        parts.push(`${n} change ${n === 1 ? 'set' : 'sets'} of other devices cannot be read yet: an earlier one is missing or damaged. The vault is shown without ${n === 1 ? 'it' : 'them'}.`);
      }
      if (deferred.size) {
        const n = deferred.size;
        const size = [...deferred.values()].reduce((sum, bytes) => sum + bytes, 0);
        parts.push(`${n} new index ${n === 1 ? 'object' : 'objects'} (${mib(size)}) ${n === 1 ? 'was' : 'were'} not loaded: a refresh downloads no more than ${mib(INDEX_CONFIRM)} without asking. Lock the vault and unlock it again to decide.`);
      }
      if (newerBase) {
        parts.push(`The index was rewritten on the store (${mib(newerBase)}), which a refresh does not download without asking. Lock the vault and unlock it again to load it.`);
      }
      const damaged = [...new Set([...result.corrupt, ...problems])];
      if (damaged.length) parts.push(`Damaged index objects: ${damaged.slice(0, 5).map((text) => screenText(text, 160)).join('; ')}${damaged.length > 5 ? '; …' : ''}.`);
      if (skipped.size) parts.push(`Not loaded, as you chose: ${[...skipped.values()].join(', ')}.`);
      return parts.length ? parts.join(' ') : null;
    }

    function settle(result, applied) {
      report = result;
      // `ok` is "everything the listing named was read": anything less comes with its note,
      // which the page shows when it starts and after every refresh.
      const note = noteOf(result);
      state = { at_ms: now(), ok: note === null, applied, note };
      return result;
    }

    /**
     * Step 5: a snapshot (newest readable), the segments it leaves, the report.
     * `options.quiet`: nobody can be asked (see above).
     */
    async function load(options) {
      pass(!!(options && options.quiet));
      let { byName, names } = await listing();
      const snapshots = JSON.parse(vault.snapshot_candidates(names));
      let accepted = null;
      for (const name of snapshots) {
        for (const object of byName.get(name) || []) {
          if (quiet) {
            if (!(await permit(object))) continue;
          } else {
            if (await ask(object.size, [object]) === 'skipped') continue;
            spent += object.size;
          }
          begin(object.size);
          let got = 0;
          const bytes = await fetchObject(object, (n) => {
            got += n;
            progress({ phase: 'snapshot', done: got, total: object.size });
          });
          if (bytes && gate(() => vault.load_snapshot(name, bytes))) {
            accepted = object;
            break;
          }
          if (bytes) problems.push(`${name}: damaged`);
        }
        if (accepted) break;
      }
      // Snapshots are listed and none can be read: what the segments alone would show is a
      // part of the vault (the segments a snapshot covers are removed after a week).
      if (snapshots.length && !accepted) {
        end();
        throw new LoadError('no-snapshot', deferred.size
          ? 'The index of this vault changed on the store and is too large to load without asking. Lock the vault and unlock it again.'
          : `No snapshot of this vault's index could be read (${snapshots.join(', ')}). Run \`gclone check\` on one of your devices.`);
      }
      let needed;
      for (;;) {
        needed = JSON.parse(vault.needed_segments(names)).filter((name) => byName.has(name));
        const objects = needed.flatMap((name) => byName.get(name));
        const total = (accepted ? accepted.size : 0) + objects.reduce((sum, object) => sum + object.size, 0);
        if (quiet || await ask(total, objects) !== 'skipped') {
          begin(total);
          await addSegments(needed, byName, accepted ? accepted.size : 0, total);
          break;
        }
        ({ byName, names } = await listing());
      }
      const result = await finish();
      end();
      quiet = false;
      return settle(result, result.applied);
    }

    /**
     * Step 6: list again, fetch what is new, apply. Failures leave the loaded state in place.
     * Returns `{ reload }` — `true`: start over with `load({ quiet: true })`.
     */
    async function refresh() {
      const before = report ? report.applied : 0;
      pass(true);
      const { byName, names } = await listing();
      const needed = JSON.parse(vault.needed_segments(names)).filter((name) => byName.has(name));
      await addSegments(needed, byName, 0, needed.flatMap((name) => byName.get(name)).reduce((sum, object) => sum + object.size, 0));
      const result = await finish();
      quiet = false;
      if (result.blocked.length) {
        // Segments stay blocked while a newer snapshot is listed: start over from that one —
        // unless that is a download someone has to be asked about.
        const snapshots = JSON.parse(vault.snapshot_candidates(names));
        if (snapshots.length && snapshots[0] !== result.snapshot) {
          const size = Math.max(...(byName.get(snapshots[0]) || []).map((object) => object.size), 0);
          if (size <= INDEX_CONFIRM) return { reload: true };
          newerBase = size;
        }
      }
      settle(result, Math.max(0, result.applied - before));
      return { reload: false };
    }

    return {
      load,
      refresh,
      /** The state `info` reports: `{ at_ms, ok, applied, note }`. */
      state: () => state,
      /** A refresh that failed: the loaded vault stays, the note says why. */
      failed(message) {
        quiet = false;
        state = { at_ms: now(), ok: false, applied: 0, note: message };
      },
      report: () => report,
    };
  }

  gclone.loader = {
    SMALL_MAX, KEYFILE_LOOK_MAX, INDEX_PARALLEL_MAX, INDEX_OBJECT_MAX, INDEX_CONFIRM, NEWER,
    LoadError, codeOf, sentenceOf, expensive, screenText, discover, open, createIndex,
  };
})();
