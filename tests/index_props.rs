//! WP4 acceptance (SPEC §12.1): the merge rule as properties over seeded histories, and the
//! journal — resolution, refresh, fingerprint, clones, coverage, crash safety, compaction,
//! cleanup, repair, vault creation / discovery / keyfile objects, the lock — on
//! `Flaky<MemBackend>`. The adversary cases are in `tests/index_adversary.rs`.

mod support;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use gclone::backend::{Backend, DirBackend, Flaky, Handle, MemBackend, ObjMeta, OpKind, PutBody};
use gclone::consts::{
    COMPACT_MIN_SEGMENTS, DATA_FOLDER_MAX, GAP_GRACE_MS, GC_GRACE_MS, INDEX_TRASH_DELAY_MS,
    RESTORE_WINDOW_MS,
};
use gclone::crypto::{Keyring, MasterKey, ciphertext_len};
use gclone::error::{BackendError, IndexError, QuotaKind, StateError};
use gclone::format::{
    DESCRIPTOR_NAME, Op, README_NAME, SealedObject, SegmentV1, SnapshotV1, keyfile_name,
    open_segment, open_snapshot,
};
use gclone::index::{
    CreateParams, HeadStore, MemIndex, OpenParams, Vault, VaultHandles, apply_segment,
    causal_order, creation_winner, testing,
};
use gclone::path::conflict_name;
use gclone::state::{Db, LedgerDir, PairIdentity, lock_exclusive, try_lock};
use gclone::types::{
    BaseEffect, BaseEffectKind, BaseRow, BlobId, BlobRec, CoveredSeg, DeviceId, Entry, EntryKind,
    Loc, OpDraft, SegRef, Stamp, StatSig,
};
use support::prng::{Prng, for_each_seed};

const VAULT: [u8; 16] = [0x11; 16];
const DAY_MS: u64 = 86_400_000;

// =============================================================================================
// Part 1 — the merge rule (§5.2.2) on MemIndex and on the SQLite store
// =============================================================================================

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 8])
}

fn stamp(lamport: u64, d: u8, idx: u32) -> Stamp {
    Stamp {
        lamport,
        device: dev(d),
        idx,
    }
}

/// A file entry whose content is named by `tag`; `variant` changes only where it is stored.
fn file_at(tag: u8, variant: u8) -> Entry {
    let size = 1000 + u64::from(tag);
    Entry {
        kind: EntryKind::File,
        size,
        mtime_ns: i64::from(variant),
        exec: false,
        hash: [tag; 32],
        loc: Some(Loc {
            blob: BlobId([variant; 16]),
            off: 0,
            clen: ciphertext_len(size, 16),
            salt: [variant; 16],
            chunk_log2: 16,
            epoch: 1,
            suite: 1,
            flags: 0,
        }),
    }
}

fn file(tag: u8) -> Entry {
    file_at(tag, tag)
}

fn put_op(path: &str, entry: Entry, base: Option<Stamp>) -> Op {
    Op::Put {
        path: path.into(),
        entry,
        base,
        origin: None,
    }
}

fn del_op(path: &str, base: Stamp) -> Op {
    Op::Del {
        path: path.into(),
        base,
    }
}

/// A hand-made segment: op `i` has the stamp `(lamport, d, i)`.
fn seg(d: u8, seq: u64, lamport: u64, ops: Vec<Op>) -> SegmentV1 {
    SegmentV1 {
        vault_id: VAULT,
        device: dev(d),
        seq,
        lamport,
        prev: None,
        seen: Vec::new(),
        created_ms: 0,
        host: "test".into(),
        ops,
    }
}

fn sim_hash(seg: &SegmentV1) -> [u8; 32] {
    *blake3::hash(&postcard::to_stdvec(seg).unwrap()).as_bytes()
}

/// Applies `(segment, removed_ms)` in the given order to a `MemIndex` and to SQLite; the two
/// must agree, including the winner flags.
fn run(order: &[(&SegmentV1, u64)]) -> MemIndex {
    let mut mem = MemIndex::default();
    let db = Db::open_in_memory().unwrap();
    for (seg, ms) in order {
        apply_segment(&mut mem, seg, *ms).unwrap();
        testing::apply(&db, seg, *ms).unwrap();
    }
    assert_eq!(
        testing::dump(&db).unwrap(),
        mem,
        "SQLite and MemIndex differ"
    );
    assert_eq!(testing::winners(&db).unwrap(), mem.winners());
    mem
}

fn head_stamps(m: &MemIndex, path: &str) -> Vec<Stamp> {
    m.heads(path).unwrap().iter().map(|h| h.stamp).collect()
}

#[test]
fn rule_successor_replaces() {
    let a1 = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    let a2 = seg(1, 2, 2, vec![put_op("p", file(2), Some(stamp(1, 1, 0)))]);
    let a3 = seg(1, 3, 3, vec![put_op("p", file(3), Some(stamp(2, 1, 0)))]);
    let m = run(&[(&a1, 10), (&a2, 20), (&a3, 30)]);
    // an ancestor of the winner is never a head, so never a conflict
    assert_eq!(head_stamps(&m, "p"), vec![stamp(3, 1, 0)]);
    assert_eq!(m.winners().len(), 1);
    assert_eq!(m.winners()[0].entry, file(3));
    let removed = m.removed();
    assert_eq!(removed.len(), 2);
    assert_eq!(
        (removed[0].stamp, removed[0].by, removed[0].removed_ms),
        (stamp(1, 1, 0), stamp(2, 1, 0), 20)
    );
    assert_eq!(
        (removed[1].stamp, removed[1].by, removed[1].removed_ms),
        (stamp(2, 1, 0), stamp(3, 1, 0), 30)
    );
}

#[test]
fn rule_concurrent_puts_make_two_heads() {
    let a = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    let b = seg(2, 1, 1, vec![put_op("p", file(2), None)]);
    for order in [[(&a, 10), (&b, 20)], [(&b, 20), (&a, 10)]] {
        let m = run(&order);
        let heads = m.heads("p").unwrap();
        assert_eq!(heads.len(), 2);
        // winner = the greatest stamp: equal lamports, so the greater device id
        assert_eq!(m.winners()[0].stamp, stamp(1, 2, 0));
        assert!(heads.iter().any(|h| !h.winner && h.stamp == stamp(1, 1, 0)));
        assert!(m.removed().is_empty());
    }
}

#[test]
fn rule_identical_concurrent_puts_stay_two_heads() {
    // the same content uploaded by two devices: no collapse inside apply
    let a = seg(1, 1, 1, vec![put_op("p", file_at(7, 1), None)]);
    let b = seg(2, 1, 1, vec![put_op("p", file_at(7, 2), None)]);
    let m = run(&[(&a, 10), (&b, 20)]);
    let heads = m.heads("p").unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads[0].entry.same_content(&heads[1].entry));
}

#[test]
fn rule_stale_delete_is_a_noop_and_current_delete_empties() {
    let a1 = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    let a2 = seg(1, 2, 2, vec![put_op("p", file(2), Some(stamp(1, 1, 0)))]);
    // a device that saw only a1 deletes p: the put beats the concurrent delete
    let stale = seg(2, 1, 2, vec![del_op("p", stamp(1, 1, 0))]);
    for order in [
        [(&a1, 10), (&a2, 20), (&stale, 30)],
        [(&a1, 10), (&stale, 30), (&a2, 20)],
    ] {
        let m = run(&order);
        assert_eq!(head_stamps(&m, "p"), vec![stamp(2, 1, 0)]);
        // two ops superseded the first version: the smaller stamp is recorded, with its time
        let removed = m.removed();
        assert_eq!(removed.len(), 1);
        assert_eq!((removed[0].by, removed[0].removed_ms), (stamp(2, 1, 0), 20));
    }
    let mut mem = MemIndex::default();
    apply_segment(&mut mem, &a1, 10).unwrap();
    apply_segment(&mut mem, &a2, 20).unwrap();
    let stats = apply_segment(&mut mem, &stale, 30).unwrap();
    assert_eq!((stats.dels, stats.noop_dels), (1, 1));

    let current = seg(2, 1, 3, vec![del_op("p", stamp(2, 1, 0))]);
    let m = run(&[(&a1, 10), (&a2, 20), (&current, 40)]);
    assert!(m.heads("p").unwrap().is_empty());
    assert!(m.winners().is_empty());
    assert_eq!(m.removed().len(), 2);
}

#[test]
fn rule_two_superseding_ops_record_the_smaller_stamp_in_either_order() {
    let a1 = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    let x = seg(2, 1, 2, vec![put_op("p", file(2), Some(stamp(1, 1, 0)))]);
    let y = seg(3, 1, 5, vec![put_op("p", file(3), Some(stamp(1, 1, 0)))]);
    let one = run(&[(&a1, 10), (&x, 20), (&y, 50)]);
    let two = run(&[(&a1, 10), (&y, 50), (&x, 20)]);
    assert_eq!(one, two);
    let removed = one.removed();
    assert_eq!(removed.len(), 1);
    assert_eq!((removed[0].by, removed[0].removed_ms), (stamp(2, 2, 0), 20));
    assert_eq!(one.heads("p").unwrap().len(), 2);
}

#[test]
fn rule_fork_twins_tie_break_by_hash_and_fall_together() {
    // two different segments with the same (device, seq, lamport): cloned device state
    let twin_lo = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    let twin_hi = seg(1, 1, 1, vec![put_op("p", file(2), None)]);
    for order in [
        [(&twin_lo, 10), (&twin_hi, 11)],
        [(&twin_hi, 11), (&twin_lo, 10)],
    ] {
        let m = run(&order);
        let heads = m.heads("p").unwrap();
        assert_eq!(heads.len(), 2);
        assert_eq!(heads[0].stamp, heads[1].stamp);
        assert_eq!(m.winners()[0].entry.hash, [2; 32]);
    }
    // an op whose base is that stamp removes ALL heads carrying it; they stay restorable
    let successor = seg(2, 1, 2, vec![put_op("p", file(3), Some(stamp(1, 1, 0)))]);
    let m = run(&[(&twin_lo, 10), (&twin_hi, 11), (&successor, 20)]);
    assert_eq!(head_stamps(&m, "p"), vec![stamp(2, 2, 0)]);
    assert_eq!(m.removed().len(), 2);
}

#[test]
fn rule_identical_heads_and_a_writer_that_saw_only_one() {
    // identical heads P1 < P2; O has base P2 and comes from a writer that had not seen P1
    let p1 = seg(1, 1, 1, vec![put_op("p", file_at(7, 1), None)]);
    let p2 = seg(2, 1, 1, vec![put_op("p", file_at(7, 2), None)]);
    for o in [
        seg(3, 1, 2, vec![del_op("p", stamp(1, 2, 0))]),
        seg(3, 1, 2, vec![put_op("p", file(9), Some(stamp(1, 2, 0)))]),
    ] {
        let one = run(&[(&p1, 10), (&p2, 20), (&o, 30)]);
        let two = run(&[(&p2, 20), (&o, 30), (&p1, 10)]);
        assert_eq!(one, two);
        assert!(head_stamps(&one, "p").contains(&stamp(1, 1, 0)));
        assert!(!head_stamps(&one, "p").contains(&stamp(1, 2, 0)));
    }
}

#[test]
fn rule_blob_device_and_vault_ops() {
    let rec = BlobRec {
        id: BlobId([4; 16]),
        file_id: "f".into(),
        clen: 9,
        md5: [1; 16],
        created_ms: 5,
    };
    let init = seg(
        1,
        1,
        1,
        vec![
            Op::VaultInit {
                format: 1,
                name: "vault".into(),
            },
            Op::Device {
                id: dev(1),
                name: "mbp".into(),
            },
            Op::Blob(rec.clone()),
        ],
    );
    let rename = seg(
        1,
        2,
        2,
        vec![Op::Device {
            id: dev(1),
            name: "mbp-2".into(),
        }],
    );
    let m = run(&[(&init, 100), (&rename, 200)]);
    assert_eq!(m.vault(), (1, "vault"));
    assert_eq!(m.blobs(), vec![rec]);
    let devices = m.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        (devices[0].name.as_str(), devices[0].first_ms),
        ("mbp-2", 100)
    );

    let newer = seg(
        1,
        1,
        1,
        vec![
            put_op("p", file(1), None),
            Op::VaultInit {
                format: 2,
                name: "x".into(),
            },
        ],
    );
    let mut mem = MemIndex::default();
    assert!(matches!(
        apply_segment(&mut mem, &newer, 1),
        Err(IndexError::NeedsNewerGclone)
    ));
    assert_eq!(
        mem,
        MemIndex::default(),
        "nothing of a refused segment is applied"
    );
}

#[test]
fn a_failing_sqlite_call_surfaces_as_a_state_error() {
    let db = Db::open_in_memory().unwrap();
    let a1 = seg(1, 1, 1, vec![put_op("p", file(1), None)]);
    testing::apply(&db, &a1, 10).unwrap();
    testing::drop_table(&db, "removed").unwrap();
    let a2 = seg(1, 2, 2, vec![put_op("p", file(2), Some(stamp(1, 1, 0)))]);
    let err = testing::apply(&db, &a2, 20).unwrap_err();
    assert!(
        matches!(err, IndexError::State(StateError::Sqlite(_))),
        "{err:?}"
    );
    // the failed transaction left nothing behind: the first version is still the head
    let heads = testing::winners(&db).unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(
        (heads[0].stamp, heads[0].entry.clone()),
        (stamp(1, 1, 0), file(1))
    );
    assert!(matches!(
        testing::dump(&db),
        Err(IndexError::State(StateError::Sqlite(_)))
    ));
}

// --- seeded histories of three devices -------------------------------------------------------

struct SimDev {
    id: DeviceId,
    seq: u64,
    lamport: u64,
    state: MemIndex,
    has: BTreeSet<usize>,
    last: Option<SegRef>,
    tips: BTreeMap<DeviceId, SegRef>,
    announced: bool,
}

/// `segs` is in generation order, which is one causal order.
struct History {
    segs: Vec<(SegmentV1, [u8; 32])>,
    ms: Vec<u64>,
    devs: Vec<SimDev>,
}

const HISTORY_T0: u64 = 1_700_000_000_000;

fn learn(d: &mut SimDev, i: usize, seg: &SegmentV1, hash: [u8; 32], ms: u64) {
    apply_segment(&mut d.state, seg, ms).unwrap();
    d.has.insert(i);
    d.lamport = d.lamport.max(seg.lamport);
    let r = SegRef {
        device: seg.device,
        seq: seg.seq,
        hash,
        file_id: format!("file-{i}"),
    };
    if seg.device == d.id {
        d.seq = seg.seq;
        d.last = Some(r);
    } else if d
        .tips
        .get(&seg.device)
        .is_none_or(|t| (t.seq, t.hash) < (r.seq, r.hash))
    {
        d.tips.insert(seg.device, r);
    }
}

fn random_entry(rng: &mut Prng) -> (Entry, Option<BlobRec>) {
    match rng.below(10) {
        0 => (Entry::dir(), None),
        1 => (
            Entry::empty_file(rng.below(1 << 40) as i64, rng.bool()),
            None,
        ),
        _ => {
            // few distinct contents (so identical concurrent puts happen), unique locations
            let tag = rng.below(4) as u8 + 1;
            let size = 100 + u64::from(tag);
            let blob = BlobId(rng.array());
            let entry = Entry {
                kind: EntryKind::File,
                size,
                mtime_ns: rng.below(1 << 40) as i64,
                exec: rng.bool(),
                hash: [tag; 32],
                loc: Some(Loc {
                    blob,
                    off: rng.below(1 << 30),
                    clen: ciphertext_len(size, 16),
                    salt: rng.array(),
                    chunk_log2: 16,
                    epoch: 1,
                    suite: 1,
                    flags: 0,
                }),
            };
            let rec = BlobRec {
                id: blob,
                file_id: rng.name(12),
                clen: rng.range(200, 1 << 24),
                md5: rng.array(),
                created_ms: HISTORY_T0,
            };
            (entry, Some(rec))
        }
    }
}

fn history(rng: &mut Prng) -> History {
    const PATHS: [&str; 6] = ["a", "b", "d", "d/x", "d/y", "e.txt"];
    let mut h = History {
        segs: Vec::new(),
        ms: Vec::new(),
        devs: (1..=3u8)
            .map(|n| SimDev {
                id: dev(n),
                seq: 0,
                lamport: 0,
                state: MemIndex::default(),
                has: BTreeSet::new(),
                last: None,
                tips: BTreeMap::new(),
                announced: false,
            })
            .collect(),
    };
    for _ in 0..rng.range(12, 45) {
        let d = rng.index(3);
        if rng.chance(2, 5) {
            // device d pulls everything another device knows
            let other = (d + 1 + rng.index(2)) % 3;
            let news: Vec<usize> = h.devs[other]
                .has
                .difference(&h.devs[d].has)
                .copied()
                .collect();
            for i in news {
                let (seg, hash) = &h.segs[i];
                learn(&mut h.devs[d], i, seg, *hash, h.ms[i]);
            }
            continue;
        }
        let me = &mut h.devs[d];
        let mut ops = Vec::new();
        if h.segs.is_empty() {
            ops.push(Op::VaultInit {
                format: 1,
                name: "props".into(),
            });
        }
        if !me.announced || rng.chance(1, 12) {
            me.announced = true;
            ops.push(Op::Device {
                id: me.id,
                name: format!("device-{d}-{}", rng.below(3)),
            });
        }
        let mut put_paths = HashSet::new();
        for _ in 0..rng.range(1, 4) {
            let path = *rng.pick(&PATHS);
            let heads = me.state.heads(path).unwrap();
            if !heads.is_empty() && rng.chance(1, 4) {
                ops.push(del_op(path, rng.pick(&heads).stamp));
            } else if put_paths.insert(path) {
                // mostly a successor of a head this device knows, sometimes a blind put
                let base = match heads.is_empty() || rng.chance(1, 5) {
                    true => None,
                    false => Some(rng.pick(&heads).stamp),
                };
                let (entry, blob) = random_entry(rng);
                ops.extend(blob.map(Op::Blob));
                ops.push(put_op(path, entry, base));
            }
        }
        if ops.is_empty() {
            continue;
        }
        let seg = SegmentV1 {
            vault_id: VAULT,
            device: me.id,
            seq: me.seq + 1,
            lamport: me.lamport + 1,
            prev: me.last.clone(),
            seen: me.tips.values().cloned().collect(),
            created_ms: 1,
            host: "sim".into(),
            ops,
        };
        let hash = sim_hash(&seg);
        let i = h.segs.len();
        let ms = HISTORY_T0 + 1_000 * i as u64 + rng.below(500);
        learn(me, i, &seg, hash, ms);
        h.segs.push((seg, hash));
        h.ms.push(ms);
    }
    h
}

fn key(seg: &SegmentV1, hash: &[u8; 32]) -> (DeviceId, u64, [u8; 32]) {
    (seg.device, seg.seq, *hash)
}

fn ready(seg: &SegmentV1, done: &HashSet<(DeviceId, u64, [u8; 32])>) -> bool {
    seg.prev
        .iter()
        .chain(&seg.seen)
        .all(|r| done.contains(&(r.device, r.seq, r.hash)))
}

/// A uniformly drawn linear extension of the causal partial order, starting from `done`.
fn random_causal_order(rng: &mut Prng, h: &History, start: &BTreeSet<usize>) -> Vec<usize> {
    let mut done: HashSet<_> = start
        .iter()
        .map(|&i| key(&h.segs[i].0, &h.segs[i].1))
        .collect();
    let mut left: Vec<usize> = (0..h.segs.len()).filter(|i| !start.contains(i)).collect();
    let mut order = Vec::new();
    while !left.is_empty() {
        let choices: Vec<usize> = (0..left.len())
            .filter(|&k| ready(&h.segs[left[k]].0, &done))
            .collect();
        assert!(!choices.is_empty(), "a history is always causally complete");
        let i = left.swap_remove(*rng.pick(&choices));
        done.insert(key(&h.segs[i].0, &h.segs[i].1));
        order.push(i);
    }
    order
}

fn apply_all(m: &mut MemIndex, h: &History, order: &[usize]) {
    for &i in order {
        apply_segment(m, &h.segs[i].0, h.ms[i]).unwrap();
    }
}

fn snapshot_of(m: &MemIndex, h: &History, covered: &BTreeSet<usize>) -> SnapshotV1 {
    let refs = covered.iter().map(|&i| {
        let (seg, hash) = &h.segs[i];
        SegRef {
            device: seg.device,
            seq: seg.seq,
            hash: *hash,
            file_id: String::new(),
        }
    });
    let mut tips: BTreeMap<DeviceId, SegRef> = BTreeMap::new();
    for r in refs.clone() {
        if tips
            .get(&r.device)
            .is_none_or(|t| (t.seq, t.hash) < (r.seq, r.hash))
        {
            tips.insert(r.device, r);
        }
    }
    m.to_snapshot(
        VAULT,
        dev(1),
        7,
        tips.into_values().collect(),
        refs.map(|r| r.covered()).collect(),
        HISTORY_T0 + DAY_MS,
    )
}

#[test]
fn merge_is_independent_of_causal_order_and_grouping() {
    for_each_seed(
        "merge_is_independent_of_causal_order_and_grouping",
        240,
        |rng| {
            let h = history(rng);
            let n = h.segs.len();
            let everything: Vec<usize> = (0..n).collect();
            let mut reference = MemIndex::default();
            apply_all(&mut reference, &h, &everything);

            // any causal order
            for _ in 0..3 {
                let order = random_causal_order(rng, &h, &BTreeSet::new());
                let mut m = MemIndex::default();
                apply_all(&mut m, &h, &order);
                assert_eq!(m, reference, "order {order:?}");
            }

            // `causal_order` over a shuffled set with nothing known: everything applies
            let mut shuffled = everything.clone();
            rng.shuffle(&mut shuffled);
            let segs: Vec<_> = shuffled.iter().map(|&i| h.segs[i].clone()).collect();
            let (order, blocked) = causal_order(&segs, &|_| false);
            assert!(blocked.is_empty());
            let mut m = MemIndex::default();
            let mut done = HashSet::new();
            for &k in &order {
                assert!(ready(&segs[k].0, &done), "causal_order broke causality");
                done.insert(key(&segs[k].0, &segs[k].1));
                apply_segment(&mut m, &segs[k].0, h.ms[shuffled[k]]).unwrap();
            }
            assert_eq!(m, reference);

            // any grouping: segments arrive in random batches; what is blocked waits for a later one
            let mut arrival = everything.clone();
            rng.shuffle(&mut arrival);
            let mut m = MemIndex::default();
            let mut known: HashSet<(DeviceId, u64, [u8; 32])> = HashSet::new();
            let mut waiting: Vec<usize> = Vec::new();
            let mut at = 0;
            while at < n {
                let size = rng.range(1, 6) as usize;
                waiting.extend(&arrival[at..n.min(at + size)]);
                at += size;
                let segs: Vec<_> = waiting.iter().map(|&i| h.segs[i].clone()).collect();
                let (order, blocked) =
                    causal_order(&segs, &|r| known.contains(&(r.device, r.seq, r.hash)));
                for &k in &order {
                    let i = waiting[k];
                    apply_segment(&mut m, &h.segs[i].0, h.ms[i]).unwrap();
                }
                for &k in &order {
                    known.insert(key(&segs[k].0, &segs[k].1));
                }
                waiting = blocked.iter().map(|&k| waiting[k]).collect();
            }
            assert!(waiting.is_empty());
            assert_eq!(m, reference);

            // snapshot round trip
            let all: BTreeSet<usize> = everything.iter().copied().collect();
            let snap = snapshot_of(&reference, &h, &all);
            assert_eq!(MemIndex::load_snapshot(&snap), reference);
            assert!(snap.covered.is_sorted_by(|a, b| a < b));
            assert!(snap.covers.is_sorted_by(|a, b| a.device < b.device));
            assert!(snap.heads.is_sorted_by(|a, b| {
                (&a.path, a.stamp, a.entry.hash) < (&b.path, b.stamp, b.entry.hash)
            }));

            // state(snapshot ⊕ uncovered) == state(all): what one device knew is a causally closed set
            let who = &h.devs[rng.index(3)];
            let partial = snapshot_of(&who.state, &h, &who.has);
            let mut rebuilt = MemIndex::load_snapshot(&partial);
            assert_eq!(rebuilt, who.state);
            let tail = random_causal_order(rng, &h, &who.has);
            apply_all(&mut rebuilt, &h, &tail);
            assert_eq!(rebuilt, reference);

            // the SQLite HeadStore equals MemIndex for the same history — applied in another order,
            // and rebuilt from the partial snapshot
            let db = Db::open_in_memory().unwrap();
            for &i in &random_causal_order(rng, &h, &BTreeSet::new()) {
                testing::apply(&db, &h.segs[i].0, h.ms[i]).unwrap();
            }
            assert_eq!(testing::dump(&db).unwrap(), reference);
            assert_eq!(testing::winners(&db).unwrap(), reference.winners());

            let db = Db::open_in_memory().unwrap();
            testing::load_snapshot(&db, &partial).unwrap();
            assert_eq!(testing::dump(&db).unwrap(), who.state);
            assert_eq!(testing::winners(&db).unwrap(), who.state.winners());
            for &i in &tail {
                testing::apply(&db, &h.segs[i].0, h.ms[i]).unwrap();
            }
            assert_eq!(testing::dump(&db).unwrap(), reference);
            assert_eq!(testing::winners(&db).unwrap(), reference.winners());
        },
    );
}

#[test]
fn causal_order_blocks_what_lacks_its_references() {
    let a1 = seg(1, 1, 1, vec![]);
    let h1 = sim_hash(&a1);
    let r1 = SegRef {
        device: dev(1),
        seq: 1,
        hash: h1,
        file_id: "x".into(),
    };
    let mut a2 = seg(1, 2, 2, vec![]);
    a2.prev = Some(r1.clone());
    let h2 = sim_hash(&a2);
    let mut b1 = seg(2, 1, 3, vec![]);
    b1.seen = vec![SegRef {
        device: dev(1),
        seq: 2,
        hash: h2,
        file_id: "y".into(),
    }];
    let hb = sim_hash(&b1);
    let mut c1 = seg(3, 1, 1, vec![]);
    c1.seen = vec![SegRef {
        device: dev(9),
        seq: 4,
        hash: [9; 32],
        file_id: "gone".into(),
    }];
    let hc = sim_hash(&c1);
    let segs = vec![(b1, hb), (c1, hc), (a2, h2), (a1, h1)];
    let (order, blocked) = causal_order(&segs, &|_| false);
    assert_eq!(order, vec![3, 2, 0]);
    assert_eq!(blocked, vec![1]);
    // with a1 already known, a2 is ready at once and sorts by lamport before b1
    let (order, blocked) = causal_order(&segs[..3], &|r| *r == r1);
    assert_eq!((order, blocked), (vec![2, 0], vec![1]));
    // a hash that does not match is not a satisfied reference
    let mut forged = segs[2].clone();
    forged.1 = [0; 32];
    let (order, blocked) = causal_order(&[segs[0].clone(), forged], &|r| *r == r1);
    assert_eq!((order, blocked), (vec![1], vec![0]));
}

// =============================================================================================
// Part 2 — the journal on Flaky<MemBackend>
// =============================================================================================

type Net = Flaky<MemBackend>;
type V = Vault<Net>;

struct World {
    mem: MemBackend,
    net: Arc<Net>,
    keys: Keyring,
    handles: VaultHandles,
    tmp: tempfile::TempDir,
    /// The devices' local clock (grace periods, §5.3).
    clock: Arc<AtomicU64>,
}

fn keyring(vault_id: [u8; 16]) -> Keyring {
    Keyring::new(vault_id, vec![(1, MasterKey::from_bytes([7; 32]))], 1).unwrap()
}

/// Bytes named like a keyfile; the index layer never opens one.
fn fake_keyfile(generation: u32, tag: u8) -> SealedObject {
    let bytes = vec![tag; 200];
    let hash = *blake3::hash(&bytes).as_bytes();
    SealedObject {
        name: keyfile_name(generation, &hash),
        hash,
        bytes,
    }
}

fn create_params(vault_id: [u8; 16], cache_dir: PathBuf) -> CreateParams {
    CreateParams {
        vault_id,
        vault_name: "gclone".into(),
        device_name: "a".into(),
        cache_dir,
        machine_fp: Some([1; 32]),
        keyfile: fake_keyfile(1, 1),
    }
}

async fn world() -> (World, V) {
    let mem = MemBackend::new();
    let net = Arc::new(Flaky::new(mem.clone()));
    let tmp = tempfile::tempdir().unwrap();
    let keys = keyring(VAULT);
    let (mut a, found) = Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keys.clone(),
        create_params(VAULT, tmp.path().join("a")),
    )
    .await
    .unwrap();
    let w = World {
        mem,
        net,
        keys,
        handles: found.handles,
        tmp,
        clock: Arc::new(AtomicU64::new(1_800_000_000_000)),
    };
    w.set_clock(&mut a);
    (w, a)
}

impl World {
    fn set_clock(&self, v: &mut V) {
        let clock = self.clock.clone();
        v.set_local_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
    }

    fn cache(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    /// Opens (or re-opens) a device on `db`; no network.
    async fn open(&self, db: Db, name: &str, fp: u8) -> V {
        let params = OpenParams {
            vault_id: VAULT,
            handles: self.handles.clone(),
            device_name: name.into(),
            cache_dir: self.cache(name),
            machine_fp: Some([fp; 32]),
        };
        let mut v = Vault::open(self.net.clone(), db, self.keys.clone(), params)
            .await
            .unwrap();
        self.set_clock(&mut v);
        v
    }

    /// A new device with an empty replica.
    async fn device(&self, name: &str) -> V {
        self.open(Db::open_in_memory().unwrap(), name, 1).await
    }

    /// A new device that has pulled the vault.
    async fn join(&self, name: &str) -> V {
        let v = self.device(name).await;
        v.refresh().await.unwrap();
        v
    }

    /// Un-trashed objects of `index/` whose name starts with `prefix`, sorted by name.
    fn listed(&self, prefix: &str) -> Vec<ObjMeta> {
        let mut found: Vec<ObjMeta> = self
            .mem
            .all_objects()
            .into_iter()
            .filter(|m| m.parent == self.handles.index && !m.trashed && m.name.starts_with(prefix))
            .collect();
        found.sort_by(|a, b| a.name.cmp(&b.name));
        found
    }

    /// The (un-trashed) segment `seq` of `device`.
    fn segment(&self, device: DeviceId, seq: u64) -> ObjMeta {
        let prefix = format!("s-{}-{seq:016x}-", device.hex());
        let mut found = self.listed(&prefix);
        assert_eq!(found.len(), 1, "segment {prefix}");
        found.remove(0)
    }

    fn tick(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    /// §5.2.2 writer-side invariant over everything ever published.
    fn assert_no_double_puts(&self) {
        for m in self.mem.all_objects() {
            if m.parent != self.handles.index || !m.name.starts_with("s-") {
                continue;
            }
            let bytes = self.mem.read(&m.handle).unwrap();
            let (seg, _) = open_segment(&self.keys, &m.name, &bytes).unwrap();
            let mut paths = HashSet::new();
            for op in &seg.ops {
                if let Op::Put { path, .. } = op {
                    assert!(
                        paths.insert(path.clone()),
                        "two Puts for {path} in {}",
                        m.name
                    );
                }
            }
        }
    }
}

fn put(path: &str, tag: u8) -> OpDraft {
    OpDraft::Put {
        path: path.into(),
        entry: file(tag),
        base: None,
        origin: None,
        effect: None,
    }
}

/// A put that succeeds the version `v` currently shows at `path`.
fn put_over(v: &V, path: &str, tag: u8) -> OpDraft {
    OpDraft::Put {
        path: path.into(),
        entry: file(tag),
        base: v.head(path).unwrap().map(|h| h.stamp),
        origin: None,
        effect: None,
    }
}

fn del(v: &V, path: &str) -> OpDraft {
    OpDraft::Del {
        path: path.into(),
        base: v.head(path).unwrap().expect("a head to delete").stamp,
        effect: None,
    }
}

/// `(winners: path, stamp, content hash; losers: path, stamp)`.
type View = (Vec<(String, Stamp, [u8; 32])>, Vec<(String, Stamp)>);

/// The visible tree and the conflict losers: what converged devices agree on.
fn view(v: &V) -> View {
    (
        v.walk("")
            .unwrap()
            .into_iter()
            .map(|h| (h.path, h.stamp, h.entry.hash))
            .collect(),
        v.conflicts()
            .unwrap()
            .into_iter()
            .map(|h| (h.path, h.stamp))
            .collect(),
    )
}

fn paths(v: &V) -> Vec<String> {
    v.walk("").unwrap().into_iter().map(|h| h.path).collect()
}

fn transient() -> BackendError {
    BackendError::Transient("injected".into())
}

fn quota() -> BackendError {
    BackendError::QuotaExceeded(QuotaKind::StorageFull)
}

fn fatal() -> BackendError {
    BackendError::Fatal {
        status: 500,
        reason: "backendError".into(),
        message: "injected".into(),
    }
}

// --- resolve_conflicts -----------------------------------------------------------------------

/// Devices a and b put different content at one path without seeing each other.
async fn conflict_at(path: &str, tag_a: u8, tag_b: u8) -> (World, V, V) {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put(path, tag_a)]).await.unwrap();
    b.commit_ops(vec![put(path, tag_b)]).await.unwrap();
    let ra = a.refresh().await.unwrap();
    let rb = b.refresh().await.unwrap();
    assert_eq!((ra.conflicts, rb.conflicts), (1, 1));
    (w, a, b)
}

#[tokio::test]
async fn resolve_moves_the_loser_to_a_deterministic_conflict_path() {
    let (w, a, b) = conflict_at("docs/report.tar.gz", 1, 2).await;
    let heads = a.heads("docs/report.tar.gz").unwrap();
    assert_eq!(heads.len(), 2);
    let (winner, loser) = (heads[0].clone(), heads[1].clone());
    assert!(winner.winner && !loser.winner && winner.stamp > loser.stamp);
    assert_eq!(a.head("docs/report.tar.gz").unwrap().unwrap(), winner);

    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    let copy = conflict_name("docs/report.tar.gz", &loser.stamp);
    assert_eq!(
        copy,
        format!(
            "docs/report.tar.conflict-{}-{}.gz",
            loser.stamp.device.short(),
            loser.stamp.lamport
        )
    );
    assert_eq!(
        paths(&a),
        vec![copy.clone(), "docs/report.tar.gz".to_owned()]
    );
    let moved = a.head(&copy).unwrap().unwrap();
    assert_eq!(
        (moved.entry, moved.origin),
        (loser.entry, Some(loser.stamp))
    );
    assert_eq!(
        a.head("docs/report.tar.gz").unwrap().unwrap().stamp,
        winner.stamp
    );
    assert!(a.conflicts().unwrap().is_empty());
    // the loser stays restorable at its old path
    let removed = a.removed_versions("docs/report.tar.gz").unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].stamp, loser.stamp);

    assert_eq!(b.refresh().await.unwrap().conflicts, 0);
    assert_eq!(view(&a), view(&b));
    assert_eq!(b.resolve_conflicts().await.unwrap(), 0);
    w.assert_no_double_puts();
}

#[tokio::test]
async fn resolve_drops_same_content_losers_without_a_copy() {
    // two devices uploaded identical content under different locations (first sync of a folder)
    let (w, a) = world().await;
    let b = w.join("b").await;
    let same = |variant| OpDraft::Put {
        path: "photo.jpg".into(),
        entry: file_at(5, variant),
        base: None,
        origin: None,
        effect: None,
    };
    a.commit_ops(vec![same(1)]).await.unwrap();
    b.commit_ops(vec![same(2)]).await.unwrap();
    a.refresh().await.unwrap();
    assert_eq!(a.conflicts().unwrap().len(), 1);
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    assert_eq!(paths(&a), vec!["photo.jpg".to_owned()]);
    assert!(a.conflicts().unwrap().is_empty());
    b.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));
}

#[tokio::test]
async fn independent_resolvers_converge() {
    let (w, a, b) = conflict_at("f.txt", 1, 2).await;
    // both resolve before seeing the other's resolution
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    assert_eq!(b.resolve_conflicts().await.unwrap(), 1);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    // two identical heads at the conflict path: the next resolution drops one, on either device
    assert_eq!(a.conflicts().unwrap().len(), 1);
    assert_eq!(view(&a), view(&b));
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    assert_eq!(b.resolve_conflicts().await.unwrap(), 1);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    assert!(a.conflicts().unwrap().is_empty());
    assert_eq!(view(&a), view(&b));
    assert_eq!(paths(&a).len(), 2);
    assert_eq!(a.resolve_conflicts().await.unwrap(), 0);
    assert_eq!(b.resolve_conflicts().await.unwrap(), 0);
    let c = w.join("c").await;
    assert_eq!(view(&c), view(&a));
    w.assert_no_double_puts();
}

#[tokio::test]
async fn a_second_device_follows_a_resolution() {
    let (w, a, b) = conflict_at("f.txt", 1, 2).await;
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    let segments = w.listed("s-").len();
    assert_eq!(b.refresh().await.unwrap().conflicts, 0);
    assert_eq!(view(&a), view(&b));
    // nothing left to resolve: no segment is written
    assert_eq!(b.resolve_conflicts().await.unwrap(), 0);
    assert_eq!(w.listed("s-").len(), segments);
}

#[tokio::test]
async fn resolve_moves_a_file_that_blocks_a_directory() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("d", 1)]).await.unwrap();
    b.commit_ops(vec![put("d/x", 2), put("d/sub/y", 3)])
        .await
        .unwrap();
    a.refresh().await.unwrap();
    let blocker = a.head("d").unwrap().unwrap();
    assert!(a.conflicts().unwrap().is_empty());
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    let moved = conflict_name("d", &blocker.stamp);
    assert_eq!(
        paths(&a),
        vec![moved.clone(), "d/sub/y".to_owned(), "d/x".to_owned()]
    );
    assert_eq!(a.head(&moved).unwrap().unwrap().origin, Some(blocker.stamp));
    assert!(a.exists_dir("d").unwrap());
    b.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));
    assert_eq!(b.resolve_conflicts().await.unwrap(), 0);
    w.assert_no_double_puts();
}

/// Regression: the conflict copy's name was clamped to 255 bytes but the whole path was not
/// kept within `PATH_MAX`. For a path near the limit `stage` refused the copy, the resolution
/// failed — identically on every device and on every call — and with it every mutating
/// command and `repair`, which all resolve first.
#[tokio::test]
async fn a_conflict_at_a_path_near_the_length_limit_is_resolved() {
    let mut comps: Vec<String> = (0..15).map(|_| "d".repeat(255)).collect();
    comps.push("e".repeat(249));
    comps.push("abcde".to_owned());
    let path = comps.join("/");
    assert_eq!(path.len(), 4095);
    gclone::path::validate(&path).unwrap();

    let (w, a, b) = conflict_at(&path, 1, 2).await;
    let loser = a.conflicts().unwrap().remove(0);
    let copy = conflict_name(&path, &loser.stamp);
    gclone::path::validate(&copy).unwrap();
    let mut both = vec![path.clone(), copy.clone()];
    both.sort();
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    assert!(a.conflicts().unwrap().is_empty());
    assert_eq!(paths(&a), both);
    assert_eq!(a.head(&copy).unwrap().unwrap().entry.hash, loser.entry.hash);
    // the other device emits the same ops; both converge
    assert_eq!(b.resolve_conflicts().await.unwrap(), 1);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    a.finish_mutation().await.unwrap();
    b.refresh().await.unwrap();
    b.finish_mutation().await.unwrap();
    a.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));
    assert!(a.conflicts().unwrap().is_empty());
    assert_eq!(paths(&a), both);
    a.repair(false).await.unwrap();
    w.assert_no_double_puts();

    // Rule 2 names its copy the same way: a file where a directory is needed, near the limit.
    let (w, a) = world().await;
    let b = w.join("b").await;
    let mut comps: Vec<String> = (0..15).map(|_| "d".repeat(255)).collect();
    comps.push("e".repeat(243));
    comps.push("abcde".to_owned());
    let file_path = comps.join("/");
    let below = format!("{file_path}/x");
    assert_eq!((file_path.len(), below.len()), (4089, 4091));
    a.commit_ops(vec![put(&file_path, 1)]).await.unwrap();
    b.commit_ops(vec![put(&below, 2)]).await.unwrap();
    a.refresh().await.unwrap();
    let blocker = a.head(&file_path).unwrap().unwrap();
    let moved = conflict_name(&file_path, &blocker.stamp);
    gclone::path::validate(&moved).unwrap();
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    let mut both = vec![below.clone(), moved.clone()];
    both.sort();
    assert_eq!(paths(&a), both);
    b.refresh().await.unwrap();
    assert_eq!(b.resolve_conflicts().await.unwrap(), 0);
    assert_eq!(view(&a), view(&b));
    w.assert_no_double_puts();
}

#[tokio::test]
async fn a_losing_directory_entry_is_just_deleted() {
    let (_w, a) = world().await;
    let b = _w.join("b").await;
    let dir = OpDraft::Put {
        path: "thing".into(),
        entry: Entry::dir(),
        base: None,
        origin: None,
        effect: None,
    };
    // equal lamports: the greater device id wins, so make the directory the loser on purpose
    let (low, high) = if a.device_id() < b.device_id() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    low.commit_ops(vec![dir]).await.unwrap();
    high.commit_ops(vec![put("thing", 4)]).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(a.resolve_conflicts().await.unwrap(), 1);
    assert_eq!(paths(&a), vec!["thing".to_owned()]);
    assert_eq!(a.head("thing").unwrap().unwrap().entry, file(4));
}

#[tokio::test]
async fn resolve_commits_staged_leftovers_even_with_nothing_to_resolve() {
    let (w, a) = world().await;
    a.stage(vec![put("left/over", 1)]).unwrap();
    assert_eq!(a.db().pending_count().unwrap(), 1);
    assert!(a.head("left/over").unwrap().is_none());
    assert_eq!(a.resolve_conflicts().await.unwrap(), 0);
    assert_eq!(a.db().pending_count().unwrap(), 0);
    assert!(a.head("left/over").unwrap().is_some());
    assert_eq!(w.listed("s-").len(), 2);
    // with nothing staged and nothing to resolve, nothing is published
    assert_eq!(a.resolve_conflicts().await.unwrap(), 0);
    assert_eq!(w.listed("s-").len(), 2);
}

#[tokio::test]
async fn stage_refuses_what_could_never_be_published() {
    let (_w, a) = world().await;
    for bad in ["", "/abs", "a//b", "a/../b", "trailing/"] {
        let err = a.stage(vec![put(bad, 1)]).unwrap_err();
        assert!(matches!(err, IndexError::Format(_)), "{bad:?}: {err:?}");
    }
    let mut odd_chunks = file(1);
    odd_chunks.loc.as_mut().unwrap().chunk_log2 = 99;
    let odd = OpDraft::Put {
        path: "ok".into(),
        entry: odd_chunks,
        base: None,
        origin: None,
        effect: None,
    };
    assert!(matches!(a.stage(vec![odd]), Err(IndexError::Format(_))));
    let mut entry = file(1);
    entry.size += 1; // the stored length no longer matches
    let broken = OpDraft::Put {
        path: "ok".into(),
        entry,
        base: None,
        origin: None,
        effect: None,
    };
    assert!(matches!(a.stage(vec![broken]), Err(IndexError::Format(_))));
    assert_eq!(a.db().pending_count().unwrap(), 0);
    assert!(a.commit().await.unwrap().segment.is_none());
}

// --- refresh ---------------------------------------------------------------------------------

#[tokio::test]
async fn three_devices_converge_after_interleaved_commits() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    let c = w.join("c").await;
    let devices = [&a, &b, &c];
    let mut rng = Prng::from_env();
    const PATHS: [&str; 5] = ["x", "y", "dir/z", "dir/w", "v.txt"];
    for step in 0..60u8 {
        let v = devices[rng.index(3)];
        if rng.chance(1, 3) {
            v.refresh().await.unwrap();
            continue;
        }
        let path = *rng.pick(&PATHS);
        let op = match v.head(path).unwrap() {
            Some(_) if rng.chance(1, 4) => del(v, path),
            _ => put_over(v, path, step),
        };
        v.commit_ops(vec![op]).await.unwrap();
    }
    for v in devices {
        v.refresh().await.unwrap();
    }
    assert_eq!(view(&a), view(&b));
    assert_eq!(view(&a), view(&c));
    let head = a.head_fingerprint().unwrap();
    assert_eq!(head, b.head_fingerprint().unwrap());
    assert_eq!(head, c.head_fingerprint().unwrap());

    // conflicts are settled by whoever mutates next; everyone follows
    a.resolve_conflicts().await.unwrap();
    for v in devices {
        v.refresh().await.unwrap();
        v.resolve_conflicts().await.unwrap();
    }
    for v in devices {
        let r = v.refresh().await.unwrap();
        assert_eq!((r.conflicts, r.blocked_young), (0, 0));
    }
    assert_eq!(view(&a), view(&b));
    assert_eq!(view(&a), view(&c));
    let fresh = w.join("d").await;
    assert_eq!(view(&fresh), view(&a));
    assert_eq!(
        fresh.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    w.assert_no_double_puts();
}

/// No adversary, any interleaving of commits, refreshes, resolutions, snapshots and cleanups
/// (with time passing): no command ever fails, and every device — also one that joins at the
/// end — reaches the same state.
#[tokio::test]
async fn random_journals_with_compaction_and_cleanup_converge() {
    const PATHS: [&str; 6] = ["x", "y", "dir/z", "dir/w", "dir", "v.txt"];
    let mut seeds = Prng::from_env();
    for case in 0..6 {
        let mut rng = seeds.fork();
        let (w, a) = world().await;
        let mut devices = vec![a, w.join("b").await, w.join("c").await];
        let mut log: Vec<String> = Vec::new();
        for step in 0..70u8 {
            if devices.len() < 5 && rng.chance(1, 30) {
                let name = format!("late-{step}");
                devices.push(w.join(&name).await);
                log.push(format!("join {name}"));
                continue;
            }
            let d = rng.index(devices.len());
            let v = &devices[d];
            let action = rng.below(20);
            let done = match action {
                0..=7 => {
                    let path = *rng.pick(&PATHS);
                    let op = match v.head(path).unwrap() {
                        Some(_) if rng.chance(1, 4) => del(v, path),
                        _ => put_over(v, path, step),
                    };
                    v.commit_ops(vec![op]).await.map(drop)
                }
                8..=12 => v.refresh().await.map(drop),
                13 | 14 => v.resolve_conflicts().await.map(drop),
                15 | 16 => v.finish_mutation().await,
                17 => v.write_snapshot().await.map(drop),
                _ => {
                    w.mem.advance_ms(rng.range(1, 6) * DAY_MS);
                    v.cleanup_index().await.map(drop)
                }
            };
            log.push(format!("{d}:{action}"));
            if let Err(e) = done {
                panic!("case {case}, step {step}: device {d} action {action} failed: {e}\n{log:?}");
            }
        }
        for round in 0..2 {
            for (d, v) in devices.iter().enumerate() {
                if let Err(e) = v.refresh().await {
                    panic!("case {case}: final refresh {round} of device {d} failed: {e}\n{log:?}");
                }
            }
        }
        let fresh = w.join("fresh").await;
        let expect = (view(&fresh), fresh.head_fingerprint().unwrap());
        for (d, v) in devices.iter().enumerate() {
            let got = (view(v), v.head_fingerprint().unwrap());
            assert_eq!(got, expect, "case {case}: device {d} diverged\n{log:?}");
            assert_eq!(v.stats(0).unwrap().files, fresh.stats(0).unwrap().files);
        }
        w.assert_no_double_puts();
    }
}

#[tokio::test]
async fn refresh_reports_what_it_applied_and_is_idempotent() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    a.commit_ops(vec![put("two", 2)]).await.unwrap();
    let b = w.device("b").await;
    assert!(b.vault_name().is_empty());
    let r = b.refresh().await.unwrap();
    assert_eq!(r.applied, 3);
    assert!(r.corrupt_objects.is_empty() && !r.rotated_device && !r.outbox_stuck);
    assert_eq!(b.vault_name(), "gclone");
    assert_eq!(a.vault_name(), "gclone");
    assert_eq!(b.refresh().await.unwrap().applied, 0);
    // an up-to-date refresh is one listing and nothing else
    let before = w.mem.counters();
    b.refresh().await.unwrap();
    let after = w.mem.counters();
    assert_eq!(after.list, before.list + 1);
    assert_eq!(
        (after.get, after.stat, after.put),
        (before.get, before.stat, before.put)
    );
    assert!(b.db().meta_get_u64("last_refresh_ms").unwrap().is_some());
}

#[tokio::test]
async fn list_lag_is_healed_by_file_id_and_never_a_rollback() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    b.commit_ops(vec![put("b-first", 1)]).await.unwrap();
    let c = w.device("c").await;

    // b publishes a segment that references a's newest one; then the listing starts to lag and
    // hides a's segment while b's (made to look older) is listed
    let t = w.net.now_ms();
    a.refresh().await.unwrap();
    a.commit_ops(vec![put("young", 2)]).await.unwrap();
    b.refresh().await.unwrap();
    w.mem.set_now_ms(t - 3_600_000);
    b.commit_ops(vec![put("references-young", 3)])
        .await
        .unwrap();
    w.mem.set_now_ms(t + 1_000);
    w.net.set_list_lag_ms(600_000);
    let young = format!("s-{}-", a.device_id().hex());
    assert_eq!(w.listed(&young).len(), 2, "both of a's segments exist");

    // the writers themselves: their own newest segments are not listed, yet nothing is "gone"
    for _ in 0..3 {
        a.refresh().await.unwrap();
        b.refresh().await.unwrap();
        w.tick(GAP_GRACE_MS / 4);
    }

    // a fresh device is served a listing without a's segments: it fetches them by the file id
    // the reference carries
    let r = c.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    assert_eq!(paths(&c), paths(&b));
    assert!(paths(&c).contains(&"young".to_owned()));
    assert_eq!(c.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    w.tick(2 * GAP_GRACE_MS);
    c.refresh().await.unwrap();

    w.net.clear();
    for v in [&a, &b, &c] {
        v.refresh().await.unwrap();
    }
    assert_eq!(view(&a), view(&c));
}

#[tokio::test]
async fn gap_grace_runs_on_the_local_clock() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("lost", 1)]).await.unwrap();
    b.refresh().await.unwrap();
    b.commit_ops(vec![put("kept", 2)]).await.unwrap();
    // b's segment names a's second segment in `seen`; that one disappears for good
    assert!(w.mem.hard_delete(&w.segment(a.device_id(), 2).handle));

    let c = w.device("c").await;
    let r = c.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 1);
    assert_eq!(paths(&c), Vec::<String>::new());

    // server time (object ages) does not start the alarm
    w.mem.advance_ms(30 * DAY_MS);
    assert_eq!(c.refresh().await.unwrap().blocked_young, 1);
    w.tick(GAP_GRACE_MS - 1);
    assert_eq!(c.refresh().await.unwrap().blocked_young, 1);
    w.tick(1);
    let err = c.refresh().await.unwrap_err();
    let IndexError::Gap { names } = err else {
        panic!("expected a gap, got {err:?}");
    };
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with(&format!("s-{}-{:016x}-", a.device_id().hex(), 2)));
    // the replica stays consistent and readable
    assert!(c.walk("").unwrap().is_empty());
    assert_eq!(c.devices().unwrap().len(), 1);
}

// --- head fingerprint ------------------------------------------------------------------------

fn assert_fingerprint_form(s: &str) {
    assert_eq!(s.len(), 9, "{s}");
    for (i, ch) in s.chars().enumerate() {
        if i == 4 {
            assert_eq!(ch, '-');
        } else {
            assert!("0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch), "{s}");
        }
    }
}

#[tokio::test]
async fn head_fingerprint_follows_the_journal() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    let empty = w.device("empty").await;
    assert_fingerprint_form(&a.head_fingerprint().unwrap());
    assert_fingerprint_form(&empty.head_fingerprint().unwrap());
    assert_eq!(a.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    assert_ne!(
        a.head_fingerprint().unwrap(),
        empty.head_fingerprint().unwrap()
    );

    // it changes with a commit and is equal again once the other device refreshed
    let before = a.head_fingerprint().unwrap();
    a.commit_ops(vec![put("f", 1)]).await.unwrap();
    let after = a.head_fingerprint().unwrap();
    assert_ne!(before, after);
    assert_eq!(b.head_fingerprint().unwrap(), before);
    b.refresh().await.unwrap();
    assert_eq!(b.head_fingerprint().unwrap(), after);

    // a rolled-back store: a fresh replica gets a value that differs from an up-to-date device's
    let checkpoint = w.mem.checkpoint();
    a.commit_ops(vec![put("g", 2)]).await.unwrap();
    b.refresh().await.unwrap();
    let current = w.mem.checkpoint();
    w.mem.restore(&checkpoint);
    let stale = w.join("stale").await;
    assert_eq!(stale.head_fingerprint().unwrap(), after);
    assert_ne!(
        stale.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    w.mem.restore(&current);

    // a replica rebuilt from a snapshot equals one that applied every segment
    b.commit_ops(vec![put("h", 3)]).await.unwrap();
    a.refresh().await.unwrap();
    a.write_snapshot().await.unwrap();
    for s in w.listed("s-") {
        w.net.trash(&s.handle).await.unwrap();
    }
    let rebuilt = w.device("rebuilt").await;
    assert!(rebuilt.refresh().await.unwrap().rebuilt_from.is_some());
    b.refresh().await.unwrap();
    assert_eq!(
        rebuilt.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    assert_eq!(b.head_fingerprint().unwrap(), a.head_fingerprint().unwrap());
    assert_eq!(view(&rebuilt), view(&b));
}

// --- clones ----------------------------------------------------------------------------------

/// A device with a `state.db` on disk, so that its state directory can be copied.
struct OnDisk {
    dir: PathBuf,
}

impl OnDisk {
    fn db(&self) -> Db {
        Db::open(&self.dir.join("state.db")).unwrap()
    }
}

/// Device "x" with two commits behind it, closed; and a byte copy of its state directory.
async fn cloned_device(w: &World) -> (OnDisk, OnDisk, DeviceId) {
    let original = OnDisk {
        dir: w.tmp.path().join("state-x"),
    };
    let x = w.open(original.db(), "x", 1).await;
    x.refresh().await.unwrap();
    x.commit_ops(vec![put("x/1", 1)]).await.unwrap();
    x.commit_ops(vec![put("x/2", 2)]).await.unwrap();
    let id = x.device_id();
    drop(x);
    let copy = OnDisk {
        dir: w.tmp.path().join("state-x-copy"),
    };
    std::fs::create_dir_all(&copy.dir).unwrap();
    std::fs::copy(original.dir.join("state.db"), copy.dir.join("state.db")).unwrap();
    (original, copy, id)
}

#[tokio::test]
async fn clones_that_commit_the_same_seq_both_rotate() {
    let (w, a) = world().await;
    let (original, copy, id) = cloned_device(&w).await;
    // same pinned machine fingerprint: the copy is not noticed when it opens
    let x = w.open(original.db(), "x", 1).await;
    let y = w.open(copy.db(), "y", 1).await;
    assert_eq!((x.device_id(), y.device_id()), (id, id));
    x.commit_ops(vec![put("from-x", 3)]).await.unwrap();
    y.commit_ops(vec![put("from-y", 4)]).await.unwrap();
    let prefix = format!("s-{}-{:016x}-", id.hex(), 3);
    assert_eq!(
        w.listed(&prefix).len(),
        2,
        "a fork: two segments with one (device, seq)"
    );

    let rx = x.refresh().await.unwrap();
    let ry = y.refresh().await.unwrap();
    assert!(rx.rotated_device && ry.rotated_device);
    assert_eq!((rx.forks, ry.forks), (1, 1));
    assert_ne!(x.device_id(), id);
    assert_ne!(y.device_id(), id);
    assert_ne!(x.device_id(), y.device_id());
    for v in [&x, &y] {
        let seen = paths(v);
        assert!(seen.contains(&"from-x".to_owned()) && seen.contains(&"from-y".to_owned()));
    }

    // both continue under their new ids, from seq 1, and everyone converges
    x.commit_ops(vec![put("x-again", 5)]).await.unwrap();
    y.commit_ops(vec![put("y-again", 6)]).await.unwrap();
    assert_eq!(
        w.listed(&format!("s-{}-{:016x}-", x.device_id().hex(), 1))
            .len(),
        1
    );
    for v in [&x, &y, &a, &x, &y] {
        let r = v.refresh().await.unwrap();
        assert!(!r.rotated_device);
    }
    assert_eq!(view(&x), view(&y));
    assert_eq!(view(&x), view(&a));
    assert_eq!(x.head_fingerprint().unwrap(), a.head_fingerprint().unwrap());
    let devices = a.devices().unwrap();
    assert!(
        devices
            .iter()
            .any(|d| d.id == x.device_id() && d.name == "x")
    );
    assert!(
        devices
            .iter()
            .any(|d| d.id == y.device_id() && d.name == "y")
    );
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), view(&a));
}

#[tokio::test]
async fn fork_twins_at_one_path_are_resolved_without_losing_the_winner() {
    let (w, a) = world().await;
    let (original, copy, _) = cloned_device(&w).await;
    let x = w.open(original.db(), "x", 1).await;
    let y = w.open(copy.db(), "y", 1).await;
    // the same op index of the same (device, lamport): two heads with EQUAL stamps
    x.commit_ops(vec![put("twin", 3)]).await.unwrap();
    y.commit_ops(vec![put("twin", 4)]).await.unwrap();
    x.refresh().await.unwrap();
    let heads = x.heads("twin").unwrap();
    assert_eq!(heads.len(), 2);
    assert_eq!(heads[0].stamp, heads[1].stamp);
    assert!(heads[0].winner && heads[0].entry.hash > heads[1].entry.hash);
    let (winner, loser) = (heads[0].clone(), heads[1].clone());

    // a `Del` on the shared stamp would take the winner along: the resolution re-puts it
    assert_eq!(x.resolve_conflicts().await.unwrap(), 1);
    assert!(x.conflicts().unwrap().is_empty());
    let copy_path = conflict_name("twin", &loser.stamp);
    let kept = x.head("twin").unwrap().unwrap();
    assert_eq!(kept.entry, winner.entry);
    assert!(kept.stamp > winner.stamp);
    assert_eq!(x.head(&copy_path).unwrap().unwrap().entry, loser.entry);
    assert_eq!(x.removed_versions("twin").unwrap().len(), 2);

    for v in [&y, &a] {
        v.refresh().await.unwrap();
        assert_eq!(view(v), view(&x));
        assert_eq!(v.resolve_conflicts().await.unwrap(), 0);
    }
    w.assert_no_double_puts();
}

#[tokio::test]
async fn a_clone_rotates_on_a_foreign_segment_below_its_next_seq() {
    let (w, _a) = world().await;
    let (original, copy, id) = cloned_device(&w).await;
    let x = w.open(original.db(), "x", 1).await;
    let y = w.open(copy.db(), "y", 1).await;
    // y runs ahead: seq 3 and 4; x then publishes its own seq 3
    y.commit_ops(vec![put("y/3", 3)]).await.unwrap();
    y.commit_ops(vec![put("y/4", 4)]).await.unwrap();
    x.commit_ops(vec![put("x/3", 5)]).await.unwrap();
    let r = y.refresh().await.unwrap();
    assert!(
        r.rotated_device,
        "seq 3 is below y's next_seq, but y never sealed that segment"
    );
    assert_ne!(y.device_id(), id);
    assert!(paths(&y).contains(&"x/3".to_owned()));
    let r = x.refresh().await.unwrap();
    assert!(r.rotated_device);
    assert_eq!(view(&x), view(&y));
}

#[tokio::test]
async fn a_different_machine_rotates_before_the_first_commit() {
    let (w, a) = world().await;
    let (_original, copy, id) = cloned_device(&w).await;
    // the copied state directory is opened on "another machine"
    let y = w.open(copy.db(), "y", 2).await;
    assert_ne!(
        y.device_id(),
        id,
        "rotated when opened, before sealing anything"
    );
    let rotated = y.device_id();
    let report = y.commit_ops(vec![put("y/new", 9)]).await.unwrap();
    let name = report.segment.unwrap();
    assert!(name.starts_with(&format!("s-{}-{:016x}-", rotated.hex(), 1)));
    let r = y.refresh().await.unwrap();
    assert!(r.rotated_device, "the next refresh reports the rotation");
    assert_eq!(r.forks, 0);
    assert!(!y.refresh().await.unwrap().rotated_device);
    // re-opening on that machine does not rotate again
    let db = y.db().clone();
    drop(y);
    let y = w.open(db, "y", 2).await;
    assert_eq!(y.device_id(), rotated);
    a.refresh().await.unwrap();
    assert!(a.devices().unwrap().iter().any(|d| d.id == rotated));
    assert!(paths(&a).contains(&"y/new".to_owned()));
}

#[tokio::test]
async fn an_unreadable_segment_name_under_the_own_id_does_not_rotate() {
    let (w, a) = world().await;
    let id = a.device_id();
    let [h] = <[Handle; 1]>::try_from(w.net.new_ids(1).await.unwrap()).unwrap();
    let name = format!("s-{}-{:016x}-{}", id.hex(), 7, "deadbeef");
    w.net
        .put(
            &h,
            &w.handles.index,
            &name,
            PutBody::Small(Bytes::from_static(b"not a segment")),
        )
        .await
        .unwrap();
    let r = a.refresh().await.unwrap();
    assert!(!r.rotated_device);
    assert_eq!(r.corrupt_objects, vec![name]);
    assert_eq!(a.device_id(), id);
}

// --- coverage --------------------------------------------------------------------------------

#[tokio::test]
async fn a_fork_branch_outside_a_snapshot_is_applied_everywhere() {
    let (w, a) = world().await;
    let (original, copy, _) = cloned_device(&w).await;
    let x = w.open(original.db(), "x", 1).await;
    let y = w.open(copy.db(), "y", 1).await;
    let behind = w.join("behind").await; // has x's seq 1..2
    x.commit_ops(vec![put("branch-x", 3)]).await.unwrap();
    // a saw only x's branch when it wrote the snapshot
    a.refresh().await.unwrap();
    let snapshot = a.write_snapshot().await.unwrap();
    y.commit_ops(vec![put("branch-y", 4)]).await.unwrap();
    let both = |v: &V| {
        let seen = paths(v);
        seen.contains(&"branch-x".to_owned()) && seen.contains(&"branch-y".to_owned())
    };

    // up to date: a applies the late branch although (x, 3) is covered under another hash
    let r = a.refresh().await.unwrap();
    assert_eq!((r.applied, r.forks), (1, 1));
    assert!(both(&a));

    // fresh, everything still listed
    let fresh = w.join("fresh").await;
    assert!(both(&fresh));
    assert_eq!(view(&fresh), view(&a));

    // rebuilt: the covered segments are gone from the listing, the uncovered branch is not
    for s in w.listed("s-") {
        let (seg, _) = open_segment(&w.keys, &s.name, &w.mem.read(&s.handle).unwrap()).unwrap();
        let uncovered = |op: &Op| matches!(op, Op::Put { path, .. } if path == "branch-y");
        if !seg.ops.iter().any(uncovered) {
            w.net.trash(&s.handle).await.unwrap();
        }
    }
    assert_eq!(w.listed("s-").len(), 1);
    let r = behind.refresh().await.unwrap();
    assert_eq!(r.rebuilt_from.as_deref(), Some(snapshot.as_str()));
    assert!(both(&behind));
    assert_eq!(view(&behind), view(&a));
    let late = w.join("late").await;
    assert!(both(&late));
    assert_eq!(view(&late), view(&a));
    assert_eq!(
        late.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
}

#[tokio::test]
async fn a_replayed_covered_segment_is_inert() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("f", 1)]).await.unwrap();
    a.commit_ops(vec![put_over(&a, "f", 2)]).await.unwrap();
    a.commit_ops(vec![del(&a, "f"), put("g", 3)]).await.unwrap();
    let old = w.join("old").await;
    a.write_snapshot().await.unwrap();
    old.refresh().await.unwrap();
    let covered = w.listed("s-");
    for s in &covered {
        w.net.trash(&s.handle).await.unwrap();
    }
    a.commit_ops(vec![put("tail", 4)]).await.unwrap();
    let expect = view(&a);

    // the adversary un-trashes covered segments, one at a time and all together
    for replay in [vec![1usize], vec![0], vec![2, 3], vec![0, 1, 2, 3]] {
        for s in &covered {
            w.net.trash(&s.handle).await.unwrap();
        }
        for &i in &replay {
            w.net.untrash(&covered[i].handle).await.unwrap();
        }
        let fresh = w.device("fresh").await;
        let r = fresh.refresh().await.unwrap();
        assert_eq!(r.blocked_young, 0, "replay {replay:?}");
        assert_eq!(view(&fresh), expect, "replay {replay:?}");
        for v in [&a, &old] {
            let r = v.refresh().await.unwrap();
            assert_eq!((r.blocked_young, r.conflicts), (0, 0));
            assert_eq!(view(v), expect);
        }
        std::fs::remove_dir_all(w.cache("fresh")).unwrap();
    }
}

// --- crash safety ----------------------------------------------------------------------------

/// `put(path, tag)` with the blob it names really uploaded, and the blob's record. A sealed
/// segment that waits in the outbox is published only while its blobs are there (§5.8).
async fn put_uploaded(w: &World, v: &V, path: &str, tag: u8) -> Vec<OpDraft> {
    vec![OpDraft::Blob(upload_blob(w, v, tag).await), put(path, tag)]
}

#[tokio::test]
async fn a_failed_segment_put_is_published_once_after_reopening() {
    for lose_ack in [false, true] {
        let (w, a) = world().await;
        let mut drafts = put_uploaded(&w, &a, "f", 1).await;
        drafts.extend(put_uploaded(&w, &a, "g", 2).await);
        if lose_ack {
            w.net.lose_ack_next_put();
        } else {
            w.net.fail_put_named("s-", 1, transient);
        }
        a.stage(drafts).unwrap();
        let err = a.commit().await.unwrap_err();
        assert!(matches!(err, IndexError::OutboxStuck(_)), "{err:?}");
        // the sealed segment and its ops survive
        assert_eq!(a.db().pending_count().unwrap(), 1);
        assert!(a.outbox_stuck().is_some());
        assert!(a.walk("").unwrap().is_empty());
        assert_eq!(w.listed("s-").len(), 1 + usize::from(lose_ack));
        let fingerprint = a.head_fingerprint().unwrap();

        let db = a.db().clone();
        drop(a);
        let a = w.open(db, "a", 1).await;
        assert!(a.outbox_stuck().is_some(), "known before the first refresh");
        let r = a.refresh().await.unwrap();
        assert!(!r.outbox_stuck);
        assert_eq!(
            r.applied, 0,
            "the outbox applies its segment, the pull does not repeat it"
        );
        assert!(a.outbox_stuck().is_none());
        assert_eq!(a.db().pending_count().unwrap(), 0);
        assert_eq!(paths(&a), vec!["f".to_owned(), "g".to_owned()]);
        assert_eq!(w.listed("s-").len(), 2, "one object, put once");
        assert_ne!(a.head_fingerprint().unwrap(), fingerprint);
        assert_eq!(a.refresh().await.unwrap().applied, 0);
        // the next segment chains onto the recovered one
        let next = a
            .commit_ops(vec![put("h", 3)])
            .await
            .unwrap()
            .segment
            .unwrap();
        assert!(next.starts_with(&format!("s-{}-{:016x}-", a.device_id().hex(), 3)));
        let b = w.join("b").await;
        assert_eq!(view(&a), view(&b));
    }
}

#[tokio::test]
async fn a_stuck_outbox_blocks_publishing_but_not_reading() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("old", 1)]).await.unwrap();
    let new = put_uploaded(&w, &a, "new", 2).await;
    w.net.fail_put_named("s-", u32::MAX, quota);
    let err = a.commit_ops(new).await.unwrap_err();
    assert!(matches!(err, IndexError::OutboxStuck(_)));

    let db = a.db().clone();
    drop(a);
    let a = w.open(db, "a", 1).await;
    for _ in 0..2 {
        let r = a.refresh().await.unwrap();
        assert!(
            r.outbox_stuck,
            "a full Drive must not lock the user out of reading"
        );
    }
    let cause = a.outbox_stuck().unwrap();
    assert!(cause.contains("quota"), "{cause}");
    assert_eq!(paths(&a), vec!["old".to_owned()]);
    assert!(a.head("old").unwrap().is_some());
    assert_eq!(a.stats(w.net.now_ms()).unwrap().files, 1);

    // new work cannot be published
    a.stage(vec![put("more", 3)]).unwrap();
    let err = a.commit().await.unwrap_err();
    assert!(matches!(err, IndexError::OutboxStuck(_)), "{err:?}");
    assert_eq!(a.db().pending_count().unwrap(), 2);
    assert!(matches!(
        a.resolve_conflicts().await,
        Err(IndexError::OutboxStuck(_))
    ));
    // the end-of-command sequence has nothing to do and says so quietly
    a.finish_mutation().await.unwrap();
    assert!(a.maybe_compact().await.unwrap().is_none());
    assert_eq!(a.pending_blob_names().unwrap().len(), 2);

    w.net.clear();
    let r = a.refresh().await.unwrap();
    assert!(!r.outbox_stuck);
    assert!(a.outbox_stuck().is_none());
    assert_eq!(paths(&a), vec!["new".to_owned(), "old".to_owned()]);
    assert_eq!(a.db().pending_count().unwrap(), 1);
    a.commit().await.unwrap();
    assert_eq!(
        paths(&a),
        vec!["more".to_owned(), "new".to_owned(), "old".to_owned()]
    );
    let b = w.join("b").await;
    assert_eq!(view(&a), view(&b));
}

#[tokio::test]
async fn a_fatal_publish_failure_is_an_error_and_keeps_the_outbox() {
    let (w, a) = world().await;
    let f = put_uploaded(&w, &a, "f", 1).await;
    w.net.fail_put_named("s-", 1, fatal);
    let err = a.commit_ops(f).await.unwrap_err();
    assert!(
        matches!(err, IndexError::Backend(BackendError::Fatal { .. })),
        "{err:?}"
    );
    assert_eq!(a.db().pending_count().unwrap(), 1);
    a.refresh().await.unwrap();
    assert_eq!(paths(&a), vec!["f".to_owned()]);
}

#[tokio::test]
async fn a_damaged_segment_upload_is_retried_under_a_new_id() {
    let (w, a) = world().await;
    w.net.corrupt_md5_next_put();
    let name = a
        .commit_ops(vec![put("f", 1)])
        .await
        .unwrap()
        .segment
        .unwrap();
    let stored: Vec<ObjMeta> = w
        .mem
        .all_objects()
        .into_iter()
        .filter(|m| m.name == name)
        .collect();
    assert_eq!(stored.len(), 2, "the suspect object and its replacement");
    assert_eq!(stored.iter().filter(|m| m.trashed).count(), 1);
    let b = w.join("b").await;
    assert_eq!(view(&a), view(&b));
    // the next segment's `prev` names the replacement
    a.commit_ops(vec![put("g", 2)]).await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));
}

/// A blob object in the device's data folder, and its record.
async fn upload_blob(w: &World, v: &V, tag: u8) -> BlobRec {
    let folder = v.data_folder().await.unwrap();
    let id = w.net.new_ids(1).await.unwrap().remove(0);
    let blob = BlobId([tag; 16]);
    let size = ciphertext_len(1000 + u64::from(tag), 16);
    let data = Bytes::from(vec![tag; size as usize]);
    let meta = w
        .net
        .put(&id, &folder, &blob.hex(), PutBody::Small(data))
        .await
        .unwrap();
    v.note_blob_created().unwrap();
    BlobRec {
        id: blob,
        file_id: id.0,
        clen: size,
        md5: meta.md5.unwrap(),
        created_ms: meta.created_ms,
    }
}

#[tokio::test]
async fn stale_staged_ops_are_dropped_and_trashed_blobs_untrashed() {
    let (w, a) = world().await;
    let mut recs = Vec::new();
    for tag in [1u8, 2, 3] {
        let rec = upload_blob(&w, &a, tag).await;
        a.stage(vec![
            OpDraft::Blob(rec.clone()),
            put(&format!("file-{tag}"), tag),
        ])
        .unwrap();
        recs.push(rec);
    }
    a.stage(vec![OpDraft::Put {
        path: "empty".into(),
        entry: Entry::empty_file(5, false),
        base: None,
        origin: None,
        effect: None,
    }])
    .unwrap();
    assert_eq!(a.pending_blob_names().unwrap().len(), 3);

    // the process dies; meanwhile one blob vanishes and another lands in the trash
    let db = a.db().clone();
    drop(a);
    assert!(w.mem.hard_delete(&Handle(recs[0].file_id.clone())));
    w.net.trash(&Handle(recs[2].file_id.clone())).await.unwrap();
    let a = w.open(db, "a", 1).await;
    a.refresh().await.unwrap();
    let report = a.commit().await.unwrap();
    assert_eq!(report.dropped_ops, 2);
    assert_eq!(report.ops, 5);
    assert_eq!(
        paths(&a),
        vec!["empty".to_owned(), "file-2".to_owned(), "file-3".to_owned()]
    );
    assert!(a.blob(&recs[0].id).unwrap().is_none());
    assert_eq!(a.blob(&recs[1].id).unwrap().unwrap(), recs[1]);
    let untrashed = w
        .net
        .stat(&Handle(recs[2].file_id.clone()))
        .await
        .unwrap()
        .unwrap();
    assert!(!untrashed.trashed);
    assert_eq!(a.db().pending_count().unwrap(), 0);

    // a blob that waited longer than ORPHAN_GRACE / 2 is not trusted any more
    let old = upload_blob(&w, &a, 4).await;
    a.stage(vec![OpDraft::Blob(old.clone()), put("file-4", 4)])
        .unwrap();
    let db = a.db().clone();
    drop(a);
    w.mem.advance_ms(7 * DAY_MS + 1);
    let a = w.open(db, "a", 1).await;
    let report = a.commit().await.unwrap();
    assert_eq!((report.dropped_ops, report.ops), (2, 0));
    assert!(report.segment.is_none());
    assert!(a.head("file-4").unwrap().is_none());
    assert_eq!(a.db().pending_count().unwrap(), 0);

    // ops staged by the running process are not second-guessed
    let fresh = upload_blob(&w, &a, 5).await;
    let stats = w.net.calls(OpKind::Stat);
    a.commit_ops(vec![OpDraft::Blob(fresh), put("file-5", 5)])
        .await
        .unwrap();
    assert_eq!(w.net.calls(OpKind::Stat), stats);
    assert!(a.head("file-5").unwrap().is_some());
}

/// A segment that was sealed and then stuck in the outbox — a full Drive, a device that was
/// switched off — names blobs that no other device knows. Regression: `recover_outbox` put it
/// again as sealed, however long it had waited; another device's orphan sweep had trashed the
/// blobs by then, and the published heads (and the base rows saying "in sync") pointed at
/// objects in the trash, 30 days from being purged.
#[tokio::test]
async fn a_stale_outbox_segment_is_not_published_over_swept_blobs() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("old", 1)]).await.unwrap();
    let b = w.join("b").await;
    let pair = b.db().pair_open("/home/b", "", 4, 4, false).unwrap().id;
    let rec = upload_blob(&w, &b, 9).await;
    let effect = |key: &str| {
        Some(BaseEffect {
            pair,
            key: key.into(),
            rel: key.into(),
            kind: BaseEffectKind::Set {
                sig: StatSig {
                    size: 1,
                    mtime_ns: 2,
                    ctime_ns: 3,
                    ino: 4,
                    mode: 0o100644,
                },
                hash: [9; 32],
                observed_ns: 5,
                kind: EntryKind::File,
            },
        })
    };
    let with_effect = |path: &str, entry: Entry| OpDraft::Put {
        path: path.into(),
        entry,
        base: None,
        origin: None,
        effect: effect(path),
    };
    w.net.fail_put_named("s-", u32::MAX, quota);
    let err = b
        .commit_ops(vec![
            OpDraft::Blob(rec.clone()),
            with_effect("file-9", file(9)),
            with_effect("empty", Entry::empty_file(5, false)),
        ])
        .await
        .unwrap_err();
    assert!(matches!(err, IndexError::OutboxStuck(_)));
    assert_eq!(b.db().pending_count().unwrap(), 1);
    let db = b.db().clone();
    drop(b);
    w.net.clear();

    // b stays off for 15 days. To every other device the blob is an unknown object.
    w.mem.advance_ms(15 * DAY_MS);
    let r = a.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    let swept = gclone::sync::gc(&a, false, true, false).await.unwrap();
    assert_eq!(swept.orphans, 1, "another device's orphan sweep takes it");
    let blob = Handle(rec.file_id.clone());
    assert!(w.net.stat(&blob).await.unwrap().unwrap().trashed);

    // b comes back: the segment is withdrawn, not published.
    let b = w.open(db, "b", 1).await;
    let r = b.refresh().await.unwrap();
    assert!(!r.outbox_stuck);
    assert!(b.outbox_stuck().is_none());
    assert!(
        b.head("file-9").unwrap().is_none(),
        "no head on a blob that sits in the trash"
    );
    assert!(b.blob(&rec.id).unwrap().is_none());
    assert!(
        b.db().base_all(pair).unwrap().is_empty(),
        "no base row says the file is in sync: the next sync uploads it again"
    );
    // The ops that name no blob survive as staged ops (the device's announcement, which the
    // segment carried as b's first, and the empty file with its base effect).
    assert_eq!(b.db().pending_count().unwrap(), 2);
    let report = b.commit().await.unwrap();
    assert_eq!((report.ops, report.dropped_ops), (2, 0));
    let name = report.segment.unwrap();
    assert!(
        name.starts_with(&format!("s-{}-{:016x}-", b.device_id().hex(), 1)),
        "the withdrawn segment's sequence number is used again: {name}"
    );
    assert_eq!(paths(&b), vec!["empty".to_owned(), "old".to_owned()]);
    let base: Vec<String> = b
        .db()
        .base_all(pair)
        .unwrap()
        .into_iter()
        .map(|r| r.key)
        .collect();
    assert_eq!(base, vec!["empty".to_owned()]);

    // The journal is whole for everyone: no gap, no fork, no rotation.
    let r = a.refresh().await.unwrap();
    assert_eq!((r.blocked_young, r.forks), (0, 0));
    assert!(a.head("file-9").unwrap().is_none());
    assert_eq!(view(&a), view(&b));
    let r = b.refresh().await.unwrap();
    assert!(!r.rotated_device);
    assert_eq!(w.listed(&format!("s-{}-", b.device_id().hex())).len(), 1);
    assert_eq!(a.devices().unwrap().len(), 2);
}

/// What `recover_outbox` does with the blobs of a waiting segment, case by case (§5.8).
#[tokio::test]
async fn recover_outbox_checks_the_blobs_of_a_waiting_segment() {
    // (1) A young blob that landed in the trash is un-trashed and the segment published.
    let (w, a) = world().await;
    let rec = upload_blob(&w, &a, 3).await;
    w.net.fail_put_named("s-", 1, quota);
    let err = a
        .commit_ops(vec![OpDraft::Blob(rec.clone()), put("file-3", 3)])
        .await
        .unwrap_err();
    assert!(matches!(err, IndexError::OutboxStuck(_)));
    let blob = Handle(rec.file_id.clone());
    w.net.trash(&blob).await.unwrap();
    w.mem.advance_ms(DAY_MS);
    assert!(!a.refresh().await.unwrap().outbox_stuck);
    assert!(a.head("file-3").unwrap().is_some());
    assert!(!w.net.stat(&blob).await.unwrap().unwrap().trashed);

    // (2) A blob that is gone: its ops are dropped, the ops of the intact blob are staged
    //     again and published by the next commit.
    let (gone, kept) = (upload_blob(&w, &a, 4).await, upload_blob(&w, &a, 5).await);
    w.net.fail_put_named("s-", 1, quota);
    a.commit_ops(vec![
        OpDraft::Blob(gone.clone()),
        put("file-4", 4),
        OpDraft::Blob(kept.clone()),
        put("file-5", 5),
    ])
    .await
    .unwrap_err();
    assert!(w.mem.hard_delete(&Handle(gone.file_id.clone())));
    assert!(!a.refresh().await.unwrap().outbox_stuck);
    assert!(a.outbox_stuck().is_none());
    assert_eq!(
        a.db().pending_count().unwrap(),
        2,
        "Blob + Put of the intact blob"
    );
    assert!(
        a.head("file-5").unwrap().is_none(),
        "staged, not yet published"
    );
    let report = a.commit().await.unwrap();
    assert_eq!(report.ops, 2);
    assert!(a.head("file-4").unwrap().is_none());
    assert!(a.head("file-5").unwrap().is_some());
    assert_eq!(a.blob(&kept.id).unwrap().unwrap(), kept);
    assert!(a.blob(&gone.id).unwrap().is_none());

    // (3) `commit` meets the waiting segment first: what it drops is in its report, and the
    //     ops staged meanwhile go out together with the ones that came back.
    let gone = upload_blob(&w, &a, 6).await;
    w.net.fail_put_named("s-", 1, quota);
    a.commit_ops(vec![
        OpDraft::Blob(gone.clone()),
        put("file-6", 6),
        put("plain", 5),
    ])
    .await
    .unwrap_err();
    assert!(w.mem.hard_delete(&Handle(gone.file_id.clone())));
    let report = a.commit_ops(vec![put("more", 5)]).await.unwrap();
    assert_eq!((report.ops, report.dropped_ops), (2, 2));
    assert!(a.head("file-6").unwrap().is_none());
    assert!(a.head("plain").unwrap().is_some() && a.head("more").unwrap().is_some());

    // (4) The segment is in the store already (the process died after the put): other devices
    //     may have applied it, so it is finished as sealed — however old its blob is.
    let rec = upload_blob(&w, &a, 7).await;
    w.net.lose_ack_next_put();
    a.commit_ops(vec![OpDraft::Blob(rec.clone()), put("file-7", 7)])
        .await
        .unwrap_err();
    w.net.trash(&Handle(rec.file_id.clone())).await.unwrap();
    w.mem.advance_ms(8 * DAY_MS);
    assert!(!a.refresh().await.unwrap().outbox_stuck);
    assert!(a.head("file-7").unwrap().is_some());
    assert!(
        !w.net
            .stat(&Handle(rec.file_id.clone()))
            .await
            .unwrap()
            .unwrap()
            .trashed
    );

    // (5) An unpublished blob older than ORPHAN_GRACE / 2 is not trusted, as for staged ops.
    let rec = upload_blob(&w, &a, 8).await;
    w.net.fail_put_named("s-", 1, quota);
    a.commit_ops(vec![OpDraft::Blob(rec), put("file-8", 8)])
        .await
        .unwrap_err();
    w.mem.advance_ms(7 * DAY_MS + 1);
    assert!(!a.refresh().await.unwrap().outbox_stuck);
    assert!(a.head("file-8").unwrap().is_none());
    assert_eq!(a.db().pending_count().unwrap(), 0);

    // A segment sealed by this very commit is not second-guessed: no extra stat.
    let fresh = upload_blob(&w, &a, 10).await;
    let stats = w.net.calls(OpKind::Stat);
    a.commit_ops(vec![OpDraft::Blob(fresh), put("file-10", 10)])
        .await
        .unwrap();
    assert_eq!(w.net.calls(OpKind::Stat), stats);

    let b = w.join("b").await;
    assert_eq!(view(&a), view(&b));
    w.assert_no_double_puts();
}

/// §5.9: a blob that this device's unpublished ops name is not dead. Regression: `gc` judged
/// by heads alone, so with a `restore` stuck in the outbox (a full Drive — exactly when
/// `gc --purge` is run) it trashed and deleted the blob the restore was about to publish.
#[tokio::test]
async fn gc_spares_blobs_that_unpublished_ops_name() {
    let (w, a) = world().await;
    let rec = upload_blob(&w, &a, 9).await;
    let blob = Handle(rec.file_id.clone());
    a.commit_ops(vec![OpDraft::Blob(rec.clone()), put("f", 9)])
        .await
        .unwrap();
    a.commit_ops(vec![del(&a, "f")]).await.unwrap();

    // Day 24: the version is restored (what `restore` stages), but the Drive is full.
    w.mem.advance_ms(24 * DAY_MS);
    assert!(a.dead_blobs(w.net.now_ms()).unwrap().is_empty());
    w.net.fail_put_named("s-", u32::MAX, quota);
    let err = a.commit_ops(vec![put("f", 9)]).await.unwrap_err();
    assert!(matches!(err, IndexError::OutboxStuck(_)));

    // Day 31: the removal is older than GC_GRACE and outside RESTORE_WINDOW.
    w.mem.advance_ms(7 * DAY_MS);
    let now = w.net.now_ms();
    assert!(a.refresh().await.unwrap().outbox_stuck);
    assert!(a.dead_blobs(now).unwrap().is_empty());
    assert_eq!(a.stats(now).unwrap().dead_blob_bytes, 0);
    let report = gclone::sync::gc(&a, false, false, true).await.unwrap();
    assert_eq!((report.dead_blobs, report.purged), (0, 0));
    let meta = w.net.stat(&blob).await.unwrap().expect("the blob is there");
    assert!(!meta.trashed);

    // The same for a blob that gc itself trashed earlier and a restore then staged.
    a.set_blob_trashed(&rec.id, Some(now)).unwrap();
    assert!(a.purge_candidates(now).unwrap().is_empty());
    a.set_blob_trashed(&rec.id, None).unwrap();

    // The quota clears: the restore is published onto a blob that exists.
    w.net.clear();
    assert!(!a.refresh().await.unwrap().outbox_stuck);
    assert!(a.head("f").unwrap().is_some());
    assert!(!w.net.stat(&blob).await.unwrap().unwrap().trashed);

    // Staged (not yet sealed) ops protect their blobs as well …
    a.commit_ops(vec![del(&a, "f")]).await.unwrap();
    w.mem.advance_ms(31 * DAY_MS);
    let now = w.net.now_ms();
    a.stage(vec![put("f", 9)]).unwrap();
    assert!(a.dead_blobs(now).unwrap().is_empty());
    let report = gclone::sync::gc(&a, false, false, true).await.unwrap();
    assert_eq!((report.dead_blobs, report.purged), (0, 0));
    a.commit().await.unwrap();
    // … and without them the blob is collected as before.
    a.commit_ops(vec![del(&a, "f")]).await.unwrap();
    w.mem.advance_ms(31 * DAY_MS);
    let report = gclone::sync::gc(&a, false, false, true).await.unwrap();
    assert_eq!((report.dead_blobs, report.purged), (1, 1));
    assert!(w.net.stat(&blob).await.unwrap().is_none());
}

#[tokio::test]
async fn commit_applies_base_effects_with_the_ops_stamp() {
    let (_w, a) = world().await;
    let pair = a
        .db()
        .pair_open("/home/me/docs", "docs", 42, 7, false)
        .unwrap();
    assert_eq!(pair.identity, PairIdentity::New);
    let sig = StatSig {
        size: 1001,
        mtime_ns: 5,
        ctime_ns: 6,
        ino: u64::MAX,
        mode: 0o100644,
    };
    let effect = |key: &str, kind| {
        Some(BaseEffect {
            pair: pair.id,
            key: key.into(),
            rel: key.to_uppercase(),
            kind,
        })
    };
    let set = BaseEffectKind::Set {
        sig,
        hash: [1; 32],
        observed_ns: 99,
        kind: EntryKind::File,
    };
    // drafts are staged Del-first; the segment orders Puts before Dels
    a.commit_ops(vec![put("docs/gone", 3)]).await.unwrap();
    a.db()
        .base_put(
            pair.id,
            &[BaseRow {
                key: "gone".into(),
                rel: "gone".into(),
                kind: EntryKind::File,
                sig,
                hash: [3; 32],
                remote_stamp: a.head("docs/gone").unwrap().unwrap().stamp,
                observed_ns: 1,
            }],
        )
        .unwrap();
    a.stage(vec![OpDraft::Del {
        path: "docs/gone".into(),
        base: a.head("docs/gone").unwrap().unwrap().stamp,
        effect: effect("gone", BaseEffectKind::Forget),
    }])
    .unwrap();
    a.stage(vec![OpDraft::Put {
        path: "docs/a".into(),
        entry: file(1),
        base: None,
        origin: None,
        effect: effect("a", set),
    }])
    .unwrap();
    assert!(
        a.db().base_all(pair.id).unwrap().len() == 1,
        "effects wait for the commit"
    );
    a.commit().await.unwrap();
    let rows = a.db().base_all(pair.id).unwrap();
    assert_eq!(rows.len(), 1);
    let head = a.head("docs/a").unwrap().unwrap();
    assert_eq!(head.stamp.idx, 0, "the Put precedes the Del in the segment");
    assert_eq!(
        rows[0],
        BaseRow {
            key: "a".into(),
            rel: "A".into(),
            kind: EntryKind::File,
            sig,
            hash: [1; 32],
            remote_stamp: head.stamp,
            observed_ns: 99,
        }
    );
    assert!(a.head("docs/gone").unwrap().is_none());
}

// --- compaction ------------------------------------------------------------------------------

#[tokio::test]
async fn compaction_adoption_and_rebuilds() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    b.commit_ops(vec![put("from-b", 200)]).await.unwrap();

    // a blob whose only reference will be history older than HISTORY_KEEP when the snapshot is
    // written: `behind` marks it trashed, and that mark must survive the rebuild
    let rec = BlobRec {
        id: BlobId([250; 16]),
        file_id: "blob-file".into(),
        clen: 4321,
        md5: [9; 16],
        created_ms: w.net.now_ms(),
    };
    a.commit_ops(vec![OpDraft::Blob(rec.clone()), put("short-lived", 250)])
        .await
        .unwrap();
    a.commit_ops(vec![del(&a, "short-lived")]).await.unwrap();
    let behind = w.join("behind").await;
    behind.set_blob_trashed(&rec.id, Some(777)).unwrap();
    let pair = behind.db().pair_open("/root", "", 1, 1, false).unwrap();
    let base_row = BaseRow {
        key: "from-b".into(),
        rel: "from-b".into(),
        kind: EntryKind::File,
        sig: StatSig {
            size: 1,
            mtime_ns: 2,
            ctime_ns: 3,
            ino: 4,
            mode: 5,
        },
        hash: [200; 32],
        remote_stamp: behind.head("from-b").unwrap().unwrap().stamp,
        observed_ns: 6,
    };
    behind
        .db()
        .base_put(pair.id, std::slice::from_ref(&base_row))
        .unwrap();
    w.mem.advance_ms(40 * DAY_MS);

    // after 64 applied segments a snapshot appears — not before
    a.refresh().await.unwrap();
    let mut i = 0u8;
    while a.stats(0).unwrap().segments < COMPACT_MIN_SEGMENTS - 1 {
        a.commit_ops(vec![put(&format!("f/{i}"), i)]).await.unwrap();
        assert!(a.maybe_compact().await.unwrap().is_none());
        i += 1;
    }
    b.refresh().await.unwrap();
    a.commit_ops(vec![put("last", 201)]).await.unwrap();
    assert_eq!(a.stats(0).unwrap().segments, COMPACT_MIN_SEGMENTS);
    a.finish_mutation().await.unwrap();
    let snaps = w.listed("c-");
    assert_eq!(snaps.len(), 1);
    let snapshot = snaps[0].name.clone();
    assert_eq!(
        (a.stats(0).unwrap().segments, a.stats(0).unwrap().snapshots),
        (0, 1)
    );
    assert!(a.maybe_compact().await.unwrap().is_none());
    let expect = view(&a);

    // b follows a's compaction: no snapshot of its own, `applied` pruned, state unchanged
    let before = view(&b);
    let r = b.refresh().await.unwrap();
    assert_eq!(r.adopted.as_deref(), Some(snapshot.as_str()));
    assert!(r.rebuilt_from.is_none());
    assert_eq!(r.applied, 1);
    assert_ne!(view(&b), before);
    assert_eq!(view(&b), expect);
    assert_eq!(
        (b.stats(0).unwrap().segments, b.stats(0).unwrap().snapshots),
        (0, 1)
    );
    assert!(b.maybe_compact().await.unwrap().is_none());
    b.finish_mutation().await.unwrap();
    assert_eq!(w.listed("c-").len(), 1);
    assert!(b.refresh().await.unwrap().adopted.is_none());

    // a fresh replica reaches the same state from scratch while everything is still listed …
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), expect);
    // … and from the snapshot alone when every covered segment is trashed
    for s in w.listed("s-") {
        w.net.trash(&s.handle).await.unwrap();
    }
    let alone = w.device("alone").await;
    let r = alone.refresh().await.unwrap();
    assert_eq!(r.rebuilt_from.as_deref(), Some(snapshot.as_str()));
    assert_eq!(view(&alone), expect);
    assert_eq!(
        alone.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    assert_eq!(alone.devices().unwrap().len(), 2);
    assert_eq!(alone.vault_name(), "gclone");
    // … plus a tail
    a.commit_ops(vec![put("tail", 202)]).await.unwrap();
    let with_tail = w.join("with-tail").await;
    assert_eq!(view(&with_tail), view(&a));

    // a device that was behind rebuilds, and keeps its base rows and its trashed_ms rows
    assert!(behind.blob(&rec.id).unwrap().is_some());
    let r = behind.refresh().await.unwrap();
    assert_eq!(r.rebuilt_from.as_deref(), Some(snapshot.as_str()));
    assert_eq!(view(&behind), view(&a));
    assert_eq!(behind.db().base_all(pair.id).unwrap(), vec![base_row]);
    assert_eq!(behind.blob(&rec.id).unwrap(), Some(rec.clone()));
    assert_eq!(behind.stats(0).unwrap().trashed_blob_bytes, 4321);
    // the snapshot no longer carries that blob: its history aged out
    assert!(alone.blob(&rec.id).unwrap().is_none());
    assert!(alone.removed_versions("short-lived").unwrap().is_empty());
    for v in [&a, &b, &fresh, &alone, &behind] {
        v.refresh().await.unwrap();
    }
}

#[tokio::test]
async fn compaction_waits_for_conflicts_to_be_resolved() {
    let (w, a, _b) = conflict_at("p", 1, 2).await;
    for i in 0..COMPACT_MIN_SEGMENTS as u8 {
        a.commit_ops(vec![put(&format!("f{i}"), i)]).await.unwrap();
    }
    assert!(
        a.maybe_compact().await.unwrap().is_none(),
        "a conflict is unresolved"
    );
    a.finish_mutation().await.unwrap();
    assert_eq!(w.listed("c-").len(), 1);
    assert!(a.conflicts().unwrap().is_empty());
}

// --- cleanup ---------------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_is_delayed_writer_only_and_keeps_two_snapshots() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    for i in 0..4 {
        a.commit_ops(vec![put(&format!("one/{i}"), i)])
            .await
            .unwrap();
    }
    let s1 = a.write_snapshot().await.unwrap();
    b.refresh().await.unwrap();
    let covered_by_s1 = w.listed("s-").len();
    assert_eq!(covered_by_s1, 5);

    assert_eq!(
        a.cleanup_index().await.unwrap(),
        0,
        "younger than INDEX_TRASH_DELAY"
    );
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS - 1);
    assert_eq!(a.cleanup_index().await.unwrap(), 0);
    w.mem.advance_ms(1);
    assert_eq!(
        b.cleanup_index().await.unwrap(),
        0,
        "only the writer of the snapshot cleans up"
    );
    assert_eq!(a.cleanup_index().await.unwrap(), 5);
    assert!(w.listed("s-").is_empty());
    assert_eq!(w.listed("c-").len(), 1);
    assert_eq!(a.cleanup_index().await.unwrap(), 0);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();

    // two more snapshots: the oldest goes, the newest two stay
    for i in 0..3 {
        a.commit_ops(vec![put(&format!("two/{i}"), i)])
            .await
            .unwrap();
    }
    let s2 = a.write_snapshot().await.unwrap();
    for i in 0..2 {
        a.commit_ops(vec![put(&format!("three/{i}"), i)])
            .await
            .unwrap();
    }
    let s3 = a.write_snapshot().await.unwrap();
    a.commit_ops(vec![put("tail", 9)]).await.unwrap();
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    // 1 snapshot (s1) + the 3 segments that both retained snapshots cover
    assert_eq!(a.cleanup_index().await.unwrap(), 4);
    let snaps: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    assert_eq!(snaps.len(), 2);
    assert!(snaps.contains(&s2) && snaps.contains(&s3) && !snaps.contains(&s1));
    // the two segments only s3 covers, and the uncovered tail, are still listed
    assert_eq!(w.listed("s-").len(), 3);

    for v in [&a, &b] {
        v.refresh().await.unwrap();
    }
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), view(&a));
    assert_eq!(view(&b), view(&a));
}

fn drop_cached_snapshots(w: &World, device: &str) {
    for entry in std::fs::read_dir(w.cache(device)).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with("c-") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
}

/// Regression (cost): once a cleanup had trashed the tip segment of a device that then stayed
/// quiet, the presence check proved that rollback mark by loading and decoding a whole
/// snapshot — on every refresh of every device — although the answer is in `base_covered`.
/// And every mutating command's cleanup listed the index and decoded every listed snapshot
/// again, to find nothing to do. With the cached copies removed, each such load shows as a
/// download.
#[tokio::test]
async fn snapshots_are_not_reloaded_command_after_command() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    b.commit_ops(vec![put("b/0", 9)]).await.unwrap();
    a.refresh().await.unwrap();
    for i in 0..3 {
        a.commit_ops(vec![put(&format!("one/{i}"), i)])
            .await
            .unwrap();
    }
    let s1 = a.write_snapshot().await.unwrap();
    a.commit_ops(vec![put("two", 7)]).await.unwrap();
    a.write_snapshot().await.unwrap();
    b.refresh().await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();

    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    assert!(a.cleanup_index().await.unwrap() > 0);
    assert!(
        w.listed(&format!("s-{}-", b.device_id().hex())).is_empty(),
        "b's tip segment is trashed: its mark is no longer listed"
    );

    // Refresh: the marks are proved from the base's coverage, no snapshot is loaded.
    for _ in 0..2 {
        for (name, v) in [("a", &a), ("b", &b)] {
            drop_cached_snapshots(&w, name);
            w.mem.reset_counters();
            v.refresh().await.unwrap();
            let c = w.mem.counters();
            assert_eq!((c.list, c.get), (1, 0), "refresh of {name}");
        }
    }

    // Cleanup with nothing new to decide: one listing, nothing read, nothing decoded.
    for _ in 0..2 {
        drop_cached_snapshots(&w, "a");
        w.mem.reset_counters();
        assert_eq!(a.cleanup_index().await.unwrap(), 0);
        let c = w.mem.counters();
        assert_eq!((c.list, c.stat, c.get, c.trash), (1, 0, 0, 0));
    }
    // At the end of a command the refresh's own listing answers it: no call at all.
    a.refresh().await.unwrap();
    drop_cached_snapshots(&w, "a");
    w.mem.reset_counters();
    a.finish_mutation().await.unwrap();
    let c = w.mem.counters();
    assert_eq!((c.list, c.stat, c.get, c.put), (0, 0, 0, 0));

    // A change in the listed snapshots is a reason to look again: b's new snapshot makes a's
    // first one the third-newest, and a's cleanup takes it.
    b.commit_ops(vec![put("b/1", 8)]).await.unwrap();
    let s3 = b.write_snapshot().await.unwrap();
    a.refresh().await.unwrap();
    a.finish_mutation().await.unwrap();
    let snaps: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    assert_eq!(snaps.len(), 2);
    assert!(snaps.contains(&s3) && !snaps.contains(&s1), "{snaps:?}");
    // … and that pass is remembered in turn.
    a.refresh().await.unwrap();
    w.mem.reset_counters();
    a.finish_mutation().await.unwrap();
    assert_eq!(w.mem.counters().list, 0);

    for v in [&a, &b] {
        v.refresh().await.unwrap();
    }
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), view(&a));
    assert_eq!(view(&b), view(&a));
}

#[tokio::test]
async fn cleanup_never_trashes_an_object_that_fails_acceptance() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("f", 1)]).await.unwrap();
    // an impostor carries the name of a covered segment
    let genuine = w.segment(a.device_id(), 2);
    let id = w.net.new_ids(1).await.unwrap().remove(0);
    w.net
        .put(
            &id,
            &w.handles.index,
            &genuine.name,
            PutBody::Small(Bytes::from_static(b"junk")),
        )
        .await
        .unwrap();
    a.write_snapshot().await.unwrap();
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    assert_eq!(a.cleanup_index().await.unwrap(), 2);
    let left = w.listed("s-");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].handle, id);

    // a snapshot that was altered after it was written stops its writer's cleanup altogether
    a.commit_ops(vec![put("g", 2)]).await.unwrap();
    let name = a.write_snapshot().await.unwrap();
    let snap = w.listed(&name).remove(0);
    w.mem.tamper(&snap.handle, |b| b.truncate(b.len() - 1));
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    assert_eq!(a.cleanup_index().await.unwrap(), 0);
}

#[tokio::test]
async fn two_concurrent_compactors() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    for i in 0..3 {
        a.commit_ops(vec![put(&format!("a/{i}"), i)]).await.unwrap();
        b.refresh().await.unwrap();
        b.commit_ops(vec![put(&format!("b/{i}"), 10 + i)])
            .await
            .unwrap();
        a.refresh().await.unwrap();
    }
    // each writes one more segment the other has not seen, then both compact
    a.commit_ops(vec![put("a/last", 20)]).await.unwrap();
    b.commit_ops(vec![put("b/last", 21)]).await.unwrap();
    let a_last = w
        .listed(&format!("s-{}-", a.device_id().hex()))
        .pop()
        .unwrap();
    let b_last = w
        .listed(&format!("s-{}-", b.device_id().hex()))
        .pop()
        .unwrap();
    let s_a = a.write_snapshot().await.unwrap();
    let s_b = b.write_snapshot().await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));

    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    let trashed = a.cleanup_index().await.unwrap() + b.cleanup_index().await.unwrap();
    assert!(trashed > 0);
    // two incomparable snapshots: both are kept, only their common coverage is trashed
    let snaps: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    assert_eq!(snaps.len(), 2);
    assert!(snaps.contains(&s_a) && snaps.contains(&s_b));
    let segs: Vec<String> = w.listed("s-").into_iter().map(|m| m.name).collect();
    assert_eq!(segs.len(), 2);
    assert!(segs.contains(&a_last.name) && segs.contains(&b_last.name));

    // no Rollback on either device, and a fresh device joins without a gap
    for v in [&a, &b] {
        let r = v.refresh().await.unwrap();
        assert_eq!(r.blocked_young, 0);
    }
    let fresh = w.device("fresh").await;
    let r = fresh.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    assert!(r.rebuilt_from.is_some());
    assert_eq!(view(&fresh), view(&a));
    assert_eq!(
        fresh.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );

    // the next snapshot, written after both were seen, dominates both and lets cleanup finish
    let s3 = a.write_snapshot().await.unwrap();
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    a.cleanup_index().await.unwrap();
    let snaps: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    assert_eq!(snaps.len(), 2, "the newest two are always kept");
    assert!(snaps.contains(&s3));
    let s4 = a.write_snapshot().await.unwrap();
    w.mem.advance_ms(INDEX_TRASH_DELAY_MS);
    a.cleanup_index().await.unwrap();
    let snaps: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    assert_eq!(snaps.len(), 2);
    assert!(snaps.contains(&s3) && snaps.contains(&s4));
    assert!(w.listed("s-").is_empty(), "the rest is trashed");

    for v in [&a, &b, &fresh] {
        v.refresh().await.unwrap();
    }
    let late = w.join("late").await;
    assert_eq!(view(&late), view(&a));
    assert_eq!(view(&b), view(&a));
}

// --- repair ----------------------------------------------------------------------------------

fn empty_dir(dir: &std::path::Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
}

#[tokio::test]
async fn repair_republishes_from_the_cache_and_cures_another_devices_gap() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    a.commit_ops(vec![put("two", 2)]).await.unwrap();
    let lost = w.segment(a.device_id(), 2);
    assert!(w.mem.hard_delete(&lost.handle));

    let b = w.device("b").await;
    assert_eq!(b.refresh().await.unwrap().blocked_young, 1);
    w.tick(GAP_GRACE_MS);
    assert!(matches!(b.refresh().await, Err(IndexError::Gap { .. })));
    assert!(matches!(
        a.refresh().await,
        Err(IndexError::Rollback { .. })
    ));

    let report = a.repair(false).await.unwrap();
    assert_eq!(report.republished, vec![lost.name.clone()]);
    assert!(report.untrashed.is_empty() && report.still_missing.is_empty());
    assert!(report.snapshot.is_some());
    let again = w.segment(a.device_id(), 2);
    assert_ne!(
        again.handle, lost.handle,
        "same name and bytes under a new id"
    );
    a.refresh().await.unwrap();

    let r = b.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    assert_eq!(view(&a), view(&b));
    assert_eq!(paths(&b), vec!["one".to_owned(), "two".to_owned()]);

    // a trashed object is un-trashed instead of duplicated
    a.commit_ops(vec![put("three", 3)]).await.unwrap();
    let hidden = w.segment(a.device_id(), 4);
    w.net.trash(&hidden.handle).await.unwrap();
    assert!(matches!(
        a.refresh().await,
        Err(IndexError::Rollback { .. })
    ));
    let report = a.repair(false).await.unwrap();
    assert_eq!(report.untrashed, vec![hidden.name.clone()]);
    assert!(report.republished.is_empty());
    assert_eq!(w.segment(a.device_id(), 4).handle, hidden.handle);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(view(&a), view(&b));
}

#[tokio::test]
async fn a_presence_failure_with_an_empty_cache_is_cured_by_a_snapshot() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    b.refresh().await.unwrap();
    assert!(w.mem.hard_delete(&w.segment(a.device_id(), 2).handle));
    empty_dir(&w.cache("a"));
    empty_dir(&w.cache("b"));

    for v in [&a, &b] {
        let err = v.refresh().await.unwrap_err();
        assert!(
            matches!(err, IndexError::Rollback { seq: 2, .. }),
            "{err:?}"
        );
        // read-only use continues on the consistent replica
        assert_eq!(paths(v), vec!["one".to_owned()]);
    }
    let report = a.repair(false).await.unwrap();
    assert!(report.republished.is_empty() && report.still_missing.is_empty());
    let snapshot = report.snapshot.unwrap();
    a.refresh().await.unwrap();
    // b: the lost segment's identity is in a listed snapshot's covered set
    let r = b.refresh().await.unwrap();
    assert_eq!(r.adopted.as_deref(), Some(snapshot.as_str()));
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), view(&a));
    assert_eq!(view(&b), view(&a));
}

#[tokio::test]
async fn repair_accept_loss_and_the_device_that_still_holds_the_segment() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("x", 1)]).await.unwrap();
    a.commit_ops(vec![put("y", 2)]).await.unwrap();
    let lost = w.segment(a.device_id(), 2);
    assert!(w.mem.hard_delete(&lost.handle));
    let b = w.device("b").await;
    b.refresh().await.unwrap();
    w.tick(GAP_GRACE_MS);
    assert!(matches!(b.refresh().await, Err(IndexError::Gap { .. })));

    // without --accept-loss: exactly what is missing, nothing changed
    let report = b.repair(false).await.unwrap();
    assert_eq!(report.still_missing.len(), 1);
    assert!(
        report.still_missing[0].starts_with(&lost.name),
        "{:?}",
        report.still_missing
    );
    assert!(report.still_missing[0].contains("seq 2"));
    assert!(report.snapshot.is_none() && report.accepted_loss.is_empty());
    assert!(matches!(b.refresh().await, Err(IndexError::Gap { .. })));
    assert!(paths(&b).is_empty());

    let report = b.repair(true).await.unwrap();
    assert_eq!(report.accepted_loss.len(), 1);
    assert!(report.still_missing.is_empty());
    let snapshot = report.snapshot.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(paths(&b), vec!["y".to_owned()]);
    // the snapshot claims only what was applied
    let object = w.listed(&snapshot).remove(0);
    let (snap, _) =
        open_snapshot(&w.keys, &snapshot, &w.mem.read(&object.handle).unwrap()).unwrap();
    let skipped = CoveredSeg {
        device: a.device_id(),
        seq: 2,
        h4: lost
            .name
            .rsplit('-')
            .next()
            .map(|h| {
                let b = gclone::util::unhex(h).unwrap();
                [b[0], b[1], b[2], b[3]]
            })
            .unwrap(),
    };
    assert!(!snap.covered.contains(&skipped));
    assert!(
        snap.covered
            .iter()
            .any(|c| c.device == a.device_id() && c.seq == 3)
    );
    // a fresh device rebuilds from it without a gap
    let fresh = w.join("fresh").await;
    assert_eq!(view(&fresh), view(&b));

    // a still holds the skipped segment: Rollback, and its repair gives the segment back
    let err = a.refresh().await.unwrap_err();
    assert!(
        matches!(err, IndexError::Rollback { seq: 2, .. }),
        "{err:?}"
    );
    assert_eq!(paths(&a), vec!["x".to_owned(), "y".to_owned()]);
    let report = a.repair(false).await.unwrap();
    assert_eq!(report.republished, vec![lost.name.clone()]);
    a.refresh().await.unwrap();
    for v in [&b, &fresh] {
        v.refresh().await.unwrap();
        assert_eq!(view(v), view(&a));
    }
    assert_eq!(paths(&b), vec!["x".to_owned(), "y".to_owned()]);
    assert_eq!(b.head_fingerprint().unwrap(), a.head_fingerprint().unwrap());
}

// --- create / discover / keyfile -------------------------------------------------------------

#[tokio::test]
async fn create_writes_the_descriptor_last() {
    let mem = MemBackend::new();
    let net = Arc::new(Flaky::new(mem.clone()));
    let tmp = tempfile::tempdir().unwrap();
    assert!(
        V::discover(&net).await.unwrap().is_empty(),
        "an empty backend holds no vault"
    );

    net.fail_put_named(DESCRIPTOR_NAME, 1, fatal);
    let first = [0x21; 16];
    let err = Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keyring(first),
        create_params(first, tmp.path().join("one")),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        err,
        IndexError::Backend(BackendError::Fatal { .. })
    ));
    // everything but the descriptor exists …
    let objects = mem.all_objects();
    let names: Vec<&str> = objects.iter().map(|m| m.name.as_str()).collect();
    for expected in ["gclone", "index", "data", README_NAME] {
        assert!(names.contains(&expected), "{expected} missing in {names:?}");
    }
    assert!(names.iter().any(|n| n.starts_with("gclone-key-00000001-")));
    assert!(names.iter().any(|n| n.starts_with("s-")));
    assert!(!names.contains(&DESCRIPTOR_NAME));
    // … so the half-made vault is not discovered
    assert!(V::discover(&net).await.unwrap().is_empty());

    // a second create succeeds beside the orphan
    let second = [0x22; 16];
    let params = create_params(second, tmp.path().join("two"));
    let keyfile = params.keyfile.clone();
    let (vault, own) = Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keyring(second),
        params,
    )
    .await
    .unwrap();
    let roots = mem
        .all_objects()
        .into_iter()
        .filter(|m| m.name == "gclone")
        .count();
    assert_eq!(roots, 2);
    let found = V::discover(&net).await.unwrap();
    assert_eq!(found.len(), 1);
    let v = &found[0];
    assert_eq!((v.vault_id, v.root_name.as_str()), (second, "gclone"));
    assert_eq!(v.descriptor_created_ms, own.descriptor_created_ms);
    assert_eq!(v.handles.root, vault.handles().root);
    assert_eq!(v.handles.index, vault.handles().index);
    assert_eq!(v.handles.data, vault.handles().data);
    assert_eq!(v.keyfiles.len(), 1);
    assert_eq!(v.keyfiles[0].name, keyfile.name);
    assert_eq!(mem.read(&v.keyfiles[0].handle).unwrap(), keyfile.bytes);
    assert_eq!(own.keyfiles[0].handle, v.keyfiles[0].handle);

    // the first segment is [VaultInit, Device] and the creator is a device of the vault
    assert_eq!(vault.vault_name(), "gclone");
    let devices = vault.devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        (devices[0].id, devices[0].name.as_str()),
        (vault.device_id(), "a")
    );
    let first_segment = mem
        .all_objects()
        .into_iter()
        .find(|m| m.parent == v.handles.index)
        .unwrap();
    let (seg, _) = open_segment(
        vault.keys(),
        &first_segment.name,
        &mem.read(&first_segment.handle).unwrap(),
    )
    .unwrap();
    assert_eq!((seg.seq, seg.ops.len()), (1, 2));
    assert!(matches!(&seg.ops[0], Op::VaultInit { format: 1, name } if name == "gclone"));
    assert!(matches!(&seg.ops[1], Op::Device { name, .. } if name == "a"));
    assert!(seg.prev.is_none() && seg.seen.is_empty());

    // a keyring of another vault is refused before anything is written
    let before = mem.all_objects().len();
    let wrong = Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keyring([0x33; 16]),
        create_params([0x34; 16], tmp.path().join("three")),
    )
    .await;
    assert!(matches!(wrong, Err(IndexError::Format(_))));
    assert_eq!(mem.all_objects().len(), before);
}

async fn make_vault(
    net: &Arc<Net>,
    tmp: &tempfile::TempDir,
    id: u8,
) -> (V, gclone::index::FoundVault) {
    let vault_id = [id; 16];
    Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keyring(vault_id),
        create_params(vault_id, tmp.path().join(format!("vault-{id}"))),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn discover_sorts_vaults_and_refuses_ambiguous_folders() {
    let mem = MemBackend::new();
    let net = Arc::new(Flaky::new(mem.clone()));
    let tmp = tempfile::tempdir().unwrap();
    let (_late, _) = {
        mem.advance_ms(5_000);
        make_vault(&net, &tmp, 0x50).await
    };
    // two vaults created in the same millisecond: the id breaks the tie
    mem.advance_ms(5_000);
    let (_x, found_x) = make_vault(&net, &tmp, 0x70).await;
    let (_y, found_y) = make_vault(&net, &tmp, 0x60).await;
    assert_eq!(found_x.descriptor_created_ms, found_y.descriptor_created_ms);

    let found = V::discover(&net).await.unwrap();
    let ids: Vec<u8> = found.iter().map(|v| v.vault_id[0]).collect();
    assert_eq!(ids, vec![0x50, 0x60, 0x70]);
    assert_eq!(creation_winner(&found).unwrap().vault_id, [0x50; 16]);
    assert_eq!(creation_winner(&found[1..]).unwrap().vault_id, [0x60; 16]);
    assert!(creation_winner(&[]).is_none());
    // own vault first in the slice or last: the rule does not depend on the order
    let mut reversed = found.clone();
    reversed.reverse();
    assert_eq!(creation_winner(&reversed).unwrap().vault_id, [0x50; 16]);

    // an unparsable descriptor, and one that needs a newer reader, are skipped
    for (i, body) in [
        &b"{ not json"[..],
        br#"{"gclone_vault":9,"min_reader":9,"vault_id":"00112233445566778899aabbccddeeff","created_ms":1}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let ids = net.new_ids(2).await.unwrap();
        net.create_folder(&ids[0], &Handle::top(), &format!("junk-{i}")).await.unwrap();
        net.put(&ids[1], &ids[0], DESCRIPTOR_NAME, PutBody::Small(Bytes::copy_from_slice(body)))
            .await
            .unwrap();
    }
    assert_eq!(V::discover(&net).await.unwrap().len(), 3);

    // keyfiles: highest generation first, ties by name descending; other names are not keyfiles
    let root = &found[0].handles.root;
    let mut expected = vec![found[0].keyfiles[0].name.clone()];
    for (generation, tag) in [(3u32, 3u8), (2, 4), (3, 5)] {
        let kf = fake_keyfile(generation, tag);
        let id = net.new_ids(1).await.unwrap().remove(0);
        net.put(&id, root, &kf.name, PutBody::Small(kf.bytes.into()))
            .await
            .unwrap();
        expected.push(kf.name);
    }
    let id = net.new_ids(1).await.unwrap().remove(0);
    net.put(
        &id,
        root,
        "gclone-key-0000002-abcdef01",
        PutBody::Small(Bytes::new()),
    )
    .await
    .unwrap();
    expected.sort_by(|a, b| b.cmp(a));
    let listed: Vec<String> = V::discover(&net).await.unwrap()[0]
        .keyfiles
        .iter()
        .map(|m| m.name.clone())
        .collect();
    assert_eq!(listed, expected);
    assert!(
        listed[0].starts_with("gclone-key-00000003-")
            && listed[3].starts_with("gclone-key-00000001-")
    );

    // two children named `index`: an explicit error, never a silent pick
    let id = net.new_ids(1).await.unwrap().remove(0);
    net.create_folder(&id, root, "index").await.unwrap();
    let err = V::discover(&net).await.unwrap_err();
    assert!(err.to_string().contains("two folders named index"), "{err}");
    assert_eq!(gclone::error::exit_code(&anyhow::Error::new(err)), 1);

    // a login that may not read the vault
    net.fail_next(OpKind::FindByName, 1, || BackendError::AppNotAuthorized);
    assert!(matches!(
        V::discover(&net).await,
        Err(IndexError::VaultNotVisible)
    ));
}

#[tokio::test]
async fn discover_finds_the_descriptor_at_depth_one_and_at_the_top() {
    let tmp = tempfile::tempdir().unwrap();
    let outer = tmp.path().join("drive");
    std::fs::create_dir(&outer).unwrap();
    let dir = Arc::new(DirBackend::open(&outer).unwrap());
    let vault_id = [0x44; 16];
    let (vault, own) = Vault::create(
        dir.clone(),
        Db::open_in_memory().unwrap(),
        keyring(vault_id),
        create_params(vault_id, tmp.path().join("cache")),
    )
    .await
    .unwrap();
    vault.commit_ops(vec![put("hello", 1)]).await.unwrap();

    let found = Vault::<DirBackend>::discover(&dir).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].vault_id, found[0].root_name.as_str()),
        (vault_id, "gclone")
    );
    assert_eq!(found[0].handles.root, own.handles.root);
    assert_eq!(found[0].keyfiles.len(), 1);
    Vault::<DirBackend>::verify_visible(&dir, &found[0].handles)
        .await
        .unwrap();

    // a directory cannot hold a second folder of that name (§2.6)
    let again = Vault::create(
        dir.clone(),
        Db::open_in_memory().unwrap(),
        keyring([0x45; 16]),
        create_params([0x45; 16], tmp.path().join("cache-2")),
    )
    .await;
    assert!(
        matches!(&again, Err(IndexError::Backend(BackendError::Fatal { status: 409, reason, .. })) if reason == "nameConflict"),
        "{:?}",
        again.err()
    );

    // the inner vault folder alone — what a web download yields — opened as the top level
    let inner = Arc::new(DirBackend::open(&outer.join("gclone")).unwrap());
    let found = Vault::<DirBackend>::discover(&inner).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].vault_id, found[0].root_name.as_str()),
        (vault_id, "")
    );
    assert!(found[0].handles.root.is_top());
    assert_eq!(found[0].keyfiles.len(), 1);
    Vault::<DirBackend>::verify_visible(&inner, &found[0].handles)
        .await
        .unwrap();
    let reader = Vault::open(
        inner.clone(),
        Db::open_in_memory().unwrap(),
        keyring(vault_id),
        OpenParams {
            vault_id,
            handles: found[0].handles.clone(),
            device_name: "reader".into(),
            cache_dir: tmp.path().join("cache-reader"),
            machine_fp: Some([1; 32]),
        },
    )
    .await
    .unwrap();
    reader.refresh().await.unwrap();
    assert_eq!(reader.walk("").unwrap().len(), 1);
    assert_eq!(
        reader.head_fingerprint().unwrap(),
        vault.head_fingerprint().unwrap()
    );
}

#[tokio::test]
async fn verify_visible_uses_ids_only() {
    let (w, a) = world().await;
    let lists = w.net.calls(OpKind::List);
    let finds = w.net.calls(OpKind::FindByName);
    V::verify_visible(&w.net, &w.handles).await.unwrap();
    assert_eq!(w.net.calls(OpKind::List), lists, "never a listing");
    assert_eq!(w.net.calls(OpKind::FindByName), finds);

    // `index` under another parent
    let ids = w.net.new_ids(2).await.unwrap();
    w.net
        .create_folder(&ids[0], &Handle::top(), "elsewhere")
        .await
        .unwrap();
    w.net
        .create_folder(&ids[1], &ids[0], "index")
        .await
        .unwrap();
    let moved = VaultHandles {
        index: ids[1].clone(),
        ..w.handles.clone()
    };
    let err = V::verify_visible(&w.net, &moved).await.unwrap_err();
    assert!(
        err.to_string().contains("not inside the vault folder"),
        "{err}"
    );
    // a file where a folder belongs, and a handle that does not exist
    let readme = w
        .mem
        .all_objects()
        .into_iter()
        .find(|m| m.name == README_NAME)
        .unwrap();
    let not_a_folder = VaultHandles {
        data: readme.handle,
        ..w.handles.clone()
    };
    assert!(V::verify_visible(&w.net, &not_a_folder).await.is_err());
    let absent = VaultHandles {
        data: Handle("nope".into()),
        ..w.handles.clone()
    };
    assert!(matches!(
        V::verify_visible(&w.net, &absent).await,
        Err(IndexError::VaultNotVisible)
    ));

    w.net
        .fail_next(OpKind::Stat, 1, || BackendError::AppNotAuthorized);
    assert!(matches!(
        V::verify_visible(&w.net, &w.handles).await,
        Err(IndexError::VaultNotVisible)
    ));

    w.net.trash(&w.handles.root).await.unwrap();
    assert!(matches!(
        V::verify_visible(&w.net, &w.handles).await,
        Err(IndexError::VaultTrashed)
    ));
    // the same condition seen by a refresh: the listing is empty, the replica is not
    assert!(matches!(a.refresh().await, Err(IndexError::VaultTrashed)));
    assert!(V::discover(&w.net).await.unwrap().is_empty());

    assert!(w.mem.hard_delete(&w.handles.root));
    assert!(matches!(
        V::verify_visible(&w.net, &w.handles).await,
        Err(IndexError::VaultNotVisible)
    ));
    assert!(matches!(a.refresh().await, Err(IndexError::VaultMissing)));
}

#[tokio::test]
async fn replace_keyfile_trashes_lower_generations_after_the_put() {
    let (w, a) = world().await;
    let first = a.keyfiles().await.unwrap();
    assert_eq!(first.len(), 1);
    let names = |v: Vec<ObjMeta>| v.into_iter().map(|m| m.name).collect::<Vec<_>>();

    // a failing put leaves the old keyfile untouched
    let second = fake_keyfile(2, 2);
    w.net.fail_put_named("gclone-key-", 1, fatal);
    assert!(a.replace_keyfile(&second).await.is_err());
    assert_eq!(
        names(a.keyfiles().await.unwrap()),
        vec![first[0].name.clone()]
    );
    // so does a put that was not stored intact: the damaged object is trashed, nothing else
    w.net.corrupt_md5_next_put();
    assert!(a.replace_keyfile(&second).await.is_err());
    assert_eq!(
        names(a.keyfiles().await.unwrap()),
        vec![first[0].name.clone()]
    );
    let puts = w.mem.counters().put;

    assert_eq!(a.replace_keyfile(&second).await.unwrap(), 1);
    assert_eq!(w.mem.counters().put, puts + 1);
    assert_eq!(
        names(a.keyfiles().await.unwrap()),
        vec![second.name.clone()]
    );
    let old = w.net.stat(&first[0].handle).await.unwrap().unwrap();
    assert!(old.trashed, "trashed, not deleted");

    // a concurrent `passwd` on another device left a keyfile of the same generation: it survives
    let twin = fake_keyfile(2, 3);
    assert_eq!(a.replace_keyfile(&twin).await.unwrap(), 0);
    let mut both = vec![second.name.clone(), twin.name.clone()];
    both.sort_by(|a, b| b.cmp(a));
    assert_eq!(names(a.keyfiles().await.unwrap()), both);

    // the next generation retires both; junk under a lower number goes with them
    let junk = w.net.new_ids(1).await.unwrap().remove(0);
    w.net
        .put(
            &junk,
            &w.handles.root,
            "gclone-key-00000001-00000000",
            PutBody::Small(Bytes::new()),
        )
        .await
        .unwrap();
    let third = fake_keyfile(3, 4);
    assert_eq!(a.replace_keyfile(&third).await.unwrap(), 3);
    assert_eq!(names(a.keyfiles().await.unwrap()), vec![third.name.clone()]);
    // no index operation is written by any of this
    assert_eq!(w.listed("s-").len(), 1);
    let bad = SealedObject {
        name: "not-a-keyfile".into(),
        hash: [0; 32],
        bytes: vec![],
    };
    assert!(matches!(
        a.replace_keyfile(&bad).await,
        Err(IndexError::Format(_))
    ));
}

// --- data folder, queries, lock --------------------------------------------------------------

#[tokio::test]
async fn the_data_folder_is_created_lazily_and_rolled() {
    let (w, a) = world().await;
    let folders = || -> Vec<ObjMeta> {
        w.mem
            .all_objects()
            .into_iter()
            .filter(|m| m.parent == w.handles.data && m.is_folder)
            .collect()
    };
    assert!(folders().is_empty());
    let first = a.data_folder().await.unwrap();
    assert_eq!(a.data_folder().await.unwrap(), first);
    assert_eq!(folders().len(), 1);
    assert_eq!(folders()[0].name, format!("{}-0001", a.device_id().hex()));
    a.note_blob_created().unwrap();
    assert_eq!(a.db().meta_get_u64("data_folder_count").unwrap(), Some(1));
    a.db()
        .meta_set_u64("data_folder_count", DATA_FOLDER_MAX - 1)
        .unwrap();
    assert_eq!(a.data_folder().await.unwrap(), first);
    a.note_blob_created().unwrap();
    let second = a.data_folder().await.unwrap();
    assert_ne!(second, first);
    assert_eq!(folders().len(), 2);
    assert!(
        folders()
            .iter()
            .any(|m| m.name == format!("{}-0002", a.device_id().hex()))
    );
    assert_eq!(a.db().meta_get_u64("data_folder_count").unwrap(), Some(0));
    // the folder survives a re-open
    let db = a.db().clone();
    drop(a);
    let a = w.open(db, "a", 1).await;
    assert_eq!(a.data_folder().await.unwrap(), second);
}

#[tokio::test]
async fn queries_read_the_replica() {
    let (w, a) = world().await;
    let now = w.net.now_ms();
    let blob = |tag: u8, clen: u64| BlobRec {
        id: BlobId([tag; 16]),
        file_id: format!("blob-{tag}"),
        clen,
        md5: [tag; 16],
        created_ms: now,
    };
    let dir = OpDraft::Put {
        path: "empty-dir".into(),
        entry: Entry::dir(),
        base: None,
        origin: None,
        effect: None,
    };
    a.commit_ops(vec![
        OpDraft::Blob(blob(1, 5_000)),
        OpDraft::Blob(blob(2, 3_000)),
        put("docs/a.txt", 1),
        put("docs/sub/b.txt", 2),
        put("docs-other", 1),
        put("docs.txt", 2),
        put("top", 1),
        dir,
    ])
    .await
    .unwrap();

    let names = |prefix: &str| -> Vec<(String, bool, bool)> {
        a.list(prefix)
            .unwrap()
            .into_iter()
            .map(|r| (r.name, r.is_dir, r.head.is_some()))
            .collect()
    };
    assert_eq!(
        names(""),
        vec![
            ("docs".to_owned(), true, false),
            ("docs-other".to_owned(), false, true),
            ("docs.txt".to_owned(), false, true),
            ("empty-dir".to_owned(), true, true),
            ("top".to_owned(), false, true),
        ]
    );
    assert_eq!(
        names("docs"),
        vec![
            ("a.txt".to_owned(), false, true),
            ("sub".to_owned(), true, false)
        ]
    );
    assert_eq!(names("docs/sub"), vec![("b.txt".to_owned(), false, true)]);
    assert!(names("nothing").is_empty());
    assert!(names("top").is_empty());

    let walked = |prefix: &str| -> Vec<String> {
        a.walk(prefix)
            .unwrap()
            .into_iter()
            .map(|h| h.path)
            .collect()
    };
    assert_eq!(walked("docs"), vec!["docs/a.txt", "docs/sub/b.txt"]);
    assert_eq!(walked("docs/a.txt"), vec!["docs/a.txt"]);
    assert_eq!(walked("doc"), Vec::<String>::new());
    assert_eq!(walked("").len(), 6);
    for (path, is_dir) in [
        ("", true),
        ("docs", true),
        ("docs/sub", true),
        ("empty-dir", true),
        ("top", false),
        ("doc", false),
        ("docs/a.txt", false),
    ] {
        assert_eq!(a.exists_dir(path).unwrap(), is_dir, "{path:?}");
    }
    assert!(a.head("docs").unwrap().is_none());
    assert!(a.heads("nope").unwrap().is_empty());

    // search: names, not paths, in path order; directories with and without a head
    let found = |needle: &str, limit: usize| -> (Vec<(String, bool, bool)>, bool) {
        let (hits, more) = a.search(needle, limit).unwrap();
        let hits = hits
            .into_iter()
            .map(|h| (h.path, h.is_dir, h.head.is_some()));
        (hits.collect(), more)
    };
    let hit = |path: &str, is_dir: bool| (path.to_owned(), is_dir, !is_dir);
    assert_eq!(
        found("docs", 10),
        (
            vec![
                hit("docs-other", false),
                hit("docs.txt", false),
                hit("docs", true)
            ],
            false
        )
    );
    assert_eq!(
        found("TXT", 10).0,
        vec![
            hit("docs.txt", false),
            hit("docs/a.txt", false),
            hit("docs/sub/b.txt", false)
        ]
    );
    assert_eq!(found("Sub", 10), (vec![hit("docs/sub", true)], false));
    assert_eq!(found("empty", 10), (vec![hit("empty-dir", true)], false));
    assert_eq!(found("o", 1), (vec![hit("docs-other", false)], true));
    assert!(
        !found("o", 4).1,
        "exactly as many as the limit: nothing more"
    );
    assert_eq!(found("o", 4).0.len(), 4);
    for nothing in ["", "zzz", "docs/a", "/"] {
        assert_eq!(found(nothing, 10), (Vec::new(), false), "{nothing:?}");
    }
    assert_eq!(found("docs", 0), (Vec::new(), false));

    let s = a.stats(now).unwrap();
    assert_eq!((s.files, s.dirs, s.bytes), (5, 1, 3 * 1001 + 2 * 1002));
    assert_eq!(
        (
            s.blobs,
            s.blob_bytes,
            s.dead_blob_bytes,
            s.trashed_blob_bytes
        ),
        (2, 8_000, 0, 0)
    );
    // blob 1 holds one distinct member, blob 2 another: the rest of each blob is dead space
    assert_eq!(
        s.pack_dead_bytes,
        8_000 - ciphertext_len(1001, 16) - ciphertext_len(1002, 16)
    );
    assert_eq!((s.segments, s.snapshots, s.conflicts), (2, 0, 0));
    assert_eq!(s.last_change_by.as_deref(), Some("a"));
    assert_eq!(s.last_change_ms, Some(now));
    assert_eq!(a.blobs().unwrap().len(), 2);

    // deleting every file of blob 2 makes it dead — for gc only after GC_GRACE
    w.mem.advance_ms(1_000);
    let removed_at = w.net.now_ms();
    a.commit_ops(vec![del(&a, "docs/sub/b.txt"), del(&a, "docs.txt")])
        .await
        .unwrap();
    assert!(
        a.dead_blobs(removed_at + GC_GRACE_MS - 1)
            .unwrap()
            .is_empty()
    );
    let dead = a.dead_blobs(removed_at + GC_GRACE_MS).unwrap();
    assert_eq!(dead, vec![(blob(2, 3_000), removed_at)]);
    assert_eq!(
        a.stats(removed_at + GC_GRACE_MS).unwrap().dead_blob_bytes,
        3_000
    );
    assert_eq!(a.stats(removed_at).unwrap().dead_blob_bytes, 0);
    let history = a.removed_versions("docs.txt").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        (history[0].removed_ms, history[0].entry.clone()),
        (removed_at, file(2))
    );

    // gc marks it trashed: no longer "dead", purgeable once nothing can restore it
    a.set_blob_trashed(&BlobId([2; 16]), Some(removed_at + GC_GRACE_MS))
        .unwrap();
    assert!(a.dead_blobs(u64::MAX / 2).unwrap().is_empty());
    assert_eq!(a.stats(now).unwrap().trashed_blob_bytes, 3_000);
    assert_eq!(a.stats(now).unwrap().blobs, 1);
    assert!(
        a.purge_candidates(removed_at + RESTORE_WINDOW_MS - 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        a.purge_candidates(removed_at + RESTORE_WINDOW_MS).unwrap(),
        vec![blob(2, 3_000)]
    );
    // restore clears the mark; a purge forgets the row
    a.set_blob_trashed(&BlobId([2; 16]), None).unwrap();
    assert!(a.purge_candidates(u64::MAX / 2).unwrap().is_empty());
    a.forget_blob(&BlobId([2; 16])).unwrap();
    assert!(a.blob(&BlobId([2; 16])).unwrap().is_none());
    assert_eq!(a.blob(&BlobId([1; 16])).unwrap(), Some(blob(1, 5_000)));

    // the ledger and the pair table live in the same database
    a.db().ledger_add(now, LedgerDir::Up, 10).unwrap();
    assert_eq!(a.db().ledger_sum_24h(now, LedgerDir::Up).unwrap(), 10);
    assert_eq!(a.db().ledger_sum_24h(now, LedgerDir::Down).unwrap(), 0);
}

#[tokio::test]
async fn devices_are_listed_with_their_names_and_times() {
    let (w, a) = world().await;
    let t0 = w.net.now_ms();
    w.mem.advance_ms(60_000);
    let b = w.join("b").await;
    // ATTACH publishes the device once; a second login does not repeat it
    let announced = b.devices().unwrap().iter().any(|d| d.id == b.device_id());
    assert!(!announced);
    b.commit_ops(vec![OpDraft::Device {
        id: b.device_id(),
        name: "b".into(),
    }])
    .await
    .unwrap();
    b.finish_mutation().await.unwrap();
    a.refresh().await.unwrap();
    let devices = a.devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(
        (devices[0].id, devices[0].name.as_str(), devices[0].first_ms),
        (a.device_id(), "a", t0)
    );
    assert_eq!(
        (
            devices[1].id,
            devices[1].name.as_str(),
            devices[1].first_ms,
            devices[1].last_ms
        ),
        (b.device_id(), "b", t0 + 60_000, t0 + 60_000)
    );
    // a device that never announced itself is announced by its first segment
    let c = w.join("c").await;
    w.mem.advance_ms(60_000);
    c.commit_ops(vec![put("from-c", 1)]).await.unwrap();
    c.commit_ops(vec![put("from-c-2", 2)]).await.unwrap();
    a.refresh().await.unwrap();
    let devices = a.devices().unwrap();
    assert_eq!(devices.len(), 3);
    assert_eq!(
        (devices[2].id, devices[2].name.as_str()),
        (c.device_id(), "c")
    );
    let segments = w.listed(&format!("s-{}-", c.device_id().hex()));
    let device_ops: usize = segments
        .iter()
        .map(|m| {
            let (seg, _) = open_segment(&w.keys, &m.name, &w.mem.read(&m.handle).unwrap()).unwrap();
            seg.ops
                .iter()
                .filter(|op| matches!(op, Op::Device { .. }))
                .count()
        })
        .sum();
    assert_eq!(device_ops, 1);
    let s = a.stats(0).unwrap();
    assert_eq!(s.last_change_by.as_deref(), Some("c"));
}

/// A snapshot carries only when each device joined (`first_ms`). A replica that takes one for
/// its base — by writing it, by adopting it, or by starting from it — records that the
/// snapshot's writer was alive at the snapshot's time; otherwise a replica that starts from a
/// snapshot would name the device that joined last, at the time it joined, as the last change.
#[tokio::test]
async fn the_last_change_survives_a_snapshot_on_every_replica() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    w.mem.advance_ms(60_000);
    // `b` joins — the device that joined last — and never writes again.
    let b = w.join("b").await;
    b.commit_ops(vec![put("from-b", 2)]).await.unwrap();
    let b_joined = b.backend().now_ms();
    w.mem.advance_ms(120_000);
    // The last change is `a`'s, later; then `a` writes a snapshot that covers everything.
    a.refresh().await.unwrap();
    a.commit_ops(vec![put("two", 3)]).await.unwrap();
    w.mem.advance_ms(60_000);
    a.write_snapshot().await.unwrap();
    let written = a.backend().now_ms();
    assert!(written > b_joined);
    w.mem.advance_ms(60_000);

    // `b` applied the segments itself and adopts the snapshot; `c` starts from it (the
    // segments it covers are gone, as they are a week after a compaction).
    assert!(b.refresh().await.unwrap().adopted.is_some());
    for s in w.listed("s-") {
        w.net.trash(&s.handle).await.unwrap();
    }
    let c = w.device("c").await;
    assert!(c.refresh().await.unwrap().rebuilt_from.is_some());
    for (v, what) in [
        (&a, "wrote it"),
        (&b, "adopted it"),
        (&c, "started from it"),
    ] {
        let s = v.stats(0).unwrap();
        assert_eq!(
            (s.last_change_by.as_deref(), s.last_change_ms),
            (Some("a"), Some(written)),
            "{what}"
        );
        let seen: Vec<(String, u64)> = v
            .devices()
            .unwrap()
            .into_iter()
            .map(|d| (d.name, d.last_ms))
            .collect();
        assert!(
            seen.contains(&("a".to_owned(), written)),
            "{what}: {seen:?}"
        );
    }
    // A snapshot written by a device that is not registered (it never committed anything)
    // has no device to raise: a replica that starts from it knows the join times only.
    let d = w.device("d").await;
    d.refresh().await.unwrap();
    w.mem.advance_ms(60_000);
    d.write_snapshot().await.unwrap();
    let e = w.device("e").await;
    assert!(e.refresh().await.unwrap().rebuilt_from.is_some());
    let s = e.stats(0).unwrap();
    assert_eq!(
        (s.last_change_by.as_deref(), s.last_change_ms),
        (Some("b"), Some(b_joined))
    );
}

#[tokio::test]
async fn a_state_directory_of_another_vault_is_refused() {
    let (w, a) = world().await;
    let other = [0x99; 16];
    let params = OpenParams {
        vault_id: other,
        handles: w.handles.clone(),
        device_name: "z".into(),
        cache_dir: w.cache("z"),
        machine_fp: Some([1; 32]),
    };
    let err = Vault::open(w.net.clone(), a.db().clone(), keyring(other), params)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, IndexError::State(StateError::Corrupt(_))),
        "{err:?}"
    );
}

#[test]
fn the_state_lock_is_exclusive_and_released_on_drop() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("9f2c");
    let held = lock_exclusive(&state, Duration::from_millis(50)).unwrap();
    // a second handle — what another gclone process would open — times out
    assert!(matches!(
        lock_exclusive(&state, Duration::from_millis(150)),
        Err(StateError::Locked)
    ));
    assert!(try_lock(&state).unwrap().is_none());
    let waiter = {
        let state = state.clone();
        std::thread::spawn(move || lock_exclusive(&state, Duration::from_secs(10)).map(drop))
    };
    std::thread::sleep(Duration::from_millis(100));
    drop(held);
    waiter.join().unwrap().unwrap();
    let again = try_lock(&state).unwrap();
    assert!(again.is_some());
    assert!(try_lock(&state).unwrap().is_none());
}

/// §8.3: a read-only command that finds the lock busy uses the replica as it is. Regression:
/// it still opened the vault with a write transaction (the device name, the machine
/// fingerprint), waited five seconds for the lock holder's transaction and failed with
/// "database is locked".
#[tokio::test(flavor = "multi_thread")]
async fn a_reader_without_the_lock_is_not_blocked_by_a_writer() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("docs/x", 1)]).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");

    // Nothing there yet, or no schema yet: the lock holder is still creating it.
    assert!(matches!(Db::open_shared(&path), Err(StateError::Locked)));
    std::fs::write(&path, b"").unwrap();
    assert!(matches!(Db::open_shared(&path), Err(StateError::Locked)));
    std::fs::remove_file(&path).unwrap();

    let b = w.open(Db::open(&path).unwrap(), "b", 1).await;
    b.refresh().await.unwrap();
    let id = b.device_id();
    drop(b);

    // "The lock holder": another connection inside a long write transaction.
    let holder = rusqlite::Connection::open(&path).unwrap();
    holder
        .execute_batch("BEGIN IMMEDIATE; INSERT INTO ledger VALUES (1, 1, 1);")
        .unwrap();

    let started = std::time::Instant::now();
    let db = Db::open_shared(&path).unwrap();
    let params = OpenParams {
        vault_id: VAULT,
        handles: w.handles.clone(),
        device_name: "another name".into(),
        cache_dir: dir.path().join("no-such-cache"),
        machine_fp: None,
    };
    let reader = Vault::open_unlocked(w.net.clone(), db, w.keys.clone(), params)
        .await
        .unwrap();
    assert_eq!(reader.device_id(), id);
    assert_eq!(paths(&reader), vec!["docs/x".to_owned()]);
    assert_eq!(reader.list("docs").unwrap().len(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "it must not wait for the writer: {:?}",
        started.elapsed()
    );
    // It wrote nothing and created nothing.
    assert_eq!(
        reader.db().meta_get("device_name").unwrap().as_deref(),
        Some(&b"b"[..])
    );
    assert!(!dir.path().join("no-such-cache").exists());
    holder.execute_batch("COMMIT").unwrap();

    // A vault of another id is refused here as well.
    let other = OpenParams {
        vault_id: [0x22; 16],
        handles: w.handles.clone(),
        device_name: "b".into(),
        cache_dir: w.cache("b"),
        machine_fp: None,
    };
    let refused = Vault::open_unlocked(
        w.net.clone(),
        Db::open_shared(&path).unwrap(),
        keyring([0x22; 16]),
        other,
    )
    .await;
    assert!(matches!(
        refused,
        Err(IndexError::State(StateError::Corrupt(_)))
    ));
}
