//! Tests of `past.rs`: the time model on hand-made histories, and properties over random ones
//! against a brute-force oracle and against the trees that were really there.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::format::{Op, SegmentV1};
use crate::index::{HeadStore, apply_segment};
use crate::test_prng::{Prng, for_each_seed};
use crate::types::{BlobId, BlobRec, Loc};

const DAY: u64 = 86_400_000;
/// "Now" of every test: far enough from 0 that a window fits before it.
const NOW_MS: u64 = 1_000 * DAY;
const FROM_MS: u64 = NOW_MS - RESTORE_WINDOW_MS;

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 8])
}

fn stamp(lamport: u64, device: u8, idx: u32) -> Stamp {
    Stamp {
        lamport,
        device: dev(device),
        idx,
    }
}

/// What is at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Thing {
    /// `(content, size)`: the hash is the content byte, 32 times.
    File(u8, u64),
    Dir,
}

enum Change<'a> {
    /// A file with this content; `true`: uploaded now (a new blob), `false`: no blob at all
    /// (an empty file).
    Put(&'a str, u8, bool),
    /// The same without a base: over whatever is at the path, which stays a head beside it
    /// (`copy --force`) until a `Resolve`.
    Over(&'a str, u8, bool),
    /// The bytes of another path, as they are stored: a copy that reuses the blob.
    Copy(&'a str, &'a str),
    /// Such a copy without a base (`Over`).
    CopyOver(&'a str, &'a str),
    Mkdir(&'a str),
    Del(&'a str),
    /// What conflict resolution writes: every head of the path but the winner goes.
    Resolve(&'a str),
}
use Change::{Copy, CopyOver, Del, Mkdir, Over, Put, Resolve};

/// Devices that always see each other's segments, writing a vault one segment at a time.
#[derive(Default)]
struct Sim {
    mem: MemIndex,
    lamport: u64,
    seqs: BTreeMap<u8, u64>,
    blobs: u64,
    tree: BTreeMap<String, Thing>,
    /// The tree after each segment, with the segment's true time.
    truth: Vec<(u64, BTreeMap<String, Thing>)>,
    /// `(path, from, until)`: a file put over another one without superseding it, in a
    /// segment that brought a blob, shows from that blob on — a moment before its segment.
    /// The one case in which the model shows something in place of what was there.
    early: Vec<(String, u64, u64)>,
}

fn file_entry(content: u8, size: u64, loc: Option<Loc>) -> Entry {
    Entry {
        kind: EntryKind::File,
        size,
        mtime_ns: i64::from(content) * 1_000_000_000,
        exec: false,
        hash: [content; 32],
        loc,
    }
}

impl Sim {
    fn winner(&self, path: &str) -> Option<Stamp> {
        self.mem.heads(path).unwrap().last().map(|h| h.stamp)
    }

    /// One segment of `device`, written at `time`; its removals are recorded with `recorded`
    /// (the same, unless a clock is wrong) and its new blobs were created at `uploaded`.
    fn segment_at(
        &mut self,
        device: u8,
        time: u64,
        recorded: u64,
        uploaded: u64,
        changes: &[Change<'_>],
    ) {
        self.lamport += 1;
        let seq = {
            let seq = self.seqs.entry(device).or_insert(0);
            *seq += 1;
            *seq
        };
        let mut ops = Vec::new();
        if seq == 1 {
            ops.push(Op::Device {
                id: dev(device),
                name: format!("device-{device}"),
            });
        }
        // Bases are looked up before anything is applied: a segment touches a path once.
        let brings_a_blob = changes
            .iter()
            .any(|change| matches!(change, Put(_, _, true) | Over(_, _, true)));
        for change in changes {
            if let Over(path, ..) | CopyOver(path, _) = change
                && brings_a_blob
                && self.tree.contains_key(*path)
            {
                self.early.push(((*path).to_owned(), uploaded, time));
            }
            match change {
                Copy(path, from) | CopyOver(path, from) => {
                    let source = self.mem.heads(from).unwrap().pop().expect("a source");
                    ops.push(Op::Put {
                        path: (*path).to_owned(),
                        entry: source.entry.clone(),
                        base: self.winner(path).filter(|_| matches!(change, Copy(..))),
                        origin: None,
                    });
                    let thing = Thing::File(source.entry.hash[0], source.entry.size);
                    self.tree.insert((*path).to_owned(), thing);
                }
                Resolve(path) => {
                    let mut heads = self.mem.heads(path).unwrap();
                    heads.pop();
                    ops.extend(heads.into_iter().map(|loser| Op::Del {
                        path: (*path).to_owned(),
                        base: loser.stamp,
                    }));
                }
                Put(path, content, fresh) | Over(path, content, fresh) => {
                    let size = u64::from(*content) + 1;
                    let loc = fresh.then(|| {
                        self.blobs += 1;
                        let mut id = [0u8; 16];
                        id[..8].copy_from_slice(&self.blobs.to_be_bytes());
                        ops.push(Op::Blob(BlobRec {
                            id: BlobId(id),
                            file_id: String::new(),
                            clen: 100,
                            md5: [0; 16],
                            created_ms: uploaded,
                        }));
                        Loc {
                            blob: BlobId(id),
                            off: 0,
                            clen: 100,
                            salt: [0; 16],
                            chunk_log2: 16,
                            epoch: 1,
                            suite: 1,
                            flags: 0,
                        }
                    });
                    let over = matches!(change, Over(..));
                    ops.push(Op::Put {
                        path: (*path).to_owned(),
                        entry: file_entry(*content, size, loc),
                        base: self.winner(path).filter(|_| !over),
                        origin: None,
                    });
                    self.tree
                        .insert((*path).to_owned(), Thing::File(*content, size));
                }
                Mkdir(path) => {
                    ops.push(Op::Put {
                        path: (*path).to_owned(),
                        entry: Entry {
                            kind: EntryKind::Dir,
                            size: 0,
                            mtime_ns: 0,
                            exec: false,
                            hash: [0; 32],
                            loc: None,
                        },
                        base: self.winner(path),
                        origin: None,
                    });
                    self.tree.insert((*path).to_owned(), Thing::Dir);
                }
                Del(path) => {
                    let base = self.winner(path).expect("something to delete");
                    ops.push(Op::Del {
                        path: (*path).to_owned(),
                        base,
                    });
                    self.tree.remove(*path);
                }
            }
        }
        let seg = SegmentV1 {
            vault_id: [0; 16],
            device: dev(device),
            seq,
            lamport: self.lamport,
            prev: None,
            seen: Vec::new(),
            created_ms: recorded,
            host: String::new(),
            ops,
        };
        apply_segment(&mut self.mem, &seg, recorded).unwrap();
        self.truth.push((time, self.tree.clone()));
    }

    /// An honest segment: recorded when it was written, blobs made a second before.
    fn segment(&mut self, device: u8, time: u64, changes: &[Change<'_>]) {
        self.segment_at(device, time, time, time.saturating_sub(1_000), changes);
    }

    fn history(&self) -> History {
        History::of_mem(&self.mem, NOW_MS)
    }

    fn group(&self, path: &str) -> Group {
        Cursor::new(&mut MemSource(&self.mem)).at(path).unwrap()
    }

    /// The content at `path` at `t`, as the model sees it.
    fn at(&self, path: &str, t: u64) -> Option<Thing> {
        let group = self.group(path);
        entry_at(&self.history().clock, &group, t).map(thing_of)
    }

    /// The tree that was really there at `t`.
    fn truly(&self, t: u64) -> BTreeMap<String, Thing> {
        self.truth
            .iter()
            .rev()
            .find(|(time, _)| *time <= t)
            .map(|(_, tree)| tree.clone())
            .unwrap_or_default()
    }
}

fn thing_of(ver: &Ver) -> Thing {
    match ver.kind {
        EntryKind::File => Thing::File(ver.hash[0], ver.size),
        EntryKind::Dir => Thing::Dir,
    }
}

// ---------------------------------------------------------------------------------------------
// A listing, reduced to what is compared
// ---------------------------------------------------------------------------------------------

/// `(name or path, is a directory, content of a file)`, sorted.
type Shown = Vec<(String, bool, Option<(u8, u64)>)>;

fn shown(rows: &[Row]) -> Shown {
    let mut out: Shown = rows
        .iter()
        .map(|row| {
            let file = row
                .head
                .as_ref()
                .filter(|_| !row.is_dir)
                .map(|h| (h.entry.hash[0], h.entry.size));
            (row.tie().to_owned(), row.is_dir, file)
        })
        .collect();
    out.sort();
    out
}

/// What a listing of `dir` shows of a tree `path → thing`: `None` if `dir` is no directory
/// of it.
fn list_of(tree: &BTreeMap<String, Thing>, dir: &str) -> Option<Shown> {
    let lo = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let mut rows: BTreeMap<String, (bool, Option<(u8, u64)>)> = BTreeMap::new();
    for (path, thing) in tree {
        let Some(rel) = path.strip_prefix(&lo) else {
            continue;
        };
        match rel.split_once('/') {
            Some((name, _)) => rows.entry(name.to_owned()).or_insert((true, None)).0 = true,
            None => {
                let row = rows.entry(rel.to_owned()).or_insert((false, None));
                match thing {
                    Thing::Dir => row.0 = true,
                    Thing::File(content, size) => row.1 = Some((*content, *size)),
                }
            }
        }
    }
    let exists = dir.is_empty() || !rows.is_empty() || tree.get(dir) == Some(&Thing::Dir);
    exists.then(|| {
        rows.into_iter()
            .map(|(name, (is_dir, file))| (name, is_dir, file.filter(|_| !is_dir)))
            .collect()
    })
}

fn search_of(tree: &BTreeMap<String, Thing>, needle: &str, limit: usize) -> (Shown, bool) {
    let rows = tree
        .iter()
        .map(|(path, thing)| Ok::<_, std::convert::Infallible>((path, *thing == Thing::Dir)));
    let (found, more) = rules::search_paths(rows, needle, limit).unwrap();
    let mut hits: Shown = found
        .into_iter()
        .map(|(path, is_dir)| {
            let file = match tree.get(&path) {
                Some(Thing::File(content, size)) if !is_dir => Some((*content, *size)),
                _ => None,
            };
            (path, is_dir, file)
        })
        .collect();
    hits.sort();
    (hits, more)
}

/// Every directory of a tree, the root included.
fn dirs_of(tree: &BTreeMap<String, Thing>) -> BTreeSet<String> {
    let mut dirs = BTreeSet::from([String::new()]);
    for (path, thing) in tree {
        dirs.extend(crate::path::ancestors(path).map(str::to_owned));
        if *thing == Thing::Dir {
            dirs.insert(path.clone());
        }
    }
    dirs
}

/// The oracle: every path's entry at `t`, one path at a time, with no walk and no memo.
fn oracle(sim: &Sim, history: &History, t: u64) -> BTreeMap<String, Thing> {
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for (path, stamp, entry, _) in sim.mem.heads_iter() {
        let group = groups.entry(path.to_owned()).or_default();
        group.heads.push(Ver::of(stamp, entry, None));
    }
    for (path, stamp, entry, ms, by) in sim.mem.removed_iter() {
        let group = groups.entry(path.to_owned()).or_default();
        group.removed.push(Ver::of(stamp, entry, Some((*by, ms))));
    }
    let mut tree = BTreeMap::new();
    for (path, mut group) in groups {
        group.heads.sort_by_key(|v| (v.stamp, v.hash));
        by_removal(&mut group.removed);
        if let Some(ver) = entry_at(&history.clock, &group, t) {
            tree.insert(path, thing_of(ver));
        }
    }
    tree
}

fn listed(sim: &Sim, history: &History, dir: &str, t: u64) -> Option<Shown> {
    match list_at(&mut MemSource(&sim.mem), history, dir, t).unwrap() {
        Listing::Rows(rows) => Some(shown(&rows)),
        Listing::Absent { .. } => None,
    }
}

/// Every answer about the vault at `t` against a tree.
fn assert_same_tree(
    sim: &Sim,
    history: &History,
    t: u64,
    tree: &BTreeMap<String, Thing>,
    what: &str,
) {
    let mut dirs = dirs_of(tree);
    dirs.extend(dirs_of(&sim.tree));
    dirs.insert("no/such/dir".to_owned());
    for dir in &dirs {
        assert_eq!(
            listed(sim, history, dir, t),
            list_of(tree, dir),
            "{what}: list {dir:?} at {t}"
        );
    }
    let mut paths: BTreeSet<&String> = tree.keys().collect();
    paths.extend(sim.tree.keys());
    for path in paths.into_iter().chain(&dirs).filter(|p| !p.is_empty()) {
        let found = stat_at(&mut MemSource(&sim.mem), history, path, t).unwrap();
        let expected = match tree.get(path) {
            _ if list_of(tree, path).is_some() => Some((true, None)),
            Some(Thing::File(content, size)) => Some((false, Some((*content, *size)))),
            _ => None,
        };
        let got = found.map(|row| {
            let file = row.head.as_ref().map(|h| (h.entry.hash[0], h.entry.size));
            (row.is_dir, file.filter(|_| !row.is_dir))
        });
        assert_eq!(got, expected, "{what}: stat {path:?} at {t}");
    }
    for needle in ["a", "b", "x", "dir", "1"] {
        for limit in [3, 1000] {
            let (hits, more) =
                search_at(&mut MemSource(&sim.mem), history, needle, limit, t).unwrap();
            let expected = search_of(tree, needle, limit);
            assert_eq!(
                (shown(&hits), more),
                expected,
                "{what}: search {needle:?} at {t}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The clock
// ---------------------------------------------------------------------------------------------

#[test]
fn the_clock_of_the_segments() {
    let t = FROM_MS + DAY;
    let history = History::build(
        FROM_MS,
        [
            // Device 1: lamport 10 recorded twice (the smaller time counts), 20 with a clock
            // that ran ahead (later than 30's), 30.
            (10, dev(1), t + 500, 1),
            (10, dev(1), t + 400, 1),
            (20, dev(1), t + 9_000, 0),
            (30, dev(1), t + 2_000, 3),
            // Device 2 has one anchor.
            (25, dev(2), t + 1_000, 1),
        ],
        [
            // Uploads: between two anchors, before the first, after the last, on a device
            // without anchors, and one whose blob is older than the floor.
            (15, dev(1), t + 700, 2),
            (15, dev(1), t + 650, 1),
            (5, dev(1), t + 100, 1),
            (40, dev(1), t + 5_000, 1),
            (7, dev(3), t + 300, 4),
            (8, dev(3), FROM_MS, 1),
            // Evidence outside its neighbours: brought back between them.
            (26, dev(1), t + 9_999, 1),
            (27, dev(1), t + 1, 1),
        ],
        // Device 4 was first seen at a known time, and nothing else is known of it; device 1
        // long before what it did.
        [(dev(4), t + 50), (dev(1), t - 7)],
    );
    let clock = |l, d| {
        let when = history.clock.at(&stamp(l, d, 0));
        (when.ms, when.basis == Basis::Exact)
    };
    // Anchors: the smallest recorded time, and never later than a later segment's.
    assert_eq!(clock(10, 1), (t + 400, true));
    assert_eq!(clock(20, 1), (t + 2_000, true), "the hull");
    assert_eq!(clock(30, 1), (t + 2_000, true));
    assert_eq!(clock(25, 2), (t + 1_000, true));
    // Uploads: the newest blob, held between the device's neighbouring anchors.
    assert_eq!(clock(15, 1), (t + 700, false));
    assert_eq!(clock(5, 1), (t + 100, false));
    assert_eq!(clock(40, 1), (t + 5_000, false));
    assert_eq!(clock(7, 3), (t + 300, false));
    assert_eq!(
        clock(26, 1),
        (t + 2_000, false),
        "not after the next anchor"
    );
    assert_eq!(
        clock(27, 1),
        (t + 2_000, false),
        "not before the previous one"
    );
    // Nothing of its own: the latest the device is known to have done before — its previous
    // anchor, the blobs it had uploaded by then, the moment it was first seen — or "before
    // the window".
    assert_eq!(clock(12, 1), (t + 400, false));
    assert_eq!(clock(3, 1), (t - 7, false), "the device's first appearance");
    assert_eq!(
        clock(8, 3),
        (t + 300, false),
        "a blob from before the floor is no evidence: what the device uploaded before counts"
    );
    assert_eq!(clock(6, 3), (0, false));
    assert_eq!(clock(1, 4), (t + 50, false));
    assert_eq!(clock(1, 9), (0, false));
    assert_eq!(
        clock(45, 1),
        (t + 5_000, false),
        "evidence beyond an anchor is not carried on"
    );
    // How a time is known, and the time by which the segment was written.
    let when = |l, d| history.clock.at(&stamp(l, d, 0));
    assert_eq!((when(10, 1).basis, when(10, 1).by), (Basis::Exact, t + 400));
    assert_eq!(
        (when(15, 1).basis, when(15, 1).by),
        (Basis::Upload, t + 2_000)
    );
    assert_eq!(
        (when(12, 1).basis, when(12, 1).by),
        (Basis::Bound, t + 2_000)
    );
    assert_eq!(
        (when(45, 1).basis, when(45, 1).by),
        (Basis::Bound, u64::MAX)
    );

    // The moments: one per anchored segment with the files it took, one per upload that is
    // not anchored with its versions — by time, then by lamport.
    let seen: Vec<(u64, u64, bool)> = history
        .moments
        .iter()
        .map(|m| (m.ms - t, m.files, m.approx))
        .collect();
    assert_eq!(
        seen,
        [
            (100, 1, true),
            (300, 4, true),
            (400, 2, false),
            (700, 3, true),
            (1_000, 1, false),
            (2_000, 0, false),
            (2_000, 1, true),
            (2_000, 1, true),
            (2_000, 3, false),
            (5_000, 1, true),
        ]
    );
    assert!(history.serves(NOW_MS) && history.serves(NOW_MS + DAY));
    assert!(!history.serves(NOW_MS - 1), "a clock that went back");
}

#[test]
fn the_timeline_holds_the_moments_of_the_window_and_merges_too_many() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        FROM_MS - 5 * DAY,
        &[Put("old", 1, true), Put("f", 1, true)],
    );
    sim.segment(1, FROM_MS - DAY, &[Put("old", 2, true)]);
    sim.segment(1, t, &[Put("f", 2, true), Put("g", 1, true)]);
    sim.segment(
        2,
        t + 10,
        &[Put("h", 1, true), Put("i", 1, true), Put("j", 1, false)],
    );
    sim.segment(2, t + 20, &[Del("f"), Del("g")]);
    let found = timeline(&MemSource(&sim.mem), &sim.history(), NOW_MS);
    assert_eq!((found.now_ms, found.from_ms), (NOW_MS, FROM_MS));
    assert_eq!(found.devices, ["device-1", "device-2"]);
    assert_eq!(
        found.moments,
        [
            // Exact: one file replaced.
            (t, 1, 0, 0),
            // An upload — an estimate: its two new blobs were made a second before, and the
            // device was first seen with this segment.
            (t + 10, 2, 1, 1),
            // Exact: two files deleted.
            (t + 20, 2, 1, 0),
        ]
    );
    // A device the index has no name for is shown by the start of its id.
    let unnamed = History::build(FROM_MS, [(1, dev(7), t, 1)], [], []);
    assert_eq!(
        timeline(&MemSource(&MemIndex::default()), &unnamed, NOW_MS).devices,
        ["07070707"]
    );

    // More than the cap: neighbours are merged — the earliest time, the sum, the device of
    // the largest member, an estimate only if all are.
    let many = (0..5_000u64).map(|i| (i + 1, dev(1 + (i % 2) as u8), t + i, 1 + (i % 2)));
    let fresh = [(9_000, dev(3), t + 2, 50)];
    let history = History::build(FROM_MS, many, fresh, []);
    assert_eq!(history.moments.len(), 5_001);
    let found = timeline(&MemSource(&sim.mem), &history, NOW_MS);
    assert_eq!(found.moments.len(), 1_667, "groups of three");
    assert_eq!(found.moments[0], (t, 1 + 2 + 1, 0, 0));
    assert_eq!(found.devices[0], "device-2");
    // The upload sorts after the anchor of its time: it is the largest of the second group.
    assert_eq!(
        (found.moments[1].0, found.moments[1].1, found.moments[1].3),
        (t + 2, 50 + 2 + 1, 0)
    );
    assert_eq!(found.devices[found.moments[1].2], "03030303");
    let total: u64 = found.moments.iter().map(|m| m.1).sum();
    assert_eq!(total, 2_500 + 5_000 + 50);
    assert!(found.moments.windows(2).all(|w| w[0].0 <= w[1].0));
    // Only estimates in a group: the group is one.
    let history = History::build(
        FROM_MS,
        [],
        (0..6_000u64).map(|i| (i, dev(1), t + i, 1)),
        [],
    );
    let found = timeline(&MemSource(&sim.mem), &history, NOW_MS);
    assert_eq!(found.moments.len(), 2_000);
    assert!(found.moments.iter().all(|m| m.3 == 1 && m.1 == 3));
}

// ---------------------------------------------------------------------------------------------
// One path
// ---------------------------------------------------------------------------------------------

#[test]
fn a_chain_of_overwrites_a_delete_and_a_new_file() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(1, t, &[Put("f", 1, true)]);
    sim.segment(2, t + 100_000, &[Put("f", 2, true)]);
    sim.segment(1, t + 200_000, &[Put("f", 3, true)]);
    sim.segment(1, t + 300_000, &[Del("f")]);
    sim.segment(2, t + 400_000, &[Put("f", 4, true)]);
    let file = |content: u8| Some(Thing::File(content, u64::from(content) + 1));
    // The first upload: its blob was made a moment before, but the device was first seen
    // with this segment.
    assert_eq!(sim.at("f", t - 1), None);
    assert_eq!(sim.at("f", t), file(1));
    // Overwrites and the delete are exact, to the millisecond.
    assert_eq!(sim.at("f", t + 99_999), file(1));
    assert_eq!(sim.at("f", t + 100_000), file(2));
    assert_eq!(sim.at("f", t + 199_999), file(2));
    assert_eq!(sim.at("f", t + 200_000), file(3));
    assert_eq!(sim.at("f", t + 299_999), file(3));
    assert_eq!(sim.at("f", t + 300_000), None);
    // The file that came after the delete: its upload.
    assert_eq!(sim.at("f", t + 398_999), None);
    assert_eq!(sim.at("f", t + 399_000), file(4));
    assert_eq!(sim.at("f", NOW), file(4));

    // The lives: removed versions in the order they were superseded, then the head.
    let group = sim.group("f");
    let seen: Vec<(i64, bool, Option<u64>)> = lives(&sim.history().clock, &group)
        .iter()
        .map(|l| (l.born as i64 - t as i64, l.exact, l.end.map(|e| e - t)))
        .collect();
    assert_eq!(
        seen,
        [
            (0, false, Some(100_000)),
            (100_000, true, Some(200_000)),
            (200_000, true, Some(300_000)),
            (399_000, false, None),
        ]
    );
}

#[test]
fn a_restore_of_a_deleted_path_and_a_move() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(1, t, &[Put("a/f", 1, true), Put("beat", 1, true)]);
    sim.segment(1, t + 10_000, &[Del("a/f"), Put("beat", 2, true)]);
    // A restore: a put without a base and without a new blob. Its segment replaced nothing,
    // so its time is not on record: the file is back from the device's last known segment
    // on — early (here: from the delete itself), never late.
    sim.segment(1, t + 20_000, &[Put("a/f", 1, false)]);
    sim.segment(1, t + 30_000, &[Put("beat", 3, true)]);
    let file = Some(Thing::File(1, 2));
    assert_eq!(sim.at("a/f", t + 9_999), file);
    let life = *lives(&sim.history().clock, &sim.group("a/f"))
        .last()
        .unwrap();
    assert_eq!((life.born, life.exact), (t + 10_000, false));
    assert_eq!(sim.at("a/f", t + 20_000), file);
    // It is surely there from the device's next segment whose time is on record, and until
    // then the row says that it may not have been there yet.
    assert_eq!(life.sure, t + 30_000);
    let history = sim.history();
    let row = |at| {
        stat_at(&mut MemSource(&sim.mem), &history, "a/f", at)
            .unwrap()
            .unwrap()
    };
    assert!(!row(t + 9_999).approx, "before the delete");
    assert!(row(t + 10_000).approx && row(t + 29_999).approx);
    assert!(!row(t + 30_000).approx);
    assert_eq!(
        serde_json::to_value(row(t + 15_000).json()).unwrap()["approx"],
        true
    );
    assert!(
        serde_json::to_value(row(t + 30_000).json())
            .unwrap()
            .get("approx")
            .is_none()
    );

    // A move: put and delete in one segment — both sides exact.
    sim.segment(2, t + 40_000, &[Put("b/g", 1, false), Del("a/f")]);
    sim.segment(2, t + 50_000, &[Put("b/g", 5, true)]);
    assert_eq!(sim.at("a/f", t + 39_999), file);
    assert_eq!(sim.at("a/f", t + 40_000), None);
    assert_eq!(sim.at("b/g", t + 39_999), None);
    assert_eq!(sim.at("b/g", t + 40_000), file);
    assert_eq!(sim.at("b/g", t + 50_000), Some(Thing::File(5, 6)));
    let history = sim.history();
    assert_eq!(
        listed(&sim, &history, "", t + 39_999).unwrap(),
        [
            ("a".to_owned(), true, None),
            ("beat".to_owned(), false, Some((3, 4)))
        ]
    );
    assert_eq!(
        listed(&sim, &history, "", t + 40_000).unwrap(),
        [
            ("b".to_owned(), true, None),
            ("beat".to_owned(), false, Some((3, 4)))
        ]
    );
}

/// Conflict twins: two devices write the same path without seeing each other.
#[test]
fn twins_losers_and_one_op_that_supersedes_one_of_them() {
    let t = FROM_MS + DAY;
    let mut mem = MemIndex::default();
    let put = |lamport, device: u8, content: u8, base: Option<Stamp>, created_ms| SegmentV1 {
        vault_id: [0; 16],
        device: dev(device),
        seq: lamport,
        lamport,
        prev: None,
        seen: Vec::new(),
        created_ms,
        host: String::new(),
        ops: vec![Op::Put {
            path: "f".into(),
            entry: file_entry(content, 1, None),
            base,
            origin: None,
        }],
    };
    // v0, then two overwrites of it that did not see each other: both are heads.
    apply_segment(&mut mem, &put(1, 1, 1, None, t), t).unwrap();
    let v0 = stamp(1, 1, 0);
    apply_segment(&mut mem, &put(2, 1, 2, Some(v0), t + 1_000), t + 1_000).unwrap();
    apply_segment(&mut mem, &put(2, 2, 3, Some(v0), t + 5_000), t + 5_000).unwrap();
    let at = |mem: &MemIndex, t| {
        let history = History::of_mem(mem, NOW_MS);
        let group = Cursor::new(&mut MemSource(mem)).at("f").unwrap();
        entry_at(&history.clock, &group, t).map(|v| v.hash[0])
    };
    // The removal is recorded once — by the smaller op — and both successors are there
    // from that time on.
    assert_eq!(at(&mem, t + 999), Some(1));
    assert_eq!(at(&mem, t + 1_000), Some(3), "the greater stamp wins");
    assert_eq!(at(&mem, NOW), Some(3));
    // The versions list shows the winner and what is removed — never a loser.
    let history = History::of_mem(&mem, NOW_MS);
    let listed = versions(&mut MemSource(&mem), &history, "f", None, NOW_MS).unwrap();
    assert_eq!(listed.versions.len(), 2);
    assert!(listed.versions[0].current && !listed.deleted);
    assert_eq!(listed.versions[1].why, Some("overwritten"));

    // One op that supersedes the loser: the winner was the entry until then.
    let loser = stamp(2, 1, 0);
    apply_segment(&mut mem, &put(3, 2, 4, Some(loser), t + 9_000), t + 9_000).unwrap();
    assert_eq!(at(&mem, t + 8_999), Some(3));
    assert_eq!(at(&mem, t + 9_000), Some(4));
}

/// The case of `removed_versions_are_ordered_by_the_superseding_op_not_by_time`: a writer
/// whose clock runs days ahead.
#[test]
fn a_version_is_never_alive_after_a_later_removal_on_its_path() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(1, t, &[Put("f", 1, true)]);
    // Device 2 overwrites; its clock is three days ahead.
    sim.segment_at(2, t + 1_000, t + 3 * DAY, t, &[Put("f", 2, true)]);
    sim.segment(1, t + 2_000, &[Put("f", 3, true)]);
    sim.segment(1, t + 3_000, &[Del("f")]);
    let group = sim.group("f");
    let ends: Vec<u64> = lives(&sim.history().clock, &group)
        .iter()
        .filter_map(|l| l.end)
        .collect();
    // The recorded times are t + 3 d, t + 2 s, t + 3 s; the first is brought back.
    assert_eq!(ends, [t + 2_000, t + 2_000, t + 3_000]);
    for at in [t + 3_000, t + DAY, t + 3 * DAY - 1, t + 3 * DAY, NOW_MS - 1] {
        assert_eq!(sim.at("f", at), None, "{at}: the file was deleted");
    }
    assert_eq!(sim.at("f", t + 1_999), Some(Thing::File(1, 2)));
    assert_eq!(sim.at("f", t + 2_500), Some(Thing::File(3, 4)));
    // The versions list is in the order of the ops, with the times the chain gives.
    let listed = versions(&mut MemSource(&sim.mem), &sim.history(), "f", None, NOW_MS).unwrap();
    assert!(listed.deleted);
    let seen: Vec<(u64, Option<u64>, Option<&str>)> = listed
        .versions
        .iter()
        .map(|v| (v.size, v.until_ms.map(|ms| ms - t), v.why))
        .collect();
    assert_eq!(
        seen,
        [
            (4, Some(3_000), Some("deleted")),
            (3, Some(2_000), Some("overwritten")),
            (2, Some(2_000), Some("overwritten")),
        ]
    );
}

#[test]
fn a_name_that_was_a_file_and_a_folder_and_directory_markers() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        t,
        &[Put("x", 1, true), Put("beat", 1, true), Mkdir("empty")],
    );
    // The file gives way to a folder of the same name …
    sim.segment(
        1,
        t + 10_000,
        &[Del("x"), Put("x/inner", 2, true), Put("beat", 2, true)],
    );
    // … and the folder to a file again.
    sim.segment(
        1,
        t + 20_000,
        &[Del("x/inner"), Put("x", 3, true), Del("empty")],
    );
    let history = sim.history();
    let root = |at| listed(&sim, &history, "", at).unwrap();
    assert_eq!(
        root(t + 9_999),
        [
            ("beat".to_owned(), false, Some((1, 2))),
            ("empty".to_owned(), true, None),
            ("x".to_owned(), false, Some((1, 2))),
        ]
    );
    assert_eq!(root(t + 10_000)[2], ("x".to_owned(), true, None));
    assert_eq!(
        listed(&sim, &history, "x", t + 10_000).unwrap(),
        [("inner".to_owned(), false, Some((2, 3)))]
    );
    assert_eq!(root(t + 20_000)[1], ("x".to_owned(), false, Some((3, 4))));
    assert_eq!(root(t + 20_000).len(), 2, "the empty folder is gone");
    // Then and now: no folder at a time when the name was a file.
    assert!(listed(&sim, &history, "x", t + 9_999).is_none());
    assert!(listed(&sim, &history, "x", t + 20_000).is_none());
    // An empty folder is a folder, through its marker alone.
    assert_eq!(listed(&sim, &history, "empty", t + 5_000), Some(Vec::new()));
    assert!(listed(&sim, &history, "empty", t + 20_000).is_none());
    let stat = |path, at| stat_at(&mut MemSource(&sim.mem), &history, path, at).unwrap();
    assert!(stat("empty", t + 5_000).unwrap().is_dir);
    assert!(stat("empty", t + 20_000).is_none());
    assert!(stat("x", t + 10_000).unwrap().is_dir);
    let file = stat("x", t + 9_999).unwrap();
    assert!(!file.is_dir && file.v.is_some() && file.since == Some("changed"));
    assert_eq!(stat("x/inner", t + 10_000).unwrap().since, Some("deleted"));
    // Where the folder was not: the nearest folder above that was.
    sim.segment(1, t + 30_000, &[Put("p/q/r/s", 1, true)]);
    let history = sim.history();
    for (dir, at, nearest) in [
        ("p/q/r", t + 20_000, ""),
        ("x/deeper/still", t + 10_000, "x"),
        ("x/deeper/still", t + 20_000, ""),
        ("p/q/r/none", NOW, "p/q/r"),
    ] {
        match list_at(&mut MemSource(&sim.mem), &history, dir, at).unwrap() {
            Listing::Absent { nearest: found } => assert_eq!(found, nearest, "{dir} at {at}"),
            Listing::Rows(_) => panic!("{dir} did not exist at {at}"),
        }
    }
}

#[test]
fn rows_of_the_past_say_what_became_of_them() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        t,
        &[
            Put("same", 1, true),
            Put("changed", 1, true),
            Put("gone", 1, true),
            Put("dir/kept", 1, true),
            Put("old/a", 1, true),
            Put("old/b", 1, true),
            Put("turned", 1, true),
            Mkdir("marker"),
        ],
    );
    sim.segment(
        1,
        t + 10_000,
        &[
            Put("changed", 2, true),
            Del("gone"),
            Del("old/a"),
            Del("old/b"),
            Del("turned"),
            Put("turned/in", 1, true),
            Del("marker"),
        ],
    );
    // Metadata alone: the same bytes again.
    sim.segment(1, t + 20_000, &[Put("same", 1, false)]);
    let history = sim.history();
    let Listing::Rows(rows) = list_at(&mut MemSource(&sim.mem), &history, "", t + 5_000).unwrap()
    else {
        panic!("the root exists");
    };
    let since: Vec<(&str, bool, Option<&str>)> = rows
        .iter()
        .map(|r| (r.name.as_str(), r.is_dir, r.since))
        .collect();
    assert_eq!(
        since,
        [
            ("changed", false, Some("changed")),
            ("dir", true, None),
            ("gone", false, Some("deleted")),
            ("marker", true, Some("deleted")),
            ("old", true, Some("deleted")),
            ("same", false, None),
            // A file then, a folder now: the file is no more.
            ("turned", false, Some("deleted")),
        ]
    );
    // Rows carry no version id (only `stat` hands one out), and "now" has no marks.
    assert!(rows.iter().all(|r| r.v.is_none() && r.gone.is_none()));
    let Listing::Rows(now) = list_at(&mut MemSource(&sim.mem), &history, "", NOW).unwrap() else {
        panic!("the root exists");
    };
    assert!(now.iter().all(|r| r.since.is_none()));
    let (hits, _) = search_at(&mut MemSource(&sim.mem), &history, "o", 100, t + 5_000).unwrap();
    let since: Vec<(&str, Option<&str>)> = hits
        .iter()
        .map(|r| (r.path.as_deref().unwrap(), r.since))
        .collect();
    assert_eq!(since, [("gone", Some("deleted")), ("old", Some("deleted"))]);
}

// ---------------------------------------------------------------------------------------------
// Versions, ids, the window
// ---------------------------------------------------------------------------------------------

#[test]
fn the_versions_of_a_file() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        FROM_MS - 9 * DAY,
        &[Put("f", 1, true), Put("beat", 1, true)],
    );
    sim.segment(1, FROM_MS - 5 * DAY, &[Put("f", 2, true)]);
    sim.segment(2, t, &[Put("f", 3, true)]);
    sim.segment(1, t + 10_000, &[Put("f", 4, true)]);
    // The same bytes again (a change of the modification time): no version of its own.
    sim.segment(2, t + 20_000, &[Put("f", 4, false)]);
    sim.segment(2, t + 30_000, &[Put("f", 5, true)]);
    let history = sim.history();
    let listed = versions(&mut MemSource(&sim.mem), &history, "f", None, NOW_MS).unwrap();
    assert_eq!((listed.now_ms, listed.from_ms), (NOW_MS, FROM_MS));
    assert!(!listed.deleted && !listed.more);
    let rows = &listed.versions;
    let seen: Vec<_> = rows
        .iter()
        .map(|v| {
            (
                v.size,
                v.current,
                v.written_ms.map(|ms| ms - t),
                v.until_ms.map(|ms| ms - t),
                v.written_approx,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (6, true, Some(30_000), None, false),
            // The folded pair: one row, from when the bytes came to when they went.
            (5, false, Some(10_000), Some(30_000), false),
            (4, false, Some(0), Some(10_000), false),
            // Written before the window: no time is claimed. Removed inside it: offered.
            (3, false, None, Some(0), false),
        ]
    );
    // The version removed five days before the window is not offered at all.
    assert_eq!(rows[0].written_by, "device-2");
    assert_eq!(
        rows[1].written_by, "device-1",
        "the device that wrote the bytes"
    );
    assert_eq!(rows[1].by.as_deref(), Some("device-2"));
    assert_eq!(rows[2].why, Some("overwritten"));
    assert!(rows[0].restore.is_none() && rows[0].by.is_none() && rows[0].why.is_none());
    for row in &rows[1..] {
        assert_eq!(
            row.restore.as_deref(),
            Some(format!("gclone restore :f --version @{}", row.v).as_str())
        );
    }
    // Every id is one of this path's, and names what it shows.
    let ids: BTreeSet<&str> = rows.iter().map(|r| r.v.as_str()).collect();
    assert_eq!(ids.len(), rows.len());
    for row in rows {
        assert!(rules::parse_v(&row.v).is_ok(), "{}", row.v);
        match resolve(&mut MemSource(&sim.mem), "f", &row.v, NOW_MS).unwrap() {
            Resolved::One(ver) => assert_eq!(ver.size, row.size),
            other => panic!("{other:?}"),
        }
        let stat = stat_version(&mut MemSource(&sim.mem), "f", &row.v, NOW_MS)
            .unwrap()
            .unwrap();
        assert_eq!(stat.v.as_deref(), Some(row.v.as_str()));
        assert_eq!(stat.since, (!row.current).then_some("changed"));
    }
    assert_eq!(
        resolve(&mut MemSource(&sim.mem), "f", "0123456789ab", NOW_MS).unwrap(),
        Resolved::None
    );
    assert_eq!(
        resolve(&mut MemSource(&sim.mem), "beat", &rows[1].v, NOW_MS).unwrap(),
        Resolved::None,
        "an id belongs to its path"
    );

    // The version that was there at a moment is marked — through the fold.
    for (at, size) in [
        (t + 5_000, 4),
        (t + 15_000, 5),
        (t + 25_000, 5),
        (t + 30_000, 6),
    ] {
        let listed = versions(&mut MemSource(&sim.mem), &history, "f", Some(at), NOW_MS).unwrap();
        let marked: Vec<u64> = listed
            .versions
            .iter()
            .filter(|v| v.shown)
            .map(|v| v.size)
            .collect();
        assert_eq!(marked, [size], "at {at}");
    }
    // A path nobody ever wrote, and one under a file: nothing, and no file now.
    for path in ["nothing", "beat/none"] {
        let listed = versions(&mut MemSource(&sim.mem), &history, path, None, NOW_MS).unwrap();
        assert!(listed.deleted && listed.versions.is_empty());
    }
}

#[test]
fn the_window_is_the_restore_window_to_the_millisecond() {
    let mut sim = Sim::default();
    sim.segment(
        1,
        FROM_MS - 9 * DAY,
        &[Put("in", 1, true), Put("out", 1, true)],
    );
    // Removed exactly one millisecond inside the window, and exactly at its edge.
    sim.segment(1, FROM_MS + 1, &[Put("in", 2, true)]);
    sim.segment(2, FROM_MS, &[Put("out", 2, true)]);
    let history = sim.history();
    let count = |path: &str, now| {
        let listed = versions(&mut MemSource(&sim.mem), &history, path, None, now).unwrap();
        listed.versions.len()
    };
    assert_eq!(count("in", NOW_MS), 2);
    assert_eq!(
        count("out", NOW_MS),
        1,
        "25 days old: `gclone restore` does not offer it"
    );
    assert_eq!(count("in", NOW_MS + 1), 1, "a millisecond later");
    let old = sim.group("out").removed[0].clone();
    let id = version_id("out", &old.stamp, &old.hash);
    assert_eq!(
        resolve(&mut MemSource(&sim.mem), "out", &id, NOW_MS).unwrap(),
        Resolved::None
    );
    assert!(matches!(
        resolve(&mut MemSource(&sim.mem), "out", &id, NOW_MS - 1).unwrap(),
        Resolved::One(_)
    ));
    // `at` is moved into the window, and "now" is the present.
    assert_eq!(clamp_at(0, NOW_MS), FROM_MS);
    assert_eq!(clamp_at(FROM_MS + 5, NOW_MS), FROM_MS + 5);
    assert_eq!(clamp_at(NOW_MS + DAY, NOW_MS), NOW_MS);
    assert_eq!(moment(NOW_MS, NOW_MS), NOW);
    assert_eq!(moment(NOW_MS - 1, NOW_MS), NOW_MS - 1);
    // Every file a view of the window shows is one that is offered.
    assert_eq!(sim.at("out", FROM_MS), Some(Thing::File(2, 3)));
    assert_eq!(sim.at("in", FROM_MS), Some(Thing::File(1, 2)));
}

/// A plain vector as a source, which also counts the questions it is asked.
#[derive(Default)]
struct VecSource {
    heads: Vec<(String, Ver)>,
    removed: Vec<(String, Ver)>,
    asked: usize,
}

impl VecSource {
    fn first(rows: &[(String, Ver)], from: &str, hi: Option<&str>) -> Option<PathVers> {
        let path = rows
            .iter()
            .map(|(p, _)| p.as_str())
            .filter(|p| *p >= from && hi.is_none_or(|hi| *p < hi))
            .min()?
            .to_owned();
        let vers = rows
            .iter()
            .filter(|(p, _)| *p == path)
            .map(|(_, v)| v.clone())
            .collect();
        Some((path, vers))
    }
}

impl Source for VecSource {
    type Err = String;
    fn heads_from(&mut self, from: &str, hi: Option<&str>) -> Result<Option<PathVers>, String> {
        self.asked += 1;
        Ok(Self::first(&self.heads, from, hi))
    }
    fn removed_from(&mut self, from: &str, hi: Option<&str>) -> Result<Option<PathVers>, String> {
        self.asked += 1;
        Ok(Self::first(&self.removed, from, hi))
    }
    fn device_name(&self, _: &DeviceId) -> Option<String> {
        None
    }
}

fn ver(lamport: u64, content: u8, end: Option<(u64, u64)>) -> Ver {
    Ver {
        stamp: stamp(lamport, 1, 0),
        hash: [content; 32],
        kind: EntryKind::File,
        size: 1,
        mtime_ns: 0,
        end: end.map(|(by, ms)| (stamp(by, 1, 0), ms)),
    }
}

#[test]
fn version_ids_and_what_they_name() {
    let s = stamp(7, 3, 2);
    let id = version_id("docs/a b.txt", &s, &[9; 32]);
    assert_eq!(id, version_id("docs/a b.txt", &s, &[9; 32]));
    assert_eq!(id.len(), 12);
    assert!(rules::parse_v(&id).is_ok());
    // Path, every part of the stamp and the content are in it.
    let others = [
        version_id("docs/a b.tx", &s, &[9; 32]),
        version_id("docs/a b.txt", &stamp(8, 3, 2), &[9; 32]),
        version_id("docs/a b.txt", &stamp(7, 4, 2), &[9; 32]),
        version_id("docs/a b.txt", &stamp(7, 3, 3), &[9; 32]),
        version_id("docs/a b.txt", &s, &[8; 32]),
    ];
    let distinct: BTreeSet<&String> = others.iter().chain([&id]).collect();
    assert_eq!(distinct.len(), 6);
    for bad in [
        "",
        "0123456789a",
        "0123456789abc",
        "0123456789AB",
        "0123456789ag",
        "@123456789ab",
    ] {
        assert!(rules::parse_v(bad).is_err(), "{bad:?}");
    }
    for (text, at) in [
        ("0", 0),
        ("1700000000000", 1_700_000_000_000),
        ("9999999999999999", 9_999_999_999_999_999),
    ] {
        assert_eq!(rules::parse_at(text), Ok(at));
    }
    for bad in [
        "",
        "-1",
        "+1",
        "1.5",
        "1e3",
        " 1",
        "12345678901234567",
        "now",
    ] {
        assert!(rules::parse_at(bad).is_err(), "{bad:?}");
    }

    // An id that two versions of a path share names neither — here the same version, held
    // twice. A head that is a folder has no id.
    let t = FROM_MS + DAY;
    let twice = ver(5, 1, Some((6, t)));
    let mut src = VecSource {
        heads: vec![("f".into(), ver(6, 2, None))],
        removed: vec![("f".into(), twice.clone()), ("f".into(), twice.clone())],
        asked: 0,
    };
    let id = version_id("f", &twice.stamp, &twice.hash);
    assert_eq!(resolve(&mut src, "f", &id, NOW_MS), Ok(Resolved::Ambiguous));
    assert_eq!(
        stat_version(&mut src, "f", &id, NOW_MS).map(|r| r.is_none()),
        Ok(true)
    );
    let head = version_id("f", &stamp(6, 1, 0), &[2; 32]);
    assert!(matches!(
        resolve(&mut src, "f", &head, NOW_MS),
        Ok(Resolved::One(_))
    ));
    src.heads[0].1.kind = EntryKind::Dir;
    assert_eq!(resolve(&mut src, "f", &head, NOW_MS), Ok(Resolved::None));

    // Deleted or overwritten: whether the path still held a file after the superseding op —
    // a file version written no later than that op, which went later or is a head.
    let old = [ver(5, 1, Some((6, t)))];
    assert_eq!(why(&old, &[ver(6, 2, None)], 0), "overwritten");
    assert_eq!(
        why(&old, &[ver(4, 2, None)], 0),
        "overwritten",
        "a file that had come before, without superseding it"
    );
    let later = [old[0].clone(), ver(6, 2, Some((9, t + 1)))];
    assert_eq!(why(&later, &[], 0), "overwritten");
    assert_eq!(why(&old, &[ver(7, 2, None)], 0), "deleted");
    let earlier = [ver(3, 2, Some((4, t - 1))), old[0].clone()];
    assert_eq!(
        why(&earlier, &[], 1),
        "deleted",
        "a version that went before is not there"
    );
    let mut folder = ver(6, 2, None);
    folder.kind = EntryKind::Dir;
    assert_eq!(why(&old, &[folder], 0), "deleted", "a folder now");
    assert_eq!(why(&old, &[], 0), "deleted");
    assert_eq!(why(&[], &[], 0), "deleted");
}

#[test]
fn the_cursor_merges_both_sides_and_asks_each_once() {
    let t = FROM_MS + DAY;
    let mut src = VecSource {
        heads: ["a", "c", "c/x", "e"]
            .iter()
            .map(|p| ((*p).to_owned(), ver(1, 1, None)))
            .collect(),
        removed: ["b", "c", "z"]
            .iter()
            .map(|p| ((*p).to_owned(), ver(1, 2, Some((2, t)))))
            .collect(),
        asked: 0,
    };
    let mut cursor = Cursor::new(&mut src);
    let mut from = String::new();
    let mut seen = Vec::new();
    while let Some(group) = cursor.group(&from, None).unwrap() {
        seen.push((group.path.clone(), group.heads.len(), group.removed.len()));
        from = successor(&group.path);
    }
    let expected = [
        ("a", 1, 0),
        ("b", 0, 1),
        ("c", 1, 1),
        ("c/x", 1, 0),
        ("e", 1, 0),
        ("z", 0, 1),
    ]
    .map(|(p, h, r)| (p.to_owned(), h, r));
    assert_eq!(seen, expected);
    // Each side is asked once per group it gave, and once to learn that it has no more:
    // the side that is ahead waits.
    assert_eq!(src.asked, (4 + 1) + (3 + 1));

    // Bounds: a range that holds nothing does not lose what was read ahead.
    let mut cursor = Cursor::new(&mut src);
    assert_eq!(cursor.group("c/", Some("c0")).unwrap().unwrap().path, "c/x");
    assert!(cursor.group("c/x\0", Some("c0")).unwrap().is_none());
    assert_eq!(cursor.group("c0", None).unwrap().unwrap().path, "e");
    assert!(cursor.at("nothing").unwrap().heads.is_empty());
    assert_eq!(cursor.at("c").unwrap().removed.len(), 1);
    // An error of the source is the answer.
    struct Broken;
    impl Source for Broken {
        type Err = &'static str;
        fn heads_from(&mut self, _: &str, _: Option<&str>) -> Result<Option<PathVers>, Self::Err> {
            Err("broken")
        }
        fn removed_from(
            &mut self,
            _: &str,
            _: Option<&str>,
        ) -> Result<Option<PathVers>, Self::Err> {
            Ok(None)
        }
        fn device_name(&self, _: &DeviceId) -> Option<String> {
            None
        }
    }
    let history = History::build(FROM_MS, [], [], []);
    assert_eq!(
        list_at(&mut Broken, &history, "", NOW).err(),
        Some("broken")
    );
    assert_eq!(
        search_at(&mut Broken, &history, "a", 5, NOW).err(),
        Some("broken")
    );
}

// ---------------------------------------------------------------------------------------------
// Deleted from a folder
// ---------------------------------------------------------------------------------------------

#[test]
fn what_was_deleted_from_a_folder() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        FROM_MS - 9 * DAY,
        &[
            Put("d/kept", 1, true),
            Put("d/file", 1, true),
            Put("d/file.bak", 1, true),
            Put("d/sub/a", 1, true),
            Put("d/sub/b", 1, true),
            Put("d/sub/deep/c", 1, true),
            Put("d/live/x", 1, true),
            Put("d/live/y", 1, true),
            Put("d/ancient", 1, true),
            Put("d/replaced", 1, true),
            Put("d/moved", 1, true),
            Mkdir("d/marker"),
            Put("gone/one", 1, true),
            Put("gone/two/three", 1, true),
            Put("other", 1, true),
        ],
    );
    // Outside the window: never listed.
    sim.segment(1, FROM_MS - DAY, &[Del("d/ancient")]);
    sim.segment(1, t, &[Put("d/file", 2, true), Put("d/replaced", 2, true)]);
    sim.segment(
        2,
        t + 10_000,
        &[
            Del("d/file"),
            Del("d/file.bak"),
            Del("d/sub/a"),
            Del("d/sub/b"),
            Del("d/sub/deep/c"),
            Del("d/live/x"),
            Del("d/marker"),
            Put("e/moved", 1, false),
            Del("d/moved"),
        ],
    );
    sim.segment(1, t + 20_000, &[Del("gone/one"), Del("gone/two/three")]);
    let all = |dir: &str| deleted(&mut MemSource(&sim.mem), dir, NOW_MS).unwrap();
    let found = all("d").unwrap();
    assert!(!found.gone);
    let rows: Vec<_> = found
        .rows
        .iter()
        .map(|r| (r.name.as_str(), r.is_dir, r.files))
        .collect();
    assert_eq!(
        rows,
        [
            // A deleted file shows its newest version; a moved one counts as deleted here.
            ("file", false, None),
            ("file.bak", false, None),
            ("moved", false, None),
            // A folder with nothing left in it: its kept files, however deep.
            ("sub", true, Some((3, false))),
        ]
    );
    // Not listed: `live` (something is in it), `replaced` (a file is there), `marker` (no
    // file was removed), `ancient` (outside the window), `kept`.
    let file = &found.rows[0];
    assert_eq!(
        file.head.as_ref().unwrap().entry.hash[0],
        2,
        "the newest version"
    );
    let gone = file.gone.as_ref().unwrap();
    assert_eq!(
        (gone.ms, gone.by.as_str(), gone.why),
        (t + 10_000, "device-2", "deleted")
    );
    let id = file.v.as_deref().unwrap();
    assert!(matches!(
        resolve(&mut MemSource(&sim.mem), "d/file", id, NOW_MS).unwrap(),
        Resolved::One(ver) if ver.hash[0] == 2
    ));
    assert_eq!(found.rows[2].gone.as_ref().unwrap().why, "deleted");

    // The answer: sorted like a folder, in pages; no command while the folder exists.
    let by = SortOrder::parse(Some("name"), Some("desc")).unwrap();
    let json = deleted_json("d".into(), all("d").unwrap(), by, 1, 2);
    assert_eq!((json.total, json.offset, json.gone), (4, 1, false));
    let names: Vec<&str> = json.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        ["moved", "file.bak"],
        "folders first, then names falling"
    );
    assert!(json.restore.is_none() && json.as_it_was_ms.is_none());
    let text = serde_json::to_value(&json.entries[0]).unwrap();
    assert_eq!(text["gone"]["why"], "deleted");
    assert_eq!(text["v"].as_str().unwrap().len(), 12);
    assert!(text.get("since").is_none() && text.get("files").is_none());

    // A folder that is gone: its children, the command, and the last moment it held
    // something.
    let found = all("gone").unwrap();
    assert!(found.gone);
    let by = SortOrder::parse(None, None).unwrap();
    let json = deleted_json("gone".into(), found, by, 0, 100);
    let names: Vec<(&str, bool)> = json
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.dir))
        .collect();
    assert_eq!(names, [("two", true), ("one", false)]);
    assert_eq!(json.restore.as_deref(), Some("gclone restore -r :gone"));
    assert_eq!(json.as_it_was_ms, Some(t + 20_000 - 1));
    let history = sim.history();
    assert_eq!(
        listed(&sim, &history, "gone", t + 20_000 - 1)
            .unwrap()
            .len(),
        2
    );
    assert!(listed(&sim, &history, "gone", t + 20_000).is_none());
    let json = serde_json::to_value(&json).unwrap();
    assert_eq!(json["entries"][0]["files"], 1);
    assert!(json["entries"][0].get("files_more").is_none());
    // The folder inside the deleted folder, and `sub` (gone as well).
    assert!(all("gone/two").unwrap().gone);
    assert_eq!(all("d/sub").unwrap().rows.len(), 3);
    // No folder, and nothing kept under the name: no answer. The root always is one.
    assert!(all("nowhere").is_none());
    assert!(all("other").is_none(), "a file");
    assert!(all("d/ancient").is_none());
    assert_eq!(all("d/live").unwrap().rows.len(), 1);
    assert_eq!(all("").unwrap().rows.len(), 1, "gone");
    // 25 days after the deletions the window has moved past them.
    let later = deleted(
        &mut MemSource(&sim.mem),
        "d",
        t + 10_000 + RESTORE_WINDOW_MS,
    )
    .unwrap();
    assert!(later.unwrap().rows.is_empty());
}

#[test]
fn a_deleted_folder_is_counted_up_to_a_bound() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    let names: Vec<String> = (0..DELETED_ROWS_MAX + 50)
        .map(|i| format!("big/{i:05}"))
        .collect();
    let old: Vec<String> = (0..DELETED_ROWS_MAX + 20)
        .map(|i| format!("old/{i:05}"))
        .collect();
    let puts: Vec<Change<'_>> = names.iter().chain(&old).map(|p| Put(p, 1, false)).collect();
    sim.segment(1, FROM_MS - 9 * DAY, &puts);
    // `old`: all but the last file were removed before the window.
    let dels: Vec<Change<'_>> = old[..old.len() - 1].iter().map(|p| Del(p)).collect();
    sim.segment(1, FROM_MS - DAY, &dels);
    let mut dels: Vec<Change<'_>> = names.iter().map(|p| Del(p)).collect();
    dels.push(Del(old.last().unwrap()));
    sim.segment(1, t, &dels);
    let found = deleted(&mut MemSource(&sim.mem), "", NOW_MS)
        .unwrap()
        .unwrap();
    let rows: Vec<(&str, Option<(u64, bool)>)> = found
        .rows
        .iter()
        .map(|r| (r.name.as_str(), r.files))
        .collect();
    assert_eq!(
        rows,
        [
            ("big", Some((DELETED_ROWS_MAX as u64, true))),
            // Past the bound rows are read until one kept file is found.
            ("old", Some((1, false))),
        ]
    );
    let json = serde_json::to_value(found.rows[0].json()).unwrap();
    assert_eq!(json["files"], DELETED_ROWS_MAX);
    assert_eq!(json["files_more"], true);
    assert_eq!(json["kind"], "folder");
}

// ---------------------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------------------

#[test]
fn the_restore_command_is_one_shell_word_per_argument() {
    assert_eq!(
        restore_command("docs/a.txt", "0123456789ab").as_deref(),
        Some("gclone restore :docs/a.txt --version @0123456789ab")
    );
    assert_eq!(
        restore_command("a b", "0123456789ab").as_deref(),
        Some("gclone restore ':a b' --version @0123456789ab")
    );
    assert_eq!(
        restore_dir_command("it's").as_deref(),
        Some("gclone restore -r ':it'\\''s'")
    );
    assert_eq!(
        restore_dir_command("").as_deref(),
        Some("gclone restore -r :")
    );
    // No command at all for a name with a control character or a line separator (a pasted
    // line must be one line), with a backslash (fish reads one inside single quotes as an
    // escape of the quote or the backslash after it: `a\'b` would end the quotes there), or
    // with a character that turns text around (the command would not read as it is copied).
    for path in [
        "a\nb",
        "a\rb",
        "tab\there",
        "bell\u{7}",
        "del\u{7f}",
        "esc\u{1b}[0m",
        "c1\u{85}next-line",
        "c1\u{9b}csi",
        "line\u{2028}separator",
        "paragraph\u{2029}separator",
        "a\\'b",
        "a\\\\b",
        "tail\\",
        "x\\';touch PWNED;echo \\'y.txt",
        "invoice\u{202e}fdp.exe",
        "mark\u{200e}ltr",
        "mark\u{200f}rtl",
        "mark\u{61c}arabic",
        "embed\u{202a}a",
        "embed\u{202b}b",
        "pop\u{202c}",
        "override\u{202d}",
        "isolate\u{2066}a",
        "isolate\u{2067}b",
        "isolate\u{2068}c",
        "pop\u{2069}",
    ] {
        assert_eq!(restore_command(path, "0123456789ab"), None, "{path:?}");
        assert_eq!(restore_dir_command(path), None, "{path:?}");
    }
    // What a shell makes of the command is exactly the arguments meant: the command runs
    // with `gclone` as a shell function that prints its arguments — in sh, and in bash, zsh
    // and fish where this machine has them.
    let paths = [
        "plain/path-1_2.txt",
        "with space/and  two",
        "quote's/\"double\"",
        "hash # and % and $HOME and `tick`",
        "-rf",
        "--version",
        "gr\u{f6}\u{df}e \u{1f389}/\u{65e5}\u{672c}",
        "semi;colon && pipe | redirect > x < y",
        "glob * ? [a-z] {a,b} ~ !",
        "'",
        "''",
        "a=b,c@d+e:f",
    ];
    for path in paths {
        let version = vec![
            "restore".to_owned(),
            format!(":{path}"),
            "--version".to_owned(),
            "@0123456789ab".to_owned(),
        ];
        let folder = vec!["restore".to_owned(), "-r".to_owned(), format!(":{path}")];
        for (command, expected) in [
            (restore_command(path, "0123456789ab").unwrap(), version),
            (restore_dir_command(path).unwrap(), folder),
        ] {
            for shell in ["sh", "bash", "zsh", "fish"] {
                let script = match shell {
                    "fish" => format!("function gclone; printf '%s\\0' $argv; end\n{command}\n"),
                    _ => format!("gclone() {{ printf '%s\\0' \"$@\"; }}\n{command}\n"),
                };
                let mut run = std::process::Command::new(shell);
                if shell == "fish" {
                    run.arg("--no-config");
                }
                let out = match run
                    .args(["-c", &script])
                    .env("HOME", "/nonexistent")
                    .output()
                {
                    Ok(out) => out,
                    // Only sh is on every machine.
                    Err(_) if shell != "sh" => continue,
                    Err(e) => panic!("sh: {e}"),
                };
                assert!(out.status.success(), "{shell}: {command}");
                let mut args: Vec<String> = String::from_utf8(out.stdout)
                    .unwrap()
                    .split('\0')
                    .map(str::to_owned)
                    .collect();
                assert_eq!(args.pop().as_deref(), Some(""));
                assert_eq!(args, expected, "{shell}: {command}");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

const NAMES: [&str; 14] = [
    "a",
    "b",
    "a.txt",
    "ab",
    "dir/a",
    "dir/b",
    "dir/x1",
    "dir/sub/a",
    "dir/sub/x10",
    "dir0",
    "dir.d/a",
    "big/x",
    "x",
    "b/a",
];

/// A random history: uploads, overwrites, deletes, folders, files without a blob, files put
/// over a file without superseding it (with new bytes, without a blob, with stored bytes). Also a
/// folder that is large enough for a walk through it to be remembered, deleted and brought
/// back as a whole. `anchored`: every segment also overwrites a heartbeat file, so every
/// segment's time is on record. `skew`: the most a recorded removal time lies after the truth.
/// Returns the times of the segments as well.
fn random_history(rng: &mut Prng, anchored: bool, skew: u64) -> (Sim, Vec<u64>) {
    let mut sim = Sim::default();
    let mut time = FROM_MS + DAY;
    let big: Vec<String> = (0..80).map(|i| format!("big/f{i:02}")).collect();
    let mut first: Vec<Change<'_>> = big.iter().map(|p| Put(p, 1, true)).collect();
    first.push(Put("beat", 0, true));
    sim.segment(1, time, &first);
    let mut times = vec![time];
    let mut beat = 0u8;
    for _ in 0..rng.range(5, 30) {
        time += rng.range(1, 3) * 1_000 * rng.range(1, 2_000);
        let device = rng.range(1, 4) as u8;
        let mut changes: Vec<Change<'_>> = Vec::new();
        let mut resolves: Vec<Change<'_>> = Vec::new();
        let mut touched: BTreeSet<&str> = BTreeSet::new();
        for _ in 0..rng.range(1, 5) {
            let path = *rng.pick(&NAMES);
            // One op per path and segment, and no file where a folder is needed (or the
            // other way): the rules a real client keeps.
            let clash = |other: &str| {
                other.starts_with(&format!("{path}/")) || path.starts_with(&format!("{other}/"))
            };
            if touched.contains(path)
                || sim.tree.keys().any(|p| clash(p))
                || touched.iter().any(|p| clash(p))
            {
                continue;
            }
            touched.insert(path);
            match (sim.tree.get(path), rng.below(10)) {
                (Some(_), 0..=3) => changes.push(Del(path)),
                // `copy --force`: a file over a file it does not supersede — new bytes, an
                // empty file or stored bytes — and the op that resolves the two right after.
                (Some(Thing::File(..)), 4) => {
                    changes.push(match rng.below(3) {
                        0 => Over(path, rng.range(1, 250) as u8, true),
                        1 => Over(path, rng.range(1, 6) as u8, false),
                        _ => CopyOver(path, "beat"),
                    });
                    resolves.push(Resolve(path));
                }
                (None, 0) => changes.push(Mkdir(path)),
                (_, 1..=2) => changes.push(Put(path, rng.range(1, 6) as u8, false)),
                _ => changes.push(Put(path, rng.range(1, 250) as u8, true)),
            }
        }
        let has_big = big.iter().all(|p| sim.tree.contains_key(p));
        if rng.chance(1, 6) {
            let fresh = rng.bool();
            changes.extend(big.iter().map(|p| match has_big {
                true => Del(p),
                false => Put(p, 2, fresh),
            }));
        }
        if anchored || changes.is_empty() {
            beat = beat.wrapping_add(1);
            changes.push(Put("beat", beat, true));
        }
        let recorded = time + if skew > 0 { rng.below(skew) } else { 0 };
        let uploaded = time - rng.range(1, 900);
        sim.segment_at(device, time, recorded, uploaded, &changes);
        if !resolves.is_empty() {
            sim.segment_at(device, time, recorded, uploaded, &resolves);
        }
        times.push(time);
    }
    (sim, times)
}

/// Moments worth asking about: around every segment, between them, the ends of the window —
/// `most` of them.
fn moments_of(rng: &mut Prng, times: &[u64], most: usize) -> Vec<u64> {
    let mut out = Vec::new();
    for time in times {
        out.extend([
            time - 1,
            *time,
            time + 1,
            time - 1_000,
            time + rng.range(1, 5_000_000),
        ]);
    }
    rng.shuffle(&mut out);
    out.truncate(most.saturating_sub(3));
    out.extend([FROM_MS, NOW_MS - 1, NOW]);
    out
}

/// P1: at "now", every answer about the past is the answer about the present.
#[test]
fn p1_now_is_the_present() {
    for_each_seed("past_p1", 40, |rng| {
        let anchored = rng.bool();
        let (sim, _) = random_history(rng, anchored, 0);
        let history = sim.history();
        assert_same_tree(&sim, &history, NOW, &sim.tree, "now");
        // The tree of the winners, read off the index directly.
        let mut winners = BTreeMap::new();
        for head in sim.mem.winners() {
            let thing = match head.entry.kind {
                EntryKind::File => Thing::File(head.entry.hash[0], head.entry.size),
                EntryKind::Dir => Thing::Dir,
            };
            winners.insert(head.path, thing);
        }
        assert_eq!(winners, sim.tree);
        // No row of the present carries a mark.
        for dir in dirs_of(&sim.tree) {
            let Listing::Rows(rows) =
                list_at(&mut MemSource(&sim.mem), &history, &dir, NOW).unwrap()
            else {
                panic!("{dir:?} exists");
            };
            assert!(rows.iter().all(|r| r.since.is_none() && r.v.is_none()));
        }
    });
}

/// P2: every walk — with its jumps, its early exits and its memo, cold and warm — gives what
/// looking at every path one by one gives.
#[test]
fn p2_the_walks_agree_with_the_oracle() {
    for_each_seed("past_p2", 40, |rng| {
        let skew = if rng.bool() { 0 } else { 3 * DAY };
        let anchored = rng.bool();
        let (sim, times) = random_history(rng, anchored, skew);
        let history = sim.history();
        let moments = moments_of(rng, &times, 24);
        for pass in ["cold", "warm"] {
            for t in &moments {
                let tree = oracle(&sim, &history, *t);
                assert_same_tree(&sim, &history, *t, &tree, pass);
            }
        }
    });
}

/// The memo of a walk in vain: asked again — at the same moment and at others — the subtree
/// is not walked again, and the answers are the oracle's.
#[test]
fn a_walk_in_vain_is_remembered() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    let young: Vec<String> = (0..200).map(|i| format!("young/{i:03}")).collect();
    let dead: Vec<String> = (0..200).map(|i| format!("dead/{i:03}")).collect();
    sim.segment(1, t, &[Put("beat", 1, true)]);
    let puts: Vec<Change<'_>> = dead.iter().map(|p| Put(p, 1, true)).collect();
    sim.segment(1, t + 10_000, &puts);
    let dels: Vec<Change<'_>> = dead.iter().map(|p| Del(p)).collect();
    sim.segment(1, t + 20_000, &dels);
    let puts: Vec<Change<'_>> = young.iter().map(|p| Put(p, 1, true)).collect();
    sim.segment(1, t + 30_000, &puts);
    sim.segment(1, t + 40_000, &[Put("beat", 2, true)]);
    let history = sim.history();

    /// A source that counts the groups it hands out.
    struct Counting<'a>(MemSource<'a>, usize);
    impl Source for Counting<'_> {
        type Err = std::convert::Infallible;
        fn heads_from(
            &mut self,
            from: &str,
            hi: Option<&str>,
        ) -> Result<Option<PathVers>, Self::Err> {
            self.1 += 1;
            self.0.heads_from(from, hi)
        }
        fn removed_from(
            &mut self,
            from: &str,
            hi: Option<&str>,
        ) -> Result<Option<PathVers>, Self::Err> {
            self.1 += 1;
            self.0.removed_from(from, hi)
        }
        fn device_name(&self, id: &DeviceId) -> Option<String> {
            self.0.device_name(id)
        }
    }
    let asked = |at: u64| {
        let mut src = Counting(MemSource(&sim.mem), 0);
        let Listing::Rows(rows) = list_at(&mut src, &history, "", at).unwrap() else {
            panic!("the root exists");
        };
        let names: Vec<String> = rows.into_iter().map(|r| r.name).collect();
        (names, src.1)
    };
    // Before either folder: both are walked to their end, once.
    let (names, cold) = asked(t + 5_000);
    assert_eq!(names, ["beat"]);
    assert!(cold > 400, "{cold}");
    let (names, warm) = asked(t + 5_000);
    assert_eq!(names, ["beat"]);
    assert!(warm < 20, "{warm}");
    // Other moments, from what the walks learned: the young folder from its first birth on,
    // the dead one only between its birth and its end.
    for (at, expected) in [
        (t + 9_000 - 1, vec!["beat"]),
        (t + 9_000, vec!["beat", "dead"]),
        (t + 19_999, vec!["beat", "dead"]),
        (t + 20_000, vec!["beat"]),
        (t + 28_999, vec!["beat"]),
        (t + 29_000, vec!["beat", "young"]),
        (NOW, vec!["beat", "young"]),
    ] {
        let (names, n) = asked(at);
        assert_eq!(names, expected, "at {at}");
        assert!(n < 20, "at {at}: {n} questions");
        assert_same_tree(&sim, &history, at, &oracle(&sim, &history, at), "memo");
    }
}

/// P3: with honest clocks and every segment's time on record, the past is exactly what was
/// there.
#[test]
fn p3_exact_when_every_segment_is_anchored() {
    for_each_seed("past_p3", 40, |rng| {
        let (sim, times) = random_history(rng, true, 0);
        let history = sim.history();
        // From the second segment on: the first one is placed by its upload.
        for t in moments_of(rng, &times[1..], 24) {
            if t < times[1] - 1 {
                continue;
            }
            let truth = if t == NOW {
                sim.tree.clone()
            } else {
                sim.truly(t)
            };
            assert_same_tree(&sim, &history, t, &truth, "truth");
        }
    });
}

/// P4: under any skew of the recorded times nothing is shown that had ended, nothing at a
/// path after its last deletion, and the versions of a path end in the order of the ops.
#[test]
fn p4_skewed_clocks_never_show_what_was_removed() {
    for_each_seed("past_p4", 40, |rng| {
        let anchored = rng.bool();
        let (sim, times) = random_history(rng, anchored, 5 * DAY);
        let history = sim.history();
        let paths: BTreeSet<String> = sim
            .mem
            .heads_iter()
            .map(|h| h.0.to_owned())
            .chain(sim.mem.removed_iter().map(|r| r.0.to_owned()))
            .collect();
        let moments = moments_of(rng, &times, 40);
        for path in &paths {
            let group = sim.group(path);
            let ends: Vec<u64> = lives(&history.clock, &group)
                .iter()
                .filter_map(|l| l.end)
                .collect();
            assert!(ends.windows(2).all(|w| w[0] <= w[1]), "{path}: {ends:?}");
            for t in &moments {
                let Some(ver) = entry_at(&history.clock, &group, *t) else {
                    continue;
                };
                if *t == NOW {
                    assert!(ver.end.is_none());
                    continue;
                }
                if let Some((_, removed_ms)) = ver.end {
                    assert!(*t < removed_ms, "{path} at {t}");
                }
                if group.heads.is_empty() {
                    let last = group.removed.last().and_then(|v| v.end).map(|e| e.1);
                    assert!(last.is_some_and(|last| *t < last), "{path} at {t}");
                }
            }
        }
    });
}

/// P5: with honest clocks an addition whose time is not on record may show early and never
/// late: whatever was really there at a moment is shown at that moment, with its content —
/// also where a file was put over another one without superseding it. (One exception, which
/// lasts as long as an upload: such a file with new bytes shows from its blob on, `Sim::early`.)
#[test]
fn p5_an_addition_is_never_shown_late() {
    for_each_seed("past_p5", 60, |rng| {
        let (sim, times) = random_history(rng, false, 0);
        for t in moments_of(rng, &times, 40) {
            if t == NOW || t < times[0] {
                continue;
            }
            for (path, thing) in sim.truly(t) {
                let early = |(p, from, until): &(String, u64, u64)| {
                    *p == path && (*from..*until).contains(&t)
                };
                if sim.early.iter().any(early) {
                    continue;
                }
                assert_eq!(sim.at(&path, t), Some(thing), "{path} at {t}");
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Entries that came without an upload of their own
// ---------------------------------------------------------------------------------------------

/// A folder, an empty file, a copy of stored bytes, a restore: nothing in the index says when
/// they came. They are placed by what their device is known to have done before — never
/// before the device was first seen — and marked until the device's next recorded segment.
#[test]
fn an_entry_without_an_upload_of_its_own_is_placed_by_what_its_device_did_before() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        t,
        &[
            Put("big/p", 1, true),
            Put("beat", 1, true),
            Put("keep/k", 3, true),
        ],
    );
    sim.segment(1, t + 10_000, &[Put("beat", 2, true), Del("keep/k")]);
    // A device that joins now: a folder, an empty file, a copy of stored bytes and a restore.
    sim.segment(
        2,
        t + 20_000,
        &[
            Mkdir("plans"),
            Put("empty", 0, false),
            Copy("big/copy", "big/p"),
            Put("keep/k", 3, false),
        ],
    );
    let names = |sim: &Sim, dir: &str, at: u64| -> Vec<(String, bool)> {
        match list_at(&mut MemSource(&sim.mem), &sim.history(), dir, at).unwrap() {
            Listing::Rows(mut rows) => {
                rows.sort_by(|a, b| a.name.cmp(&b.name));
                rows.into_iter().map(|r| (r.name, r.approx)).collect()
            }
            Listing::Absent { .. } => Vec::new(),
        }
    };
    let row = |name: &str, approx: bool| (name.to_owned(), approx);
    // Not before the device existed — and so the restored path is seen deleted in between.
    assert_eq!(
        names(&sim, "", t + 19_999),
        [row("beat", false), row("big", false)]
    );
    assert_eq!(names(&sim, "big", t + 19_999), [row("p", false)]);
    // From then on, each with the mark: the device has no later segment on record.
    assert_eq!(
        names(&sim, "", t + 20_000),
        [
            row("beat", false),
            row("big", false),
            row("empty", true),
            row("keep", true),
            row("plans", true),
        ]
    );
    assert_eq!(
        names(&sim, "big", t + 20_000),
        [row("copy", true), row("p", false)]
    );
    assert_eq!(names(&sim, "keep", t + 20_000), [row("k", true)]);
    let (hits, _) = search_at(
        &mut MemSource(&sim.mem),
        &sim.history(),
        "p",
        100,
        t + 20_000,
    )
    .unwrap();
    let mut found: Vec<(String, bool)> = hits
        .into_iter()
        .map(|r| (r.path.unwrap(), r.approx))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            row("big/copy", true),
            row("big/p", false),
            row("empty", true),
            row("keep", true),
            row("plans", true),
        ]
    );
    // The device's next segment with a time on record: from there on they surely were there.
    sim.segment(2, t + 30_000, &[Put("beat", 3, true)]);
    assert!(names(&sim, "", t + 29_999).contains(&row("plans", true)));
    assert_eq!(
        names(&sim, "", t + 30_000),
        [
            row("beat", false),
            row("big", false),
            row("empty", false),
            row("keep", false),
            row("plans", false),
        ]
    );

    // A device that has been here before: from the last it is known to have done — its
    // previous recorded segment …
    sim.segment(1, t + 40_000, &[Mkdir("late"), Copy("big/copy2", "big/p")]);
    assert!(!names(&sim, "", t + 9_999).contains(&row("late", true)));
    assert!(names(&sim, "", t + 10_000).contains(&row("late", true)));
    assert_eq!(
        names(&sim, "big", t + 10_000),
        [row("copy2", true), row("p", false)]
    );
    // … or its last upload, where that is later.
    sim.segment(1, t + 50_000, &[Put("y", 9, true)]);
    sim.segment(1, t + 60_000, &[Mkdir("after-y")]);
    assert!(!names(&sim, "", t + 48_999).contains(&row("after-y", true)));
    assert!(names(&sim, "", t + 49_000).contains(&row("after-y", true)));

    // The timeline: a copy of stored bytes is no upload — the blob counts for the segment
    // that brought it, and for no later one.
    let found = timeline(&MemSource(&sim.mem), &sim.history(), NOW_MS);
    assert_eq!(
        found.moments,
        [
            // The first upload (the device was first seen with it), then what replaced or
            // removed something, then the upload of `y`.
            (t, 3, 0, 1),
            (t + 10_000, 2, 0, 0),
            (t + 30_000, 1, 1, 0),
            (t + 49_000, 1, 0, 1),
        ]
    );
    assert_eq!(found.devices, ["device-1", "device-2"]);
}

/// `Uploads`: of the versions that point into a blob, those of the lowest segment brought it.
#[test]
fn a_blob_counts_for_the_segment_that_brought_it() {
    let t = FROM_MS + DAY;
    let mut uploads = Uploads::new(FROM_MS);
    // A copy is seen before the upload it copies; two versions of the upload; a blob from
    // before the floor; a second blob of the copying segment.
    uploads.see([1; 16], t, 9, dev(2), 1);
    uploads.see([1; 16], t, 4, dev(1), 1);
    uploads.see([1; 16], t, 4, dev(1), 1);
    uploads.see([1; 16], t, 12, dev(1), 5);
    uploads.see([2; 16], FROM_MS, 3, dev(1), 1);
    uploads.see([3; 16], t + 5, 9, dev(2), 2);
    let mut fresh: Vec<_> = uploads.fresh().collect();
    fresh.sort();
    assert_eq!(fresh, [(4, dev(1), t, 2), (9, dev(2), t + 5, 2)]);
}

/// `copy --force` of bytes the vault holds already, and of an empty file, over a file: the
/// new version supersedes nothing (the old one goes with the op that resolves the two) and
/// brings no blob. It is there from when the old version went — not from the last its device
/// is known to have done, which lies before that.
#[test]
fn a_file_put_over_another_without_a_blob_starts_where_the_older_version_ends() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        t,
        &[
            Put("big/p", 1, true),
            Put("big/q", 2, true),
            Put("docs/x", 3, true),
            Put("beat", 1, true),
        ],
    );
    sim.segment(2, t + 5_000, &[Put("beat", 2, true)]);
    sim.segment(2, t + 10_000, &[CopyOver("big/q", "big/p")]);
    sim.segment(2, t + 10_050, &[Resolve("big/q")]);
    sim.segment(2, t + 20_000, &[Over("docs/x", 0, false)]);
    sim.segment(2, t + 20_050, &[Resolve("docs/x")]);
    let file = |content: u8| Some(Thing::File(content, u64::from(content) + 1));
    // Stored bytes: the old content until the op that removed it.
    for at in [t, t + 5_000, t + 9_999, t + 10_049] {
        assert_eq!(sim.at("big/q", at), file(2), "{at}");
    }
    assert_eq!(sim.at("big/q", t + 10_050), file(1));
    // The empty file: the device's previous segment (t + 10.05 s) is not when it came.
    for at in [t + 10_050, t + 15_000, t + 20_049] {
        assert_eq!(sim.at("docs/x", at), file(3), "{at}");
    }
    assert_eq!(sim.at("docs/x", t + 20_050), file(0));
    assert_eq!(sim.at("docs/x", NOW), file(0));
    let history = sim.history();
    let life = *lives(&history.clock, &sim.group("big/q")).last().unwrap();
    // An estimate, and no doubt left: the resolving segment is the device's next on record.
    assert_eq!(
        (life.born, life.exact, life.sure),
        (t + 10_050, false, t + 10_050)
    );
    let row = stat_at(&mut MemSource(&sim.mem), &history, "big/q", t + 10_050)
        .unwrap()
        .unwrap();
    assert!(!row.approx);
    // The versions: the old one was replaced — the path never was empty — although the op
    // that superseded it is a delete.
    let listed = versions(&mut MemSource(&sim.mem), &history, "big/q", None, NOW_MS).unwrap();
    let seen: Vec<_> = listed
        .versions
        .iter()
        .map(|v| {
            (
                v.size,
                v.written_ms.map(|ms| ms - t),
                v.until_ms.map(|ms| ms - t),
                v.why,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (2, Some(10_050), None, None),
            (3, Some(0), Some(10_050), Some("overwritten")),
        ]
    );
    // The same when the new version has gone as well.
    sim.segment(1, t + 30_000, &[Put("big/q", 7, true)]);
    assert_eq!(sim.at("big/q", t + 10_049), file(2));
    assert_eq!(sim.at("big/q", t + 10_050), file(1));
    assert_eq!(sim.at("big/q", t + 30_000), file(7));
    // A version that an older one outlived is not moved behind it.
    let mut odd = Group {
        path: "f".into(),
        heads: Vec::new(),
        removed: vec![ver(3, 1, Some((9, t + 900))), ver(5, 2, Some((7, t + 100)))],
    };
    by_removal(&mut odd.removed);
    let born: Vec<u64> = lives(&History::build(FROM_MS, [], [], []).clock, &odd)
        .iter()
        .map(|l| l.born)
        .collect();
    assert_eq!(born, [0, 0]);
}

/// Rows that name each other as the version that superseded them — an index that was written
/// to mislead — do not keep the list of versions busy for ever, and a path with very many
/// versions is not searched once per version.
#[test]
fn the_versions_list_ends_whatever_the_index_holds() {
    let t = FROM_MS + DAY;
    let mut src = VecSource {
        heads: Vec::new(),
        removed: vec![
            (
                "loop".into(),
                ver(1_000, 1, Some((1_001, NOW_MS - 3_600_000))),
            ),
            ("loop".into(), ver(1_001, 1, Some((1_000, t)))),
        ],
        asked: 0,
    };
    let history = History::build(FROM_MS, [], [], []);
    for at in [None, Some(t + DAY), Some(NOW_MS - 1)] {
        let listed = versions(&mut src, &history, "loop", at, NOW_MS).unwrap();
        // The version with the smaller stamp is one row with the one that followed it.
        assert_eq!(listed.versions.len(), 1, "{at:?}");
        assert!(listed.deleted);
    }
    // A version superseded by itself.
    src.removed = vec![("loop".into(), ver(7, 1, Some((7, t))))];
    let listed = versions(&mut src, &history, "loop", Some(t - 1), NOW_MS).unwrap();
    assert_eq!(listed.versions.len(), 1);

    // 20,000 versions of one path, each replaced by the next.
    let n = 20_000u64;
    src.removed = (1..n)
        .map(|i| ("many".into(), ver(i, (i % 251) as u8, Some((i + 1, t + i)))))
        .collect();
    src.heads = vec![("many".into(), ver(n, 0, None))];
    let started = std::time::Instant::now();
    let listed = versions(&mut src, &history, "many", Some(t + n / 2), NOW_MS).unwrap();
    assert_eq!(listed.versions.len(), VERSIONS_MAX);
    assert!(listed.more);
    assert_eq!(listed.versions.iter().filter(|v| v.shown).count(), 0);
    // (Quadratic work on 20,000 versions takes many seconds without optimisation.)
    assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
}

/// A walk that ended early at a path that was there is remembered as well, and a folder with
/// many small subfolders that were not there stays known.
#[test]
fn what_a_walk_learned_is_kept_also_when_it_ended_early() {
    let mut sim = Sim::default();
    let t = FROM_MS + DAY;
    sim.segment(
        1,
        t,
        &[
            Put("beat", 1, true),
            Put("young/zz-old", 1, true),
            Put("photos/old", 1, true),
        ],
    );
    let young: Vec<String> = (0..300).map(|i| format!("young/{i:03}")).collect();
    let small: Vec<String> = (0..40)
        .flat_map(|d| (0..20).map(move |i| format!("photos/{d:02}/{i:02}")))
        .collect();
    let puts: Vec<Change<'_>> = young
        .iter()
        .chain(&small)
        .map(|p| Put(p, 1, true))
        .collect();
    sim.segment(1, t + 30_000, &puts);
    sim.segment(1, t + 40_000, &[Put("beat", 2, true)]);
    let history = sim.history();

    /// A source that counts the questions it is asked.
    struct Counting<'a>(MemSource<'a>, usize);
    impl Source for Counting<'_> {
        type Err = std::convert::Infallible;
        fn heads_from(
            &mut self,
            from: &str,
            hi: Option<&str>,
        ) -> Result<Option<PathVers>, Self::Err> {
            self.1 += 1;
            self.0.heads_from(from, hi)
        }
        fn removed_from(
            &mut self,
            from: &str,
            hi: Option<&str>,
        ) -> Result<Option<PathVers>, Self::Err> {
            self.1 += 1;
            self.0.removed_from(from, hi)
        }
        fn device_name(&self, id: &DeviceId) -> Option<String> {
            self.0.device_name(id)
        }
    }
    let asked = |dir: &str, at: u64| {
        let mut src = Counting(MemSource(&sim.mem), 0);
        let Listing::Rows(rows) = list_at(&mut src, &history, dir, at).unwrap() else {
            panic!("{dir:?} exists");
        };
        let names: Vec<String> = rows.into_iter().map(|r| r.name).collect();
        (names, src.1)
    };
    // 40 subfolders of 20 files, none of which was there: walked once, then known.
    let (names, cold) = asked("photos", t + 5_000);
    assert_eq!(names, ["old"]);
    assert!(cold > 800, "{cold}");
    let (names, warm) = asked("photos", t + 6_000);
    assert_eq!(names, ["old"]);
    assert!(warm < 250, "{warm}");
    let (names, warm) = asked("photos", t + 29_000);
    assert_eq!(names.len(), 41);
    assert!(warm < 250, "{warm}");

    // `young` holds 300 files that were not there yet and, last in order, one that was: the
    // first listing walks to it, the next ones — at this moment and at any later one — know.
    let (names, cold) = asked("", t + 5_000);
    assert_eq!(names, ["beat", "photos", "young"]);
    assert!(cold > 300, "{cold}");
    for at in [t + 5_000, t + 20_000, t + 29_500, NOW_MS - 1] {
        let (names, warm) = asked("", at);
        assert!(names.contains(&"young".to_owned()), "at {at}");
        assert!(warm < 40, "at {at}: {warm} questions");
        assert_same_tree(&sim, &history, at, &oracle(&sim, &history, at), "early end");
    }
    // The memo is bounded: when it is full the older half goes, and what is newer stays.
    let history = History::build(FROM_MS, [], [], []);
    let whole = Summary {
        whole: true,
        ..Summary::default()
    };
    for i in 0..MEMO_MAX + 10 {
        history.remember(&format!("dir/{i:06}"), whole);
    }
    assert!(history.known("dir/000000").is_none());
    assert!(
        history
            .known(&format!("dir/{:06}", MEMO_MAX / 2 - 1))
            .is_none()
    );
    assert!(history.known(&format!("dir/{:06}", MEMO_MAX / 2)).is_some());
    assert!(history.known(&format!("dir/{:06}", MEMO_MAX + 9)).is_some());
    assert_eq!(history.memo().kept.len(), MEMO_MAX / 2 + 10);
    // Two walks that ended early: the earlier of what they found; a whole one stays.
    let early = |sure| Summary {
        heads_sure: Some(sure),
        ..Summary::default()
    };
    history.remember("part", early(50));
    history.remember("part", early(70));
    assert_eq!(history.known("part").unwrap().heads_sure, Some(50));
    history.remember("part", early(20));
    assert_eq!(history.known("part").unwrap().heads_sure, Some(20));
    history.remember("part", whole);
    history.remember("part", early(5));
    assert!(history.known("part").unwrap().whole);
}
