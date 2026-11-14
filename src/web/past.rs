//! The vault as it was (SPEC §7.4, "Time machine"): which version was at a path at an earlier
//! moment, the versions of a file, what was deleted from a folder, and the moments at which the
//! vault changed — all derived from what the index keeps anyway: the heads, the removed
//! versions and the blob records.
//!
//! Pure code — no server, no database, no clock: "now" is an argument, and it is used for the
//! window only. Both viewers compile this file (the hosted viewer's core a second time, by
//! path) and give it a [`Source`] of their own, so the two cannot disagree about the past. This
//! file may use `crate::consts`, `crate::path`, `crate::types`, `crate::util`, `crate::index`'s
//! in-memory index and `super::rules`.
//!
//! The index records when a version was **removed** and never when it was written, so the time
//! a version came into being is derived (`Clock`, `lives`): exactly for everything that took
//! another version's place, and as an estimate for a plain addition: close to the truth where
//! the addition brought a blob of its own, and no more than a lower bound where it did not (a
//! folder, an empty file, a restore, a copy of stored bytes) — such an entry is marked
//! (`Life::sure`, `approx` in the answers).

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::rules::{
    self, DeletedJson, EntryJson, GoneJson, RowView, SortOrder, TimelineJson, VersionJson,
    VersionsJson,
};
use crate::consts::RESTORE_WINDOW_MS;
use crate::index::MemIndex;
use crate::types::{DeviceId, Entry, EntryKind, Head, Stamp};
use crate::util;

/// Versions per `versions` answer.
pub const VERSIONS_MAX: usize = 200;
/// Moments per `timeline` answer; more are merged into neighbouring groups.
pub const MOMENTS_MAX: usize = 2000;
/// Removed rows read below one deleted folder to count its files.
pub const DELETED_ROWS_MAX: usize = 1000;
/// Subtree summaries kept (`History::memo`; the older half goes when it is full), and the
/// size of a walk from which one is worth keeping.
const MEMO_MAX: usize = 1 << 15;
const MEMO_WALK_MIN: usize = 16;
/// Paths a walk reads on after one that may have been there (`Presence::Maybe`), looking for
/// one that surely was.
const MAYBE_WALK: usize = 256;
/// "Now" as a moment: every head is alive, no removed version is.
pub const NOW: u64 = u64::MAX;

// ---------------------------------------------------------------------------------------------
// What a source of history hands over
// ---------------------------------------------------------------------------------------------

/// One version of a path, as much of it as the questions about time need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ver {
    pub stamp: Stamp,
    pub hash: [u8; 32],
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_ns: i64,
    /// A removed version: the op that superseded it and the time recorded for that. `None`: a
    /// head.
    pub end: Option<(Stamp, u64)>,
}

impl Ver {
    pub fn of(stamp: &Stamp, entry: &Entry, end: Option<(Stamp, u64)>) -> Ver {
        Ver {
            stamp: *stamp,
            hash: entry.hash,
            kind: entry.kind,
            size: entry.size,
            mtime_ns: entry.mtime_ns,
            end,
        }
    }

    fn is_file(&self) -> bool {
        self.kind == EntryKind::File
    }

    /// A `Head` to show the version with: listings and `stat` read name, size and time of it.
    fn head(&self, path: &str) -> Head {
        Head {
            path: path.to_owned(),
            stamp: self.stamp,
            entry: Entry {
                kind: self.kind,
                size: self.size,
                mtime_ns: self.mtime_ns,
                exec: false,
                hash: self.hash,
                loc: None,
            },
            origin: None,
            winner: false,
        }
    }
}

/// The versions of one path: `(path, versions)`.
pub type PathVers = (String, Vec<Ver>);

/// Where the versions come from: the SQL replica, the in-memory index, a vector in a test.
/// Paths are compared as bytes.
pub trait Source {
    type Err;
    /// The first path `p` with `from <= p` and `p < hi` (`None`: no bound) that has a head,
    /// with all its heads — winner and losers.
    fn heads_from(&mut self, from: &str, hi: Option<&str>) -> Result<Option<PathVers>, Self::Err>;
    /// The same over the removed versions: every removed version of that path, of any age.
    fn removed_from(&mut self, from: &str, hi: Option<&str>)
    -> Result<Option<PathVers>, Self::Err>;
    fn device_name(&self, id: &DeviceId) -> Option<String>;

    /// Every path in `[from, hi)` that has a head or a removed version, in order, each with
    /// all of both ([`Group`]), until `visit` answers `false`. What a search of the past
    /// reads (the whole index, once), a listing (each run of a folder's direct children) and
    /// the question whether a subtree existed. The default asks path by path; a source that
    /// can read its rows in one pass does that instead.
    fn walk(
        &mut self,
        from: &str,
        hi: Option<&str>,
        visit: &mut dyn FnMut(&Group) -> bool,
    ) -> Result<(), Self::Err>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(self);
        let mut from = from.to_owned();
        while let Some(group) = cursor.group(&from, hi)? {
            if !visit(&group) {
                break;
            }
            from = successor(&group.path);
        }
        Ok(())
    }
}

/// Two sequences of rows in path order — heads, removed versions — as one sequence of
/// [`Group`]s: `next_*` hand out the rows one at a time (`None`: no more), each as
/// `(path, version)`. One group is built at a time, in place.
pub fn merge_rows<'a, E>(
    mut next_head: impl FnMut() -> Result<Option<(&'a str, Ver)>, E>,
    mut next_removed: impl FnMut() -> Result<Option<(&'a str, Ver)>, E>,
    visit: &mut dyn FnMut(&Group) -> bool,
) -> Result<(), E> {
    let mut head = next_head()?;
    let mut removed = next_removed()?;
    let mut group = Group::default();
    loop {
        let path = match (&head, &removed) {
            (None, None) => return Ok(()),
            (Some((h, _)), None) => *h,
            (None, Some((r, _))) => *r,
            (Some((h, _)), Some((r, _))) => (*h).min(*r),
        };
        group.path.clear();
        group.path.push_str(path);
        group.heads.clear();
        group.removed.clear();
        while let Some((_, ver)) = head.take_if(|(p, _)| *p == group.path) {
            group.heads.push(ver);
            head = next_head()?;
        }
        while let Some((_, ver)) = removed.take_if(|(p, _)| *p == group.path) {
            group.removed.push(ver);
            removed = next_removed()?;
        }
        if group.removed.len() > 1 {
            by_removal(&mut group.removed);
        }
        if !visit(&group) {
            return Ok(());
        }
    }
}

/// The first string after `path` in byte order (no path holds a NUL).
pub fn successor(path: &str) -> String {
    format!("{path}\0")
}

/// `(first path under dir/, first path after the subtree)`; the root has no bounds.
/// `'/' + 1 == '0'`.
fn subtree(dir: &str) -> (String, Option<String>) {
    match dir.is_empty() {
        true => (String::new(), None),
        false => (format!("{dir}/"), Some(format!("{dir}0"))),
    }
}

fn device_label<S: Source>(src: &S, id: &DeviceId) -> String {
    src.device_name(id).unwrap_or_else(|| id.short())
}

/// The in-memory index as a [`Source`]: the hosted viewer's, and the tests'.
pub struct MemSource<'a>(pub &'a MemIndex);

impl Source for MemSource<'_> {
    type Err = std::convert::Infallible;

    fn heads_from(&mut self, from: &str, hi: Option<&str>) -> Result<Option<PathVers>, Self::Err> {
        let mut found: Option<PathVers> = None;
        for (path, stamp, entry, _) in self.0.heads_range(from, hi) {
            match &mut found {
                None => found = Some((path.to_owned(), vec![Ver::of(stamp, entry, None)])),
                Some((first, vers)) if first == path => vers.push(Ver::of(stamp, entry, None)),
                Some(_) => break,
            }
        }
        Ok(found)
    }

    fn removed_from(
        &mut self,
        from: &str,
        hi: Option<&str>,
    ) -> Result<Option<PathVers>, Self::Err> {
        let mut found: Option<PathVers> = None;
        for (path, stamp, entry, removed_ms, by) in self.0.removed_range(from, hi) {
            let ver = Ver::of(stamp, entry, Some((*by, removed_ms)));
            match &mut found {
                None => found = Some((path.to_owned(), vec![ver])),
                Some((first, vers)) if first == path => vers.push(ver),
                Some(_) => break,
            }
        }
        Ok(found)
    }

    fn device_name(&self, id: &DeviceId) -> Option<String> {
        self.0.device_name(id).map(str::to_owned)
    }

    /// One pass over the two maps, in their order: no seek per path.
    fn walk(
        &mut self,
        from: &str,
        hi: Option<&str>,
        visit: &mut dyn FnMut(&Group) -> bool,
    ) -> Result<(), Self::Err> {
        let mut heads = self.0.heads_range(from, hi);
        let mut removed = self.0.removed_range(from, hi);
        merge_rows(
            || {
                Ok(heads
                    .next()
                    .map(|(path, stamp, entry, _)| (path, Ver::of(stamp, entry, None))))
            },
            || {
                Ok(removed.next().map(|(path, stamp, entry, ms, by)| {
                    (path, Ver::of(stamp, entry, Some((*by, ms))))
                }))
            },
            visit,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The two sides, merged by path
// ---------------------------------------------------------------------------------------------

/// Everything the index holds about one path.
#[derive(Clone, Debug, Default)]
pub struct Group {
    pub path: String,
    /// By rising `(stamp, hash)`: the last one is the winner.
    pub heads: Vec<Ver>,
    /// By rising `(by, stamp, hash)`: the order in which they were superseded.
    pub removed: Vec<Ver>,
}

#[derive(Default)]
struct Side {
    /// What `ahead` answers: the first path at or after `from` (below `hi`).
    asked: Option<(String, Option<String>)>,
    ahead: Option<PathVers>,
}

impl Side {
    /// Whether `ahead` also answers a question about `[from, hi)`.
    fn answers(&self, from: &str, hi: Option<&str>) -> bool {
        let Some((asked_from, asked_hi)) = &self.asked else {
            return false;
        };
        if asked_from.as_str() > from {
            return false;
        }
        match &self.ahead {
            // The first path at or after `asked_from`: nothing lies between the two.
            Some((path, _)) => path.as_str() >= from,
            // Nothing up to `asked_hi`.
            None => match (asked_hi, hi) {
                (None, _) => true,
                (Some(asked), Some(hi)) => hi <= asked.as_str(),
                (Some(_), None) => false,
            },
        }
    }
}

/// Heads and removed versions as one sequence of paths. Each side keeps the one group it has
/// read ahead, so that the side that is ahead is not asked again while the other catches up.
pub struct Cursor<'s, S: Source> {
    src: &'s mut S,
    heads: Side,
    removed: Side,
}

impl<'s, S: Source> Cursor<'s, S> {
    pub fn new(src: &'s mut S) -> Self {
        Cursor {
            src,
            heads: Side::default(),
            removed: Side::default(),
        }
    }

    fn fill(&mut self, removed: bool, from: &str, hi: Option<&str>) -> Result<(), S::Err> {
        let side = if removed { &self.removed } else { &self.heads };
        if side.answers(from, hi) {
            return Ok(());
        }
        let ahead = match removed {
            true => self.src.removed_from(from, hi)?,
            false => self.src.heads_from(from, hi)?,
        };
        let side = if removed {
            &mut self.removed
        } else {
            &mut self.heads
        };
        side.asked = Some((from.to_owned(), hi.map(str::to_owned)));
        side.ahead = ahead;
        Ok(())
    }

    fn ahead<'a>(side: &'a Side, hi: Option<&str>) -> Option<&'a str> {
        side.ahead
            .as_ref()
            .map(|(path, _)| path.as_str())
            .filter(|path| hi.is_none_or(|hi| *path < hi))
    }

    /// The first path in `[from, hi)` that has a head or a removed version, with both.
    pub fn group(&mut self, from: &str, hi: Option<&str>) -> Result<Option<Group>, S::Err> {
        self.fill(false, from, hi)?;
        self.fill(true, from, hi)?;
        let path = match (Self::ahead(&self.heads, hi), Self::ahead(&self.removed, hi)) {
            (None, None) => return Ok(None),
            (Some(h), None) => h,
            (None, Some(r)) => r,
            (Some(h), Some(r)) => h.min(r),
        }
        .to_owned();
        let take = |side: &mut Side| match &side.ahead {
            Some((p, _)) if *p == path => {
                side.asked = None;
                side.ahead.take().map(|(_, vers)| vers).unwrap_or_default()
            }
            _ => Vec::new(),
        };
        let mut heads = take(&mut self.heads);
        let mut removed = take(&mut self.removed);
        order_by(&mut heads, |v| (v.stamp, v.hash));
        by_removal(&mut removed);
        Ok(Some(Group {
            path,
            heads,
            removed,
        }))
    }

    /// Everything about exactly `path` (empty when the index knows nothing of it).
    pub fn at(&mut self, path: &str) -> Result<Group, S::Err> {
        let found = self.group(path, Some(&successor(path)))?;
        Ok(found.unwrap_or_else(|| Group {
            path: path.to_owned(),
            ..Group::default()
        }))
    }
}

// ---------------------------------------------------------------------------------------------
// The time model (§7.4, normative)
// ---------------------------------------------------------------------------------------------

/// A segment — `(device, lamport)` — and a time: one entry of the clock, which is sorted.
type Timed = (DeviceId, u64, u64);

/// The entry of `(device, lamport)` in a sorted list, or where it would be.
fn timed_at(list: &[Timed], device: &DeviceId, lamport: u64) -> (usize, Option<u64>) {
    let k = list.partition_point(|(d, l, _)| (d, *l) < (device, lamport));
    let found = list
        .get(k)
        .filter(|(d, l, _)| d == device && *l == lamport)
        .map(|(_, _, ms)| *ms);
    (k, found)
}

/// How the time of a segment is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// On record: the segment superseded something.
    Exact,
    /// From a blob the segment brought: early by no more than its upload took.
    Upload,
    /// Nothing but a lower bound: what the same device is known to have done before.
    Bound,
}

/// When a segment was written, as far as the index tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct When {
    /// 0: before the window.
    pub ms: u64,
    pub basis: Basis,
    /// It was written no later than this: the time of the device's next segment that is on
    /// record (`u64::MAX`: there is none).
    pub by: u64,
}

/// When each segment `(lamport, device)` was written, as far as the index tells.
#[derive(Default)]
pub struct Clock {
    /// The segments that superseded something, by device and lamport, with the time
    /// recorded for that (the smallest), made monotone per device: a device's lamports grow
    /// with real time, and a recorded removal time only errs late.
    anchors: Vec<Timed>,
    /// The segments that brought a blob of their own (`Uploads`), by device and lamport. The
    /// time is the creation of the newest such blob of the segment and of the device's
    /// segments before it, each held below the anchor that follows it.
    fresh: Vec<Timed>,
    /// When each device was first seen, by device.
    firsts: Vec<(DeviceId, u64)>,
}

impl Clock {
    /// The time of the segment a stamp belongs to.
    pub fn at(&self, stamp: &Stamp) -> When {
        let (k, anchored) = timed_at(&self.anchors, &stamp.device, stamp.lamport);
        if let Some(ms) = anchored {
            return When {
                ms,
                basis: Basis::Exact,
                by: ms,
            };
        }
        // Every lower bound there is: the device's anchor below, the blobs it had made by
        // then, and the moment the device was first seen.
        let own = |at: Option<&Timed>| at.filter(|(d, ..)| *d == stamp.device).map(|a| a.2);
        let below = |list: &[Timed], k: usize| own(k.checked_sub(1).and_then(|i| list.get(i)));
        let lo = below(&self.anchors, k).unwrap_or(0);
        let (f, brought) = timed_at(&self.fresh, &stamp.device, stamp.lamport);
        let uploads = brought.or_else(|| below(&self.fresh, f)).unwrap_or(0);
        let first = self
            .firsts
            .binary_search_by(|(d, _)| d.cmp(&stamp.device))
            .map_or(0, |at| self.firsts[at].1);
        let by = own(self.anchors.get(k)).unwrap_or(u64::MAX);
        When {
            ms: lo.max(uploads).max(first).min(by),
            basis: match brought {
                Some(_) => Basis::Upload,
                None => Basis::Bound,
            },
            by,
        }
    }
}

/// Which segment brought each blob. Of the versions that point into a blob created after the
/// floor, those of the lowest segment count as its upload: a later version that points into
/// the same blob reuses stored bytes (a copy, a restore) and says nothing about when it was
/// written.
pub struct Uploads {
    floor_b: u64,
    /// Per blob: `(lamport, device)` of the lowest segment seen, the blob's creation time,
    /// the versions of that segment.
    by_blob: BTreeMap<[u8; 16], ((u64, DeviceId), u64, u64)>,
}

impl Uploads {
    pub fn new(floor_b: u64) -> Uploads {
        Uploads {
            floor_b,
            by_blob: BTreeMap::new(),
        }
    }

    /// `versions` versions of the segment `(lamport, device)` point into the blob `blob`,
    /// which was created at `created_ms`.
    pub fn see(
        &mut self,
        blob: [u8; 16],
        created_ms: u64,
        lamport: u64,
        device: DeviceId,
        versions: u64,
    ) {
        if created_ms <= self.floor_b {
            return;
        }
        let segment = (lamport, device);
        let slot = self.by_blob.entry(blob).or_insert((segment, created_ms, 0));
        if segment < slot.0 {
            *slot = (segment, created_ms, 0);
        }
        if segment == slot.0 {
            slot.2 += versions;
        }
    }

    /// What [`History::build`] takes as `fresh`.
    pub fn fresh(self) -> impl Iterator<Item = (u64, DeviceId, u64, u64)> {
        self.by_blob
            .into_values()
            .map(|((lamport, device), created_ms, versions)| {
                (lamport, device, created_ms, versions)
            })
    }
}

/// Orders a list by a key that is unique in it. The lists of this file are short (the versions
/// of one path) or sorted once per state of the index (the moments), and the hosted viewer's
/// module has a size limit (§7.5): a few lines of Shell sort serve them, where each use of the
/// standard library's sort would add its whole machinery for one more type.
fn order_by<T, K: Ord>(items: &mut [T], key: impl Fn(&T) -> K) {
    let mut gap = items.len() / 2;
    while gap > 0 {
        for i in gap..items.len() {
            let mut j = i;
            while j >= gap && key(&items[j - gap]) > key(&items[j]) {
                items.swap(j - gap, j);
                j -= gap;
            }
        }
        gap /= 2;
    }
}

/// A moment at which the vault changed: one segment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Moment {
    ms: u64,
    lamport: u64,
    device: DeviceId,
    /// Removed file versions it superseded (exact), or its versions with new blobs (approx).
    files: u64,
    approx: bool,
}

/// Whether something was there at a moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Presence {
    #[default]
    No,
    /// Only through entries whose time of arrival is a lower bound (`Basis::Bound`): they may
    /// have come later than the moment asked for.
    Maybe,
    Yes,
}

impl Presence {
    fn of(doubt: bool) -> Presence {
        if doubt {
            Presence::Maybe
        } else {
            Presence::Yes
        }
    }
}

/// What a walk learned about a subtree.
#[derive(Clone, Copy, Default)]
struct Summary {
    /// The walk saw all of it. Otherwise it ended at a path that was there, and only
    /// `heads_sure` — an upper bound then — says something.
    whole: bool,
    /// The earliest birth of a head under it: from then on the subtree may exist.
    heads_first: Option<u64>,
    /// The earliest moment from which a head under it was surely there (`Life::sure`): from
    /// then on the subtree exists.
    heads_sure: Option<u64>,
    /// `(earliest birth, latest end)` of the removed versions under it.
    removed: Option<(u64, u64)>,
}

impl Summary {
    fn head(&mut self, born: u64, sure: u64) {
        self.heads_first = Some(self.heads_first.map_or(born, |b| b.min(born)));
        self.heads_sure = Some(self.heads_sure.map_or(sure, |s| s.min(sure)));
    }
}

/// Summaries by subtree, each with the number it was kept under: the greater, the newer.
#[derive(Default)]
struct Memo {
    kept: BTreeMap<String, (Summary, u64)>,
    next: u64,
}

/// What is derived once per state of the index: the clock of the segments, the moments of the
/// timeline, and summaries of subtrees that were walked in vain. Small: its size follows the
/// number of segments the index still remembers, not the number of files.
pub struct History {
    /// Blobs created after this count as evidence of an upload: the start of the window when
    /// this was built.
    floor_b: u64,
    clock: Clock,
    /// By rising `(ms, lamport, device)`.
    moments: Vec<Moment>,
    memo: Mutex<Memo>,
}

impl History {
    pub fn floor_for(now_ms: u64) -> u64 {
        now_ms.saturating_sub(RESTORE_WINDOW_MS)
    }

    /// Whether this history serves a call at `now_ms`: its floor must not lie inside that
    /// call's window (a clock that went back).
    pub fn serves(&self, now_ms: u64) -> bool {
        Self::floor_for(now_ms) >= self.floor_b
    }

    /// `anchors`: `(by.lamport, by.device, removed_ms, files)` over the removed versions —
    /// one per row (`files`: 1 for a file) or grouped per segment (the smallest time, the sum).
    /// `fresh`: `(stamp.lamport, stamp.device, blob.created_ms, versions)` over the versions
    /// that brought a blob created after `floor_b` ([`Uploads`]), raw or grouped likewise.
    /// `firsts`: when each device was first seen.
    pub fn build(
        floor_b: u64,
        anchors: impl IntoIterator<Item = (u64, DeviceId, u64, u64)>,
        fresh: impl IntoIterator<Item = (u64, DeviceId, u64, u64)>,
        firsts: impl IntoIterator<Item = (DeviceId, u64)>,
    ) -> History {
        // Per segment, by device and lamport: `(time, count)`.
        type Segments = BTreeMap<(DeviceId, u64), (u64, u64)>;
        let mut anchored = Segments::new();
        for (lamport, device, ms, files) in anchors {
            let slot = anchored.entry((device, lamport)).or_insert((ms, 0));
            slot.0 = slot.0.min(ms);
            slot.1 += files;
        }
        let mut uploads = Segments::new();
        for (lamport, device, created_ms, versions) in fresh {
            if created_ms <= floor_b {
                continue;
            }
            let slot = uploads.entry((device, lamport)).or_insert((created_ms, 0));
            slot.0 = slot.0.max(created_ms);
            slot.1 += versions;
        }
        let mut clock = Clock::default();
        let mut moments = Vec::new();
        // From each device's last segment back: no anchor is later than one that follows it.
        let mut later: Option<(DeviceId, u64)> = None;
        for ((device, lamport), (ms, files)) in anchored.into_iter().rev() {
            let ms = match later {
                Some((of, later)) if of == device => later.min(ms),
                _ => ms,
            };
            later = Some((device, ms));
            clock.anchors.push((device, lamport, ms));
            moments.push(Moment {
                ms,
                lamport,
                device,
                files,
                approx: false,
            });
        }
        clock.anchors.reverse();
        clock.firsts = firsts.into_iter().collect();
        order_by(&mut clock.firsts, |(device, _)| *device);
        // What a device had uploaded by each of its segments: the newest blob so far. Evidence
        // that lies after the anchor that follows it is brought back to that anchor first, so a
        // wrong time is not carried on.
        let mut so_far: Option<(DeviceId, u64)> = None;
        for ((device, lamport), (ms, _)) in &uploads {
            let (k, _) = timed_at(&clock.anchors, device, *lamport);
            let next = clock.anchors.get(k).filter(|(d, ..)| d == device);
            let ms = next.map_or(*ms, |(.., anchor)| (*ms).min(*anchor));
            let ms = match so_far {
                Some((of, before)) if of == *device => before.max(ms),
                _ => ms,
            };
            so_far = Some((*device, ms));
            clock.fresh.push((*device, *lamport, ms));
        }
        for ((device, lamport), (_, files)) in uploads {
            let stamp = Stamp {
                lamport,
                device,
                idx: 0,
            };
            let when = clock.at(&stamp);
            if when.basis != Basis::Exact {
                moments.push(Moment {
                    ms: when.ms,
                    lamport,
                    device,
                    files,
                    approx: true,
                });
            }
        }
        order_by(&mut moments, |m| (m.ms, m.lamport, m.device));
        History {
            floor_b,
            clock,
            moments,
            memo: Mutex::new(Memo::default()),
        }
    }

    /// The history of an in-memory index.
    pub fn of_mem(mem: &MemIndex, now_ms: u64) -> History {
        let floor_b = Self::floor_for(now_ms);
        let file = |entry: &Entry| u64::from(entry.kind == EntryKind::File);
        let anchors = mem
            .removed_iter()
            .map(|(_, _, entry, ms, by)| (by.lamport, by.device, ms, file(entry)));
        let mut uploads = Uploads::new(floor_b);
        let versions = mem
            .heads_iter()
            .map(|(_, stamp, entry, _)| (stamp, entry))
            .chain(
                mem.removed_iter()
                    .map(|(_, stamp, entry, _, _)| (stamp, entry)),
            );
        for (stamp, entry) in versions {
            let Some(loc) = &entry.loc else { continue };
            if let Some(blob) = mem.blob(&loc.blob) {
                uploads.see(loc.blob.0, blob.created_ms, stamp.lamport, stamp.device, 1);
            }
        }
        let firsts = mem.devices().into_iter().map(|d| (d.id, d.first_ms));
        History::build(floor_b, anchors, uploads.fresh(), firsts)
    }

    fn memo(&self) -> std::sync::MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What a walk learned about the subtree `prefix`, if that was kept.
    fn known(&self, prefix: &str) -> Option<Summary> {
        self.memo().kept.get(prefix).map(|(summary, _)| *summary)
    }

    fn remember(&self, prefix: &str, mut summary: Summary) {
        let mut memo = self.memo();
        if let Some((known, _)) = memo.kept.get(prefix) {
            if known.whole {
                return;
            }
            if !summary.whole {
                // Two walks that ended early: the earlier of what they found.
                summary.heads_sure = match (summary.heads_sure, known.heads_sure) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
        } else if memo.kept.len() >= MEMO_MAX {
            // Full: the older half goes. (Every summary has a number of its own, and none
            // leaves in another way: the numbers in use are the last `len` ones.)
            let keep_from = memo.next - (MEMO_MAX / 2) as u64;
            memo.kept.retain(|_, (_, number)| *number >= keep_from);
        }
        let number = memo.next;
        memo.next += 1;
        memo.kept.insert(prefix.to_owned(), (summary, number));
    }
}

/// Where a version lies in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Life {
    pub born: u64,
    /// `born` is a recorded time, not an estimate.
    pub exact: bool,
    /// From when on the version was surely there: `born`, unless that is no more than a lower
    /// bound (`Basis::Bound`) — then the time by which its segment was written (`When::by`).
    pub sure: u64,
    /// When it stopped being a head: its recorded removal, or that of a version superseded
    /// later on the same path where that is earlier. `None`: a head.
    pub end: Option<u64>,
}

impl Life {
    fn alive(&self, t: u64) -> bool {
        self.born <= t && self.end.is_none_or(|end| t < end)
    }

    /// Alive at `t` (`alive`), but perhaps not yet: its birth is a lower bound.
    fn doubt(&self, t: u64) -> bool {
        t < self.sure
    }
}

/// When each removed version of one path (in the order they were superseded) stopped being a
/// head: its recorded time, or the time of a version superseded after it where that is
/// earlier — a recorded removal time only errs late, and the order of the ops is causal.
fn chain_ends(removed: &[Ver]) -> Vec<u64> {
    let mut ends: Vec<u64> = removed
        .iter()
        .map(|ver| ver.end.map_or(u64::MAX, |(_, ms)| ms))
        .collect();
    for i in (0..ends.len().saturating_sub(1)).rev() {
        ends[i] = ends[i].min(ends[i + 1]);
    }
    ends
}

pub fn by_removal(removed: &mut [Ver]) {
    order_by(removed, |v| (v.end.map(|e| e.0), v.stamp, v.hash));
}

/// The lives of a group's versions: the removed ones first (in the group's order), then the
/// heads.
pub fn lives(clock: &Clock, group: &Group) -> Vec<Life> {
    let removed = &group.removed;
    let by = |ver: &Ver| ver.end.map(|(by, _)| by);
    let ends = chain_ends(removed);
    // The removed versions by stamp, each with the latest end among it and those before it:
    // made when the first version asks for it. The latest end among the versions that the
    // writer of `stamp` can have seen: those of a lower lamport.
    let older = std::cell::OnceCell::new();
    let ended_before = |stamp: &Stamp| {
        let list: &Vec<(Stamp, u64)> = older.get_or_init(|| {
            let mut list: Vec<(Stamp, u64)> = removed
                .iter()
                .zip(&ends)
                .map(|(u, end)| (u.stamp, *end))
                .collect();
            order_by(&mut list, |(stamp, end)| (*stamp, *end));
            let mut latest = 0;
            for (_, end) in &mut list {
                latest = latest.max(*end);
                *end = latest;
            }
            list
        });
        let k = list.partition_point(|(s, _)| s.lamport < stamp.lamport);
        k.checked_sub(1).map_or(0, |k| list[k].1)
    };
    let life = |ver: &Ver, end: Option<u64>| {
        // The last version superseded at or before this one came.
        let before = removed.partition_point(|u| by(u).is_some_and(|by| by <= ver.stamp));
        let (floor, took_its_place) = match before.checked_sub(1) {
            Some(prev) => (ends[prev], by(&removed[prev]) == Some(ver.stamp)),
            None => (0, false),
        };
        if took_its_place {
            return Life {
                born: floor,
                exact: true,
                sure: floor,
                end,
            };
        }
        let when = clock.at(&ver.stamp);
        let mut born = when.ms.max(floor);
        if when.basis != Basis::Bound {
            return Life {
                born,
                exact: when.basis == Basis::Exact,
                sure: born,
                end,
            };
        }
        // Nothing says when it came but what its device did before. A version that came
        // without taking another one's place and without a blob of its own (`copy --force`
        // of stored bytes or of an empty file over a file that was there: the older version
        // goes with the op that resolves the two) is placed where the older versions of its
        // path had gone — those its writer can have seen, and unless one of them outlived it.
        let gone = ended_before(&ver.stamp);
        if end.is_none_or(|end| gone < end) {
            born = born.max(gone);
        }
        Life {
            born,
            exact: false,
            sure: when.by.max(born),
            end,
        }
    };
    let mut out = Vec::with_capacity(removed.len() + group.heads.len());
    out.extend(
        removed
            .iter()
            .zip(&ends)
            .map(|(v, end)| life(v, Some(*end))),
    );
    out.extend(group.heads.iter().map(|v| life(v, None)));
    out
}

/// The version at the group's path at `t`: the alive one with the greatest `(stamp, hash)`.
pub fn entry_at<'g>(clock: &Clock, group: &'g Group, t: u64) -> Option<&'g Ver> {
    entry_then(clock, group, t).map(|(ver, _)| ver)
}

/// [`entry_at`], and whether the version may have come later than `t` (`Life::doubt`).
pub fn entry_then<'g>(clock: &Clock, group: &'g Group, t: u64) -> Option<(&'g Ver, bool)> {
    if t == NOW {
        return group.heads.last().map(|ver| (ver, false));
    }
    if group.removed.is_empty() {
        // Nothing was ever superseded here: a head is there from its segment's time on.
        return group.heads.iter().rev().find_map(|ver| {
            let when = clock.at(&ver.stamp);
            (when.ms <= t).then(|| (ver, when.basis == Basis::Bound && t < when.by))
        });
    }
    let lives = lives(clock, group);
    group
        .removed
        .iter()
        .chain(&group.heads)
        .zip(&lives)
        .filter(|(_, life)| life.alive(t))
        .max_by_key(|(ver, _)| (ver.stamp, ver.hash))
        .map(|(ver, life)| (ver, life.doubt(t)))
}

/// Whether the group's path held something at `t`: surely, if one of the versions alive then
/// surely was.
fn present(lives: &[Life], t: u64) -> Presence {
    let mut found = Presence::No;
    for life in lives.iter().filter(|life| life.alive(t)) {
        found = found.max(Presence::of(life.doubt(t)));
    }
    found
}

/// The start of the window at `now_ms`: nothing removed before it is offered.
pub fn window_from(now_ms: u64) -> u64 {
    now_ms.saturating_sub(RESTORE_WINDOW_MS)
}

/// `at` moved into the window: the value an answer echoes.
pub fn clamp_at(at: u64, now_ms: u64) -> u64 {
    at.clamp(window_from(now_ms), now_ms)
}

/// The moment a clamped `at` stands for: the present for `now_ms` itself.
pub fn moment(at: u64, now_ms: u64) -> u64 {
    if at >= now_ms { NOW } else { at }
}

/// A removed version that is offered: a file, removed inside the window (the raw recorded
/// time — what `gclone restore` and the garbage collection count by).
pub fn offered(ver: &Ver, now_ms: u64) -> bool {
    match ver.end {
        Some((_, removed_ms)) => {
            ver.is_file() && now_ms.saturating_sub(removed_ms) < RESTORE_WINDOW_MS
        }
        None => false,
    }
}

/// How the removed version `removed[at]` of a path went (`removed`: all of them, in the order
/// they were superseded — `by_removal`; `heads`: the path's heads): `"overwritten"` when the
/// path still held a file after the op that superseded it, else `"deleted"` (a delete, or a
/// move away).
///
/// A file was still there when another file version of the path had been written by then
/// (its stamp is not after the superseding op) and went later, or not at all. That is the
/// version that took the removed one's place — or, where a file was replaced without being
/// superseded (`copy --force`: the old version goes with the op that resolves the two), the
/// one that had come before. The viewers and `gclone restore --list` both ask here.
pub fn why(removed: &[Ver], heads: &[Ver], at: usize) -> &'static str {
    let Some((by, _)) = removed.get(at).and_then(|ver| ver.end) else {
        return "deleted";
    };
    let there = |ver: &Ver| ver.is_file() && ver.stamp <= by;
    match removed[at + 1..].iter().chain(heads).any(there) {
        true => "overwritten",
        false => "deleted",
    }
}

/// The name of one version of a path in an address or a command: 12 hexadecimal digits that
/// reveal neither its stamp nor its content hash.
pub fn version_id(path: &str, stamp: &Stamp, hash: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new_derive_key("gclone version id v1");
    h.update(path.as_bytes());
    h.update(&[0]);
    h.update(&stamp.lamport.to_be_bytes());
    h.update(&stamp.device.0);
    h.update(&stamp.idx.to_be_bytes());
    h.update(hash);
    util::hex(&h.finalize().as_bytes()[..6])
}

fn id_of(path: &str, ver: &Ver) -> String {
    version_id(path, &ver.stamp, &ver.hash)
}

/// A file row of an earlier moment against the present winner.
fn since_file(ver: &Ver, group: &Group) -> Option<&'static str> {
    match group.heads.last() {
        Some(now) if now.is_file() => {
            (now.size != ver.size || now.hash != ver.hash).then_some("changed")
        }
        _ => Some("deleted"),
    }
}

// ---------------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------------

/// A row of an earlier moment, a deleted row, or a match of a search in the past.
#[derive(Clone, Debug)]
pub struct Row {
    pub name: String,
    /// Search results and `stat`.
    pub path: Option<String>,
    pub is_dir: bool,
    pub head: Option<Head>,
    pub v: Option<String>,
    pub since: Option<&'static str>,
    pub gone: Option<GoneJson>,
    pub files: Option<(u64, bool)>,
    /// A row of an earlier moment that may not have been there yet (`Presence::Maybe`).
    pub approx: bool,
    /// A deleted row: the last removal at or under it.
    pub last_end: u64,
}

impl Row {
    fn dir(name: &str, since: Option<&'static str>) -> Row {
        Row {
            name: name.to_owned(),
            path: None,
            is_dir: true,
            head: None,
            v: None,
            since,
            gone: None,
            files: None,
            approx: false,
            last_end: 0,
        }
    }

    fn file(name: &str, path: &str, ver: &Ver) -> Row {
        Row {
            is_dir: false,
            head: Some(ver.head(path)),
            ..Row::dir(name, None)
        }
    }

    /// The version this row shows.
    pub fn version(&self) -> Option<(&Stamp, &[u8; 32])> {
        self.head.as_ref().map(|h| (&h.stamp, &h.entry.hash))
    }

    /// The row as an entry of the API.
    pub fn json(&self) -> EntryJson {
        EntryJson::of_row(self, self.path.clone())
    }
}

impl RowView for Row {
    fn name(&self) -> &str {
        &self.name
    }
    fn tie(&self) -> &str {
        self.path.as_deref().unwrap_or(&self.name)
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }
    fn v(&self) -> Option<&str> {
        self.v.as_deref()
    }
    fn since(&self) -> Option<&'static str> {
        self.since
    }
    fn gone_info(&self) -> Option<&GoneJson> {
        self.gone.as_ref()
    }
    fn files(&self) -> Option<(u64, bool)> {
        self.files
    }
    fn approx(&self) -> bool {
        self.approx
    }
}

// ---------------------------------------------------------------------------------------------
// The vault at a moment
// ---------------------------------------------------------------------------------------------

/// Whether a removed version under `prefix/` is alive at `t` — what the heads say is known.
fn removed_alive_under<S: Source>(
    src: &mut S,
    history: &History,
    prefix: &str,
    t: u64,
) -> Result<Presence, S::Err> {
    let (lo, hi) = subtree(prefix);
    let mut from = lo;
    let mut found = Presence::No;
    let mut read_on = MAYBE_WALK;
    while let Some((path, removed)) = src.removed_from(&from, hi.as_deref())? {
        let mut group = Group {
            path,
            heads: Vec::new(),
            removed,
        };
        by_removal(&mut group.removed);
        found = found.max(present(&lives(&history.clock, &group), t));
        match found {
            Presence::Yes => break,
            Presence::Maybe if read_on == 0 => break,
            Presence::Maybe => read_on -= 1,
            Presence::No => {}
        }
        from = successor(&group.path);
    }
    Ok(found)
}

/// Whether some path under `prefix/` has an entry at `t`.
///
/// One pass over the subtree (`Source::walk`), which ends at the first path that surely was
/// there; after one that may have been, it reads on for a while and then settles for that.
/// What a walk of some length learned is kept (`Summary`): a walk that saw the whole subtree
/// answers every later question about it, at any moment, without another one — or with a
/// look at the removed versions alone — and a walk that ended early says from when on the
/// subtree surely exists.
pub fn exists_under<S: Source>(
    src: &mut S,
    history: &History,
    prefix: &str,
    t: u64,
) -> Result<Presence, S::Err> {
    let (lo, hi) = subtree(prefix);
    if t == NOW {
        let live = src.heads_from(&lo, hi.as_deref())?.is_some();
        return Ok(if live { Presence::Yes } else { Presence::No });
    }
    if let Some(known) = history.known(prefix) {
        if known.heads_sure.is_some_and(|sure| sure <= t) {
            return Ok(Presence::Yes);
        }
        if known.whole {
            let heads = match known.heads_first {
                Some(born) if born <= t => Presence::Maybe,
                _ => Presence::No,
            };
            return Ok(match known.removed {
                Some((born, end)) if born <= t && t < end => {
                    heads.max(removed_alive_under(src, history, prefix, t)?)
                }
                _ => heads,
            });
        }
    }
    let clock = &history.clock;
    let mut seen = Summary::default();
    let mut found = Presence::No;
    let (mut walked, mut read_on, mut ended) = (0usize, MAYBE_WALK, false);
    // Files of one upload follow each other and share a segment: its time is looked up once.
    let mut last: Option<((u64, DeviceId), When)> = None;
    src.walk(&lo, hi.as_deref(), &mut |group| {
        walked += 1;
        let here = if group.removed.is_empty() {
            // Nothing was ever superseded at this path: each head is there from its
            // segment's time on.
            let mut here = Presence::No;
            for head in &group.heads {
                let segment = (head.stamp.lamport, head.stamp.device);
                let when = match last {
                    Some((of, when)) if of == segment => when,
                    _ => clock.at(&head.stamp),
                };
                last = Some((segment, when));
                let sure = match when.basis {
                    Basis::Bound => when.by.max(when.ms),
                    _ => when.ms,
                };
                seen.head(when.ms, sure);
                if when.ms <= t {
                    here = here.max(Presence::of(t < sure));
                }
            }
            here
        } else {
            let lives = lives(clock, group);
            let (removed, heads) = lives.split_at(group.removed.len());
            for life in heads {
                seen.head(life.born, life.sure);
            }
            for life in removed {
                let end = life.end.unwrap_or(0);
                seen.removed = Some(match seen.removed {
                    Some((born, last)) => (born.min(life.born), last.max(end)),
                    None => (life.born, end),
                });
            }
            present(&lives, t)
        };
        found = found.max(here);
        ended = match found {
            Presence::Yes => true,
            Presence::Maybe if read_on == 0 => true,
            Presence::Maybe => {
                read_on -= 1;
                false
            }
            Presence::No => false,
        };
        !ended
    })?;
    seen.whole = !ended;
    if walked > MEMO_WALK_MIN && (seen.whole || seen.heads_sure.is_some()) {
        history.remember(prefix, seen);
    }
    Ok(found)
}

/// Whether `dir` was a directory at `t`: a directory marker at it, or something under it.
fn dir_at<S: Source>(
    src: &mut S,
    history: &History,
    dir: &str,
    t: u64,
) -> Result<Presence, S::Err> {
    if dir.is_empty() {
        return Ok(Presence::Yes);
    }
    let group = Cursor::new(src).at(dir)?;
    let marker = match entry_then(&history.clock, &group, t) {
        Some((ver, doubt)) if !ver.is_file() => Presence::of(doubt),
        _ => Presence::No,
    };
    if marker == Presence::Yes {
        return Ok(marker);
    }
    Ok(marker.max(exists_under(src, history, dir, t)?))
}

/// The entry of `name` in a list of the child names of a folder, in the order their first
/// path came — made if it is not there. A name comes a second time only as a folder (`c/x`
/// after `c`), and then every name that came in between starts with it (`c.txt` lies between
/// `c` and `c/`): the way back to it is short.
fn named<'a, T: Default>(names: &'a mut Vec<(String, T)>, name: &str) -> &'a mut T {
    let between = names
        .iter()
        .rev()
        .take_while(|(other, _)| other.starts_with(name))
        .position(|(other, _)| other == name);
    let at = match between {
        Some(back) => names.len() - 1 - back,
        None => {
            names.push((name.to_owned(), T::default()));
            names.len() - 1
        }
    };
    &mut names[at].1
}

/// A listing of an earlier moment.
pub enum Listing {
    Rows(Vec<Row>),
    /// The folder did not exist then; the closest folder above it that did.
    Absent {
        nearest: String,
    },
}

/// The direct children of `dir` (`""`: the root) at `t`, directories that existed only through
/// what was under them included: what `Vault::list` returns for the present. The direct
/// children are read in one pass each run of them; a subtree is asked whether it existed
/// (`exists_under`), not listed, and the pass goes on behind it.
pub fn list_at<S: Source>(
    src: &mut S,
    history: &History,
    dir: &str,
    t: u64,
) -> Result<Listing, S::Err> {
    #[derive(Default)]
    struct Child {
        ver: Option<Ver>,
        since: Option<&'static str>,
        is_dir: bool,
        /// Something is at or under the name now.
        live: bool,
        there: Presence,
    }
    let (lo, hi) = subtree(dir);
    let clock = &history.clock;
    let mut children: Vec<(String, Child)> = Vec::new();
    let mut from = lo.clone();
    loop {
        // A run of direct children, up to the first path that lies deeper.
        let mut deeper: Option<(String, bool)> = None;
        src.walk(&from, hi.as_deref(), &mut |group| {
            let rel = &group.path[lo.len()..];
            if let Some((name, _)) = rel.split_once('/') {
                deeper = Some((name.to_owned(), !group.heads.is_empty()));
                return false;
            }
            let child = named(&mut children, rel);
            child.live |= !group.heads.is_empty();
            if let Some((ver, doubt)) = entry_then(clock, group, t) {
                child.is_dir |= !ver.is_file();
                child.since = since_file(ver, group);
                child.ver = Some(ver.clone());
                child.there = Presence::of(doubt);
            }
            true
        })?;
        // The first path under `name/`: the whole subtree is decided here.
        let Some((name, live_first)) = deeper else {
            break;
        };
        let prefix = format!("{lo}{name}");
        let after = format!("{prefix}0");
        let under = exists_under(src, history, &prefix, t)?;
        let child = named(&mut children, &name);
        if under != Presence::No {
            // A folder through what was under it — whatever else was at the name.
            child.there = match child.is_dir {
                true => child.there.max(under),
                false => under,
            };
            child.is_dir = true;
        }
        // (Whether something is at a name now matters only if the name was a folder then.)
        if child.is_dir && !child.live {
            let live = live_first
                || src
                    .heads_from(&format!("{prefix}/"), Some(&after))?
                    .is_some();
            named(&mut children, &name).live = live;
        }
        from = after;
    }
    let rows: Vec<Row> = children
        .into_iter()
        .filter(|(_, child)| child.is_dir || child.ver.is_some())
        .map(|(name, child)| {
            let path = format!("{lo}{name}");
            let approx = child.there == Presence::Maybe;
            match (child.is_dir, child.ver) {
                (true, ver) => Row {
                    // A marker keeps its head, as in a listing of the present.
                    head: ver.filter(|v| !v.is_file()).map(|v| v.head(&path)),
                    approx,
                    ..Row::dir(&name, (!child.live).then_some("deleted"))
                },
                (false, Some(ver)) => Row {
                    since: child.since,
                    approx,
                    ..Row::file(&name, &path, &ver)
                },
                (false, None) => Row::dir(&name, None),
            }
        })
        .collect();
    if !rows.is_empty() || dir.is_empty() {
        return Ok(Listing::Rows(rows));
    }
    // Empty: an empty folder, or no folder at all.
    let group = Cursor::new(src).at(dir)?;
    if entry_at(clock, &group, t).is_some_and(|v| !v.is_file()) {
        return Ok(Listing::Rows(rows));
    }
    let mut nearest = String::new();
    for above in crate::path::ancestors(dir) {
        if dir_at(src, history, above, t)? != Presence::No {
            nearest = above.to_owned();
            break;
        }
    }
    Ok(Listing::Absent { nearest })
}

/// The answer to `list` for an earlier moment: the rows of that moment sorted and cut into a
/// page as in the present, with the moment asked for (`at`, moved into the window) — or, for a
/// folder that was not there, `absent` and the nearest folder above it that was.
pub fn list_answer(
    path: String,
    listing: Listing,
    by: SortOrder,
    offset: usize,
    limit: usize,
    at: u64,
) -> rules::ListJson {
    match listing {
        Listing::Rows(rows) => rules::ListJson {
            at: Some(at),
            ..rules::list_json(path, rows, by, offset, limit)
        },
        Listing::Absent { nearest } => rules::ListJson {
            at: Some(at),
            absent: true,
            nearest: Some(nearest),
            ..rules::list_json(path, Vec::<Row>::new(), by, offset, limit)
        },
    }
}

/// The answer to `search` for an earlier moment.
pub fn search_answer(
    q: String,
    hits: Vec<Row>,
    more: bool,
    by: SortOrder,
    at: u64,
) -> rules::SearchJson {
    rules::SearchJson {
        at: Some(at),
        ..rules::search_json(q, hits, more, by)
    }
}

/// Whether something is at `path` or under it now.
fn live_now<S: Source>(src: &mut S, path: &str) -> Result<bool, S::Err> {
    if src.heads_from(path, Some(&successor(path)))?.is_some() {
        return Ok(true);
    }
    let (lo, hi) = subtree(path);
    Ok(src.heads_from(&lo, hi.as_deref())?.is_some())
}

/// The folder `path` of the moment `t` as a row of `stat` or of a search: whether it is
/// still there now, and whether it surely was there then.
fn dir_row<S: Source>(src: &mut S, path: &str, there: Presence) -> Result<Row, S::Err> {
    let since = (!live_now(src, path)?).then_some("deleted");
    Ok(Row {
        path: Some(path.to_owned()),
        approx: there == Presence::Maybe,
        ..Row::dir(crate::path::file_name(path), since)
    })
}

/// The entry at `path` at `t`, with its path and — a file — the id of its version: a
/// directory if one was there (a marker, or something under it), else the file.
pub fn stat_at<S: Source>(
    src: &mut S,
    history: &History,
    path: &str,
    t: u64,
) -> Result<Option<Row>, S::Err> {
    let group = Cursor::new(src).at(path)?;
    let entry = entry_then(&history.clock, &group, t);
    let marker = match entry {
        Some((ver, doubt)) if !ver.is_file() => Presence::of(doubt),
        _ => Presence::No,
    };
    let there = match marker {
        Presence::Yes => marker,
        _ => marker.max(exists_under(src, history, path, t)?),
    };
    if there != Presence::No {
        return dir_row(src, path, there).map(Some);
    }
    Ok(entry.map(|(ver, doubt)| Row {
        path: Some(path.to_owned()),
        v: Some(id_of(path, ver)),
        since: since_file(ver, &group),
        approx: doubt,
        ..Row::file(crate::path::file_name(path), path, ver)
    }))
}

/// The files and directories that existed at `t` and whose name contains `needle`: what
/// `Vault::search` finds in the present, by the same loop (`rules::search_paths`), over one
/// walk of the heads and the removed versions.
pub fn search_at<S: Source>(
    src: &mut S,
    history: &History,
    needle: &str,
    limit: usize,
    t: u64,
) -> Result<(Vec<Row>, bool), S::Err> {
    let mut search = rules::NameSearch::new(needle, limit);
    if !search.idle() {
        // Files of one upload follow each other and share a segment: its time is looked up
        // once.
        let mut last: Option<((u64, DeviceId), u64)> = None;
        src.walk("", None, &mut |group| {
            let there = match (group.removed.is_empty(), group.heads.as_slice()) {
                // Nothing was ever superseded at this path, and it has one head: it is there
                // from its segment's time on.
                (true, [head]) if t != NOW => {
                    let segment = (head.stamp.lamport, head.stamp.device);
                    let born = match last {
                        Some((of, born)) if of == segment => born,
                        _ => history.clock.at(&head.stamp).ms,
                    };
                    last = Some((segment, born));
                    (born <= t).then_some(head)
                }
                _ => entry_at(&history.clock, group, t),
            };
            match there {
                Some(ver) => search.feed(&group.path, !ver.is_file()),
                None => true,
            }
        })?;
    }
    let (found, more) = search.finish();
    let mut hits = Vec::with_capacity(found.len());
    for (path, is_dir) in found {
        if is_dir {
            let there = dir_at(src, history, &path, t)?;
            hits.push(dir_row(src, &path, there.max(Presence::Maybe))?);
            continue;
        }
        let group = Cursor::new(src).at(&path)?;
        if let Some((ver, doubt)) = entry_then(&history.clock, &group, t) {
            hits.push(Row {
                since: since_file(ver, &group),
                path: Some(path.clone()),
                approx: doubt,
                ..Row::file(crate::path::file_name(&path), &path, ver)
            });
        }
    }
    Ok((hits, more))
}

// ---------------------------------------------------------------------------------------------
// The versions of one file
// ---------------------------------------------------------------------------------------------

/// The answer to `versions`: the file as it is now (if it is), then the removed versions that
/// are offered, newest removal first — the order of `gclone restore --list`. `t`: the moment
/// the page shows, to mark the version that was there then.
pub fn versions<S: Source>(
    src: &mut S,
    history: &History,
    path: &str,
    t: Option<u64>,
    now_ms: u64,
) -> Result<VersionsJson, S::Err> {
    let from_ms = window_from(now_ms);
    let group = Cursor::new(src).at(path)?;
    let lives = lives(&history.clock, &group);
    let removed = group.removed.len();
    let all: Vec<&Ver> = group.removed.iter().chain(&group.heads).collect();
    // The winner, when it is a file: the current version.
    let current = (!group.heads.is_empty() && all[all.len() - 1].is_file()).then(|| all.len() - 1);
    // Versions that changed nothing but metadata are one row with the version that followed:
    // the version with the superseding stamp and the same content. It is looked up, not
    // searched for (a path may have very many versions), and it is always a later one — a
    // chain of folds ends.
    let mut successors: Vec<(Stamp, [u8; 32], usize)> = (0..removed)
        .chain(current)
        .filter(|i| all[*i].is_file())
        .map(|i| (all[i].stamp, all[i].hash, i))
        .collect();
    order_by(&mut successors, |key| *key);
    let mut written: Vec<(u64, bool, DeviceId)> = all
        .iter()
        .zip(&lives)
        .map(|(ver, life)| (life.born, life.exact, ver.stamp.device))
        .collect();
    let mut folded_into: Vec<Option<usize>> = vec![None; all.len()];
    for i in 0..removed {
        let ver = all[i];
        let Some((by, _)) = ver.end else { continue };
        if !ver.is_file() || by <= ver.stamp {
            continue;
        }
        let k = successors.partition_point(|(stamp, hash, _)| (stamp, hash) < (&by, &ver.hash));
        let Some((stamp, hash, j)) = successors.get(k).copied() else {
            continue;
        };
        if stamp == by && hash == ver.hash && all[j].size == ver.size {
            folded_into[i] = Some(j);
            if written[i].0 <= written[j].0 {
                written[j] = written[i];
            }
        }
    }
    let shown = t.and_then(|t| {
        let at = entry_at(&history.clock, &group, t)?;
        let mut i = all.iter().position(|ver| std::ptr::eq(*ver, at))?;
        while let Some(next) = folded_into[i] {
            i = next;
        }
        Some(i)
    });
    let devices: &S = src;
    let row = |i: usize| {
        let ver = all[i];
        let v = id_of(path, ver);
        let (born, exact, writer) = written[i];
        let kept = born >= from_ms && born > 0;
        VersionJson {
            current: Some(i) == current,
            shown: Some(i) == shown,
            size: ver.size,
            mtime_ms: ver.mtime_ns.div_euclid(1_000_000),
            written_ms: kept.then_some(born),
            written_approx: kept && !exact,
            written_by: device_label(devices, &writer),
            until_ms: lives[i].end,
            by: ver.end.map(|(by, _)| device_label(devices, &by.device)),
            why: ver.end.map(|_| why(&group.removed, &group.heads, i)),
            restore: ver.end.and_then(|_| restore_command(path, &v)),
            v,
        }
    };
    let mut rows = Vec::new();
    let mut more = false;
    let listed = current.into_iter().chain(
        (0..removed)
            .rev()
            .filter(|i| folded_into[*i].is_none() && offered(all[*i], now_ms)),
    );
    for i in listed {
        if rows.len() == VERSIONS_MAX {
            more = true;
            break;
        }
        rows.push(row(i));
    }
    Ok(VersionsJson {
        path: path.to_owned(),
        now_ms,
        from_ms,
        deleted: current.is_none(),
        more,
        versions: rows,
    })
}

/// What an id names among the versions of a path.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    One(Ver),
    /// No version of the path that is offered has this id.
    None,
    /// Two have it (12 digits can collide): neither is served.
    Ambiguous,
}

/// The version of `path` with the id `v`: a file head, or a removed file version inside the
/// window.
pub fn resolve<S: Source>(
    src: &mut S,
    path: &str,
    v: &str,
    now_ms: u64,
) -> Result<Resolved, S::Err> {
    let group = Cursor::new(src).at(path)?;
    let mut found = group
        .heads
        .iter()
        .filter(|ver| ver.is_file())
        .chain(group.removed.iter().filter(|ver| offered(ver, now_ms)))
        .filter(|ver| id_of(path, ver) == v);
    Ok(match (found.next(), found.next()) {
        (Some(ver), None) => Resolved::One(ver.clone()),
        (None, _) => Resolved::None,
        (Some(_), Some(_)) => Resolved::Ambiguous,
    })
}

/// `stat` of one version: the row `stat_at` gives for a file, for the version an id names.
pub fn stat_version<S: Source>(
    src: &mut S,
    path: &str,
    v: &str,
    now_ms: u64,
) -> Result<Option<Row>, S::Err> {
    let Resolved::One(ver) = resolve(src, path, v, now_ms)? else {
        return Ok(None);
    };
    let group = Cursor::new(src).at(path)?;
    Ok(Some(Row {
        path: Some(path.to_owned()),
        v: Some(v.to_owned()),
        since: since_file(&ver, &group),
        ..Row::file(crate::path::file_name(path), path, &ver)
    }))
}

// ---------------------------------------------------------------------------------------------
// What was deleted from a folder
// ---------------------------------------------------------------------------------------------

/// The answer to `deleted`, before it is sorted and cut into pages.
pub struct Deleted {
    /// The folder itself does not exist now.
    pub gone: bool,
    pub rows: Vec<Row>,
}

/// The names that were deleted from `dir` (`""`: the root) and are still kept: a child name
/// with nothing at or under it now, and at least one removed file version inside the window at
/// or under it. `None`: `dir` is no folder now and nothing kept lies under it.
///
/// Walks the removed versions under `dir/` with the jumps of a listing; a name that is live
/// now is skipped whole. No `History`: removal times are recorded.
pub fn deleted<S: Source>(src: &mut S, dir: &str, now_ms: u64) -> Result<Option<Deleted>, S::Err> {
    #[derive(Default)]
    struct Name {
        live: Option<bool>,
        /// The removed versions at the name itself.
        direct: Vec<Ver>,
        /// Under it: files counted, whether rows were left unread, the last removal.
        under: Option<(u64, bool, u64)>,
    }
    let (lo, hi) = subtree(dir);
    let is_dir_now = dir.is_empty()
        || src
            .heads_from(dir, Some(&successor(dir)))?
            .is_some_and(|(_, heads)| {
                heads
                    .iter()
                    .max_by_key(|v| (v.stamp, v.hash))
                    .is_some_and(|v| !v.is_file())
            })
        || src.heads_from(&lo, hi.as_deref())?.is_some();
    let mut names: Vec<(String, Name)> = Vec::new();
    let mut from = lo.clone();
    while let Some((path, mut removed)) = src.removed_from(&from, hi.as_deref())? {
        let rel = &path[lo.len()..];
        let (name, direct) = match rel.split_once('/') {
            Some((name, _)) => (name.to_owned(), false),
            None => (rel.to_owned(), true),
        };
        let child = format!("{lo}{name}");
        let after = format!("{child}0");
        let slot = named(&mut names, &name);
        let live = match slot.live {
            Some(live) => live,
            None => *slot.live.insert(live_now(src, &child)?),
        };
        if direct {
            if !live {
                by_removal(&mut removed);
                slot.direct = removed;
            }
            from = successor(&path);
            continue;
        }
        from = after.clone();
        if live {
            continue;
        }
        // A deleted folder: count the kept files under it and find the last removal. The
        // count stops at a bound; past it, rows are read only until one kept file is found.
        let (mut files, mut read, mut last, mut more) = (0u64, 0usize, 0u64, false);
        let mut next = Some((path, removed));
        while let Some((path, mut removed)) = next {
            read += removed.len();
            by_removal(&mut removed);
            let ends = chain_ends(&removed);
            let kept = removed
                .iter()
                .zip(&ends)
                .filter(|(v, _)| offered(v, now_ms));
            if let Some(end) = kept.map(|(_, end)| *end).max() {
                files += 1;
                last = last.max(end);
            }
            next = src.removed_from(&successor(&path), Some(&after))?;
            if read >= DELETED_ROWS_MAX && files > 0 && next.is_some() {
                more = true;
                break;
            }
        }
        if files > 0 {
            slot.under = Some((files, more, last));
        }
    }
    let mut rows = Vec::new();
    for (name, slot) in names {
        if let Some((files, more, last)) = slot.under {
            rows.push(Row {
                files: Some((files, more)),
                last_end: last,
                ..Row::dir(&name, None)
            });
            continue;
        }
        // A deleted file: its newest version that is offered.
        let group = Group {
            path: format!("{lo}{name}"),
            heads: Vec::new(),
            removed: slot.direct,
        };
        let Some(at) = group.removed.iter().rposition(|v| offered(v, now_ms)) else {
            continue;
        };
        let ver = &group.removed[at];
        let Some((by, removed_ms)) = ver.end else {
            continue;
        };
        // The end the chain gives (`lives`), which the versions list shows as well.
        let end = chain_ends(&group.removed)
            .get(at)
            .copied()
            .unwrap_or(removed_ms);
        rows.push(Row {
            v: Some(id_of(&group.path, ver)),
            gone: Some(GoneJson {
                ms: end,
                by: device_label(src, &by.device),
                why: why(&group.removed, &group.heads, at),
            }),
            last_end: end,
            ..Row::file(&name, &group.path, ver)
        });
    }
    if !is_dir_now && rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(Deleted {
        gone: !is_dir_now,
        rows,
    }))
}

/// The answer to `deleted`: the rows in the order a folder would show them, a page of them,
/// and — for a folder that is gone — the command that brings it back and the moment to see it
/// at.
pub fn deleted_json(
    path: String,
    found: Deleted,
    by: SortOrder,
    offset: usize,
    limit: usize,
) -> DeletedJson {
    let Deleted { gone, rows } = found;
    let last = rows.iter().map(|row| row.last_end).max().unwrap_or(0);
    let order = rules::listing_order(&rows, by.key, by.descending);
    DeletedJson {
        gone,
        sort: by.sort,
        order: by.order,
        total: rows.len(),
        offset,
        entries: order
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|i| rows[i].json())
            .collect(),
        restore: gone.then(|| restore_dir_command(&path)).flatten(),
        as_it_was_ms: (gone && last > 0).then(|| last - 1),
        path,
    }
}

// ---------------------------------------------------------------------------------------------
// The timeline
// ---------------------------------------------------------------------------------------------

/// The moments inside the window at `now_ms`, at most `MOMENTS_MAX` of them: more are merged
/// in neighbouring groups — the earliest time, the sum of the files, the device of the largest
/// member, an estimate only if every member is one.
pub fn timeline<S: Source>(src: &S, history: &History, now_ms: u64) -> TimelineJson {
    let from_ms = window_from(now_ms);
    let inside: Vec<&Moment> = history
        .moments
        .iter()
        .filter(|m| m.ms > from_ms && m.ms <= now_ms)
        .collect();
    let per_group = inside.len().div_ceil(MOMENTS_MAX).max(1);
    let mut devices: Vec<DeviceId> = Vec::new();
    let mut moments = Vec::with_capacity(inside.len().min(MOMENTS_MAX));
    for group in inside.chunks(per_group) {
        let files: u64 = group.iter().map(|m| m.files).sum();
        let mut largest = group[0];
        for m in group {
            if m.files > largest.files {
                largest = m;
            }
        }
        let device = match devices.iter().position(|d| *d == largest.device) {
            Some(at) => at,
            None => {
                devices.push(largest.device);
                devices.len() - 1
            }
        };
        let approx = group.iter().all(|m| m.approx);
        moments.push((group[0].ms, files, device, u8::from(approx)));
    }
    TimelineJson {
        now_ms,
        from_ms,
        devices: devices.iter().map(|id| device_label(src, id)).collect(),
        moments,
    }
}

// ---------------------------------------------------------------------------------------------
// The command that brings a version back
// ---------------------------------------------------------------------------------------------

/// A character that turns the text around it, or sets its direction: a command that holds
/// one does not read as what it is. (The ones the page's `show()` replaces in a name.)
fn turns_text(c: char) -> bool {
    matches!(c, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// `:path` as one word of a command line for sh, bash, zsh and fish: as it is when it holds
/// nothing a shell reads, else in single quotes. `None` — such a name gets no command — for a
/// path with
/// - a control character or a line separator: a pasted line must be one line;
/// - a backslash: inside single quotes sh takes it as it is, and fish as an escape of the
///   quote or the backslash that follows — no quoting reads the same in both;
/// - a character that turns text around: the command would not be shown as it is copied.
fn shell_word(path: &str) -> Option<String> {
    let refused = |c: char| {
        c.is_control() || c == '\\' || c == '\u{2028}' || c == '\u{2029}' || turns_text(c)
    };
    if path.chars().any(refused) {
        return None;
    }
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b);
    if path.bytes().all(plain) {
        return Some(format!(":{path}"));
    }
    Some(format!("':{}'", path.replace('\'', "'\\''")))
}

/// `gclone restore ':PATH' --version @ID`: the command line that restores exactly the version
/// `v` of `path`, whatever was removed since.
pub fn restore_command(path: &str, v: &str) -> Option<String> {
    Some(format!(
        "gclone restore {} --version @{v}",
        shell_word(path)?
    ))
}

/// `gclone restore -r ':DIR'`: every deleted file under a folder.
pub fn restore_dir_command(dir: &str) -> Option<String> {
    Some(format!("gclone restore -r {}", shell_word(dir)?))
}

#[cfg(test)]
#[path = "past_tests.rs"]
mod tests;
