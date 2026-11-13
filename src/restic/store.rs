//! One restic repository on Drive (SPEC §7.6): the ID cache and the six operations of the
//! protocol, generic over the backend.
//!
//! What restic relies on, and what this file therefore guarantees:
//!
//! - **A listing is what Drive says now** (R1): every `list` asks the backend after the call
//!   arrived, and answers with that listing and nothing remembered. It is complete or an error
//!   — an absent repository, a missing or trashed folder are errors, never "empty" (R2, R9).
//! - **A success means stored, verified and listed** (C1, C2): an upload is acknowledged when
//!   its bytes hash to its name, Drive's size and checksum agree, the object is not in the
//!   trash, and a listing shows it — for packs: before the next index or snapshot is
//!   acknowledged. A delete of an index or key is acknowledged when a listing no longer shows
//!   it (C4).
//! - **Trashed means gone** (R8): by Drive's query, by the flag of each listed entry, and by
//!   the set of IDs this process trashed itself — until a listing that started after the trash
//!   omits the ID, or Drive says that the file was restored.
//!
//! The cache maps names to Drive IDs for downloads and deletes. It can be stale after another
//! machine's delete; a trashed file still downloads by ID, and its name is the hash of its
//! bytes, so what is served is right, and what *exists* restic takes from listings.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt as _;
use md5::Digest as _;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::layout::{self, Layout, Resolved, SMALL_TYPES, Tree};
use super::{
    CONFIG_REFUSAL, Error, FileType, HIDDEN_RECHECK, LIST_CONFIRM_POLL, LIST_CONFIRM_POLL_MAX,
    LIST_CONFIRM_WAIT, LIST_FANOUT, Name, OWN_GRACE, Options, RepoName, SHARDS, SMALL_MAX, Target,
    note,
};
use crate::backend::{Backend, ByteStream, Handle, ObjMeta, PutBody};
use crate::consts::PART_SIZE;
use crate::error::BackendError;
use crate::web::rules::{ByteRange, parse_range};

/// What `open` found.
pub enum Opened {
    /// `200`.
    Whole { size: u64, stream: ByteStream },
    /// `206`: `range` of a file of `size` bytes.
    Part {
        size: u64,
        range: Range<u64>,
        stream: ByteStream,
    },
    /// `416`: the range starts at or after the end.
    Unsatisfiable { size: u64 },
}

/// A Drive folder that holds files of the repository.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Slot {
    /// The repository folder: `config`.
    Repo,
    /// keys, locks, snapshots, index (an index into `SMALL_TYPES`).
    Small(usize),
    /// `data/<xx>`.
    Shard(u8),
}

impl Slot {
    const COUNT: usize = 1 + SMALL_TYPES.len() + SHARDS;
    /// `locks/`: its place in [`SMALL_TYPES`] (asserted below).
    const LOCKS: Slot = Slot::Small(1);

    fn of(t: &Target) -> Slot {
        match t {
            Target::Config => Slot::Repo,
            Target::File(FileType::Data, name) => Slot::Shard(name.shard()),
            Target::File(ty, _) => {
                Slot::Small(SMALL_TYPES.iter().position(|s| s == ty).unwrap_or(0))
            }
        }
    }

    fn index(self) -> usize {
        match self {
            Slot::Repo => 0,
            Slot::Small(i) => 1 + i,
            Slot::Shard(s) => 1 + SMALL_TYPES.len() + usize::from(s),
        }
    }

    fn shown(self) -> String {
        match self {
            Slot::Repo => "(the repository folder)".to_string(),
            Slot::Small(i) => SMALL_TYPES[i].dir().to_string(),
            Slot::Shard(s) => format!("data/{}", layout::shard_name(usize::from(s))),
        }
    }

    /// The file a listed object of this folder is, if it is one: names are filtered by the
    /// grammar of the protocol, and a pack is visible only in the folder a download would look
    /// in.
    fn target(self, meta: &ObjMeta) -> Option<Target> {
        if meta.is_folder {
            return None;
        }
        match self {
            Slot::Repo => (meta.name == "config").then_some(Target::Config),
            Slot::Small(i) => Some(Target::File(SMALL_TYPES[i], Name::parse(&meta.name)?)),
            Slot::Shard(s) => {
                let name = Name::parse(&meta.name).filter(|n| n.shard() == s)?;
                Some(Target::File(FileType::Data, name))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Entry {
    id: Handle,
    size: u64,
    md5: Option<[u8; 16]>,
    created_ms: u64,
    /// Shown by the newest installed listing of the folder.
    listed: bool,
    /// `Some`: uploaded by this process, then.
    own_since: Option<Instant>,
}

impl Entry {
    fn of(meta: &ObjMeta) -> Entry {
        Entry {
            id: meta.handle.clone(),
            size: meta.size,
            md5: meta.md5,
            created_ms: meta.created_ms,
            listed: false,
            own_since: None,
        }
    }

    /// The order every machine picks the same object of a name by.
    fn age(&self) -> (u64, &str) {
        (self.created_ms, &self.id.0)
    }
}

#[derive(Default)]
struct Folder {
    /// What the newest installed listing showed (not trashed, named by the grammar), plus this
    /// process's own uploads that no listing has shown yet. Not filtered by `hidden` or
    /// `inflight`: `State::visible` does that.
    objects: HashMap<Target, Vec<Entry>>,
    /// When the newest installed listing started (`Repo::tick`); 0 = none yet.
    listed_seq: u64,
}

/// An upload from the moment its ID is taken until it is committed or cleaned up.
struct Attempt {
    id: Handle,
    cancel: CancellationToken,
    /// A `DELETE` of the name came in: whatever the attempt stored is not wanted.
    deleted: bool,
}

/// An ID this process trashed, or tried to.
struct Hidden {
    slot: Slot,
    /// When the trash was done (`Repo::tick`).
    at: u64,
    /// From when on Drive is asked about the ID, should a listing still show it.
    recheck: Instant,
}

/// What a failed attempt may have left on Drive.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Left {
    Nothing,
    /// An object, perhaps, and not one that was verified.
    Unknown,
    /// The object: stored, verified, in a folder that is not in the trash. Only the
    /// confirmation is missing.
    Stored,
}

struct State {
    layout: Option<Arc<Layout>>,
    /// The stored layout has to be resolved again before it is used.
    stale: bool,
    folders: Vec<Folder>,
    /// Every ID this process trashed, or tried to: invisible, whatever a listing says, for as
    /// long as that can be list lag — until a listing that started after the trash omits the
    /// ID (assumption A2; `install`), or Drive itself says that the file is not in the trash
    /// (someone restored it; `recheck_hidden`). An orphan stays hidden.
    hidden: HashMap<Handle, Hidden>,
    inflight: HashMap<Target, Vec<Attempt>>,
    /// Own packs that no listing has shown yet, by shard.
    unlisted_packs: HashMap<u8, HashSet<Handle>>,
    /// Own packs that were found gone or trashed before a listing showed them.
    lost_packs: HashSet<Handle>,
    /// Counts the times the pack bookkeeping was dropped because the restic runs it belonged
    /// to had ended (`forget_ended_runs`; `--port` only). A pack that was on its way then does not
    /// enter the new bookkeeping.
    run: u64,
    /// Trashed index and key files that a listing may still show: ID and when it was trashed.
    leaving: HashMap<Target, Vec<(Handle, u64)>>,
    /// Unacknowledged uploads that may still be on Drive — a clean-up that failed (hidden), or
    /// an index that is deliberately not taken back (`save`) — trashed by the next delete of
    /// the name.
    orphans: HashMap<Target, Vec<Handle>>,
    /// A `POST config` was refused because another config is there (then): the `DELETE config`
    /// that restic sends after every failed upload is not carried out (`remove`).
    config_refused: Option<Instant>,
    /// `Repo::close` was called: nobody waits for an answer any more.
    closed: bool,
}

impl State {
    fn is_visible(&self, t: &Target, id: &Handle) -> bool {
        !self.hidden.contains_key(id)
            && !self
                .inflight
                .get(t)
                .is_some_and(|attempts| attempts.iter().any(|a| a.id == *id))
    }

    /// The entries of `t` that requests may use: not trashed here, not an uncommitted upload.
    fn visible(&self, t: &Target) -> Vec<Entry> {
        let entries = self.folders[Slot::of(t).index()].objects.get(t);
        let mut found: Vec<Entry> = entries
            .into_iter()
            .flatten()
            .filter(|e| self.is_visible(t, &e.id))
            .cloned()
            .collect();
        found.sort_by(|a, b| a.age().cmp(&b.age()));
        found
    }

    fn forget(&mut self, t: &Target, id: &Handle) {
        let folder = &mut self.folders[Slot::of(t).index()];
        if let Some(entries) = folder.objects.get_mut(t) {
            entries.retain(|e| e.id != *id);
            if entries.is_empty() {
                folder.objects.remove(t);
            }
        }
    }

    fn end_attempt(&mut self, t: &Target, id: &Handle) {
        if let Some(attempts) = self.inflight.get_mut(t) {
            attempts.retain(|a| a.id != *id);
            if attempts.is_empty() {
                self.inflight.remove(t);
            }
        }
    }

    fn clear_caches(&mut self) {
        self.folders.iter_mut().for_each(|f| *f = Folder::default());
        self.unlisted_packs.clear();
        self.lost_packs.clear();
        self.leaving.clear();
    }

    /// `id` of `t` was trashed at `at`, or should have been.
    fn hide(&mut self, t: &Target, id: Handle, at: u64) {
        let hidden = Hidden {
            slot: Slot::of(t),
            at,
            recheck: Instant::now() + HIDDEN_RECHECK,
        };
        self.hidden.insert(id, hidden);
    }

    fn is_orphan(&self, id: &Handle) -> bool {
        self.orphans.values().flatten().any(|o| o == id)
    }

    /// A lock this process created is on Drive, as far as the newest listing of `locks/`
    /// knows: a restic run that writes through this process is still going.
    fn holds_lock(&self) -> bool {
        let locks = &self.folders[Slot::LOCKS.index()].objects;
        locks.iter().any(|(t, entries)| {
            let own = |e: &Entry| e.own_since.is_some() && e.listed && self.is_visible(t, &e.id);
            entries.iter().any(own)
        })
    }

    /// `--port`: the process outlives restic runs, and the pack bookkeeping (C2) must not. A
    /// run that writes packs holds a lock from before its first pack until after its snapshot;
    /// when no lock created through this process is left — removed through it, or no longer
    /// listed — every such run has ended. Packs it left unlisted (it was interrupted before
    /// its index) are nobody's to wait for: another machine may prune them, rightly.
    fn forget_ended_runs(&mut self) {
        if self.holds_lock() {
            return;
        }
        self.unlisted_packs.clear();
        self.lost_packs.clear();
        self.run += 1;
    }
}

const _: () = assert!(matches!(SMALL_TYPES[1], FileType::Locks));

fn differ(a: &Entry, b: &Entry) -> bool {
    a.size != b.size || (a.md5.is_some() && b.md5.is_some() && a.md5 != b.md5)
}

const CANCELLED: &str = "the upload was cancelled";

pub struct Repo<B: Backend> {
    backend: Arc<B>,
    name: RepoName,
    opts: Options,
    state: Mutex<State>,
    /// The uploads that are running (`close` waits for them).
    saves: TaskTracker,
    /// A logical clock: "this listing started after that upload" must not depend on timer
    /// resolution.
    seq: AtomicU64,
    /// One resolution or creation of the tree at a time.
    resolving: tokio::sync::Mutex<()>,
    /// Requests that need a new listing of one folder take turns, so that one listing serves
    /// all that were waiting for it.
    turns: Vec<tokio::sync::Mutex<()>>,
}

impl<B: Backend> Repo<B> {
    pub fn new(backend: Arc<B>, name: RepoName, opts: Options) -> Arc<Self> {
        Arc::new(Repo {
            backend,
            name,
            opts,
            state: Mutex::new(State {
                layout: None,
                stale: false,
                folders: (0..Slot::COUNT).map(|_| Folder::default()).collect(),
                hidden: HashMap::new(),
                inflight: HashMap::new(),
                unlisted_packs: HashMap::new(),
                lost_packs: HashSet::new(),
                run: 0,
                leaving: HashMap::new(),
                orphans: HashMap::new(),
                config_refused: None,
                closed: false,
            }),
            saves: TaskTracker::new(),
            seq: AtomicU64::new(0),
            resolving: tokio::sync::Mutex::new(()),
            turns: (0..Slot::COUNT)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
        })
    }

    pub fn name(&self) -> &RepoName {
        &self.name
    }

    /// The end of the run — the connection is gone, nobody can be told anything any more:
    /// every upload that is not committed is cancelled, and this returns when each has ended
    /// the way a cancelled upload ends (aborted, or its object trashed again; a stored index
    /// stays, `save`). Without it the process would exit between the put of a lock and its
    /// clean-up, and the lock of a restic that was interrupted while it created it would stay.
    /// The caller bounds the wait.
    pub async fn close(&self) {
        {
            let mut st = self.st();
            st.closed = true;
            let attempts = st.inflight.values().flatten();
            attempts.for_each(|attempt| attempt.cancel.cancel());
        }
        self.saves.close();
        self.saves.wait().await;
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tick(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    // -----------------------------------------------------------------------------------------
    // The tree
    // -----------------------------------------------------------------------------------------

    /// The layout: the stored one, or — `fresh`, or none stored — resolved from the top.
    async fn layout(&self, fresh: bool) -> Result<Arc<Layout>, Error> {
        let stored = || {
            let st = self.st();
            st.layout.clone().filter(|_| !st.stale && !fresh)
        };
        if let Some(layout) = stored() {
            return Ok(layout);
        }
        let _one = self.resolving.lock().await;
        if let Some(layout) = stored() {
            return Ok(layout);
        }
        let seq = self.tick();
        match layout::resolve(&*self.backend, &self.name).await {
            Ok(Resolved::Found(layout)) => Ok(self.adopt(layout, seq)),
            Ok(Resolved::Absent) => {
                // Never stored: the next request looks again.
                let mut st = self.st();
                st.layout = None;
                st.clear_caches();
                Err(Error::NoRepo)
            }
            Err(e) => {
                // What the tree is now is not known, or known to be ambiguous: the stored
                // layout is not served from until a resolution succeeds.
                if matches!(e, Error::Layout(_)) {
                    self.drop_layout();
                }
                Err(e)
            }
        }
    }

    /// Stores a resolved layout. Folders that are not the ones the caches were filled from —
    /// renamed, moved, created anew in the Drive UI — take the caches with them.
    fn adopt(&self, layout: Arc<Layout>, seq: u64) -> Arc<Layout> {
        {
            let mut st = self.st();
            if st
                .layout
                .as_ref()
                .is_some_and(|old| !old.same_folders(&layout))
            {
                st.clear_caches();
            }
            st.layout = Some(layout.clone());
            st.stale = false;
        }
        self.install(Slot::Repo, seq, &layout.configs);
        layout
    }

    fn drop_layout(&self) {
        self.st().stale = true;
    }

    /// The folders of the tree — or the error for an incomplete one.
    fn tree<'a>(&self, layout: &'a Layout) -> Result<&'a Tree, Error> {
        layout.tree.as_ref().map_err(|missing| {
            let name = &self.name;
            Error::Layout(match self.st().visible(&Target::Config).is_empty() {
                true => format!(
                    "repository \"{name}\" is incomplete on Drive (no folder {missing}): run \
                     restic init again"
                ),
                false => format!(
                    "repository \"{name}\" has no folder {missing} on Drive; restore it from \
                     the Drive trash in drive.google.com"
                ),
            })
        })
    }

    /// The Drive folder of `slot`; only the repository folder exists without a complete tree.
    fn folder(&self, slot: Slot, layout: &Layout) -> Result<Handle, Error> {
        Ok(match slot {
            Slot::Repo => layout.repo.clone(),
            Slot::Small(i) => self.tree(layout)?.small[i].clone(),
            Slot::Shard(s) => self.tree(layout)?.shards[usize::from(s)].clone(),
        })
    }

    fn folder_gone(&self, slot: Slot) -> Error {
        self.folder_missing(&slot.shown())
    }

    fn folder_missing(&self, shown: &str) -> Error {
        self.drop_layout();
        Error::Layout(format!(
            "folder {shown} of repository \"{}\" is missing or in the Drive trash; restore it in \
             drive.google.com",
            self.name
        ))
    }

    /// `in this run`, or — the listener serves many — `through this listener`.
    fn own_packs(&self) -> &'static str {
        match self.opts.listener {
            true => "through this listener",
            false => "in this run",
        }
    }

    fn lost_pack(&self) -> Error {
        let whose = self.own_packs();
        Error::Layout(format!("a pack uploaded {whose} is no longer on Drive"))
    }

    /// `POST ?create=true`.
    pub async fn create(&self) -> Result<(), Error> {
        let _one = self.resolving.lock().await;
        let seq = self.tick();
        let layout = layout::create(&*self.backend, &self.name).await?;
        self.adopt(layout, seq);
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Listings and the cache
    // -----------------------------------------------------------------------------------------

    /// The untrashed children of a folder of the tree — all of them, or an error. "Not found"
    /// for the folder is never taken for "empty" (R2): the folder is looked at. Gone or in the
    /// trash is the layout error; still there, Drive gave an answer it should not have given,
    /// and the request is one to try again.
    async fn children(&self, folder: &Handle, shown: &str) -> Result<Vec<ObjMeta>, Error> {
        match layout::list_live(&*self.backend, folder).await {
            Err(Error::Backend(BackendError::NotFound)) => {}
            listed => return listed,
        }
        match self.backend.stat(folder).await? {
            Some(meta) if meta.is_folder && !meta.trashed => Err(Error::Unconfirmed(format!(
                "Drive answered \"not found\" to a listing of folder {shown} of repository \
                 \"{}\", which is there",
                self.name
            ))),
            _ => Err(self.folder_missing(shown)),
        }
    }

    /// One listing of a folder, with the moment it started.
    async fn list_folder(&self, slot: Slot, layout: &Layout) -> Result<(u64, Vec<ObjMeta>), Error> {
        let folder = self.folder(slot, layout)?;
        let seq = self.tick();
        let found = self.children(&folder, &slot.shown()).await?;
        self.recheck_hidden(slot, seq, &found).await;
        Ok((seq, found))
    }

    /// Own deletes that a listing still shows [`HIDDEN_RECHECK`] after the trash: list lag
    /// beyond anything assumed, or — the usual reason — someone restored the file from the
    /// Drive trash. Drive is asked about each; a file that is not in the trash is not hidden
    /// any more.
    async fn recheck_hidden(&self, slot: Slot, seq: u64, found: &[ObjMeta]) {
        let now = Instant::now();
        let doubtful: Vec<Handle> = {
            let st = self.st();
            if st.hidden.is_empty() {
                return;
            }
            let due = |id: &&Handle| {
                let hidden = st.hidden.get(*id);
                hidden.is_some_and(|h| h.slot == slot && h.at < seq && now >= h.recheck)
                    && !st.is_orphan(id)
            };
            let shown = found.iter().map(|m| &m.handle);
            shown.filter(due).cloned().collect()
        };
        let mut asked = futures_util::stream::iter(doubtful)
            .map(|id| async move {
                let meta = self.backend.stat(&id).await;
                (id, meta)
            })
            .buffer_unordered(LIST_FANOUT);
        while let Some((id, meta)) = asked.next().await {
            let mut st = self.st();
            match meta {
                Ok(Some(meta)) if !meta.trashed => drop(st.hidden.remove(&id)),
                Ok(_) => {
                    if let Some(hidden) = st.hidden.get_mut(&id) {
                        hidden.recheck = now + HIDDEN_RECHECK;
                    }
                }
                Err(e) => tracing::debug!("restic: cannot look at a removed file again: {e}"),
            }
        }
    }

    /// Makes a listing that started at `seq` the folder's cache — unless a listing that
    /// started later is installed already.
    fn install(&self, slot: Slot, seq: u64, found: &[ObjMeta]) {
        let now = Instant::now();
        let mut st = self.st();
        let st = &mut *st;
        // What this process trashed and a listing that started afterwards omits is gone for
        // everyone (assumption A2): from here on a listing that shows the ID is believed —
        // the file was restored from the trash.
        {
            let listed: HashSet<&Handle> = found.iter().map(|m| &m.handle).collect();
            let orphans = &st.orphans;
            st.hidden.retain(|id, h| {
                h.slot != slot
                    || h.at >= seq
                    || listed.contains(id)
                    || orphans.values().flatten().any(|o| o == id)
            });
        }
        let folder = &mut st.folders[slot.index()];
        if folder.listed_seq > seq {
            return;
        }
        let mut old = std::mem::take(&mut folder.objects);
        let mut shown: HashSet<&Handle> = HashSet::new();
        for meta in found.iter().filter(|m| !m.trashed) {
            let Some(target) = slot.target(meta) else {
                continue;
            };
            shown.insert(&meta.handle);
            let own_since = old
                .get(&target)
                .and_then(|entries| entries.iter().find(|e| e.id == meta.handle))
                .and_then(|e| e.own_since);
            folder.objects.entry(target).or_default().push(Entry {
                listed: true,
                own_since,
                ..Entry::of(meta)
            });
        }
        // An own upload that the listing lacks — it started before the upload was done, or it
        // lags — stays for downloads and deletes. It is never part of a list response.
        for (target, entries) in old.drain() {
            for entry in entries {
                let young = entry
                    .own_since
                    .is_some_and(|since| now.duration_since(since) < OWN_GRACE);
                if young && !shown.contains(&entry.id) {
                    folder.objects.entry(target).or_default().push(Entry {
                        listed: false,
                        ..entry
                    });
                }
            }
        }
        folder.listed_seq = seq;
        if let Slot::Shard(shard) = slot
            && let Some(unlisted) = st.unlisted_packs.get_mut(&shard)
        {
            unlisted.retain(|id| !shown.contains(id));
        }
        // A trashed file that a listing started after the trash no longer shows is gone for
        // everyone (assumption A2).
        for (target, ids) in st.leaving.iter_mut() {
            if Slot::of(target) == slot {
                ids.retain(|(id, trashed_at)| *trashed_at >= seq || shown.contains(id));
            }
        }
        st.leaving.retain(|_, ids| !ids.is_empty());
        if self.opts.listener && slot == Slot::LOCKS {
            st.forget_ended_runs();
        }
    }

    /// Makes sure a listing of `slot` that started after `after` is installed, and says when
    /// the installed one started. Waiters take turns; one listing serves all of them.
    async fn listed_after(&self, slot: Slot, layout: &Layout, after: u64) -> Result<u64, Error> {
        let _turn = self.turns[slot.index()].lock().await;
        let installed = self.st().folders[slot.index()].listed_seq;
        if installed > after {
            return Ok(installed);
        }
        let (seq, found) = self.list_folder(slot, layout).await?;
        self.install(slot, seq, &found);
        Ok(self.st().folders[slot.index()].listed_seq)
    }

    /// Lists `slot` until `done` holds — the first listing at once, then with growing pauses —
    /// for at most `LIST_CONFIRM_WAIT`. Any listing of the folder counts, whoever made it.
    async fn confirm(
        &self,
        slot: Slot,
        layout: &Layout,
        done: impl Fn(&State) -> bool,
    ) -> Result<bool, Error> {
        let deadline = Instant::now() + LIST_CONFIRM_WAIT;
        let mut pause = LIST_CONFIRM_POLL;
        loop {
            let seen = {
                let st = self.st();
                if done(&st) {
                    return Ok(true);
                }
                st.folders[slot.index()].listed_seq
            };
            self.listed_after(slot, layout, seen).await?;
            if done(&self.st()) {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(pause).await;
            pause = (pause * 2).min(LIST_CONFIRM_POLL_MAX);
        }
    }

    /// The object of `t` that every machine picks: the oldest visible one.
    fn canonical(&self, t: &Target) -> Result<Option<Entry>, Error> {
        let found = self.st().visible(t);
        if *t == Target::Config {
            let keys: Vec<layout::ConfigKey<'_>> = found
                .iter()
                .map(|e| (e.size, e.md5, e.created_ms, e.id.0.as_str()))
                .collect();
            let picked = layout::pick_config(&keys, &self.name)?;
            return Ok(picked.map(|at| found[at].clone()));
        }
        let mut found = found.into_iter();
        let Some(first) = found.next() else {
            return Ok(None);
        };
        if found.any(|other| differ(&first, &other)) {
            note(&format!(
                "{}: two objects of this name differ on Drive; the older one is used",
                t.shown()
            ));
        }
        Ok(Some(first))
    }

    /// R4: the cached object, or what a listing that started after this call shows.
    async fn find(&self, layout: &Layout, t: &Target) -> Result<Entry, Error> {
        let arrival = self.tick();
        if let Some(entry) = self.canonical(t)? {
            return Ok(entry);
        }
        self.listed_after(Slot::of(t), layout, arrival).await?;
        self.canonical(t)?.ok_or(Error::NotFound)
    }

    /// What a listing answers to restic: one entry per name, without anything trashed here or
    /// not yet acknowledged.
    fn answer(&self, slot: Slot, found: &[ObjMeta]) -> Vec<(Name, u64)> {
        let mut by_name: HashMap<Name, Entry> = HashMap::new();
        let st = self.st();
        for meta in found.iter().filter(|m| !m.trashed) {
            let Some(target @ Target::File(_, name)) = slot.target(meta) else {
                continue;
            };
            if !st.is_visible(&target, &meta.handle) {
                continue;
            }
            let entry = Entry::of(meta);
            match by_name.get_mut(&name) {
                None => drop(by_name.insert(name, entry)),
                Some(held) => {
                    if differ(held, &entry) {
                        note(&format!(
                            "{}: two objects of this name differ on Drive; the older one is used",
                            target.shown()
                        ));
                    }
                    if entry.age() < held.age() {
                        *held = entry;
                    }
                }
            }
        }
        by_name.into_iter().map(|(n, e)| (n, e.size)).collect()
    }

    /// `GET <type>/`: always from Drive, complete or an error.
    pub async fn list(&self, ty: FileType) -> Result<Vec<(Name, u64)>, Error> {
        let layout = self.layout(false).await?;
        let tree = self.tree(&layout)?;
        let Some(small) = SMALL_TYPES.iter().position(|s| *s == ty) else {
            return self.list_data(&layout, tree).await;
        };
        let slot = Slot::Small(small);
        let (seq, found) = self.list_folder(slot, &layout).await?;
        if found.is_empty() {
            // "Nothing" is also what a trashed or deleted folder lists (R2).
            let folder = self.folder(slot, &layout)?;
            match self.backend.stat(&folder).await? {
                Some(meta) if meta.is_folder && !meta.trashed => {}
                _ => return Err(self.folder_gone(slot)),
            }
        }
        let answer = self.answer(slot, &found);
        self.install(slot, seq, &found);
        Ok(answer)
    }

    /// `GET data/`: all 256 shards, then one listing of `data/` itself, which must still show
    /// every shard folder — that one call covers every shard that listed nothing.
    async fn list_data(&self, layout: &Layout, tree: &Tree) -> Result<Vec<(Name, u64)>, Error> {
        let mut listings = futures_util::stream::iter(0..SHARDS)
            .map(|shard| async move {
                let slot = Slot::Shard(shard as u8);
                let (seq, found) = self.list_folder(slot, layout).await?;
                Ok::<_, Error>((slot, seq, found))
            })
            .buffer_unordered(LIST_FANOUT);
        let mut answer = Vec::new();
        while let Some(listing) = listings.next().await {
            let (slot, seq, found) = listing?;
            answer.extend(self.answer(slot, &found));
            self.install(slot, seq, &found);
        }
        let children = self.children(&tree.data, "data").await?;
        let live: HashSet<&Handle> = children
            .iter()
            .filter(|m| m.is_folder)
            .map(|m| &m.handle)
            .collect();
        let shard_named = |m: &&ObjMeta| {
            m.is_folder && m.name.len() == 2 && crate::util::unhex(&m.name).is_some()
        };
        let complete = tree.shards.iter().all(|shard| live.contains(shard))
            && children.iter().filter(shard_named).count() == SHARDS;
        if !complete {
            self.drop_layout();
            return Err(Error::Layout(format!(
                "the folders under data/ of repository \"{}\" changed on Drive (one is missing, \
                 in the trash, or there twice); restore it in drive.google.com",
                self.name
            )));
        }
        Ok(answer)
    }

    // -----------------------------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------------------------

    /// The size of a file. `HEAD config` is how every restic command starts: it resolves the
    /// tree from the top, so a repository that was replaced under its name is noticed.
    pub async fn head(&self, t: &Target) -> Result<u64, Error> {
        if *t == Target::Config {
            let layout = self.layout(true).await?;
            // No config: 404, also while the folders are incomplete — `restic init` then
            // completes them.
            let config = self.canonical(t)?.ok_or(Error::NotFound)?;
            self.tree(&layout)?;
            return Ok(config.size);
        }
        let layout = self.layout(false).await?;
        self.tree(&layout)?;
        Ok(self.find(&layout, t).await?.size)
    }

    /// A file's bytes, whole or one range of them.
    pub async fn open(&self, t: &Target, range: Option<&str>) -> Result<Opened, Error> {
        let layout = self.layout(false).await?;
        if *t != Target::Config {
            self.tree(&layout)?;
        }
        let mut entry = self.find(&layout, t).await?;
        self.tree(&layout)?;
        let mut retried = false;
        loop {
            let size = entry.size;
            let range = match parse_range(range, size) {
                // An empty file is `200` whatever the header says.
                _ if size == 0 => None,
                ByteRange::Whole => None,
                ByteRange::Part(range) => Some(range),
                ByteRange::Unsatisfiable => return Ok(Opened::Unsatisfiable { size }),
            };
            match self.backend.get(&entry.id, range.clone()).await {
                Ok(stream) => {
                    return Ok(match range {
                        None => Opened::Whole { size, stream },
                        Some(range) => Opened::Part {
                            size,
                            range,
                            stream,
                        },
                    });
                }
                // R5: the object was deleted for good. What is there now?
                Err(BackendError::NotFound) if !retried => {
                    retried = true;
                    self.st().forget(t, &entry.id);
                    let after = self.tick();
                    self.listed_after(Slot::of(t), &layout, after).await?;
                    entry = self.canonical(t)?.ok_or(Error::NotFound)?;
                }
                Err(BackendError::NotFound) => {
                    self.st().forget(t, &entry.id);
                    return Err(Error::NotFound);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Deletes
    // -----------------------------------------------------------------------------------------

    /// Moves every object of that name to the Drive trash; nothing there is a success too.
    pub async fn remove(&self, t: &Target) -> Result<(), Error> {
        let lock = matches!(t, Target::File(FileType::Locks, _));
        if self.opts.append_only && !lock {
            return Err(Error::Forbidden);
        }
        // restic removes a file after every upload of it that failed. After a refused `POST
        // config` that is the config of whoever was first — another `restic init`, whose
        // repository this delete would take away — and nothing of the client's own.
        if *t == Target::Config {
            let refused = self.st().config_refused.take();
            if refused.is_some_and(|at| at.elapsed() < CONFIG_REFUSAL) {
                return Err(Error::ConfigKept);
            }
        }
        let layout = self.layout(false).await?;
        self.tree(&layout)?;
        let slot = Slot::of(t);
        let cached = || {
            let st = self.st();
            st.visible(t).into_iter().map(|e| e.id).collect::<Vec<_>>()
        };
        // An upload of the name that is still on its way is not acknowledged any more, and
        // what it stores is not kept.
        {
            let mut st = self.st();
            for attempt in st.inflight.get_mut(t).into_iter().flatten() {
                attempt.deleted = true;
                attempt.cancel.cancel();
            }
        }
        let mut ids = cached();
        if ids.is_empty() {
            let after = self.tick();
            self.listed_after(slot, &layout, after).await?;
            ids = cached();
        }
        for orphan in self.st().orphans.get(t).into_iter().flatten() {
            if !ids.contains(orphan) {
                ids.push(orphan.clone());
            }
        }
        for id in ids {
            match self.backend.trash(&id).await {
                Ok(()) | Err(BackendError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
            let at = self.tick();
            let mut st = self.st();
            st.hide(t, id.clone(), at);
            st.forget(t, &id);
            if let Some(orphans) = st.orphans.get_mut(t) {
                orphans.retain(|o| *o != id);
            }
            if let Slot::Shard(shard) = slot
                && let Some(unlisted) = st.unlisted_packs.get_mut(&shard)
            {
                unlisted.remove(&id);
            }
            if matches!(t, Target::File(FileType::Index | FileType::Keys, _)) {
                st.leaving.entry(*t).or_default().push((id, at));
            }
        }
        if self.opts.listener && lock {
            self.st().forget_ended_runs();
        }
        // C4: another machine must not find a removed index (it would skip blobs that live only
        // in pruned packs) or a removed key in its next listing.
        let gone = self
            .confirm(slot, &layout, |st| !st.leaving.contains_key(t))
            .await?;
        match gone {
            true => Ok(()),
            false => Err(Error::Unconfirmed(format!(
                "Drive still lists the removed file {}",
                t.shown()
            ))),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Uploads
    // -----------------------------------------------------------------------------------------

    /// Stores a file of `len` bytes. `body` delivers them in pieces of any size and ends by
    /// closing; `cancel` fires when nobody waits for the answer any more. Must be run to its
    /// end (the HTTP layer spawns it): a put is never dropped in mid-flight.
    pub async fn save(
        &self,
        t: &Target,
        len: u64,
        body: mpsc::Receiver<std::io::Result<Bytes>>,
        cancel: CancellationToken,
    ) -> Result<(), Error> {
        let _running = self.saves.token();
        let done = self.store(t, len, body, cancel).await;
        if *t == Target::Config && matches!(done, Err(Error::Exists)) {
            // What restic does next is `DELETE config` (`remove`).
            self.st().config_refused = Some(Instant::now());
            let name = &self.name;
            note(&format!(
                "repository \"{name}\" has another config already — a restic init that ran at \
                 the same time was first — and that one is kept: this upload is refused. A key \
                 file this init wrote stays in gclone-restic/{name}/keys: remove it with restic \
                 key remove (restic key list shows it; if restic reports a damaged config or \
                 key instead, both runs used one password: move the newer file in keys to the \
                 Drive trash)"
            ));
        }
        done
    }

    async fn store(
        &self,
        t: &Target,
        len: u64,
        mut body: mpsc::Receiver<std::io::Result<Bytes>>,
        cancel: CancellationToken,
    ) -> Result<(), Error> {
        let layout = self.layout(false).await?;
        self.tree(&layout)?;
        let slot = Slot::of(t);
        // C2: the packs acknowledged before this request arrived.
        let (run, packs): (u64, Vec<(u8, Handle)>) = {
            let st = self.st();
            let packs = match t {
                Target::File(FileType::Index | FileType::Snapshots, _) => {
                    let all = st.unlisted_packs.iter();
                    all.flat_map(|(shard, ids)| ids.iter().map(|id| (*shard, id.clone())))
                        .collect()
                }
                _ => Vec::new(),
            };
            (st.run, packs)
        };

        // A name that exists already (8.3). Nothing is ever overwritten.
        if *t == Target::Config {
            let after = self.tick();
            self.listed_after(slot, &layout, after).await?;
        }
        loop {
            let present = self.st().visible(t);
            if present.is_empty() {
                break;
            }
            let Some(same) = present.iter().find(|e| e.size == len) else {
                return Err(Error::Exists);
            };
            // The cache may be stale: only what Drive has now can stand in for an upload.
            match self.backend.stat(&same.id).await? {
                Some(meta) if !meta.trashed && !meta.is_folder && meta.size == len => {
                    return self.same_as(t, &meta, len, &mut body).await;
                }
                _ => {
                    // Gone or in the trash: this upload is what takes its place.
                    let mut st = self.st();
                    st.forget(t, &same.id);
                    if let Slot::Shard(shard) = slot
                        && let Some(unlisted) = st.unlisted_packs.get_mut(&shard)
                    {
                        unlisted.remove(&same.id);
                    }
                }
            }
        }

        let id = self.backend.new_ids(1).await?.remove(0);
        let cancel = cancel.child_token();
        {
            let mut st = self.st();
            if st.closed {
                cancel.cancel();
            }
            st.inflight.entry(*t).or_default().push(Attempt {
                id: id.clone(),
                cancel: cancel.clone(),
                deleted: false,
            });
        }
        let folder = self.folder(slot, &layout)?;
        let stored = self
            .upload(
                t, slot, &layout, &folder, &id, len, &mut body, &cancel, packs,
            )
            .await;

        // Commit, or clean up: an upload that is not acknowledged leaves no object — an index
        // excepted, below.
        let (error, left) = match stored {
            Ok(meta) => {
                let mut st = self.st();
                if !cancel.is_cancelled() {
                    st.end_attempt(t, &id);
                    let entries = st.folders[slot.index()].objects.entry(*t).or_default();
                    let now = Some(Instant::now());
                    let listed = match entries.iter_mut().find(|e| e.id == id) {
                        Some(entry) => {
                            entry.own_since = now;
                            entry.listed
                        }
                        None => {
                            entries.push(Entry {
                                own_since: now,
                                ..Entry::of(&meta)
                            });
                            false
                        }
                    };
                    // A pack of a run that ended meanwhile is nobody's to wait for.
                    if let Slot::Shard(shard) = slot
                        && !listed
                        && st.run == run
                    {
                        st.unlisted_packs.entry(shard).or_default().insert(id);
                    }
                    return Ok(());
                }
                (Error::Unconfirmed(CANCELLED.into()), Left::Stored)
            }
            Err(failed) => failed,
        };
        // An index is the one file other machines act on the moment it exists: a backup
        // elsewhere that found it in a listing has left out the blobs it describes, and is
        // told "saved". Once Drive has it, verified, it is therefore not taken back for want
        // of an acknowledgement — restic went away, the connection closed, the confirming
        // listing failed or came too late — only when it must not be trusted (a pack it
        // describes is gone, its folder is in the trash) or when the client asks (`DELETE`,
        // restic's own step before it uploads again).
        let deleted = {
            let st = self.st();
            let attempts = st.inflight.get(t).into_iter().flatten();
            attempts.into_iter().any(|a| a.id == id && a.deleted)
        };
        let keep = left == Left::Stored
            && matches!(t, Target::File(FileType::Index, _))
            && matches!(error, Error::Unconfirmed(_) | Error::Backend(_))
            && !deleted;
        if keep {
            let mut st = self.st();
            st.end_attempt(t, &id);
            st.orphans.entry(*t).or_default().push(id);
            return Err(error);
        }
        if left != Left::Nothing {
            match self.backend.trash(&id).await {
                Ok(()) | Err(BackendError::NotFound) => {}
                Err(e) => {
                    tracing::debug!("restic: cannot trash the unacknowledged {}: {e}", t.shown());
                    self.st().orphans.entry(*t).or_default().push(id.clone());
                }
            }
        }
        let at = self.tick();
        let mut st = self.st();
        st.hide(t, id.clone(), at);
        st.forget(t, &id);
        st.end_attempt(t, &id);
        Err(error)
    }

    /// An identical file is there already: the body only has to be what it claims to be.
    async fn same_as(
        &self,
        t: &Target,
        existing: &ObjMeta,
        len: u64,
        body: &mut mpsc::Receiver<std::io::Result<Bytes>>,
    ) -> Result<(), Error> {
        let keep = *t == Target::Config && existing.md5.is_none() && len <= SMALL_MAX;
        let mut kept = Vec::new();
        let mut hashes = Hashes::default();
        while let Some(chunk) = body.recv().await {
            let chunk = chunk.map_err(|_| Error::BadUpload(BODY_FAILED))?;
            hashes.update(&chunk);
            if keep {
                kept.extend_from_slice(&chunk);
            }
        }
        if hashes.len != len {
            return Err(Error::BadUpload(BODY_LENGTH));
        }
        let (sha, md5) = hashes.finish();
        match (t, existing.md5) {
            (Target::File(_, name), _) if sha != name.0 => Err(Error::BadUpload(BODY_HASH)),
            (_, Some(theirs)) if theirs != md5 => Err(Error::Exists),
            (Target::File(..), _) | (Target::Config, Some(_)) => Ok(()),
            // A config without a checksum from the store: a few hundred bytes to compare.
            (Target::Config, None) if keep => {
                let theirs = crate::backend::get_bounded(&*self.backend, &existing.handle, len);
                match theirs.await? {
                    Some(theirs) if theirs == kept => Ok(()),
                    _ => Err(Error::Exists),
                }
            }
            (Target::Config, None) => Err(Error::Exists),
        }
    }

    /// Hash, put, verify, confirm. `Err((error, left))`: what of `id` may be on Drive now.
    #[allow(clippy::too_many_arguments)]
    async fn upload(
        &self,
        t: &Target,
        slot: Slot,
        layout: &Layout,
        folder: &Handle,
        id: &Handle,
        len: u64,
        body: &mut mpsc::Receiver<std::io::Result<Bytes>>,
        cancel: &CancellationToken,
        packs: Vec<(u8, Handle)>,
    ) -> Result<ObjMeta, (Error, Left)> {
        let name = t.file_name();
        let want = match t {
            Target::File(_, name) => Some(name.0),
            Target::Config => None,
        };
        let (put, md5) = if len <= SMALL_MAX {
            let read = read_small(body, len, want).await;
            let (bytes, md5) = read.map_err(|e| (e, Left::Nothing))?;
            if cancel.is_cancelled() {
                return Err((Error::Unconfirmed(CANCELLED.into()), Left::Nothing));
            }
            let put = self.backend.put(id, folder, &name, PutBody::Small(bytes));
            (put.await, md5)
        } else {
            let (tx, parts) = mpsc::channel(1);
            let stream = PutBody::Stream { total: len, parts };
            let put = self.backend.put(id, folder, &name, stream);
            let (put, pumped) = tokio::join!(put, pump(body, len, want, tx, cancel));
            match (pumped, put) {
                (Ok(md5), put) => (put, md5),
                // The put ended before it had the whole body: its error is the answer. The
                // last part never left, so there is no object.
                (Err(Pumped::PutEnded), Err(e)) => {
                    return Err((self.put_failed(e), Left::Nothing));
                }
                (Err(Pumped::PutEnded), Ok(_)) => {
                    let e = BackendError::Transient("the upload ended before its body".into());
                    return Err((e.into(), Left::Unknown));
                }
                (Err(Pumped::Refused(e)), _) => return Err((e, Left::Nothing)),
            }
        };
        let meta = put.map_err(|e| (self.put_failed(e), Left::Unknown))?;
        if meta.size != len || meta.md5.is_some_and(|theirs| theirs != md5) {
            let text = format!(
                "Drive stored {} differently from what was sent; the copy is trashed",
                t.shown()
            );
            return Err((Error::Integrity(text), Left::Unknown));
        }
        if meta.trashed {
            // Stored, but where no listing will ever show it.
            return Err((self.folder_gone(slot), Left::Unknown));
        }

        let listed = |st: &State| {
            let entries = st.folders[slot.index()].objects.get(t);
            entries.is_some_and(|es| es.iter().any(|e| e.id == *id && e.listed))
        };
        let confirmed = async {
            let own = async {
                match slot {
                    // Packs are confirmed before the next index or snapshot (C2).
                    Slot::Shard(_) => Ok(true),
                    _ => self.confirm(slot, layout, listed).await,
                }
            };
            tokio::try_join!(own, self.confirm_packs(layout, packs))
        };
        let own = tokio::select! {
            done = confirmed => done.map_err(|e| (e, Left::Stored))?.0,
            () = cancel.cancelled() => {
                return Err((Error::Unconfirmed(CANCELLED.into()), Left::Stored));
            }
        };
        if !own {
            let text = format!("Drive does not list the new file {} yet", t.shown());
            return Err((Error::Unconfirmed(text), Left::Stored));
        }
        if *t == Target::Config {
            // A concurrent `restic init` may have put another config: the older one wins.
            let ours = Entry::of(&meta);
            let others = self.st().visible(t);
            if others
                .iter()
                .any(|o| differ(o, &ours) && o.age() < ours.age())
            {
                return Err((Error::Exists, Left::Stored));
            }
        }
        Ok(meta)
    }

    fn put_failed(&self, e: BackendError) -> Error {
        // The folder may be gone: look again before the next request.
        if matches!(e, BackendError::Fatal { .. } | BackendError::NotFound) {
            self.drop_layout();
        }
        e.into()
    }

    /// C2: every pack of `packs` has been shown by a listing of its shard.
    async fn confirm_packs(&self, layout: &Layout, packs: Vec<(u8, Handle)>) -> Result<(), Error> {
        if packs.is_empty() {
            return Ok(());
        }
        if packs
            .iter()
            .any(|(_, id)| self.st().lost_packs.contains(id))
        {
            return Err(self.lost_pack());
        }
        let mut by_shard: HashMap<u8, Vec<Handle>> = HashMap::new();
        for (shard, id) in packs {
            by_shard.entry(shard).or_default().push(id);
        }
        let mut shards = futures_util::stream::iter(by_shard)
            .map(|(shard, ids)| async move {
                let unlisted = |st: &State| -> Vec<Handle> {
                    let set = st.unlisted_packs.get(&shard);
                    let waiting = ids.iter().filter(|id| set.is_some_and(|s| s.contains(*id)));
                    waiting.cloned().collect()
                };
                let slot = Slot::Shard(shard);
                if self
                    .confirm(slot, layout, |st| unlisted(st).is_empty())
                    .await?
                {
                    return Ok(());
                }
                // Not listed in time: slow, or gone?
                let waiting = unlisted(&self.st());
                for id in waiting {
                    match self.backend.stat(&id).await? {
                        Some(meta) if !meta.trashed => {}
                        _ => {
                            self.st().lost_packs.insert(id);
                            return Err(self.lost_pack());
                        }
                    }
                }
                Err(Error::Unconfirmed(format!(
                    "Drive does not list a pack uploaded {} yet",
                    self.own_packs()
                )))
            })
            .buffer_unordered(LIST_FANOUT);
        while let Some(done) = shards.next().await {
            done?;
        }
        Ok(())
    }
}

const BODY_FAILED: &str = "the request body could not be read";
const BODY_LENGTH: &str = "the body does not have the announced length";
const BODY_HASH: &str = "the SHA-256 of the body is not the file's name";

/// SHA-256 (the name), MD5 (what Drive reports) and the length of a body.
#[derive(Default)]
struct Hashes {
    sha: sha2::Sha256,
    md5: md5::Md5,
    len: u64,
}

impl Hashes {
    fn update(&mut self, bytes: &[u8]) {
        self.sha.update(bytes);
        self.md5.update(bytes);
        self.len += bytes.len() as u64;
    }

    fn finish(self) -> ([u8; 32], [u8; 16]) {
        (self.sha.finalize().into(), self.md5.finalize().into())
    }
}

/// A body of at most `SMALL_MAX` bytes, whole and checked.
async fn read_small(
    body: &mut mpsc::Receiver<std::io::Result<Bytes>>,
    len: u64,
    want: Option<[u8; 32]>,
) -> Result<(Bytes, [u8; 16]), Error> {
    let mut buf = BytesMut::with_capacity(len as usize);
    while let Some(chunk) = body.recv().await {
        let chunk = chunk.map_err(|_| Error::BadUpload(BODY_FAILED))?;
        if (buf.len() + chunk.len()) as u64 > len {
            return Err(Error::BadUpload(BODY_LENGTH));
        }
        buf.extend_from_slice(&chunk);
    }
    if buf.len() as u64 != len {
        return Err(Error::BadUpload(BODY_LENGTH));
    }
    let mut hashes = Hashes::default();
    hashes.update(&buf);
    let (sha, md5) = hashes.finish();
    if want.is_some_and(|want| want != sha) {
        return Err(Error::BadUpload(BODY_HASH));
    }
    Ok((buf.freeze(), md5))
}

enum Pumped {
    /// Nothing may be stored: the body is not what it claims to be, or nobody waits any more.
    /// The put was told so in place of its last part.
    Refused(Error),
    /// The put stopped taking parts.
    PutEnded,
}

/// Cuts the body into parts of exactly `PART_SIZE` (the last one shorter) for a resumable
/// upload, hashing as it goes. A part is filled only once the put can take it, so one upload
/// holds two parts at most; and **the last part is withheld** until the body has ended, has the
/// announced length and hashes to the name — otherwise the put gets an error in its place, the
/// session is abandoned and no object appears.
async fn pump(
    body: &mut mpsc::Receiver<std::io::Result<Bytes>>,
    len: u64,
    want: Option<[u8; 32]>,
    parts: mpsc::Sender<std::io::Result<Bytes>>,
    cancel: &CancellationToken,
) -> Result<[u8; 16], Pumped> {
    let mut hashes = Hashes::default();
    let mut carry = Bytes::new();
    loop {
        let permit = parts.reserve().await.map_err(|_| Pumped::PutEnded)?;
        let refuse = |permit: mpsc::Permit<'_, std::io::Result<Bytes>>, e: Error| {
            permit.send(Err(std::io::Error::other(e.to_string())));
            Err(Pumped::Refused(e))
        };
        let size = PART_SIZE.min(len - hashes.len) as usize;
        let mut part = BytesMut::with_capacity(size);
        while part.len() < size {
            if carry.is_empty() {
                let next = tokio::select! {
                    next = body.recv() => next,
                    () = parts.closed() => return Err(Pumped::PutEnded),
                };
                carry = match next {
                    Some(Ok(chunk)) => chunk,
                    Some(Err(_)) => return refuse(permit, Error::BadUpload(BODY_FAILED)),
                    None => return refuse(permit, Error::BadUpload(BODY_LENGTH)),
                };
            }
            let piece = carry.split_to(carry.len().min(size - part.len()));
            hashes.update(&piece);
            part.extend_from_slice(&piece);
        }
        if hashes.len < len {
            permit.send(Ok(part.freeze()));
            continue;
        }
        // The last part: the body has to end here.
        let more = !carry.is_empty() || body.recv().await.is_some();
        if more {
            return refuse(permit, Error::BadUpload(BODY_LENGTH));
        }
        let (sha, md5) = hashes.finish();
        if want.is_some_and(|want| want != sha) {
            return refuse(permit, Error::BadUpload(BODY_HASH));
        }
        if cancel.is_cancelled() {
            return refuse(permit, Error::Unconfirmed(CANCELLED.into()));
        }
        permit.send(Ok(part.freeze()));
        return Ok(md5);
    }
}

#[cfg(test)]
mod tests;
