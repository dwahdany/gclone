//! Unit tests of the store (SPEC §13, "restic": U9–U36), on the in-memory backend.
//!
//! `Stale` is a wrapper that can make a store behave as real Drive is not known to, but may:
//! a listing that still shows what was trashed (with or without the `trashed` flag), a put
//! that takes its time, an object without a checksum.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::backend::{Flaky, MemBackend, OpKind, Quota};
use crate::restic::layout::tests::{file, repo};
use crate::restic::{CONFIG_REFUSAL, HIDDEN_RECHECK};
use crate::test_prng::Prng;

// ---------------------------------------------------------------------------------------------
// Stale: the backend the tests need and the fakes do not have
// ---------------------------------------------------------------------------------------------

/// Where a held call waits: `arrived` gets a permit when the call reaches the gate, the call
/// goes on when `open` has one.
#[derive(Clone)]
struct Gate {
    arrived: Arc<Semaphore>,
    open: Arc<Semaphore>,
}

impl Gate {
    fn new() -> Gate {
        Gate {
            arrived: Arc::new(Semaphore::new(0)),
            open: Arc::new(Semaphore::new(0)),
        }
    }

    async fn pass(&self) {
        self.arrived.add_permits(1);
        self.open.acquire().await.unwrap().forget();
    }

    async fn reached(&self) {
        self.arrived.acquire().await.unwrap().forget();
    }

    fn release(&self) {
        self.open.add_permits(1);
    }
}

#[derive(Default)]
struct Plan {
    /// Listings of these folders answer with an earlier result, this many more times.
    frozen: HashMap<Handle, (u32, Vec<ObjMeta>)>,
    /// IDs that every listing flags as trashed (and still returns).
    flagged: HashSet<Handle>,
    /// The next put of a name waits here, before it reaches the store.
    put_gates: Vec<(String, Gate)>,
    /// The next listing of a folder waits here: `true` before it is made, `false` after.
    list_gates: Vec<(Handle, bool, Gate)>,
    lists: HashMap<Handle, u64>,
    /// Metadata comes without checksums.
    no_md5: bool,
}

struct Stale<B: Backend> {
    inner: B,
    plan: Mutex<Plan>,
}

impl<B: Backend> Stale<B> {
    fn new(inner: B) -> Self {
        Stale {
            inner,
            plan: Mutex::default(),
        }
    }

    fn plan(&self) -> std::sync::MutexGuard<'_, Plan> {
        self.plan.lock().unwrap()
    }

    /// The next `times` listings of `parent` (`u32::MAX`: all) show what it holds now.
    async fn freeze(&self, parent: &Handle, times: u32) {
        let now = self.inner.list(parent).await.unwrap();
        self.plan().frozen.insert(parent.clone(), (times, now));
    }

    fn thaw(&self) {
        self.plan().frozen.clear();
    }

    fn flag_trashed(&self, id: &Handle) {
        self.plan().flagged.insert(id.clone());
    }

    fn hold_put(&self, name: &str) -> Gate {
        let gate = Gate::new();
        self.plan().put_gates.push((name.to_string(), gate.clone()));
        gate
    }

    fn hold_list(&self, parent: &Handle, before: bool) -> Gate {
        let gate = Gate::new();
        let held = (parent.clone(), before, gate.clone());
        self.plan().list_gates.push(held);
        gate
    }

    fn lists(&self, parent: &Handle) -> u64 {
        self.plan().lists.get(parent).copied().unwrap_or(0)
    }

    fn listed_folders(&self) -> HashSet<Handle> {
        self.plan().lists.keys().cloned().collect()
    }

    fn reset_lists(&self) {
        self.plan().lists.clear();
    }

    fn strip_md5(&self, on: bool) {
        self.plan().no_md5 = on;
    }

    fn shape(&self, mut meta: ObjMeta) -> ObjMeta {
        if self.plan().no_md5 {
            meta.md5 = None;
        }
        meta
    }

    async fn listing(&self, parent: &Handle, strict: bool) -> Result<Vec<ObjMeta>, BackendError> {
        let gate = {
            let mut plan = self.plan();
            *plan.lists.entry(parent.clone()).or_default() += 1;
            let at = plan.list_gates.iter().position(|(p, ..)| p == parent);
            at.map(|at| plan.list_gates.remove(at))
        };
        if let Some((_, true, gate)) = &gate {
            gate.pass().await;
        }
        let live = match strict {
            true => self.inner.list_strict(parent).await?,
            false => self.inner.list(parent).await?,
        };
        if let Some((_, false, gate)) = &gate {
            gate.pass().await;
        }
        let mut plan = self.plan();
        let found = match plan.frozen.get_mut(parent) {
            Some((times, earlier)) if *times > 0 => {
                if *times != u32::MAX {
                    *times -= 1;
                }
                earlier.clone()
            }
            _ => live,
        };
        let no_md5 = plan.no_md5;
        Ok(found
            .into_iter()
            .map(|mut m| {
                m.trashed |= plan.flagged.contains(&m.handle);
                if no_md5 {
                    m.md5 = None;
                }
                m
            })
            .collect())
    }
}

impl<B: Backend> Backend for Stale<B> {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.inner.new_ids(n).await
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        self.inner.create_folder(id, parent, name).await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let gate = {
            let mut plan = self.plan();
            let at = plan.put_gates.iter().position(|(n, _)| n == name);
            at.map(|at| plan.put_gates.remove(at).1)
        };
        if let Some(gate) = gate {
            gate.pass().await;
        }
        Ok(self.shape(self.inner.put(id, parent, name, body).await?))
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        self.inner.get(h, range).await
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        Ok(self.inner.stat(h).await?.map(|m| self.shape(m)))
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.listing(parent, false).await
    }

    async fn list_strict(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        self.listing(parent, true).await
    }
    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        self.inner.find_by_name(name).await
    }

    async fn trash(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.trash(h).await
    }

    async fn untrash(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.untrash(h).await
    }

    async fn delete(&self, h: &Handle) -> Result<(), BackendError> {
        self.inner.delete(h).await
    }

    async fn about(&self) -> Result<Quota, BackendError> {
        self.inner.about().await
    }

    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

type Store = Stale<Flaky<MemBackend>>;

struct Lab {
    /// The store itself: "another machine", and the judge.
    mem: MemBackend,
    flaky: Flaky<MemBackend>,
    be: Arc<Store>,
    repo: Arc<Repo<Store>>,
    layout: Arc<Layout>,
}

impl Lab {
    /// An initialised tree (no config) named `r`.
    async fn new() -> Lab {
        Lab::with(Options::default()).await
    }

    async fn with(opts: Options) -> Lab {
        let mem = MemBackend::new();
        let flaky = Flaky::new(mem.clone());
        let be = Arc::new(Stale::new(flaky.clone()));
        let repo = Repo::new(be.clone(), repo("r"), opts);
        repo.create().await.unwrap();
        let layout = repo.st().layout.clone().unwrap();
        Lab {
            mem,
            flaky,
            be,
            repo,
            layout,
        }
    }

    fn tree(&self) -> &Tree {
        self.layout.tree.as_ref().ok().unwrap()
    }

    /// The Drive folder named after `ty`.
    fn dir(&self, ty: FileType) -> &Handle {
        match SMALL_TYPES.iter().position(|small| *small == ty) {
            Some(at) => &self.tree().small[at],
            None => &self.tree().data,
        }
    }

    /// The Drive folder files of `ty` and `name` live in.
    fn folder(&self, t: &Target) -> Handle {
        match t {
            Target::Config => self.layout.repo.clone(),
            Target::File(FileType::Data, name) => {
                self.tree().shards[usize::from(name.shard())].clone()
            }
            Target::File(ty, _) => self.dir(*ty).clone(),
        }
    }

    async fn save(&self, ty: FileType, data: &[u8]) -> Result<Target, Error> {
        let t = target(ty, data);
        self.put(&t, data).await.map(|()| t)
    }

    async fn put(&self, t: &Target, data: &[u8]) -> Result<(), Error> {
        let len = data.len() as u64;
        let cancel = CancellationToken::new();
        self.repo.save(t, len, body(data), cancel).await
    }

    /// As another machine: an object of that name with these bytes.
    async fn plant(&self, t: &Target, data: &[u8]) -> Handle {
        file(&self.mem, &self.folder(t), &t.file_name(), data).await
    }

    /// The untrashed objects of that name in its folder, as the store has them.
    fn live(&self, t: &Target) -> Vec<ObjMeta> {
        let (folder, name) = (self.folder(t), t.file_name());
        let all = self.mem.all_objects().into_iter();
        all.filter(|m| m.parent == folder && m.name == name && !m.trashed)
            .collect()
    }

    async fn read(&self, t: &Target, range: Option<&str>) -> Result<Vec<u8>, Error> {
        match self.repo.open(t, range).await? {
            Opened::Whole { stream, .. } | Opened::Part { stream, .. } => collect(stream).await,
            Opened::Unsatisfiable { .. } => panic!("unsatisfiable"),
        }
    }

    async fn names(&self, ty: FileType) -> Vec<(Name, u64)> {
        let mut found = self.repo.list(ty).await.unwrap();
        found.sort();
        found
    }
}

async fn collect(mut stream: ByteStream) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

fn data(seed: u64, len: usize) -> Vec<u8> {
    Prng::new(seed).bytes(len)
}

fn sha(data: &[u8]) -> Name {
    use sha2::Digest as _;
    Name(sha2::Sha256::digest(data).into())
}

fn target(ty: FileType, data: &[u8]) -> Target {
    Target::File(ty, sha(data))
}

/// A complete request body, in pieces of 100 kB.
fn body(data: &[u8]) -> mpsc::Receiver<std::io::Result<Bytes>> {
    let chunks: Vec<&[u8]> = data.chunks(100_000).collect();
    let (tx, rx) = mpsc::channel(chunks.len().max(1));
    for chunk in chunks {
        tx.try_send(Ok(Bytes::copy_from_slice(chunk))).unwrap();
    }
    rx
}

const SMALL: [FileType; 4] = [
    FileType::Keys,
    FileType::Locks,
    FileType::Snapshots,
    FileType::Index,
];

fn status(e: &Error, listing: bool) -> u16 {
    crate::restic::proto::status(e, listing).as_u16()
}

// ---------------------------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------------------------

/// U9.
#[tokio::test(start_paused = true)]
async fn config_and_tree() {
    let lab = Lab::new().await;
    let (repo, config) = (&lab.repo, Target::Config);

    // A complete tree without a config serves: restic init lists and uploads its key first.
    assert!(matches!(repo.head(&config).await, Err(Error::NotFound)));
    assert!(lab.names(FileType::Keys).await.is_empty());
    let key = lab.save(FileType::Keys, b"a key").await.unwrap();
    assert_eq!(lab.read(&key, None).await.unwrap(), b"a key");

    // An interrupted init: no config, a folder missing. `HEAD config` still says "no
    // repository here" (so that init can run again); everything else is an explicit error.
    lab.mem.trash(&lab.tree().shards[7]).await.unwrap();
    assert!(matches!(repo.head(&config).await, Err(Error::NotFound)));
    let Err(Error::Layout(text)) = repo.list(FileType::Keys).await else {
        panic!("an incomplete tree listed");
    };
    assert!(
        text.contains("no folder data/07") && text.contains("restic init"),
        "{text}"
    );
    assert!(matches!(
        repo.open(&config, None).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(repo.remove(&key).await, Err(Error::Layout(_))));
    assert!(matches!(
        lab.put(&config, b"cfg").await,
        Err(Error::Layout(_))
    ));

    // A config and a missing folder: both are errors, and the text says what to do.
    lab.plant(&config, b"the config").await;
    for failed in [
        repo.head(&config).await.map(|_| ()),
        repo.list(FileType::Locks).await.map(|_| ()),
        repo.open(&config, None).await.map(|_| ()),
    ] {
        let Err(Error::Layout(text)) = failed else {
            panic!("a broken repository answered");
        };
        assert!(text.contains("restore it from the Drive trash"), "{text}");
        assert_eq!(status(&Error::Layout(text), true), 403);
    }

    // `create` completes the tree; the config is served.
    repo.create().await.unwrap();
    assert_eq!(repo.head(&config).await.unwrap(), 10);
    assert_eq!(
        lab.read(&config, Some("bytes=0-")).await.unwrap(),
        b"the config"
    );
}

/// U32, and R3: `HEAD config` resolves from the top, and other folders mean other caches.
#[tokio::test(start_paused = true)]
async fn another_repository_under_the_name() {
    let lab = Lab::new().await;
    lab.put(&Target::Config, b"old config").await.unwrap();
    let lock = lab.save(FileType::Locks, b"old lock").await.unwrap();
    let pack = lab.save(FileType::Data, b"old pack").await.unwrap();
    assert_eq!(lab.repo.head(&Target::Config).await.unwrap(), 10);

    // In the Drive UI the folder is renamed, and another machine creates the name anew.
    assert!(lab.mem.rename(&lab.layout.repo, "r-old"));
    let fresh = layout::create(&lab.mem, &repo("r")).await.unwrap();
    file(&lab.mem, &fresh.repo, "config", b"new").await;

    // Without a HEAD config the old folders are still what is served …
    assert_eq!(lab.read(&lock, None).await.unwrap(), b"old lock");
    // … the next command starts with one, and nothing of the old repository is left.
    assert_eq!(lab.repo.head(&Target::Config).await.unwrap(), 3);
    assert_eq!(lab.read(&Target::Config, None).await.unwrap(), b"new");
    assert!(matches!(lab.read(&lock, None).await, Err(Error::NotFound)));
    assert!(matches!(lab.read(&pack, None).await, Err(Error::NotFound)));
    assert!(lab.names(FileType::Locks).await.is_empty());
    assert!(lab.repo.st().unlisted_packs.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------------------------

/// U10: listings always hit the backend, and show what another machine did meanwhile.
#[tokio::test(start_paused = true)]
async fn listings_are_never_served_from_memory() {
    let lab = Lab::new().await;
    for ty in SMALL {
        let folder = lab.dir(ty).clone();
        let own = lab.save(ty, &data(1, 300)).await.unwrap();
        let Target::File(_, own_name) = own else {
            unreachable!()
        };
        lab.be.reset_lists();
        assert_eq!(lab.names(ty).await, vec![(own_name, 300)]);
        assert_eq!(lab.be.lists(&folder), 1);
        // Another machine adds a file and removes ours.
        let theirs = data(2, 400);
        lab.plant(&target(ty, &theirs), &theirs).await;
        lab.mem.trash(&lab.live(&own)[0].handle).await.unwrap();
        assert_eq!(lab.names(ty).await, vec![(sha(&theirs), 400)]);
        assert_eq!(lab.be.lists(&folder), 2, "{ty:?}");
    }
    // Packs: every shard, every time.
    let pack = data(3, 500);
    lab.plant(&target(FileType::Data, &pack), &pack).await;
    for _ in 0..2 {
        let before = lab.mem.counters().list;
        assert_eq!(lab.names(FileType::Data).await, vec![(sha(&pack), 500)]);
        assert_eq!(lab.mem.counters().list - before, 257);
    }
    // A failing listing is an error, never a short list.
    lab.flaky
        .fail_nth(OpKind::List, 100, || BackendError::RateLimited);
    let failed = lab.repo.list(FileType::Data).await;
    assert!(matches!(
        failed,
        Err(Error::Backend(BackendError::RateLimited))
    ));
}

/// U11: "nothing" is checked before it is believed.
#[tokio::test(start_paused = true)]
async fn an_empty_listing_needs_a_living_folder() {
    let lab = Lab::new().await;
    let before = lab.mem.counters().stat;
    assert!(lab.names(FileType::Snapshots).await.is_empty());
    assert_eq!(lab.mem.counters().stat - before, 1);
    // A listing with something in it needs no second look.
    lab.save(FileType::Snapshots, b"snap").await.unwrap();
    let before = lab.mem.counters().stat;
    assert_eq!(lab.names(FileType::Snapshots).await.len(), 1);
    assert_eq!(lab.mem.counters().stat, before);

    // The folder goes to the trash: what it held is not "nothing".
    lab.mem.trash(lab.dir(FileType::Snapshots)).await.unwrap();
    let Err(e @ Error::Layout(_)) = lab.repo.list(FileType::Snapshots).await else {
        panic!("a trashed folder listed as empty");
    };
    assert!(
        e.to_string()
            .contains("folder snapshots of repository \"r\""),
        "{e}"
    );
    assert_eq!(status(&e, true), 403);
    // And again, now through a new resolution.
    assert!(matches!(
        lab.repo.list(FileType::Snapshots).await,
        Err(Error::Layout(_))
    ));

    // A shard folder trashed by another machine: `GET data/` fails as a whole.
    let lab = Lab::new().await;
    assert!(lab.names(FileType::Data).await.is_empty());
    lab.mem.trash(&lab.tree().shards[0xc4]).await.unwrap();
    assert!(matches!(
        lab.repo.list(FileType::Data).await,
        Err(Error::Layout(_))
    ));
    // A second folder of a shard's name is no better.
    let lab = Lab::new().await;
    crate::restic::layout::tests::folder(&lab.mem, &lab.tree().data, "c4").await;
    assert!(matches!(
        lab.repo.list(FileType::Data).await,
        Err(Error::Layout(_))
    ));
    assert!(matches!(
        lab.repo.list(FileType::Keys).await,
        Err(Error::Layout(_))
    ));
}

/// U12: a repository that vanished is an error on the first listing and on every retry.
#[tokio::test(start_paused = true)]
async fn absent_is_never_empty() {
    let lab = Lab::new().await;
    lab.save(FileType::Snapshots, b"snap").await.unwrap();
    lab.mem.trash(&lab.layout.repo).await.unwrap();
    for ty in [FileType::Snapshots, FileType::Data, FileType::Index] {
        for attempt in 0..3 {
            let Err(e) = lab.repo.list(ty).await else {
                panic!("{ty:?} listed after the repository was trashed (attempt {attempt})");
            };
            assert_eq!(status(&e, true), 403, "{e:?}");
        }
    }
    // For a file the same state is "no such repository".
    let e = lab.repo.head(&Target::Config).await.unwrap_err();
    assert!(matches!(e, Error::NoRepo));
    assert_eq!(status(&e, false), 404);
    // A repository that never existed.
    let be = Arc::new(Stale::new(Flaky::new(MemBackend::new())));
    let never = Repo::new(be, repo("never"), Options::default());
    for _ in 0..2 {
        assert!(matches!(
            never.list(FileType::Keys).await,
            Err(Error::NoRepo)
        ));
    }
    assert!(matches!(
        never.open(&target(FileType::Keys, b"x"), None).await,
        Err(Error::NoRepo)
    ));
}

/// U13: Drive allows two objects of one name.
#[tokio::test(start_paused = true)]
async fn duplicate_names_are_one_file() {
    let lab = Lab::new().await;
    let pack = data(4, 1000);
    let t = target(FileType::Data, &pack);
    let Target::File(_, name) = t else {
        unreachable!()
    };
    let first = lab.plant(&t, &pack).await;
    lab.mem.advance_ms(1000);
    lab.plant(&t, &pack).await;
    assert_eq!(lab.names(FileType::Data).await, vec![(name, 1000)]);
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);

    // A copy of another size (a leftover of some other tool): the older object is the file.
    lab.mem.advance_ms(1000);
    lab.plant(&t, b"short").await;
    assert_eq!(lab.names(FileType::Data).await, vec![(name, 1000)]);
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    assert_eq!(lab.repo.canonical(&t).unwrap().unwrap().id, first);

    // A delete removes them all.
    lab.repo.remove(&t).await.unwrap();
    assert!(lab.live(&t).is_empty());
    assert!(lab.names(FileType::Data).await.is_empty());

    // A pack in a folder its name does not belong to is not there.
    let stray = data(5, 100);
    let wrong = (usize::from(sha(&stray).shard()) + 1) % SHARDS;
    file(
        &lab.mem,
        &lab.tree().shards[wrong],
        &sha(&stray).hex(),
        &stray,
    )
    .await;
    // … nor is anything that is not named like a file of restic.
    file(&lab.mem, lab.dir(FileType::Keys), "notes.txt", b"x").await;
    file(&lab.mem, lab.dir(FileType::Keys), &"A".repeat(64), b"x").await;
    assert!(lab.names(FileType::Data).await.is_empty());
    assert!(lab.names(FileType::Keys).await.is_empty());
    let stray = target(FileType::Data, &stray);
    assert!(matches!(lab.read(&stray, None).await, Err(Error::NotFound)));
}

// ---------------------------------------------------------------------------------------------
// The cache and what other machines do
// ---------------------------------------------------------------------------------------------

/// U14: a file another machine trashed is served until the next listing — its name is the
/// hash of its bytes — and gone after it.
#[tokio::test(start_paused = true)]
async fn a_foreign_trash_shows_with_the_next_listing() {
    let lab = Lab::new().await;
    let pack = data(6, 2000);
    let t = target(FileType::Data, &pack);
    let id = lab.plant(&t, &pack).await;
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    lab.mem.trash(&id).await.unwrap();
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    assert!(lab.names(FileType::Data).await.is_empty());
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
    assert!(matches!(lab.repo.head(&t).await, Err(Error::NotFound)));
}

/// U15: an object deleted for good answers 404 from Drive; a listing then says what is there.
#[tokio::test(start_paused = true)]
async fn a_permanent_delete_leads_to_a_new_listing() {
    let lab = Lab::new().await;
    let pack = data(7, 2000);
    let t = target(FileType::Data, &pack);
    let shard = lab.folder(&t);
    let id = lab.plant(&t, &pack).await;
    assert_eq!(lab.repo.head(&t).await.unwrap(), 2000);
    assert!(lab.mem.hard_delete(&id));
    lab.be.reset_lists();
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
    assert_eq!(lab.be.lists(&shard), 1);

    // Deleted and uploaded again under a new ID: served from the new one.
    let id = lab.plant(&t, &pack).await;
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    assert!(lab.mem.hard_delete(&id));
    lab.plant(&t, &pack).await;
    assert_eq!(
        lab.read(&t, Some("bytes=10-19")).await.unwrap(),
        pack[10..20]
    );
}

/// U16: a miss is answered by a listing that started after the request — one listing for all
/// that were waiting, and a second one for a request that arrived while the first ran.
#[tokio::test(start_paused = true)]
async fn misses_share_a_listing_that_is_new_enough() {
    let lab = Arc::new(Lab::new().await);
    let (x, y) = (data(8, 100), data(9, 100));
    let (tx, ty) = (target(FileType::Keys, &x), target(FileType::Keys, &y));
    let keys = lab.folder(&tx);
    lab.plant(&tx, &x).await;
    lab.be.reset_lists();
    let reads = (0..5).map(|_| lab.read(&tx, None));
    for read in futures_util::future::join_all(reads).await {
        assert_eq!(read.unwrap(), x);
    }
    assert_eq!(lab.be.lists(&keys), 1);
    // Negative results are not remembered (R7): every miss asks.
    assert!(matches!(lab.read(&ty, None).await, Err(Error::NotFound)));
    assert!(matches!(lab.read(&ty, None).await, Err(Error::NotFound)));
    assert_eq!(lab.be.lists(&keys), 3);

    // A listing is made and held; `y` appears; a request for `y` arrives. The held listing
    // does not know `y`, and must not answer for it.
    let z = target(FileType::Keys, b"never there");
    let gate = lab.be.hold_list(&keys, false);
    let first = tokio::spawn({
        let lab = lab.clone();
        async move { lab.read(&z, None).await }
    });
    gate.reached().await;
    lab.plant(&ty, &y).await;
    let second = tokio::spawn({
        let lab = lab.clone();
        async move { lab.read(&ty, None).await }
    });
    tokio::task::yield_now().await;
    gate.release();
    assert!(matches!(first.await.unwrap(), Err(Error::NotFound)));
    assert_eq!(second.await.unwrap().unwrap(), y);
    assert_eq!(lab.be.lists(&keys), 5);
}

/// U17: what this process trashed stays gone, whatever a listing says (R8).
#[tokio::test(start_paused = true)]
async fn own_removals_are_filtered_from_stale_listings() {
    for flagged in [true, false] {
        let lab = Lab::new().await;
        let lock = lab.save(FileType::Locks, b"a lock").await.unwrap();
        let other = lab.save(FileType::Locks, b"another lock").await.unwrap();
        let Target::File(_, other_name) = other else {
            unreachable!()
        };
        let id = lab.live(&lock)[0].handle.clone();
        // From now on Drive's listing is stuck: it shows the lock, removed or not.
        lab.be.freeze(&lab.folder(&lock), u32::MAX).await;
        lab.repo.remove(&lock).await.unwrap();
        assert!(lab.live(&lock).is_empty());
        if flagged {
            lab.be.flag_trashed(&id);
        }
        assert_eq!(lab.names(FileType::Locks).await, vec![(other_name, 12)]);
        assert!(matches!(lab.read(&lock, None).await, Err(Error::NotFound)));
        assert!(matches!(lab.repo.head(&lock).await, Err(Error::NotFound)));
        // An upload of the name is a real upload: the removed object does not stand in.
        lab.be.thaw();
        let puts = lab.mem.counters().put;
        lab.put(&lock, b"a lock").await.unwrap();
        assert_eq!(lab.mem.counters().put, puts + 1);
        assert_eq!(lab.live(&lock).len(), 1);
        assert_ne!(lab.live(&lock)[0].handle, id);
        assert_eq!(lab.names(FileType::Locks).await.len(), 2);
    }
}

/// U18: a removed index or key is acknowledged when a listing no longer shows it (C4).
#[tokio::test(start_paused = true)]
async fn index_and_key_removals_are_confirmed() {
    for ty in [FileType::Index, FileType::Keys] {
        let lab = Lab::new().await;
        let folder = lab.dir(ty).clone();
        let one = lab.save(ty, b"one").await.unwrap();
        // Two more listings still show it.
        lab.be.freeze(&folder, 2).await;
        lab.be.reset_lists();
        lab.repo.remove(&one).await.unwrap();
        assert_eq!(lab.be.lists(&folder), 3, "{ty:?}");

        // Never gone: no acknowledgement — and none for the retry either.
        let two = lab.save(ty, b"two").await.unwrap();
        lab.be.freeze(&folder, u32::MAX).await;
        for _ in 0..2 {
            let started = Instant::now();
            let failed = lab.repo.remove(&two).await;
            let Err(e @ Error::Unconfirmed(_)) = failed else {
                panic!("acknowledged a removal that is still listed");
            };
            assert_eq!(status(&e, false), 503);
            assert!(
                e.to_string().contains("Drive still lists the removed file"),
                "{e}"
            );
            assert!(started.elapsed() >= LIST_CONFIRM_WAIT);
        }
        assert!(lab.live(&two).is_empty(), "it is in the trash all the same");
        lab.be.thaw();
        lab.repo.remove(&two).await.unwrap();
    }

    // Five removals at once wait for the same listings.
    let lab = Arc::new(Lab::new().await);
    let folder = lab.dir(FileType::Index).clone();
    let mut files = Vec::new();
    for i in 0..5u8 {
        files.push(lab.save(FileType::Index, &[i; 40]).await.unwrap());
    }
    lab.be.reset_lists();
    let gate = lab.be.hold_list(&folder, true);
    let all = tokio::spawn({
        let (lab, files) = (lab.clone(), files.clone());
        async move {
            let removals = files.iter().map(|t| lab.repo.remove(t));
            futures_util::future::join_all(removals).await
        }
    });
    gate.reached().await;
    tokio::task::yield_now().await;
    gate.release();
    for done in all.await.unwrap() {
        done.unwrap();
    }
    assert_eq!(lab.be.lists(&folder), 2);

    // Locks, snapshots and packs are not confirmed: no listing at all.
    for ty in [FileType::Locks, FileType::Snapshots, FileType::Data] {
        let t = lab.save(ty, b"something").await.unwrap();
        lab.be.reset_lists();
        lab.repo.remove(&t).await.unwrap();
        assert!(lab.be.listed_folders().is_empty(), "{ty:?}");
        assert!(lab.live(&t).is_empty());
    }
}

/// U30.
#[tokio::test(start_paused = true)]
async fn removing_what_is_not_there() {
    let lab = Lab::new().await;
    let t = target(FileType::Snapshots, b"never uploaded");
    lab.be.reset_lists();
    let trashes = lab.mem.counters().trash;
    lab.repo.remove(&t).await.unwrap();
    assert_eq!(lab.be.lists(&lab.folder(&t)), 1);
    assert_eq!(lab.mem.counters().trash, trashes);

    // An upload that failed verification and could not be trashed is an orphan: hidden, and
    // removed with the next delete of its name.
    let snap = data(10, 500);
    let t = target(FileType::Snapshots, &snap);
    lab.flaky.corrupt_md5_next_put();
    lab.flaky
        .fail_next(OpKind::Trash, 1, || BackendError::RateLimited);
    assert!(matches!(lab.put(&t, &snap).await, Err(Error::Integrity(_))));
    assert_eq!(lab.live(&t).len(), 1, "the clean-up failed");
    assert!(lab.names(FileType::Snapshots).await.is_empty());
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
    lab.repo.remove(&t).await.unwrap();
    assert!(lab.live(&t).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------------------------

/// U19.
#[tokio::test(start_paused = true)]
async fn uploads_small_and_streamed() {
    let lab = Lab::new().await;
    for len in [
        0,
        1,
        155,
        SMALL_MAX as usize,
        SMALL_MAX as usize + 1,
        PART_SIZE as usize + 1,
    ] {
        let pack = data(len as u64, len);
        let t = lab.save(FileType::Data, &pack).await.unwrap();
        let [stored] = lab.live(&t).try_into().unwrap();
        assert_eq!(stored.size, len as u64);
        assert_eq!(stored.md5, Some(crate::backend::md5_of(&pack)));
        assert_eq!(lab.mem.read(&stored.handle).unwrap(), pack, "{len} bytes");
        assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    }
    // The fake checks what Drive requires of a resumable upload: parts of exactly PART_SIZE.
    let before = lab.mem.counters().put;
    let pack = data(77, 2 * PART_SIZE as usize + 12345);
    lab.save(FileType::Data, &pack).await.unwrap();
    assert_eq!(lab.mem.counters().put, before + 1);
}

/// U20: a body that is not what its name says leaves no object behind.
#[tokio::test(start_paused = true)]
async fn a_wrong_body_is_refused_before_anything_is_stored() {
    let lab = Lab::new().await;
    let objects = lab.mem.all_objects().len();
    for len in [1000, PART_SIZE as usize + 1000] {
        let pack = data(11, len);
        let wrong = target(FileType::Data, b"something else");
        let failed = lab.put(&wrong, &pack).await;
        assert!(matches!(failed, Err(Error::BadUpload(_))), "{len}");
        assert_eq!(status(&failed.unwrap_err(), false), 400);

        // Shorter and longer than announced.
        let t = target(FileType::Data, &pack);
        for announced in [len as u64 + 1, len as u64 - 1] {
            let cancel = CancellationToken::new();
            let failed = lab.repo.save(&t, announced, body(&pack), cancel).await;
            assert!(
                matches!(failed, Err(Error::BadUpload(_))),
                "{len} as {announced}"
            );
        }
        // A body that fails on the way.
        let (tx, rx) = mpsc::channel(2);
        tx.try_send(Ok(Bytes::copy_from_slice(&pack[..500])))
            .unwrap();
        tx.try_send(Err(std::io::Error::other("reset"))).unwrap();
        let failed = lab
            .repo
            .save(&t, len as u64, rx, CancellationToken::new())
            .await;
        assert!(matches!(failed, Err(Error::BadUpload(_))));
    }
    assert_eq!(
        lab.mem.all_objects().len(),
        objects,
        "not even in the trash"
    );
    assert!(lab.repo.st().inflight.is_empty());
    // The config has no name to check against, but a length.
    let failed = lab
        .repo
        .save(&Target::Config, 9, body(b"short"), CancellationToken::new());
    assert!(matches!(failed.await, Err(Error::BadUpload(_))));
}

/// U21: what Drive says about the stored object is checked.
#[tokio::test(start_paused = true)]
async fn the_stored_object_is_verified() {
    let lab = Lab::new().await;
    let pack = data(12, 3000);
    let t = target(FileType::Data, &pack);
    lab.flaky.corrupt_md5_next_put();
    let failed = lab.put(&t, &pack).await;
    assert!(matches!(failed, Err(Error::Integrity(_))));
    assert_eq!(status(&failed.unwrap_err(), false), 500);
    assert!(lab.live(&t).is_empty(), "the copy is trashed");
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
    lab.put(&t, &pack).await.unwrap();

    // A store that reports no checksum: size and the SHA-256 of the body have to do.
    lab.be.strip_md5(true);
    let other = data(13, 3000);
    lab.save(FileType::Data, &other).await.unwrap();
    lab.save(FileType::Index, &other).await.unwrap();
    lab.be.strip_md5(false);

    // A put into a folder that is in the trash is stored where no listing shows it.
    lab.mem.trash(lab.dir(FileType::Locks)).await.unwrap();
    let failed = lab.save(FileType::Locks, b"lock").await;
    let Err(e @ Error::Layout(_)) = failed else {
        panic!("acknowledged an upload into the trash");
    };
    assert!(e.to_string().contains("folder locks"), "{e}");
    assert_eq!(status(&e, false), 403);
}

/// U22: failed puts leave nothing, and a lost answer leaves one file.
#[tokio::test(start_paused = true)]
async fn failed_uploads_leave_nothing() {
    let lab = Lab::new().await;
    let big = data(14, PART_SIZE as usize + 5);
    let t = target(FileType::Data, &big);
    lab.flaky.cut_next_stream_put(1_000_000);
    let failed = lab.put(&t, &big).await;
    assert!(matches!(
        failed,
        Err(Error::Backend(BackendError::SessionLost))
    ));
    lab.flaky
        .fail_next(OpKind::Put, 1, || BackendError::Transient("x".into()));
    let failed = lab.put(&t, &big).await;
    assert!(matches!(
        failed,
        Err(Error::Backend(BackendError::Transient(_)))
    ));
    // restic's next step is a DELETE, then the POST again.
    lab.repo.remove(&t).await.unwrap();
    assert!(lab.live(&t).is_empty());
    assert!(lab.names(FileType::Data).await.is_empty());

    // Stored, but the answer was lost: the unacknowledged copy is trashed, the retry is the file.
    for pack in [data(15, 700), data(16, PART_SIZE as usize + 700)] {
        let t = target(FileType::Data, &pack);
        lab.flaky.lose_ack_next_put();
        assert!(lab.put(&t, &pack).await.is_err());
        assert!(lab.live(&t).is_empty());
        lab.repo.remove(&t).await.unwrap();
        lab.put(&t, &pack).await.unwrap();
        assert_eq!(lab.live(&t).len(), 1);
        assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    }
    assert_eq!(lab.names(FileType::Data).await.len(), 2);
    assert!(lab.repo.st().inflight.is_empty());
}

/// U23: a small file is acknowledged when a listing shows it (C1).
#[tokio::test(start_paused = true)]
async fn listed_before_acknowledged() {
    let lab = Arc::new(Lab::new().await);
    lab.flaky.set_list_lag_ms(5_000);
    for ty in SMALL {
        let lock = data(17, 155);
        let t = target(ty, &lock);
        let task = tokio::spawn({
            let lab = lab.clone();
            async move { lab.put(&t, &lock).await }
        });
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !task.is_finished(),
            "{ty:?} acknowledged before it was listed"
        );
        assert_eq!(lab.live(&t).len(), 1, "it is stored");
        lab.mem.advance_ms(5_000);
        task.await.unwrap().unwrap();
        // Any other machine sees it now.
        let seen = lab.flaky.list(&lab.folder(&t)).await.unwrap();
        assert!(seen.iter().any(|m| m.name == t.file_name()));
    }

    // Never listed: an error, and the upload is taken back.
    let lock = data(18, 155);
    let t = target(FileType::Locks, &lock);
    let started = Instant::now();
    let failed = lab.put(&t, &lock).await;
    let Err(e @ Error::Unconfirmed(_)) = failed else {
        panic!("acknowledged a lock no listing showed");
    };
    assert_eq!(status(&e, false), 503);
    assert!(started.elapsed() >= LIST_CONFIRM_WAIT);
    assert!(lab.live(&t).is_empty());

    // A pack is not confirmed by a listing of its own.
    lab.be.reset_lists();
    lab.save(FileType::Data, &data(19, 900)).await.unwrap();
    assert!(lab.be.listed_folders().is_empty());
}

/// U24: packs are listed before the index that describes them is acknowledged (C2).
#[tokio::test(start_paused = true)]
async fn packs_before_index() {
    for ty in [FileType::Index, FileType::Snapshots] {
        let lab = Arc::new(Lab::new().await);
        lab.flaky.set_list_lag_ms(5_000);
        let mut packs = Vec::new();
        let mut shards = HashSet::new();
        let mut seed = 100;
        while packs.len() < 3 {
            seed += 1;
            let pack = data(seed, 600);
            if shards.insert(sha(&pack).shard()) {
                packs.push(lab.save(FileType::Data, &pack).await.unwrap());
            }
        }
        lab.be.reset_lists();
        let index = data(20, 300);
        let t = target(ty, &index);
        let task = tokio::spawn({
            let lab = lab.clone();
            async move { lab.put(&t, &index).await }
        });
        tokio::time::sleep(Duration::from_secs(2)).await;
        lab.mem.advance_ms(2_500);
        // A pack that arrives while the index waits is not part of what it waits for.
        let late = loop {
            seed += 1;
            let pack = data(seed, 600);
            if !shards.contains(&sha(&pack).shard()) {
                break lab.save(FileType::Data, &pack).await.unwrap();
            }
        };
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !task.is_finished(),
            "{ty:?} acknowledged before its packs were listed"
        );
        lab.mem.advance_ms(2_500);
        task.await.unwrap().unwrap();
        let late_shard = lab.folder(&late);
        let seen = lab.flaky.list(&late_shard).await.unwrap();
        assert!(seen.is_empty(), "the late pack is still unlisted");
        // Exactly the shards that got a pack were listed, and the file's own folder.
        let mut expected: HashSet<Handle> = packs.iter().map(|p| lab.folder(p)).collect();
        expected.insert(lab.folder(&t));
        assert_eq!(lab.be.listed_folders(), expected);
        assert_eq!(lab.repo.st().unlisted_packs.values().flatten().count(), 1);
    }

    // A pack that vanished before any listing showed it: a permanent error, once after the
    // wait and at once from then on.
    let lab = Lab::new().await;
    lab.flaky.set_list_lag_ms(5_000);
    let pack = lab.save(FileType::Data, &data(21, 600)).await.unwrap();
    lab.mem.trash(&lab.live(&pack)[0].handle).await.unwrap();
    lab.mem.advance_ms(5_000);
    lab.flaky.set_list_lag_ms(0);
    let started = Instant::now();
    let failed = lab.save(FileType::Index, b"index one").await;
    let Err(e @ Error::Layout(_)) = failed else {
        panic!("an index was acknowledged without its pack");
    };
    assert_eq!(status(&e, false), 403);
    assert!(e.to_string().contains("no longer on Drive"));
    assert!(started.elapsed() >= LIST_CONFIRM_WAIT);
    let started = Instant::now();
    let again = lab.save(FileType::Index, b"index two").await;
    assert!(matches!(again, Err(Error::Layout(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        lab.names(FileType::Index).await.is_empty(),
        "both were taken back"
    );

    // A pack this process deleted is not waited for.
    let lab = Lab::new().await;
    lab.flaky.set_list_lag_ms(u64::MAX);
    let pack = lab.save(FileType::Data, &data(22, 600)).await.unwrap();
    lab.repo.remove(&pack).await.unwrap();
    lab.flaky.set_list_lag_ms(0);
    lab.save(FileType::Index, b"index").await.unwrap();
}

/// U25: an upload nobody waits for any more is taken back (8.5).
#[tokio::test(start_paused = true)]
async fn cancelled_uploads_are_taken_back() {
    let lab = Arc::new(Lab::new().await);
    let lock = data(23, 155);
    let t = target(FileType::Locks, &lock);
    let start = |cancel: &CancellationToken| {
        let (lab, lock, cancel) = (lab.clone(), lock.clone(), cancel.clone());
        tokio::spawn(async move { lab.repo.save(&t, 155, body(&lock), cancel).await })
    };

    // Cancelled while the put is on the wire: the put is not dropped; its object is trashed.
    let gate = lab.be.hold_put(&t.file_name());
    let cancel = CancellationToken::new();
    let task = start(&cancel);
    gate.reached().await;
    cancel.cancel();
    assert!(!task.is_finished());
    gate.release();
    assert!(matches!(task.await.unwrap(), Err(Error::Unconfirmed(_))));
    assert_eq!(lab.mem.counters().put, 1, "the put went through");
    assert!(lab.live(&t).is_empty());
    assert!(lab.names(FileType::Locks).await.is_empty());
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));

    // Cancelled while it waits for the confirming listing.
    lab.flaky.set_list_lag_ms(u64::MAX);
    let cancel = CancellationToken::new();
    let task = start(&cancel);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(lab.live(&t).len(), 1);
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(Error::Unconfirmed(_))));
    assert!(lab.live(&t).is_empty());
    lab.flaky.set_list_lag_ms(0);

    // A second upload of the name while the first is cancelled but not cleaned up yet: it
    // uploads for itself, and its object is the one that stays.
    let gate = lab.be.hold_put(&t.file_name());
    let cancel = CancellationToken::new();
    let first = start(&cancel);
    gate.reached().await;
    cancel.cancel();
    let puts = lab.mem.counters().put;
    lab.put(&t, &lock).await.unwrap();
    assert_eq!(lab.mem.counters().put, puts + 1);
    let kept = lab.live(&t)[0].handle.clone();
    gate.release();
    assert!(first.await.unwrap().is_err());
    let [only] = lab.live(&t).try_into().unwrap();
    assert_eq!(only.handle, kept);
    assert_eq!(lab.names(FileType::Locks).await.len(), 1);
    assert_eq!(lab.read(&t, None).await.unwrap(), lock);

    // Cancelled after the commit: the file stays.
    let other = data(24, 155);
    let cancel = CancellationToken::new();
    let t2 = target(FileType::Locks, &other);
    lab.repo
        .save(&t2, 155, body(&other), cancel.clone())
        .await
        .unwrap();
    cancel.cancel();
    assert_eq!(lab.live(&t2).len(), 1);
    assert_eq!(lab.names(FileType::Locks).await.len(), 2);

    // A delete of the name cancels an upload of it that is still on its way.
    let third = data(25, 155);
    let t3 = target(FileType::Locks, &third);
    let gate = lab.be.hold_put(&t3.file_name());
    let task = tokio::spawn({
        let (lab, third) = (lab.clone(), third.clone());
        async move { lab.put(&t3, &third).await }
    });
    gate.reached().await;
    lab.repo.remove(&t3).await.unwrap();
    gate.release();
    assert!(task.await.unwrap().is_err());
    assert!(lab.live(&t3).is_empty());

    // A streamed upload cancelled before its last part left: no object, not even in the trash.
    let objects = lab.mem.all_objects().len();
    let big = data(26, PART_SIZE as usize + 100_000);
    let tb = target(FileType::Data, &big);
    let (tx, rx) = mpsc::channel(1);
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let (lab, cancel, len) = (lab.clone(), cancel.clone(), big.len() as u64);
        async move { lab.repo.save(&tb, len, rx, cancel).await }
    });
    let (head, tail) = big.split_at(PART_SIZE as usize + 50_000);
    tx.send(Ok(Bytes::copy_from_slice(head))).await.unwrap();
    tokio::task::yield_now().await;
    cancel.cancel();
    tx.send(Ok(Bytes::copy_from_slice(tail))).await.unwrap();
    drop(tx);
    assert!(matches!(task.await.unwrap(), Err(Error::Unconfirmed(_))));
    assert_eq!(lab.mem.all_objects().len(), objects);
    assert!(lab.repo.st().inflight.is_empty());
}

/// The end of a run (`Repo::close`): what is in flight is cancelled, and waited for.
#[tokio::test(start_paused = true)]
async fn close_takes_back_what_was_not_acknowledged() {
    // Nothing in flight: at once.
    Lab::new().await.repo.close().await;

    let lab = Arc::new(Lab::new().await);
    let (on_wire, unlisted) = (data(40, 155), data(41, 155));
    let (t1, t2) = (
        target(FileType::Locks, &on_wire),
        target(FileType::Locks, &unlisted),
    );
    let start = |t: Target, lock: Vec<u8>| {
        let lab = lab.clone();
        tokio::spawn(async move { lab.put(&t, &lock).await })
    };
    // One put is on the wire, another upload waits for a listing that never shows it.
    let gate = lab.be.hold_put(&t1.file_name());
    let first = start(t1, on_wire.clone());
    gate.reached().await;
    lab.flaky.set_list_lag_ms(u64::MAX);
    let second = start(t2, unlisted);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(lab.live(&t2).len(), 1, "stored, not acknowledged");

    let closing = tokio::spawn({
        let lab = lab.clone();
        async move { lab.repo.close().await }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(matches!(second.await.unwrap(), Err(Error::Unconfirmed(_))));
    assert!(lab.live(&t2).is_empty());
    assert!(!closing.is_finished(), "a put is not dropped in mid-flight");
    gate.release();
    closing.await.unwrap();
    assert!(matches!(first.await.unwrap(), Err(Error::Unconfirmed(_))));
    assert!(lab.live(&t1).is_empty());
    assert!(lab.repo.st().inflight.is_empty());

    // What arrives afterwards is cancelled before it stores anything.
    let puts = lab.mem.counters().put;
    assert!(matches!(
        lab.put(&t1, &on_wire).await,
        Err(Error::Unconfirmed(_))
    ));
    assert_eq!(lab.mem.counters().put, puts);
}

/// U26: an upload of what is there already writes nothing.
#[tokio::test(start_paused = true)]
async fn an_identical_upload_is_a_success_without_a_write() {
    let lab = Lab::new().await;
    for pack in [data(27, 5000), data(28, PART_SIZE as usize + 9)] {
        let t = lab.save(FileType::Data, &pack).await.unwrap();
        let before = lab.mem.counters();
        lab.put(&t, &pack).await.unwrap();
        let after = lab.mem.counters();
        assert_eq!((after.put, after.stat), (before.put, before.stat + 1));
        assert_eq!(after.new_ids, before.new_ids);
        // The body still has to be the file.
        let mut wrong = pack.clone();
        wrong[17] ^= 1;
        assert!(matches!(
            lab.put(&t, &wrong).await,
            Err(Error::BadUpload(_))
        ));
        assert_eq!(lab.live(&t).len(), 1);

        // Trashed by another machine since: the cache must not turn that into "stored".
        lab.mem.trash(&lab.live(&t)[0].handle).await.unwrap();
        let puts = lab.mem.counters().put;
        lab.put(&t, &pack).await.unwrap();
        assert_eq!(lab.mem.counters().put, puts + 1);
        assert_eq!(lab.live(&t).len(), 1);
    }

    // A name that holds something of another size: refused (rest-server's answer).
    let snap = data(29, 400);
    let t = target(FileType::Snapshots, &snap);
    lab.plant(&t, b"a leftover").await;
    assert_eq!(lab.repo.head(&t).await.unwrap(), 10);
    let failed = lab.put(&t, &snap).await;
    assert!(matches!(failed, Err(Error::Exists)));
    assert_eq!(status(&failed.unwrap_err(), false), 403);
    // restic deletes and retries.
    lab.repo.remove(&t).await.unwrap();
    lab.put(&t, &snap).await.unwrap();

    // The existing object has no checksum: size and the body's SHA-256 decide.
    lab.be.strip_md5(true);
    assert_eq!(lab.names(FileType::Snapshots).await.len(), 1);
    let puts = lab.mem.counters().put;
    lab.put(&t, &snap).await.unwrap();
    assert_eq!(lab.mem.counters().put, puts);
}

/// U27.
#[tokio::test(start_paused = true)]
async fn the_config_file() {
    let lab = Arc::new(Lab::new().await);
    let config = Target::Config;
    lab.flaky.set_list_lag_ms(5_000);
    let task = tokio::spawn({
        let lab = lab.clone();
        async move { lab.put(&Target::Config, b"config one").await }
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!task.is_finished(), "acknowledged before it was listed");
    lab.mem.advance_ms(5_000);
    task.await.unwrap().unwrap();
    lab.flaky.set_list_lag_ms(0);
    assert_eq!(lab.repo.head(&config).await.unwrap(), 10);

    // The same config again: nothing written. Another one: refused, in every mode.
    let puts = lab.mem.counters().put;
    lab.put(&config, b"config one").await.unwrap();
    assert!(matches!(
        lab.put(&config, b"config two").await,
        Err(Error::Exists)
    ));
    assert!(matches!(
        lab.put(&config, b"another config").await,
        Err(Error::Exists)
    ));
    assert_eq!(lab.mem.counters().put, puts);
    // Without a checksum from the store the bytes are compared.
    lab.be.strip_md5(true);
    lab.put(&config, b"config one").await.unwrap();
    assert!(matches!(
        lab.put(&config, b"config two").await,
        Err(Error::Exists)
    ));
    lab.be.strip_md5(false);
    assert_eq!(lab.mem.counters().put, puts);

    // restic removes a file after every upload of it that failed. After a refused config
    // that would be the config of whoever was first: it is not carried out, without a call.
    let before = lab.mem.counters();
    let kept = lab.repo.remove(&config).await.unwrap_err();
    assert!(matches!(kept, Error::ConfigKept), "{kept:?}");
    assert_eq!(status(&kept, false), 403);
    let after = lab.mem.counters();
    assert_eq!((after.trash, after.list), (before.trash, before.list));
    assert_eq!(lab.read(&config, None).await.unwrap(), b"config one");
    // It holds for one delete, and not for long: a refusal whose delete never came (restic
    // died in between) does not swallow a delete that is meant.
    assert!(matches!(
        lab.put(&config, b"config two").await,
        Err(Error::Exists)
    ));
    tokio::time::advance(CONFIG_REFUSAL + Duration::from_secs(1)).await;

    // upgrade_repo_v2: delete, then upload another — while a listing still shows the old one.
    lab.be.freeze(&lab.layout.repo, 2).await;
    lab.repo.remove(&config).await.unwrap();
    lab.put(&config, b"config v2").await.unwrap();
    assert_eq!(lab.read(&config, None).await.unwrap(), b"config v2");
    assert_eq!(lab.repo.head(&config).await.unwrap(), 9);

    // A concurrent init elsewhere wrote an older, different config: ours is taken back.
    let lab = Lab::new().await;
    let gate = lab.be.hold_list(&lab.layout.repo, false);
    let lab = Arc::new(lab);
    let task = tokio::spawn({
        let lab = lab.clone();
        async move { lab.put(&Target::Config, b"ours").await }
    });
    gate.reached().await;
    lab.plant(&config, b"theirs!").await;
    lab.mem.advance_ms(10);
    gate.release();
    assert!(matches!(task.await.unwrap(), Err(Error::Exists)));
    let [left] = lab.live(&config).try_into().unwrap();
    assert_eq!(left.size, 7);
    assert_eq!(lab.read(&config, None).await.unwrap(), b"theirs!");
    // What restic does next — `DELETE config`, then `POST config` again, five times over —
    // leaves the first init's repository as it is.
    for _ in 0..5 {
        assert!(matches!(
            lab.repo.remove(&config).await,
            Err(Error::ConfigKept)
        ));
        assert!(matches!(
            lab.put(&config, b"ours").await,
            Err(Error::Exists)
        ));
    }
    assert!(matches!(
        lab.repo.remove(&config).await,
        Err(Error::ConfigKept)
    ));
    let [still] = lab.live(&config).try_into().unwrap();
    assert_eq!(still.handle, left.handle);
    // A delete that follows no refusal is a delete (the second one in a row, here).
    lab.repo.remove(&config).await.unwrap();
    assert!(lab.live(&config).is_empty());
}

/// U28.
#[tokio::test(start_paused = true)]
async fn append_only() {
    let lab = Lab::with(Options {
        append_only: true,
        ..Options::default()
    })
    .await;
    lab.put(&Target::Config, b"config").await.unwrap();
    let mut files = vec![Target::Config];
    for ty in FileType::ALL {
        files.push(lab.save(ty, &data(30, 200)).await.unwrap());
    }
    let before = lab.mem.counters();
    for t in &files {
        let lock = matches!(t, Target::File(FileType::Locks, _));
        match lab.repo.remove(t).await {
            Ok(()) => assert!(lock, "{t:?} was deleted"),
            Err(e) => {
                assert!(matches!(e, Error::Forbidden) && !lock, "{t:?}: {e:?}");
                assert_eq!(status(&e, false), 403);
            }
        }
    }
    let after = lab.mem.counters();
    assert_eq!(after.trash, before.trash + 1, "the lock, and nothing else");
    assert_eq!(after.list, before.list);
    // A name that is not there is refused all the same, without a look at Drive.
    let absent = target(FileType::Data, b"absent");
    assert!(matches!(
        lab.repo.remove(&absent).await,
        Err(Error::Forbidden)
    ));
    assert_eq!(lab.mem.counters().list, before.list);

    // Stored, answer lost, restic's DELETE refused, POST again: this used to be a dead end.
    let snap = data(31, 450);
    let t = target(FileType::Snapshots, &snap);
    lab.flaky.lose_ack_next_put();
    assert!(lab.put(&t, &snap).await.is_err());
    assert!(matches!(lab.repo.remove(&t).await, Err(Error::Forbidden)));
    lab.put(&t, &snap).await.unwrap();
    assert_eq!(lab.live(&t).len(), 1);
    assert_eq!(lab.names(FileType::Snapshots).await.len(), 2);
    // And again: an identical upload of what is there is a success.
    lab.put(&t, &snap).await.unwrap();
    // The tree can still be created.
    lab.repo.create().await.unwrap();
}

/// U29: an own upload that a listing lacks stays usable for a while — never listed, though.
#[tokio::test(start_paused = true)]
async fn own_uploads_survive_a_lagging_listing() {
    let lab = Lab::new().await;
    let pack = data(32, 800);
    let t = target(FileType::Data, &pack);
    let shard = lab.folder(&t);
    // Listings of the shard are stuck before the upload.
    lab.be.freeze(&shard, u32::MAX).await;
    lab.put(&t, &pack).await.unwrap();
    assert!(
        lab.names(FileType::Data).await.is_empty(),
        "no listing showed it"
    );
    assert_eq!(lab.read(&t, None).await.unwrap(), pack);
    assert_eq!(lab.repo.head(&t).await.unwrap(), 800);

    // Past the grace a listing that lacks it is believed.
    tokio::time::advance(OWN_GRACE + Duration::from_secs(1)).await;
    assert_eq!(
        lab.read(&t, None).await.unwrap(),
        pack,
        "until the next listing"
    );
    assert!(lab.names(FileType::Data).await.is_empty());
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
}

/// U31.
#[tokio::test(start_paused = true)]
async fn ranges() {
    let lab = Lab::new().await;
    let pack = data(33, 1000);
    let t = lab.save(FileType::Data, &pack).await.unwrap();
    for (header, expected) in [
        (None, 0..1000),
        (Some("bytes=0-"), 0..1000),
        (Some("bytes=10-"), 10..1000),
        (Some("bytes=10-19"), 10..20),
        (Some("bytes=999-999"), 999..1000),
        // Past the end: truncated, which restic treats as the error it is.
        (Some("bytes=990-1100"), 990..1000),
    ] {
        let opened = lab.repo.open(&t, header).await.unwrap();
        let (size, range, stream) = match opened {
            Opened::Whole { size, stream } => (size, 0..size, stream),
            Opened::Part {
                size,
                range,
                stream,
            } => (size, range, stream),
            Opened::Unsatisfiable { .. } => panic!("{header:?}"),
        };
        assert_eq!((size, range.clone()), (1000, expected), "{header:?}");
        assert_eq!(
            collect(stream).await.unwrap(),
            pack[range.start as usize..range.end as usize]
        );
    }
    for header in ["bytes=1000-", "bytes=1000-1001", "bytes=5000-"] {
        let opened = lab.repo.open(&t, Some(header)).await.unwrap();
        assert!(
            matches!(opened, Opened::Unsatisfiable { size: 1000 }),
            "{header}"
        );
    }
    // An empty file is the whole file, whatever was asked for.
    let empty = lab.save(FileType::Keys, b"").await.unwrap();
    for header in [None, Some("bytes=0-"), Some("bytes=5-9")] {
        let opened = lab.repo.open(&empty, header).await.unwrap();
        assert!(
            matches!(opened, Opened::Whole { size: 0, .. }),
            "{header:?}"
        );
    }
    assert_eq!(lab.repo.head(&empty).await.unwrap(), 0);
}

// ---------------------------------------------------------------------------------------------
// Review of 0.5.0 (SPEC §17.25)
// ---------------------------------------------------------------------------------------------

/// U33: an index that Drive has is not taken back for want of an acknowledgement — another
/// machine may have left out blobs on the strength of it — unless the client deletes it.
#[tokio::test(start_paused = true)]
async fn a_stored_index_is_not_taken_back() {
    let lab = Arc::new(Lab::new().await);
    let start = |t: Target, bytes: &[u8], cancel: &CancellationToken| {
        let (lab, bytes, cancel) = (lab.clone(), bytes.to_vec(), cancel.clone());
        let len = bytes.len() as u64;
        tokio::spawn(async move { lab.repo.save(&t, len, body(&bytes), cancel).await })
    };

    // restic goes away (Ctrl-C, a reset stream) while its index waits for the listing that
    // confirms it. Another machine has listed and read the index meanwhile.
    lab.flaky.set_list_lag_ms(u64::MAX);
    let index = data(50, 300);
    let t = target(FileType::Index, &index);
    let cancel = CancellationToken::new();
    let task = start(t, &index, &cancel);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let [seen] = lab.live(&t).try_into().unwrap();
    assert_eq!(lab.mem.read(&seen.handle).unwrap(), index);
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(Error::Unconfirmed(_))));
    let [left] = lab.live(&t).try_into().unwrap();
    assert_eq!(left.handle, seen.handle, "the index was taken back");
    assert!(lab.repo.st().inflight.is_empty());
    // It is a file of the repository for this process too.
    lab.flaky.set_list_lag_ms(0);
    assert_eq!(lab.names(FileType::Index).await, vec![(sha(&index), 300)]);
    assert_eq!(lab.read(&t, None).await.unwrap(), index);

    // The end of the run: the lock that was not answered goes, the index stays.
    let lab = Arc::new(Lab::new().await);
    lab.flaky.set_list_lag_ms(u64::MAX);
    let (lock, index) = (data(51, 155), data(52, 300));
    let (tl, ti) = (
        target(FileType::Locks, &lock),
        target(FileType::Index, &index),
    );
    let tasks = [(tl, lock), (ti, index)].map(|(t, bytes)| {
        let lab = lab.clone();
        tokio::spawn(async move { lab.put(&t, &bytes).await })
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((lab.live(&tl).len(), lab.live(&ti).len()), (1, 1));
    lab.repo.close().await;
    for task in tasks {
        assert!(matches!(task.await.unwrap(), Err(Error::Unconfirmed(_))));
    }
    assert_eq!((lab.live(&tl).len(), lab.live(&ti).len()), (0, 1));

    // The listing never comes: `503`, and the index stays. restic's next step is a DELETE —
    // which removes it, also while no listing shows it — and the POST again.
    let lab = Lab::new().await;
    lab.flaky.set_list_lag_ms(u64::MAX);
    let index = data(53, 300);
    let t = target(FileType::Index, &index);
    let failed = lab.put(&t, &index).await.unwrap_err();
    assert!(matches!(failed, Error::Unconfirmed(_)), "{failed:?}");
    assert_eq!(status(&failed, false), 503);
    let first = lab.live(&t)[0].handle.clone();
    lab.repo.remove(&t).await.unwrap();
    assert!(lab.live(&t).is_empty());
    lab.flaky.set_list_lag_ms(0);
    lab.put(&t, &index).await.unwrap();
    let [second] = lab.live(&t).try_into().unwrap();
    assert_ne!(second.handle, first);
    assert_eq!(lab.names(FileType::Index).await.len(), 1);

    // The confirming listing fails: the same.
    let other = data(54, 300);
    let t = target(FileType::Index, &other);
    lab.flaky
        .fail_next(OpKind::List, 1, || BackendError::RateLimited);
    let failed = lab.put(&t, &other).await;
    assert!(matches!(
        failed,
        Err(Error::Backend(BackendError::RateLimited))
    ));
    assert_eq!(lab.live(&t).len(), 1);
    // restic uploads it again without a delete (`--append-only` refused that): nothing is
    // written a second time.
    let puts = lab.mem.counters().put;
    assert_eq!(lab.names(FileType::Index).await.len(), 2);
    lab.put(&t, &other).await.unwrap();
    assert_eq!(lab.mem.counters().put, puts);
    assert_eq!(lab.live(&t).len(), 1);

    // What must not be trusted is still taken back: Drive stored something else …
    let bad = data(55, 300);
    let t = target(FileType::Index, &bad);
    lab.flaky.corrupt_md5_next_put();
    assert!(matches!(lab.put(&t, &bad).await, Err(Error::Integrity(_))));
    assert!(lab.live(&t).is_empty());
    // … and so is an index that the client deletes while it is on its way.
    let lab = Arc::new(Lab::new().await);
    let index = data(56, 300);
    let t = target(FileType::Index, &index);
    for held_at_the_put in [true, false] {
        let gate = lab.be.hold_put(&t.file_name());
        if !held_at_the_put {
            gate.release();
            lab.flaky.set_list_lag_ms(u64::MAX);
        }
        let task = tokio::spawn({
            let (lab, index) = (lab.clone(), index.clone());
            async move { lab.put(&t, &index).await }
        });
        match held_at_the_put {
            true => gate.reached().await,
            false => tokio::time::sleep(Duration::from_secs(1)).await,
        }
        let removing = tokio::spawn({
            let lab = lab.clone();
            async move { lab.repo.remove(&t).await }
        });
        tokio::task::yield_now().await;
        gate.release();
        lab.flaky.set_list_lag_ms(0);
        assert!(task.await.unwrap().is_err());
        removing.await.unwrap().unwrap();
        assert!(
            lab.live(&t).is_empty(),
            "held at the put: {held_at_the_put}"
        );
        assert!(lab.names(FileType::Index).await.is_empty());
    }
}

fn unlisted(lab: &Lab) -> usize {
    let st = lab.repo.st();
    st.unlisted_packs.values().map(HashSet::len).sum()
}

/// Uploads a pack that no listing of its shard will show: the listings are stuck before it.
async fn stuck_pack(lab: &Lab, seed: u64) -> Target {
    let pack = data(seed, 600);
    let t = target(FileType::Data, &pack);
    lab.be.freeze(&lab.folder(&t), u32::MAX).await;
    lab.put(&t, &pack).await.unwrap();
    t
}

/// U34: `--port`. What the process remembers about packs ends with the restic run that
/// uploaded them — a run holds a lock, created through this process, for as long as it writes.
#[tokio::test(start_paused = true)]
async fn the_listener_forgets_the_packs_of_a_run_that_ended() {
    let listener = Options {
        listener: true,
        ..Options::default()
    };
    let lab = Arc::new(Lab::with(listener).await);
    let trash = |t: Target| {
        let lab = lab.clone();
        async move { lab.mem.trash(&lab.live(&t)[0].handle).await.unwrap() }
    };

    // A backup: its lock, a pack — and Ctrl-C. restic removes its lock; no index was written.
    let lock = lab.save(FileType::Locks, b"lock one").await.unwrap();
    let pack = stuck_pack(&lab, 60).await;
    assert_eq!(unlisted(&lab), 1);
    lab.repo.remove(&lock).await.unwrap();
    assert_eq!(unlisted(&lab), 0);
    // Another machine prunes: the pack, which no index names, goes to the trash. The next
    // backup through the listener is not held up by it, and does not fail.
    trash(pack).await;
    let lock = lab.save(FileType::Locks, b"lock two").await.unwrap();
    let started = Instant::now();
    lab.save(FileType::Index, b"index two").await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));

    // While the run that uploaded a pack holds its lock, the pack is waited for, and one that
    // vanished fails the run: once after the wait, at once from then on.
    let pack = stuck_pack(&lab, 61).await;
    trash(pack).await;
    let started = Instant::now();
    let failed = lab.save(FileType::Index, b"index three").await;
    let Err(e @ Error::Layout(_)) = failed else {
        panic!("an index was acknowledged without its pack");
    };
    assert_eq!(
        e.to_string(),
        "a pack uploaded through this listener is no longer on Drive"
    );
    assert!(started.elapsed() >= LIST_CONFIRM_WAIT);
    let started = Instant::now();
    let again = lab.save(FileType::Index, b"index four").await;
    assert!(matches!(again, Err(Error::Layout(_))));
    assert!(started.elapsed() < Duration::from_secs(1));
    // restic gives up and removes its lock: the run after it starts clean.
    lab.repo.remove(&lock).await.unwrap();
    let lock = lab.save(FileType::Locks, b"lock three").await.unwrap();
    lab.save(FileType::Index, b"index five").await.unwrap();

    // A killed restic leaves its lock. `restic unlock` on another machine removes it, a prune
    // there the pack; this process learns it from its next listing of `locks/`, with which
    // every restic command begins.
    let pack = stuck_pack(&lab, 62).await;
    trash(lock).await;
    trash(pack).await;
    assert_eq!(unlisted(&lab), 1);
    assert!(lab.names(FileType::Locks).await.is_empty());
    assert_eq!(unlisted(&lab), 0);

    // A pack that was on its way when its run ended does not enter the bookkeeping either.
    let lock = lab.save(FileType::Locks, b"lock four").await.unwrap();
    let late = data(63, 600);
    let tl = target(FileType::Data, &late);
    lab.be.freeze(&lab.folder(&tl), u32::MAX).await;
    let gate = lab.be.hold_put(&tl.file_name());
    let task = tokio::spawn({
        let lab = lab.clone();
        async move { lab.put(&tl, &late).await }
    });
    gate.reached().await;
    lab.repo.remove(&lock).await.unwrap();
    gate.release();
    task.await.unwrap().unwrap();
    assert_eq!(unlisted(&lab), 0);

    // Two runs at once: the packs stay for as long as either holds a lock. A refreshed lock
    // (restic writes the new one before it removes the old one) keeps them as well.
    let a = lab.save(FileType::Locks, b"lock of run a").await.unwrap();
    let b = lab.save(FileType::Locks, b"lock of run b").await.unwrap();
    stuck_pack(&lab, 64).await;
    lab.repo.remove(&a).await.unwrap();
    assert_eq!(unlisted(&lab), 1);
    let b2 = lab
        .save(FileType::Locks, b"lock of run b, new")
        .await
        .unwrap();
    lab.repo.remove(&b).await.unwrap();
    assert_eq!(unlisted(&lab), 1);
    lab.repo.remove(&b2).await.unwrap();
    assert_eq!(unlisted(&lab), 0);

    // `--stdio`: the process is one run. Nothing is forgotten, whatever happens to locks.
    let lab = Lab::new().await;
    let lock = lab.save(FileType::Locks, b"the lock").await.unwrap();
    let pack = stuck_pack(&lab, 65).await;
    lab.repo.remove(&lock).await.unwrap();
    assert!(lab.names(FileType::Locks).await.is_empty());
    assert_eq!(unlisted(&lab), 1);
    lab.mem.trash(&lab.live(&pack)[0].handle).await.unwrap();
    let e = lab.save(FileType::Index, b"index").await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "a pack uploaded in this run is no longer on Drive"
    );
}

/// U35: what this process trashed is hidden for as long as a listing that shows it can be
/// list lag — not for good: a file restored from the Drive trash is a file again.
#[tokio::test(start_paused = true)]
async fn a_file_restored_from_the_trash_is_served_again() {
    let lab = Lab::new().await;
    // A listing that started after the delete omits the file: listings are believed again.
    let snap = data(70, 400);
    let t = lab.save(FileType::Snapshots, &snap).await.unwrap();
    let id = lab.live(&t)[0].handle.clone();
    lab.repo.remove(&t).await.unwrap();
    assert!(lab.repo.st().hidden.contains_key(&id));
    assert!(lab.names(FileType::Snapshots).await.is_empty());
    assert!(lab.repo.st().hidden.is_empty());
    // "Restore" in drive.google.com.
    lab.mem.untrash(&id).await.unwrap();
    assert_eq!(
        lab.names(FileType::Snapshots).await,
        vec![(sha(&snap), 400)]
    );
    assert_eq!(lab.read(&t, None).await.unwrap(), snap);
    assert_eq!(lab.repo.head(&t).await.unwrap(), 400);

    // Restored before any listing omitted it. For HIDDEN_RECHECK a listing that shows the
    // file is taken for list lag …
    let pack = data(71, 900);
    let p = lab.save(FileType::Data, &pack).await.unwrap();
    let id = lab.live(&p)[0].handle.clone();
    lab.repo.remove(&p).await.unwrap();
    lab.mem.untrash(&id).await.unwrap();
    assert!(lab.names(FileType::Data).await.is_empty());
    assert!(matches!(lab.read(&p, None).await, Err(Error::NotFound)));
    // … then Drive is asked, once, and the file is back.
    tokio::time::advance(HIDDEN_RECHECK).await;
    let stats = lab.mem.counters().stat;
    assert_eq!(lab.names(FileType::Data).await, vec![(sha(&pack), 900)]);
    assert_eq!(lab.mem.counters().stat, stats + 1);
    assert_eq!(lab.read(&p, None).await.unwrap(), pack);
    assert_eq!(lab.names(FileType::Data).await.len(), 1);
    assert_eq!(lab.mem.counters().stat, stats + 1);
    assert!(lab.repo.st().hidden.is_empty());

    // Real lag: the listing shows a lock that is in the trash. Drive says so, and the lock
    // stays hidden — asked about once per HIDDEN_RECHECK, not with every listing.
    let lock = lab.save(FileType::Locks, b"a lock").await.unwrap();
    lab.be.freeze(&lab.folder(&lock), u32::MAX).await;
    lab.repo.remove(&lock).await.unwrap();
    tokio::time::advance(HIDDEN_RECHECK).await;
    let stats = lab.mem.counters().stat;
    for _ in 0..3 {
        assert!(lab.names(FileType::Locks).await.is_empty());
        assert!(matches!(lab.read(&lock, None).await, Err(Error::NotFound)));
    }
    assert_eq!(lab.mem.counters().stat, stats + 1);
    lab.be.thaw();
    assert!(lab.names(FileType::Locks).await.is_empty());
    assert!(lab.repo.st().hidden.is_empty());

    // An upload that failed verification and could not be trashed is on Drive, not in the
    // trash, and was never a file of the repository: it stays hidden.
    let bad = data(72, 500);
    let t = target(FileType::Keys, &bad);
    lab.flaky.corrupt_md5_next_put();
    lab.flaky
        .fail_next(OpKind::Trash, 1, || BackendError::RateLimited);
    assert!(matches!(lab.put(&t, &bad).await, Err(Error::Integrity(_))));
    assert_eq!(lab.live(&t).len(), 1);
    tokio::time::advance(HIDDEN_RECHECK * 2).await;
    for _ in 0..2 {
        assert!(lab.names(FileType::Keys).await.is_empty());
    }
    assert!(matches!(lab.read(&t, None).await, Err(Error::NotFound)));
}

/// U36: "not found" for a folder that is there is not "empty" (R2) — on any path that lists.
#[tokio::test(start_paused = true)]
async fn a_listing_the_store_does_not_find_is_not_empty() {
    let lab = Lab::new().await;
    let not_found = || {
        lab.flaky
            .fail_next(OpKind::List, 1, || BackendError::NotFound)
    };
    lab.put(&Target::Config, b"cfg").await.unwrap();
    for ty in FileType::ALL {
        lab.save(ty, &data(80, 500)).await.unwrap();
    }
    for ty in FileType::ALL {
        not_found();
        let Err(e) = lab.repo.list(ty).await else {
            panic!("{ty:?}: one \"not found\" from the store listed as empty");
        };
        assert!(matches!(e, Error::Unconfirmed(_)), "{ty:?}: {e:?}");
        assert_eq!(status(&e, true), 503, "{ty:?}");
        assert!(e.to_string().contains("which is there"), "{e}");
        // restic tries again, and gets the listing.
        assert_eq!(lab.names(ty).await.len(), 1, "{ty:?}");
    }
    // The listing of `data/` itself, after its 256 shards.
    lab.flaky
        .fail_nth(OpKind::List, 257, || BackendError::NotFound);
    let e = lab.repo.list(FileType::Data).await.unwrap_err();
    assert!(matches!(e, Error::Unconfirmed(_)), "{e:?}");
    assert!(e.to_string().contains("folder data of"), "{e}");

    // A miss that a listing has to decide, and a delete of a name that is not cached.
    let absent = target(FileType::Snapshots, b"never uploaded");
    not_found();
    let e = lab.read(&absent, None).await.unwrap_err();
    assert_eq!(status(&e, false), 503, "{e:?}");
    not_found();
    let e = lab.repo.remove(&absent).await.unwrap_err();
    assert_eq!(status(&e, false), 503, "{e:?}");
    assert!(matches!(
        lab.read(&absent, None).await,
        Err(Error::NotFound)
    ));

    // Finding the repository: "no such repository" would let `restic init` make a second one.
    let fresh = Repo::new(lab.be.clone(), repo("r"), Options::default());
    not_found();
    let e = fresh.head(&Target::Config).await.unwrap_err();
    assert!(matches!(e, Error::Backend(BackendError::NotFound)), "{e:?}");
    assert_eq!(status(&e, false), 503);
    assert_eq!(fresh.head(&Target::Config).await.unwrap(), 3);

    // A folder that is gone, or in the trash, is the layout error it always was.
    lab.mem.trash(lab.dir(FileType::Snapshots)).await.unwrap();
    not_found();
    let e = lab.repo.list(FileType::Snapshots).await.unwrap_err();
    assert!(matches!(e, Error::Layout(_)), "{e:?}");
    assert_eq!(status(&e, true), 403);
}
