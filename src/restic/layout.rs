//! The folder tree of a restic repository on Drive (SPEC §3.4): found by listing, created by
//! `restic init` and by nothing else.
//!
//! ```text
//! gclone-restic/<repo>/{config, keys/, locks/, snapshots/, index/, data/00 … data/ff}
//! ```
//!
//! restic's own local layout. Every level but the top one must exist exactly once: Drive allows
//! two folders of one name, and picking one silently could split `locks/` between two machines.
//! The top level is the exception — two machines that initialise two repositories on a fresh
//! account each create a `gclone-restic` — so the root is the union of all of them.

use std::sync::Arc;

use futures_util::StreamExt as _;

use super::{
    CREATE_FANOUT, Error, FileType, LIST_CONFIRM_POLL, LIST_CONFIRM_POLL_MAX, LIST_CONFIRM_WAIT,
    ROOT_NAME, RepoName, SHARDS,
};
use crate::backend::{Backend, Handle, ObjMeta};
use crate::format::DESCRIPTOR_NAME;

/// The four type folders that hold files directly, in the order of [`Tree::small`].
pub const SMALL_TYPES: [FileType; 4] = [
    FileType::Keys,
    FileType::Locks,
    FileType::Snapshots,
    FileType::Index,
];

pub enum Resolved {
    /// No folder of that name in any root.
    Absent,
    Found(Arc<Layout>),
}

pub struct Layout {
    pub repo: Handle,
    /// Every file named `config` in the repository folder, as listed (not trashed).
    pub configs: Vec<ObjMeta>,
    /// `Err`: the name of the first folder that is missing (`locks`, `data/3f`).
    pub tree: Result<Tree, String>,
}

#[derive(PartialEq, Eq)]
pub struct Tree {
    /// keys, locks, snapshots, index ([`SMALL_TYPES`]).
    pub small: [Handle; 4],
    pub data: Handle,
    /// `data/00` … `data/ff`.
    pub shards: Vec<Handle>,
}

impl Layout {
    /// Same folders, by ID: what was cached under one layout is good under the other.
    pub fn same_folders(&self, other: &Layout) -> bool {
        self.repo == other.repo
            && match (&self.tree, &other.tree) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
    }
}

/// `00` … `ff`.
pub fn shard_name(i: usize) -> String {
    format!("{i:02x}")
}

/// What one pass of listings found.
struct Scan {
    /// The non-vault top-level folders named `gclone-restic`, the canonical one first (oldest,
    /// then smallest ID): where a new repository is created.
    roots: Vec<Handle>,
    repo: Option<Handle>,
    configs: Vec<ObjMeta>,
    /// keys, locks, snapshots, index, data.
    types: [Option<Handle>; 5],
    shards: Vec<Option<Handle>>,
}

const TYPE_ORDER: [FileType; 5] = [
    FileType::Keys,
    FileType::Locks,
    FileType::Snapshots,
    FileType::Index,
    FileType::Data,
];

impl Scan {
    fn missing(&self) -> Option<String> {
        let ty = TYPE_ORDER
            .iter()
            .zip(&self.types)
            .find(|(_, h)| h.is_none());
        if let Some((ty, _)) = ty {
            return Some(ty.dir().to_string());
        }
        let shard = self.shards.iter().position(Option::is_none)?;
        Some(format!("data/{}", shard_name(shard)))
    }

    fn resolved(self) -> Resolved {
        let Some(repo) = self.repo.clone() else {
            return Resolved::Absent;
        };
        let tree = match self.missing() {
            Some(name) => Err(name),
            None => {
                let mut types = self.types.into_iter().flatten();
                let mut next = || types.next().unwrap_or_else(Handle::top);
                Ok(Tree {
                    small: [next(), next(), next(), next()],
                    data: next(),
                    shards: self.shards.into_iter().flatten().collect(),
                })
            }
        };
        Resolved::Found(Arc::new(Layout {
            repo,
            configs: self.configs,
            tree,
        }))
    }
}

/// A listing without what its own flags call trashed: the query asked for `trashed = false`,
/// and an index that lags behind the resource may answer otherwise. A store that says "not
/// found" for the folder fails with `BackendError::NotFound` — never an empty listing: "no
/// repository here" and "no snapshots" are answers restic acts on.
pub async fn list_live<B: Backend>(backend: &B, parent: &Handle) -> Result<Vec<ObjMeta>, Error> {
    let mut found = backend.list_strict(parent).await?;
    found.retain(|m| !m.trashed);
    Ok(found)
}

fn folders<'a>(children: &'a [ObjMeta], name: &str) -> Vec<&'a ObjMeta> {
    children
        .iter()
        .filter(|m| m.is_folder && m.name == name)
        .collect()
}

fn duplicate(what: &str, repo: &RepoName, initialised: bool) -> Error {
    let mut text = format!(
        "two folders named {what} in repository \"{repo}\" on Drive; remove the stray one in \
         drive.google.com"
    );
    if !initialised {
        text.push_str(&format!(
            " (the repository is not initialised: move {ROOT_NAME}/{repo} to the Drive trash \
             and run restic init again)"
        ));
    }
    Error::Layout(text)
}

/// At most one folder of `name`, else the explicit error.
fn single(
    children: &[ObjMeta],
    name: &str,
    shown: &str,
    repo: &RepoName,
    initialised: bool,
) -> Result<Option<Handle>, Error> {
    match folders(children, name).as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.handle.clone())),
        _ => Err(duplicate(shown, repo, initialised)),
    }
}

async fn scan<B: Backend>(backend: &B, repo: &RepoName) -> Result<Scan, Error> {
    let top = list_live(backend, &Handle::top()).await?;
    let mut candidates = folders(&top, ROOT_NAME);
    candidates.sort_by(|a, b| (a.created_ms, &a.handle.0).cmp(&(b.created_ms, &b.handle.0)));
    let mut scan = Scan {
        roots: Vec::new(),
        repo: None,
        configs: Vec::new(),
        types: Default::default(),
        shards: vec![None; SHARDS],
    };
    let mut repos: Vec<Handle> = Vec::new();
    for candidate in candidates {
        let children = list_live(backend, &candidate.handle).await?;
        // A vault that happens to be called gclone-restic is not a root.
        if children
            .iter()
            .any(|m| !m.is_folder && m.name == DESCRIPTOR_NAME)
        {
            continue;
        }
        scan.roots.push(candidate.handle.clone());
        repos.extend(
            folders(&children, repo.as_str())
                .iter()
                .map(|m| m.handle.clone()),
        );
    }
    let repo_id = match repos.as_slice() {
        [] => return Ok(scan),
        [only] => only.clone(),
        several => {
            // Which hint the error carries depends on whether any of them was ever initialised.
            let mut initialised = false;
            for id in several {
                let children = list_live(backend, id).await?;
                initialised |= children.iter().any(|m| !m.is_folder && m.name == "config");
            }
            return Err(Error::Layout(match initialised {
                true => format!(
                    "two folders named {repo} in {ROOT_NAME} on Drive; remove the stray one in \
                     drive.google.com"
                ),
                false => format!(
                    "two folders named {repo} in {ROOT_NAME} on Drive, neither initialised: \
                     move both to the Drive trash and run restic init again"
                ),
            }));
        }
    };
    let children = list_live(backend, &repo_id).await?;
    scan.repo = Some(repo_id);
    scan.configs = children
        .iter()
        .filter(|m| !m.is_folder && m.name == "config")
        .cloned()
        .collect();
    let initialised = !scan.configs.is_empty();
    for (slot, ty) in scan.types.iter_mut().zip(TYPE_ORDER) {
        *slot = single(&children, ty.dir(), ty.dir(), repo, initialised)?;
    }
    if let Some(data) = &scan.types[4] {
        let children = list_live(backend, data).await?;
        for (i, slot) in scan.shards.iter_mut().enumerate() {
            let name = shard_name(i);
            *slot = single(&children, &name, &format!("data/{name}"), repo, initialised)?;
        }
    }
    Ok(scan)
}

/// Finds the repository by listing from the top: four listings (five with two roots).
pub async fn resolve<B: Backend>(backend: &B, repo: &RepoName) -> Result<Resolved, Error> {
    Ok(scan(backend, repo).await?.resolved())
}

/// `POST ?create=true`: creates what is missing of the tree — each folder with a pre-generated
/// ID, so that a repeated request cannot make a second one — and returns once a listing shows
/// all of it, because the next restic command is a new process that finds the tree by listing.
pub async fn create<B: Backend>(backend: &B, repo: &RepoName) -> Result<Arc<Layout>, Error> {
    let found = scan(backend, repo).await?;
    if found.repo.is_none() || found.missing().is_some() {
        build(backend, repo, found).await?;
    }
    let deadline = tokio::time::Instant::now() + LIST_CONFIRM_WAIT;
    let mut pause = LIST_CONFIRM_POLL;
    loop {
        if let Resolved::Found(layout) = resolve(backend, repo).await?
            && layout.tree.is_ok()
        {
            return Ok(layout);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Unconfirmed(format!(
                "Drive does not list the new folders of repository \"{repo}\" yet"
            )));
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(LIST_CONFIRM_POLL_MAX);
    }
}

async fn build<B: Backend>(backend: &B, repo: &RepoName, found: Scan) -> Result<(), Error> {
    let missing_types = found.types.iter().filter(|h| h.is_none()).count();
    let missing_shards = found.shards.iter().filter(|h| h.is_none()).count();
    let need = usize::from(found.roots.is_empty())
        + usize::from(found.repo.is_none())
        + missing_types
        + missing_shards;
    let mut ids = backend.new_ids(need).await?.into_iter();
    let mut fresh = || {
        ids.next()
            .ok_or_else(|| Error::Integrity("the store handed out too few object ids".into()))
    };
    let root = match found.roots.first() {
        Some(root) => root.clone(),
        None => {
            let id = fresh()?;
            backend
                .create_folder(&id, &Handle::top(), ROOT_NAME)
                .await?;
            id
        }
    };
    let repo_id = match found.repo {
        Some(id) => id,
        None => {
            let id = fresh()?;
            backend.create_folder(&id, &root, repo.as_str()).await?;
            id
        }
    };
    let mut data = found.types[4].clone();
    let mut jobs: Vec<(Handle, Handle, String)> = Vec::new();
    for (slot, ty) in found.types.iter().zip(TYPE_ORDER) {
        if slot.is_none() {
            let id = fresh()?;
            if ty == FileType::Data {
                data = Some(id.clone());
            }
            jobs.push((id, repo_id.clone(), ty.dir().to_string()));
        }
    }
    make(backend, jobs).await?;
    let data = data.ok_or_else(|| Error::Integrity("no data folder".into()))?;
    let mut jobs = Vec::new();
    for (i, slot) in found.shards.iter().enumerate() {
        if slot.is_none() {
            jobs.push((fresh()?, data.clone(), shard_name(i)));
        }
    }
    make(backend, jobs).await
}

async fn make<B: Backend>(backend: &B, jobs: Vec<(Handle, Handle, String)>) -> Result<(), Error> {
    let mut made = futures_util::stream::iter(jobs)
        .map(|(id, parent, name)| async move { backend.create_folder(&id, &parent, &name).await })
        .buffer_unordered(CREATE_FANOUT);
    while let Some(done) = made.next().await {
        done?;
    }
    Ok(())
}

/// Size, checksum, creation time and ID of a file named `config`.
pub type ConfigKey<'a> = (u64, Option<[u8; 16]>, u64, &'a str);

/// The one config of a repository among `configs` (its position): `Ok(None)` without any, the
/// oldest of several copies with the same content, and an explicit error for two that differ —
/// which two `restic init` runs at the same time leave behind, and which no pick can repair.
pub fn pick_config(configs: &[ConfigKey<'_>], repo: &RepoName) -> Result<Option<usize>, Error> {
    let Some((size, md5, ..)) = configs.first() else {
        return Ok(None);
    };
    // Without a checksum from the store, two files of one size cannot be told apart here.
    let differs =
        |(s, m, ..): &ConfigKey<'_>| s != size || (m.is_some() && md5.is_some() && m != md5);
    if configs.iter().any(differs) {
        return Err(Error::Layout(format!(
            "two different config files in repository \"{repo}\" on Drive (two restic init runs \
             at the same time): move {ROOT_NAME}/{repo} to the Drive trash and run restic init \
             again"
        )));
    }
    let oldest = configs.iter().enumerate().min_by_key(|(_, c)| (c.2, c.3));
    Ok(oldest.map(|(at, _)| at))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::backend::{Flaky, MemBackend, OpKind, PutBody};
    use crate::error::BackendError;

    pub(crate) fn repo(name: &str) -> RepoName {
        RepoName::parse(name).unwrap()
    }

    pub(crate) async fn folder(b: &MemBackend, parent: &Handle, name: &str) -> Handle {
        let id = b.new_ids(1).await.unwrap().remove(0);
        b.create_folder(&id, parent, name).await.unwrap();
        id
    }

    pub(crate) async fn file(b: &MemBackend, parent: &Handle, name: &str, data: &[u8]) -> Handle {
        let id = b.new_ids(1).await.unwrap().remove(0);
        b.put(&id, parent, name, PutBody::Small(data.to_vec().into()))
            .await
            .unwrap();
        id
    }

    async fn found(b: &impl Backend, name: &str) -> Arc<Layout> {
        match resolve(b, &repo(name)).await.unwrap() {
            Resolved::Found(layout) => layout,
            Resolved::Absent => panic!("{name} is absent"),
        }
    }

    async fn layout_error(b: &impl Backend, name: &str) -> String {
        match resolve(b, &repo(name)).await {
            Err(Error::Layout(text)) => text,
            Ok(_) => panic!("{name} resolved"),
            Err(e) => panic!("{e:?}"),
        }
    }

    /// U6, U8.
    #[tokio::test(start_paused = true)]
    async fn resolve_and_create() {
        let b = MemBackend::new();
        let name = repo("laptop");
        assert!(matches!(
            resolve(&b, &name).await.unwrap(),
            Resolved::Absent
        ));

        // A fresh account: the root and the 262 folders of the repository, each created once.
        let layout = create(&b, &name).await.unwrap();
        assert_eq!(b.counters().create_folder, 263);
        let tree = layout.tree.as_ref().ok().unwrap();
        assert_eq!(tree.shards.len(), SHARDS);
        assert!(layout.configs.is_empty());
        let all = b.all_objects();
        assert_eq!(all.len(), 263);
        let root = all.iter().find(|m| m.name == ROOT_NAME).unwrap();
        assert!(root.parent.is_top());
        let shard = all.iter().find(|m| m.name == "3f").unwrap();
        assert_eq!(shard.parent, tree.data);
        assert_eq!(shard.handle, tree.shards[0x3f]);
        for (ty, id) in SMALL_TYPES.iter().zip(&tree.small) {
            let folder = all.iter().find(|m| m.handle == *id).unwrap();
            assert_eq!(folder.name, ty.dir());
        }

        // Resolving costs four listings; a repeated create writes nothing.
        b.reset_counters();
        let again = found(&b, "laptop").await;
        assert!(again.same_folders(&layout));
        assert_eq!(b.counters().list, 4);
        b.reset_counters();
        create(&b, &name).await.unwrap();
        let c = b.counters();
        assert_eq!((c.create_folder, c.new_ids, c.put), (0, 0, 0));

        // Another repository lives beside it, under the same root: 262 folders.
        assert!(matches!(
            resolve(&b, &repo("other")).await.unwrap(),
            Resolved::Absent
        ));
        b.reset_counters();
        create(&b, &repo("other")).await.unwrap();
        assert_eq!(b.counters().create_folder, 262);

        // A missing type folder, a missing shard: named, and created again by `create` alone.
        b.trash(&tree.small[1]).await.unwrap();
        b.trash(&tree.shards[0x3f]).await.unwrap();
        let broken = found(&b, "laptop").await;
        assert_eq!(broken.tree.as_ref().err().unwrap(), "locks");
        assert!(!broken.same_folders(&layout));
        b.untrash(&tree.small[1]).await.unwrap();
        assert_eq!(
            found(&b, "laptop").await.tree.as_ref().err().unwrap(),
            "data/3f"
        );
        b.reset_counters();
        let repaired = create(&b, &name).await.unwrap();
        assert_eq!(b.counters().create_folder, 1);
        assert!(repaired.tree.is_ok());
        assert!(!repaired.same_folders(&layout));

        // The whole repository in the trash is an absent repository.
        b.trash(&layout.repo).await.unwrap();
        assert!(matches!(
            resolve(&b, &name).await.unwrap(),
            Resolved::Absent
        ));
    }

    /// U6: duplicates at each level are an explicit error that names the folder.
    #[tokio::test(start_paused = true)]
    async fn duplicate_folders_are_never_picked_from() {
        let b = MemBackend::new();
        let name = repo("laptop");
        let layout = create(&b, &name).await.unwrap();
        let tree = layout.tree.as_ref().ok().unwrap();

        let stray = folder(&b, &layout.repo, "locks").await;
        let text = layout_error(&b, "laptop").await;
        assert!(
            text.contains("two folders named locks in repository \"laptop\""),
            "{text}"
        );
        assert!(
            text.contains("not initialised") && text.contains("restic init again"),
            "{text}"
        );
        // An entry the listing itself flags as trashed does not count (R8) — here: gone.
        b.trash(&stray).await.unwrap();
        found(&b, "laptop").await;

        file(&b, &layout.repo, "config", b"one").await;
        let stray = folder(&b, &tree.data, "3f").await;
        let text = layout_error(&b, "laptop").await;
        assert!(text.contains("two folders named data/3f"), "{text}");
        assert!(!text.contains("not initialised"), "{text}");
        b.trash(&stray).await.unwrap();

        // A file of a folder's name, and a folder named config, are not what they are named.
        file(&b, &layout.repo, "locks", b"x").await;
        folder(&b, &layout.repo, "config").await;
        let ok = found(&b, "laptop").await;
        assert_eq!(ok.configs.len(), 1);

        // Two repository folders of one name in one root.
        let root = b
            .all_objects()
            .into_iter()
            .find(|m| m.name == ROOT_NAME)
            .unwrap();
        let stray = folder(&b, &root.handle, "laptop").await;
        let text = layout_error(&b, "laptop").await;
        assert!(
            text.contains("two folders named laptop in gclone-restic"),
            "{text}"
        );
        assert!(text.contains("remove the stray one"), "{text}");
        b.trash(&stray).await.unwrap();
        found(&b, "laptop").await;
    }

    /// U7: the root is the union of all top-level `gclone-restic` folders that are no vault.
    #[tokio::test(start_paused = true)]
    async fn two_roots_and_a_vault_of_the_same_name() {
        let b = MemBackend::new();
        // The older folder of the name is a vault: never a root, never written to.
        let vault = folder(&b, &Handle::top(), ROOT_NAME).await;
        file(&b, &vault, DESCRIPTOR_NAME, b"{}").await;
        folder(&b, &vault, "a").await;
        b.advance_ms(1000);
        assert!(matches!(
            resolve(&b, &repo("a")).await.unwrap(),
            Resolved::Absent
        ));

        // No root: one is created. Then a second root appears, with repository `b` in it.
        let a = create(&b, &repo("a")).await.unwrap();
        let first_root = b.stat(&a.repo).await.unwrap().unwrap().parent;
        assert_ne!(first_root, vault);
        b.advance_ms(1000);
        let second_root = folder(&b, &Handle::top(), ROOT_NAME).await;
        folder(&b, &second_root, "b").await;
        let bb = create(&b, &repo("b")).await.unwrap();
        assert_eq!(b.stat(&bb.repo).await.unwrap().unwrap().parent, second_root);
        assert!(found(&b, "a").await.same_folders(&a));
        assert!(found(&b, "b").await.same_folders(&bb));
        // Five listings with two roots (the vault's is a sixth here).
        b.reset_counters();
        found(&b, "a").await;
        assert_eq!(b.counters().list, 6);

        // A new repository goes into the older root.
        let c = create(&b, &repo("c")).await.unwrap();
        assert_eq!(b.stat(&c.repo).await.unwrap().unwrap().parent, first_root);

        // `a` in both roots: an explicit error, with the hint that fits.
        let stray = folder(&b, &second_root, "a").await;
        let text = layout_error(&b, "a").await;
        assert!(text.contains("neither initialised"), "{text}");
        file(&b, &stray, "config", b"x").await;
        let text = layout_error(&b, "a").await;
        assert!(text.contains("remove the stray one"), "{text}");
        assert!(matches!(
            create(&b, &repo("a")).await,
            Err(Error::Layout(_))
        ));
    }

    /// U8: create returns when the tree is listed, and gives up with an error.
    #[tokio::test(start_paused = true)]
    async fn create_waits_for_the_listing() {
        let mem = MemBackend::new();
        let b = Flaky::new(mem.clone());
        b.set_list_lag_ms(5_000);
        let name = repo("laptop");
        let task = tokio::spawn({
            let b = b.clone();
            let name = name.clone();
            async move { create(&b, &name).await.map(|_| ()) }
        });
        // The folders exist; the listings do not show them yet.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert_eq!(mem.counters().create_folder, 263);
        assert!(!task.is_finished());
        mem.advance_ms(5_000);
        task.await.unwrap().unwrap();
        // Nothing was created twice while it waited.
        assert_eq!(mem.counters().create_folder, 263);

        // Never listed: an error after LIST_CONFIRM_WAIT, not a hang.
        let never = repo("never");
        b.set_list_lag_ms(u64::MAX);
        let started = tokio::time::Instant::now();
        let failed = create(&b, &never).await;
        assert!(matches!(failed, Err(Error::Unconfirmed(_))));
        assert!(started.elapsed() >= LIST_CONFIRM_WAIT);
        assert!(started.elapsed() < LIST_CONFIRM_WAIT * 2);

        // A failing store is passed on.
        b.clear();
        b.fail_next(OpKind::List, 1, || BackendError::RateLimited);
        assert!(matches!(
            create(&b, &name).await,
            Err(Error::Backend(BackendError::RateLimited))
        ));
    }

    /// U6: identical copies of the config are one config; two that differ are an error.
    #[test]
    fn config_copies() {
        let name = repo("laptop");
        let key =
            |id: &'static str, size: u64, md5: Option<u8>, created_ms: u64| -> ConfigKey<'_> {
                (size, md5.map(|b| [b; 16]), created_ms, id)
            };
        assert_eq!(pick_config(&[], &name).unwrap(), None);
        assert_eq!(
            pick_config(&[key("b", 155, Some(1), 20)], &name).unwrap(),
            Some(0)
        );
        // Copies: the oldest, then the smallest ID.
        let copies = [
            key("c", 155, Some(1), 20),
            key("b", 155, Some(1), 10),
            key("a", 155, None, 10),
        ];
        assert_eq!(pick_config(&copies, &name).unwrap(), Some(2));
        for differing in [
            [key("a", 155, Some(1), 1), key("b", 155, Some(2), 2)],
            [key("a", 155, Some(1), 1), key("b", 156, Some(1), 2)],
        ] {
            let Err(Error::Layout(text)) = pick_config(&differing, &name) else {
                panic!("differing configs were accepted");
            };
            assert!(text.contains("two different config files in repository \"laptop\""));
        }
    }
}
