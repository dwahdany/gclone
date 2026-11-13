//! The vault: journal, replica and queries (SPEC §5.2–§5.6, §5.8, §5.10, §9.7) — owned by WP4.
//!
//! This file holds the public types, the vault's lifecycle (create / open / discover), the
//! keyfile objects and the data folder. The journal lives in `refresh.rs` (§5.3), `commit.rs`
//! (§5.6, §5.8), `resolve.rs` (§5.2.3) and `repair.rs` (§5.10); `query.rs` has the SQL reads.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use crate::backend::{Backend, Handle, ObjMeta, get_bounded, md5_of};
use crate::consts::{DATA_FOLDER_MAX, DESCRIPTOR_MAX, INDEX_OBJECT_MAX, KEYFILE_MAX};
use crate::crypto::Keyring;
use crate::error::{BackendError, FormatError, IndexError, StateError};
use crate::format::{
    DATA_FOLDER, DESCRIPTOR_NAME, INDEX_FOLDER, README_NAME, README_TEXT, SUPPORTED_FORMAT,
    VaultDescriptor, data_folder_name, parse_keyfile_name,
};
use crate::state::{Db, tables};
use crate::types::{DeviceId, Head, OpDraft};
use crate::util;

pub mod apply;
mod commit;
mod query;
mod refresh;
mod repair;
mod resolve;

pub use apply::{
    ApplyStats, HeadStore, MemIndex, apply_segment, causal_order, check_snapshot_format,
    removal_time,
};

#[derive(Clone, Debug)]
pub struct VaultHandles {
    pub root: Handle,
    pub index: Handle,
    pub data: Handle,
}

/// One vault as seen by discovery (§3.3). `keyfiles` = ALL the root's children named
/// `gclone-key-<gen>-<h8>`, highest generation first (ties: name descending); the caller
/// (ATTACH) looks at the first `KEYFILE_TRY_MAX` only.
#[derive(Clone, Debug)]
pub struct FoundVault {
    pub vault_id: [u8; 16],
    /// `""` when the root is `Handle::top()`.
    pub root_name: String,
    pub descriptor_created_ms: u64,
    pub handles: VaultHandles,
    pub keyfiles: Vec<ObjMeta>,
}

pub struct CreateParams {
    pub vault_id: [u8; 16],
    pub vault_name: String,
    pub device_name: String,
    pub cache_dir: std::path::PathBuf,
    /// `None` = compute (§5.3); tests pin it.
    pub machine_fp: Option<[u8; 32]>,
    /// Generation 1, sealed by the caller (§2.6).
    pub keyfile: crate::format::SealedObject,
}

pub struct OpenParams {
    pub vault_id: [u8; 16],
    pub handles: VaultHandles,
    pub device_name: String,
    pub cache_dir: std::path::PathBuf,
    pub machine_fp: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct RefreshReport {
    pub applied: u64,
    pub blocked_young: u64,
    pub conflicts: u64,
    pub forks: u64,
    pub rotated_device: bool,
    pub rebuilt_from: Option<String>,
    pub adopted: Option<String>,
    pub outbox_stuck: bool,
    pub corrupt_objects: Vec<String>,
    /// The newest listed snapshot covers index segments this replica lacks, and the replica
    /// could not be rebuilt from it (§5.3 `snapshot_news`): its name.
    pub unused_snapshot: Option<String>,
}

impl RefreshReport {
    /// Why this replica may lack index state although the refresh ended without a verdict:
    /// segments that wait for their predecessors, listed index objects that failed
    /// verification and were ignored, or a newer snapshot that was left unused. `gc` judges
    /// what is dead and must not run on such a replica (§5.9); the text names the objects.
    pub fn incomplete(&self) -> Option<String> {
        let mut why = Vec::new();
        if self.blocked_young > 0 {
            why.push(format!(
                "{} index segment(s) cannot be applied yet (their predecessors are not visible)",
                self.blocked_young
            ));
        }
        if !self.corrupt_objects.is_empty() {
            why.push(format!(
                "{} index object(s) failed verification and were ignored ({})",
                self.corrupt_objects.len(),
                self.corrupt_objects.join(", ")
            ));
        }
        if let Some(name) = &self.unused_snapshot {
            why.push(format!(
                "snapshot {name} covers index segments this device lacks and could not be used"
            ));
        }
        (!why.is_empty()).then(|| why.join("; "))
    }
}

/// What became of the keyfiles a `passwd` retired (§2.7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetiredKeyfiles {
    /// Moved to the trash (the store keeps them for 30 days).
    pub trashed: u64,
    /// Deleted for good from the vault folder …
    pub deleted: u64,
    /// … and from the trash, where earlier runs had left them.
    pub deleted_from_trash: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CommitReport {
    pub segment: Option<String>,
    pub ops: u64,
    /// §5.8.
    pub dropped_ops: u64,
}

/// `still_missing` is non-empty when a gap or an unsatisfied rollback mark remains and
/// `--accept-loss` was not given: the caller reports it and exits 3 (§5.10 step 4).
#[derive(Clone, Debug, Default)]
pub struct RepairReport {
    pub republished: Vec<String>,
    pub untrashed: Vec<String>,
    pub accepted_loss: Vec<String>,
    pub snapshot: Option<String>,
    pub still_missing: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct VaultStats {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub blobs: u64,
    pub blob_bytes: u64,
    pub dead_blob_bytes: u64,
    pub pack_dead_bytes: u64,
    /// Trashed by this device, not yet purged.
    pub trashed_blob_bytes: u64,
    pub segments: u64,
    pub snapshots: u64,
    pub conflicts: u64,
    pub last_change_ms: Option<u64>,
    pub last_change_by: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ListRow {
    pub name: String,
    pub is_dir: bool,
    /// `None` for implied dirs.
    pub head: Option<Head>,
}

/// One match of [`Vault::search`].
#[derive(Clone, Debug)]
pub struct SearchHit {
    pub path: String,
    pub is_dir: bool,
    /// `None` for directories.
    pub head: Option<Head>,
}

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub first_ms: u64,
    pub last_ms: u64,
}

/// §2.6 "two first devices": the winner among `found` (which must include one's own vault) =
/// smallest `(descriptor_created_ms, vault_id)`.
pub fn creation_winner(found: &[FoundVault]) -> Option<&FoundVault> {
    found
        .iter()
        .min_by_key(|v| (v.descriptor_created_ms, v.vault_id))
}

/// `Arc<B>`, `Db`, `Keyring`, handles, cache dir, device identity, local clock.
pub struct Vault<B: Backend> {
    backend: Arc<B>,
    db: Db,
    keys: Keyring,
    handles: VaultHandles,
    cache_dir: PathBuf,
    device_name: String,
    machine_fp: [u8; 32],
    /// Local clock for grace periods (§5.3); never a server time.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    device: Mutex<DeviceId>,
    /// A rotation that happened in `open`, reported by the next refresh.
    rotated: AtomicBool,
    /// Why the outbox row could not be published the last time it was tried.
    stuck: Mutex<Option<String>>,
    /// `pending` rows up to this id were staged by an earlier process (§5.8).
    inherited_pending: i64,
    /// Serialises the journal operations of one process.
    journal: tokio::sync::Mutex<()>,
    /// `INDEX_OBJECT_MAX`: no more bytes than this are read of one index object (§4.6 rule 1).
    object_max: u64,
    /// The snapshots the last refresh of this process saw listed
    /// (`Listed::snapshots_fingerprint`): `finish_mutation`'s cleanup compares it with what
    /// its last complete pass left (§5.6).
    listed_snaps: Mutex<Option<[u8; 32]>>,
    /// What the last refresh of this process said about the replica when it may lack index
    /// state — an error, or `RefreshReport::incomplete` (§5.9). `None`: no refresh yet, or a
    /// clean one.
    incomplete: Mutex<Option<String>>,
}

/// A message-only error (exit 1), shown as written.
pub(crate) fn plain_error(message: impl Into<String>) -> IndexError {
    IndexError::Io(std::io::Error::other(message.into()))
}

/// What `403 appNotAuthorizedToFile` means for a vault object (§2.8).
fn not_visible(e: BackendError) -> IndexError {
    match e {
        BackendError::AppNotAuthorized => IndexError::VaultNotVisible,
        e => IndexError::Backend(e),
    }
}

/// CPU- or SQLite-heavy work off the async threads (§9.2).
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, IndexError> + Send + 'static,
) -> Result<T, IndexError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(out) => out,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => Err(plain_error("a background task was cancelled")),
        },
    }
}

enum PutOutcome {
    Stored(ObjMeta),
    /// The stored size or md5 differ from what was sent; the object has been trashed.
    Damaged,
}

async fn put_once<B: Backend>(
    backend: &B,
    id: &Handle,
    parent: &Handle,
    name: &str,
    bytes: &Bytes,
) -> Result<PutOutcome, BackendError> {
    let body = crate::backend::stream_body(bytes.clone());
    let meta = backend.put(id, parent, name, body).await?;
    if meta.size == bytes.len() as u64 && meta.md5.is_none_or(|m| m == md5_of(bytes)) {
        return Ok(PutOutcome::Stored(meta));
    }
    if let Err(e) = backend.trash(id).await {
        tracing::warn!("could not trash the damaged object {name}: {e}");
    }
    Ok(PutOutcome::Damaged)
}

fn damaged(name: &str) -> IndexError {
    BackendError::Transient(format!("{name} was not stored intact (size or md5 differ)")).into()
}

/// One put under `id`; the stored size and md5 must be those of `bytes`, else the object is
/// trashed and the put fails with a temporary error.
pub(crate) async fn put_checked<B: Backend>(
    backend: &B,
    id: &Handle,
    parent: &Handle,
    name: &str,
    bytes: &Bytes,
) -> Result<ObjMeta, IndexError> {
    match put_once(backend, id, parent, name, bytes).await? {
        PutOutcome::Stored(meta) => Ok(meta),
        PutOutcome::Damaged => Err(damaged(name)),
    }
}

/// Like [`put_checked`], retried under fresh ids when the object arrives damaged or the upload
/// session is lost (§5.8). `on_new_id` is told each replacement id before it is used.
pub(crate) async fn put_retrying<B: Backend>(
    backend: &B,
    first: Handle,
    parent: &Handle,
    name: &str,
    bytes: &Bytes,
    mut on_new_id: impl FnMut(&Handle) -> Result<(), IndexError>,
) -> Result<(Handle, ObjMeta), IndexError> {
    const ATTEMPTS: u32 = 3;
    let mut id = first;
    for attempt in 1.. {
        match put_once(backend, &id, parent, name, bytes).await {
            Ok(PutOutcome::Stored(meta)) => return Ok((id, meta)),
            Ok(PutOutcome::Damaged) | Err(BackendError::SessionLost) if attempt < ATTEMPTS => {
                [id] = fresh_ids(backend).await?;
                on_new_id(&id)?;
            }
            Ok(PutOutcome::Damaged) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Err(damaged(name))
}

/// Puts an index object into the cache. Best effort: the cache feeds `repair`; losing an entry
/// costs a download.
fn cache_store(path: &Path, bytes: &[u8]) {
    if path.exists() {
        return;
    }
    if let Err(e) = util::write_atomic(path, bytes, 0o600) {
        tracing::warn!("could not cache index object {}: {e}", path.display());
    }
}

async fn fresh_ids<B: Backend, const N: usize>(backend: &B) -> Result<[Handle; N], IndexError> {
    let ids = backend.new_ids(N).await.map_err(not_visible)?;
    ids.try_into()
        .map_err(|_| plain_error("the backend returned the wrong number of object ids"))
}

/// Children of a vault root that are keyfiles, highest generation first (ties: name descending).
fn keyfiles_of(children: &[ObjMeta]) -> Vec<ObjMeta> {
    let mut found: Vec<(u32, &ObjMeta)> = children
        .iter()
        .filter(|m| !m.is_folder && !m.trashed)
        .filter_map(|m| Some((parse_keyfile_name(&m.name)?.0, m)))
        .collect();
    found.sort_by(|a, b| (b.0, &b.1.name).cmp(&(a.0, &a.1.name)));
    found.into_iter().map(|(_, m)| m.clone()).collect()
}

/// §3.3: exactly one folder of that name — never a silent pick.
fn single_folder(children: &[ObjMeta], name: &str) -> Result<Handle, IndexError> {
    let mut folders = children
        .iter()
        .filter(|m| m.is_folder && !m.trashed && m.name == name);
    match (folders.next(), folders.next()) {
        (Some(only), None) => Ok(only.handle.clone()),
        (Some(_), Some(_)) => Err(plain_error(format!(
            "two folders named {name} in the vault; remove the stray one in drive.google.com"
        ))),
        (None, _) => Err(plain_error(format!(
            "the vault has no folder named {name}; restore it from the trash in drive.google.com"
        ))),
    }
}

fn machine_fingerprint(cache_dir: &Path) -> Result<[u8; 32], IndexError> {
    use std::os::unix::fs::MetadataExt;
    let ino = std::fs::metadata(cache_dir)?.ino();
    let mut h = blake3::Hasher::new();
    h.update(&util::host_id());
    h.update(&ino.to_be_bytes());
    Ok(*h.finalize().as_bytes())
}

impl<B: Backend> Vault<B> {
    // --- lifecycle

    /// Creates, in this order (§2.6): the root folder `<vault_name>` under `Handle::top()`,
    /// `index/`, `data/`, README, the keyfile (`p.keyfile`, verified by size + md5), the first
    /// segment `[VaultInit, Device]` — and the descriptor LAST. Initialises `db`. Every object
    /// uses a pre-generated id. Returns the vault and its own `FoundVault`
    /// (`descriptor_created_ms` from the put).
    pub async fn create(
        backend: Arc<B>,
        db: Db,
        keys: Keyring,
        p: CreateParams,
    ) -> Result<(Self, FoundVault), IndexError> {
        if keys.vault_id() != p.vault_id {
            return Err(FormatError::IdentityMismatch(
                "the keyring belongs to another vault".into(),
            )
            .into());
        }
        let [root, index, data, readme, keyfile, descriptor] = fresh_ids(&*backend).await?;
        backend
            .create_folder(&root, &Handle::top(), &p.vault_name)
            .await?;
        backend.create_folder(&index, &root, INDEX_FOLDER).await?;
        backend.create_folder(&data, &root, DATA_FOLDER).await?;
        let readme_text = Bytes::from_static(README_TEXT.as_bytes());
        put_checked(&*backend, &readme, &root, README_NAME, &readme_text).await?;
        let keyfile_meta = put_checked(
            &*backend,
            &keyfile,
            &root,
            &p.keyfile.name,
            &Bytes::from(p.keyfile.bytes),
        )
        .await?;

        let handles = VaultHandles { root, index, data };
        let open = OpenParams {
            vault_id: p.vault_id,
            handles: handles.clone(),
            device_name: p.device_name.clone(),
            cache_dir: p.cache_dir,
            machine_fp: p.machine_fp,
        };
        let vault = Self::open(backend, db, keys, open).await?;
        vault
            .commit_ops(vec![
                OpDraft::VaultInit {
                    format: SUPPORTED_FORMAT,
                    name: p.vault_name.clone(),
                },
                OpDraft::Device {
                    id: vault.device_id(),
                    name: p.device_name,
                },
            ])
            .await?;

        // Written last: a vault exists for discovery only once it is complete.
        let body = Bytes::from(VaultDescriptor::new(p.vault_id).to_bytes());
        let put = put_checked(
            &*vault.backend,
            &descriptor,
            &handles.root,
            DESCRIPTOR_NAME,
            &body,
        )
        .await?;
        let found = FoundVault {
            vault_id: p.vault_id,
            root_name: p.vault_name,
            descriptor_created_ms: put.created_ms,
            handles,
            keyfiles: vec![keyfile_meta],
        };
        Ok((vault, found))
    }

    /// No network; creates the device id if `db` is new. For the process that holds the state
    /// lock (§8.3) — it writes to `db`.
    pub async fn open(
        backend: Arc<B>,
        db: Db,
        keys: Keyring,
        p: OpenParams,
    ) -> Result<Self, IndexError> {
        if keys.vault_id() != p.vault_id {
            return Err(FormatError::IdentityMismatch(
                "the keyring belongs to another vault".into(),
            )
            .into());
        }
        util::create_dir_private(&p.cache_dir)?;
        let machine_fp = match p.machine_fp {
            Some(fp) => fp,
            None => machine_fingerprint(&p.cache_dir)?,
        };
        Self::open_with(backend, db, keys, p, machine_fp, true)
    }

    /// For a process that does **not** hold the state lock — a read-only command that found
    /// it busy (§8.3): the replica as it is, read with plain reads. Nothing is written — no
    /// device name, no machine fingerprint, no device-id rotation — and no write transaction
    /// is opened, so the lock holder's long transactions (a rebuild from a snapshot, a batch
    /// of applied segments) cannot make this fail with `SQLITE_BUSY`. `db` comes from
    /// `Db::open_shared`. The vault is for queries and downloads only: the caller must not
    /// refresh, stage or commit on it. `StateError::Locked` if the replica was never
    /// initialised (the lock holder is doing that right now).
    pub async fn open_unlocked(
        backend: Arc<B>,
        db: Db,
        keys: Keyring,
        p: OpenParams,
    ) -> Result<Self, IndexError> {
        if keys.vault_id() != p.vault_id {
            return Err(FormatError::IdentityMismatch(
                "the keyring belongs to another vault".into(),
            )
            .into());
        }
        // Never a fingerprint that differs from the recorded one: nothing here may rotate.
        let machine_fp = match p.machine_fp {
            Some(fp) => fp,
            None => match db.meta_get("machine_fp")? {
                Some(fp) => tables::arr(fp)?,
                None => [0; 32],
            },
        };
        Self::open_with(backend, db, keys, p, machine_fp, false)
    }

    fn open_with(
        backend: Arc<B>,
        db: Db,
        keys: Keyring,
        p: OpenParams,
        machine_fp: [u8; 32],
        locked: bool,
    ) -> Result<Self, IndexError> {
        let stored = |c: &rusqlite::Connection| {
            let vault_id = tables::meta_get(c, "vault_id")?;
            if vault_id.as_ref().is_some_and(|id| *id != p.vault_id) {
                return Err(StateError::Corrupt(
                    "this state directory belongs to another vault".into(),
                ));
            }
            let device = match tables::meta_get(c, "device_id")? {
                Some(id) => Some(DeviceId(tables::arr(id)?)),
                None => None,
            };
            Ok((vault_id.is_some(), device))
        };
        let (device, inherited_pending) = if locked {
            db.txn(|c| Self::open_state(c, &p, stored(c)?))?
        } else {
            db.read(|c| match stored(c)? {
                (true, Some(device)) => Ok((device, tables::pending_max_id(c)?)),
                _ => Err(StateError::Locked),
            })?
        };
        let vault = Vault {
            backend,
            db,
            keys,
            handles: p.handles,
            cache_dir: p.cache_dir,
            device_name: p.device_name,
            machine_fp,
            clock: Arc::new(util::now_ms),
            device: Mutex::new(device),
            rotated: AtomicBool::new(false),
            stuck: Mutex::new(None),
            inherited_pending,
            journal: tokio::sync::Mutex::new(()),
            object_max: INDEX_OBJECT_MAX,
            listed_snaps: Mutex::new(None),
            incomplete: Mutex::new(None),
        };
        // A copied or restored state directory changes its identity before it seals anything.
        if locked && vault.check_machine()? {
            vault.rotated.store(true, Ordering::Relaxed);
        }
        Ok(vault)
    }

    /// The writes of `open`: the vault id and the device id of a new replica, the device name.
    fn open_state(
        c: &rusqlite::Connection,
        p: &OpenParams,
        (has_vault_id, device): (bool, Option<DeviceId>),
    ) -> Result<(DeviceId, i64), StateError> {
        if !has_vault_id {
            tables::meta_set(c, "vault_id", &p.vault_id)?;
        }
        let device = match device {
            Some(id) => id,
            None => {
                let id = DeviceId::random();
                tables::meta_set(c, "device_id", &id.0)?;
                tables::meta_set_u64(c, "next_seq", 1)?;
                id
            }
        };
        if tables::meta_u64(c, "lamport")?.is_none() {
            tables::meta_set_u64(c, "lamport", 0)?;
        }
        // The name rarely changes: an unchanged one costs no write.
        if tables::meta_str(c, "device_name")?.as_deref() != Some(p.device_name.as_str()) {
            tables::meta_set_str(c, "device_name", &p.device_name)?;
        }
        Ok((device, tables::pending_max_id(c)?))
    }

    /// Every vault this backend can see (§3.3) — needs no keys: `find_by_name(DESCRIPTOR_NAME)`;
    /// per hit: get + parse the descriptor (unparsable or `min_reader` too new → skipped with a
    /// warning), root = its parent (possibly `Handle::top()`; otherwise `stat(root)` for the
    /// name), `list(root)` → exactly one `index` and one `data` folder (else an error naming the
    /// duplicate) and the keyfiles. Sorted by `(descriptor_created_ms, vault_id)`. An empty Vec
    /// means "no vault". `BackendError::AppNotAuthorized` → `VaultNotVisible`.
    pub async fn discover(backend: &B) -> Result<Vec<FoundVault>, IndexError> {
        let hits = backend
            .find_by_name(DESCRIPTOR_NAME)
            .await
            .map_err(not_visible)?;
        let mut found: Vec<FoundVault> = Vec::new();
        for hit in hits.iter().filter(|h| !h.is_folder && !h.trashed) {
            if hit.size > DESCRIPTOR_MAX {
                tracing::warn!(
                    "ignoring an oversized {DESCRIPTOR_NAME} ({} bytes)",
                    hit.size
                );
                continue;
            }
            // The listed size is the store's claim; the bound holds for what arrives.
            let bytes = match get_bounded(backend, &hit.handle, DESCRIPTOR_MAX).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    tracing::warn!(
                        "ignoring an oversized {DESCRIPTOR_NAME} (more than {DESCRIPTOR_MAX} bytes)"
                    );
                    continue;
                }
                Err(BackendError::NotFound) => continue,
                Err(e) => return Err(not_visible(e)),
            };
            let descriptor = match VaultDescriptor::parse(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("ignoring an unreadable {DESCRIPTOR_NAME}: {e}");
                    continue;
                }
            };
            if !descriptor.readable() {
                tracing::warn!(
                    "ignoring vault {}: it needs a newer gclone (reader version {})",
                    descriptor.vault_id,
                    descriptor.min_reader
                );
                continue;
            }
            let Some(vault_id) =
                util::unhex(&descriptor.vault_id).and_then(|v| <[u8; 16]>::try_from(v).ok())
            else {
                continue;
            };
            let root = hit.parent.clone();
            let root_name = if root.is_top() {
                String::new()
            } else {
                match backend.stat(&root).await.map_err(not_visible)? {
                    Some(meta) if !meta.trashed => meta.name,
                    _ => {
                        tracing::warn!(
                            "ignoring vault {}: its folder is gone",
                            descriptor.vault_id
                        );
                        continue;
                    }
                }
            };
            if found
                .iter()
                .any(|f| f.vault_id == vault_id && f.handles.root == root)
            {
                continue;
            }
            let children = backend.list(&root).await.map_err(not_visible)?;
            found.push(FoundVault {
                vault_id,
                root_name,
                descriptor_created_ms: hit.created_ms,
                handles: VaultHandles {
                    index: single_folder(&children, INDEX_FOLDER)?,
                    data: single_folder(&children, DATA_FOLDER)?,
                    root,
                },
                keyfiles: keyfiles_of(&children),
            });
        }
        found.sort_by_key(|v| (v.descriptor_created_ms, v.vault_id));
        Ok(found)
    }

    /// Re-login on an attached device (§2.6 B.1): `stat(root)` must be an un-trashed folder
    /// (trashed → `VaultTrashed`; absent or `AppNotAuthorized` → `VaultNotVisible`);
    /// `stat(index)` and `stat(data)` must exist with parent == root. Never a listing.
    pub async fn verify_visible(backend: &B, handles: &VaultHandles) -> Result<(), IndexError> {
        let root = backend.stat(&handles.root).await.map_err(not_visible)?;
        match root {
            None => return Err(IndexError::VaultNotVisible),
            Some(m) if m.trashed => return Err(IndexError::VaultTrashed),
            Some(m) if !m.is_folder => return Err(IndexError::VaultNotVisible),
            Some(_) => {}
        }
        for (handle, name) in [(&handles.index, INDEX_FOLDER), (&handles.data, DATA_FOLDER)] {
            match backend.stat(handle).await.map_err(not_visible)? {
                None => return Err(IndexError::VaultNotVisible),
                Some(m) if m.trashed => return Err(IndexError::VaultTrashed),
                Some(m) if !m.is_folder || m.parent != handles.root => {
                    return Err(plain_error(format!(
                        "the stored `{name}` folder is not inside the vault folder; \
                         run `gclone logout --forget` and `gclone login` again"
                    )));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    pub fn backend(&self) -> &Arc<B> {
        &self.backend
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn keys(&self) -> &Keyring {
        &self.keys
    }

    pub fn handles(&self) -> &VaultHandles {
        &self.handles
    }

    pub fn device_id(&self) -> DeviceId {
        *self.device.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Some(why)` when the last refresh of this process left a replica that may lack index
    /// state: it failed, or it ignored index objects (`RefreshReport::incomplete`). Whoever
    /// decides that something is dead asks this first (§5.9).
    pub fn index_incomplete(&self) -> Option<String> {
        self.incomplete
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The name given by the vault's `VaultInit` op; empty until the replica has applied it.
    pub fn vault_name(&self) -> String {
        self.db
            .read(|c| tables::meta_str(c, "vault_name"))
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Tests: `GAP_GRACE` without sleeping.
    #[doc(hidden)]
    pub fn set_local_clock(&mut self, now_ms: Arc<dyn Fn() -> u64 + Send + Sync>) {
        self.clock = now_ms;
    }

    /// Tests: the read bound of §4.6 rule 1 without gibibyte objects. (The format's own cap,
    /// `INDEX_OBJECT_MAX`, is not changed by this.)
    #[doc(hidden)]
    pub fn set_index_object_max(&mut self, max: u64) {
        self.object_max = max;
    }

    // --- shared helpers of the journal files

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The machine fingerprint decides whether this state directory was copied (§5.3). First
    /// run: store it. Returns whether the device id was rotated.
    fn check_machine(&self) -> Result<bool, IndexError> {
        let stored = self.db.read(|c| tables::meta_get(c, "machine_fp"))?;
        match stored {
            Some(fp) if fp == self.machine_fp => Ok(false),
            Some(_) => {
                self.rotate_device_id(
                    "this state directory was copied from another machine or restored from a backup",
                )?;
                Ok(true)
            }
            None => {
                self.db.meta_set("machine_fp", &self.machine_fp)?;
                Ok(false)
            }
        }
    }

    /// §5.3: new random device id, `next_seq := 1`, clear `own` and the data-folder meta, store
    /// the current machine fingerprint. A stuck outbox row stays as sealed.
    fn rotate_device_id(&self, why: &str) -> Result<(), IndexError> {
        let id = DeviceId::random();
        self.db.txn(|c| {
            tables::meta_set(c, "device_id", &id.0)?;
            tables::meta_set_u64(c, "next_seq", 1)?;
            tables::own_clear(c)?;
            for k in ["data_folder_id", "data_folder_n", "data_folder_count"] {
                tables::meta_del(c, k)?;
            }
            tables::meta_set(c, "machine_fp", &self.machine_fp)
        })?;
        let old = std::mem::replace(
            &mut *self.device.lock().unwrap_or_else(|e| e.into_inner()),
            id,
        );
        tracing::warn!("{why}: this device continues as {id} (was {old})");
        Ok(())
    }

    fn cache_path(&self, name: &str) -> PathBuf {
        self.cache_dir.join(name)
    }

    fn cache_read(&self, name: &str) -> Option<Vec<u8>> {
        std::fs::read(self.cache_path(name)).ok()
    }

    fn cache_write(&self, name: &str, bytes: &[u8]) {
        cache_store(&self.cache_path(name), bytes);
    }

    // --- keyfile (§2.6, §2.7)

    /// `list(root)`, names that parse as keyfiles, highest generation first.
    pub async fn keyfiles(&self) -> Result<Vec<ObjMeta>, IndexError> {
        let children = self
            .backend
            .list(&self.handles.root)
            .await
            .map_err(not_visible)?;
        Ok(keyfiles_of(&children))
    }

    /// passwd: put `kf` into the root under a pre-generated id (returned size + md5 must match,
    /// else trash it and fail), THEN trash every listed keyfile with a lower generation. Returns
    /// the number trashed. ([`Vault::put_keyfile`] and [`Vault::retire_keyfiles`] in one call.)
    pub async fn replace_keyfile(
        &self,
        kf: &crate::format::SealedObject,
    ) -> Result<u64, IndexError> {
        let new = self.put_keyfile(kf).await?;
        Ok(self.retire_keyfiles(&new, false).await?.trashed)
    }

    /// passwd, first half (§2.7): puts `kf` into the root under a pre-generated id — the
    /// returned size and md5 must match, else it is trashed and the put fails — and then reads
    /// the object back from the store and compares it byte for byte with what was sealed.
    /// Nothing is retired before this returns: after it, the store verifiably holds a keyfile
    /// that the caller has opened with the new passphrase.
    pub async fn put_keyfile(
        &self,
        kf: &crate::format::SealedObject,
    ) -> Result<ObjMeta, IndexError> {
        if parse_keyfile_name(&kf.name).is_none() {
            return Err(FormatError::BadName(kf.name.clone()).into());
        }
        let [id] = fresh_ids(&*self.backend).await?;
        let meta = put_checked(
            &*self.backend,
            &id,
            &self.handles.root,
            &kf.name,
            &Bytes::copy_from_slice(&kf.bytes),
        )
        .await?;
        let stored = get_bounded(&*self.backend, &id, KEYFILE_MAX).await?;
        if stored.as_deref() != Some(&kf.bytes[..]) {
            if let Err(e) = self.backend.trash(&id).await {
                tracing::warn!("could not trash the damaged keyfile {}: {e}", kf.name);
            }
            return Err(damaged(&kf.name));
        }
        Ok(meta)
    }

    /// The objects under a keyfile's name in the vault root and in its trash (as far as the
    /// store lists the trash: `Backend::list_trashed`), each highest generation first. Names
    /// only: the device holds no passphrase and can open none of them.
    pub async fn keyfiles_and_trashed(&self) -> Result<(Vec<ObjMeta>, Vec<ObjMeta>), IndexError> {
        let live = self.keyfiles().await?;
        let mut trashed: Vec<(u32, ObjMeta)> = self
            .backend
            .list_trashed(&self.handles.root)
            .await
            .map_err(not_visible)?
            .into_iter()
            .filter(|m| !m.is_folder && m.trashed)
            .filter_map(|m| Some((parse_keyfile_name(&m.name)?.0, m)))
            .collect();
        trashed.sort_by(|a, b| (b.0, &b.1.name).cmp(&(a.0, &a.1.name)));
        Ok((live, trashed.into_iter().map(|(_, m)| m).collect()))
    }

    /// passwd, second half (§2.7): every keyfile of the vault root with a lower generation
    /// than `new` is retired — moved to the trash, or with `purge` deleted for good, together
    /// with EVERY object under a keyfile's name that is in the trash already, whatever its
    /// generation (what earlier `passwd` runs left there and what was trashed by hand, as far
    /// as the store lists it: `Backend::list_trashed`). Nothing in the trash is a keyfile in
    /// use, and each of them opens with an old passphrase.
    ///
    /// Only objects of the vault's root folder whose name is a keyfile's name are touched, and
    /// never `new` itself — junk planted under such a name goes with them. Among the objects
    /// that are not in the trash the generation decides: a keyfile of the same generation (a
    /// concurrent `passwd`) or a higher one stays. The generations are names: the device
    /// holds no passphrase and can open none of them.
    pub async fn retire_keyfiles(
        &self,
        new: &ObjMeta,
        purge: bool,
    ) -> Result<RetiredKeyfiles, IndexError> {
        let Some((generation, _)) = parse_keyfile_name(&new.name) else {
            return Err(FormatError::BadName(new.name.clone()).into());
        };
        let lower = |m: &ObjMeta| {
            !m.is_folder
                && m.handle != new.handle
                && parse_keyfile_name(&m.name).is_some_and(|(g, _)| g < generation)
        };
        let gone = |r: Result<(), BackendError>| match r {
            Ok(()) | Err(BackendError::NotFound) => Ok(()),
            Err(e) => Err(IndexError::from(e)),
        };
        let mut retired = RetiredKeyfiles::default();
        for old in self.keyfiles().await?.iter().filter(|m| lower(m)) {
            if purge {
                gone(self.backend.delete(&old.handle).await)?;
                retired.deleted += 1;
            } else {
                gone(self.backend.trash(&old.handle).await)?;
                retired.trashed += 1;
            }
        }
        if purge {
            let (_, trashed) = self.keyfiles_and_trashed().await?;
            for old in trashed.iter().filter(|m| m.handle != new.handle) {
                gone(self.backend.delete(&old.handle).await)?;
                retired.deleted_from_trash += 1;
            }
        }
        Ok(retired)
    }

    /// This device's current data folder (creates / rolls).
    pub async fn data_folder(&self) -> Result<Handle, IndexError> {
        let (id, n, count) = self.db.read(|c| {
            Ok::<_, StateError>((
                tables::meta_str(c, "data_folder_id")?,
                tables::meta_u64(c, "data_folder_n")?.unwrap_or(0),
                tables::meta_u64(c, "data_folder_count")?.unwrap_or(0),
            ))
        })?;
        if let Some(id) = id.filter(|_| count < DATA_FOLDER_MAX) {
            return Ok(Handle(id));
        }
        let n = n + 1;
        let number = u32::try_from(n).map_err(|_| plain_error("too many data folders"))?;
        let [id] = fresh_ids(&*self.backend).await?;
        let name = data_folder_name(self.device_id(), number);
        self.backend
            .create_folder(&id, &self.handles.data, &name)
            .await?;
        self.db.txn(|c| {
            tables::meta_set_str(c, "data_folder_id", &id.0)?;
            tables::meta_set_u64(c, "data_folder_n", n)?;
            tables::meta_set_u64(c, "data_folder_count", 0)
        })?;
        Ok(id)
    }

    /// Bumps `data_folder_count`.
    pub fn note_blob_created(&self) -> Result<(), IndexError> {
        self.db.txn(|c| {
            let count = tables::meta_u64(c, "data_folder_count")?.unwrap_or(0);
            tables::meta_set_u64(c, "data_folder_count", count + 1)
        })?;
        Ok(())
    }
}

/// Hooks for the property tests of `tests/index_props.rs`: the SQLite `HeadStore` without a
/// `Vault` around it.
#[doc(hidden)]
pub mod testing {
    use super::{ApplyStats, MemIndex, apply_segment, query, refresh};
    use crate::error::{IndexError, StateError};
    use crate::format::{SegmentV1, SnapshotV1};
    use crate::state::{Db, tables};
    use crate::types::Head;

    /// `apply_segment` on the SQLite store, in one transaction.
    pub fn apply(db: &Db, seg: &SegmentV1, removed_ms: u64) -> Result<ApplyStats, IndexError> {
        db.txn(|c| apply_segment(&mut tables::SqlStore(c), seg, removed_ms))
    }

    /// The replica as a `MemIndex` (heads, removed, blobs, devices, vault).
    pub fn dump(db: &Db) -> Result<MemIndex, IndexError> {
        Ok(db.read(query::mem_index)?)
    }

    /// The heads SQLite flags as winners, sorted by path.
    pub fn winners(db: &Db) -> Result<Vec<Head>, IndexError> {
        Ok(db.read(|c| tables::heads_query(c, "winner = 1 ORDER BY path", &[]))?)
    }

    /// Replaces the replica's content with `snap`, as a rebuild does.
    pub fn load_snapshot(db: &Db, snap: &SnapshotV1) -> Result<(), IndexError> {
        db.txn(|c| refresh::load_snapshot(c, snap))
    }

    /// Failure injection: drops a table so that the next statement touching it fails.
    pub fn drop_table(db: &Db, table: &str) -> Result<(), IndexError> {
        db.read(|c| {
            c.execute_batch(&format!("DROP TABLE {table}"))
                .map_err(StateError::from)
        })?;
        Ok(())
    }
}
