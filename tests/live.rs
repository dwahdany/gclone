//! The opt-in live run of SPEC §13 item 10 — owned by WP7.
//!
//! Every test is `#[ignore]` **and** returns at once unless `GCLONE_LIVE` is set, so `cargo test`
//! and a bare `cargo test -- --ignored` both pass without credentials:
//!
//! ```text
//! GCLONE_LIVE=1 cargo test --test live -- --ignored --test-threads 1
//! ```
//!
//! `GCLONE_LIVE=1` uses the login of the configured device (`gclone login` must have been run;
//! `secrets.json` is read through `config::secret_store`, the backend is built with
//! `cli::drive_backend(.., cache = false)`) and talks to the real Google Drive through the
//! user's deployed auth Worker. Everything is created inside one throwaway top-level folder
//! (`gclone-live-test-<hex>`), which is trashed at the end — also when a check fails. The
//! user's vault is never touched: the backend handed to the checks is scoped to that folder.
//!
//! `GCLONE_LIVE=mem` is a rehearsal of the same code against an in-memory backend that already
//! holds foreign objects (no network): it checks this file, not Google.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use gclone::backend::{
    AnyBackend, Backend, ByteStream, Handle, MemBackend, ObjMeta, PutBody, Quota,
};
use gclone::crypto::{KdfParams, Keyring, MasterKey, Passphrase};
use gclone::error::BackendError;
use gclone::format::{KeyfilePayload, open_keyfile, seal_keyfile};
use gclone::index::{CreateParams, OpenParams, Vault};
use gclone::state::Db;
use gclone::sync::{self, Direction, Mode, SyncOpts, SyncRequest};
use gclone::ui::Ui;

/// What `GCLONE_LIVE` asks for; `None` = the tests return at once.
enum Target {
    Drive,
    Mem,
}

fn target() -> Option<Target> {
    match std::env::var("GCLONE_LIVE").ok()?.as_str() {
        "1" => Some(Target::Drive),
        "mem" => Some(Target::Mem),
        _ => None,
    }
}

/// The backend of the configured device's login — or the in-memory stand-in, which already
/// holds objects that the checks must neither see nor touch.
async fn open_backend(target: Target) -> anyhow::Result<AnyBackend> {
    match target {
        Target::Mem => {
            let mem = MemBackend::default();
            let [folder, file] = &mem.new_ids(2).await?[..] else {
                unreachable!()
            };
            mem.create_folder(folder, &Handle::top(), "someone-elses-folder")
                .await?;
            // The names the conformance suite and vault discovery look for, outside the scope.
            for name in ["small.bin", "gclone-vault.json"] {
                let id = &mem.new_ids(1).await?[0];
                mem.put(id, folder, name, PutBody::Small("foreign".into()))
                    .await?;
            }
            mem.put(
                file,
                &Handle::top(),
                "top.bin",
                PutBody::Small("foreign".into()),
            )
            .await?;
            Ok(AnyBackend::Mem(mem))
        }
        Target::Drive => {
            let paths = gclone::config::Paths::resolve()?;
            let secrets = gclone::config::secret_store(&paths)
                .load()?
                .filter(|s| s.has_login())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "GCLONE_LIVE=1 needs a signed-in device: run `gclone login <AUTH_URL>` first"
                    )
                })?;
            let token = secrets.refresh_token.clone().unwrap_or_default();
            let (backend, _tokens) = gclone::cli::drive_backend(
                secrets.endpoints()?,
                &token,
                secrets.client,
                &paths,
                gclone::consts::TRANSFERS_DEFAULT,
                false,
            )?;
            Ok(AnyBackend::Drive(backend))
        }
    }
}

/// A backend whose top level is one folder of the real backend: what the checks create "at the
/// top" lands in that folder, and nothing outside it is listed, found or reported as a parent.
struct Scoped {
    inner: Arc<AnyBackend>,
    scope: Handle,
}

impl Scoped {
    fn inward(&self, h: &Handle) -> Handle {
        if h.is_top() {
            self.scope.clone()
        } else {
            h.clone()
        }
    }

    fn outward(&self, mut meta: ObjMeta) -> ObjMeta {
        if meta.parent == self.scope {
            meta.parent = Handle::top();
        }
        meta
    }

    /// Whether `meta` lives somewhere under the scope folder.
    async fn inside(&self, meta: &ObjMeta) -> Result<bool, BackendError> {
        let mut parent = meta.parent.clone();
        for _ in 0..32 {
            if parent == self.scope {
                return Ok(true);
            }
            if parent.is_top() {
                return Ok(false);
            }
            match self.inner.stat(&parent).await? {
                Some(up) => parent = up.parent,
                None => return Ok(false),
            }
        }
        Ok(false)
    }
}

impl Backend for Scoped {
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError> {
        self.inner.new_ids(n).await
    }

    async fn create_folder(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
    ) -> Result<(), BackendError> {
        self.inner
            .create_folder(id, &self.inward(parent), name)
            .await
    }

    async fn put(
        &self,
        id: &Handle,
        parent: &Handle,
        name: &str,
        body: PutBody,
    ) -> Result<ObjMeta, BackendError> {
        let meta = self.inner.put(id, &self.inward(parent), name, body).await?;
        Ok(self.outward(meta))
    }

    async fn get(
        &self,
        h: &Handle,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<ByteStream, BackendError> {
        self.inner.get(h, range).await
    }

    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError> {
        Ok(self.inner.stat(h).await?.map(|m| self.outward(m)))
    }

    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError> {
        let listed = self.inner.list(&self.inward(parent)).await?;
        Ok(listed.into_iter().map(|m| self.outward(m)).collect())
    }

    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError> {
        let mut found = Vec::new();
        for meta in self.inner.find_by_name(name).await? {
            if self.inside(&meta).await? {
                found.push(self.outward(meta));
            }
        }
        Ok(found)
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

/// Runs `check` on a backend scoped to a fresh throwaway folder and trashes that folder
/// afterwards, whatever the outcome.
async fn in_throwaway_folder<F, Fut>(what: &str, check: F)
where
    F: FnOnce(Scoped) -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let Some(target) = target() else {
        return;
    };
    let inner = Arc::new(open_backend(target).await.expect("the live backend"));
    let before = inner
        .list(&Handle::top())
        .await
        .expect("list the top level");
    let scope = inner.new_ids(1).await.expect("an id").remove(0);
    let name = format!(
        "gclone-live-test-{}",
        gclone::util::hex(&gclone::util::random::<4>())
    );
    inner
        .create_folder(&scope, &Handle::top(), &name)
        .await
        .expect("create the throwaway folder");
    eprintln!("{what}: working in the throwaway folder {name}");

    let scoped = Scoped {
        inner: inner.clone(),
        scope: scope.clone(),
    };
    // A task of its own, so that a failed assertion still reaches the clean-up below.
    let outcome = tokio::spawn(check(scoped)).await;
    inner
        .trash(&scope)
        .await
        .expect("trash the throwaway folder");

    let mut after = inner
        .list(&Handle::top())
        .await
        .expect("list the top level");
    after.retain(|m| m.handle != scope);
    let ids = |metas: &[ObjMeta]| {
        let mut ids: Vec<String> = metas.iter().map(|m| m.handle.0.clone()).collect();
        ids.sort();
        ids
    };
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{what}: {e:#}"),
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
    assert_eq!(
        ids(&before),
        ids(&after),
        "{what} left something behind at the top level"
    );
}

fn pattern(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut buf);
    buf
}

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().expect("UTF-8 name");
            let rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().expect("type").is_dir() {
                walk(&entry.path(), &rel, out);
            } else {
                out.insert(rel, std::fs::read(entry.path()).expect("read"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

fn request(direction: Direction, local_root: &Path) -> SyncRequest {
    SyncRequest {
        direction,
        mode: Mode::Sync,
        local_root: local_root.to_path_buf(),
        remote_prefix: "live".into(),
        own_dirs: Vec::new(),
        opts: SyncOpts {
            dry_run: false,
            checksum: false,
            force: false,
            excludes: Vec::new(),
            max_delete: None,
            assume_yes: true,
            transfers: 2,
            reset_pair: false,
            keep_pair: false,
        },
    }
}

/// The backend contract of §12.1 (WP2) against the live service: this is what confirms the
/// wire shapes of §6.4.1.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: needs GCLONE_LIVE=1 and a device signed in through the deployed auth Worker"]
async fn backend_conformance() {
    in_throwaway_folder("conformance", |backend| async move {
        gclone::backend::conformance::run(backend).await;
        Ok(())
    })
    .await;
}

/// A small end to end: a throwaway vault, one device pushes, a second one finds the vault,
/// unlocks it with the passphrase, pulls, and both end with the same tree and head.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: needs GCLONE_LIVE=1 and a device signed in through the deployed auth Worker"]
async fn two_devices_end_to_end() {
    in_throwaway_folder("end to end", |backend| async move {
        let backend = Arc::new(backend);
        let tmp = tempfile::tempdir()?;
        let ui = Ui::silent();
        let cancel = tokio_util::sync::CancellationToken::new();

        // A packed file, an empty file, a multipart blob and a resumable (two-part) one.
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("sub"))?;
        std::fs::write(src.join("small.txt"), b"hello, drive\n")?;
        std::fs::write(src.join("empty"), b"")?;
        std::fs::write(src.join("sub/medium.bin"), pattern(1, 1_500_000))?;
        std::fs::write(
            src.join("sub/large.bin"),
            pattern(2, 17 * 1024 * 1024 + 123),
        )?;

        // --- device one creates the vault and pushes
        let vault_id: [u8; 16] = gclone::util::random();
        let keys = Keyring::new(vault_id, vec![(1, MasterKey::generate())], 1)?;
        let pass = Passphrase::generate();
        let params = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let payload = KeyfilePayload::from_keyring(&keys, 1, "live-one", gclone::util::now_ms());
        let keyfile = seal_keyfile(&payload, &pass, params)?;
        let one = Vault::create(
            backend.clone(),
            Db::open(&tmp.path().join("one/state.db"))?,
            keys,
            CreateParams {
                vault_id,
                vault_name: "vault".into(),
                device_name: "live-one".into(),
                cache_dir: tmp.path().join("one/index-cache"),
                machine_fp: None,
                keyfile,
            },
        )
        .await?
        .0;
        let pushed = sync::run(&one, &request(Direction::Up, &src), &ui, cancel.clone()).await?;
        one.finish_mutation().await?;
        anyhow::ensure!(
            pushed.uploaded == 4 && pushed.exit_code() == 0,
            "push: {pushed:?}"
        );

        // --- device two discovers the vault, unlocks it with the passphrase and pulls
        let found = Vault::discover(&*backend).await?;
        anyhow::ensure!(
            found.len() == 1,
            "exactly the throwaway vault is visible: {found:?}"
        );
        let found = &found[0];
        anyhow::ensure!(found.vault_id == vault_id && found.keyfiles.len() == 1);
        let sealed = gclone::backend::get_all(&*backend, &found.keyfiles[0].handle, None).await?;
        let opened = open_keyfile(&found.keyfiles[0].name, &sealed, &pass)?;
        anyhow::ensure!(opened.vault_id_bytes()? == vault_id);
        Vault::verify_visible(&*backend, &found.handles).await?;
        let two = Vault::open(
            backend.clone(),
            Db::open(&tmp.path().join("two/state.db"))?,
            opened.keyring()?,
            OpenParams {
                vault_id,
                handles: found.handles.clone(),
                device_name: "live-two".into(),
                cache_dir: tmp.path().join("two/index-cache"),
                machine_fp: None,
            },
        )
        .await?;
        two.refresh().await?;
        let dst = tmp.path().join("dst");
        let pulled = sync::run(&two, &request(Direction::Down, &dst), &ui, cancel.clone()).await?;
        two.finish_mutation().await?;
        anyhow::ensure!(
            pulled.downloaded == 4 && pulled.exit_code() == 0,
            "pull: {pulled:?}"
        );
        anyhow::ensure!(snapshot(&src) == snapshot(&dst), "the pulled tree differs");

        // --- an edit and a delete flow back; both devices end on the same head
        std::fs::write(dst.join("small.txt"), b"edited on the second device\n")?;
        std::fs::remove_file(dst.join("sub/medium.bin"))?;
        sync::run(&two, &request(Direction::Up, &dst), &ui, cancel.clone()).await?;
        two.finish_mutation().await?;
        one.refresh().await?;
        sync::run(&one, &request(Direction::Down, &src), &ui, cancel).await?;
        one.finish_mutation().await?;
        anyhow::ensure!(
            snapshot(&src) == snapshot(&dst),
            "the trees differ after the round trip"
        );
        two.refresh().await?;
        anyhow::ensure!(
            one.head_fingerprint()? == two.head_fingerprint()?,
            "the heads differ"
        );
        let report = sync::check_download(&one, "", gclone::ui::Progress::hidden()).await?;
        anyhow::ensure!(report.ok(), "check --download: {report:?}");
        Ok(())
    })
    .await;
}
