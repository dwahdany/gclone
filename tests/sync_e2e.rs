//! End-to-end tests of the sync engine (SPEC §12.1 WP6): two or three `Vault`s on one
//! `MemBackend`, each with its own temp directory. A "device" runs the command flow of §10:
//! settle (`refresh → commit → resolve_conflicts`) → `sync::run` → `finish_mutation`.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gclone::backend::{Backend, Handle, MemBackend};
use gclone::consts::{GC_GRACE_MS, MIB, ORPHAN_GRACE_MS};
use gclone::crypto::{KdfParams, Keyring, MasterKey, Passphrase};
use gclone::error::{GuardKind, SyncError, TransferError};
use gclone::format::{KeyfilePayload, seal_keyfile};
use gclone::index::{CreateParams, OpenParams, Vault, VaultHandles};
use gclone::state::Db;
use gclone::sync::{
    self, Action, Direction, Mode, Plan, SkipReason, Summary, SyncOpts, SyncRequest, remote_ops,
};
use gclone::transfer::LocalExpect;
use gclone::types::EntryKind;
use gclone::ui::{Progress, Ui};
use tokio_util::sync::CancellationToken;

use Direction::{Down, Up};

const VAULT: [u8; 16] = [0x51; 16];
const DAY_MS: u64 = 86_400_000;

fn pattern(seed: u32, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&seed.to_le_bytes())
        .finalize_xof()
        .fill(&mut buf);
    buf
}

/// One "Drive" shared by every device of a test.
struct Net {
    backend: MemBackend,
    keys: Keyring,
    handles: VaultHandles,
    tmp: tempfile::TempDir,
    devices: std::sync::atomic::AtomicU8,
}

struct Dev {
    vault: Vault<MemBackend>,
    root: PathBuf,
}

impl Net {
    /// Creates the vault; returns the net and its first device.
    async fn new() -> (Net, Dev) {
        let backend = MemBackend::new();
        let tmp = tempfile::tempdir().unwrap();
        let keys = Keyring::new(VAULT, vec![(1, MasterKey::generate())], 1).unwrap();
        let keyfile = seal_keyfile(
            &KeyfilePayload::from_keyring(&keys, 1, "a", backend.now_ms()),
            &Passphrase::from_input("correct horse battery staple"),
            KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
            },
        )
        .unwrap();
        let (vault, found) = Vault::create(
            Arc::new(backend.clone()),
            Db::open_in_memory().unwrap(),
            keys.clone(),
            CreateParams {
                vault_id: VAULT,
                vault_name: "gclone".into(),
                device_name: "dev0".into(),
                cache_dir: tmp.path().join("cache0"),
                machine_fp: Some([0; 32]),
                keyfile,
            },
        )
        .await
        .unwrap();
        let root = tmp.path().join("root0");
        std::fs::create_dir(&root).unwrap();
        let net = Net {
            backend,
            keys,
            handles: found.handles,
            tmp,
            devices: 1.into(),
        };
        (net, Dev { vault, root })
    }

    /// Attaches another device with an empty sync root.
    async fn device(&self) -> Dev {
        let n = self
            .devices
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let vault = Vault::open(
            Arc::new(self.backend.clone()),
            Db::open_in_memory().unwrap(),
            self.keys.clone(),
            OpenParams {
                vault_id: VAULT,
                handles: self.handles.clone(),
                device_name: format!("dev{n}"),
                cache_dir: self.tmp.path().join(format!("cache{n}")),
                machine_fp: Some([n; 32]),
            },
        )
        .await
        .unwrap();
        vault.refresh().await.unwrap();
        let root = self.tmp.path().join(format!("root{n}"));
        std::fs::create_dir(&root).unwrap();
        Dev { vault, root }
    }
}

fn opts() -> SyncOpts {
    SyncOpts {
        dry_run: false,
        checksum: false,
        force: false,
        excludes: Vec::new(),
        max_delete: None,
        assume_yes: false,
        transfers: 2,
        reset_pair: false,
        keep_pair: false,
    }
}

impl Dev {
    fn req(&self, direction: Direction, mode: Mode) -> SyncRequest {
        SyncRequest {
            direction,
            mode,
            local_root: self.root.clone(),
            remote_prefix: String::new(),
            own_dirs: Vec::new(),
            opts: opts(),
        }
    }

    /// What `open_ctx` does before a mutating command (§10).
    async fn settle(&self) {
        self.vault.refresh().await.unwrap();
        self.vault.commit().await.unwrap();
        self.vault.resolve_conflicts().await.unwrap();
    }

    /// `sync::run` alone — the caller decides what the replica has seen.
    async fn run(&self, req: &SyncRequest) -> Result<Summary, SyncError> {
        sync::run(&self.vault, req, &Ui::silent(), CancellationToken::new()).await
    }

    /// The whole command: settle → run → finish_mutation.
    async fn cmd(&self, req: &SyncRequest) -> Result<Summary, SyncError> {
        self.settle().await;
        let summary = self.run(req).await?;
        self.vault.finish_mutation().await.unwrap();
        Ok(summary)
    }

    async fn up(&self) -> Summary {
        self.cmd(&self.req(Up, Mode::Sync)).await.unwrap()
    }

    async fn down(&self) -> Summary {
        self.cmd(&self.req(Down, Mode::Sync)).await.unwrap()
    }

    fn write(&self, rel: &str, data: &[u8]) {
        let p = self.root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn exists(&self, rel: &str) -> bool {
        std::fs::symlink_metadata(self.root.join(rel)).is_ok()
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(self.root.join(rel)).unwrap();
    }

    /// Every file under the root: relative path → content.
    fn tree(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let md = std::fs::symlink_metadata(&path).unwrap();
                if md.is_dir() {
                    walk(root, &path, out);
                } else if md.is_file() {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        if self.root.is_dir() {
            walk(&self.root, &self.root, &mut out);
        }
        out
    }

    fn names(&self) -> Vec<String> {
        self.tree().into_keys().collect()
    }

    /// The winners of the replica: path → kind.
    fn remote(&self) -> BTreeMap<String, EntryKind> {
        self.vault
            .walk("")
            .unwrap()
            .into_iter()
            .map(|h| (h.path, h.entry.kind))
            .collect()
    }

    fn remote_paths(&self) -> Vec<String> {
        self.remote().into_keys().collect()
    }

    /// The content of a remote file, through the index and the backend.
    async fn remote_content(&self, path: &str) -> Vec<u8> {
        let head = self
            .vault
            .head(path)
            .unwrap()
            .unwrap_or_else(|| panic!("{path} is not in the index"));
        let Some(loc) = &head.entry.loc else {
            return Vec::new();
        };
        let blob = self.vault.blob(&loc.blob).unwrap().unwrap();
        let mut out = Vec::new();
        gclone::transfer::read_range(
            &**self.vault.backend(),
            self.vault.keys(),
            &blob,
            &head,
            0..head.entry.size,
            &mut out,
        )
        .await
        .unwrap();
        out
    }
}

fn skipped(summary: &Summary) -> Vec<(&str, &SkipReason)> {
    let mut all: Vec<_> = summary
        .skipped
        .iter()
        .map(|(rel, reason)| (rel.as_str(), reason))
        .collect();
    all.sort_by(|a, b| a.0.cmp(b.0));
    all
}

fn clean(summary: &Summary) {
    assert!(summary.failed.is_empty(), "{:?}", summary.failed);
    assert!(summary.skipped.is_empty(), "{:?}", summary.skipped);
    assert_eq!(summary.exit_code(), 0);
}

fn conflict_paths(paths: &[String]) -> Vec<&String> {
    paths.iter().filter(|p| p.contains(".conflict-")).collect()
}

// ---------------------------------------------------------------------------------------------
// Push, pull, cycles
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn push_then_pull_is_byte_equal_and_a_second_sync_hashes_nothing() {
    let (net, a) = Net::new().await;
    a.write("empty", b"");
    a.write("small.txt", b"hello");
    a.write("docs/deep/er/notes.md", &pattern(1, 70_000));
    a.write("docs/big.bin", &pattern(2, (MIB + MIB / 2) as usize));
    a.write("bin/tool", b"#!/bin/sh\necho hi\n");
    std::fs::set_permissions(a.root.join("bin/tool"), PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::create_dir_all(a.root.join("hollow/inner")).unwrap();
    for i in 0..30u32 {
        a.write(
            &format!("many/f{i:02}"),
            &pattern(100 + i, 1 + 300 * i as usize),
        );
    }

    let up = a.up().await;
    clean(&up);
    assert_eq!(up.uploaded, 35);
    assert_eq!(
        up.bytes_up,
        a.tree().values().map(|v| v.len() as u64).sum::<u64>()
    );
    assert_eq!(a.remote().get("hollow/inner"), Some(&EntryKind::Dir));

    let b = net.device().await;
    let down = b.down().await;
    clean(&down);
    assert_eq!(down.downloaded, 35);
    assert_eq!(down.bytes_down, up.bytes_up);
    assert_eq!(a.tree(), b.tree());
    assert!(b.root.join("hollow/inner").is_dir());
    let mode = |d: &Dev, rel: &str| std::fs::metadata(d.root.join(rel)).unwrap().mode() & 0o111;
    assert_ne!(mode(&b, "bin/tool"), 0);
    assert_eq!(mode(&b, "small.txt"), 0);
    let mtime = |d: &Dev, rel: &str| {
        let md = std::fs::metadata(d.root.join(rel)).unwrap();
        md.mtime() * 1_000_000_000 + md.mtime_nsec()
    };
    for rel in ["small.txt", "docs/big.bin", "empty"] {
        assert!((mtime(&a, rel) - mtime(&b, rel)).abs() < 1_000, "{rel}");
    }

    // A second no-change sync after the download hashes nothing (§5.7 step 5).
    let again = b.down().await;
    clean(&again);
    assert_eq!(again.hashed, 0);
    assert_eq!((again.downloaded, again.meta_updates), (0, 0));
    let again = b.up().await;
    clean(&again);
    assert_eq!(
        (again.hashed, again.uploaded, again.deleted_remote),
        (0, 0, 0)
    );
}

#[tokio::test]
async fn modify_rename_delete_cycles_converge() {
    let (net, a) = Net::new().await;
    for i in 0..8u32 {
        a.write(&format!("d/f{i}"), &pattern(i, 2_000 + i as usize));
    }
    a.write("top", b"top v1");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    assert_eq!(a.tree(), b.tree());

    // A: modify, rename, delete, add.
    a.write("d/f0", b"f0 v2 with another length");
    std::fs::rename(a.root.join("d/f1"), a.root.join("d/renamed")).unwrap();
    a.remove("d/f2");
    a.write("new/file", b"new");
    let up = a.up().await;
    clean(&up);
    assert_eq!((up.uploaded, up.reused, up.deleted_remote), (2, 1, 2));
    let down = b.down().await;
    clean(&down);
    assert_eq!((down.downloaded, down.deleted_local), (3, 2));
    assert_eq!(a.tree(), b.tree());

    // B: the same kind of changes flow back; a directory emptied by the run disappears.
    b.write("top", b"top v2");
    b.remove("new/file");
    std::fs::remove_dir(b.root.join("new")).unwrap();
    clean(&b.up().await);
    let down = a.down().await;
    clean(&down);
    assert_eq!((down.downloaded, down.deleted_local), (1, 1));
    assert_eq!(a.tree(), b.tree());
    assert!(!a.exists("new"), "the emptied directory was removed");
    assert!(conflict_paths(&a.remote_paths()).is_empty());
}

#[tokio::test]
async fn copy_never_deletes_and_does_not_report_destination_only_files() {
    let (net, a) = Net::new().await;
    a.write("a", b"a");
    a.write("b", b"b");
    clean(&a.cmd(&a.req(Up, Mode::Copy)).await.unwrap());
    let b = net.device().await;
    b.write("mine", b"local only");
    let down = b.cmd(&b.req(Down, Mode::Copy)).await.unwrap();
    clean(&down);
    assert_eq!(down.downloaded, 2);

    // Deleted at the source: copy leaves the destination alone, in both directions.
    a.remove("a");
    let up = a.cmd(&a.req(Up, Mode::Copy)).await.unwrap();
    clean(&up);
    assert_eq!(up.deleted_remote, 0);
    assert_eq!(a.remote_paths(), ["a", "b"]);
    b.settle().await;
    remote_ops::rm(&b.vault, &["b".to_string()], false)
        .await
        .unwrap();
    let down = b.cmd(&b.req(Down, Mode::Copy)).await.unwrap();
    clean(&down);
    assert_eq!(b.names(), ["a", "b", "mine"]);
    // sync does delete, and reports what it leaves alone.
    let down = b.down().await;
    assert_eq!(down.deleted_local, 1);
    assert_eq!(skipped(&down), [("mine", &SkipReason::LocalOnly)]);
    assert_eq!(down.exit_code(), 6);
    assert_eq!(b.names(), ["a", "mine"]);
}

#[tokio::test]
async fn sync_under_a_remote_prefix_touches_nothing_outside_it() {
    let (net, a) = Net::new().await;
    a.write("x", b"x");
    let mut req = a.req(Up, Mode::Sync);
    req.remote_prefix = "Backups/laptop".into();
    clean(&a.cmd(&req).await.unwrap());
    a.settle().await;
    remote_ops::mkdir(&a.vault, "Other").await.unwrap();
    assert_eq!(a.remote_paths(), ["Backups/laptop/x", "Other"]);

    let b = net.device().await;
    let mut down = b.req(Down, Mode::Sync);
    down.remote_prefix = "Backups/laptop".into();
    clean(&b.cmd(&down).await.unwrap());
    assert_eq!(b.names(), ["x"]);
    // Deleting everything under the prefix leaves `Other` alone.
    a.remove("x");
    let mut req = a.req(Up, Mode::Sync);
    req.remote_prefix = "Backups/laptop".into();
    req.opts.force = true; // the source is empty (G2)
    let up = a.cmd(&req).await.unwrap();
    assert_eq!(up.deleted_remote, 1);
    assert_eq!(a.remote_paths(), ["Other"]);
    let mut bad = a.req(Up, Mode::Sync);
    bad.remote_prefix = "a//b".into();
    assert!(matches!(a.run(&bad).await, Err(SyncError::Usage(_))));
}

// ---------------------------------------------------------------------------------------------
// Several devices
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_stale_device_neither_deletes_nor_overwrites() {
    let (net, a) = Net::new().await;
    a.write("edited", b"v1");
    a.write("kept", b"same");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    a.write("edited", b"v2 from a");
    a.write("brand-new", b"only a has this");
    clean(&a.up().await);

    // B syncs up without having pulled: its tree lacks `brand-new` and has the old `edited`.
    let up = b.up().await;
    assert_eq!(
        skipped(&up),
        [
            ("brand-new", &SkipReason::RemoteOnly),
            ("edited", &SkipReason::RemoteNewer),
        ]
    );
    assert_eq!((up.uploaded, up.deleted_remote), (0, 0));
    assert_eq!(up.exit_code(), 6);
    assert_eq!(b.remote_paths(), ["brand-new", "edited", "kept"]);
    assert_eq!(b.remote_content("edited").await, b"v2 from a");
    assert_eq!(b.read("edited"), b"v1");

    // Pulling brings it up to date; then nothing is skipped.
    clean(&b.down().await);
    assert_eq!(a.tree(), b.tree());
    clean(&b.up().await);
}

#[tokio::test]
async fn concurrent_edits_keep_both_versions() {
    let (net, a) = Net::new().await;
    a.write("f.txt", b"base");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    a.write("f.txt", b"edit by a");
    b.write("f.txt", b"edit by b, longer");
    // Both plan against the same replica state: neither has seen the other's segment.
    a.settle().await;
    b.settle().await;
    let up_a = a.run(&a.req(Up, Mode::Sync)).await.unwrap();
    let up_b = b.run(&b.req(Up, Mode::Sync)).await.unwrap();
    assert_eq!((up_a.uploaded, up_b.uploaded), (1, 1));
    a.vault.finish_mutation().await.unwrap();
    b.vault.finish_mutation().await.unwrap();

    for dev in [&a, &b] {
        clean(&dev.down().await);
    }
    clean(&a.down().await);
    // Winner at the path, loser under the deterministic conflict name — on both devices.
    assert_eq!(a.tree(), b.tree());
    let names = a.names();
    assert_eq!(names.len(), 2, "{names:?}");
    let conflict = names.iter().find(|n| n.contains(".conflict-")).unwrap();
    assert!(conflict.starts_with("f.conflict-") && conflict.ends_with(".txt"));
    let contents: BTreeSet<Vec<u8>> = a.tree().into_values().collect();
    let expected: BTreeSet<Vec<u8>> = [b"edit by a".to_vec(), b"edit by b, longer".to_vec()].into();
    assert_eq!(contents, expected);
    assert!(a.vault.conflicts().unwrap().is_empty());
    assert_eq!(a.remote_paths(), names);
}

#[tokio::test]
async fn identical_first_syncs_make_no_conflict_copies() {
    let (net, a) = Net::new().await;
    let b = net.device().await;
    let c = net.device().await;
    let mtime = filetime::FileTime::from_unix_time(1_700_000_000, 0);
    for dev in [&a, &b, &c] {
        dev.write("same/one", &pattern(1, 5_000));
        dev.write("same/two", &pattern(2, (MIB + 5) as usize));
        dev.write("same/empty", b"");
        for name in ["same/one", "same/two", "same/empty"] {
            filetime::set_file_mtime(dev.root.join(name), mtime).unwrap();
        }
    }
    // A and B upload concurrently (neither sees the other's segment while planning).
    a.settle().await;
    b.settle().await;
    let up_a = a.run(&a.req(Up, Mode::Sync)).await.unwrap();
    let up_b = b.run(&b.req(Up, Mode::Sync)).await.unwrap();
    assert_eq!((up_a.uploaded, up_b.uploaded), (3, 3));
    a.vault.finish_mutation().await.unwrap();
    b.vault.finish_mutation().await.unwrap();
    // C syncs afterwards: equal content, nothing to send.
    let up_c = c.up().await;
    clean(&up_c);
    assert_eq!((up_c.uploaded, up_c.reused), (0, 0));

    for dev in [&a, &b, &c] {
        let s = dev.down().await;
        clean(&s);
        assert_eq!(s.downloaded, 0);
        assert_eq!(dev.remote_paths(), ["same/empty", "same/one", "same/two"]);
        assert!(dev.vault.conflicts().unwrap().is_empty());
        assert_eq!(dev.names(), ["same/empty", "same/one", "same/two"]);
    }
}

#[tokio::test]
async fn an_edit_survives_a_concurrent_delete() {
    let (net, a) = Net::new().await;
    a.write("doc", b"v1");
    a.write("other", b"o");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    a.remove("doc");
    b.write("doc", b"v2 edited on b");
    a.settle().await;
    b.settle().await;
    let up_a = a.run(&a.req(Up, Mode::Sync)).await.unwrap();
    let up_b = b.run(&b.req(Up, Mode::Sync)).await.unwrap();
    assert_eq!((up_a.deleted_remote, up_b.uploaded), (1, 1));
    a.vault.finish_mutation().await.unwrap();
    b.vault.finish_mutation().await.unwrap();

    clean(&a.down().await);
    clean(&b.down().await);
    assert_eq!(a.read("doc"), b"v2 edited on b");
    assert_eq!(a.tree(), b.tree());
    assert_eq!(a.remote_paths(), ["doc", "other"]);
}

#[tokio::test]
async fn a_first_sync_into_a_differing_destination_deletes_and_overwrites_nothing() {
    let (net, a) = Net::new().await;
    a.write("shared", b"remote version");
    a.write("remote-only", b"r");
    a.write("equal", b"equal");
    clean(&a.up().await);

    // DOWN into a non-empty directory that never synced.
    let b = net.device().await;
    b.write("shared", b"local version");
    b.write("local-only", b"l");
    b.write("equal", b"equal");
    let down = b.down().await;
    assert_eq!(skipped(&down), [("local-only", &SkipReason::LocalOnly)]);
    assert_eq!(
        (down.downloaded, down.conflicts, down.deleted_local),
        (2, 1, 0)
    );
    assert_eq!(b.read("shared"), b"remote version");
    assert_eq!(b.read("local-only"), b"l");
    let tree = b.tree();
    let aside: Vec<_> = tree
        .iter()
        .filter(|(name, _)| name.starts_with("shared.conflict-local-"))
        .collect();
    assert_eq!(aside.len(), 1, "{:?}", tree.keys());
    assert_eq!(aside[0].1, b"local version");

    // UP from a non-empty directory that never synced.
    let c = net.device().await;
    c.write("shared", b"third version");
    c.write("local-only", b"l");
    let up = c.up().await;
    assert_eq!(
        skipped(&up),
        [
            ("equal", &SkipReason::RemoteOnly),
            ("remote-only", &SkipReason::RemoteOnly),
        ]
    );
    assert_eq!((up.uploaded, up.conflicts, up.deleted_remote), (2, 1, 0));
    let paths = c.remote_paths();
    assert_eq!(paths.len(), 5, "{paths:?}");
    let conflict = conflict_paths(&paths);
    assert_eq!(conflict.len(), 1);
    assert_eq!(c.remote_content("shared").await, b"third version");
    assert_eq!(c.remote_content(conflict[0]).await, b"remote version");
}

#[tokio::test]
async fn a_local_conflict_is_moved_aside_before_the_download() {
    let (net, a) = Net::new().await;
    a.write("notes.txt", b"v1");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    a.write("notes.txt", b"v2 by a");
    clean(&a.up().await);
    b.write("notes.txt", b"v2 by b (unsynced)");

    let down = b.down().await;
    assert_eq!((down.downloaded, down.conflicts), (1, 1));
    assert!(down.skipped.is_empty() && down.failed.is_empty());
    assert_eq!(b.read("notes.txt"), b"v2 by a");
    let names = b.names();
    assert_eq!(names.len(), 2);
    let aside = names
        .iter()
        .find(|n| n.contains(".conflict-local-"))
        .unwrap();
    assert!(aside.starts_with("notes.conflict-local-") && aside.ends_with(".txt"));
    assert_eq!(b.read(aside), b"v2 by b (unsynced)");
    // Without --force an edited local file is not overwritten by an unchanged remote one …
    b.write("notes.txt", b"v3 by b");
    let down = b.down().await;
    assert!(skipped(&down).contains(&("notes.txt", &SkipReason::LocalChanged)));
    assert_eq!(b.read("notes.txt"), b"v3 by b");
    // … and with it, it is.
    let mut req = b.req(Down, Mode::Sync);
    req.opts.force = true;
    let down = b.cmd(&req).await.unwrap();
    assert_eq!(down.downloaded, 1);
    assert_eq!(b.read("notes.txt"), b"v2 by a");
}

#[tokio::test]
async fn adding_an_exclude_deletes_nothing_on_either_side() {
    let (net, a) = Net::new().await;
    a.write("src/main.rs", b"fn main() {}");
    a.write("node_modules/pkg/index.js", b"module.exports = 1");
    a.write("build.tmp", b"tmp");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    let all = a.remote_paths();
    assert_eq!(all.len(), 3);

    let excluded = |dev: &Dev, direction| {
        let mut req = dev.req(direction, Mode::Sync);
        req.opts.excludes = vec!["node_modules/".into(), "*.tmp".into()];
        req
    };
    // Base rows exist for the excluded keys on both devices.
    for (dev, direction) in [(&a, Up), (&b, Down), (&a, Down), (&b, Up)] {
        let s = dev.cmd(&excluded(dev, direction)).await.unwrap();
        clean(&s);
        assert_eq!(
            (s.deleted_remote, s.deleted_local, s.uploaded, s.downloaded),
            (0, 0, 0, 0)
        );
    }
    // Even when the excluded files are gone on one side.
    std::fs::remove_dir_all(a.root.join("node_modules")).unwrap();
    a.remove("build.tmp");
    let s = a.cmd(&excluded(&a, Up)).await.unwrap();
    clean(&s);
    assert_eq!(s.deleted_remote, 0);
    assert_eq!(a.remote_paths(), all);
    let s = b.cmd(&excluded(&b, Down)).await.unwrap();
    clean(&s);
    assert_eq!(b.names().len(), 3);

    // A device without base rows: the excluded remote rows are not downloaded either.
    let c = net.device().await;
    let s = c.cmd(&excluded(&c, Down)).await.unwrap();
    clean(&s);
    assert_eq!(c.names(), ["src/main.rs"]);
    // A `.gcloneignore` in the root does the same and is itself synced.
    let d = net.device().await;
    d.write(".gcloneignore", b"node_modules/\n*.tmp\n");
    let s = d.down().await;
    assert_eq!(skipped(&s), [(".gcloneignore", &SkipReason::LocalOnly)]);
    assert_eq!(d.names(), [".gcloneignore", "src/main.rs"]);
    let s = d.up().await;
    clean(&s);
    assert_eq!((s.uploaded, s.deleted_remote), (1, 0));
    assert_eq!(d.remote_paths().len(), 4);
}

// ---------------------------------------------------------------------------------------------
// API budgets (§6.6)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_negation_under_an_excluded_directory_deletes_and_duplicates_nothing() {
    let (net, a) = Net::new().await;
    a.write("build/keep.txt", b"keep");
    a.write("build/sub/deep.txt", b"deep");
    a.write("build/junk.o", b"junk");
    a.write("src/a.rs", b"a");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    let all = a.remote_paths();
    assert_eq!(all.len(), 4);

    // As in git, nothing under an ignored directory can be re-included: the walker never
    // looks inside `build`, and the remote rows and base rows under it are hidden with it.
    // (By the path alone `build/keep.txt` was visible remotely and in the base rows while
    // the local file was not: an upload deleted the remote copy, a download moved the local
    // file aside and fetched it again on every run.)
    let excluded = |dev: &Dev, direction| {
        let mut req = dev.req(direction, Mode::Sync);
        req.opts.excludes = vec![
            "build/".into(),
            "!build/keep.txt".into(),
            "!build/sub/".into(),
        ];
        req
    };
    for round in 0..2 {
        for (dev, direction) in [(&a, Up), (&b, Down), (&b, Up), (&a, Down)] {
            let s = dev.cmd(&excluded(dev, direction)).await.unwrap();
            clean(&s);
            assert_eq!(
                (
                    s.deleted_remote,
                    s.deleted_local,
                    s.uploaded,
                    s.downloaded,
                    s.conflicts
                ),
                (0, 0, 0, 0, 0),
                "round {round} {direction:?}"
            );
        }
    }
    assert_eq!(a.remote_paths(), all);
    assert_eq!(b.names(), all);
    assert_eq!(a.names(), all);

    // The same through a synced `.gcloneignore`.
    a.write(".gcloneignore", b"build/\n!build/keep.txt\n");
    let s = a.up().await;
    clean(&s);
    assert_eq!((s.uploaded, s.deleted_remote), (1, 0));
    assert!(a.remote_paths().contains(&"build/keep.txt".to_string()));
    let s = b.down().await;
    clean(&s);
    assert_eq!((s.downloaded, s.deleted_local, s.conflicts), (1, 0, 0));
    let s = b.down().await;
    clean(&s);
    assert_eq!((s.downloaded, s.deleted_local, s.conflicts), (0, 0, 0));
    assert!(conflict_paths(&b.names()).is_empty());

    // What does work: ignore the directory's content, not the directory.
    let c = net.device().await;
    let mut req = c.req(Down, Mode::Sync);
    req.opts.excludes = vec!["build/*".into(), "!build/keep.txt".into()];
    clean(&c.cmd(&req).await.unwrap());
    assert_eq!(c.names(), [".gcloneignore", "build/keep.txt", "src/a.rs"]);
}

#[tokio::test]
async fn an_exclude_that_matches_one_spelling_hides_the_key_on_both_sides() {
    let (net, a) = Net::new().await;
    a.write("Cache/x", b"x");
    a.write("Cache/sub/y", b"y");
    a.write("keep", b"k");
    clean(&a.up().await);
    let b = net.device().await;
    if !sync::probe_fold_case(&b.root).unwrap() {
        // `cache` and `Cache` are two directories here; the rule itself is covered by
        // `sync::scan`'s unit test on any file system.
        return;
    }
    // B has the same files under another spelling: one key each, in sync after one run.
    b.write("cache/x", b"x");
    b.write("cache/sub/y", b"y");
    clean(&b.down().await);
    let names = ["cache/sub/y", "cache/x", "keep"];
    assert_eq!(b.names(), names);
    let all = b.remote_paths();
    assert_eq!(all, ["Cache/sub/y", "Cache/x", "keep"]);

    // A pattern in the remote spelling (as a `.gcloneignore` written on A would carry it):
    // by spelling alone only the remote rows were hidden, and `sync` down deleted B's files.
    // A pattern in the local spelling hides the remote rows too.
    for pattern in ["Cache/", "cache/"] {
        for direction in [Down, Up] {
            let mut req = b.req(direction, Mode::Sync);
            req.opts.excludes = vec![pattern.into()];
            let s = b.cmd(&req).await.unwrap();
            clean(&s);
            assert_eq!(
                (s.deleted_local, s.deleted_remote, s.uploaded, s.downloaded),
                (0, 0, 0, 0),
                "{pattern} {direction:?}"
            );
            assert_eq!(b.names(), names);
            assert_eq!(b.remote_paths(), all);
        }
    }
    // A new local file under the excluded key is not uploaded under either pattern.
    b.write("cache/new", b"n");
    let mut req = b.req(Up, Mode::Sync);
    req.opts.excludes = vec!["Cache/".into()];
    let s = b.cmd(&req).await.unwrap();
    clean(&s);
    assert_eq!(s.uploaded, 0);
    assert_eq!(b.remote_paths(), all);
}

#[tokio::test]
async fn a_directory_rename_sends_no_data_and_one_segment() {
    let (net, a) = Net::new().await;
    for i in 0..20u32 {
        a.write(
            &format!("photos/2026/img{i:02}.jpg"),
            &pattern(i, 3_000 + 17 * i as usize),
        );
    }
    a.write("photos/big.raw", &pattern(77, (MIB + 1234) as usize));
    a.write("photos/empty.txt", b"");
    a.write("unrelated", b"u");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    std::fs::rename(a.root.join("photos"), a.root.join("pictures")).unwrap();
    net.backend.reset_counters();
    // To the planner a rename is 22 deletes of 23 entries: guard G4 wants a confirmation.
    assert!(matches!(
        a.cmd(&a.req(Up, Mode::Sync)).await,
        Err(SyncError::Guard(GuardKind::DeleteLimit {
            deletes: 22,
            total: 23
        }))
    ));
    net.backend.reset_counters();
    let mut confirmed = a.req(Up, Mode::Sync);
    confirmed.opts.assume_yes = true;
    let up = a.cmd(&confirmed).await.unwrap();
    clean(&up);
    let c = net.backend.counters();
    assert_eq!(c.put, 1, "one segment, no blob: {c:?}");
    assert!(c.put_bytes < 64 * 1024, "{c:?}");
    assert_eq!(c.create_folder, 0);
    // The zero-length file has no data to reuse: it is "uploaded" without a blob.
    assert_eq!(
        (up.reused, up.uploaded, up.deleted_remote, up.bytes_up),
        (21, 1, 22, 0)
    );
    // The 21 moved files with content, and `unrelated` once more (its row is still racy).
    assert!((21..=22).contains(&up.hashed), "{}", up.hashed);

    let mut confirmed = b.req(Down, Mode::Sync);
    confirmed.opts.assume_yes = true;
    let down = b.cmd(&confirmed).await.unwrap();
    clean(&down);
    assert_eq!(down.deleted_local, 22);
    assert_eq!(a.tree(), b.tree());
    assert!(!b.exists("photos"), "the emptied directory tree is gone");
    assert!(b.names().iter().any(|n| n == "pictures/2026/img07.jpg"));
}

#[tokio::test]
async fn a_no_change_sync_costs_one_list_and_no_put() {
    let (net, a) = Net::new().await;
    for i in 0..10u32 {
        a.write(&format!("f{i}"), &pattern(i, 1_000));
    }
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    for (dev, direction) in [(&a, Up), (&a, Down), (&b, Up), (&b, Down)] {
        // Let the first run after a transfer settle its base rows.
        dev.cmd(&dev.req(direction, Mode::Sync)).await.unwrap();
        net.backend.reset_counters();
        let s = dev.cmd(&dev.req(direction, Mode::Sync)).await.unwrap();
        clean(&s);
        let c = net.backend.counters();
        assert_eq!(c.list, 1, "{direction:?}: {c:?}");
        assert_eq!(
            (c.put, c.get, c.create_folder, c.trash, c.new_ids),
            (0, 0, 0, 0, 0),
            "{c:?}"
        );
    }
}

#[tokio::test]
async fn five_thousand_small_files_fit_the_put_budget() {
    let (net, a) = Net::new().await;
    let mut total = 0u64;
    for i in 0..5_000u32 {
        let data = pattern(i, 40 + (i % 97) as usize * 7);
        total += data.len() as u64;
        a.write(&format!("d{:02}/f{i:04}", i % 50), &data);
    }
    net.backend.reset_counters();
    let up = a.up().await;
    clean(&up);
    assert_eq!((up.uploaded, up.bytes_up), (5_000, total));
    let c = net.backend.counters();
    let budget = total.div_ceil(16 * MIB) + 2;
    assert!(
        c.put <= budget,
        "{} puts for {total} bytes (budget {budget}): {c:?}",
        c.put
    );
    assert_eq!(a.remote().len(), 5_000);
    // And the plan for the next run is empty without hashing the world again more than once.
    let again = a.up().await;
    clean(&again);
    assert_eq!((again.uploaded, again.reused), (0, 0));
}

#[tokio::test]
async fn a_dry_run_changes_nothing() {
    let (net, a) = Net::new().await;
    a.write("keep", b"k");
    a.write("gone", b"g");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    a.write("keep", b"k2");
    a.write("new", b"n");
    a.remove("gone");

    net.backend.reset_counters();
    a.settle().await;
    let mut req = a.req(Up, Mode::Sync);
    req.opts.dry_run = true;
    let s = a.run(&req).await.unwrap();
    assert!(s.dry_run);
    assert_eq!((s.uploaded, s.deleted_remote), (2, 1));
    let c = net.backend.counters();
    assert_eq!((c.put, c.create_folder, c.trash), (0, 0, 0));
    assert_eq!(a.remote_paths(), ["gone", "keep"]);
    assert_eq!(a.vault.db().pending_count().unwrap(), 0);

    clean(&a.up().await);
    let before = b.tree();
    b.settle().await;
    let mut req = b.req(Down, Mode::Sync);
    req.opts.dry_run = true;
    let s = b.run(&req).await.unwrap();
    assert_eq!((s.downloaded, s.deleted_local), (2, 1));
    assert_eq!(b.tree(), before);
    // A dry run into a directory that does not exist creates nothing.
    let mut req = b.req(Down, Mode::Sync);
    req.local_root = net.tmp.path().join("not-yet");
    req.opts.dry_run = true;
    let s = b.run(&req).await.unwrap();
    assert_eq!(s.downloaded, 2);
    assert!(!req.local_root.exists());
    // The real run creates it.
    req.opts.dry_run = false;
    let s = b.run(&req).await.unwrap();
    assert_eq!(s.downloaded, 2);
    assert_eq!(std::fs::read(req.local_root.join("new")).unwrap(), b"n");
}

// ---------------------------------------------------------------------------------------------
// Metadata, hashing, scan
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn meta_only_changes_send_no_data() {
    let (net, a) = Net::new().await;
    a.write("script.sh", b"#!/bin/sh\n");
    a.write("data", b"d");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    // chmod +x and a new mtime, same content.
    std::fs::set_permissions(a.root.join("script.sh"), PermissionsExt::from_mode(0o755)).unwrap();
    let earlier = filetime::FileTime::from_unix_time(1_500_000_000, 0);
    filetime::set_file_mtime(a.root.join("data"), earlier).unwrap();
    net.backend.reset_counters();
    let up = a.up().await;
    clean(&up);
    assert_eq!((up.meta_updates, up.uploaded, up.hashed), (2, 0, 2));
    assert_eq!(net.backend.counters().put, 1, "one segment");

    let down = b.down().await;
    clean(&down);
    assert_eq!((down.meta_updates, down.downloaded), (2, 0));
    let md = std::fs::metadata(b.root.join("script.sh")).unwrap();
    assert_ne!(md.mode() & 0o100, 0);
    assert_eq!(
        std::fs::metadata(b.root.join("data")).unwrap().mtime(),
        1_500_000_000
    );
    // Settled on both sides.
    for dev in [&a, &b] {
        for direction in [Up, Down] {
            let s = dev.cmd(&dev.req(direction, Mode::Sync)).await.unwrap();
            clean(&s);
            assert_eq!((s.meta_updates, s.uploaded, s.downloaded), (0, 0, 0));
        }
    }
}

#[tokio::test]
async fn equal_content_with_different_mtimes_settles_between_two_uploaders() {
    // The same bytes on two devices that both only upload, with mtimes years apart (a tree
    // copied without its times). Each device records the other's entry as equal content;
    // neither may then push its own mtime, or the other answers in kind on every sync.
    let (net, a) = Net::new().await;
    let b = net.device().await;
    for (dev, mtime) in [(&a, 1_580_000_000), (&b, 1_680_000_000)] {
        dev.write("f", b"the same bytes");
        dev.write("tool", b"#!/bin/sh\n");
        let mtime = filetime::FileTime::from_unix_time(mtime, 0);
        filetime::set_file_mtime(dev.root.join("f"), mtime).unwrap();
        filetime::set_file_mtime(dev.root.join("tool"), mtime).unwrap();
    }
    // The exec bit differs as well.
    std::fs::set_permissions(b.root.join("tool"), PermissionsExt::from_mode(0o755)).unwrap();
    let first = a.up().await;
    clean(&first);
    assert_eq!(first.uploaded, 2);
    let remote_meta = |dev: &Dev| {
        let head = |p: &str| dev.vault.head(p).unwrap().unwrap();
        (
            head("f").stamp,
            head("f").entry.mtime_ns,
            head("tool").stamp,
            head("tool").entry.exec,
        )
    };
    let settled = remote_meta(&a);
    for round in 0..3 {
        for dev in [&b, &a] {
            for run in 0..2 {
                let s = dev.up().await;
                clean(&s);
                assert_eq!(
                    (s.meta_updates, s.uploaded, s.reused),
                    (0, 0, 0),
                    "round {round} run {run}"
                );
            }
        }
    }
    assert_eq!(remote_meta(&b), settled);
    assert_eq!(remote_meta(&a), settled);
    // Each device kept its own times; nothing was written locally either.
    assert_eq!(
        std::fs::metadata(b.root.join("f")).unwrap().mtime(),
        1_680_000_000
    );
    assert_eq!(
        std::fs::metadata(a.root.join("f")).unwrap().mtime(),
        1_580_000_000
    );

    // A change made on B after that is B's to push, once.
    let later = filetime::FileTime::from_unix_time(1_700_000_000, 0);
    filetime::set_file_mtime(b.root.join("f"), later).unwrap();
    let s = b.up().await;
    clean(&s);
    assert_eq!(s.meta_updates, 1);
    assert_eq!(remote_meta(&b).1, 1_700_000_000_000_000_000);
    for dev in [&a, &b, &a] {
        let s = dev.up().await;
        clean(&s);
        assert_eq!(s.meta_updates, 0);
    }
    // A download aligns a device with the remote metadata and ends the difference for good.
    let s = a.down().await;
    clean(&s);
    assert_eq!((s.meta_updates, s.downloaded), (1, 0));
    let mtime = |dev: &Dev, rel: &str| std::fs::metadata(dev.root.join(rel)).unwrap().mtime();
    assert_eq!(mtime(&a, "f"), 1_700_000_000);
    let s = b.down().await;
    clean(&s);
    assert_eq!((s.meta_updates, s.downloaded), (1, 0));
    assert_eq!(mtime(&b, "tool"), 1_580_000_000);
    let tool = std::fs::metadata(b.root.join("tool")).unwrap();
    assert_eq!(tool.mode() & 0o111, 0, "the remote entry is not executable");
    for dev in [&a, &b] {
        for direction in [Up, Down] {
            let s = dev.cmd(&dev.req(direction, Mode::Sync)).await.unwrap();
            clean(&s);
            assert_eq!(s.meta_updates, 0);
        }
    }
}

#[tokio::test]
async fn a_download_never_widens_the_mode_of_an_existing_file() {
    let (net, a) = Net::new().await;
    a.write("secret.key", b"v1");
    a.write("run.sh", b"#!/bin/sh\n");
    std::fs::set_permissions(a.root.join("secret.key"), PermissionsExt::from_mode(0o600)).unwrap();
    std::fs::set_permissions(a.root.join("run.sh"), PermissionsExt::from_mode(0o700)).unwrap();
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    // Only the exec flag travels: B's copies are new files under B's umask.
    let mode =
        |dev: &Dev, rel: &str| std::fs::metadata(dev.root.join(rel)).unwrap().mode() & 0o7777;
    assert_eq!(mode(&b, "secret.key") & 0o111, 0);
    assert_ne!(mode(&b, "run.sh") & 0o100, 0);

    // B edits both; A pulls the new versions over its own private files.
    b.write("secret.key", b"v2, edited on B");
    b.write("run.sh", b"#!/bin/sh\necho 2\n");
    clean(&b.up().await);
    let down = a.down().await;
    clean(&down);
    assert_eq!(down.downloaded, 2);
    assert_eq!(a.read("secret.key"), b"v2, edited on B");
    assert_eq!(mode(&a, "secret.key"), 0o600);
    assert_eq!(mode(&a, "run.sh"), 0o700);
    // The kept mode is what the base row holds: nothing is left to do.
    for direction in [Up, Down] {
        let s = a.cmd(&a.req(direction, Mode::Sync)).await.unwrap();
        clean(&s);
        assert_eq!((s.meta_updates, s.uploaded, s.downloaded), (0, 0, 0));
    }
}

#[tokio::test]
async fn a_racy_row_is_rehashed_exactly_once() {
    let (_net, a) = Net::new().await;
    a.write("f", b"content");
    let up = a.up().await;
    assert_eq!(up.uploaded, 1);
    // The row was observed within 2 s of the file's mtime: it cannot vouch for the file.
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let second = a.up().await;
    clean(&second);
    assert_eq!((second.hashed, second.uploaded), (1, 0));
    let third = a.up().await;
    assert_eq!(third.hashed, 0);

    // A change inside the racy window that keeps the size is still found.
    a.write("g", b"aaaa");
    assert_eq!(a.up().await.uploaded, 1);
    a.write("g", b"bbbb");
    let s = a.up().await;
    assert_eq!((s.hashed, s.uploaded), (1, 1));
    assert_eq!(a.remote_content("g").await, b"bbbb");
}

#[tokio::test]
async fn chmod_costs_one_rehash() {
    let (_net, a) = Net::new().await;
    a.write("f", b"content");
    a.up().await;
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    assert_eq!(a.up().await.hashed, 1);
    assert_eq!(a.up().await.hashed, 0);

    // The ctime moves, the content does not (no exec bit involved).
    std::fs::set_permissions(a.root.join("f"), PermissionsExt::from_mode(0o600)).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let s = a.up().await;
    clean(&s);
    assert_eq!((s.hashed, s.uploaded, s.meta_updates), (1, 0, 0));
    assert_eq!(a.up().await.hashed, 0);
    // --checksum hashes regardless.
    let mut req = a.req(Up, Mode::Sync);
    req.opts.checksum = true;
    assert_eq!(a.cmd(&req).await.unwrap().hashed, 1);
}

#[tokio::test]
async fn a_synced_directory_replaced_by_a_symlink_deletes_nothing() {
    let (net, a) = Net::new().await;
    a.write("d/a", b"a");
    a.write("d/sub/b", b"b");
    a.write("file", b"f");
    a.write("keep", b"k");
    clean(&a.up().await);

    let elsewhere = net.tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir_all(a.root.join("d")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, a.root.join("d")).unwrap();
    // … and a synced file replaced by a FIFO.
    a.remove("file");
    let fifo = std::ffi::CString::new(a.root.join("file").to_str().unwrap()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let up = a.up().await;
    assert_eq!(up.deleted_remote, 0);
    let unsupported = |rel| {
        (
            rel,
            SkipReason::Unsupported("replaced by a symlink or a special file".into()),
        )
    };
    let got: Vec<(&str, SkipReason)> = skipped(&up)
        .into_iter()
        .map(|(r, s)| (r, s.clone()))
        .collect();
    assert_eq!(
        got,
        [
            unsupported("d/a"),
            unsupported("d/sub/b"),
            unsupported("file")
        ]
    );
    assert_eq!(a.remote_paths(), ["d/a", "d/sub/b", "file", "keep"]);
    // Nor does a download write through the symlink.
    let down = a.down().await;
    assert_eq!((down.downloaded, down.deleted_local), (0, 0));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[tokio::test]
async fn an_unreadable_subdirectory_suppresses_deletes_under_it() {
    let (net, a) = Net::new().await;
    a.write("locked/a", b"a");
    a.write("locked/deep/b", b"b");
    a.write("open/c", b"c");
    a.write("open/d", b"d");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    let locked = a.root.join("locked");
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o755)).unwrap();
        return; // running as root: permissions do not bind
    }
    a.remove("open/c");
    let up = a.cmd(&a.req(Up, Mode::Sync)).await;
    std::fs::set_permissions(&locked, PermissionsExt::from_mode(0o755)).unwrap();
    let up = up.unwrap();
    // The delete outside the unreadable directory is carried out, nothing under it is.
    assert_eq!(up.deleted_remote, 1);
    assert_eq!(
        skipped(&up),
        [
            ("locked/a", &SkipReason::ScanError),
            ("locked/deep/b", &SkipReason::ScanError),
        ]
    );
    assert_eq!(a.remote_paths(), ["locked/a", "locked/deep/b", "open/d"]);
    // Readable again: a clean run.
    clean(&a.up().await);
}

#[tokio::test]
async fn partial_and_probe_files_are_never_uploaded() {
    let (_net, a) = Net::new().await;
    a.write("real", b"r");
    a.write(".gclone-partial-0a1b2c3d", b"half a download");
    a.write("sub/.gclone-probe-ffffffff", b"");
    let up = a.up().await;
    clean(&up);
    assert_eq!(up.uploaded, 1);
    // `sub` holds nothing that is synced: it is an empty directory.
    assert_eq!(a.remote_paths(), ["real", "sub"]);
    assert!(
        a.exists(".gclone-partial-0a1b2c3d"),
        "a fresh partial file is left alone"
    );
}

// ---------------------------------------------------------------------------------------------
// Spelling and case
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_nfc_file_and_its_nfd_remote_twin_stay_one_entry() {
    const NFC: &str = "caf\u{e9}.txt";
    const NFD: &str = "cafe\u{301}.txt";
    let (net, a) = Net::new().await;
    // The remote twin is NFD (uploaded by a device whose file system kept that spelling).
    a.write(NFD, b"v1");
    clean(&a.up().await);
    let on_disk = a.names();
    if on_disk != [NFD] {
        return; // this file system rewrites names; the planner tests cover the rule
    }
    assert_eq!(a.remote_paths(), [NFD]);

    let b = net.device().await;
    b.write(NFC, b"v1");
    if b.names() != [NFC] {
        return;
    }
    // First sync: one key, equal content — nothing is sent or fetched.
    let s = b.up().await;
    clean(&s);
    assert_eq!(s.uploaded, 0);
    // Modified locally, synced up: one remote path (R's), no second entry.
    b.write(NFC, b"v2 from b");
    let s = b.up().await;
    clean(&s);
    assert_eq!(s.uploaded, 1);
    assert_eq!(b.remote_paths(), [NFD]);
    assert_eq!(b.remote_content(NFD).await, b"v2 from b");
    // Modified remotely, synced down: the existing local file is replaced, no second file.
    clean(&a.down().await);
    a.write(NFD, b"v3 from a");
    clean(&a.up().await);
    let s = b.down().await;
    clean(&s);
    assert_eq!(s.downloaded, 1);
    assert_eq!(b.names(), [NFC]);
    assert_eq!(b.read(NFC), b"v3 from a");
    assert_eq!(b.remote_paths(), [NFD]);
}

#[tokio::test]
async fn a_new_file_takes_the_remote_directory_spelling_on_a_folding_file_system() {
    let (net, a) = Net::new().await;
    a.write("foo/a", b"a");
    clean(&a.up().await);
    let b = net.device().await;
    let folds = sync::probe_fold_case(&b.root).unwrap();
    b.write("Foo/a", b"a");
    b.write("Foo/new", b"n");
    let up = b.up().await;
    if folds {
        // `Foo/a` and `foo/a` are one key; the new file goes under the existing spelling.
        clean(&up);
        assert_eq!(up.uploaded, 1);
        assert_eq!(b.remote_paths(), ["foo/a", "foo/new"]);
        // No download + delete pair for the twin, in either direction.
        let down = b.down().await;
        clean(&down);
        assert_eq!((down.downloaded, down.deleted_local), (0, 0));
        assert_eq!(b.names(), ["Foo/a", "Foo/new"]);
    } else {
        // Two directories. `Foo/a` is a path of its own whose content the vault already holds
        // (as `foo/a`): it is reused, and only `Foo/new` is sent. `foo/a` exists at the
        // destination alone, which a one-way sync reports and leaves.
        assert!(up.failed.is_empty(), "{:?}", up.failed);
        assert_eq!(skipped(&up), [("foo/a", &SkipReason::RemoteOnly)]);
        assert_eq!((up.uploaded, up.reused), (1, 1));
        assert_eq!(b.remote_paths(), ["Foo/a", "Foo/new", "foo/a"]);
        let down = b.down().await;
        clean(&down);
        assert_eq!((down.downloaded, down.deleted_local), (1, 0));
        assert_eq!(b.names(), ["Foo/a", "Foo/new", "foo/a"]);
    }
}

#[tokio::test]
async fn a_differently_spelled_entry_at_download_time_is_a_collision_skip() {
    let (net, a) = Net::new().await;
    a.write("docs/Readme.txt", b"remote");
    clean(&a.up().await);
    let b = net.device().await;
    b.vault.refresh().await.unwrap();
    let folds = sync::probe_fold_case(&b.root).unwrap();
    // The scan saw nothing; then `README.TXT` appears before the download finishes.
    b.write("docs/README.TXT", b"local, other spelling");
    let head = b.vault.head("docs/Readme.txt").unwrap().unwrap();
    let plan = Plan {
        actions: vec![Action::Download {
            key: "docs/readme.txt".into(),
            rel: "docs/Readme.txt".into(),
            head,
            expect_local: LocalExpect::Absent,
            keep_local: false,
        }],
        ..Plan::default()
    };
    let req = b.req(Down, Mode::Sync);
    let pair = b
        .vault
        .db()
        .pair_open(b.root.to_str().unwrap(), "", 1, 1, folds)
        .unwrap()
        .id;
    let s = sync::execute(
        &b.vault,
        pair,
        &req,
        plan,
        &Ui::silent(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    if folds {
        assert_eq!(
            skipped(&s),
            [("docs/Readme.txt", &SkipReason::KeyCollision)]
        );
        assert_eq!(s.downloaded, 0);
        // Nothing was moved aside or overwritten.
        assert_eq!(b.names(), ["docs/README.TXT"]);
        assert_eq!(b.read("docs/README.TXT"), b"local, other spelling");
        assert!(b.vault.db().base_all(pair).unwrap().is_empty());
    } else {
        assert_eq!(s.downloaded, 1);
        assert_eq!(b.names(), ["docs/README.TXT", "docs/Readme.txt"]);
    }
}

// ---------------------------------------------------------------------------------------------
// Type changes (§5.5.1)
// ---------------------------------------------------------------------------------------------

/// Two devices in sync on `{p, q, r}` built by `setup` on the first.
async fn synced_pair(setup: impl Fn(&Dev)) -> (Net, Dev, Dev) {
    let (net, a) = Net::new().await;
    setup(&a);
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);
    (net, a, b)
}

fn file_to_dir(dev: &Dev) {
    dev.remove("p");
    dev.write("p/one", b"1");
    dev.write("p/sub/two", b"22");
}

fn dir_to_file(dev: &Dev) {
    std::fs::remove_dir_all(dev.root.join("p")).unwrap();
    dev.write("p", b"now a file");
}

#[tokio::test]
async fn file_to_directory_converges_in_one_run_each_way() {
    let (_net, a, b) = synced_pair(|d| {
        d.write("p", b"was a file");
        d.write("q", b"q");
    })
    .await;
    file_to_dir(&a);
    let up = a.up().await;
    clean(&up);
    assert_eq!((up.uploaded, up.deleted_remote), (2, 1));
    assert_eq!(a.remote_paths(), ["p/one", "p/sub/two", "q"]);

    let down = b.down().await;
    clean(&down);
    assert_eq!((down.downloaded, down.deleted_local), (2, 1));
    assert_eq!(a.tree(), b.tree());
    for dev in [&a, &b] {
        dev.settle().await;
        assert!(conflict_paths(&dev.remote_paths()).is_empty());
        assert!(dev.vault.conflicts().unwrap().is_empty());
        clean(&dev.up().await);
        clean(&dev.down().await);
    }
}

#[tokio::test]
async fn directory_to_file_converges_in_one_run_each_way() {
    let (_net, a, b) = synced_pair(|d| {
        d.write("p/one", b"1");
        d.write("p/sub/two", b"22");
        d.write("q", b"q");
    })
    .await;
    dir_to_file(&a);
    let up = a.up().await;
    clean(&up);
    assert_eq!((up.uploaded, up.deleted_remote), (1, 2));
    assert_eq!(a.remote_paths(), ["p", "q"]);

    let down = b.down().await;
    clean(&down);
    assert_eq!((down.downloaded, down.deleted_local), (1, 2));
    assert_eq!(b.read("p"), b"now a file");
    assert_eq!(a.tree(), b.tree());
    for dev in [&a, &b] {
        dev.settle().await;
        assert!(conflict_paths(&dev.remote_paths()).is_empty());
        assert!(dev.vault.conflicts().unwrap().is_empty());
        clean(&dev.up().await);
        clean(&dev.down().await);
    }
}

#[tokio::test]
async fn a_type_change_lands_in_one_segment() {
    // No device may ever see the file and the directory together: a third device that
    // refreshes after the run finds no conflict name, although it never resolved anything.
    for to_dir in [true, false] {
        let (net, a) = Net::new().await;
        if to_dir {
            a.write("p", b"file");
        } else {
            a.write("p/one", b"1");
            a.write("p/sub/two", b"22");
        }
        clean(&a.up().await);
        if to_dir {
            file_to_dir(&a);
        } else {
            dir_to_file(&a);
        }
        a.settle().await;
        let before = a.vault.stats(net.backend.now_ms()).unwrap().segments;
        clean(&a.run(&a.req(Up, Mode::Sync)).await.unwrap());
        let after = a.vault.stats(net.backend.now_ms()).unwrap().segments;
        assert_eq!(after - before, 1, "deletes and puts share one segment");
        let c = net.device().await;
        assert_eq!(c.vault.resolve_conflicts().await.unwrap(), 0);
        assert!(conflict_paths(&c.remote_paths()).is_empty());
    }
}

#[tokio::test]
async fn a_local_only_file_keeps_the_old_directory_and_other_deletes_still_run() {
    let (_net, a, b) = synced_pair(|d| {
        d.write("p/one", b"1");
        d.write("p/two", b"2");
        d.write("q", b"q");
        d.write("r", b"r");
    })
    .await;
    dir_to_file(&a);
    a.remove("q");
    clean(&a.up().await);

    b.write("p/mine", b"not synced");
    let down = b.down().await;
    assert_eq!(
        skipped(&down),
        [
            ("p", &SkipReason::UnsafeTarget),
            ("p/mine", &SkipReason::LocalOnly)
        ]
    );
    assert!(down.failed.is_empty());
    assert!(!down.deletes_suppressed);
    // The directory stays with the local-only file; the delete of another key ran.
    assert!(b.root.join("p").is_dir());
    assert_eq!(b.read("p/mine"), b"not synced");
    assert!(!b.exists("q"));
    assert!(b.exists("r"));

    // The same when the file is invisible to the scan (excluded): found at run time.
    let (_net, a, b) = synced_pair(|d| {
        d.write("p/one", b"1");
        d.write("q", b"q");
    })
    .await;
    dir_to_file(&a);
    a.remove("q");
    clean(&a.up().await);
    b.write("p/cache.tmp", b"excluded");
    let mut req = b.req(Down, Mode::Sync);
    req.opts.excludes = vec!["*.tmp".into()];
    let down = b.cmd(&req).await.unwrap();
    assert_eq!(skipped(&down), [("p", &SkipReason::UnsafeTarget)]);
    assert_eq!(down.deleted_local, 2);
    assert!(b.root.join("p").is_dir() && b.exists("p/cache.tmp"));
    assert!(!b.exists("p/one") && !b.exists("q"));
    // Once the file is gone the next run completes the change.
    b.remove("p/cache.tmp");
    let down = b.cmd(&req).await.unwrap();
    clean(&down);
    assert_eq!(b.read("p"), b"now a file");
}

#[tokio::test]
async fn copy_skips_a_type_change() {
    let unsupported = SkipReason::Unsupported("type change: use sync".into());
    let (_net, a, b) = synced_pair(|d| {
        d.write("p", b"file");
        d.write("q", b"q");
    })
    .await;
    file_to_dir(&a);
    let up = a.cmd(&a.req(Up, Mode::Copy)).await.unwrap();
    assert_eq!(
        skipped(&up),
        [("p/one", &unsupported), ("p/sub/two", &unsupported)]
    );
    assert_eq!((up.uploaded, up.deleted_remote), (0, 0));
    assert_eq!(a.remote_paths(), ["p", "q"]);
    // sync carries it out; a copy down on the other device skips it again.
    clean(&a.up().await);
    let down = b.cmd(&b.req(Down, Mode::Copy)).await.unwrap();
    assert_eq!(
        skipped(&down),
        [("p/one", &unsupported), ("p/sub/two", &unsupported)]
    );
    assert_eq!(b.read("p"), b"file");
}

#[tokio::test]
async fn an_unsynced_file_in_the_way_of_a_remote_directory_is_moved_aside() {
    let (net, a) = Net::new().await;
    std::fs::create_dir_all(a.root.join("x")).unwrap();
    a.write("y/inside", b"i");
    clean(&a.up().await);
    // B never synced and has files where the remote has directories.
    let b = net.device().await;
    b.write("x", b"a file named like the remote's empty directory");
    b.write("y", b"a file named like the remote's directory");
    let down = b.down().await;
    // `x`: both sides are new and differ — the file is kept under a conflict name and the
    // directory is created. `y`: the file is local-only and in the way of `y/inside`.
    assert_eq!(
        skipped(&down),
        [
            ("y", &SkipReason::LocalOnly),
            ("y/inside", &SkipReason::UnsafeTarget)
        ]
    );
    assert!(down.failed.is_empty());
    assert!(b.root.join("x").is_dir());
    let names = b.names();
    assert_eq!(names.len(), 2, "{names:?}");
    let aside = names
        .iter()
        .find(|n| n.starts_with("x.conflict-local-"))
        .unwrap();
    assert_eq!(
        b.read(aside),
        b"a file named like the remote's empty directory"
    );
    assert_eq!(b.read("y"), b"a file named like the remote's directory");
    // Upward the same clash is settled by the index: the file wins the path.
    let c = net.device().await;
    c.write("x", b"file wins");
    let up = c.up().await;
    assert_eq!(up.uploaded, 1);
    assert_eq!(c.remote().get("x"), Some(&EntryKind::File));
    assert!(c.vault.conflicts().unwrap().is_empty());
}

#[tokio::test]
async fn an_empty_directory_and_a_file_swap_within_one_key() {
    let (_net, a, b) = synced_pair(|d| {
        d.write("thing", b"file");
        std::fs::create_dir(d.root.join("other")).unwrap();
    })
    .await;
    assert_eq!(b.remote().get("other"), Some(&EntryKind::Dir));
    // file → empty directory, empty directory → file
    a.remove("thing");
    std::fs::create_dir(a.root.join("thing")).unwrap();
    std::fs::remove_dir(a.root.join("other")).unwrap();
    a.write("other", b"now a file");
    let up = a.up().await;
    clean(&up);
    assert_eq!(a.remote().get("thing"), Some(&EntryKind::Dir));
    assert_eq!(a.remote().get("other"), Some(&EntryKind::File));

    let down = b.down().await;
    clean(&down);
    assert!(b.root.join("thing").is_dir());
    assert_eq!(b.read("other"), b"now a file");
    assert!(conflict_paths(&b.remote_paths()).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Guards at run level (G4, G6)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_delete_guard_needs_yes_without_a_terminal() {
    let (_net, a) = Net::new().await;
    for i in 0..30 {
        a.write(&format!("f{i:02}"), format!("{i}").as_bytes());
    }
    clean(&a.up().await);
    for i in 0..10 {
        a.remove(&format!("f{i:02}"));
    }
    let err = a.cmd(&a.req(Up, Mode::Sync)).await.unwrap_err();
    assert!(matches!(
        err,
        SyncError::Guard(GuardKind::DeleteLimit {
            deletes: 10,
            total: 30
        })
    ));
    assert_eq!(gclone::error::exit_code(&err.into()), 5);
    assert_eq!(a.remote().len(), 30, "nothing was deleted");
    // --max-delete replaces the test and is a hard limit: --yes does not lift it.
    let mut req = a.req(Up, Mode::Sync);
    req.opts.max_delete = Some(9);
    for assume_yes in [false, true] {
        req.opts.assume_yes = assume_yes;
        let err = a.cmd(&req).await.unwrap_err();
        assert!(
            matches!(
                err,
                SyncError::Guard(GuardKind::MaxDelete {
                    deletes: 10,
                    limit: 9
                })
            ),
            "{err:?}"
        );
        assert_eq!(gclone::error::exit_code(&err.into()), 5);
        assert_eq!(a.remote().len(), 30, "nothing was deleted");
    }
    // A dry run only warns.
    req.opts.dry_run = true;
    let dry = a.cmd(&req).await.unwrap();
    assert_eq!((dry.dry_run, dry.deleted_remote), (true, 10));
    assert_eq!(a.remote().len(), 30);
    req.opts.dry_run = false;
    req.opts.assume_yes = false;
    req.opts.max_delete = Some(10);
    assert_eq!(a.cmd(&req).await.unwrap().deleted_remote, 10);
    for i in 10..20 {
        a.remove(&format!("f{i:02}"));
    }
    let mut req = a.req(Up, Mode::Sync);
    req.opts.assume_yes = true;
    assert_eq!(a.cmd(&req).await.unwrap().deleted_remote, 10);
    assert_eq!(a.remote().len(), 10);
}

#[tokio::test]
async fn an_empty_source_is_refused_unless_forced() {
    let (net, a) = Net::new().await;
    a.write("f", b"f");
    clean(&a.up().await);
    a.remove("f");
    let err = a.cmd(&a.req(Up, Mode::Sync)).await.unwrap_err();
    assert!(matches!(err, SyncError::Guard(GuardKind::EmptySource)));
    assert_eq!(a.remote_paths(), ["f"]);
    // A root that does not exist is refused whatever the pair knows.
    let mut req = a.req(Up, Mode::Sync);
    req.local_root = net.tmp.path().join("unmounted");
    let err = a.run(&req).await.unwrap_err();
    assert!(matches!(err, SyncError::Guard(GuardKind::EmptySource)));
    // --force carries the (single) delete out.
    let mut req = a.req(Up, Mode::Sync);
    req.opts.force = true;
    assert_eq!(a.cmd(&req).await.unwrap().deleted_remote, 1);
}

#[tokio::test]
async fn a_replaced_root_is_refused_until_the_user_says_which_it_is() {
    let (net, a) = Net::new().await;
    a.write("stays", b"s");
    a.write("vanishes", b"v");
    clean(&a.up().await);
    // Running twice on the same directory: same identity, whatever st_dev says.
    clean(&a.up().await);

    // The directory is replaced by another one of the same name without `vanishes`
    // (a restore, a re-created mount point): new inode, new birth time.
    let replace = |dev: &Dev| {
        let old = net.tmp.path().join(format!(
            "old-{}",
            gclone::util::hex(&gclone::util::random::<4>())
        ));
        std::fs::rename(&dev.root, &old).unwrap();
        std::fs::create_dir(&dev.root).unwrap();
        dev.write("stays", b"s");
        let (new, old) = (
            std::fs::metadata(&dev.root).unwrap(),
            std::fs::metadata(&old).unwrap(),
        );
        assert_ne!(new.ino(), old.ino());
        assert_eq!(new.dev(), old.dev());
    };
    replace(&a);
    for direction in [Up, Down] {
        let err = a.cmd(&a.req(direction, Mode::Sync)).await.unwrap_err();
        assert!(
            matches!(err, SyncError::Guard(GuardKind::RootChanged)),
            "{err}"
        );
        assert_eq!(gclone::error::exit_code(&err.into()), 5);
    }
    assert_eq!(a.remote_paths(), ["stays", "vanishes"]);
    let mut both = a.req(Up, Mode::Sync);
    (both.opts.reset_pair, both.opts.keep_pair) = (true, true);
    assert!(matches!(a.cmd(&both).await, Err(SyncError::Usage(_))));

    // --reset-pair: the rows are dropped — a conservative first sync that deletes nothing.
    let mut reset = a.req(Up, Mode::Sync);
    reset.opts.reset_pair = true;
    let s = a.cmd(&reset).await.unwrap();
    assert_eq!(s.deleted_remote, 0);
    assert_eq!(skipped(&s), [("vanishes", &SkipReason::RemoteOnly)]);
    assert_eq!(a.remote_paths(), ["stays", "vanishes"]);
    // The new identity is recorded: the next plain run is not refused.
    let s = a.up().await;
    assert_eq!(skipped(&s), [("vanishes", &SkipReason::RemoteOnly)]);

    // --keep-pair: the rows are kept — the missing file counts as deleted.
    clean(&a.down().await);
    replace(&a);
    assert!(a.cmd(&a.req(Up, Mode::Sync)).await.is_err());
    let mut keep = a.req(Up, Mode::Sync);
    keep.opts.keep_pair = true;
    let s = a.cmd(&keep).await.unwrap();
    assert_eq!(s.deleted_remote, 1);
    assert_eq!(a.remote_paths(), ["stays"]);
    clean(&a.up().await);
}

#[tokio::test]
async fn reset_pair_is_honoured_when_the_root_is_the_same_directory() {
    // The tree was damaged inside the same directory (a restore into the existing folder, an
    // accidental `rm`): the inode did not change, so G6 does not fire — and the flag still
    // has to give the first sync it promises.
    let (_net, a) = Net::new().await;
    a.write("stays", b"s");
    a.write("vanishes", b"v");
    a.write("local-only-later", b"l");
    clean(&a.up().await);
    a.remove("vanishes");
    let all = ["local-only-later", "stays", "vanishes"];

    // Upward: the missing file is "only on the remote", not a delete. A dry run shows the
    // same plan and drops nothing.
    let mut reset = a.req(Up, Mode::Sync);
    reset.opts.reset_pair = true;
    let mut dry = reset.clone();
    dry.opts.dry_run = true;
    for req in [&dry, &reset] {
        let s = a.cmd(req).await.unwrap();
        assert_eq!(s.deleted_remote, 0, "dry={}", s.dry_run);
        assert_eq!(skipped(&s), [("vanishes", &SkipReason::RemoteOnly)]);
        assert_eq!(a.remote_paths(), all);
    }
    // The rows are gone for good: the next plain run does not delete either.
    let s = a.up().await;
    assert_eq!(skipped(&s), [("vanishes", &SkipReason::RemoteOnly)]);
    // After the dry run alone the rows would still have been there.
    clean(&a.down().await);
    assert_eq!(a.names(), all);

    // Downward: a synced file that was deleted remotely is "only local", not a delete.
    a.settle().await;
    remote_ops::rm(&a.vault, &["local-only-later".to_string()], false)
        .await
        .unwrap();
    let mut reset = a.req(Down, Mode::Sync);
    reset.opts.reset_pair = true;
    let s = a.cmd(&reset).await.unwrap();
    assert_eq!(s.deleted_local, 0);
    assert_eq!(skipped(&s), [("local-only-later", &SkipReason::LocalOnly)]);
    assert_eq!(a.names(), all);

    // Without the flag the same damage is an ordinary change.
    a.remove("vanishes");
    let s = a.up().await;
    assert_eq!((s.deleted_remote, s.uploaded), (1, 1));
    // --keep-pair with an unchanged root asks for what happens anyway.
    a.remove("stays");
    let mut keep = a.req(Up, Mode::Sync);
    keep.opts.keep_pair = true;
    let s = a.cmd(&keep).await.unwrap();
    clean(&s);
    assert_eq!(s.deleted_remote, 1);
    assert_eq!(a.remote_paths(), ["local-only-later"]);
}

#[tokio::test]
async fn a_directory_with_a_remote_marker_survives_the_delete_of_its_last_file() {
    let (net, a) = Net::new().await;
    std::fs::create_dir(a.root.join("d")).unwrap();
    a.write("keep", b"k");
    clean(&a.up().await);
    a.write("d/a", b"a");
    clean(&a.up().await);
    assert_eq!(a.remote()["d"], EntryKind::Dir);
    let b = net.device().await;
    clean(&b.down().await);
    assert_eq!(b.names(), ["d/a", "keep"]);

    // A deletes the file and keeps the directory: the marker stays.
    a.remove("d/a");
    let s = a.up().await;
    clean(&s);
    assert_eq!(s.deleted_remote, 1);
    assert_eq!(a.remote_paths(), ["d", "keep"]);

    // B follows: the file goes, the directory the remote still names stays.
    let s = b.down().await;
    clean(&s);
    assert_eq!(s.deleted_local, 1);
    assert!(b.root.join("d").is_dir(), "the marked directory was pruned");
    // So B's next upload has nothing to say about it …
    let s = b.up().await;
    clean(&s);
    assert_eq!(s.deleted_remote, 0);
    assert_eq!(b.remote_paths(), ["d", "keep"]);
    // … and A keeps the directory its user never removed.
    let s = a.down().await;
    clean(&s);
    assert_eq!(s.deleted_local, 0);
    assert!(a.root.join("d").is_dir());

    // A directory without a marker is still pruned with its last file.
    a.write("plain/sub/f", b"f");
    clean(&a.up().await);
    clean(&b.down().await);
    a.remove("plain/sub/f");
    std::fs::remove_dir_all(a.root.join("plain")).unwrap();
    clean(&a.up().await);
    let s = b.down().await;
    clean(&s);
    assert_eq!(s.deleted_local, 1);
    assert!(!b.exists("plain"));
    // Removing the marked directory itself is the user's delete and travels.
    std::fs::remove_dir(b.root.join("d")).unwrap();
    let s = b.up().await;
    clean(&s);
    assert_eq!(s.deleted_remote, 1);
    let s = a.down().await;
    clean(&s);
    assert!(!a.exists("d"));
}

#[tokio::test]
async fn a_directory_emptied_by_an_upload_stays_a_directory_on_every_device() {
    let (net, a) = Net::new().await;
    a.write("d/sub/f", b"f");
    a.write("d/g", b"g");
    a.write("keep", b"k");
    clean(&a.up().await);
    let b = net.device().await;
    clean(&b.down().await);

    // A removes everything under `d` and keeps `d` itself: one run deletes the files and
    // records the now empty directory — not the next one.
    std::fs::remove_dir_all(a.root.join("d/sub")).unwrap();
    a.remove("d/g");
    let s = a.up().await;
    clean(&s);
    assert_eq!((s.deleted_remote, s.dirs_created), (2, 1));
    assert_eq!(a.remote_paths(), ["d", "keep"]);
    assert_eq!(a.remote()["d"], EntryKind::Dir);
    let s = a.up().await;
    clean(&s);
    assert_eq!((s.deleted_remote, s.dirs_created), (0, 0));

    // B follows: the files and `d/sub` go, `d` stays.
    let s = b.down().await;
    clean(&s);
    assert_eq!(s.deleted_local, 2);
    assert!(b.root.join("d").is_dir() && !b.exists("d/sub"));
    // Neither direction has anything left to say on either device.
    for dev in [&a, &b] {
        let (up, down) = (dev.up().await, dev.down().await);
        clean(&up);
        clean(&down);
        assert_eq!((up.dirs_created, up.deleted_remote), (0, 0));
        assert_eq!((down.dirs_created, down.deleted_local), (0, 0));
        assert!(dev.root.join("d").is_dir());
    }
    assert_eq!(a.remote_paths(), ["d", "keep"]);
}

// ---------------------------------------------------------------------------------------------
// Remote-only commands (§5.5.4)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn mkdir_rm_mv_are_index_only() {
    let (net, a) = Net::new().await;
    a.write("docs/a.txt", b"a");
    a.write("docs/sub/b.txt", b"bb");
    a.write("top", b"t");
    clean(&a.up().await);
    net.backend.reset_counters();
    let v = &a.vault;

    // mkdir: a Dir entry; a no-op when the directory exists (explicitly or implied).
    remote_ops::mkdir(v, "new/dir").await.unwrap();
    assert_eq!(a.remote().get("new/dir"), Some(&EntryKind::Dir));
    let puts = net.backend.counters().put;
    assert_eq!(puts, 1, "one segment");
    remote_ops::mkdir(v, "new/dir").await.unwrap();
    remote_ops::mkdir(v, "docs").await.unwrap();
    remote_ops::mkdir(v, "new").await.unwrap();
    assert_eq!(net.backend.counters().put, puts);
    assert!(matches!(
        remote_ops::mkdir(v, "top").await,
        Err(SyncError::Usage(_))
    ));
    assert!(matches!(
        remote_ops::mkdir(v, "top/below").await,
        Err(SyncError::Usage(_))
    ));
    assert!(matches!(
        remote_ops::mkdir(v, "bad//path").await,
        Err(SyncError::Usage(_))
    ));

    // mv of a directory: every entry moves, puts and dels in one segment, no data.
    let moved = remote_ops::mv(v, "docs", "papers", false).await.unwrap();
    assert_eq!(
        (moved.to.as_str(), moved.entries, moved.replaced),
        ("papers", 2, 0)
    );
    assert_eq!(
        a.remote_paths(),
        ["new/dir", "papers/a.txt", "papers/sub/b.txt", "top"]
    );
    assert_eq!(net.backend.counters().put, puts + 1);
    assert_eq!(a.remote_content("papers/sub/b.txt").await, b"bb");
    let moved = v.head("papers/a.txt").unwrap().unwrap();
    assert!(moved.origin.is_some());
    // mv of one file onto an existing file: only with `force`, and the replaced version
    // stays restorable.
    assert!(matches!(
        remote_ops::mv(v, "top", "papers/a.txt", false).await,
        Err(SyncError::Usage(_))
    ));
    assert_eq!(a.remote_content("papers/a.txt").await, b"a");
    let moved = remote_ops::mv(v, "top", "papers/a.txt", true)
        .await
        .unwrap();
    assert_eq!((moved.entries, moved.replaced), (1, 1));
    assert_eq!(a.remote_content("papers/a.txt").await, b"t");
    assert_eq!(v.removed_versions("papers/a.txt").unwrap().len(), 1);
    // Refusals.
    let before = net.backend.counters().put;
    for (from, to) in [
        ("papers", "papers/sub/x"),
        ("papers", "papers"),
        ("papers/sub", "papers/a.txt"),
        ("papers", "papers/a.txt/x"),
        ("papers/a.txt", "papers/a.txt"),
    ] {
        for force in [false, true] {
            assert!(
                matches!(
                    remote_ops::mv(v, from, to, force).await,
                    Err(SyncError::Usage(_))
                ),
                "{from} -> {to}"
            );
        }
    }
    assert!(matches!(
        remote_ops::mv(v, "nothing", "x", false).await,
        Err(SyncError::Io(_))
    ));
    assert_eq!(
        net.backend.counters().put,
        before,
        "a refusal commits nothing"
    );

    // rm: a file; a directory only with -r; several paths in one segment.
    assert!(matches!(
        remote_ops::rm(v, &["papers".into()], false).await,
        Err(SyncError::Usage(_))
    ));
    assert!(matches!(
        remote_ops::rm(v, &["nothing".into()], true).await,
        Err(SyncError::Io(_))
    ));
    let before = net.backend.counters().put;
    let n = remote_ops::rm(
        v,
        &[
            "papers/sub".into(),
            "new/dir".into(),
            "papers/sub/b.txt".into(),
        ],
        true,
    )
    .await
    .unwrap();
    assert_eq!(n, 2);
    assert_eq!(net.backend.counters().put, before + 1);
    assert_eq!(
        remote_ops::rm(v, &["papers/a.txt".into()], false)
            .await
            .unwrap(),
        1
    );
    assert!(a.remote_paths().is_empty());
    v.finish_mutation().await.unwrap();

    // The other device follows with a plain sync.
    let b = net.device().await;
    clean(&b.down().await);
    assert!(b.names().is_empty());
    let c = net.backend.counters();
    assert_eq!((c.get_bytes > 0, c.trash, c.delete), (true, 0, 0));
}

#[tokio::test]
async fn restore_after_overwrite_and_after_delete() {
    let (net, a) = Net::new().await;
    a.write("doc", b"version one");
    clean(&a.up().await);
    net.backend.advance_ms(DAY_MS);
    a.write("doc", b"version two, longer");
    clean(&a.up().await);
    net.backend.advance_ms(DAY_MS);
    a.remove("doc");
    let mut req = a.req(Up, Mode::Sync);
    req.opts.force = true;
    assert_eq!(a.cmd(&req).await.unwrap().deleted_remote, 1);
    assert!(a.remote_paths().is_empty());

    a.settle().await;
    let v = &a.vault;
    let now = net.backend.now_ms();
    let offered = remote_ops::restore_candidates(v, "doc", now).await.unwrap();
    assert_eq!(
        offered.len(),
        2,
        "newest first: the deleted one, then the overwritten one"
    );
    assert_eq!(offered[0].entry.size, 19);
    assert_eq!(offered[1].entry.size, 11);
    assert!(offered[0].removed_ms > offered[1].removed_ms);

    // After a delete: the path comes back.
    remote_ops::restore(v, "doc", &offered[0]).await.unwrap();
    assert_eq!(a.remote_content("doc").await, b"version two, longer");
    let head = v.head("doc").unwrap().unwrap();
    assert_eq!(head.origin, Some(offered[0].stamp));
    // After an overwrite: the older version replaces the current one, which stays restorable.
    remote_ops::restore(v, "doc", &offered[1]).await.unwrap();
    assert_eq!(a.remote_content("doc").await, b"version one");
    v.finish_mutation().await.unwrap();
    let down = a.down().await;
    assert_eq!(down.downloaded, 1);
    assert_eq!(a.read("doc"), b"version one");

    // Outside the 25-day window nothing is offered.
    let later = now + 26 * DAY_MS;
    let old: Vec<_> = remote_ops::restore_candidates(v, "doc", later)
        .await
        .unwrap();
    assert!(old.iter().all(|c| later - c.removed_ms < 25 * DAY_MS));
    assert!(old.len() < 3);
    assert!(
        remote_ops::restore_candidates(v, "never", now)
            .await
            .unwrap()
            .is_empty()
    );
}

/// `mv` follows the shell: an existing directory as the destination means "into it". Nothing
/// that exists is replaced or merged into without `force`, and what `force` replaces is counted.
#[tokio::test]
async fn mv_moves_into_an_existing_directory_and_replaces_nothing_unasked() {
    let (_net, a) = Net::new().await;
    a.write("mva/same.txt", b"A-version");
    a.write("mva/onlya.txt", b"only a");
    a.write("mvb/same.txt", b"B-version");
    a.write("mvb/onlyb.txt", b"only b");
    a.write("f", b"a file");
    clean(&a.up().await);
    let v = &a.vault;
    remote_ops::mkdir(v, "e/c").await.unwrap();

    // Onto an existing directory: into it, under its own name — no merge, nothing replaced.
    let moved = remote_ops::mv(v, "mva", "mvb", false).await.unwrap();
    assert_eq!(
        (moved.to.as_str(), moved.entries, moved.replaced),
        ("mvb/mva", 2, 0)
    );
    assert_eq!(
        a.remote_paths(),
        [
            "e/c",
            "f",
            "mvb/mva/onlya.txt",
            "mvb/mva/same.txt",
            "mvb/onlyb.txt",
            "mvb/same.txt"
        ]
    );
    assert_eq!(a.remote_content("mvb/same.txt").await, b"B-version");
    // Into the directory it is in already: nothing to do, and said so.
    assert!(matches!(
        remote_ops::mv(v, "mvb/mva", "mvb", false).await,
        Err(SyncError::Usage(_))
    ));
    // The vault root is a directory like any other.
    let moved = remote_ops::mv(v, "mvb/mva", "", false).await.unwrap();
    assert_eq!(moved.to, "mva");
    // An empty directory is a directory: a file moves into it instead of replacing it.
    let moved = remote_ops::mv(v, "f", "e/c", false).await.unwrap();
    assert_eq!(moved.to, "e/c/f");
    assert_eq!(a.remote().get("e/c"), Some(&EntryKind::Dir));

    // A file onto an existing file: refused; with force it is replaced, counted, restorable.
    let err = remote_ops::mv(v, "mvb/onlyb.txt", "mvb/same.txt", false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, SyncError::Usage(text) if text.contains("--force")),
        "{err:?}"
    );
    assert_eq!(a.remote_content("mvb/same.txt").await, b"B-version");
    assert!(v.removed_versions("mvb/same.txt").unwrap().is_empty());
    let moved = remote_ops::mv(v, "mvb/onlyb.txt", "mvb/same.txt", true)
        .await
        .unwrap();
    assert_eq!((moved.entries, moved.replaced), (1, 1));
    assert_eq!(a.remote_content("mvb/same.txt").await, b"only b");
    assert_eq!(v.removed_versions("mvb/same.txt").unwrap().len(), 1);

    // A directory onto a directory of the same name: refused; with force merged, and the
    // files it replaces are counted.
    remote_ops::mv(v, "mvb", "y/mva", false).await.unwrap();
    assert_eq!(
        a.remote_paths(),
        [
            "e/c",
            "e/c/f",
            "mva/onlya.txt",
            "mva/same.txt",
            "y/mva/same.txt"
        ]
    );
    let err = remote_ops::mv(v, "mva", "y", false).await.unwrap_err();
    assert!(
        matches!(&err, SyncError::Usage(text) if text.contains("--force")),
        "{err:?}"
    );
    assert_eq!(a.remote_content("y/mva/same.txt").await, b"only b");
    assert_eq!(a.remote_content("mva/same.txt").await, b"A-version");
    let moved = remote_ops::mv(v, "mva", "y", true).await.unwrap();
    assert_eq!(
        (moved.to.as_str(), moved.entries, moved.replaced),
        ("y/mva", 2, 1)
    );
    assert_eq!(
        a.remote_paths(),
        ["e/c", "e/c/f", "y/mva/onlya.txt", "y/mva/same.txt"]
    );
    assert_eq!(a.remote_content("y/mva/same.txt").await, b"A-version");

    // A file never replaces a directory, a directory never a file — force or not.
    remote_ops::mv(v, "e/c/f", "mva", false).await.unwrap(); // a file named mva at the root
    for force in [false, true] {
        assert!(matches!(
            remote_ops::mv(v, "mva", "y", force).await,
            Err(SyncError::Usage(_))
        ));
        assert!(matches!(
            remote_ops::mv(v, "y/mva", "", force).await,
            Err(SyncError::Usage(_))
        ));
    }
    assert_eq!(a.remote_content("mva").await, b"a file");
    assert_eq!(a.remote_content("y/mva/same.txt").await, b"A-version");
}

/// `rm -r` promises "restorable": a removed directory can be listed and brought back as one.
#[tokio::test]
async fn a_removed_directory_is_listed_and_restored_in_one_segment() {
    let (net, a) = Net::new().await;
    a.write("d/a", b"file a");
    a.write("d/sub/b", b"file b, longer");
    a.write("d/sub/empty", b"");
    a.write("d/kept", b"first");
    a.write("other", b"untouched");
    clean(&a.up().await);
    net.backend.advance_ms(DAY_MS);
    a.write("d/kept", b"second edition");
    clean(&a.up().await);
    net.backend.advance_ms(DAY_MS);
    let v = &a.vault;
    assert_eq!(remote_ops::rm(v, &["d".into()], true).await.unwrap(), 4);
    // What used to be the whole story: the directory itself has no version.
    let now = net.backend.now_ms();
    assert!(
        remote_ops::restore_candidates(v, "d", now)
            .await
            .unwrap()
            .is_empty()
    );

    let found = remote_ops::restorable_under(v, "d", now).await.unwrap();
    let listed: Vec<(&str, u64, bool)> = found
        .iter()
        .map(|r| (r.version.path.as_str(), r.version.entry.size, r.live))
        .collect();
    assert_eq!(
        listed,
        [
            ("d/a", 6, false),
            ("d/kept", 14, false),
            ("d/sub/b", 14, false),
            ("d/sub/empty", 0, false)
        ],
        "the newest removed version of every file under the directory"
    );
    // The same from above; nothing under a sibling or under a name that merely starts alike.
    assert_eq!(
        remote_ops::restorable_under(v, "", now)
            .await
            .unwrap()
            .len(),
        4
    );
    assert!(
        remote_ops::restorable_under(v, "d/su", now)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        remote_ops::restorable_under(v, "d/sub", now)
            .await
            .unwrap()
            .len(),
        2
    );

    // One file is uploaded again meanwhile: it is live, and a directory restore leaves it.
    remote_ops::restore(v, "d/kept", &found[1].version)
        .await
        .unwrap();
    let found = remote_ops::restorable_under(v, "d", now).await.unwrap();
    assert_eq!(found.len(), 4);
    assert!(
        found[1].live,
        "d/kept exists again; its older version is 'overwritten'"
    );
    assert_eq!(found[1].version.entry.size, 5);

    let puts = net.backend.counters().put;
    let deleted: Vec<_> = found
        .iter()
        .filter(|r| !r.live)
        .map(|r| r.version.clone())
        .collect();
    let done = remote_ops::restore_many(v, &deleted).await.unwrap();
    assert_eq!((done.restored, done.skipped.len()), (3, 0));
    assert_eq!(net.backend.counters().put, puts + 1, "one segment");
    assert_eq!(
        a.remote_paths(),
        ["d/a", "d/kept", "d/sub/b", "d/sub/empty", "other"]
    );
    assert_eq!(a.remote_content("d/sub/b").await, b"file b, longer");
    assert_eq!(a.remote_content("d/kept").await, b"second edition");
    assert_eq!(a.remote_content("d/sub/empty").await, b"");
    v.finish_mutation().await.unwrap();
    // Restored entries are ordinary entries: another device downloads them.
    let b = net.device().await;
    clean(&b.down().await);
    assert_eq!(b.read("d/sub/b"), b"file b, longer");

    // A name that was a file and later a directory: what existed last comes back, the other
    // one is reported, and nothing lands under a file.
    a.settle().await;
    remote_ops::rm(v, &["other".into()], false).await.unwrap();
    net.backend.advance_ms(1000);
    remote_ops::mv(v, "d/a", "other/inner", false)
        .await
        .unwrap();
    net.backend.advance_ms(1000);
    remote_ops::rm(v, &["other".into()], true).await.unwrap();
    let now = net.backend.now_ms();
    let mut both = remote_ops::restore_candidates(v, "other", now)
        .await
        .unwrap();
    assert_eq!(both.len(), 1, "the file that `other` once was");
    both.extend(
        remote_ops::restorable_under(v, "other", now)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.version),
    );
    let paths: Vec<&str> = both.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, ["other", "other/inner"]);
    let done = remote_ops::restore_many(v, &both).await.unwrap();
    assert_eq!(done.restored, 1);
    assert_eq!(done.skipped.len(), 1);
    assert_eq!(done.skipped[0].0, "other");
    assert_eq!(a.remote().get("other/inner"), Some(&EntryKind::File));
    assert!(v.head("other").unwrap().is_none());
    assert!(v.conflicts().unwrap().is_empty());

    // Outside the 25-day window nothing is offered.
    let later = now + 26 * DAY_MS;
    assert!(
        remote_ops::restorable_under(v, "", later)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A mistyped remote path in a download or a check must not look like success.
#[tokio::test]
async fn reading_from_a_remote_path_that_does_not_exist_is_an_error() {
    let (net, a) = Net::new().await;
    a.write("f", b"content");
    let mut up = a.req(Up, Mode::Copy);
    up.remote_prefix = "Documents".into();
    clean(&a.cmd(&up).await.unwrap());
    remote_ops::mkdir(&a.vault, "Empty").await.unwrap();
    a.vault.finish_mutation().await.unwrap();

    let b = net.device().await;
    let not_found = |r: Result<Summary, SyncError>| match r {
        Err(SyncError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(gclone::error::exit_code(&SyncError::Io(e).into()), 1);
        }
        other => panic!("expected NotFound, got {other:?}"),
    };
    let fresh = net.tmp.path().join("restore-target");
    for mode in [Mode::Copy, Mode::Sync] {
        for dry_run in [false, true] {
            // Into a directory that does not exist yet — which must not be created — …
            let mut req = b.req(Down, mode);
            req.remote_prefix = "Documnets".into();
            req.local_root = fresh.clone();
            req.opts.dry_run = dry_run;
            not_found(b.cmd(&req).await);
            assert!(
                !fresh.exists(),
                "nothing is created for a path that is not there"
            );
            // … and into one that exists.
            req.local_root = b.root.clone();
            not_found(b.cmd(&req).await);
            req.remote_prefix = "Documents/f/deeper".into();
            assert!(b.cmd(&req).await.is_err());
        }
    }
    // The vault root, an existing directory and an empty-directory marker are fine.
    for prefix in ["Documents", "Empty", ""] {
        let mut req = b.req(Down, Mode::Copy);
        req.remote_prefix = prefix.into();
        req.local_root = net.tmp.path().join(format!("ok-{prefix}"));
        clean(&b.cmd(&req).await.unwrap());
        assert!(req.local_root.is_dir());
    }
    // Uploading to a prefix that does not exist yet stays what creates it.
    let mut req = a.req(Up, Mode::Copy);
    req.remote_prefix = "Brand/New".into();
    let up = a.cmd(&req).await.unwrap();
    assert_eq!(up.uploaded + up.reused, 1);
    assert!(a.remote_paths().contains(&"Brand/New/f".to_string()));

    // check: a verification that verified nothing is not "all good".
    let v = &b.vault;
    b.settle().await;
    let err = sync::check_download(v, "no/such/dir", Progress::hidden())
        .await
        .unwrap_err();
    assert!(matches!(&err, SyncError::Io(e) if e.kind() == std::io::ErrorKind::NotFound));
    let err = sync::check_local(v, &b.root, "nosuch").await.unwrap_err();
    assert!(matches!(&err, SyncError::Io(e) if e.kind() == std::io::ErrorKind::NotFound));
    assert!(
        sync::check_download(v, "Documents/f", Progress::hidden())
            .await
            .unwrap()
            .ok()
    );
    assert!(
        sync::check_download(v, "", Progress::hidden())
            .await
            .unwrap()
            .ok()
    );

    // A directory this pair has synced and that was removed from the vault since is not a
    // typo: `sync` down carries the removal out.
    let mut pair = b.req(Down, Mode::Sync);
    pair.remote_prefix = "Documents".into();
    clean(&b.cmd(&pair).await.unwrap());
    assert_eq!(b.read("f"), b"content");
    b.settle().await;
    remote_ops::rm(&b.vault, &["Documents".into()], true)
        .await
        .unwrap();
    b.vault.finish_mutation().await.unwrap();
    let down = b.cmd(&pair).await.unwrap();
    assert_eq!(down.deleted_local, 1);
    assert!(!b.exists("f"));
}

#[tokio::test]
async fn restore_untrashes_the_blob_and_is_refused_once_it_is_gone() {
    let (net, a) = Net::new().await;
    a.write("big", &pattern(1, (MIB + 10) as usize));
    a.write("small", b"small file in a pack");
    clean(&a.up().await);
    a.remove("big");
    a.remove("small");
    let mut req = a.req(Up, Mode::Sync);
    req.opts.force = true;
    a.cmd(&req).await.unwrap();
    a.settle().await;
    let v = &a.vault;
    let now = net.backend.now_ms();

    let big = remote_ops::restore_candidates(v, "big", now)
        .await
        .unwrap()
        .remove(0);
    let blob = v
        .blob(&big.entry.loc.as_ref().unwrap().blob)
        .unwrap()
        .unwrap();
    let handle = Handle(blob.file_id.clone());
    // Trashed (by hand, or by another device's gc): restore brings it back.
    net.backend.trash(&handle).await.unwrap();
    assert_eq!(
        remote_ops::restore_candidates(v, "big", now)
            .await
            .unwrap()
            .len(),
        1
    );
    remote_ops::restore(v, "big", &big).await.unwrap();
    assert!(!net.backend.stat(&handle).await.unwrap().unwrap().trashed);
    assert_eq!(
        a.remote_content("big").await,
        pattern(1, (MIB + 10) as usize)
    );

    // Gone for good: not offered, and a stale candidate is refused.
    let small = remote_ops::restore_candidates(v, "small", now)
        .await
        .unwrap()
        .remove(0);
    let blob = v
        .blob(&small.entry.loc.as_ref().unwrap().blob)
        .unwrap()
        .unwrap();
    assert!(net.backend.hard_delete(&Handle(blob.file_id.clone())));
    assert!(
        remote_ops::restore_candidates(v, "small", now)
            .await
            .unwrap()
            .is_empty()
    );
    let err = remote_ops::restore(v, "small", &small).await.unwrap_err();
    assert!(
        matches!(err, SyncError::Transfer(TransferError::BlobMissing(_))),
        "{err}"
    );
    assert!(v.head("small").unwrap().is_none());
}

// ---------------------------------------------------------------------------------------------
// gc and check (§5.9)
// ---------------------------------------------------------------------------------------------

/// A vault with a live file, a file overwritten now (its old blob is dead from now on) and an
/// orphan object in the device's data folder plus one in a foreign folder.
async fn gc_fixture() -> (Net, Dev, Handle, Handle, Handle) {
    let (net, a) = Net::new().await;
    a.write("live", &pattern(1, (MIB + 1) as usize));
    a.write("doomed", &pattern(2, (MIB + 2) as usize));
    clean(&a.up().await);
    let doomed = a.vault.head("doomed").unwrap().unwrap();
    let dead_blob = a
        .vault
        .blob(&doomed.entry.loc.unwrap().blob)
        .unwrap()
        .unwrap();
    a.write("doomed", &pattern(3, (MIB + 3) as usize));
    clean(&a.up().await);

    let data_folder = a.vault.data_folder().await.unwrap();
    let [orphan, foreign_folder, foreign]: [Handle; 3] =
        net.backend.new_ids(3).await.unwrap().try_into().unwrap();
    let put = |id: &Handle, parent: &Handle, name: &str| {
        let (b, id, parent, name) = (
            net.backend.clone(),
            id.clone(),
            parent.clone(),
            name.to_string(),
        );
        async move {
            let body = gclone::backend::stream_body(bytes::Bytes::from_static(b"not a blob"));
            b.put(&id, &parent, &name, body).await.unwrap();
        }
    };
    put(&orphan, &data_folder, "00112233445566778899aabbccddeeff").await;
    // A folder next to the vault that is none of its data folders.
    net.backend
        .create_folder(&foreign_folder, &Handle::top(), "someone-elses")
        .await
        .unwrap();
    put(
        &foreign,
        &foreign_folder,
        "ffeeddccbbaa99887766554433221100",
    )
    .await;
    (net, a, Handle(dead_blob.file_id), orphan, foreign)
}

async fn trashed(net: &Net, h: &Handle) -> Option<bool> {
    net.backend.stat(h).await.unwrap().map(|m| m.trashed)
}

#[tokio::test]
async fn gc_trashes_only_blobs_dead_for_thirty_days() {
    let (net, a, dead, orphan, foreign) = gc_fixture().await;
    let v = &a.vault;
    net.backend.advance_ms(GC_GRACE_MS - DAY_MS);
    a.vault.refresh().await.unwrap();
    let early = sync::gc(v, false, false, false).await.unwrap();
    assert_eq!((early.dead_blobs, early.orphans, early.purged), (0, 0, 0));
    assert_eq!(trashed(&net, &dead).await, Some(false));

    net.backend.advance_ms(2 * DAY_MS);
    net.backend.reset_counters();
    let dry = sync::gc(v, true, false, false).await.unwrap();
    assert!(dry.dry_run);
    assert_eq!((dry.dead_blobs, dry.dead_bytes > MIB), (1, true));
    assert_eq!(net.backend.counters().trash, 0);
    assert_eq!(trashed(&net, &dead).await, Some(false));

    let report = sync::gc(v, false, false, false).await.unwrap();
    assert_eq!(
        (report.dead_blobs, report.orphans, report.purged),
        (1, 0, 0)
    );
    assert_eq!(report.dead_bytes, dry.dead_bytes);
    assert_eq!(trashed(&net, &dead).await, Some(true));
    // Nothing else was touched: live blobs, the orphan, foreign objects, index objects.
    assert_eq!(net.backend.counters().trash, 1);
    assert_eq!(trashed(&net, &orphan).await, Some(false));
    assert_eq!(trashed(&net, &foreign).await, Some(false));
    assert_eq!(
        a.remote_content("live").await,
        pattern(1, (MIB + 1) as usize)
    );
    assert_eq!(
        a.remote_content("doomed").await,
        pattern(3, (MIB + 3) as usize)
    );
    // A second run finds nothing more.
    let again = sync::gc(v, false, false, false).await.unwrap();
    assert_eq!(again.dead_blobs, 0);
    assert!(v.stats(net.backend.now_ms()).unwrap().trashed_blob_bytes > MIB);
}

#[tokio::test]
async fn gc_orphans_stays_inside_the_vaults_own_data_folders() {
    let (net, a, dead, orphan, foreign) = gc_fixture().await;
    let v = &a.vault;
    // Younger than 14 days: kept.
    net.backend.advance_ms(ORPHAN_GRACE_MS - DAY_MS);
    let young = sync::gc(v, false, true, false).await.unwrap();
    assert_eq!(young.orphans, 0);
    assert_eq!(trashed(&net, &orphan).await, Some(false));

    net.backend.advance_ms(2 * DAY_MS);
    let dry = sync::gc(v, true, true, false).await.unwrap();
    assert_eq!((dry.orphans, dry.orphan_bytes), (1, 10));
    assert_eq!(trashed(&net, &orphan).await, Some(false));
    let report = sync::gc(v, false, true, false).await.unwrap();
    assert_eq!(
        (report.orphans, report.orphan_bytes, report.dead_blobs),
        (1, 10, 0)
    );
    assert_eq!(trashed(&net, &orphan).await, Some(true));
    // Known blobs — live or dead but inside the grace period — and foreign objects stay.
    assert_eq!(trashed(&net, &foreign).await, Some(false));
    assert_eq!(trashed(&net, &dead).await, Some(false));
    assert_eq!(
        a.remote_content("live").await,
        pattern(1, (MIB + 1) as usize)
    );
    // Without --orphans the listing is not even made.
    net.backend.reset_counters();
    sync::gc(v, false, false, false).await.unwrap();
    assert_eq!(net.backend.counters().list, 0);
}

#[tokio::test]
async fn gc_purge_deletes_only_its_own_intact_trashed_blobs() {
    let (net, a, dead, orphan, foreign) = gc_fixture().await;
    let v = &a.vault;
    // A second dead blob that is altered after gc trashed it, and a third that somebody
    // took out of the trash again.
    for (name, seed) in [("altered", 10u32), ("untrashed", 11)] {
        a.write(name, &pattern(seed, (MIB + 7) as usize));
    }
    clean(&a.up().await);
    let handle_of = |name: &str| {
        let head = v.head(name).unwrap().unwrap();
        Handle(
            v.blob(&head.entry.loc.unwrap().blob)
                .unwrap()
                .unwrap()
                .file_id,
        )
    };
    let (altered, untrashed) = (handle_of("altered"), handle_of("untrashed"));
    a.remove("altered");
    a.remove("untrashed");
    clean(&a.up().await);

    net.backend.advance_ms(GC_GRACE_MS + DAY_MS);
    v.refresh().await.unwrap();
    // --purge without anything trashed by this device deletes nothing.
    let none = sync::gc(v, true, true, true).await.unwrap();
    assert_eq!(
        (none.dead_blobs, none.orphans, none.purged),
        (3, 1, 3),
        "a dry run counts what a real run would purge"
    );
    assert_eq!(net.backend.counters().delete, 0);

    let report = sync::gc(v, false, true, false).await.unwrap();
    assert_eq!((report.dead_blobs, report.orphans), (3, 1));
    net.backend.tamper(&altered, |data| data[100] ^= 1);
    net.backend.untrash(&untrashed).await.unwrap();

    net.backend.reset_counters();
    let purge = sync::gc(v, false, false, true).await.unwrap();
    assert_eq!(purge.purged, 1);
    assert!(purge.purged_bytes > MIB);
    assert_eq!(purge.purge_skipped.len(), 2, "{:?}", purge.purge_skipped);
    assert_eq!(net.backend.counters().delete, 1);
    assert_eq!(trashed(&net, &dead).await, None, "deleted for good");
    assert_eq!(trashed(&net, &altered).await, Some(true));
    assert_eq!(trashed(&net, &untrashed).await, Some(false));
    // Never an orphan (although trashed by gc), a foreign object or an index object.
    assert_eq!(trashed(&net, &orphan).await, Some(true));
    assert_eq!(trashed(&net, &foreign).await, Some(false));
    let index_objects = net.backend.list(&net.handles.index).await.unwrap();
    assert!(!index_objects.is_empty());
    assert_eq!(
        a.remote_content("live").await,
        pattern(1, (MIB + 1) as usize)
    );
    // The purged row is forgotten; the skipped ones are offered again.
    let again = sync::gc(v, false, false, true).await.unwrap();
    assert_eq!((again.purged, again.purge_skipped.len()), (0, 2));
}

#[tokio::test]
async fn check_blobs_finds_missing_and_heals_trashed_blobs() {
    let (net, a) = Net::new().await;
    a.write("one", &pattern(1, (MIB + 1) as usize));
    a.write("two", &pattern(2, (MIB + 2) as usize));
    a.write("three", &pattern(3, (MIB + 3) as usize));
    a.write("packed", b"small");
    clean(&a.up().await);
    let v = &a.vault;
    let handle_of = |name: &str| {
        let head = v.head(name).unwrap().unwrap();
        Handle(
            v.blob(&head.entry.loc.unwrap().blob)
                .unwrap()
                .unwrap()
                .file_id,
        )
    };

    let ok = sync::check_blobs(v).await.unwrap();
    assert!(ok.ok());
    assert_eq!((ok.checked, ok.listed_late, ok.orphans), (4, 0, 0));
    assert!(ok.missing.is_empty() && ok.untrashed.is_empty());

    // An orphan is only counted.
    let [orphan] = <[Handle; 1]>::try_from(net.backend.new_ids(1).await.unwrap()).unwrap();
    let folder = v.data_folder().await.unwrap();
    let body = gclone::backend::stream_body(bytes::Bytes::from_static(b"stray"));
    net.backend
        .put(&orphan, &folder, "0123456789abcdef0123456789abcdef", body)
        .await
        .unwrap();

    net.backend.hard_delete(&handle_of("one"));
    net.backend.trash(&handle_of("two")).await.unwrap();
    net.backend
        .tamper(&handle_of("three"), |data| data.truncate(1000));
    let report = sync::check_blobs(v).await.unwrap();
    assert!(!report.ok());
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.untrashed.len(), 1);
    assert_eq!(report.mismatched.len(), 1);
    assert!(report.mismatched[0].contains("accidental corruption check"));
    assert_eq!(report.orphans, 1);
    assert_eq!(
        trashed(&net, &handle_of("two")).await,
        Some(false),
        "healed on the spot"
    );
    let again = sync::check_blobs(v).await.unwrap();
    assert_eq!((again.missing.len(), again.untrashed.len()), (1, 0));
}

#[tokio::test]
async fn check_local_compares_sizes_and_hashes_without_downloading() {
    let (net, a) = Net::new().await;
    a.write("same", b"same");
    a.write("edited", b"aaaa");
    a.write("resized", b"short");
    a.write("local-gone", b"x");
    a.write("sub/deep", b"deep");
    clean(&a.up().await);
    net.backend.reset_counters();
    let ok = sync::check_local(&a.vault, &a.root, "").await.unwrap();
    assert!(ok.ok(), "{:?}", ok.differing);
    assert_eq!(ok.checked, 5);

    a.write("edited", b"bbbb");
    a.write("resized", b"much longer now");
    a.remove("local-gone");
    a.write("local-new", b"n");
    let report = sync::check_local(&a.vault, &a.root, "").await.unwrap();
    assert!(!report.ok());
    let mut differing = report.differing.clone();
    differing.sort();
    assert_eq!(
        differing,
        [
            "edited: contents differ",
            "local-gone: only remote",
            "local-new: only local",
            "resized: sizes differ",
        ]
    );
    assert_eq!(net.backend.counters().get, 0, "no download");
    // Under a prefix.
    let sub = sync::check_local(&a.vault, &a.root.join("sub"), "sub")
        .await
        .unwrap();
    assert!(sub.ok());
    assert_eq!(sub.checked, 1);
}

#[tokio::test]
async fn check_download_detects_tampering() {
    let (net, a) = Net::new().await;
    a.write("big", &pattern(1, (2 * MIB + 5) as usize));
    for i in 0..5u32 {
        a.write(&format!("pack/{i}"), &pattern(10 + i, 4_000));
    }
    a.write("empty", b"");
    a.write("gone", &pattern(3, (MIB + 9) as usize));
    clean(&a.up().await);
    let v = &a.vault;
    let progress = Progress::hidden();
    let ok = sync::check_download(v, "", progress.clone()).await.unwrap();
    assert!(ok.ok(), "{:?} {:?}", ok.mismatched, ok.missing);
    assert_eq!(ok.checked, 8);
    assert_eq!(progress.files(), 7);
    assert_eq!(
        sync::check_download(v, "pack", Progress::hidden())
            .await
            .unwrap()
            .checked,
        5
    );

    // One flipped ciphertext bit in the big blob.
    let handle_of = |name: &str| {
        let head = v.head(name).unwrap().unwrap();
        Handle(
            v.blob(&head.entry.loc.unwrap().blob)
                .unwrap()
                .unwrap()
                .file_id,
        )
    };
    net.backend
        .tamper(&handle_of("big"), |data| data[MIB as usize] ^= 0x01);
    net.backend.hard_delete(&handle_of("gone"));
    let report = sync::check_download(v, "", Progress::hidden())
        .await
        .unwrap();
    assert!(!report.ok());
    assert_eq!(report.checked, 8);
    assert_eq!(report.missing, ["gone"]);
    assert_eq!(report.mismatched.len(), 1);
    assert!(
        report.mismatched[0].starts_with("big: "),
        "{:?}",
        report.mismatched
    );
    // The listing check sees both as well — the flipped bit only because the fake reports
    // an honest md5; authentication does not depend on that.
    let blobs = sync::check_blobs(v).await.unwrap();
    assert_eq!((blobs.missing.len(), blobs.mismatched.len()), (1, 1));
}
