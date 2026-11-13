//! The hosted viewer's reader against the CLI's SQL-backed replica (design §11, "Native
//! parity").
//!
//! Vaults are built with the main crate's library on its in-memory store: several devices, a
//! snapshot and segments it does not cover, renames, deletes, conflicts, names outside ASCII.
//! A device that has just attached (`Vault::refresh` into a fresh SQLite replica) and this
//! crate's `Reader`, fed the same stored objects, must then agree on everything a viewer
//! shows: the head fingerprint, every listing in every order, every search, `stat`, the counts
//! of `info` — as JSON, byte for byte, the main crate's side produced by `gclone::web::rules`
//! from SQL rows exactly as `gclone web` does. Also here: the three format gates, the refresh
//! cost, keyfiles and the key bundle, tickets and ranged decryption.

#![cfg(not(target_family = "wasm"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use gclone::backend::{Backend as _, MemBackend, ObjMeta};
use gclone::crypto::{KdfParams, Passphrase, StreamType};
use gclone::error::IndexError;
use gclone::format::{
    KeyfilePayload, Op, SealedObject, SegmentV1, SnapshotV1, VaultDescriptor, seal_keyfile,
    seal_segment, seal_snapshot, segment_name,
};
use gclone::index::{CreateParams, OpenParams, Vault, VaultHandles, testing};
use gclone::state::Db;
use gclone::types::{BlobId, BlobRec, DeviceId, Entry, EntryKind, Loc, OpDraft};
use gclone::web::rules as native_rules;

use gclone_web_core::file::FileReader;
use gclone_web_core::reader::{Reader, Report, Ticket};
use gclone_web_core::web::rules::RefreshState;
use gclone_web_core::{Code, ops};

const VAULT: [u8; 16] = [0x11; 16];
const MASTER: [u8; 32] = [7; 32];
const PASS: &str = "correct horse battery staple";
const FAST_KDF: KdfParams = KdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

type V = Vault<MemBackend>;

fn native_keys() -> gclone::crypto::Keyring {
    gclone::crypto::Keyring::new(
        VAULT,
        vec![(1, gclone::crypto::MasterKey::from_bytes(MASTER))],
        1,
    )
    .unwrap()
}

/// The same keys for the core: through the bundle, as the viewer gets them.
fn core_keys() -> gclone_web_core::crypto::Keyring {
    let keys = gclone_web_core::crypto::Keyring::new(
        VAULT,
        vec![(1, gclone_web_core::crypto::MasterKey::from_bytes(MASTER))],
        1,
    )
    .unwrap();
    ops::keys_of(&ops::bundle_of(&keys)).unwrap()
}

fn keyfile(generation: u32, pass: &str) -> SealedObject {
    let payload = KeyfilePayload::from_keyring(&native_keys(), generation, "parity", 5);
    seal_keyfile(&payload, &Passphrase::from_input(pass), FAST_KDF).unwrap()
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

/// Content that depends on the name and the length only.
fn content(name: &str, len: usize) -> Vec<u8> {
    let seed = blake3::hash(name.as_bytes());
    let mut out = Vec::with_capacity(len);
    let mut reader = blake3::Hasher::new_keyed(seed.as_bytes()).finalize_xof();
    out.resize(len, 0);
    reader.fill(&mut out);
    out
}

/// A vault on the in-memory store, with the plaintext and the blob bytes of what is in it.
struct World {
    mem: MemBackend,
    handles: VaultHandles,
    tmp: tempfile::TempDir,
    /// Blob bytes by the id the index records for them.
    blobs: BTreeMap<String, Vec<u8>>,
    /// Plaintext by content hash.
    plain: BTreeMap<[u8; 32], Vec<u8>>,
    next_blob: u8,
}

impl World {
    async fn new() -> (World, V) {
        let mem = MemBackend::new();
        mem.set_now_ms(1_800_000_000_000);
        let tmp = tempfile::tempdir().unwrap();
        let (a, found) = Vault::create(
            Arc::new(mem.clone()),
            Db::open_in_memory().unwrap(),
            native_keys(),
            CreateParams {
                vault_id: VAULT,
                vault_name: "Tresor \u{fc}ber alles".into(),
                device_name: "laptop".into(),
                cache_dir: tmp.path().join("laptop"),
                machine_fp: Some([1; 32]),
                keyfile: keyfile(1, PASS),
            },
        )
        .await
        .unwrap();
        let world = World {
            mem,
            handles: found.handles,
            tmp,
            blobs: BTreeMap::new(),
            plain: BTreeMap::new(),
            next_blob: 1,
        };
        (world, a)
    }

    /// A device with an empty replica.
    async fn device(&self, name: &str, fp: u8) -> V {
        Vault::open(
            Arc::new(self.mem.clone()),
            Db::open_in_memory().unwrap(),
            native_keys(),
            OpenParams {
                vault_id: VAULT,
                handles: self.handles.clone(),
                device_name: name.into(),
                cache_dir: self.tmp.path().join(name),
                machine_fp: Some([fp; 32]),
            },
        )
        .await
        .unwrap()
    }

    /// A device that has just attached and pulled the vault.
    async fn join(&self, name: &str, fp: u8) -> V {
        let v = self.device(name, fp).await;
        v.refresh().await.unwrap();
        v
    }

    fn tick(&self) {
        self.mem.advance_ms(60_000);
    }

    /// Seals `files` (name, length, mtime in ns) into one new blob — a pack when there are
    /// several — and returns the ops that publish them: the blob record, then one put each.
    fn pack(&mut self, files: &[(&str, usize, i64)]) -> Vec<OpDraft> {
        let keys = native_keys();
        let id = BlobId([self.next_blob; 16]);
        let file_id = format!("file-id-{}", self.next_blob);
        self.next_blob += 1;
        let mut blob = Vec::new();
        let mut puts = Vec::new();
        for (path, len, mtime_ns) in files {
            let plain = content(path, *len);
            let hash = *blake3::hash(&plain).as_bytes();
            let entry = if plain.is_empty() {
                Entry::empty_file(*mtime_ns, false)
            } else {
                let off = blob.len() as u64;
                let mut sealer = keys.data_sealer();
                blob.extend_from_slice(&sealer.header());
                let mut chunks = plain.chunks(1 << 16).peekable();
                while let Some(chunk) = chunks.next() {
                    sealer
                        .seal_chunk(chunk, chunks.peek().is_none(), &mut blob)
                        .unwrap();
                }
                Entry {
                    kind: EntryKind::File,
                    size: plain.len() as u64,
                    mtime_ns: *mtime_ns,
                    exec: false,
                    hash,
                    loc: Some(Loc {
                        blob: id,
                        off,
                        clen: blob.len() as u64 - off,
                        salt: sealer.salt(),
                        chunk_log2: 16,
                        epoch: keys.current_epoch(),
                        suite: 1,
                        flags: 0,
                    }),
                }
            };
            self.plain.insert(hash, plain);
            puts.push(OpDraft::Put {
                path: (*path).to_owned(),
                entry,
                base: None,
                origin: None,
                effect: None,
            });
        }
        let record = OpDraft::Blob(BlobRec {
            id,
            file_id: file_id.clone(),
            clen: blob.len() as u64,
            md5: [0; 16],
            created_ms: self.mem.now_ms(),
        });
        self.blobs.insert(file_id, blob);
        let mut ops = vec![record];
        ops.extend(puts);
        ops
    }

    /// The un-trashed objects of `index/`.
    fn index_objects(&self) -> Vec<ObjMeta> {
        self.mem
            .all_objects()
            .into_iter()
            .filter(|m| m.parent == self.handles.index && !m.trashed && !m.is_folder)
            .collect()
    }

    fn bytes(&self, meta: &ObjMeta) -> Vec<u8> {
        self.mem.read(&meta.handle).unwrap().to_vec()
    }

    /// Loads a reader the way the viewer's loader does (design §6, step 5): the newest
    /// snapshot that is accepted, then every segment it leaves. `snapshots: false`: as if no
    /// snapshot were listed.
    fn load(&self, reader: &mut Reader, snapshots: bool) -> Report {
        let objects = self.index_objects();
        let names: Vec<String> = objects.iter().map(|m| m.name.clone()).collect();
        let by_name = |name: &str| objects.iter().find(|m| m.name == name).unwrap();
        if snapshots {
            for name in Reader::snapshot_candidates(&names) {
                if reader
                    .load_snapshot(&name, &self.bytes(by_name(&name)))
                    .unwrap()
                {
                    break;
                }
            }
        }
        for name in reader.needed_segments(&names) {
            let meta = by_name(&name);
            assert!(
                reader
                    .add_segment(&name, &self.bytes(meta), Some(meta.created_ms))
                    .unwrap(),
                "{name}"
            );
        }
        reader.finish().unwrap()
    }
}

fn del(v: &V, path: &str) -> OpDraft {
    OpDraft::Del {
        path: path.into(),
        base: v.head(path).unwrap().expect("a head to delete").stamp,
        effect: None,
    }
}

/// `path` moved to `to`: a put that names where the version came from, and a delete.
fn mv(v: &V, path: &str, to: &str) -> Vec<OpDraft> {
    let head = v.head(path).unwrap().expect("a head to move");
    vec![
        OpDraft::Put {
            path: to.into(),
            entry: head.entry.clone(),
            base: None,
            origin: Some(head.stamp),
            effect: None,
        },
        del(v, path),
    ]
}

fn dir(path: &str) -> OpDraft {
    OpDraft::Put {
        path: path.into(),
        entry: Entry::dir(),
        base: None,
        origin: None,
        effect: None,
    }
}

/// Two devices, a snapshot, segments after it, and everything a listing can trip over.
async fn busy_vault() -> (World, V, V) {
    let (mut w, a) = World::new().await;
    let first = w.pack(&[
        ("docs/a.txt", 400, 1_700_000_000_000_000_000),
        ("docs/sub/b.txt", 70_000, 1_700_000_100_000_000_000),
        ("docs-other", 10, 1_600_000_000_000_000_000),
        ("docs.txt", 1, -1_500_000),
        ("top", 5, 0),
        ("zero", 0, 1_650_000_000_123_456_789),
        (
            "Fotos \u{e9}t\u{e9}/IMG_10.jpg",
            3_000,
            1_690_000_000_000_000_000,
        ),
        (
            "Fotos \u{e9}t\u{e9}/img_2.jpg",
            3_000,
            1_690_000_000_000_000_001,
        ),
        (
            "Fotos \u{e9}t\u{e9}/Img_1.JPG",
            9_000,
            1_680_000_000_000_000_000,
        ),
        (
            "gr\u{f6}\u{df}e \u{1f389}.txt",
            33,
            1_700_000_000_000_000_000,
        ),
        // "é" decomposed: another byte string than the folder's precomposed one.
        ("cafe\u{301}.md", 12, 1_700_000_000_000_000_000),
        ("to-delete.bin", 100, 5),
        ("to-rename.pdf", 2_000, 6),
    ]);
    a.commit_ops(first).await.unwrap();
    w.tick();
    let big = w.pack(&[("media/big clip.MP4", 200_000, 1_701_000_000_000_000_000)]);
    a.commit_ops(big).await.unwrap();
    a.commit_ops(vec![dir("empty-dir"), dir("docs/empty")])
        .await
        .unwrap();
    w.tick();

    // A second device joins, renames, deletes and adds.
    let b = w.join("phone \u{1f4f1}", 2).await;
    let mut ops = mv(&b, "to-rename.pdf", "docs/renamed.pdf");
    ops.push(del(&b, "to-delete.bin"));
    ops.extend(w.pack(&[
        ("from-phone/IMG_0001.HEIC", 5_000, 1_702_000_000_000_000_000),
        ("from-phone/notes", 44, 1_702_000_000_000_000_000),
    ]));
    b.commit_ops(ops).await.unwrap();
    w.tick();

    // The first device catches up and writes a snapshot: everything so far is covered.
    a.refresh().await.unwrap();
    a.write_snapshot().await.unwrap();
    w.tick();

    // After the snapshot: more from both, without seeing each other — a conflict at one path
    // (two heads, one winner) and a file where the other device has a folder.
    let after_a = w.pack(&[
        ("conflict.txt", 20, 1_703_000_000_000_000_000),
        ("clash", 30, 1_703_000_000_000_000_000),
        ("docs/a.txt.bak", 400, 1_703_000_000_000_000_000),
    ]);
    a.commit_ops(after_a).await.unwrap();
    w.tick();
    b.refresh().await.unwrap();
    let mut after_b = vec![del(&b, "top")];
    after_b.extend(w.pack(&[("media/song.mp3", 70_000, 1_704_000_000_000_000_000)]));
    b.commit_ops(after_b).await.unwrap();
    w.tick();
    // Concurrent: `a` has not seen b's last segment, b has not seen what follows.
    let conc_a = w.pack(&[("conflict.txt", 21, 1_705_000_000_000_000_000)]);
    let conc_b = w.pack(&[
        ("conflict.txt", 22, 1_705_000_000_000_000_001),
        ("clash/inner.txt", 7, 1_705_000_000_000_000_000),
        ("img2.png", 1, 1),
        ("img10.png", 2, 2),
        ("Img1.png", 3, 3),
        ("img02.png", 3, 4),
    ]);
    // Blind puts: neither names the head the other device (or it itself) wrote before.
    a.commit_ops(conc_a).await.unwrap();
    b.commit_ops(conc_b).await.unwrap();
    w.tick();
    (w, a, b)
}

/// Every directory of the replica, the root first.
fn directories(v: &V) -> Vec<String> {
    let mut found = vec![String::new()];
    let mut at = 0;
    while at < found.len() {
        let dir = found[at].clone();
        for row in v.list(&dir).unwrap() {
            if row.is_dir {
                found.push(gclone::path::join(&dir, &row.name));
            }
        }
        at += 1;
    }
    found
}

const ORDERS: [(&str, &str); 6] = [
    ("name", "asc"),
    ("name", "desc"),
    ("size", "asc"),
    ("size", "desc"),
    ("mtime", "asc"),
    ("mtime", "desc"),
];

/// What `gclone web` answers to `/api/stat` (without the sealed id, which is the local
/// server's own).
fn native_stat(v: &V, path: &str) -> Option<String> {
    let name = gclone::path::file_name(path);
    let entry = match (v.head(path).unwrap(), v.exists_dir(path).unwrap()) {
        (_, true) => native_rules::EntryJson::new(name, Some(path.to_owned()), true, None),
        (Some(head), false) => {
            native_rules::EntryJson::new(name, Some(path.to_owned()), false, Some(&head))
        }
        (None, false) => return None,
    };
    Some(json(&entry))
}

/// The viewer's whole surface, compared between a fresh SQL replica and a reader.
fn assert_same_view(c: &V, reader: &Reader, report: &Report) {
    assert_eq!(reader.head_fingerprint(), c.head_fingerprint().unwrap());
    assert_eq!(report.head, c.head_fingerprint().unwrap());

    // Listings: every directory, every order, whole and in pages.
    let dirs = directories(c);
    assert!(dirs.len() >= 8, "{dirs:?}");
    for dir in &dirs {
        for (sort, order) in ORDERS {
            let by = native_rules::SortOrder::parse(Some(sort), Some(order)).unwrap();
            let native = native_rules::list_json(
                dir.clone(),
                c.list(dir).unwrap(),
                by,
                0,
                native_rules::LIST_PAGE,
            );
            let core = reader
                .list(dir, Some(sort), Some(order), None, None)
                .unwrap();
            assert_eq!(json(&core), json(&native), "{dir:?} {sort} {order}");
            let native = native_rules::list_json(dir.clone(), c.list(dir).unwrap(), by, 2, 3);
            let core = reader
                .list(dir, Some(sort), Some(order), Some(2.0), Some(3.0))
                .unwrap();
            assert_eq!(json(&core), json(&native), "{dir:?} {sort} {order} page");
        }
        // The defaults are the local viewer's.
        let by = native_rules::SortOrder::parse(None, None).unwrap();
        let native = native_rules::list_json(dir.clone(), c.list(dir).unwrap(), by, 0, 2000);
        assert_eq!(
            json(&reader.list(dir, None, None, None, None).unwrap()),
            json(&native)
        );
    }
    // What is no folder: the same sentence, as `not-found`.
    for missing in ["nothing", "docs/a.txt", "docs/a.txt/x", "doc", "top"] {
        assert!(!c.exists_dir(missing).unwrap(), "{missing}");
        let refused = reader.list(missing, None, None, None, None).unwrap_err();
        assert_eq!(refused.code, Code::NotFound);
        assert_eq!(refused.message, native_rules::no_folder(missing));
    }

    // stat: every path of the tree, every directory, and what is not there.
    let mut paths: Vec<String> = c.walk("").unwrap().into_iter().map(|h| h.path).collect();
    paths.extend(dirs.iter().filter(|d| !d.is_empty()).cloned());
    for path in &paths {
        let native = native_stat(c, path).unwrap();
        assert_eq!(json(&reader.stat(path).unwrap()), native, "{path:?}");
    }
    for missing in [
        "nothing",
        "docs/zzz",
        "top",
        "to-delete.bin",
        "to-rename.pdf",
    ] {
        assert_eq!(native_stat(c, missing), None, "{missing}");
        let refused = reader.stat(missing).unwrap_err();
        assert_eq!(refused.code, Code::NotFound);
        assert_eq!(refused.message, native_rules::no_file(missing));
    }

    // Search: a word list, three caps, every order.
    let words = [
        "docs",
        "TXT",
        "img",
        "IMG_",
        "\u{e9}t\u{e9}",
        "E\u{301}T\u{c9}",
        "caf\u{e9}",
        "sub",
        "empty",
        "o",
        "a",
        ".",
        " ",
        "  txt  ",
        "",
        "zzz",
        "docs/a",
        "/",
        "clash",
        "conflict",
        "\u{1f389}",
        "GR\u{d6}",
        "mp",
        "1",
    ];
    for word in words {
        for limit in [1usize, 3, 200] {
            for (sort, order) in ORDERS {
                let by = native_rules::SortOrder::parse(Some(sort), Some(order)).unwrap();
                // As the local server does: the query is trimmed, then searched and shown.
                let q = word.trim().to_owned();
                let (hits, more) = c.search(&q, limit).unwrap();
                let native = native_rules::search_json(q, hits, more, by);
                let core = reader
                    .search(word, Some(limit as f64), Some(sort), Some(order))
                    .unwrap();
                assert_eq!(
                    json(&core),
                    json(&native),
                    "{word:?} {limit} {sort} {order}"
                );
            }
        }
        let (hits, more) = c.search(word.trim(), 200).unwrap();
        let by = native_rules::SortOrder::parse(None, None).unwrap();
        let native = native_rules::search_json(word.trim().to_owned(), hits, more, by);
        assert_eq!(
            json(&reader.search(word, None, None, None).unwrap()),
            json(&native)
        );
    }

    // info: the counts and the last change.
    let stats = c.stats(c.backend().now_ms()).unwrap();
    assert_eq!(
        (report.files, report.dirs, report.bytes, report.conflicts),
        (stats.files, stats.dirs, stats.bytes, stats.conflicts)
    );
    assert_eq!(report.vault_name, c.vault_name());
    let refresh = || RefreshState {
        at_ms: 1_800_000_999_000,
        ok: true,
        applied: report.applied,
        note: None,
    };
    let info = reader.info(refresh());
    assert_eq!(
        (
            info.files,
            info.bytes,
            info.last_change_ms,
            info.last_change_by.clone()
        ),
        (
            stats.files,
            stats.bytes,
            stats.last_change_ms,
            stats.last_change_by.clone()
        )
    );
    // The shape is the local viewer's, field for field, plus the fingerprint.
    let native = native_rules::InfoJson {
        vault: c.vault_name(),
        backend: "drive",
        device: "this browser".into(),
        version: env!("CARGO_PKG_VERSION"),
        read_only: true,
        files: stats.files,
        bytes: stats.bytes,
        last_change_ms: stats.last_change_ms,
        last_change_by: stats.last_change_by,
        refresh: native_rules::RefreshState {
            at_ms: 1_800_000_999_000,
            ok: true,
            applied: report.applied,
            note: None,
        },
        head: Some(c.head_fingerprint().unwrap()),
    };
    assert_eq!(json(&info), json(&native));
}

#[tokio::test]
async fn the_reader_and_the_sql_replica_show_the_same_vault() {
    let (w, a, b) = busy_vault().await;
    // A device that has just attached: what the viewer is, every time it is opened.
    let c = w.join("fresh", 3).await;

    let mut reader = Reader::new(core_keys());
    let report = w.load(&mut reader, true);
    assert!(report.snapshot.is_some(), "{report:?}");
    assert!(
        report.applied >= 4,
        "segments after the snapshot: {report:?}"
    );
    assert_eq!(
        (&report.blocked, &report.missing, &report.corrupt),
        (&Vec::new(), &Vec::new(), &Vec::new())
    );
    assert!(report.conflicts >= 2, "two blind puts lost: {report:?}");
    assert_eq!(report.vault_name, "Tresor \u{fc}ber alles");
    assert_same_view(&c, &reader, &report);

    // The fixture is what it is meant to be: a folder under a file's name, deleted and renamed
    // paths, names in both normal forms.
    let stat = |path: &str| json(&reader.stat(path).unwrap());
    assert!(stat("clash").contains(r#""dir":true"#));
    assert!(stat("docs/renamed.pdf").contains(r#""kind":"pdf""#));
    assert!(stat("zero").contains(r#""size":0"#));
    assert_eq!(
        stat("empty-dir"),
        r#"{"name":"empty-dir","path":"empty-dir","dir":true,"kind":"folder","size":null,"mtime_ms":null}"#
    );
    let names = |dir: &str| -> Vec<String> {
        reader
            .list_rows(dir)
            .iter()
            .map(|r| r.name.to_owned())
            .collect()
    };
    assert_eq!(names("clash"), ["inner.txt"]);
    assert_eq!(names("docs/empty"), Vec::<String>::new());
    assert!(names("").contains(&"cafe\u{301}.md".to_owned()));

    // The devices that wrote the vault see the same tree once they have caught up (their
    // replicas have another history, so only the tree and the fingerprint are compared).
    for device in [&a, &b] {
        device.refresh().await.unwrap();
        assert_eq!(
            device.head_fingerprint().unwrap(),
            reader.head_fingerprint()
        );
        for dir in directories(device) {
            let by = native_rules::SortOrder::parse(None, None).unwrap();
            let native =
                native_rules::list_json(dir.clone(), device.list(&dir).unwrap(), by, 0, 2000);
            assert_eq!(
                json(&reader.list(&dir, None, None, None, None).unwrap()),
                json(&native)
            );
        }
    }

    // Without the snapshot — a young vault, or every snapshot skipped — the same view comes
    // from the segments alone (the covered ones are still listed).
    let mut young = Reader::new(core_keys());
    let from_segments = w.load(&mut young, false);
    assert_eq!(from_segments.snapshot, None);
    assert!(from_segments.applied > report.applied);
    assert_eq!(from_segments.head, report.head);
    assert_eq!(
        (from_segments.files, from_segments.dirs, from_segments.bytes),
        (report.files, report.dirs, report.bytes)
    );
    for dir in directories(&c) {
        for (sort, order) in ORDERS {
            assert_eq!(
                json(
                    &young
                        .list(&dir, Some(sort), Some(order), None, None)
                        .unwrap()
                ),
                json(
                    &reader
                        .list(&dir, Some(sort), Some(order), None, None)
                        .unwrap()
                )
            );
        }
    }
}

/// The newest index object is a snapshot — the state right after every compaction and every
/// `gclone repair`, and what the viewer starts from on every visit. A snapshot carries only
/// the time each device joined, so the last change is taken from the snapshot itself: its
/// writer, at its time. Every replica says the same: the device that wrote the snapshot, one
/// that applied the segments itself and then took the snapshot for its base, a new device
/// that starts from it, and the reader.
#[tokio::test]
async fn the_last_change_is_the_same_when_a_snapshot_is_the_newest_object() {
    let (mut w, a) = World::new().await;
    let first = w.pack(&[("one.txt", 10, 1)]);
    a.commit_ops(first).await.unwrap();
    w.tick();
    // The phone joins — the device that joined last — and never writes again.
    let b = w.join("phone", 2).await;
    let hello = w.pack(&[("from-phone.txt", 5, 2)]);
    b.commit_ops(hello).await.unwrap();
    let phone_joined = b.backend().now_ms();
    w.tick();
    w.tick();
    // The real last change is the laptop's, later; then the laptop compacts.
    a.refresh().await.unwrap();
    let second = w.pack(&[("two.txt", 10, 3)]);
    a.commit_ops(second).await.unwrap();
    w.tick();
    a.write_snapshot().await.unwrap();
    let snapshot_written = a.backend().now_ms();
    w.tick();
    b.refresh().await.unwrap();
    let c = w.join("fresh", 3).await;

    let mut reader = Reader::new(core_keys());
    let report = w.load(&mut reader, true);
    assert!(report.snapshot.is_some(), "{report:?}");
    assert_eq!(
        report.applied, 0,
        "the snapshot covers everything: {report:?}"
    );
    let info = reader.info(RefreshState {
        at_ms: 0,
        ok: true,
        applied: 0,
        note: None,
    });
    assert_eq!(
        (info.last_change_ms, info.last_change_by.as_deref()),
        (Some(snapshot_written), Some("laptop")),
        "not the phone at {phone_joined}"
    );
    for (device, what) in [
        (&a, "the writer"),
        (&b, "took it for its base"),
        (&c, "new"),
    ] {
        let stats = device.stats(device.backend().now_ms()).unwrap();
        assert_eq!(
            (stats.last_change_ms, stats.last_change_by),
            (info.last_change_ms, info.last_change_by.clone()),
            "{what}"
        );
    }

    // Segments on top of the snapshot raise it, as before.
    let late = w.pack(&[("late.txt", 1, 4)]);
    b.commit_ops(late).await.unwrap();
    let late_at = b.backend().now_ms();
    let after = w.load(&mut reader, false);
    assert_eq!(after.applied, 1, "{after:?}");
    let info = reader.info(RefreshState {
        at_ms: 0,
        ok: true,
        applied: 1,
        note: None,
    });
    assert_eq!(
        (info.last_change_ms, info.last_change_by.as_deref()),
        (Some(late_at), Some("phone"))
    );
}

#[tokio::test]
async fn a_refresh_over_an_unchanged_listing_asks_for_nothing() {
    let (mut w, a, _b) = busy_vault().await;
    let mut reader = Reader::new(core_keys());
    let first = w.load(&mut reader, true);
    let names: Vec<String> = w.index_objects().into_iter().map(|m| m.name).collect();
    // Nothing changed at the store: nothing is needed, and `finish` changes nothing.
    assert_eq!(reader.needed_segments(&names), Vec::<String>::new());
    assert_eq!(reader.finish().unwrap(), first);

    // One more segment: exactly that one is asked for.
    let more = w.pack(&[("later.txt", 9, 1)]);
    a.refresh().await.unwrap();
    a.commit_ops(more).await.unwrap();
    let objects = w.index_objects();
    let names: Vec<String> = objects.iter().map(|m| m.name.clone()).collect();
    let needed = reader.needed_segments(&names);
    assert_eq!(needed.len(), 1, "{needed:?}");
    let meta = objects.iter().find(|m| m.name == needed[0]).unwrap();
    assert!(
        reader
            .add_segment(&meta.name, &w.bytes(meta), Some(meta.created_ms))
            .unwrap()
    );
    // In hand, not applied yet: not asked for a second time.
    assert_eq!(reader.needed_segments(&names), Vec::<String>::new());
    let second = reader.finish().unwrap();
    assert_eq!(second.applied, first.applied + 1);
    assert_eq!(second.files, first.files + 1);
    assert_eq!(reader.needed_segments(&names), Vec::<String>::new());
    let c = w.join("fresh", 3).await;
    assert_same_view(&c, &reader, &second);

    // Handing in what is already applied or covered is harmless.
    for meta in &objects {
        if meta.name.starts_with("s-") {
            assert!(
                reader
                    .add_segment(&meta.name, &w.bytes(meta), Some(meta.created_ms))
                    .unwrap()
            );
        }
    }
    assert_eq!(reader.finish().unwrap(), second);

    // reset(): the index is gone, the keys are not.
    reader.reset();
    let empty = reader.finish().unwrap();
    assert_eq!(
        (empty.snapshot.as_ref(), empty.applied, empty.files),
        (None, 0, 0)
    );
    assert_eq!(
        reader.needed_segments(&names).len(),
        names.iter().filter(|n| n.starts_with("s-")).count()
    );
    let again = w.load(&mut reader, true);
    assert_eq!(again, second);
}

#[tokio::test]
async fn a_missing_segment_blocks_what_depends_on_it_and_is_named() {
    let (w, _a, b) = busy_vault().await;
    let mut reader = Reader::new(core_keys());
    let objects = w.index_objects();
    let names: Vec<String> = objects.iter().map(|m| m.name.clone()).collect();
    let snapshot = &Reader::snapshot_candidates(&names)[0];
    let meta = |name: &str| objects.iter().find(|m| m.name == name).unwrap();
    assert!(
        reader
            .load_snapshot(snapshot, &w.bytes(meta(snapshot)))
            .unwrap()
    );
    // Leave out the first uncovered segment of device b: its later ones wait for it.
    let needed = reader.needed_segments(&names);
    let of_b: Vec<&String> = needed
        .iter()
        .filter(|n| n.starts_with(&format!("s-{}-", b.device_id().hex())))
        .collect();
    assert!(of_b.len() >= 2, "{needed:?}");
    let held_back = of_b[0].clone();
    for name in needed.iter().filter(|n| **n != held_back) {
        let m = meta(name);
        assert!(
            reader
                .add_segment(name, &w.bytes(m), Some(m.created_ms))
                .unwrap()
        );
    }
    let report = reader.finish().unwrap();
    assert!(!report.blocked.is_empty(), "{report:?}");
    assert!(report.blocked.iter().all(|n| n.starts_with("s-")));
    // The reference is reported with the id the writer recorded for the object.
    assert_eq!(report.missing.len(), 1, "{report:?}");
    let (device, seq, hash, file_id) = &report.missing[0];
    assert_eq!(device, &b.device_id().hex());
    assert_eq!(&segment_name(b.device_id(), *seq, &hex32(hash)), &held_back);
    assert_eq!(file_id, &meta(&held_back).handle.0);
    // Still asked for; once it is there, everything applies.
    assert_eq!(reader.needed_segments(&names), vec![held_back.clone()]);
    let m = meta(&held_back);
    assert!(
        reader
            .add_segment(&held_back, &w.bytes(m), Some(m.created_ms))
            .unwrap()
    );
    let report = reader.finish().unwrap();
    assert_eq!(
        (&report.blocked, &report.missing),
        (&Vec::new(), &Vec::new())
    );
    let c = w.join("fresh", 3).await;
    assert_same_view(&c, &reader, &report);
}

fn hex32(hex: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[tokio::test]
async fn damaged_objects_are_refused_and_recorded() {
    let (w, _a, _b) = busy_vault().await;
    let objects = w.index_objects();
    let names: Vec<String> = objects.iter().map(|m| m.name.clone()).collect();
    let meta = |name: &str| objects.iter().find(|m| m.name == name).unwrap();
    let snapshot = Reader::snapshot_candidates(&names)[0].clone();
    let good = w.bytes(meta(&snapshot));

    let mut reader = Reader::new(core_keys());
    // A flipped bit, a cut object, other bytes under the name, a segment under the name.
    let mut flipped = good.clone();
    flipped[good.len() / 2] ^= 1;
    assert!(!reader.load_snapshot(&snapshot, &flipped).unwrap());
    assert!(
        !reader
            .load_snapshot(&snapshot, &good[..good.len() - 1])
            .unwrap()
    );
    assert!(!reader.load_snapshot(&snapshot, b"junk").unwrap());
    let segment = names.iter().find(|n| n.starts_with("s-")).unwrap();
    assert!(
        !reader
            .load_snapshot(segment, &w.bytes(meta(segment)))
            .unwrap()
    );
    assert!(!reader.load_snapshot("not-a-name", &good).unwrap());
    let report = reader.finish().unwrap();
    assert_eq!(report.snapshot, None);
    assert_eq!(report.corrupt.len(), 3, "{report:?}");
    assert!(
        report
            .corrupt
            .iter()
            .any(|c| c.starts_with(&format!("{snapshot}: ")))
    );
    // Nothing of a refused object was taken: the good one is still accepted, and clears the note.
    assert!(reader.load_snapshot(&snapshot, &good).unwrap());
    assert!(
        !reader
            .finish()
            .unwrap()
            .corrupt
            .iter()
            .any(|c| c.starts_with(&snapshot))
    );
    // Once, and before every segment.
    let again = reader.load_snapshot(&snapshot, &good).unwrap_err();
    assert_eq!(again.code, Code::BadInput);

    // Segments: the same damage is `false`, recorded, and asked for again.
    let needed = reader.needed_segments(&names);
    let victim = needed[0].clone();
    let bytes = w.bytes(meta(&victim));
    let mut flipped = bytes.clone();
    flipped[70] ^= 0x80;
    assert!(!reader.add_segment(&victim, &flipped, Some(1)).unwrap());
    assert!(
        !reader
            .add_segment(&victim, &bytes[..bytes.len() - 5], Some(1))
            .unwrap()
    );
    // Another segment's bytes under this name: the name's hash does not match.
    assert!(
        !reader
            .add_segment(&victim, &w.bytes(meta(&needed[1])), Some(1))
            .unwrap()
    );
    let report = reader.finish().unwrap();
    assert!(
        report
            .corrupt
            .iter()
            .any(|c| c.starts_with(&format!("{victim}: "))),
        "{report:?}"
    );
    assert!(reader.needed_segments(&names).contains(&victim));
    // An object of another vault (other keys) is damage, not a newer format.
    let foreign_keys = gclone::crypto::Keyring::new(
        [0x22; 16],
        vec![(1, gclone::crypto::MasterKey::from_bytes([9; 32]))],
        1,
    )
    .unwrap();
    let foreign = seal_segment(
        &foreign_keys,
        &SegmentV1 {
            vault_id: [0x22; 16],
            device: DeviceId([5; 8]),
            seq: 1,
            lamport: 1,
            prev: None,
            seen: Vec::new(),
            created_ms: 1,
            host: "h".into(),
            ops: vec![],
        },
    )
    .unwrap();
    assert!(
        !reader
            .add_segment(&foreign.name, &foreign.bytes, Some(1))
            .unwrap()
    );

    // The real bytes: accepted, and the record of the damage goes.
    for name in &needed {
        let m = meta(name);
        assert!(
            reader
                .add_segment(name, &w.bytes(m), Some(m.created_ms))
                .unwrap()
        );
    }
    // A second object under the name of a segment in hand (a store may list two) is not
    // that segment being damaged.
    assert!(!reader.add_segment(&victim, &flipped, Some(1)).unwrap());
    let report = reader.finish().unwrap();
    assert_eq!(report.blocked, Vec::<String>::new());
    assert!(
        !report.corrupt.iter().any(|c| c.starts_with(&victim)),
        "{report:?}"
    );
    let c = w.join("fresh", 3).await;
    assert_same_view(&c, &reader, &report);
}

// ---------------------------------------------------------------------------------------------
// Format gates (SPEC §3.3: an unknown version anywhere fails closed)
// ---------------------------------------------------------------------------------------------

fn empty_snapshot(vault_format: u16) -> SnapshotV1 {
    SnapshotV1 {
        vault_id: VAULT,
        device: DeviceId([3; 8]),
        lamport: 9,
        created_ms: 4,
        vault_format,
        vault_name: "v".into(),
        covers: Vec::new(),
        covered: Vec::new(),
        devices: Vec::new(),
        blobs: Vec::new(),
        heads: Vec::new(),
        removed: Vec::new(),
    }
}

fn init_segment(format: u16) -> SegmentV1 {
    SegmentV1 {
        vault_id: VAULT,
        device: DeviceId([3; 8]),
        seq: 1,
        lamport: 1,
        prev: None,
        seen: Vec::new(),
        created_ms: 5,
        host: "host".into(),
        ops: vec![
            Op::VaultInit {
                format,
                name: "v".into(),
            },
            Op::Device {
                id: DeviceId([3; 8]),
                name: "d".into(),
            },
        ],
    }
}

#[test]
fn a_snapshot_of_vault_format_2_needs_a_newer_viewer() {
    // As the native loader does.
    let db = Db::open_in_memory().unwrap();
    assert!(matches!(
        testing::load_snapshot(&db, &empty_snapshot(2)),
        Err(IndexError::NeedsNewerGclone)
    ));
    let sealed = seal_snapshot(&native_keys(), &empty_snapshot(2)).unwrap();
    let mut reader = Reader::new(core_keys());
    let refused = reader
        .load_snapshot(&sealed.name, &sealed.bytes)
        .unwrap_err();
    assert_eq!(refused.code, Code::NeedsNewer, "{refused}");
    // Nothing of it became the base.
    assert_eq!(reader.finish().unwrap().snapshot, None);
    // Format 1 (and 0, a snapshot from before any `VaultInit`) is read.
    for format in [0, 1] {
        testing::load_snapshot(&db, &empty_snapshot(format)).unwrap();
        let sealed = seal_snapshot(&native_keys(), &empty_snapshot(format)).unwrap();
        let mut reader = Reader::new(core_keys());
        assert!(reader.load_snapshot(&sealed.name, &sealed.bytes).unwrap());
    }
}

#[test]
fn a_segment_that_declares_vault_format_2_needs_a_newer_viewer() {
    let db = Db::open_in_memory().unwrap();
    assert!(matches!(
        testing::apply(&db, &init_segment(2), 7),
        Err(IndexError::NeedsNewerGclone)
    ));
    let sealed = seal_segment(&native_keys(), &init_segment(2)).unwrap();
    let mut reader = Reader::new(core_keys());
    // The object itself is well-formed: it is taken, and refused when it is applied.
    assert!(
        reader
            .add_segment(&sealed.name, &sealed.bytes, Some(7))
            .unwrap()
    );
    let refused = reader.finish().unwrap_err();
    assert_eq!(refused.code, Code::NeedsNewer, "{refused}");
    // And again, however often the caller asks: nothing of it is ever applied.
    assert_eq!(reader.finish().unwrap_err().code, Code::NeedsNewer);

    testing::apply(&db, &init_segment(1), 7).unwrap();
    let sealed = seal_segment(&native_keys(), &init_segment(1)).unwrap();
    let mut reader = Reader::new(core_keys());
    assert!(
        reader
            .add_segment(&sealed.name, &sealed.bytes, Some(7))
            .unwrap()
    );
    let report = reader.finish().unwrap();
    assert_eq!((report.applied, report.vault_name.as_str()), (1, "v"));
}

#[test]
fn a_descriptor_with_min_reader_2_is_not_readable() {
    let descriptor = |min_reader: u32| {
        format!(
            r#"{{"gclone_vault":2,"min_reader":{min_reader},"vault_id":"11111111111111111111111111111111","created_ms":5}}"#
        )
    };
    for (min_reader, readable) in [(1, true), (2, false), (7, false)] {
        let text = descriptor(min_reader);
        // As discovery does.
        assert_eq!(
            VaultDescriptor::parse(text.as_bytes()).unwrap().readable(),
            readable
        );
        let parsed = ops::parse_descriptor(text.as_bytes()).unwrap();
        assert_eq!(
            json(&parsed),
            format!(
                r#"{{"vault_id":"11111111111111111111111111111111","min_reader":{min_reader},"created_ms":5,"readable":{readable}}}"#
            )
        );
    }
    for junk in [
        &b""[..],
        b"{}",
        b"not json",
        br#"{"gclone_vault":1,"min_reader":1,"vault_id":"00","created_ms":5}"#,
    ] {
        assert_eq!(ops::parse_descriptor(junk).unwrap_err().code, Code::Damaged);
    }
}

#[test]
fn an_index_object_of_an_unknown_version_needs_a_newer_viewer() {
    let keys = native_keys();
    let named = |ty: StreamType, body: &[u8]| -> (String, Vec<u8>) {
        let bytes = keys.seal(ty, body).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        let name = match ty {
            StreamType::Segment => segment_name(DeviceId([3; 8]), 1, &hash),
            _ => gclone::format::snapshot_name(9, DeviceId([3; 8]), &hash),
        };
        (name, bytes)
    };
    // Codec 1 (reserved for zstd), body version 2, and a stream suite of the future.
    for body in [&[0x01u8, 0, 0][..], &[0x00, 0x01, 0]] {
        let (name, bytes) = named(StreamType::Segment, body);
        let mut reader = Reader::new(core_keys());
        let refused = reader.add_segment(&name, &bytes, Some(1)).unwrap_err();
        assert_eq!(refused.code, Code::NeedsNewer, "{refused}");
        let (name, bytes) = named(StreamType::Snapshot, body);
        let refused = reader.load_snapshot(&name, &bytes).unwrap_err();
        assert_eq!(refused.code, Code::NeedsNewer, "{refused}");
    }
    let sealed = seal_segment(&keys, &init_segment(1)).unwrap();
    for (at, byte) in [(4, 2u8), (7, 1), (5, 30)] {
        let mut bytes = sealed.bytes.clone();
        bytes[at] = byte;
        let name = segment_name(DeviceId([3; 8]), 1, blake3::hash(&bytes).as_bytes());
        let mut reader = Reader::new(core_keys());
        let refused = reader.add_segment(&name, &bytes, Some(1)).unwrap_err();
        assert_eq!(refused.code, Code::NeedsNewer, "byte {at}: {refused}");
    }
}

// ---------------------------------------------------------------------------------------------
// Keyfiles and the key bundle
// ---------------------------------------------------------------------------------------------

const VAULT_HEX: &str = "11111111111111111111111111111111";

#[test]
fn unlock_tells_a_wrong_passphrase_from_everything_else() {
    let real = keyfile(1, PASS);
    let cost = ops::keyfile_cost(&real.name, &real.bytes).unwrap();
    assert_eq!(json(&cost), r#"{"gen":1,"m_kib":8192,"t":1,"p":1}"#);

    let bundle = ops::unlock(&real.name, &real.bytes, PASS, VAULT_HEX).unwrap();
    // 0x01 ‖ vault_id ‖ min_epoch ‖ n ‖ (epoch ‖ key)
    let mut expected = vec![1u8];
    expected.extend_from_slice(&VAULT);
    expected.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
    expected.extend_from_slice(&MASTER);
    assert_eq!(bundle.as_slice(), expected);
    let keys = ops::keys_of(&bundle).unwrap();
    assert_eq!(
        (keys.vault_id(), keys.min_epoch(), keys.current_epoch()),
        (VAULT, 1, 1)
    );
    // The passphrase is normalised as the CLI normalises it (a trailing line break, NFC).
    assert!(ops::unlock(&real.name, &real.bytes, &format!("{PASS}\n"), VAULT_HEX).is_ok());

    let code = |r: gclone_web_core::Result<zeroize::Zeroizing<Vec<u8>>>| r.unwrap_err().code;
    assert_eq!(
        code(ops::unlock(
            &real.name,
            &real.bytes,
            "not the passphrase",
            VAULT_HEX
        )),
        Code::WrongPassphrase
    );
    // The keyfile of another vault opens with its passphrase — and is refused.
    assert_eq!(
        code(ops::unlock(
            &real.name,
            &real.bytes,
            PASS,
            "22222222222222222222222222222222"
        )),
        Code::OtherVault
    );
    assert_eq!(
        code(ops::unlock(&real.name, &real.bytes, PASS, "not hex")),
        Code::BadInput
    );
    // Damage: a flipped bit (the name's hash no longer matches), a cut file, junk, a name
    // whose generation is not the payload's.
    let mut flipped = real.bytes.clone();
    flipped[100] ^= 1;
    assert_eq!(
        code(ops::unlock(&real.name, &flipped, PASS, VAULT_HEX)),
        Code::Damaged
    );
    assert_eq!(
        code(ops::unlock(&real.name, &real.bytes[..80], PASS, VAULT_HEX)),
        Code::Damaged
    );
    assert_eq!(
        code(ops::unlock(
            "gclone-key-00000009-00000000",
            b"junk",
            PASS,
            VAULT_HEX
        )),
        Code::Damaged
    );
    assert_eq!(
        code(ops::unlock("no keyfile name", &real.bytes, PASS, VAULT_HEX)),
        Code::Damaged
    );
    let renamed = format!("gclone-key-00000002-{}", &real.name[real.name.len() - 8..]);
    assert_eq!(
        code(ops::unlock(&renamed, &real.bytes, PASS, VAULT_HEX)),
        Code::Damaged
    );
    assert_eq!(
        ops::keyfile_cost(&real.name, &flipped).unwrap_err().code,
        Code::Damaged
    );
    assert_eq!(
        ops::keyfile_cost("no keyfile name", &real.bytes)
            .unwrap_err()
            .code,
        Code::BadInput
    );

    // A keyfile format of the future: "GCK2". And KDF parameters beyond the format's bounds,
    // which are refused before any work.
    let with = |at: usize, bytes: &[u8]| -> (String, Vec<u8>) {
        let mut changed = real.bytes.clone();
        changed[at..at + bytes.len()].copy_from_slice(bytes);
        let hash = blake3::hash(&changed);
        (gclone::format::keyfile_name(1, hash.as_bytes()), changed)
    };
    let (name, bytes) = with(3, b"2");
    assert_eq!(
        ops::keyfile_cost(&name, &bytes).unwrap_err().code,
        Code::NeedsNewer
    );
    assert_eq!(
        code(ops::unlock(&name, &bytes, PASS, VAULT_HEX)),
        Code::NeedsNewer
    );
    for (at, word) in [(8, 1_048_576u32), (8, 1024), (12, 5), (16, 2)] {
        let (name, bytes) = with(at, &word.to_be_bytes());
        assert_eq!(
            ops::keyfile_cost(&name, &bytes).unwrap_err().code,
            Code::Damaged,
            "{at} {word}"
        );
        assert_eq!(
            code(ops::unlock(&name, &bytes, PASS, VAULT_HEX)),
            Code::Damaged
        );
    }
    // The most a keyfile may ask for is reported, not refused: the page decides.
    let (name, bytes) = with(8, &[0, 8, 0, 0, 0, 0, 0, 4]);
    assert_eq!(
        json(&ops::keyfile_cost(&name, &bytes).unwrap()),
        r#"{"gen":1,"m_kib":524288,"t":4,"p":1}"#
    );
}

#[test]
fn keyfile_candidates_are_the_four_highest_generations() {
    let names: Vec<String> = [
        "gclone-key-00000001-aaaaaaaa",
        "README.txt",
        "gclone-key-00000003-00000001",
        "gclone-key-00000003-00000002",
        "gclone-key-0000000a-ffffffff",
        "gclone-key-00000002-bbbbbbbb",
        "gclone-key-00000002-bbbbbbbb",
        "gclone-key-3-bbbbbbbb",
        "gclone-key-00000004-BBBBBBBB",
        "gclone-vault.json",
        "index",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        ops::keyfile_candidates(&names),
        [
            "gclone-key-0000000a-ffffffff",
            "gclone-key-00000003-00000002",
            "gclone-key-00000003-00000001",
            "gclone-key-00000002-bbbbbbbb",
        ]
    );
    assert_eq!(ops::keyfile_candidates(&[]), Vec::<String>::new());
    // Snapshots: every listed one, newest first.
    let listing: Vec<String> = [
        "c-0000000000000005-0303030303030303-aaaaaaaa",
        "s-0303030303030303-0000000000000001-aaaaaaaa",
        "c-00000000000000ff-0101010101010101-bbbbbbbb",
        "c-0000000000000005-0404040404040404-cccccccc",
        "c-5-0404040404040404-cccccccc",
        "junk",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        Reader::snapshot_candidates(&listing),
        [
            "c-00000000000000ff-0101010101010101-bbbbbbbb",
            "c-0000000000000005-0404040404040404-cccccccc",
            "c-0000000000000005-0303030303030303-aaaaaaaa",
        ]
    );
}

#[test]
fn a_key_bundle_is_exactly_a_key_bundle() {
    let bundle = ops::bundle_of(&core_keys());
    assert_eq!(bundle.len(), 1 + 16 + 4 + 4 + 36);
    assert!(ops::keys_of(&bundle).is_ok());
    let refused = |bytes: &[u8]| ops::keys_of(bytes).err().map(|e| e.code);
    assert_eq!(refused(&[]), Some(Code::BadInput));
    assert_eq!(refused(&bundle[..bundle.len() - 1]), Some(Code::BadInput));
    let mut longer = bundle.to_vec();
    longer.push(0);
    assert_eq!(refused(&longer), Some(Code::BadInput));
    let with = |at: usize, byte: u8| {
        let mut changed = bundle.to_vec();
        changed[at] = byte;
        refused(&changed)
    };
    assert_eq!(with(0, 2), Some(Code::BadInput), "version");
    assert_eq!(with(24, 2), Some(Code::BadInput), "count");
    assert_eq!(
        with(20, 2),
        Some(Code::BadInput),
        "min_epoch above the key's epoch"
    );
    assert_eq!(with(60, 0xff), None, "a key byte is any byte");
    // Two epochs, in any order of the map: the bundle carries both.
    let two = gclone_web_core::crypto::Keyring::new(
        VAULT,
        vec![
            (3, gclone_web_core::crypto::MasterKey::from_bytes([3; 32])),
            (2, gclone_web_core::crypto::MasterKey::from_bytes([2; 32])),
        ],
        2,
    )
    .unwrap();
    let back = ops::keys_of(&ops::bundle_of(&two)).unwrap();
    assert_eq!((back.min_epoch(), back.current_epoch()), (2, 3));
    assert_eq!(back.export().len(), 2);
}

// ---------------------------------------------------------------------------------------------
// Tickets and ranged decryption
// ---------------------------------------------------------------------------------------------

/// Reads `start..end` of a ticket's file from the blob bytes, in network pieces of `piece`.
fn read(ticket: &Ticket, blob: &[u8], start: u64, end: u64, piece: usize) -> Vec<u8> {
    let mut reader = FileReader::new(ticket, start, end).unwrap();
    let (from, to) = (reader.cipher_start() as usize, reader.cipher_end() as usize);
    assert_eq!(reader.remaining(), end.min(ticket.size) - start);
    let mut out = Vec::new();
    for bytes in blob[from..to].chunks(piece.max(1)) {
        out.extend(reader.push(bytes).unwrap());
    }
    assert_eq!(reader.remaining(), 0, "{start}..{end}");
    assert_eq!(reader.resume_at() as usize, to);
    out
}

#[tokio::test]
async fn tickets_open_their_file_whole_and_by_range() {
    let (w, _a, _b) = busy_vault().await;
    let mut reader = Reader::new(core_keys());
    w.load(&mut reader, true);
    let c = w.join("fresh", 3).await;

    let mut seed = 12345u64;
    let mut rnd = |n: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % n.max(1)
    };
    let mut files = 0;
    for head in c.walk("").unwrap() {
        if head.entry.kind != EntryKind::File {
            assert_eq!(reader.ticket(&head.path).unwrap_err().code, Code::NotAFile);
            continue;
        }
        files += 1;
        let ticket = reader.ticket(&head.path).unwrap();
        let plain = &w.plain[&head.entry.hash];
        assert_eq!(ticket.v, 1);
        assert_eq!(ticket.name, gclone::path::file_name(&head.path));
        assert_eq!(ticket.size, plain.len() as u64);
        // A ticket survives the trip as JSON.
        let ticket: Ticket = serde_json::from_str(&json(&ticket)).unwrap();
        if plain.is_empty() {
            assert_eq!((ticket.key.as_ref(), ticket.header.as_ref()), (None, None));
            let mut empty = FileReader::new(&ticket, 0, 10).unwrap();
            assert_eq!(
                (empty.cipher_start(), empty.cipher_end(), empty.remaining()),
                (0, 0, 0)
            );
            assert_eq!(empty.push(&[]).unwrap(), Vec::<u8>::new());
            continue;
        }
        let loc = head.entry.loc.as_ref().unwrap();
        assert_eq!(
            (ticket.off, ticket.clen, ticket.chunk_log2),
            (loc.off, loc.clen, 16)
        );
        assert_eq!(ticket.blob_name, loc.blob.hex());
        let blob = &w.blobs[&ticket.file_id];
        // Whole, in pieces of every awkward size.
        let size = ticket.size;
        for piece in [1usize << 20, 65_552, 65_551, 4_096, 7] {
            if piece < 100 && size > 5_000 {
                continue;
            }
            assert_eq!(
                &read(&ticket, blob, 0, size, piece),
                plain,
                "{} {piece}",
                head.path
            );
        }
        // An end beyond the file is clamped.
        assert_eq!(&read(&ticket, blob, 0, u64::MAX >> 12, 50_000), plain);
        // Ranges: the edges of chunks, and random ones.
        let c16 = 1u64 << 16;
        let mut ranges = vec![
            (0, 1),
            (size - 1, size),
            (0, size.min(2)),
            (size / 2, size / 2),
        ];
        for edge in [c16, 2 * c16, 3 * c16] {
            for (a, b) in [
                (edge - 1, edge),
                (edge - 1, edge + 1),
                (edge, edge + 1),
                (edge, edge),
            ] {
                if b <= size {
                    ranges.push((a, b));
                }
            }
        }
        for _ in 0..40 {
            let a = rnd(size);
            ranges.push((a, a + 1 + rnd(size - a)));
        }
        for (a, b) in ranges {
            let got = read(&ticket, blob, a, b, 1 + rnd(90_000) as usize);
            assert_eq!(got, plain[a as usize..b as usize], "{} {a}..{b}", head.path);
        }
        // What is requested is exactly the chunks the range needs — never the header.
        let one = FileReader::new(&ticket, 0, 1).unwrap();
        assert_eq!(one.cipher_start(), loc.off + 60);
        assert_eq!(
            one.cipher_end() - one.cipher_start(),
            size.min(c16) + 16,
            "{}",
            head.path
        );
    }
    assert!(files >= 20);

    // Not files, and not there.
    for (path, code) in [
        ("docs", Code::NotAFile),
        ("empty-dir", Code::NotAFile),
        ("nothing", Code::NotFound),
        ("to-delete.bin", Code::NotFound),
        ("", Code::BadInput),
        ("a//b", Code::BadInput),
    ] {
        assert_eq!(reader.ticket(path).unwrap_err().code, code, "{path:?}");
    }
}

#[tokio::test]
async fn damaged_moved_foreign_and_cut_ciphertext_is_refused() {
    let (w, _a, _b) = busy_vault().await;
    let mut reader = Reader::new(core_keys());
    w.load(&mut reader, true);
    let big = reader.ticket("media/big clip.MP4").unwrap();
    let song = reader.ticket("media/song.mp3").unwrap();
    let (blob, other) = (&w.blobs[&big.file_id], &w.blobs[&song.file_id]);
    let full = (1usize << 16) + 16;
    let start = big.off as usize + 60;
    let corrupt = |r: gclone_web_core::Result<Vec<u8>>| {
        let e = r.unwrap_err();
        assert_eq!(e.code, Code::Corrupt, "{e}");
    };

    // A flipped bit in the second chunk: the first chunk comes out, nothing of the second,
    // and nothing after it — even if the rest is intact.
    let mut flipped = blob.clone();
    flipped[start + full + 100] ^= 1;
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    let first = r.push(&flipped[start..start + full]).unwrap();
    assert_eq!(first.len(), 1 << 16);
    corrupt(r.push(&flipped[start + full..start + 2 * full]));
    corrupt(r.push(&blob[start + 2 * full..start + 3 * full]));
    corrupt(r.push(&[]));
    // In one push, too: the verified first chunk is not handed out with a failure.
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    corrupt(r.push(&flipped[start..start + 3 * full]));

    // A chunk at another place: chunk 1 where chunk 0 is expected.
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    corrupt(r.push(&blob[start + full..start + 2 * full]));
    // A chunk of another file (same length, same position).
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    corrupt(r.push(&other[song.off as usize + 60..song.off as usize + 60 + full]));
    // The final chunk presented early, and a non-final one presented as the last: the
    // position and the final flag are authenticated.
    let last_len = (big.size as usize % (1 << 16)) + 16;
    let last_at = start + 3 * full;
    assert_eq!(last_at + last_len, big.off as usize + big.clen as usize);
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    corrupt(
        r.push(
            &[
                &blob[last_at..last_at + last_len],
                &blob[start..start + full],
            ]
            .concat(),
        ),
    );

    // A cut stream: what verified is delivered, and the rest stays owed — the caller sees
    // `remaining() > 0`, never a short file that looks complete.
    let mut r = FileReader::new(&big, 0, big.size).unwrap();
    let got = r.push(&blob[start..start + full + 1000]).unwrap();
    assert_eq!(got.len(), 1 << 16);
    assert_eq!(r.remaining(), big.size - (1 << 16));
    // Where to continue: at the chunk that did not verify; its partial bytes are dropped.
    assert_eq!(r.resume_at() as usize, start + full);
    let rest = r
        .push(&blob[start + full..big.off as usize + big.clen as usize])
        .unwrap();
    assert_eq!(r.remaining(), 0);
    let plain: Vec<u8> = [got, rest].concat();
    assert_eq!(*blake3::hash(&plain).as_bytes(), {
        let mut reader2 = FileReader::new(&big, 0, big.size).unwrap();
        let whole = reader2
            .push(&blob[start..start + big.clen as usize - 60])
            .unwrap();
        *blake3::hash(&whole).as_bytes()
    });
    // Bytes after the end of the range.
    corrupt(r.push(&[0]));
    // A truncated last chunk never verifies, whatever follows.
    let mut r = FileReader::new(&big, big.size - 10, big.size).unwrap();
    assert_eq!(r.cipher_start() as usize, last_at);
    let cut = r.push(&blob[last_at..last_at + last_len - 1]).unwrap();
    assert_eq!((cut.len(), r.remaining()), (0, 10));
    corrupt(r.push(&[blob[last_at + last_len - 1] ^ 1]));

    // A ticket with another file's key opens nothing; one that contradicts itself is refused
    // before anything is fetched.
    let wrong_key = Ticket {
        key: song.key.clone(),
        ..big.clone()
    };
    let mut r = FileReader::new(&wrong_key, 0, 10).unwrap();
    let (from, to) = (r.cipher_start() as usize, r.cipher_end() as usize);
    corrupt(r.push(&blob[from..to]));
    for (what, ticket) in [
        (
            "size",
            Ticket {
                size: big.size + 1,
                ..big.clone()
            },
        ),
        (
            "clen",
            Ticket {
                clen: big.clen - 16,
                ..big.clone()
            },
        ),
        (
            "chunk size",
            Ticket {
                chunk_log2: 12,
                ..big.clone()
            },
        ),
        (
            "version",
            Ticket {
                v: 2,
                ..big.clone()
            },
        ),
        (
            "no key",
            Ticket {
                key: None,
                ..big.clone()
            },
        ),
        (
            "short key",
            Ticket {
                key: Some("AAAA".into()),
                ..big.clone()
            },
        ),
        (
            "short header",
            Ticket {
                header: Some("AAAA".into()),
                ..big.clone()
            },
        ),
    ] {
        let e = FileReader::new(&ticket, 0, 10).err().expect(what);
        assert_eq!(e.code, Code::BadInput, "{what}");
    }
    assert_eq!(
        FileReader::new(&big, 11, 10).err().unwrap().code,
        Code::BadInput
    );
    assert_eq!(
        FileReader::new(&big, big.size + 1, big.size + 2)
            .err()
            .unwrap()
            .code,
        Code::BadInput
    );
    assert_eq!(
        FileReader::from_json("{}", 0, 1).err().unwrap().code,
        Code::BadInput
    );
    // An empty range at the end of the file is nothing to fetch.
    let r = FileReader::new(&big, big.size, big.size).unwrap();
    assert_eq!((r.cipher_start(), r.cipher_end(), r.remaining()), (0, 0, 0));
}

#[tokio::test]
async fn an_index_entry_that_contradicts_itself_gets_no_ticket() {
    // Entries as an index object may carry them (they pass acceptance) and as only a writer
    // with the keys could have made them: a location outside its blob, a blob that no record
    // describes.
    let (mut w, a) = World::new().await;
    let good = w.pack(&[("good.bin", 100, 1)]);
    let (record, put) = (good[0].clone(), good[1].clone());
    let OpDraft::Blob(record) = record else {
        unreachable!()
    };
    let OpDraft::Put { entry, .. } = put else {
        unreachable!()
    };
    let at = |path: &str, change: &dyn Fn(&mut Entry)| {
        let mut entry = entry.clone();
        change(&mut entry);
        OpDraft::Put {
            path: path.into(),
            entry,
            base: None,
            origin: None,
            effect: None,
        }
    };
    let short_blob = BlobRec {
        id: BlobId([0xee; 16]),
        clen: 10,
        ..record.clone()
    };
    a.commit_ops(vec![
        OpDraft::Blob(record.clone()),
        OpDraft::Blob(short_blob),
        at("good.bin", &|_| {}),
        at("outside.bin", &|e| {
            e.loc.as_mut().unwrap().blob = BlobId([0xee; 16])
        }),
        at("no-record.bin", &|e| {
            e.loc.as_mut().unwrap().blob = BlobId([0xdd; 16])
        }),
        at("beyond.bin", &|e| e.loc.as_mut().unwrap().off = 1 << 62),
        at("old-epoch.bin", &|e| e.loc.as_mut().unwrap().epoch = 0),
        at("new-epoch.bin", &|e| e.loc.as_mut().unwrap().epoch = 9),
    ])
    .await
    .unwrap();
    let mut reader = Reader::new(core_keys());
    w.load(&mut reader, true);
    assert!(reader.ticket("good.bin").is_ok());
    for (path, code) in [
        ("outside.bin", Code::Corrupt),
        ("no-record.bin", Code::Corrupt),
        ("beyond.bin", Code::Corrupt),
        ("old-epoch.bin", Code::Corrupt),
        // A key epoch this keyfile does not carry: written with keys of a later rotation.
        ("new-epoch.bin", Code::NeedsNewer),
    ] {
        let e = reader.ticket(path).unwrap_err();
        assert_eq!(e.code, code, "{path}: {e}");
    }
    // They are listed all the same: the listing does not depend on the data.
    assert_eq!(reader.list_rows("").len(), 6);

    // An offset no database holds, in a segment sealed by hand: `off + clen` does not overflow.
    let OpDraft::Put { entry, .. } = at("overflow.bin", &|e| {
        e.loc.as_mut().unwrap().off = u64::MAX - 5
    }) else {
        unreachable!()
    };
    let by_hand = seal_segment(
        &native_keys(),
        &SegmentV1 {
            vault_id: VAULT,
            device: DeviceId([0x77; 8]),
            seq: 1,
            lamport: 1_000,
            prev: None,
            seen: Vec::new(),
            created_ms: 1,
            host: "h".into(),
            ops: vec![Op::Put {
                path: "overflow.bin".into(),
                entry,
                base: None,
                origin: None,
            }],
        },
    )
    .unwrap();
    assert!(
        reader
            .add_segment(&by_hand.name, &by_hand.bytes, None)
            .unwrap()
    );
    assert_eq!(reader.finish().unwrap().files, 7);
    let e = reader.ticket("overflow.bin").unwrap_err();
    assert_eq!(e.code, Code::Corrupt, "{e}");
}

// ---------------------------------------------------------------------------------------------
// What the Service Worker asks
// ---------------------------------------------------------------------------------------------

#[test]
fn served_and_ranges_are_the_local_viewers() {
    use gclone::web::mime;
    for name in [
        "a.png",
        "logo.svg",
        "paper.pdf",
        "song.mp3",
        "clip.MP4",
        "notes.txt",
        "page.html",
        "app.js",
        "b.tar.gz",
        "setup.exe",
        "noext",
        "gr\u{f6}\u{df}e \u{1f389}.txt",
        "a\"b;c.txt",
        "line\nbreak.pdf",
        "",
    ] {
        let local = mime::of_name(name);
        let shown = ops::served(name, false);
        assert_eq!(
            (
                shown.kind,
                shown.mime,
                shown.csp,
                shown.disposition.as_str()
            ),
            (
                local.kind.as_str(),
                local.mime,
                local.csp(),
                native_rules::content_disposition(local.inline(), name).as_str()
            ),
            "{name:?}"
        );
        // A download: never a type the browser would show, never inline.
        let saved = ops::served(name, true);
        assert_eq!(saved.kind, local.kind.as_str());
        assert_eq!(saved.mime, "application/octet-stream");
        assert_eq!(
            saved.csp,
            "sandbox; default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(
            saved.disposition,
            native_rules::content_disposition(false, name)
        );
        assert!(saved.disposition.starts_with("attachment; "));
    }
    for (header, size) in [
        (None, 100u64),
        (Some("bytes=0-0"), 100),
        (Some("bytes=0-1"), 100),
        (Some("bytes=10-19"), 100),
        (Some("bytes=90-1000"), 100),
        (Some("bytes=-10"), 100),
        (Some("bytes=100-"), 100),
        (Some("bytes=0-"), 0),
        (None, 0),
        (Some("bytes=0-1,5-6"), 100),
        (Some("bytes=a-b"), 100),
        (Some("bytes=0-18446744073709551615"), 1 << 40),
    ] {
        let expected = match native_rules::parse_range(header, size) {
            native_rules::ByteRange::Whole => ("whole", 0, size),
            native_rules::ByteRange::Part(r) => ("range", r.start, r.end),
            native_rules::ByteRange::Unsatisfiable => ("unsatisfiable", 0, 0),
        };
        let got = ops::parse_range(header, size);
        assert_eq!(
            (got.kind, got.start, got.end),
            expected,
            "{header:?} of {size}"
        );
    }
    assert_eq!(
        json(&ops::parse_range(Some("bytes=0-1"), 100)),
        r#"{"kind":"range","start":0,"end":2}"#
    );
    assert_eq!(
        json(&ops::served("a b.TXT", false)),
        concat!(
            r#"{"kind":"text","mime":"text/plain; charset=utf-8","#,
            r#""csp":"sandbox; default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'","#,
            r#""disposition":"inline"}"#
        )
    );
    // Only a download carries the name (shown, it would become a tab's title).
    assert_eq!(
        ops::served("a b.TXT", true).disposition,
        "attachment; filename=\"a b.TXT\"; filename*=UTF-8''a%20b.TXT"
    );
    for name in ["scan.pdf", "photo.JPG", "clip.mp4", "song.mp3", "notes.txt"] {
        assert_eq!(ops::served(name, false).disposition, "inline", "{name}");
    }
    assert_eq!(
        ops::served("invoice\u{202e}fdp.exe", true).disposition,
        "attachment; filename=\"invoice_fdp.exe\"; filename*=UTF-8''invoice_fdp.exe"
    );
    assert_eq!(
        ops::parse_rfc3339_ms("2026-11-13T10:14:00.250Z"),
        gclone::util::parse_rfc3339_ms("2026-11-13T10:14:00.250Z")
    );
    assert_eq!(ops::parse_rfc3339_ms("yesterday"), None);
    assert_eq!(ops::core_version(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn numbers_from_javascript_are_whole_and_exact() {
    use gclone_web_core::{integer, number};
    assert_eq!(integer(0.0, "n").unwrap(), 0);
    assert_eq!(
        integer(9_007_199_254_740_991.0, "n").unwrap(),
        (1 << 53) - 1
    );
    for bad in [
        -1.0,
        0.5,
        f64::NAN,
        f64::INFINITY,
        9_007_199_254_740_992.0,
        1e300,
    ] {
        assert_eq!(integer(bad, "n").unwrap_err().code, Code::BadInput, "{bad}");
    }
    assert_eq!(number((1 << 53) - 1, "n").unwrap(), 9_007_199_254_740_991.0);
    assert_eq!(number(1 << 53, "n").unwrap_err().code, Code::Corrupt);
    // Counts of the API: the local viewer's bounds and sentences.
    let reader = Reader::new(core_keys());
    let refused = |r: gclone_web_core::Result<gclone_web_core::web::rules::ListJson>| {
        let e = r.err().unwrap();
        assert_eq!(e.code, Code::BadInput);
        e.message
    };
    assert_eq!(
        refused(reader.list("", None, None, None, Some(0.0))),
        "limit is at least 1"
    );
    assert_eq!(
        refused(reader.list("", None, None, None, Some(5001.0))),
        "limit is a number up to 5000"
    );
    assert_eq!(
        refused(reader.list("", None, None, None, Some(1.5))),
        "limit is a number up to 5000"
    );
    assert_eq!(
        refused(reader.list("", Some("date"), None, None, None)),
        "sort is name, size or mtime"
    );
    assert_eq!(
        refused(reader.list("", None, Some("up"), None, None)),
        "order is asc or desc"
    );
    assert!(refused(reader.list("/x", None, None, None, None)).starts_with("path: "));
    assert!(reader.list("", None, None, Some(7.0), Some(5000.0)).is_ok());
    let e = reader.search("x", Some(1001.0), None, None).err().unwrap();
    assert_eq!(
        (e.code, e.message.as_str()),
        (Code::BadInput, "limit is a number up to 1000")
    );
    assert!(
        reader
            .search("x", Some(0.0), None, None)
            .unwrap()
            .hits
            .is_empty()
    );
    assert_eq!(reader.stat("").unwrap_err().message, "path is missing");
}

// ---------------------------------------------------------------------------------------------
// The same expectations for the wasm build (test/run.sh → test/e2e.mjs)
// ---------------------------------------------------------------------------------------------

/// Writes the busy vault, what the **native** viewer rules answer about it, and the crafted
/// objects of the format gates into the directory `GCLONE_WEB_CORE_EXPORT` names, for the Node
/// suite to replay through the wasm module: its answers must be the same bytes. Does nothing
/// without the variable (an ordinary `cargo test`).
#[tokio::test]
async fn export_for_the_wasm_suite() {
    let Some(out) = std::env::var_os("GCLONE_WEB_CORE_EXPORT") else {
        return;
    };
    let out = std::path::PathBuf::from(out);
    let write = |rel: &str, bytes: &[u8]| {
        let path = out.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    let hex = gclone::util::hex;

    // --- the busy vault: objects, keys, files -------------------------------------------------
    let (w, _a, _b) = busy_vault().await;
    let c = w.join("fresh", 3).await;
    let mut listing = Vec::new();
    for meta in w.index_objects() {
        write(&format!("busy/index/{}", meta.name), &w.bytes(&meta));
        listing.push(serde_json::json!({ "name": meta.name, "created_ms": meta.created_ms }));
    }
    let mut reader = Reader::new(core_keys());
    let report = w.load(&mut reader, true);
    assert_same_view(&c, &reader, &report);
    let mut files = Vec::new();
    for (n, head) in c.walk("").unwrap().into_iter().enumerate() {
        if head.entry.kind != EntryKind::File {
            continue;
        }
        let ticket = reader.ticket(&head.path).unwrap();
        write(&format!("busy/plain/{n}"), &w.plain[&head.entry.hash]);
        if let Some(blob) = w.blobs.get(&ticket.file_id) {
            write(&format!("busy/blobs/{}", ticket.file_id), blob);
        }
        files.push(serde_json::json!({
            "path": head.path,
            "plain": format!("plain/{n}"),
            // The native build's ticket, less the key: where the wasm build must look.
            "ticket": {
                "name": ticket.name, "size": ticket.size, "file_id": ticket.file_id,
                "blob_name": ticket.blob_name, "off": ticket.off, "clen": ticket.clen,
                "chunk_log2": ticket.chunk_log2,
            },
        }));
    }

    // --- what the native rules answer: the SQL replica through `gclone::web::rules` -----------
    let mut calls: Vec<serde_json::Value> = Vec::new();
    let by = |sort: Option<&str>, order: Option<&str>| {
        native_rules::SortOrder::parse(sort, order).unwrap()
    };
    let dirs = directories(&c);
    for dir in &dirs {
        for (sort, order) in ORDERS {
            let whole = native_rules::list_json(
                dir.clone(),
                c.list(dir).unwrap(),
                by(Some(sort), Some(order)),
                0,
                native_rules::LIST_PAGE,
            );
            calls.push(serde_json::json!({ "fn": "list", "args": [dir, sort, order, null, null], "ok": json(&whole) }));
            let page = native_rules::list_json(
                dir.clone(),
                c.list(dir).unwrap(),
                by(Some(sort), Some(order)),
                1,
                2,
            );
            calls.push(serde_json::json!({ "fn": "list", "args": [dir, sort, order, 1, 2], "ok": json(&page) }));
        }
        let default =
            native_rules::list_json(dir.clone(), c.list(dir).unwrap(), by(None, None), 0, 2000);
        calls.push(serde_json::json!({ "fn": "list", "args": [dir, null, null, null, null], "ok": json(&default) }));
    }
    for missing in ["nothing", "docs/a.txt", "top", "doc"] {
        calls.push(serde_json::json!({
            "fn": "list", "args": [missing, null, null, null, null],
            "err": format!("not-found: {}", native_rules::no_folder(missing)),
        }));
    }
    for (args, sentence) in [
        (
            serde_json::json!(["", "date", null, null, null]),
            "sort is name, size or mtime".to_owned(),
        ),
        (
            serde_json::json!(["", null, "up", null, null]),
            "order is asc or desc".to_owned(),
        ),
        (
            serde_json::json!(["", null, null, null, 0]),
            native_rules::LIMIT_IS_ZERO.to_owned(),
        ),
        (
            serde_json::json!(["", null, null, null, 5001]),
            native_rules::not_a_number("limit", 5000),
        ),
        (
            serde_json::json!(["", null, null, null, 2.5]),
            native_rules::not_a_number("limit", 5000),
        ),
        (
            serde_json::json!(["a//b", null, null, null, null]),
            native_rules::dir_path(Some("a//b")).unwrap_err(),
        ),
        (
            serde_json::json!(["/a", null, null, null, null]),
            native_rules::dir_path(Some("/a")).unwrap_err(),
        ),
    ] {
        calls.push(serde_json::json!({ "fn": "list", "args": args, "err": format!("bad-input: {sentence}") }));
    }
    let mut paths: Vec<String> = c.walk("").unwrap().into_iter().map(|h| h.path).collect();
    paths.extend(dirs.iter().filter(|d| !d.is_empty()).cloned());
    for path in &paths {
        calls.push(serde_json::json!({ "fn": "stat", "args": [path], "ok": native_stat(&c, path).unwrap() }));
    }
    for missing in ["nothing", "docs/zzz", "top", "to-delete.bin"] {
        calls.push(serde_json::json!({
            "fn": "stat", "args": [missing],
            "err": format!("not-found: {}", native_rules::no_file(missing)),
        }));
    }
    calls.push(serde_json::json!({
        "fn": "stat", "args": [""], "err": format!("bad-input: {}", native_rules::PATH_IS_MISSING),
    }));
    let words = [
        "docs",
        "TXT",
        "img",
        "IMG_",
        "\u{e9}t\u{e9}",
        "E\u{301}T\u{c9}",
        "caf\u{e9}",
        "sub",
        "empty",
        "o",
        "a",
        ".",
        " ",
        "  txt  ",
        "",
        "zzz",
        "docs/a",
        "/",
        "clash",
        "conflict",
        "\u{1f389}",
        "GR\u{d6}",
        "mp",
        "1",
    ];
    for word in words {
        for limit in [1usize, 3, 200] {
            for (sort, order) in ORDERS {
                let q = word.trim().to_owned();
                let (hits, more) = c.search(&q, limit).unwrap();
                let found = native_rules::search_json(q, hits, more, by(Some(sort), Some(order)));
                calls.push(serde_json::json!({ "fn": "search", "args": [word, limit, sort, order], "ok": json(&found) }));
            }
        }
        let (hits, more) = c.search(word.trim(), 200).unwrap();
        let found = native_rules::search_json(word.trim().to_owned(), hits, more, by(None, None));
        calls.push(serde_json::json!({ "fn": "search", "args": [word, null, null, null], "ok": json(&found) }));
    }
    calls.push(serde_json::json!({
        "fn": "search", "args": ["x", 1001, null, null],
        "err": format!("bad-input: {}", native_rules::not_a_number("limit", 1000)),
    }));
    let stats = c.stats(c.backend().now_ms()).unwrap();
    let refresh = native_rules::RefreshState {
        at_ms: 1_800_000_999_000,
        ok: false,
        applied: report.applied,
        note: Some("a note with \"quotes\" and \u{fc}".into()),
    };
    let refresh_json = json(&refresh);
    let info = native_rules::InfoJson {
        vault: c.vault_name(),
        backend: "drive",
        device: "this browser".into(),
        version: env!("CARGO_PKG_VERSION"),
        read_only: true,
        files: stats.files,
        bytes: stats.bytes,
        last_change_ms: stats.last_change_ms,
        last_change_by: stats.last_change_by,
        refresh,
        head: Some(c.head_fingerprint().unwrap()),
    };
    calls.push(serde_json::json!({ "fn": "info", "args": [refresh_json], "ok": json(&info) }));
    // What the Service Worker asks, answered by the local viewer's functions.
    let mut served = Vec::new();
    for name in [
        "a.png",
        "logo.svg",
        "paper.pdf",
        "song.mp3",
        "clip.MP4",
        "notes.txt",
        "page.html",
        "app.js",
        "b.tar.gz",
        "setup.exe",
        "noext",
        "gr\u{f6}\u{df}e \u{1f389}.txt",
        "a\"b;c.txt",
        "line\nbreak.pdf",
    ] {
        let local = gclone::web::mime::of_name(name);
        served.push(serde_json::json!({
            "name": name,
            "shown": {
                "kind": local.kind.as_str(), "mime": local.mime, "csp": local.csp(),
                "disposition": native_rules::content_disposition(local.inline(), name),
            },
            "saved": {
                "kind": local.kind.as_str(), "mime": "application/octet-stream",
                "csp": "sandbox; default-src 'none'; frame-ancestors 'none'",
                "disposition": native_rules::content_disposition(false, name),
            },
        }));
    }
    let mut ranges = Vec::new();
    for (header, size) in [
        (None, 100u64),
        (Some("bytes=0-0"), 100),
        (Some("bytes=0-1"), 100),
        (Some("bytes=10-19"), 100),
        (Some("bytes=90-1000"), 100),
        (Some("bytes=-10"), 100),
        (Some("bytes=100-"), 100),
        (Some("bytes=0-"), 0),
        (None, 0),
        (Some("bytes=0-1,5-6"), 100),
        (Some("bytes=a-b"), 100),
        (Some(" bytes=5-5 "), 100),
        (Some("bytes=0-18446744073709551615"), 1 << 40),
    ] {
        let (kind, start, end) = match native_rules::parse_range(header, size) {
            native_rules::ByteRange::Whole => ("whole", 0, size),
            native_rules::ByteRange::Part(r) => ("range", r.start, r.end),
            native_rules::ByteRange::Unsatisfiable => ("unsatisfiable", 0, 0),
        };
        ranges.push(serde_json::json!({ "header": header, "size": size, "kind": kind, "start": start, "end": end }));
    }
    let busy = serde_json::json!({
        "bundle": hex(&ops::bundle_of(&core_keys())),
        "vault_id": VAULT_HEX,
        "listing": listing,
        "report": report,
        "head": c.head_fingerprint().unwrap(),
        "files": files,
        "calls": calls,
        "served": served,
        "ranges": ranges,
        "version": env!("CARGO_PKG_VERSION"),
    });
    write(
        "busy/expect.json",
        serde_json::to_string_pretty(&busy).unwrap().as_bytes(),
    );

    // --- the format gates, as objects only a writer with the keys can make ---------------------
    let keys = native_keys();
    let mut gates = Vec::new();
    let mut gate = |call: &str, object: &SealedObject, expect: &str| {
        write(&format!("gates/{}", object.name), &object.bytes);
        gates.push(serde_json::json!({ "call": call, "name": object.name, "expect": expect }));
    };
    gate(
        "load_snapshot",
        &seal_snapshot(&keys, &empty_snapshot(2)).unwrap(),
        "needs-newer",
    );
    gate(
        "load_snapshot",
        &seal_snapshot(&keys, &empty_snapshot(1)).unwrap(),
        "true",
    );
    gate(
        "finish",
        &seal_segment(&keys, &init_segment(2)).unwrap(),
        "needs-newer",
    );
    gate(
        "finish",
        &seal_segment(&keys, &init_segment(1)).unwrap(),
        "ok",
    );
    let raw = |ty: StreamType, body: &[u8]| -> SealedObject {
        let bytes = keys.seal(ty, body).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        let name = match ty {
            StreamType::Segment => segment_name(DeviceId([3; 8]), 1, &hash),
            _ => gclone::format::snapshot_name(9, DeviceId([3; 8]), &hash),
        };
        SealedObject { name, hash, bytes }
    };
    // Codec 1 (reserved for zstd) and body version 2.
    for body in [&[0x01u8, 0, 0][..], &[0x00, 0x01, 0]] {
        gate(
            "add_segment",
            &raw(StreamType::Segment, body),
            "needs-newer",
        );
        gate(
            "load_snapshot",
            &raw(StreamType::Snapshot, body),
            "needs-newer",
        );
    }
    // A stream suite, stream flags and a chunk size of the future (header bytes 4, 7, 5).
    let sealed = seal_segment(&keys, &init_segment(1)).unwrap();
    for (at, byte) in [(4, 2u8), (7, 1), (5, 30)] {
        let mut bytes = sealed.bytes.clone();
        bytes[at] = byte;
        let hash = *blake3::hash(&bytes).as_bytes();
        let object = SealedObject {
            name: segment_name(DeviceId([3; 8]), 1, &hash),
            hash,
            bytes,
        };
        gate("add_segment", &object, "needs-newer");
    }
    // Damage is not a newer format: a flipped bit under a matching name, and a foreign vault's object.
    let mut bytes = sealed.bytes.clone();
    bytes[80] ^= 1;
    let hash = *blake3::hash(&bytes).as_bytes();
    gate(
        "add_segment",
        &SealedObject {
            name: segment_name(DeviceId([3; 8]), 1, &hash),
            hash,
            bytes,
        },
        "false",
    );
    let descriptors: Vec<serde_json::Value> = [(1u32, true), (2, false), (7, false)]
        .iter()
        .map(|(min_reader, readable)| {
            let text = format!(
                r#"{{"gclone_vault":2,"min_reader":{min_reader},"vault_id":"{VAULT_HEX}","created_ms":5}}"#
            );
            assert_eq!(VaultDescriptor::parse(text.as_bytes()).unwrap().readable(), *readable);
            serde_json::json!({ "text": text, "readable": readable, "min_reader": min_reader })
        })
        .collect();

    // --- keyfiles (the test KDF cost, so that the suite is quick) ------------------------------
    let real = keyfile(1, PASS);
    write(&format!("keyfiles/{}", real.name), &real.bytes);
    let mut keyfiles = vec![serde_json::json!({
        "name": real.name, "pass": PASS, "vault_id": VAULT_HEX, "expect": "ok",
        "cost": { "gen": 1, "m_kib": 8192, "t": 1, "p": 1 },
    })];
    let mut variant =
        |at: usize, patch: &[u8], pass: &str, vault_id: &str, cost: &str, unlock: &str| {
            let mut bytes = real.bytes.clone();
            bytes[at..at + patch.len()].copy_from_slice(patch);
            let name = gclone::format::keyfile_name(1, blake3::hash(&bytes).as_bytes());
            write(&format!("keyfiles/{name}"), &bytes);
            keyfiles.push(serde_json::json!({
                "name": name, "pass": pass, "vault_id": vault_id, "expect": unlock, "cost": cost,
            }));
        };
    variant(
        0,
        b"G",
        "not the passphrase",
        VAULT_HEX,
        "ok",
        "wrong-passphrase",
    );
    variant(
        0,
        b"G",
        PASS,
        "22222222222222222222222222222222",
        "ok",
        "other-vault",
    );
    variant(3, b"2", PASS, VAULT_HEX, "needs-newer", "needs-newer");
    variant(
        8,
        &1_048_576u32.to_be_bytes(),
        PASS,
        VAULT_HEX,
        "damaged",
        "damaged",
    );
    variant(
        12,
        &5u32.to_be_bytes(),
        PASS,
        VAULT_HEX,
        "damaged",
        "damaged",
    );
    variant(
        100,
        &[real.bytes[100] ^ 1],
        PASS,
        VAULT_HEX,
        "ok",
        "damaged",
    );
    let all = serde_json::json!({
        "bundle": hex(&ops::bundle_of(&core_keys())),
        "gates": gates,
        "descriptors": descriptors,
        "keyfiles": keyfiles,
    });
    write(
        "gates/expect.json",
        serde_json::to_string_pretty(&all).unwrap().as_bytes(),
    );
}
