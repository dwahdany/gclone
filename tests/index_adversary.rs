//! WP4 adversary modes (SPEC §12.1, §13 item 5): the store rolls back, withholds, renames,
//! swaps, truncates or forges index objects. Each case must end in its specific error (or in
//! a report), never in a silently changed replica.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use gclone::backend::{Backend, Flaky, Handle, MemBackend, ObjMeta, PutBody};
use gclone::consts::{DESCRIPTOR_MAX, GAP_GRACE_MS};
use gclone::crypto::{Keyring, MasterKey, StreamType, ciphertext_len};
use gclone::error::IndexError;
use gclone::format::{
    DESCRIPTOR_NAME, Op, SealedObject, SegmentV1, SnapshotV1, keyfile_name, seal_segment,
    seal_snapshot, segment_name, snapshot_name,
};
use gclone::index::{CreateParams, OpenParams, Vault, VaultHandles};
use gclone::state::Db;
use gclone::types::{BlobId, DeviceId, Entry, EntryKind, Loc, OpDraft};

const VAULT: [u8; 16] = [0x11; 16];

type Net = Flaky<MemBackend>;
type V = Vault<Net>;

struct World {
    mem: MemBackend,
    net: Arc<Net>,
    keys: Keyring,
    handles: VaultHandles,
    tmp: tempfile::TempDir,
    clock: Arc<AtomicU64>,
}

fn keyring(vault_id: [u8; 16], key: u8) -> Keyring {
    Keyring::new(vault_id, vec![(1, MasterKey::from_bytes([key; 32]))], 1).unwrap()
}

async fn world() -> (World, V) {
    let mem = MemBackend::new();
    let net = Arc::new(Flaky::new(mem.clone()));
    let tmp = tempfile::tempdir().unwrap();
    let keys = keyring(VAULT, 7);
    let keyfile = {
        let bytes = vec![1u8; 100];
        let hash = *blake3::hash(&bytes).as_bytes();
        SealedObject {
            name: keyfile_name(1, &hash),
            hash,
            bytes,
        }
    };
    let (mut a, found) = Vault::create(
        net.clone(),
        Db::open_in_memory().unwrap(),
        keys.clone(),
        CreateParams {
            vault_id: VAULT,
            vault_name: "gclone".into(),
            device_name: "a".into(),
            cache_dir: tmp.path().join("a"),
            machine_fp: Some([1; 32]),
            keyfile,
        },
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

    /// A new device with an empty replica (no rollback marks: trust on first use).
    async fn device(&self, name: &str) -> V {
        let params = OpenParams {
            vault_id: VAULT,
            handles: self.handles.clone(),
            device_name: name.into(),
            cache_dir: self.cache(name),
            machine_fp: Some([1; 32]),
        };
        let db = Db::open_in_memory().unwrap();
        let mut v = Vault::open(self.net.clone(), db, self.keys.clone(), params)
            .await
            .unwrap();
        self.set_clock(&mut v);
        v
    }

    async fn join(&self, name: &str) -> V {
        let v = self.device(name).await;
        v.refresh().await.unwrap();
        v
    }

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

    fn segment(&self, device: DeviceId, seq: u64) -> ObjMeta {
        let mut found = self.listed(&format!("s-{}-{seq:016x}-", device.hex()));
        assert_eq!(found.len(), 1);
        found.remove(0)
    }

    /// Plants an object in `index/`.
    async fn plant(&self, name: &str, bytes: Vec<u8>) -> Handle {
        let id = self.net.new_ids(1).await.unwrap().remove(0);
        self.net
            .put(
                &id,
                &self.handles.index,
                name,
                PutBody::Small(Bytes::from(bytes)),
            )
            .await
            .unwrap();
        id
    }

    fn pass_grace(&self) {
        self.clock.fetch_add(GAP_GRACE_MS, Ordering::SeqCst);
    }
}

fn file(tag: u8) -> Entry {
    let size = 1000 + u64::from(tag);
    Entry {
        kind: EntryKind::File,
        size,
        mtime_ns: 1,
        exec: false,
        hash: [tag; 32],
        loc: Some(Loc {
            blob: BlobId([tag; 16]),
            off: 0,
            clen: ciphertext_len(size, 16),
            salt: [tag; 16],
            chunk_log2: 16,
            epoch: 1,
            suite: 1,
            flags: 0,
        }),
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

fn paths(v: &V) -> Vec<String> {
    v.walk("").unwrap().into_iter().map(|h| h.path).collect()
}

fn names(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| (*p).to_owned()).collect()
}

/// Device a with three published files: segments 2, 3 and 4 hold "one", "two", "three".
async fn three_files() -> (World, V) {
    let (w, a) = world().await;
    for (i, path) in ["one", "two", "three"].into_iter().enumerate() {
        a.commit_ops(vec![put(path, i as u8 + 1)]).await.unwrap();
    }
    (w, a)
}

fn expect_gap(result: Result<gclone::index::RefreshReport, IndexError>, missing: &ObjMeta) {
    match result {
        Err(IndexError::Gap { names }) => assert_eq!(names, vec![missing.name.clone()]),
        other => panic!("expected a gap naming {}, got {other:?}", missing.name),
    }
}

// --- rollback --------------------------------------------------------------------------------

#[tokio::test]
async fn a_rolled_back_store_is_detected_by_a_device_that_saw_newer_state() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    let checkpoint = w.mem.checkpoint();
    a.commit_ops(vec![put("two", 2)]).await.unwrap();
    b.refresh().await.unwrap();
    let before = (paths(&b), b.head_fingerprint().unwrap());

    w.mem.restore(&checkpoint);
    for v in [&a, &b] {
        let err = v.refresh().await.unwrap_err();
        assert!(
            matches!(err, IndexError::Rollback { device, seq: 3 } if device == a.device_id()),
            "{err:?}"
        );
    }
    // the replica is neither rolled back nor otherwise changed
    assert_eq!((paths(&b), b.head_fingerprint().unwrap()), before);
    assert_eq!(
        gclone::error::exit_code(&anyhow::Error::new(b.refresh().await.unwrap_err())),
        3
    );

    // withholding only the newest segment (a consistent prefix) is the same attack
    let (w, a) = three_files().await;
    let b = w.join("b").await;
    w.net
        .trash(&w.segment(a.device_id(), 4).handle)
        .await
        .unwrap();
    assert!(matches!(
        b.refresh().await,
        Err(IndexError::Rollback { seq: 4, .. })
    ));
    // `repair` on a device that holds the segment gives it back
    let report = b.repair(false).await.unwrap();
    assert_eq!(report.untrashed.len(), 1);
    b.refresh().await.unwrap();
    a.refresh().await.unwrap();
}

#[tokio::test]
async fn trust_on_first_use_then_detection() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    let stale = w.mem.checkpoint();
    a.commit_ops(vec![put("two", 2)]).await.unwrap();
    let current = w.mem.checkpoint();

    // a brand-new replica has no marks: the rolled-back state it is served becomes its baseline
    w.mem.restore(&stale);
    let fresh = w.device("fresh").await;
    let r = fresh.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    assert_eq!(paths(&fresh), names(&["one"]));
    // … which the head fingerprint exposes when compared with an up-to-date device
    assert_ne!(
        fresh.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    fresh.refresh().await.unwrap();

    // once it has seen newer state, a second rollback is detected
    w.mem.restore(&current);
    fresh.refresh().await.unwrap();
    assert_eq!(paths(&fresh), names(&["one", "two"]));
    assert_eq!(
        fresh.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
    w.mem.restore(&stale);
    let err = fresh.refresh().await.unwrap_err();
    assert!(
        matches!(err, IndexError::Rollback { seq: 3, .. }),
        "{err:?}"
    );
    assert_eq!(paths(&fresh), names(&["one", "two"]));
}

#[tokio::test]
async fn an_old_snapshot_presented_alone_is_a_rollback() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("one", 1)]).await.unwrap();
    let old = a.write_snapshot().await.unwrap();
    a.commit_ops(vec![put("two", 2)]).await.unwrap();
    a.commit_ops(vec![put("three", 3)]).await.unwrap();
    b.refresh().await.unwrap();
    // the store now offers nothing but the old snapshot
    for m in w.listed("s-") {
        assert!(w.mem.hard_delete(&m.handle));
    }
    assert_eq!(w.listed("").len(), 1);

    for v in [&a, &b] {
        let err = v.refresh().await.unwrap_err();
        assert!(matches!(err, IndexError::Rollback { .. }), "{err:?}");
        assert_eq!(paths(v), names(&["one", "three", "two"]));
    }
    // a device without marks takes it at face value (trust on first use)
    let fresh = w.device("fresh").await;
    let r = fresh.refresh().await.unwrap();
    assert_eq!(r.rebuilt_from.as_deref(), Some(old.as_str()));
    assert_eq!(paths(&fresh), names(&["one"]));
    // the devices that know better can put the vault back: their caches hold the segments
    let report = a.repair(false).await.unwrap();
    assert_eq!(report.republished.len(), 2);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    fresh.refresh().await.unwrap();
    assert_eq!(paths(&fresh), names(&["one", "three", "two"]));
}

// --- gaps ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_deleted_segment_named_by_another_devices_seen_is_a_gap_after_grace() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    a.commit_ops(vec![put("from-a", 1)]).await.unwrap();
    b.refresh().await.unwrap();
    b.commit_ops(vec![put("from-b", 2)]).await.unwrap();
    let lost = w.segment(a.device_id(), 2);
    assert!(w.mem.hard_delete(&lost.handle));

    let c = w.device("c").await;
    for _ in 0..3 {
        let r = c.refresh().await.unwrap();
        assert_eq!(r.blocked_young, 1);
        assert!(
            paths(&c).is_empty(),
            "b's segment is never applied without what it has seen"
        );
    }
    w.pass_grace();
    expect_gap(c.refresh().await, &lost);
    assert!(paths(&c).is_empty());
    assert_eq!(
        gclone::error::exit_code(&anyhow::Error::new(c.refresh().await.unwrap_err())),
        3
    );
}

#[tokio::test]
async fn a_segment_missing_from_the_listing_is_fetched_by_id() {
    let (w, a) = world().await;
    let b = w.join("b").await;
    let t = w.net.now_ms();
    a.commit_ops(vec![put("from-a", 1)]).await.unwrap();
    b.refresh().await.unwrap();
    // b's segment looks old enough to be listed; everything else is hidden by list lag
    w.mem.set_now_ms(t - 3_600_000);
    b.commit_ops(vec![put("from-b", 2)]).await.unwrap();
    w.mem.set_now_ms(t + 1);
    w.net.set_list_lag_ms(60_000);

    let c = w.device("c").await;
    let lists = w.mem.counters().list;
    let r = c.refresh().await.unwrap();
    assert_eq!(w.mem.counters().list, lists + 1);
    assert_eq!((r.applied, r.blocked_young), (3, 0));
    assert_eq!(paths(&c), names(&["from-a", "from-b"]));
    assert_eq!(c.head_fingerprint().unwrap(), b.head_fingerprint().unwrap());
    w.pass_grace();
    c.refresh().await.unwrap();
}

/// List lag while another device's snapshot forces a rebuild. Device a's newest segment is
/// folded into its own snapshot (so it is known through `base_covered`, not `applied`), in a's
/// index cache, and not listed yet. Regression: after the rebuild it was re-applied from the
/// cache with an empty file id — its id was looked up among the old `applied` rows only — so
/// the presence check could not find it by id and the refresh ended in `Rollback` although
/// nothing was missing; the empty id then went into this device's snapshot tips and `seen`
/// references.
#[tokio::test]
async fn a_cached_segment_reapplied_while_unlisted_keeps_its_file_id() {
    let (w, a) = world().await;
    a.commit_ops(vec![put("a1", 1)]).await.unwrap();
    let b = w.join("b").await;
    let t = w.net.now_ms() + 10_000_000;
    w.mem.set_now_ms(t);
    w.net.set_list_lag_ms(60_000);
    b.commit_ops(vec![put("b1", 2)]).await.unwrap();
    let b1 = w.segment(b.device_id(), 1);
    b.write_snapshot().await.unwrap();
    // a, 10 s later: b's objects are still hidden by list lag
    w.mem.set_now_ms(t + 10_000);
    a.commit_ops(vec![put("a2", 3)]).await.unwrap();
    let a2 = w.segment(a.device_id(), 3);
    a.write_snapshot().await.unwrap();
    a.refresh().await.unwrap();
    // b's segment is trashed, as a cleanup does once a snapshot covers it
    w.net.trash(&b1.handle).await.unwrap();

    // b's objects are listed now, a's newest are not yet: a rebuilds from b's snapshot and
    // re-applies its own segment from the cache.
    w.mem.set_now_ms(t + 65_000);
    let r = a
        .refresh()
        .await
        .expect("list lag is never a rollback (§5.3)");
    assert!(r.rebuilt_from.is_some());
    assert_eq!(paths(&a), names(&["a1", "a2", "b1"]));

    // The id is on record again: the tips of a's next snapshot carry it.
    let name = a.write_snapshot().await.unwrap();
    let object = w
        .mem
        .all_objects()
        .into_iter()
        .find(|m| m.name == name)
        .unwrap();
    let bytes = w.mem.read(&object.handle).unwrap();
    let (snap, _) = gclone::format::open_snapshot(&w.keys, &name, &bytes).unwrap();
    let tip = snap
        .covers
        .iter()
        .find(|t| t.device == a.device_id())
        .unwrap();
    assert_eq!((tip.seq, tip.file_id.as_str()), (3, a2.handle.0.as_str()));
    assert!(snap.covers.iter().all(|t| !t.file_id.is_empty()));

    w.mem.set_now_ms(t + 200_000);
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    assert_eq!(paths(&b), names(&["a1", "a2", "b1"]));
}

// --- forged, renamed, damaged objects --------------------------------------------------------

#[tokio::test]
async fn a_renamed_segment_is_reported_and_counts_as_missing() {
    let (w, a) = three_files().await;
    let id = a.device_id();
    // the middle segment gets the name of a later sequence number
    let victim = w.segment(id, 3);
    let h8 = victim.name.rsplit('-').next().unwrap().to_owned();
    let forged = format!("s-{}-{:016x}-{h8}", id.hex(), 9);
    assert!(w.mem.rename(&victim.handle, &forged));

    let c = w.device("c").await;
    let r = c.refresh().await.unwrap();
    assert_eq!(r.corrupt_objects, vec![forged.clone()]);
    assert_eq!(r.blocked_young, 1);
    // never applied — not under the forged name, and not through the reference of segment 4
    // either, although the object is still readable by the id that reference carries
    assert_eq!(paths(&c), names(&["one"]));
    w.pass_grace();
    expect_gap(c.refresh().await, &victim);
    assert_eq!(paths(&c), names(&["one"]));

    // the writer notices that its segment no longer stands under its name
    assert!(matches!(
        a.refresh().await,
        Err(IndexError::Rollback { seq: 3, .. })
    ));
    let report = a.repair(false).await.unwrap();
    assert_eq!(report.republished, vec![victim.name.clone()]);
    a.refresh().await.unwrap();
    let r = c.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 0);
    assert_eq!(paths(&c), names(&["one", "three", "two"]));
}

#[tokio::test]
async fn a_segment_from_another_vault_is_reported_and_never_applied() {
    let (w, a) = three_files().await;
    let foreign_op = Op::Put {
        path: "planted".into(),
        entry: file(9),
        base: None,
        origin: None,
    };
    let forged = |vault_id: [u8; 16], device: DeviceId, seq: u64| SegmentV1 {
        vault_id,
        device,
        seq,
        lamport: 99,
        prev: None,
        seen: Vec::new(),
        created_ms: 1,
        host: "evil".into(),
        ops: vec![foreign_op.clone()],
    };
    // (1) another vault's key and id, (2) this vault's id under another key,
    // (3) named as the next segment of device a
    let other_vault = [0x22; 16];
    let one = seal_segment(
        &keyring(other_vault, 7),
        &forged(other_vault, DeviceId([5; 8]), 1),
    )
    .unwrap();
    let two = seal_segment(&keyring(VAULT, 8), &forged(VAULT, DeviceId([6; 8]), 1)).unwrap();
    let three = seal_segment(
        &keyring(other_vault, 7),
        &forged(other_vault, a.device_id(), 5),
    )
    .unwrap();
    let mut planted = Vec::new();
    for object in [one, two, three] {
        w.plant(&object.name, object.bytes).await;
        planted.push(object.name);
    }
    planted.sort();

    let before = a.head_fingerprint().unwrap();
    let r = a.refresh().await.unwrap();
    assert_eq!(r.corrupt_objects, planted);
    assert_eq!(
        (r.applied, r.blocked_young, r.rotated_device),
        (0, 0, false)
    );
    assert_eq!(a.head_fingerprint().unwrap(), before);
    let c = w.device("c").await;
    let r = c.refresh().await.unwrap();
    assert_eq!(r.corrupt_objects, planted);
    assert_eq!(paths(&c), names(&["one", "three", "two"]));
    assert_eq!(c.devices().unwrap().len(), 1);
    // the forgeries do not stop the journal
    a.commit_ops(vec![put("four", 4)]).await.unwrap();
    c.refresh().await.unwrap();
    assert_eq!(paths(&c).len(), 4);
}

#[tokio::test]
async fn truncated_bit_flipped_and_swapped_segments_count_as_missing() {
    type Attack = fn(&MemBackend, &ObjMeta, &ObjMeta);
    let attacks: [(&str, Attack); 4] = [
        ("truncated", |mem, victim, _| {
            mem.tamper(&victim.handle, |b| b.truncate(b.len() - 7))
        }),
        ("bit flip", |mem, victim, _| {
            mem.tamper(&victim.handle, |b| b[70] ^= 0x01)
        }),
        ("header flip", |mem, victim, _| {
            mem.tamper(&victim.handle, |b| b[5] ^= 0x80)
        }),
        ("swapped", |mem, victim, other| {
            assert!(mem.replace_content(&victim.handle, &other.handle));
        }),
    ];
    for (what, attack) in attacks {
        let (w, a) = three_files().await;
        let victim = w.segment(a.device_id(), 3);
        attack(&w.mem, &victim, &w.segment(a.device_id(), 2));

        let c = w.device(&format!("c-{what}")).await;
        let r = c.refresh().await.unwrap();
        assert_eq!(r.corrupt_objects, vec![victim.name.clone()], "{what}");
        assert_eq!(r.blocked_young, 1, "{what}");
        assert_eq!(
            paths(&c),
            names(&["one"]),
            "{what}: nothing after the damage is applied"
        );
        w.pass_grace();
        expect_gap(c.refresh().await, &victim);
        // gc and other judges of "what is dead" must not run on this replica; reads still work
        assert_eq!(paths(&c), names(&["one"]), "{what}");

        // the writer's replica is complete; its `repair` publishes a snapshot that carries the
        // effects of the damaged segment, and the other device rebuilds from it
        a.refresh().await.unwrap();
        let report = a.repair(false).await.unwrap();
        assert!(report.still_missing.is_empty());
        let r = c.refresh().await.unwrap();
        assert_eq!(r.rebuilt_from, report.snapshot, "{what}");
        assert_eq!(paths(&c), names(&["one", "three", "two"]), "{what}");
        assert_eq!(c.head_fingerprint().unwrap(), a.head_fingerprint().unwrap());
    }
}

#[tokio::test]
async fn garbage_snapshots_are_ignored() {
    let (w, a) = three_files().await;
    let b = w.join("b").await;
    // junk under a name that claims the greatest lamport there is
    let junk = b"definitely not a snapshot".to_vec();
    let junk_name = snapshot_name(u64::MAX, a.device_id(), blake3::hash(&junk).as_bytes());
    w.plant(&junk_name, junk).await;
    // a well-formed snapshot of another vault that would empty the tree
    let other = [0x22; 16];
    let empty = |vault_id| SnapshotV1 {
        vault_id,
        device: DeviceId([5; 8]),
        lamport: u64::MAX - 1,
        created_ms: 1,
        vault_format: 1,
        vault_name: "evil".into(),
        covers: Vec::new(),
        covered: Vec::new(),
        devices: Vec::new(),
        blobs: Vec::new(),
        heads: Vec::new(),
        removed: Vec::new(),
    };
    let foreign = seal_snapshot(&keyring(other, 7), &empty(other)).unwrap();
    w.plant(&foreign.name, foreign.bytes).await;
    // and one for this vault id, sealed without this vault's key
    let keyless = seal_snapshot(&keyring(VAULT, 8), &empty(VAULT)).unwrap();
    w.plant(&keyless.name, keyless.bytes).await;
    let mut planted = vec![junk_name, foreign.name, keyless.name];
    planted.sort();

    let expect = names(&["one", "three", "two"]);
    for v in [&a, &b, &w.device("fresh").await] {
        for _ in 0..2 {
            let r = v.refresh().await.unwrap();
            assert_eq!(r.corrupt_objects, planted);
            assert!(r.rebuilt_from.is_none() && r.adopted.is_none());
            assert_eq!(paths(v), expect);
        }
    }
    // real snapshots keep working next to them
    let real = a.write_snapshot().await.unwrap();
    assert_eq!(
        b.refresh().await.unwrap().adopted.as_deref(),
        Some(real.as_str())
    );
    for m in w.listed("s-") {
        w.net.trash(&m.handle).await.unwrap();
    }
    let late = w.device("late").await;
    let r = late.refresh().await.unwrap();
    assert_eq!(r.rebuilt_from.as_deref(), Some(real.as_str()));
    assert_eq!(paths(&late), expect);
    // cleanup by the writer never touches what failed acceptance
    w.mem.advance_ms(8 * 86_400_000);
    a.cleanup_index().await.unwrap();
    let left: Vec<String> = w.listed("c-").into_iter().map(|m| m.name).collect();
    for name in &planted {
        assert!(left.contains(name));
    }
}

#[tokio::test]
async fn a_damaged_snapshot_falls_back_to_the_segments() {
    let (w, a) = three_files().await;
    let name = a.write_snapshot().await.unwrap();
    a.commit_ops(vec![put("four", 4)]).await.unwrap();
    let snapshot = w.listed(&name).remove(0);
    w.mem.tamper(&snapshot.handle, |b| {
        let at = b.len() / 2;
        b[at] ^= 0xff;
    });

    // everything is still listed: a fresh device applies the segments and reports the snapshot
    let fresh = w.device("fresh").await;
    let r = fresh.refresh().await.unwrap();
    assert_eq!(r.corrupt_objects, vec![name.clone()]);
    assert!(r.rebuilt_from.is_none() && r.adopted.is_none());
    assert_eq!(paths(&fresh), names(&["four", "one", "three", "two"]));

    // with the covered segments gone for good, the damaged snapshot leaves a gap — never a
    // wrong tree
    for m in w.listed("s-").into_iter().take(4) {
        assert!(w.mem.hard_delete(&m.handle));
    }
    let late = w.device("late").await;
    let r = late.refresh().await.unwrap();
    assert_eq!(r.blocked_young, 1);
    assert_eq!(r.corrupt_objects, vec![name.clone()]);
    assert!(paths(&late).is_empty());
    w.pass_grace();
    assert!(matches!(late.refresh().await, Err(IndexError::Gap { .. })));
    // the writer still lists its base snapshot by name (names suffice for presence); its
    // `repair` republishes what no intact listed snapshot covers
    a.refresh().await.unwrap();
    let report = a.repair(false).await.unwrap();
    assert_eq!(report.republished.len(), 4);
    late.refresh().await.unwrap();
    assert_eq!(paths(&late), names(&["four", "one", "three", "two"]));
    assert_eq!(
        late.head_fingerprint().unwrap(),
        a.head_fingerprint().unwrap()
    );
}

// --- objects of a newer format ---------------------------------------------------------------

/// An index object whose content matches its name but whose format this build does not read
/// was written by a newer gclone. It is not "corrupt" and must not count as missing: the
/// refresh stops (exit 3) instead of carrying on without it.
#[tokio::test]
async fn an_index_object_of_a_newer_format_stops_the_refresh() {
    const STRANGER: DeviceId = DeviceId([9; 8]);
    // A segment that would be accepted and applied as it is — until its header says otherwise.
    fn valid(keys: &Keyring) -> Vec<u8> {
        let seg = SegmentV1 {
            vault_id: VAULT,
            device: STRANGER,
            seq: 1,
            lamport: 50,
            prev: None,
            seen: Vec::new(),
            created_ms: 1,
            host: "newer".into(),
            ops: Vec::new(),
        };
        seal_segment(keys, &seg).unwrap().bytes
    }
    let header = |at: usize, value: u8| {
        move |keys: &Keyring| {
            let mut bytes = valid(keys);
            bytes[at] = value;
            bytes
        }
    };
    type Forge = Box<dyn Fn(&Keyring) -> Vec<u8>>;
    let as_segment = |bytes: &[u8]| segment_name(STRANGER, 1, blake3::hash(bytes).as_bytes());
    let as_snapshot =
        |bytes: &[u8]| snapshot_name(u64::MAX, STRANGER, blake3::hash(bytes).as_bytes());
    // (what the error must name, snapshot?, the object)
    let cases: Vec<(&str, bool, Forge)> = vec![
        // inside the authenticated plaintext: the reserved zstd codec, a second body version
        (
            "index codec 1",
            false,
            Box::new(|keys| keys.seal(StreamType::Segment, &[0x01, 0xaa, 0xbb]).unwrap()),
        ),
        (
            "body version 1",
            false,
            Box::new(|keys| keys.seal(StreamType::Segment, &[0x00, 0x01, 0xaa]).unwrap()),
        ),
        (
            "index codec 1",
            true,
            Box::new(|keys| {
                keys.seal(StreamType::Snapshot, &[0x01, 0xaa, 0xbb])
                    .unwrap()
            }),
        ),
        // in the stream header: suite, chunk size, the reserved type, a flag, a later key epoch
        ("stream suite", false, Box::new(header(4, 0x02))),
        ("stream chunk size", false, Box::new(header(5, 25))),
        ("stream type", false, Box::new(header(6, 0x04))),
        ("stream flags", false, Box::new(header(7, 0x01))),
        ("key epoch 2", false, Box::new(header(11, 2))),
    ];
    for (what, snapshot, forge) in cases {
        let (w, a) = three_files().await;
        let before = (paths(&a), a.head_fingerprint().unwrap());
        let bytes = forge(&w.keys);
        let name = if snapshot {
            as_snapshot(&bytes)
        } else {
            as_segment(&bytes)
        };
        let planted = w.plant(&name, bytes).await;

        let c = w.device("c").await;
        for v in [&a, &c] {
            for _ in 0..2 {
                let err = v.refresh().await.unwrap_err();
                assert!(
                    matches!(&err, IndexError::UnsupportedObject { name: n, what: reason }
                        if *n == name && reason.contains(what)),
                    "{what}: {err:?}"
                );
                let text = err.to_string();
                assert!(text.contains("needs a newer gclone"), "{what}: {text}");
                assert_eq!(
                    gclone::error::exit_code(&anyhow::Error::new(err)),
                    3,
                    "{what}"
                );
            }
        }
        // nothing was changed, nothing unreadable was kept, and `repair` does not work around it
        assert_eq!((paths(&a), a.head_fingerprint().unwrap()), before, "{what}");
        for device in ["a", "c"] {
            assert!(!w.cache(device).join(&name).exists(), "{what}");
        }
        assert!(
            matches!(
                a.repair(false).await,
                Err(IndexError::UnsupportedObject { .. })
            ),
            "{what}"
        );
        assert!(!w.mem.stat(&planted).await.unwrap().unwrap().trashed);

        // once the object is gone, everything works as before
        w.net.trash(&planted).await.unwrap();
        for v in [&a, &c] {
            let r = v.refresh().await.unwrap();
            assert!(r.corrupt_objects.is_empty(), "{what}");
        }
        assert_eq!(paths(&c), names(&["one", "three", "two"]), "{what}");
    }
}

/// The same bytes without a version reason stay what they were: corrupt, reported, ignored.
#[tokio::test]
async fn damage_is_still_reported_as_damage_not_as_a_newer_format() {
    let (w, a) = three_files().await;
    let stranger = DeviceId([9; 8]);
    let mut planted = Vec::new();
    // not a gclone stream at all; sealed for another stream type; an undecodable v1 body
    let mut bad_magic = w.keys.seal(StreamType::Segment, &[0x01]).unwrap();
    bad_magic[0] ^= 0x01;
    let wrong_type = w.keys.seal(StreamType::Snapshot, &[0x01]).unwrap();
    let garbage_body = w
        .keys
        .seal(StreamType::Segment, &[0x00, 0x00, 0xff])
        .unwrap();
    for (seq, bytes) in [(1, bad_magic), (2, wrong_type), (3, garbage_body)] {
        let name = segment_name(stranger, seq, blake3::hash(&bytes).as_bytes());
        w.plant(&name, bytes).await;
        planted.push(name);
    }
    planted.sort();
    for v in [&a, &w.device("c").await] {
        let r = v.refresh().await.unwrap();
        assert_eq!(r.corrupt_objects, planted);
        assert_eq!(paths(v), names(&["one", "three", "two"]));
    }
}

// --- oversized objects -----------------------------------------------------------------------

/// Index objects are buffered whole before anything in them is authenticated, so their size
/// is bounded before and while they are read — whatever the listing claims.
#[tokio::test]
async fn an_oversized_index_object_is_never_buffered() {
    const CAP: u64 = 64 * 1024;
    let (w, _a) = three_files().await;
    let stranger = DeviceId([9; 8]);
    let real: Vec<ObjMeta> = w.listed("s-");
    assert_eq!(real.len(), 4);
    let real_bytes: u64 = real.iter().map(|m| m.size).sum();
    assert!(real.iter().all(|m| m.size < CAP));

    // listed honestly with more than the cap: a segment and a snapshot
    let big = vec![0xab_u8; 3 * 1024 * 1024];
    let big_name = segment_name(stranger, 1, blake3::hash(&big).as_bytes());
    w.plant(&big_name, big).await;
    let big_snap = vec![0xef_u8; 1024 * 1024];
    let big_snap_name = snapshot_name(u64::MAX, stranger, blake3::hash(&big_snap).as_bytes());
    w.plant(&big_snap_name, big_snap).await;
    // a store that lies: listed with 100 bytes, serves two mebibytes
    let liar = vec![0xcd_u8; 2 * 1024 * 1024];
    let liar_name = segment_name(stranger, 2, blake3::hash(&liar).as_bytes());
    let liar_id = w.plant(&liar_name, liar).await;
    w.mem.claim_size(&liar_id, 100);
    let mut planted = vec![big_name, big_snap_name, liar_name];
    planted.sort();

    let mut c = w.device("c").await;
    c.set_index_object_max(CAP);
    for _ in 0..2 {
        let before = w.mem.counters();
        let r = c.refresh().await.unwrap();
        let after = w.mem.counters();
        assert_eq!(r.corrupt_objects, planted);
        assert_eq!(paths(&c), names(&["one", "three", "two"]));
        // What was listed as too large was not asked for at all, and of the liar exactly one
        // byte more than allowed arrived. (Second round: the real segments are known.)
        let (gets, bytes) = (after.get - before.get, after.get_bytes - before.get_bytes);
        if r.applied > 0 {
            assert_eq!((gets, bytes), (4 + 1, real_bytes + CAP + 1));
        } else {
            assert_eq!((gets, bytes), (1, CAP + 1));
        }
    }

    // an object of exactly the allowed size is still read whole (and then judged by content)
    let exact = vec![0x11_u8; CAP as usize];
    let exact_name = segment_name(stranger, 3, blake3::hash(&exact).as_bytes());
    w.plant(&exact_name, exact).await;
    let before = w.mem.counters().get_bytes;
    let r = c.refresh().await.unwrap();
    assert!(r.corrupt_objects.contains(&exact_name));
    assert_eq!(w.mem.counters().get_bytes - before, CAP + CAP + 1);
}

/// The descriptor is plaintext and found by name anywhere in the account: `discover` reads at
/// most `DESCRIPTOR_MAX` bytes of each hit, also when the listed size says it is small.
#[tokio::test]
async fn an_oversized_descriptor_is_never_buffered() {
    let (w, _a) = world().await;
    let genuine = w
        .mem
        .all_objects()
        .into_iter()
        .find(|m| m.name == DESCRIPTOR_NAME)
        .unwrap();
    // a well-formed descriptor, padded far beyond the limit, in a folder of its own
    let mut padded = w.mem.read(&genuine.handle).unwrap().to_vec();
    padded.resize(1024 * 1024, b' ');
    let ids = w.net.new_ids(3).await.unwrap();
    for (folder, lie) in [(&ids[0], None), (&ids[1], Some(200))] {
        w.net
            .create_folder(folder, &Handle::top(), "planted")
            .await
            .unwrap();
        let id = w.net.new_ids(1).await.unwrap().remove(0);
        let body = PutBody::Small(Bytes::from(padded.clone()));
        w.net.put(&id, folder, DESCRIPTOR_NAME, body).await.unwrap();
        if let Some(size) = lie {
            w.mem.claim_size(&id, size);
        }
    }

    let before = w.mem.counters();
    let found = V::discover(&*w.net).await.unwrap();
    let after = w.mem.counters();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].handles.root, w.handles.root);
    // the genuine one whole, one byte too many of the liar, nothing of the honestly listed one
    assert_eq!(after.get - before.get, 2);
    assert_eq!(
        after.get_bytes - before.get_bytes,
        genuine.size + DESCRIPTOR_MAX + 1
    );
}
