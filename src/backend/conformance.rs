//! The generic backend contract of SPEC §12.1 (WP2) — owned by WP2. Lives in the library so
//! that WP2's and WP3's test binaries both call it (no `include!`).
//!
//! Only what §9.5 promises for every backend is asserted here; what a fake adds on top (a
//! trashed folder hiding its content, `stat(Handle::top())`, …) is tested where the fake is.

use std::collections::HashSet;
use std::ops::Range;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::{Backend, Handle, ObjMeta, PutBody, get_all, md5_of};
use crate::consts::PART_SIZE;
use crate::error::BackendError;

/// Deterministic, incompressible test bytes.
fn pattern(seed: u8, len: usize) -> Bytes {
    let mut buf = vec![0u8; len];
    blake3::Hasher::new()
        .update(&[seed])
        .finalize_xof()
        .fill(&mut buf);
    buf.into()
}

fn names(metas: &[ObjMeta]) -> Vec<&str> {
    let mut names: Vec<&str> = metas.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    names
}

/// Puts `parts` as a `Stream` body through a channel of capacity 1, the way the uploader does.
async fn put_stream<B: Backend>(
    b: &B,
    id: &Handle,
    parent: &Handle,
    name: &str,
    total: u64,
    parts: Vec<std::io::Result<Bytes>>,
) -> Result<ObjMeta, BackendError> {
    let (tx, rx) = mpsc::channel(1);
    let feed = async move {
        for part in parts {
            if tx.send(part).await.is_err() {
                break;
            }
        }
    };
    let body = PutBody::Stream { total, parts: rx };
    tokio::join!(b.put(id, parent, name, body), feed).0
}

async fn assert_range<B: Backend>(b: &B, h: &Handle, data: &[u8], range: Range<u64>) {
    let got = get_all(b, h, Some(range.clone()))
        .await
        .unwrap_or_else(|e| panic!("get {range:?}: {e}"));
    let end = range.end.min(data.len() as u64) as usize;
    assert!(
        got[..] == data[range.start as usize..end],
        "get {range:?} returned {} wrong bytes",
        got.len()
    );
}

/// Written with plain asserts. `b` must be empty. Works at `Handle::top()`.
#[doc(hidden)]
pub async fn run<B: Backend>(b: B) {
    let top = Handle::top();
    let part = PART_SIZE as usize;

    // --- ids, empty backend
    assert!(b.new_ids(0).await.unwrap().is_empty());
    let ids = b.new_ids(12).await.unwrap();
    assert_eq!(ids.len(), 12);
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 12, "ids repeat");
    assert!(ids.iter().all(|h| !h.is_top()));
    let [
        folder,
        sub,
        small,
        big,
        deep,
        top_file,
        twin,
        doomed,
        failed,
        ..,
    ] = &ids[..]
    else {
        unreachable!()
    };
    let absent = &ids[9];
    assert!(b.list(&top).await.unwrap().is_empty(), "backend not empty");
    assert!(b.find_by_name("small.bin").await.unwrap().is_empty());
    assert!(b.stat(absent).await.unwrap().is_none());
    b.about().await.unwrap();
    assert!(b.now_ms() > 0);

    // --- folders: idempotent, size 0, no md5, top-level parent
    b.create_folder(folder, &top, "folder").await.unwrap();
    b.create_folder(folder, &top, "folder").await.unwrap();
    b.create_folder(sub, folder, "sub").await.unwrap();
    b.create_folder(sub, folder, "sub").await.unwrap();
    let meta = b.stat(folder).await.unwrap().expect("stat of a folder");
    assert_eq!(meta.handle, *folder);
    assert_eq!(meta.name, "folder");
    assert_eq!(meta.parent, top);
    assert!(meta.is_folder && !meta.trashed);
    assert_eq!((meta.size, meta.md5), (0, None));
    let meta = b.stat(sub).await.unwrap().expect("stat of a nested folder");
    assert_eq!(meta.parent, *folder);
    assert!(meta.is_folder);
    let listed = b.list(&top).await.unwrap();
    assert_eq!(listed.len(), 1, "create_folder twice made two folders");
    assert_eq!(listed[0].handle, *folder);
    assert_eq!(listed[0].parent, top);
    assert!(listed[0].is_folder);
    assert_eq!((listed[0].size, listed[0].md5), (0, None));

    // --- Small put, whole and ranged get
    let small_data = pattern(1, 100_000);
    let put = b
        .put(
            small,
            folder,
            "small.bin",
            PutBody::Small(small_data.clone()),
        )
        .await
        .unwrap();
    assert_eq!(put.handle, *small);
    assert_eq!(put.name, "small.bin");
    assert_eq!(put.parent, *folder);
    assert_eq!(put.size, small_data.len() as u64);
    assert_eq!(put.md5, Some(md5_of(&small_data)));
    assert!(!put.is_folder && !put.trashed);
    let stat = b.stat(small).await.unwrap().expect("stat after put");
    assert_eq!(
        (&stat.handle, &stat.name, &stat.parent, stat.size, stat.md5),
        (&put.handle, &put.name, &put.parent, put.size, put.md5)
    );
    assert_eq!(stat.created_ms, put.created_ms);
    assert!(!stat.is_folder && !stat.trashed);
    assert!(get_all(&b, small, None).await.unwrap() == small_data);
    assert_range(&b, small, &small_data, 0..10).await;
    assert_range(&b, small, &small_data, 40_000..70_001).await;
    assert_range(&b, small, &small_data, 99_990..100_000).await;
    assert_range(&b, small, &small_data, 99_990..1_000_000).await;

    // --- Stream put: 3 parts + short tail
    let big_data = pattern(2, 3 * part + 12_345);
    let parts = big_data
        .chunks(part)
        .map(|c| Ok(big_data.slice_ref(c)))
        .collect();
    let total = big_data.len() as u64;
    let put = put_stream(&b, big, folder, "big.bin", total, parts)
        .await
        .unwrap();
    assert_eq!(put.handle, *big);
    assert_eq!(put.parent, *folder);
    assert_eq!(put.size, total);
    assert_eq!(put.md5, Some(md5_of(&big_data)));
    let stat = b.stat(big).await.unwrap().expect("stat after a stream put");
    assert_eq!((stat.size, stat.md5), (put.size, put.md5));
    assert!(get_all(&b, big, None).await.unwrap() == big_data);
    let p = PART_SIZE;
    assert_range(&b, big, &big_data, 0..4096).await; // start
    assert_range(&b, big, &big_data, p + 1000..p + 70_000).await; // middle of a part
    assert_range(&b, big, &big_data, p - 5000..p + 5000).await; // crossing parts
    assert_range(&b, big, &big_data, 2 * p - 1..3 * p + 1).await; // crossing two boundaries
    assert_range(&b, big, &big_data, total - 100..total + 100).await; // past the end: clamped
    assert_range(&b, big, &big_data, total - 100..u64::MAX).await;

    // --- put-once: an existing id answers with ITS meta and nothing is written
    let other = pattern(3, 5000);
    let again = b
        .put(small, &top, "other-name", PutBody::Small(other.clone()))
        .await
        .unwrap();
    assert_eq!(again.handle, *small);
    assert_eq!(
        (again.size, again.md5),
        (stat_size(&small_data), Some(md5_of(&small_data)))
    );
    assert_eq!(again.name, "small.bin");
    assert_eq!(again.parent, *folder);
    assert!(get_all(&b, small, None).await.unwrap() == small_data);
    let one_part = pattern(4, part + 1);
    let again = put_stream(
        &b,
        big,
        folder,
        "big.bin",
        one_part.len() as u64,
        one_part
            .chunks(part)
            .map(|c| Ok(one_part.slice_ref(c)))
            .collect(),
    )
    .await
    .unwrap();
    assert_eq!((again.size, again.md5), (total, Some(md5_of(&big_data))));
    assert_range(&b, big, &big_data, 0..4096).await;
    assert!(b.find_by_name("other-name").await.unwrap().is_empty());

    // --- list: direct, non-trashed children only; find_by_name: exact, anywhere
    b.put(deep, sub, "deep.bin", PutBody::Small(pattern(5, 10)))
        .await
        .unwrap();
    let top_data = pattern(6, 777);
    let put = b
        .put(top_file, &top, "top.bin", PutBody::Small(top_data.clone()))
        .await
        .unwrap();
    assert_eq!(put.parent, top);
    b.put(twin, sub, "small.bin", PutBody::Small(pattern(7, 20)))
        .await
        .unwrap();
    let in_top = b.list(&top).await.unwrap();
    assert_eq!(names(&in_top), ["folder", "top.bin"]);
    assert!(in_top.iter().all(|m| m.parent == top));
    let in_folder = b.list(folder).await.unwrap();
    assert_eq!(names(&in_folder), ["big.bin", "small.bin", "sub"]);
    assert!(in_folder.iter().all(|m| m.parent == *folder && !m.trashed));
    let listed = in_folder.iter().find(|m| m.name == "small.bin").unwrap();
    assert_eq!(listed.handle, *small);
    assert_eq!(
        (listed.size, listed.md5),
        (stat_size(&small_data), Some(md5_of(&small_data)))
    );
    let listed = in_folder.iter().find(|m| m.name == "sub").unwrap();
    assert!(listed.is_folder);
    assert_eq!((listed.size, listed.md5), (0, None));
    assert_eq!(
        names(&b.list(sub).await.unwrap()),
        ["deep.bin", "small.bin"]
    );

    let found = b.find_by_name("small.bin").await.unwrap();
    let found: HashSet<&Handle> = found.iter().map(|m| &m.handle).collect();
    assert_eq!(found, HashSet::from([small, twin]));
    let found = b.find_by_name("top.bin").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].handle, *top_file);
    assert_eq!(found[0].parent, top);
    assert_eq!(
        (found[0].size, found[0].md5),
        (777, Some(md5_of(&top_data)))
    );
    let found = b.find_by_name("sub").await.unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].is_folder);
    assert_eq!(found[0].handle, *sub);
    assert!(
        b.find_by_name("small").await.unwrap().is_empty(),
        "prefix match"
    );
    assert!(b.find_by_name("SMALL.BIN").await.unwrap().is_empty());

    // --- trash / untrash: idempotent, hidden from listings, still readable
    b.trash(small).await.unwrap();
    b.trash(small).await.unwrap();
    let stat = b
        .stat(small)
        .await
        .unwrap()
        .expect("stat of a trashed object");
    assert!(stat.trashed);
    assert_eq!(
        (stat.size, stat.md5),
        (stat_size(&small_data), Some(md5_of(&small_data)))
    );
    assert_eq!(names(&b.list(folder).await.unwrap()), ["big.bin", "sub"]);
    let found = b.find_by_name("small.bin").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].handle, *twin);
    assert!(get_all(&b, small, None).await.unwrap() == small_data);
    assert_range(&b, small, &small_data, 10..20).await;
    b.untrash(small).await.unwrap();
    b.untrash(small).await.unwrap();
    assert!(!b.stat(small).await.unwrap().unwrap().trashed);
    assert_eq!(
        names(&b.list(folder).await.unwrap()),
        ["big.bin", "small.bin", "sub"]
    );
    assert_eq!(b.find_by_name("small.bin").await.unwrap().len(), 2);
    b.trash(top_file).await.unwrap();
    assert_eq!(names(&b.list(&top).await.unwrap()), ["folder"]);
    b.untrash(top_file).await.unwrap();
    assert_eq!(names(&b.list(&top).await.unwrap()), ["folder", "top.bin"]);

    // --- delete: gone for good, also from the trash
    b.put(
        doomed,
        folder,
        "doomed.bin",
        PutBody::Small(pattern(8, 300)),
    )
    .await
    .unwrap();
    b.delete(doomed).await.unwrap();
    assert!(b.stat(doomed).await.unwrap().is_none());
    assert!(b.find_by_name("doomed.bin").await.unwrap().is_empty());
    assert_eq!(
        names(&b.list(folder).await.unwrap()),
        ["big.bin", "small.bin", "sub"]
    );
    b.trash(twin).await.unwrap();
    b.delete(twin).await.unwrap();
    assert!(b.stat(twin).await.unwrap().is_none());

    // --- NotFound
    for gone in [doomed, twin, absent] {
        assert!(matches!(
            b.get(gone, None).await,
            Err(BackendError::NotFound)
        ));
        assert!(matches!(
            b.get(gone, Some(0..10)).await,
            Err(BackendError::NotFound)
        ));
        assert!(matches!(b.trash(gone).await, Err(BackendError::NotFound)));
        assert!(matches!(b.untrash(gone).await, Err(BackendError::NotFound)));
        assert!(matches!(b.delete(gone).await, Err(BackendError::NotFound)));
        assert!(b.stat(gone).await.unwrap().is_none());
    }

    // --- a failing source aborts the put and leaves nothing behind
    let first = pattern(9, part);
    let parts = vec![Ok(first), Err(std::io::Error::other("the source changed"))];
    let result = put_stream(&b, failed, folder, "failed.bin", 2 * PART_SIZE, parts).await;
    assert!(
        matches!(result, Err(BackendError::Io(_))),
        "a failing part must abort the put with Io, got {:?}",
        result.map(|m| m.size)
    );
    assert!(b.stat(failed).await.unwrap().is_none());
    assert!(b.find_by_name("failed.bin").await.unwrap().is_empty());
    assert_eq!(
        names(&b.list(folder).await.unwrap()),
        ["big.bin", "small.bin", "sub"]
    );
}

fn stat_size(data: &[u8]) -> u64 {
    data.len() as u64
}
