//! `gclone check` (SPEC §5.9, §9.9) — owned by WP6.

use std::collections::{HashMap, HashSet};

use futures_util::StreamExt;

use super::blocking;
use super::scan::{Filter, remote_rows, scan};
use crate::backend::{Backend, ObjMeta};
use crate::error::{SyncError, TransferError};
use crate::format::blob_name;
use crate::index::Vault;
use crate::transfer::{hash_file, locate_blob, verify_remote};
use crate::types::{BlobId, BlobRec, EntryKind};

/// Files verified at a time by `check --download`.
const VERIFY_STREAMS: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct CheckReport {
    pub checked: u64,
    pub missing: Vec<String>,
    pub mismatched: Vec<String>,
    pub untrashed: Vec<String>,
    pub listed_late: u64,
    pub orphans: u64,
    pub differing: Vec<String>,
}

impl CheckReport {
    /// Nothing missing, damaged or different (exit 0; otherwise exit 3).
    pub fn ok(&self) -> bool {
        self.missing.is_empty() && self.mismatched.is_empty() && self.differing.is_empty()
    }
}

/// Size, and md5 where the backend reports one. The md5 is Google's own statement: a check
/// against accidental corruption, never tamper evidence (§1.3).
fn intact(meta: &ObjMeta, rec: &BlobRec) -> bool {
    meta.size == rec.clen && meta.md5.is_none_or(|md5| md5 == rec.md5)
}

fn damaged(rec: &BlobRec) -> String {
    format!(
        "{} (accidental corruption check; md5 is reported by Google)",
        blob_name(&rec.id)
    )
}

/// Lists this vault's data folders and compares them with the blob table. Absence is
/// confirmed by ID before it is reported (§5.9): a listing never proves absence.
pub async fn check_blobs<B: Backend>(vault: &Vault<B>) -> Result<CheckReport, SyncError> {
    let backend = &**vault.backend();
    let now = backend.now_ms();
    let mut report = CheckReport::default();

    let mut listed: HashMap<String, Vec<ObjMeta>> = HashMap::new();
    for folder in backend.list(&vault.handles().data).await? {
        if !folder.is_folder {
            continue;
        }
        for object in backend.list(&folder.handle).await? {
            if !object.is_folder {
                listed.entry(object.name.clone()).or_default().push(object);
            }
        }
    }

    // Blobs that are allowed to be gone: trashed by this device's gc, or dead for longer than
    // the grace period (another device's gc may have trashed them).
    let mut expendable: HashSet<BlobId> = vault
        .purge_candidates(i64::MAX as u64)?
        .iter()
        .map(|rec| rec.id)
        .collect();
    expendable.extend(vault.dead_blobs(now)?.iter().map(|(rec, _)| rec.id));

    let blobs = vault.blobs()?;
    let mut known: HashSet<String> = blobs.iter().map(|b| blob_name(&b.id)).collect();
    for rec in blobs.iter().filter(|rec| !expendable.contains(&rec.id)) {
        report.checked += 1;
        let name = blob_name(&rec.id);
        let seen = listed.get(&name).and_then(|objects| {
            objects
                .iter()
                .find(|m| m.handle.0 == rec.file_id)
                .or(objects.first())
        });
        let meta = match seen {
            Some(meta) => meta.clone(),
            None => match locate_blob(backend, rec).await {
                Ok(meta) => {
                    if meta.trashed {
                        // Referenced but trashed: healed on the spot.
                        backend.untrash(&meta.handle).await?;
                        vault.set_blob_trashed(&rec.id, None)?;
                        report.untrashed.push(name);
                    } else {
                        report.listed_late += 1;
                    }
                    meta
                }
                Err(TransferError::BlobMissing(_)) => {
                    report.missing.push(name);
                    continue;
                }
                Err(e) => return Err(e.into()),
            },
        };
        if !intact(&meta, rec) {
            report.mismatched.push(damaged(rec));
        }
    }

    known.extend(vault.pending_blob_names()?);
    report.orphans = listed
        .iter()
        .filter(|(name, _)| !known.contains(*name))
        .map(|(_, objects)| objects.len() as u64)
        .sum();
    Ok(report)
}

/// `check LOCAL :REMOTE`: hashes the local files and compares `(size, BLAKE3)` with the index.
/// Downloads nothing.
pub async fn check_local<B: Backend>(
    vault: &Vault<B>,
    local_root: &std::path::Path,
    prefix: &str,
) -> Result<CheckReport, SyncError> {
    // Comparing with a remote directory that does not exist is a mistyped path, not a tree
    // that happens to differ in every file (and, with an empty local tree, not "all good").
    if !prefix.is_empty() && !vault.exists_dir(prefix)? {
        return Err(super::no_such_remote(prefix, "directory"));
    }
    let root = std::fs::canonicalize(local_root)?;
    let filter = Filter::new(&[], &root)?;
    let local = {
        let (root, filter) = (root.clone(), filter.clone());
        blocking(move || scan(&root, &filter)).await?
    };
    let (remote, remote_collisions) = remote_rows(vault, prefix, &filter, local.fold_case)?;

    let mut report = CheckReport::default();
    for key in local.collisions.iter().chain(&remote_collisions) {
        report
            .differing
            .push(format!("{key}: names differ only by case or Unicode form"));
    }
    for dir in &local.failed_dirs {
        report.differing.push(format!("{dir}: cannot be read"));
    }
    let mut remote_files: HashMap<&str, _> = remote
        .iter()
        .filter(|r| r.head.entry.kind == EntryKind::File)
        .map(|r| (r.key.as_str(), r))
        .collect();
    // (rel, expected hash) of the files whose size matches: only those need hashing.
    let mut to_hash: Vec<(String, [u8; 32])> = Vec::new();
    for entry in local.entries.iter().filter(|e| e.kind == EntryKind::File) {
        report.checked += 1;
        match remote_files.remove(entry.key.as_str()) {
            None => report.differing.push(format!("{}: only local", entry.rel)),
            Some(r) if r.head.entry.size != entry.sig.size => report
                .differing
                .push(format!("{}: sizes differ", entry.rel)),
            Some(r) => to_hash.push((entry.rel.clone(), r.head.entry.hash)),
        }
    }
    let mut only_remote: Vec<&str> = remote_files.values().map(|r| r.rel.as_str()).collect();
    only_remote.sort_unstable();
    for rel in only_remote {
        report.checked += 1;
        report.differing.push(format!("{rel}: only remote"));
    }

    let mut differing = blocking(move || {
        let mut out = Vec::new();
        for (rel, expected) in to_hash {
            match hash_file(&root.join(&rel)) {
                Ok((_, _, hash)) if hash == expected => {}
                Ok(_) => out.push(format!("{rel}: contents differ")),
                Err(e) => out.push(format!("{rel}: {e}")),
            }
        }
        Ok(out)
    })
    .await?;
    report.differing.append(&mut differing);
    Ok(report)
}

/// `check --download [:PATH]`: downloads every file under `prefix`, authenticates every chunk
/// and compares BLAKE3. Writes nothing.
pub async fn check_download<B: Backend>(
    vault: &Vault<B>,
    prefix: &str,
    progress: crate::ui::Progress,
) -> Result<CheckReport, SyncError> {
    let backend = &**vault.backend();
    let keys = vault.keys();
    let mut report = CheckReport::default();
    let mut jobs = Vec::new();
    let heads = vault.walk(prefix)?;
    // Nothing at or under the path: a check that checked nothing must not say "all good".
    if heads.is_empty() && !prefix.is_empty() {
        return Err(super::no_such_remote(prefix, "file or directory"));
    }
    for head in heads {
        if head.entry.kind != EntryKind::File {
            continue;
        }
        let Some(loc) = &head.entry.loc else {
            // A zero-length file has no blob: its entry must say so consistently.
            report.checked += 1;
            if head.entry.size != 0 || head.entry.hash != *blake3::hash(b"").as_bytes() {
                report
                    .mismatched
                    .push(format!("{}: not a zero-length file", head.path));
            }
            continue;
        };
        match vault.blob(&loc.blob)? {
            Some(rec) => jobs.push((head, rec)),
            None => {
                report.checked += 1;
                report.missing.push(head.path);
            }
        }
    }
    let mut results = futures_util::stream::iter(jobs)
        .map(|(head, rec)| async move {
            let result = verify_remote(backend, keys, &rec, &head).await;
            (head, result)
        })
        .buffer_unordered(VERIFY_STREAMS);
    while let Some((head, result)) = results.next().await {
        report.checked += 1;
        progress.add_bytes(head.entry.size);
        progress.file_done();
        match result {
            Ok(()) => {}
            Err(TransferError::BlobMissing(_)) => report.missing.push(head.path),
            Err(e @ (TransferError::Verify(_) | TransferError::Crypto(_))) => {
                report.mismatched.push(format!("{}: {e}", head.path))
            }
            Err(e) => return Err(e.into()),
        }
    }
    report.missing.sort();
    report.mismatched.sort();
    Ok(report)
}
