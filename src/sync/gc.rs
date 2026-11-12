//! Garbage collection (SPEC §5.9, §9.9) — owned by WP6.

use std::collections::HashSet;

use crate::backend::{Backend, Handle};
use crate::consts::ORPHAN_GRACE_MS;
use crate::error::{BackendError, SyncError};
use crate::format::blob_name;
use crate::index::Vault;

#[derive(Clone, Debug, Default)]
pub struct GcReport {
    pub dead_blobs: u64,
    pub dead_bytes: u64,
    pub orphans: u64,
    pub orphan_bytes: u64,
    pub purged: u64,
    pub purged_bytes: u64,
    pub purge_skipped: Vec<String>,
    pub dry_run: bool,
}

/// Already trashed or already gone is as good as trashed (§5.9).
async fn trash<B: Backend>(backend: &B, handle: &Handle) -> Result<(), BackendError> {
    match backend.trash(handle).await {
        Ok(()) | Err(BackendError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// §5.9; the caller checked the refresh verdict. Publishes nothing, so it works on a full
/// Drive and with a stuck outbox. All ages are server times (`Backend::now_ms`).
pub async fn gc<B: Backend>(
    vault: &Vault<B>,
    dry_run: bool,
    orphans: bool,
    purge: bool,
) -> Result<GcReport, SyncError> {
    let backend = &**vault.backend();
    let now = backend.now_ms();
    let mut report = GcReport {
        dry_run,
        ..GcReport::default()
    };

    // 1. Dead blobs: no head references them and the newest removed reference is older than
    //    GC_GRACE — `dead_blobs` applies that rule; it is not applied a second time here.
    for (rec, _dead_since) in vault.dead_blobs(now)? {
        if !dry_run {
            trash(backend, &Handle(rec.file_id.clone())).await?;
            vault.set_blob_trashed(&rec.id, Some(now))?;
        }
        report.dead_blobs += 1;
        report.dead_bytes += rec.clen;
    }

    // 2. Orphans: only inside this vault's own data folders, never an unscoped listing.
    if orphans {
        let mut known: HashSet<String> = vault.blobs()?.iter().map(|b| blob_name(&b.id)).collect();
        known.extend(vault.pending_blob_names()?);
        for folder in backend.list(&vault.handles().data).await? {
            if !folder.is_folder {
                continue;
            }
            for object in backend.list(&folder.handle).await? {
                let old = now.saturating_sub(object.created_ms) > ORPHAN_GRACE_MS;
                if object.is_folder || known.contains(&object.name) || !old {
                    continue;
                }
                if !dry_run {
                    trash(backend, &object.handle).await?;
                }
                report.orphans += 1;
                report.orphan_bytes += object.size;
            }
        }
    }

    // 3. Purge — the single place where gclone deletes permanently. Only ids from the blob
    //    table, and only objects that are in the trash exactly as they were uploaded.
    if purge {
        for rec in vault.purge_candidates(now)? {
            let handle = Handle(rec.file_id.clone());
            match backend.stat(&handle).await? {
                None => {
                    // Google purged it already.
                    if !dry_run {
                        vault.forget_blob(&rec.id)?;
                    }
                }
                Some(m)
                    if m.trashed
                        && !m.is_folder
                        && m.size == rec.clen
                        && m.md5.is_none_or(|md5| md5 == rec.md5) =>
                {
                    if !dry_run {
                        match backend.delete(&handle).await {
                            Ok(()) | Err(BackendError::NotFound) => {}
                            Err(e) => return Err(e.into()),
                        }
                        vault.forget_blob(&rec.id)?;
                    }
                    report.purged += 1;
                    report.purged_bytes += rec.clen;
                }
                Some(m) => report.purge_skipped.push(format!(
                    "{}: {}",
                    blob_name(&rec.id),
                    if m.trashed {
                        "size or md5 differ from the upload"
                    } else {
                        "not in the trash any more"
                    }
                )),
            }
        }
        if dry_run {
            // What step 1 would trash is purged by the same run.
            let dead = vault.dead_blobs(now)?;
            report.purged += dead.len() as u64;
            report.purged_bytes += dead.iter().map(|(rec, _)| rec.clen).sum::<u64>();
        }
    }
    Ok(report)
}
