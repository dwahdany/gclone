//! Remote-only commands (SPEC §5.5.4, §9.9) — owned by WP6. Index-only; each commits one
//! segment via `commit_ops` and nothing more.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use crate::backend::Backend;
use crate::consts::RESTORE_WINDOW_MS;
use crate::error::{SyncError, TransferError};
use crate::index::Vault;
use crate::path;
use crate::transfer::locate_blob;
use crate::types::{BlobId, Entry, EntryKind, Head, OpDraft, RemovedVersion};

fn usage(message: String) -> SyncError {
    SyncError::Usage(message)
}

fn not_found(path: &str) -> SyncError {
    SyncError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(":{path}: no such file or directory"),
    ))
}

fn valid(path: &str) -> Result<(), SyncError> {
    path::validate(path).map_err(|e| usage(format!(":{path}: {e}")))
}

/// A file may not stand where a directory is needed: the index would move it to a conflict
/// name (§5.2.3 rule 2).
fn no_file_above<B: Backend>(vault: &Vault<B>, path: &str) -> Result<(), SyncError> {
    for ancestor in path::ancestors(path) {
        if vault
            .head(ancestor)?
            .is_some_and(|h| h.entry.kind == EntryKind::File)
        {
            return Err(usage(format!(":{ancestor} is a file, not a directory")));
        }
    }
    Ok(())
}

/// Winners strictly under `path/`.
fn children<B: Backend>(vault: &Vault<B>, path: &str) -> Result<Vec<Head>, SyncError> {
    let mut heads = vault.walk(path)?;
    heads.retain(|h| h.path != path);
    Ok(heads)
}

/// `Put{p, Dir, base: None}`; a no-op if the directory exists already. `Ok(true)` = created.
pub async fn mkdir<B: Backend>(vault: &Vault<B>, path: &str) -> Result<bool, SyncError> {
    valid(path)?;
    match vault.head(path)? {
        Some(h) if h.entry.kind == EntryKind::File => {
            return Err(usage(format!(":{path} exists and is a file")));
        }
        Some(_) => return Ok(false),
        None if vault.exists_dir(path)? => return Ok(false),
        None => {}
    }
    no_file_above(vault, path)?;
    vault
        .commit_ops(vec![OpDraft::Put {
            path: path.to_string(),
            entry: Entry::dir(),
            base: None,
            origin: None,
            effect: None,
        }])
        .await?;
    Ok(true)
}

/// `Del{q, base: winner(q).stamp}` for each path (and everything under it with `recursive`;
/// without it a non-empty directory is refused). Returns the number of entries removed.
pub async fn rm<B: Backend>(
    vault: &Vault<B>,
    paths: &[String],
    recursive: bool,
) -> Result<u64, SyncError> {
    let mut doomed: BTreeMap<String, Head> = BTreeMap::new();
    for p in paths {
        valid(p)?;
        let below = children(vault, p)?;
        let at = vault.head(p)?;
        if at.is_none() && below.is_empty() {
            return Err(not_found(p));
        }
        if !below.is_empty() && !recursive {
            return Err(usage(format!(":{p} is a directory; use -r to remove it")));
        }
        for head in at.into_iter().chain(below) {
            doomed.insert(head.path.clone(), head);
        }
    }
    let drafts: Vec<OpDraft> = doomed
        .into_values()
        .map(|h| OpDraft::Del {
            path: h.path,
            base: h.stamp,
            effect: None,
        })
        .collect();
    let removed = drafts.len() as u64;
    vault.commit_ops(drafts).await?;
    Ok(removed)
}

/// What [`mv`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Moved {
    /// Where the source is now: `to`, or `to/<name of from>` when `to` was a directory.
    pub to: String,
    /// Entries moved.
    pub entries: u64,
    /// Live files at the destination that were replaced (only with `force`).
    pub replaced: u64,
}

/// `mv :from :to`, with the rules of the shell command (§5.5.4):
/// - `to` is an existing directory (the root, a directory marker, or anything with entries
///   under it) → the source moves **into** it and keeps its name;
/// - otherwise the source is renamed to `to`.
///
/// Nothing that exists at the destination is replaced or merged into unless `force` is set:
/// then a file replaces a file, and a directory is merged into a directory, replacing files of
/// the same name (`Moved.replaced`; the replaced versions stay restorable). A file never
/// replaces a directory and a directory never replaces a file.
///
/// For every winner `q` at `from` or under it: `Put{dest‖suffix, same entry, base: the
/// target's winner, origin: q}` then `Del{q}`, in one segment.
pub async fn mv<B: Backend>(
    vault: &Vault<B>,
    from: &str,
    to: &str,
    force: bool,
) -> Result<Moved, SyncError> {
    valid(from)?;
    if !to.is_empty() {
        valid(to)?;
    }
    let sources = vault.walk(from)?;
    if sources.is_empty() {
        return Err(not_found(from));
    }
    if to == from {
        return Err(usage(format!(
            ":{from}: the source and the destination are the same"
        )));
    }
    let into = vault.exists_dir(to)?;
    let dest = if into {
        path::join(to, path::file_name(from))
    } else {
        to.to_string()
    };
    if dest == from {
        return Err(usage(format!(":{from} is there already")));
    }
    if path::strip_prefix(&dest, from).is_some() {
        return Err(usage(format!(":{dest} is inside :{from}")));
    }
    no_file_above(vault, &dest)?;

    let source_is_dir =
        sources.iter().any(|h| h.path != from) || sources[0].entry.kind == EntryKind::Dir;
    let target_is_file = vault
        .head(&dest)?
        .is_some_and(|h| h.entry.kind == EntryKind::File);
    let target_is_dir = vault.exists_dir(&dest)?;
    if source_is_dir {
        if target_is_file {
            return Err(usage(format!(
                ":{dest} exists and is a file; remove it first (gclone rm)"
            )));
        }
        if target_is_dir && !force {
            return Err(usage(format!(
                ":{dest} exists already. Nothing was moved: choose another name, or pass \
                 --force to merge into it (files of the same name are replaced and stay \
                 restorable for 25 days)"
            )));
        }
    } else {
        if target_is_dir {
            return Err(usage(format!(
                ":{dest} is a directory; a file cannot replace it"
            )));
        }
        if target_is_file && !force {
            return Err(usage(format!(
                ":{dest} exists already. Nothing was moved: choose another name, or pass \
                 --force to replace it (the replaced version stays restorable for 25 days)"
            )));
        }
    }

    let (mut puts, mut dels) = (Vec::new(), Vec::new());
    let mut replaced = 0;
    for q in sources {
        let suffix = path::strip_prefix(&q.path, from).unwrap_or_default();
        let target = path::join(&dest, suffix);
        let at = vault.head(&target)?;
        let mut put = true;
        if target_is_dir {
            // A merge: every entry is checked against what stands at its new place.
            no_file_above(vault, &target)?;
            let at_is_file = at.as_ref().is_some_and(|h| h.entry.kind == EntryKind::File);
            let dir_there = vault.exists_dir(&target)?;
            match q.entry.kind {
                EntryKind::File if dir_there => {
                    return Err(usage(format!(
                        ":{target} is a directory, :{} is a file; nothing was moved",
                        q.path
                    )));
                }
                EntryKind::Dir if at_is_file => {
                    return Err(usage(format!(
                        ":{target} is a file, :{} is a directory; nothing was moved",
                        q.path
                    )));
                }
                // The directory exists there already: only the source marker goes.
                EntryKind::Dir if dir_there => put = false,
                _ => {}
            }
        }
        if put {
            if at.as_ref().is_some_and(|h| h.entry.kind == EntryKind::File) {
                replaced += 1;
            }
            puts.push(OpDraft::Put {
                base: at.map(|h| h.stamp),
                path: target,
                entry: q.entry,
                origin: Some(q.stamp),
                effect: None,
            });
        }
        dels.push(OpDraft::Del {
            path: q.path,
            base: q.stamp,
            effect: None,
        });
    }
    let entries = dels.len() as u64;
    puts.append(&mut dels);
    vault.commit_ops(puts).await?;
    Ok(Moved {
        to: dest,
        entries,
        replaced,
    })
}

/// Is the blob of this removed version still there (size, and md5 where the backend reports
/// one)? Answers are remembered per blob: the files of one pack share a lookup.
async fn blob_present<B: Backend>(
    vault: &Vault<B>,
    version: &RemovedVersion,
    seen: &mut HashMap<BlobId, bool>,
) -> Result<bool, SyncError> {
    let Some(loc) = &version.entry.loc else {
        return Ok(true);
    };
    if let Some(known) = seen.get(&loc.blob) {
        return Ok(*known);
    }
    let present = match vault.blob(&loc.blob)? {
        None => false,
        Some(rec) => match locate_blob(&**vault.backend(), &rec).await {
            Ok(meta) => meta.size == rec.clen && meta.md5.is_none_or(|m| m == rec.md5),
            Err(TransferError::BlobMissing(_)) => false,
            Err(e) => return Err(e.into()),
        },
    };
    seen.insert(loc.blob, present);
    Ok(present)
}

fn in_window(version: &RemovedVersion, now_ms: u64) -> bool {
    version.entry.kind == EntryKind::File
        && now_ms.saturating_sub(version.removed_ms) < RESTORE_WINDOW_MS
}

/// Within `RESTORE_WINDOW`, newest first. Only versions whose blob can still be located are
/// offered.
pub async fn restore_candidates<B: Backend>(
    vault: &Vault<B>,
    path: &str,
    now_ms: u64,
) -> Result<Vec<RemovedVersion>, SyncError> {
    valid(path)?;
    let mut seen = HashMap::new();
    let mut offered = Vec::new();
    for version in vault.removed_versions(path)? {
        if in_window(&version, now_ms) && blob_present(vault, &version, &mut seen).await? {
            offered.push(version);
        }
    }
    Ok(offered)
}

/// One path under a directory that `restore` can bring back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restorable {
    /// The newest restorable version of the path.
    pub version: RemovedVersion,
    /// The path has a live entry now: the version was overwritten, not deleted. `restore -r`
    /// leaves such a path alone.
    pub live: bool,
}

/// The restorable **files** strictly under `prefix/` (`""` = the whole vault), sorted by path:
/// for each path the newest version inside `RESTORE_WINDOW` whose blob can still be located.
/// This is what `restore --list :DIR` shows and `restore -r :DIR` works from (§5.5.4).
pub async fn restorable_under<B: Backend>(
    vault: &Vault<B>,
    prefix: &str,
    now_ms: u64,
) -> Result<Vec<Restorable>, SyncError> {
    if !prefix.is_empty() {
        valid(prefix)?;
    }
    let since = now_ms.saturating_sub(RESTORE_WINDOW_MS);
    let mut seen = HashMap::new();
    let mut out: Vec<Restorable> = Vec::new();
    // The path being looked at and its live entry.
    let mut at: Option<(String, Option<Head>)> = None;
    for version in vault.removed_under(prefix, since)? {
        // Newest first within a path: the first usable one is the answer for the path.
        if out.last().is_some_and(|r| r.version.path == version.path)
            || !in_window(&version, now_ms)
        {
            continue;
        }
        if at.as_ref().is_none_or(|(path, _)| *path != version.path) {
            at = Some((version.path.clone(), vault.head(&version.path)?));
        }
        let live = at.as_ref().and_then(|(_, head)| head.as_ref());
        // A removed version with the content the path has now would bring nothing back (it
        // was restored already, or the same bytes were uploaded again).
        if live.is_some_and(|h| {
            h.entry.kind == EntryKind::File
                && h.entry.size == version.entry.size
                && h.entry.hash == version.entry.hash
        }) {
            continue;
        }
        let live = live.is_some();
        if blob_present(vault, &version, &mut seen).await? {
            out.push(Restorable { version, live });
        }
    }
    Ok(out)
}

/// The blob of a version about to be restored: located, verified, un-trashed.
async fn revive_blob<B: Backend>(
    vault: &Vault<B>,
    version: &RemovedVersion,
) -> Result<(), SyncError> {
    let Some(loc) = &version.entry.loc else {
        return Ok(());
    };
    let rec = vault
        .blob(&loc.blob)?
        .ok_or_else(|| TransferError::BlobMissing(loc.blob.hex()))?;
    let meta = locate_blob(&**vault.backend(), &rec).await?;
    if meta.size != rec.clen || meta.md5.is_some_and(|m| m != rec.md5) {
        return Err(TransferError::Verify(format!(
            "blob {} is not the object that was uploaded",
            rec.id
        ))
        .into());
    }
    if meta.trashed {
        vault.backend().untrash(&meta.handle).await?;
    }
    // Clears a mark left by this device's own gc as well.
    vault.set_blob_trashed(&rec.id, None)?;
    Ok(())
}

/// `Put{p, entry: the removed version, base: winner(p).stamp or None, origin: its stamp}`.
/// The blob is located first (and un-trashed if needed); a version whose blob is gone is
/// refused with `TransferError::BlobMissing`.
pub async fn restore<B: Backend>(
    vault: &Vault<B>,
    path: &str,
    version: &RemovedVersion,
) -> Result<(), SyncError> {
    valid(path)?;
    if version.entry.kind != EntryKind::File {
        return Err(usage(format!(":{path}: only files can be restored")));
    }
    no_file_above(vault, path)?;
    if !children(vault, path)?.is_empty() {
        return Err(usage(format!(":{path} is a directory now")));
    }
    revive_blob(vault, version).await?;
    vault
        .commit_ops(vec![OpDraft::Put {
            path: path.to_string(),
            entry: version.entry.clone(),
            base: vault.head(path)?.map(|h| h.stamp),
            origin: Some(version.stamp),
            effect: None,
        }])
        .await?;
    Ok(())
}

/// What [`restore_many`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    /// Paths that have their version back.
    pub restored: u64,
    /// `(path, why)` for each version that was left out; nothing was changed for these.
    pub skipped: Vec<(String, String)>,
}

/// Restores every given version at its own path, **in one segment** (`restore -r`, several
/// paths). A version that cannot go back — its blob is gone, a file stands where one of its
/// directories is needed, the path is a directory now, or another version of this call needs
/// the path as a directory (the one removed later wins) — is skipped and reported; the others
/// are restored. A later version of the same path in `versions` is ignored.
pub async fn restore_many<B: Backend>(
    vault: &Vault<B>,
    versions: &[RemovedVersion],
) -> Result<Restored, SyncError> {
    let mut out = Restored::default();
    // Newest removal first: where a file and a directory of the same name both ask to come
    // back, the state that existed last is the one restored. "Newest" is the causal order of
    // the superseding ops (`by`), not the removal times: those follow the clocks of the
    // writers and of the store (§5.2.2).
    let mut order: Vec<&RemovedVersion> = versions.iter().collect();
    order.sort_by(|a, b| {
        b.by.cmp(&a.by)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| b.stamp.cmp(&a.stamp))
    });
    let mut accepted: BTreeMap<&str, &RemovedVersion> = BTreeMap::new();
    let mut revived: HashMap<BlobId, Result<(), String>> = HashMap::new();
    for version in order {
        let path = version.path.as_str();
        if accepted.contains_key(path) {
            continue;
        }
        let mut skip = |why: String| out.skipped.push((path.to_string(), why));
        if let Err(e) = path::validate(path) {
            skip(e.to_string());
            continue;
        }
        if version.entry.kind != EntryKind::File {
            skip("only files can be restored".into());
            continue;
        }
        let (lo, hi) = (format!("{path}/"), format!("{path}0"));
        let clash = path::ancestors(path)
            .find(|a| accepted.contains_key(a))
            .or_else(|| {
                accepted
                    .range::<str, _>((Bound::Included(lo.as_str()), Bound::Excluded(hi.as_str())))
                    .next()
                    .map(|(p, _)| *p)
            });
        if let Some(other) = clash {
            skip(format!(
                "its name is needed by :{other}, which was removed later and is restored"
            ));
            continue;
        }
        if let Err(e) = no_file_above(vault, path) {
            skip(match e {
                SyncError::Usage(text) => text,
                other => return Err(other),
            });
            continue;
        }
        if vault.exists_dir(path)? {
            skip("it is a directory now".into());
            continue;
        }
        if let Some(loc) = &version.entry.loc {
            let state = match revived.get(&loc.blob) {
                Some(state) => state.clone(),
                None => {
                    let state = match revive_blob(vault, version).await {
                        Ok(()) => Ok(()),
                        Err(SyncError::Transfer(
                            e @ (TransferError::BlobMissing(_) | TransferError::Verify(_)),
                        )) => Err(e.to_string()),
                        Err(e) => return Err(e),
                    };
                    revived.insert(loc.blob, state.clone());
                    state
                }
            };
            if let Err(why) = state {
                skip(why);
                continue;
            }
        }
        accepted.insert(path, version);
    }
    out.skipped.sort();
    let mut drafts = Vec::with_capacity(accepted.len());
    for (path, version) in accepted {
        drafts.push(OpDraft::Put {
            path: path.to_string(),
            entry: version.entry.clone(),
            base: vault.head(path)?.map(|h| h.stamp),
            origin: Some(version.stamp),
            effect: None,
        });
    }
    out.restored = drafts.len() as u64;
    if !drafts.is_empty() {
        vault.commit_ops(drafts).await?;
    }
    Ok(out)
}
