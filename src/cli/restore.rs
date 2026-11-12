//! `gclone restore` (SPEC §5.5.4, §10) — owned by WP7.

use super::{Ctx, GlobalOpts, OpenOpts, open_ctx, remote_arg, shown, usage};
use crate::backend::Backend as _;
use crate::sync::remote_ops::{self, Restorable};
use crate::types::RemovedVersion;
use crate::util::{format_local_minute, group_thousands, human_size};

#[derive(clap::Args, Clone, Debug)]
pub struct RestoreArgs {
    /// Remote paths (`:PATH`): files, or — with `-r` or `--list` — directories.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<String>,
    /// Restore every deleted file under a directory: the newest removed version of each, all
    /// in one step. Files that exist now are left as they are.
    #[arg(short = 'r', long)]
    pub recursive: bool,
    /// List what can be restored instead of restoring: the versions of a file, or the
    /// restorable files under a directory (`:` = the whole vault).
    #[arg(long, conflicts_with = "version")]
    pub list: bool,
    /// Which version of a file to restore (the K column of `--list`; default: the newest).
    /// Takes exactly one file PATH.
    #[arg(long, value_name = "K", value_parser = clap::value_parser!(u32).range(1..))]
    pub version: Option<u32>,
}

/// The versions `--list` shows and `--version K` counts: newest first. The vault root is no
/// file and has none.
async fn candidates(ctx: &Ctx, path: &str, now: u64) -> anyhow::Result<Vec<RemovedVersion>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    Ok(remote_ops::restore_candidates(&ctx.vault, path, now).await?)
}

/// `(deleted)` when no version of this path took the removed one's place: the op that
/// superseded it (`by`) was a delete or a move away, not a new upload.
fn why(
    ctx: &Ctx,
    path: &str,
    version: &RemovedVersion,
    all: &[RemovedVersion],
) -> anyhow::Result<&'static str> {
    let replaced = all.iter().any(|v| v.stamp == version.by)
        || ctx.vault.heads(path)?.iter().any(|h| h.stamp == version.by)
        || ctx
            .vault
            .removed_versions(path)?
            .iter()
            .any(|v| v.stamp == version.by);
    Ok(if replaced {
        "(overwritten)"
    } else {
        "(deleted)"
    })
}

fn files(n: usize) -> String {
    format!(
        "{} {}",
        group_thousands(n as u64),
        if n == 1 { "file" } else { "files" }
    )
}

fn not_found(text: String) -> anyhow::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, text).into()
}

/// `--list` for one path: the versions of the file at it, and the restorable files under it.
async fn list(ctx: &Ctx, path: &str, now: u64) -> anyhow::Result<()> {
    let versions = candidates(ctx, path, now).await?;
    let under = remote_ops::restorable_under(&ctx.vault, path, now).await?;
    if versions.is_empty() && under.is_empty() {
        ctx.ui.out(&format!(
            "No restorable version of {}, and nothing restorable under it (removed versions are \
             kept for 25 days).",
            shown(path)
        ));
        return Ok(());
    }
    if !versions.is_empty() {
        let devices = ctx.vault.devices()?;
        ctx.ui.out(&format!(
            "{:>3}  {:<16}   {:<9} {}",
            "K", "removed", "size", "by"
        ));
        for (k, v) in versions.iter().enumerate() {
            let by = devices
                .iter()
                .find(|d| d.id == v.by.device)
                .map_or_else(|| v.by.device.short(), |d| d.name.clone());
            ctx.ui.out(&format!(
                "{:>3}  {:<16}   {:<9} {by}   {}",
                k + 1,
                format_local_minute(v.removed_ms),
                human_size(v.entry.size),
                why(ctx, path, v, &versions)?
            ));
        }
    }
    if !under.is_empty() {
        ctx.ui.out(&format!(
            "{:<16}   {:<9} {:<11}  path",
            "removed", "size", "state"
        ));
        for Restorable { version, live } in &under {
            ctx.ui.out(&format!(
                "{:<16}   {:<9} {:<11}  {}",
                format_local_minute(version.removed_ms),
                human_size(version.entry.size),
                if *live { "overwritten" } else { "deleted" },
                shown(&version.path)
            ));
        }
        let deleted = under.iter().filter(|r| !r.live).count();
        ctx.ui.out(&format!(
            "{} under {} can be restored ({} deleted, {} overwritten). `gclone restore -r {}` \
             brings back the deleted ones; `gclone restore :PATH` brings back one file, and \
             `gclone restore --list :PATH` shows its versions.",
            files(under.len()),
            shown(path),
            group_thousands(deleted as u64),
            group_thousands((under.len() - deleted) as u64),
            shown(path)
        ));
    }
    Ok(())
}

pub async fn run(g: &GlobalOpts, args: RestoreArgs) -> anyhow::Result<i32> {
    let mut paths: Vec<String> = Vec::with_capacity(args.paths.len());
    for arg in &args.paths {
        let path = remote_arg(arg)?;
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if args.version.is_some() && (paths.len() != 1 || paths[0].is_empty()) {
        return Err(usage(
            "--version picks one version of one file: name exactly one file path",
        ));
    }
    let opts = if args.list {
        OpenOpts::read_only()
    } else {
        OpenOpts::mutating()
    };
    let ctx = open_ctx(g, opts).await?;
    // Ages are judged on the server's clock, like everything gc does (§5.9).
    let now = ctx.vault.backend().now_ms();
    if args.list {
        ctx.report_refresh();
        for (i, path) in paths.iter().enumerate() {
            if i > 0 {
                ctx.ui.out("");
            }
            list(&ctx, path, now).await?;
        }
        return Ok(0);
    }
    ctx.require_commit()?;

    // What to bring back: for a file the chosen version; for a directory (-r) the newest
    // removed version of every file under it that does not exist now.
    let mut chosen: Vec<RemovedVersion> = Vec::new();
    let mut left_alone = 0;
    for path in &paths {
        let versions = candidates(&ctx, path, now).await?;
        if let Some(k) = args.version {
            let Some(version) = versions.get(k as usize - 1) else {
                return Err(not_found(if versions.is_empty() {
                    format!(
                        "{}: no restorable version (removed versions are kept for 25 days)",
                        shown(path)
                    )
                } else {
                    format!(
                        "{}: there is no version {k} (see `gclone restore --list {}`)",
                        shown(path),
                        shown(path)
                    )
                }));
            };
            chosen.push(version.clone());
            continue;
        }
        // The path as a file — unless it is a directory now and its contents were asked for.
        let as_file = match versions.first() {
            Some(newest) if !(args.recursive && ctx.vault.exists_dir(path)?) => {
                chosen.push(newest.clone());
                true
            }
            _ => false,
        };
        if as_file && !args.recursive {
            continue;
        }
        let under = remote_ops::restorable_under(&ctx.vault, path, now).await?;
        if under.is_empty() {
            if as_file {
                continue;
            }
            return Err(not_found(format!(
                "{}: no restorable version, and nothing restorable under it (removed versions \
                 are kept for 25 days)",
                shown(path)
            )));
        }
        if !args.recursive {
            return Err(usage(format!(
                "{} is a directory with {} that can be restored: `gclone restore -r {}` brings \
                 back the deleted ones, `gclone restore --list {}` shows them",
                shown(path),
                files(under.len()),
                shown(path),
                shown(path)
            )));
        }
        let before = chosen.len();
        chosen.extend(under.iter().filter(|r| !r.live).map(|r| r.version.clone()));
        left_alone += under.len() - (chosen.len() - before);
        if chosen.len() == before && !as_file {
            return Err(not_found(format!(
                "{}: nothing under it is deleted. {} there exist in a newer version; \
                 `gclone restore :PATH` brings back the older version of one file (`gclone \
                 restore --list {}` shows them)",
                shown(path),
                files(under.len()),
                shown(path)
            )));
        }
    }
    // Overlapping arguments (`-r :a :a/b`) name a path once.
    let mut seen = std::collections::HashSet::new();
    chosen.retain(|v| seen.insert(v.path.clone()));

    let exit = if let [version] = chosen.as_slice() {
        // One file: every obstacle is an error, nothing is skipped silently.
        remote_ops::restore(&ctx.vault, &version.path, version).await?;
        ctx.vault.finish_mutation().await?;
        ctx.ui.out(&format!(
            "Restored {} ({}, the version removed {}).",
            shown(&version.path),
            human_size(version.entry.size),
            format_local_minute(version.removed_ms)
        ));
        0
    } else {
        let done = remote_ops::restore_many(&ctx.vault, &chosen).await?;
        ctx.vault.finish_mutation().await?;
        for (path, reason) in &done.skipped {
            ctx.ui
                .warn(&format!("{} was not restored: {reason}", shown(path)));
        }
        ctx.ui.out(&format!(
            "Restored {} (the newest removed version of each){}.",
            files(done.restored as usize),
            if done.skipped.is_empty() {
                String::new()
            } else {
                format!(
                    "; {} not restored",
                    group_thousands(done.skipped.len() as u64)
                )
            }
        ));
        if done.skipped.is_empty() { 0 } else { 6 }
    };
    if left_alone > 0 {
        ctx.ui.info(&format!(
            "note: {} that exist now in a newer version were left as they are (`gclone restore \
             --list` shows them; `gclone restore :PATH` brings back one)",
            files(left_alone)
        ));
    }
    Ok(exit)
}
