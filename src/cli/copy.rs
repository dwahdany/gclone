//! `gclone copy` / `gclone sync` (SPEC §7.1, §10) — owned by WP7.

use std::sync::atomic::Ordering;

use super::{
    GRACEFUL, GlobalOpts, LockMode, OpenOpts, RefreshPolicy, explained, open_ctx, shown, usage,
};
use crate::consts::TRANSFERS_DEFAULT;
use crate::error::{GuardKind, IndexError, SyncError};
use crate::path::{Arg, parse_arg};
use crate::sync::{self, Direction, Mode, SkipReason, Summary, SyncOpts, SyncRequest};
use crate::ui::{Event, Ui};
use crate::util::{group_thousands, human_size};

/// Options shared by `copy` and `sync`.
#[derive(clap::Args, Clone, Debug)]
pub struct CopyArgs {
    /// Source directory: a local path or `:REMOTE`. Its contents are transferred.
    pub src: String,
    /// Destination directory: a local path or `:REMOTE` (exactly one of SRC and DST is remote).
    pub dst: String,
    /// Show what would be done; change nothing.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Compare by content hash instead of size + times.
    #[arg(long)]
    pub checksum: bool,
    /// Carry out what a run otherwise skips and reports: overwrite a file that the other side
    /// changed since the last sync ("remote is newer", or on a download "changed locally"),
    /// upload again what was deleted in the vault, and upload from a source that is empty,
    /// missing or looks restored from an older copy. It never deletes entries that exist only
    /// at the destination and were never synced, and it does not lift the delete limits.
    #[arg(long)]
    pub force: bool,
    /// Exclude paths matching this gitignore-style pattern (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,
    /// Concurrent blob uploads (downloads: twice as many streams).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..=64))]
    pub transfers: Option<u16>,
    /// Forget what was synced before with this root (after it was replaced or restored): the run
    /// is a first sync that deletes and overwrites nothing.
    #[arg(long, conflicts_with = "keep_pair")]
    pub reset_pair: bool,
    /// The local root is the same directory as before although it looks replaced: keep the sync
    /// state.
    #[arg(long)]
    pub keep_pair: bool,
}

#[derive(clap::Args, Clone, Debug)]
pub struct SyncArgs {
    #[command(flatten)]
    pub common: CopyArgs,
    /// Refuse the whole run if it would delete more than N entries. A hard limit: neither
    /// --yes nor an answer on the terminal lifts it. Up to N deletions happen without a
    /// question (N replaces the default limits).
    #[arg(long, value_name = "N")]
    pub max_delete: Option<u64>,
    /// Do not ask before deleting more than the default limits allow (100 entries, or a
    /// quarter of the destination when that is 10 or more). Does not lift --max-delete.
    #[arg(long)]
    pub yes: bool,
}

/// "2m03s", "44s", "1h05m".
fn duration(ms: u64) -> String {
    let secs = ms / 1000;
    match secs {
        0..60 if ms < 10_000 => format!("{}.{}s", secs, ms % 1000 / 100),
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, secs % 3600 / 60),
    }
}

/// "1 directory", "12 directories".
fn directories(count: u64) -> String {
    format!(
        "{} {}",
        group_thousands(count),
        if count == 1 {
            "directory"
        } else {
            "directories"
        }
    )
}

/// What a guard's refusal means for this run and how to proceed (§5.5.2). Off a terminal the
/// error text is all the user gets — a scheduled run must be able to say which flag answers it.
fn explain_guard(e: SyncError, req: &SyncRequest) -> anyhow::Error {
    let SyncError::Guard(kind) = &e else {
        return e.into();
    };
    let local = req.local_root.display();
    let remote = shown(&req.remote_prefix);
    // Only `sync` deletes: there --force lets the vault follow an emptied source.
    let follow = if req.mode == Mode::Sync {
        " If it is meant to be so and the vault is to follow, pass --force (the delete limit \
         still applies)."
    } else {
        ""
    };
    let text = match kind {
        GuardKind::EmptySource if !req.local_root.exists() => format!(
            "safety guard: the source {local} does not exist (mistyped, or its volume is not \
             mounted). Nothing was changed.{follow}"
        ),
        GuardKind::EmptySource => format!(
            "safety guard: the source {local} is empty although it was synced with {remote} \
             before (is its volume mounted?). Nothing was changed.{follow}"
        ),
        GuardKind::RevertedTree { .. } => format!(
            "safety guard: {kind}. Nothing was changed. If these older files are what the \
             vault should get, pass --force."
        ),
        GuardKind::DeleteLimit { .. } => format!(
            "safety guard: {kind} without a confirmation. Nothing was changed. Look at the plan \
             with -n; then run it on a terminal and answer the question, or pass --yes."
        ),
        GuardKind::MaxDelete { .. } => format!(
            "safety guard: {kind}. Nothing was changed. Look at the plan with -n; to let it \
             run, raise --max-delete (--yes does not lift it)."
        ),
        GuardKind::RootChanged => format!(
            "safety guard: {local} is not the directory last synced with {remote} (it was \
             replaced, restored, or its file system has no stable inode numbers). Nothing was \
             changed. Pass --keep-pair if it is the same directory, or --reset-pair to start \
             over with it (a first sync: nothing is deleted or overwritten)."
        ),
    };
    explained(e, text)
}

/// The lines that follow the result: why files were skipped when `-q` hid the skip lines, and
/// what to do about entries that `sync` will never delete.
fn after_run(ui: &Ui, summary: &Summary, req: &SyncRequest, src: &str, dst: &str) {
    // -q drops the skip lines, yet the run exits 6 because of them: the reasons go to stderr.
    const SHOWN: usize = 10;
    if ui.quiet() && !ui.json() {
        for (path, reason) in summary.skipped.iter().take(SHOWN) {
            ui.warn(&format!("skipped {path}: {reason}"));
        }
        if summary.skipped.len() > SHOWN {
            ui.warn(&format!(
                "… and {} more skipped (run without -q for the list)",
                group_thousands((summary.skipped.len() - SHOWN) as u64)
            ));
        }
    }
    // Rows 4-DOWN / 5-UP: entries that exist only at the destination and were never synced.
    // `sync` reports them on every run until the user decides; --force is not the answer.
    let unseen = summary
        .skipped
        .iter()
        .filter(|(_, r)| matches!(r, SkipReason::LocalOnly | SkipReason::RemoteOnly))
        .count();
    if unseen > 0 {
        let n = group_thousands(unseen as u64);
        let (noun, verb) = if unseen == 1 {
            ("entry exists", "was")
        } else {
            ("entries exist", "were")
        };
        ui.info(&match req.direction {
            Direction::Up => format!(
                "hint: {n} {noun} only in the vault and {verb} never synced with this \
                 directory. sync never deletes such entries (--force does not either): fetch \
                 them with `gclone copy {dst} {src}`, or remove them with `gclone rm`."
            ),
            Direction::Down => format!(
                "hint: {n} {noun} only in the local directory and {verb} never synced with \
                 the vault. sync never deletes such entries (--force does not either): upload \
                 them with `gclone copy {dst} {src}`, or delete them yourself."
            ),
        });
    }
    if !summary.dry_run && summary.deleted_remote > 0 {
        ui.info(&format!(
            "note: what was deleted in the vault stays restorable for 25 days (gclone restore \
             --list {})",
            shown(&req.remote_prefix)
        ));
    }
}

/// The ▸ line of §7.3 for a finished run, or for a dry run.
fn summary_line(s: &Summary) -> String {
    let n = group_thousands;
    let deleted = s.deleted_remote + s.deleted_local;
    let skipped = s.skipped.len() as u64;
    let failed = s.failed.len() as u64;
    let mut parts = Vec::new();
    if s.dry_run {
        let mut add = |count: u64, text: String| {
            if count > 0 {
                parts.push(text);
            }
        };
        add(
            s.uploaded,
            format!("upload {} ({})", n(s.uploaded), human_size(s.bytes_up)),
        );
        add(
            s.downloaded,
            format!(
                "download {} ({})",
                n(s.downloaded),
                human_size(s.bytes_down)
            ),
        );
        add(s.reused, format!("reuse {}", n(s.reused)));
        add(s.meta_updates, format!("update {}", n(s.meta_updates)));
        add(
            s.dirs_created,
            format!("create {}", directories(s.dirs_created)),
        );
        add(deleted, format!("delete {}", n(deleted)));
        add(skipped, format!("skip {}", n(skipped)));
        add(s.conflicts, format!("conflict {}", n(s.conflicts)));
        return if parts.is_empty() {
            "Nothing to do. Nothing changed (dry run).".to_string()
        } else {
            format!("Would {}. Nothing changed (dry run).", parts.join(", "))
        };
    }
    let mut add = |count: u64, text: String| {
        if count > 0 {
            parts.push(text);
        }
    };
    add(
        s.uploaded,
        format!("{} uploaded ({})", n(s.uploaded), human_size(s.bytes_up)),
    );
    add(
        s.downloaded,
        format!(
            "{} downloaded ({})",
            n(s.downloaded),
            human_size(s.bytes_down)
        ),
    );
    add(s.reused, format!("{} reused", n(s.reused)));
    add(s.meta_updates, format!("{} updated", n(s.meta_updates)));
    add(
        s.dirs_created,
        format!("{} created", directories(s.dirs_created)),
    );
    add(deleted, format!("{} deleted", n(deleted)));
    add(skipped, format!("{} skipped", n(skipped)));
    add(failed, format!("{} failed", n(failed)));
    add(
        s.conflicts,
        format!(
            "{} conflict{}",
            n(s.conflicts),
            if s.conflicts == 1 { "" } else { "s" }
        ),
    );
    if parts.is_empty() {
        parts.push("nothing to transfer".to_string());
    }
    format!("Done in {}: {}.", duration(s.elapsed_ms), parts.join(", "))
}

async fn run_mode(
    g: &GlobalOpts,
    mode: Mode,
    args: CopyArgs,
    max_delete: Option<u64>,
    assume_yes: bool,
) -> anyhow::Result<i32> {
    let parse = |arg: &str| parse_arg(arg).map_err(|e| usage(format!("{arg}: {e}")));
    let (direction, local_root, remote_prefix) = match (parse(&args.src)?, parse(&args.dst)?) {
        (Arg::Local(local), Arg::Remote(remote)) => (Direction::Up, local, remote),
        (Arg::Remote(remote), Arg::Local(local)) => (Direction::Down, local, remote),
        (Arg::Remote(_), Arg::Remote(_)) => {
            return Err(usage(
                "one of SRC and DST must be a local path (inside the vault: gclone mv)",
            ));
        }
        (Arg::Local(_), Arg::Local(_)) => {
            return Err(usage(
                "one of SRC and DST must be a remote path, written with a leading ':' \
                 (for example :Photos)",
            ));
        }
    };
    if local_root.as_os_str().is_empty() {
        return Err(usage(
            "the local directory is an empty string (use . for the current directory)",
        ));
    }
    let transfers = args.transfers.map_or(TRANSFERS_DEFAULT, usize::from);
    let ctx = open_ctx(
        g,
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Required,
            // A dry run publishes nothing, leftovers of an interrupted run included.
            settle: !args.dry_run,
            transfers,
        },
    )
    .await?;
    // gclone's own files are never synced, even when the root contains them (§5.5.3).
    let mut own_dirs = vec![ctx.paths.config_dir.clone(), ctx.paths.state_root.clone()];
    if let crate::config::BackendCfg::Dir { path } = &ctx.config.backend {
        own_dirs.push(path.clone());
    }
    let req = SyncRequest {
        direction,
        mode,
        local_root,
        remote_prefix,
        own_dirs,
        opts: SyncOpts {
            dry_run: args.dry_run,
            checksum: args.checksum,
            force: args.force,
            excludes: args.exclude.clone(),
            max_delete,
            assume_yes,
            transfers,
            reset_pair: args.reset_pair,
            keep_pair: args.keep_pair,
        },
    };

    GRACEFUL.store(true, Ordering::SeqCst);
    let outcome = sync::run(&ctx.vault, &req, &ctx.ui, ctx.cancel.clone()).await;
    GRACEFUL.store(false, Ordering::SeqCst);
    // A guard, a quota stop or Ctrl-C: `execute` has already committed what completed.
    let summary = outcome.map_err(|e| explain_guard(e, &req))?;
    if !summary.dry_run {
        match ctx.vault.finish_mutation().await {
            Ok(()) => {}
            // A download changes no index state; what is stuck was stuck before it.
            Err(IndexError::OutboxStuck(cause)) if direction == Direction::Down => ctx.ui.warn(
                &format!("index changes of an earlier run are still unpublished: {cause}"),
            ),
            Err(e) => return Err(e.into()),
        }
    }

    let exit = summary.exit_code();
    ctx.ui.out(&summary_line(&summary));
    if summary.deletes_suppressed {
        ctx.ui
            .warn("nothing was deleted because some files could not be transferred or read");
    }
    after_run(&ctx.ui, &summary, &req, &args.src, &args.dst);
    if ctx.ui.json() {
        ctx.ui.event(&Event::Summary {
            uploaded: summary.uploaded,
            downloaded: summary.downloaded,
            reused: summary.reused,
            deleted: summary.deleted_remote + summary.deleted_local,
            skipped: summary.skipped.len() as u64,
            failed: summary.failed.len() as u64,
            conflicts: summary.conflicts,
            bytes_up: summary.bytes_up,
            bytes_down: summary.bytes_down,
            exit,
        });
    }
    Ok(exit)
}

pub async fn run(g: &GlobalOpts, args: CopyArgs) -> anyhow::Result<i32> {
    run_mode(g, Mode::Copy, args, None, false).await
}

/// `gclone sync`.
pub async fn run_sync(g: &GlobalOpts, args: SyncArgs) -> anyhow::Result<i32> {
    run_mode(g, Mode::Sync, args.common, args.max_delete, args.yes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration(0), "0.0s");
        assert_eq!(duration(420), "0.4s");
        assert_eq!(duration(9_999), "9.9s");
        assert_eq!(duration(44_000), "44s");
        assert_eq!(duration(123_000), "2m03s");
        assert_eq!(duration(3_900_000), "1h05m");
    }

    #[test]
    fn summary_lines_follow_the_examples() {
        let mib = 1024 * 1024;
        let dry = Summary {
            uploaded: 1,
            bytes_up: 4 * mib + mib / 5,
            reused: 1,
            deleted_remote: 1,
            conflicts: 1,
            skipped: vec![("notes.txt".into(), SkipReason::RemoteNewer)],
            dry_run: true,
            ..Summary::default()
        };
        assert_eq!(
            summary_line(&dry),
            "Would upload 1 (4.2 MiB), reuse 1, delete 1, skip 1, conflict 1. Nothing changed (dry run)."
        );
        let real = Summary {
            uploaded: 4700,
            bytes_up: 4 * 1024 * mib + 900 * mib + 22 * mib,
            reused: 12,
            deleted_remote: 2,
            deleted_local: 1,
            skipped: vec![("a".into(), SkipReason::LocalChanged)],
            elapsed_ms: 123_000,
            ..Summary::default()
        };
        assert_eq!(
            summary_line(&real),
            "Done in 2m03s: 4,700 uploaded (4.9 GiB), 12 reused, 3 deleted, 1 skipped."
        );
        let idle = Summary {
            elapsed_ms: 1_200,
            ..Summary::default()
        };
        assert_eq!(summary_line(&idle), "Done in 1.2s: nothing to transfer.");
        let idle_dry = Summary {
            dry_run: true,
            ..Summary::default()
        };
        assert_eq!(
            summary_line(&idle_dry),
            "Nothing to do. Nothing changed (dry run)."
        );
        // A run that only creates directories did something.
        let dirs_dry = Summary {
            dirs_created: 1,
            dry_run: true,
            ..Summary::default()
        };
        assert_eq!(
            summary_line(&dirs_dry),
            "Would create 1 directory. Nothing changed (dry run)."
        );
        let dirs = Summary {
            dirs_created: 2,
            uploaded: 1,
            bytes_up: 3,
            elapsed_ms: 1_200,
            ..Summary::default()
        };
        assert_eq!(
            summary_line(&dirs),
            "Done in 1.2s: 1 uploaded (3 B), 2 directories created."
        );
    }

    /// Off a terminal the guard's text is all the user gets: each one names its answer.
    #[test]
    fn every_guard_names_the_way_out() {
        let req = |mode| SyncRequest {
            direction: Direction::Up,
            mode,
            local_root: "/no/such/gclone-test-root".into(),
            remote_prefix: "Photos".into(),
            own_dirs: Vec::new(),
            opts: SyncOpts {
                dry_run: false,
                checksum: false,
                force: false,
                excludes: Vec::new(),
                max_delete: None,
                assume_yes: false,
                transfers: 1,
                reset_pair: false,
                keep_pair: false,
            },
        };
        let text = |kind: GuardKind, mode| {
            let e = explain_guard(SyncError::Guard(kind), &req(mode));
            assert_eq!(crate::error::exit_code(&e), 5, "the guard still decides");
            super::super::describe(&e)
        };
        for (kind, needles) in [
            (
                GuardKind::EmptySource,
                &["/no/such/gclone-test-root does not exist", "--force"][..],
            ),
            (GuardKind::RevertedTree { suspicious: 12 }, &["--force"]),
            (
                GuardKind::DeleteLimit {
                    deletes: 8,
                    total: 30,
                },
                &["refusing to delete 8 of 30 files", "--yes", "-n"],
            ),
            (
                GuardKind::MaxDelete {
                    deletes: 8,
                    limit: 3,
                },
                &["--max-delete 3", "raise --max-delete", "--yes does not"],
            ),
            (
                GuardKind::RootChanged,
                &[":Photos", "--keep-pair", "--reset-pair"],
            ),
        ] {
            let shown = text(kind.clone(), Mode::Sync);
            for needle in needles {
                assert!(shown.contains(needle), "{kind:?}: {shown}");
            }
            assert!(shown.contains("Nothing was changed"), "{shown}");
        }
        // `copy` never deletes: --force would do nothing for a missing source.
        assert!(!text(GuardKind::EmptySource, Mode::Copy).contains("--force"));
        // Anything else passes through untouched.
        let e = explain_guard(SyncError::Usage("u".into()), &req(Mode::Sync));
        assert_eq!(super::super::describe(&e), "u");
    }
}
