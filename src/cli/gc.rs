//! `gclone gc` (SPEC §5.9, §10) — owned by WP7.

use super::{GlobalOpts, LockMode, OpenOpts, RefreshPolicy, open_ctx};
use crate::consts::TRANSFERS_DEFAULT;
use crate::sync;
use crate::util::{group_thousands, human_size};

#[derive(clap::Args, Clone, Debug)]
pub struct GcArgs {
    /// Show what would be collected; change nothing.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Also trash unknown objects older than 14 days in this vault's data folders.
    #[arg(long)]
    pub orphans: bool,
    /// Permanently delete blobs that gclone trashed (the only permanent deletion).
    #[arg(long)]
    pub purge: bool,
}

pub async fn run(g: &GlobalOpts, args: GcArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(
        g,
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Tolerant,
            settle: false,
            transfers: TRANSFERS_DEFAULT,
        },
    )
    .await?;
    // A replica that is missing index state must not judge what is dead (§5.9).
    let refused = match &ctx.refresh {
        Some(Ok(report)) if report.blocked_young == 0 => None,
        Some(Ok(report)) => Some(format!(
            "{} index segment(s) cannot be applied yet (their predecessors are not visible)",
            report.blocked_young
        )),
        Some(Err(e)) => Some(e.to_string()),
        None => Some("the index was not refreshed".to_string()),
    };
    if let Some(why) = refused {
        ctx.ui.error(&format!(
            "gc needs a complete index and did nothing: {why}. Try again later; for a gap or a \
             rollback run `gclone repair`."
        ));
        return Ok(3);
    }

    let report = sync::gc(&ctx.vault, args.dry_run, args.orphans, args.purge).await?;
    for name in &report.purge_skipped {
        ctx.ui.warn(&format!("not purged: {name}"));
    }
    let blobs = |n: u64, bytes: u64, what: &str| {
        format!("{} {what} ({})", group_thousands(n), human_size(bytes))
    };
    let mut parts = vec![blobs(report.dead_blobs, report.dead_bytes, "dead blobs")];
    if args.orphans {
        parts.push(blobs(report.orphans, report.orphan_bytes, "orphans"));
    }
    let (trash, purge) = if report.dry_run {
        ("Would trash", "would delete")
    } else {
        ("Trashed", "deleted")
    };
    let mut line = format!("{trash} {}", parts.join(", "));
    if args.purge {
        line.push_str(&format!(
            "; {purge} {} for good",
            blobs(report.purged, report.purged_bytes, "trashed blobs")
        ));
    }
    line.push('.');
    if report.dry_run {
        line.push_str(" Nothing changed (dry run).");
    }
    ctx.ui.out(&line);
    Ok(0)
}
