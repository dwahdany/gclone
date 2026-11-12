//! `gclone repair` (SPEC §5.10, §10) — owned by WP7.

use super::{GlobalOpts, LockMode, OpenOpts, RefreshPolicy, open_ctx};
use crate::consts::TRANSFERS_DEFAULT;

#[derive(clap::Args, Clone, Debug)]
pub struct RepairArgs {
    /// Give up on index objects that cannot be recovered.
    #[arg(long)]
    pub accept_loss: bool,
}

pub async fn run(g: &GlobalOpts, args: RepairArgs) -> anyhow::Result<i32> {
    // No refresh here: `Vault::repair` refreshes by itself and tolerates the very verdicts
    // (Gap, Rollback) that would stop every other command.
    let ctx = open_ctx(
        g,
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Skip,
            settle: false,
            transfers: TRANSFERS_DEFAULT,
        },
    )
    .await?;
    let report = ctx.vault.repair(args.accept_loss).await?;
    let list = |what: &str, names: &[String]| {
        if !names.is_empty() {
            ctx.ui.out(&format!("{what} {}:", names.len()));
            for name in names {
                ctx.ui.out(&format!("  {name}"));
            }
        }
    };
    list("Republished", &report.republished);
    list("Restored from the trash", &report.untrashed);
    list("Given up (--accept-loss)", &report.accepted_loss);
    if !report.still_missing.is_empty() {
        list("Still missing", &report.still_missing);
        ctx.ui.error(
            "the index is incomplete. Run `gclone repair` on a device that has seen the missing \
             objects — or, if none is left, `gclone repair --accept-loss` to continue without \
             them",
        );
        return Ok(3);
    }
    match &report.snapshot {
        Some(name) => ctx
            .ui
            .out(&format!("Index repaired; published snapshot {name}.")),
        None => ctx.ui.out("Index repaired."),
    }
    Ok(0)
}
