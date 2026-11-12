//! `gclone mv` (SPEC §5.5.4, §10) — owned by WP7.

use super::{GlobalOpts, OpenOpts, open_ctx, remote_arg, shown, usage};
use crate::sync::remote_ops;
use crate::util::group_thousands;

#[derive(clap::Args, Clone, Debug)]
pub struct MvArgs {
    /// Remote source (`:SRC`).
    pub src: String,
    /// Remote destination (`:DST`). An existing directory: SRC is moved into it and keeps its
    /// name. Anything else: SRC is renamed to DST.
    pub dst: String,
    /// Replace a file that exists at the destination, or merge into a directory that exists
    /// there (files of the same name are replaced). Replaced versions stay restorable for 25
    /// days. Without it nothing that exists is touched.
    #[arg(long)]
    pub force: bool,
}

pub async fn run(g: &GlobalOpts, args: MvArgs) -> anyhow::Result<i32> {
    let (from, to) = (remote_arg(&args.src)?, remote_arg(&args.dst)?);
    if from.is_empty() {
        return Err(usage("the vault root cannot be moved"));
    }
    let ctx = open_ctx(g, OpenOpts::mutating()).await?;
    ctx.require_commit()?;
    let moved = remote_ops::mv(&ctx.vault, &from, &to, args.force).await?;
    ctx.vault.finish_mutation().await?;
    ctx.ui.out(&format!(
        "Moved {} to {} ({} {}; no data was transferred).",
        shown(&from),
        shown(&moved.to),
        group_thousands(moved.entries),
        if moved.entries == 1 {
            "entry"
        } else {
            "entries"
        }
    ));
    if moved.replaced > 0 {
        ctx.ui.out(&format!(
            "Replaced {} {} there; the replaced {} restorable for 25 days (gclone restore --list {}).",
            group_thousands(moved.replaced),
            if moved.replaced == 1 { "file" } else { "files" },
            if moved.replaced == 1 { "version stays" } else { "versions stay" },
            shown(&moved.to)
        ));
    }
    Ok(0)
}
