//! `gclone mkdir` (SPEC §5.5.4, §10) — owned by WP7.

use super::{GlobalOpts, OpenOpts, open_ctx, remote_arg, shown, usage};
use crate::sync::remote_ops;

#[derive(clap::Args, Clone, Debug)]
pub struct MkdirArgs {
    /// Remote directory (`:PATH`).
    pub path: String,
}

pub async fn run(g: &GlobalOpts, args: MkdirArgs) -> anyhow::Result<i32> {
    let path = remote_arg(&args.path)?;
    if path.is_empty() {
        return Err(usage(": is the vault root; it always exists"));
    }
    let ctx = open_ctx(g, OpenOpts::mutating()).await?;
    ctx.require_commit()?;
    let created = remote_ops::mkdir(&ctx.vault, &path).await?;
    ctx.vault.finish_mutation().await?;
    ctx.ui.out(&if created {
        format!("Created {}/", shown(&path))
    } else {
        format!("{}/ exists already.", shown(&path))
    });
    Ok(0)
}
