//! `gclone rm` (SPEC §5.5.4, §10) — owned by WP7.

use super::{GlobalOpts, OpenOpts, open_ctx, remote_arg, usage};
use crate::sync::remote_ops;
use crate::util::group_thousands;

#[derive(clap::Args, Clone, Debug)]
pub struct RmArgs {
    /// Remove directories and their contents.
    #[arg(short = 'r', long)]
    pub recursive: bool,
    /// Remote paths (`:PATH`).
    #[arg(required = true)]
    pub paths: Vec<String>,
}

/// The command that undoes this `rm`, spelled out: a directory needs `-r` there too.
fn restore_hint(paths: &[String], recursive: bool) -> String {
    let flag = if recursive { " -r" } else { "" };
    if paths.len() <= 3 {
        let shown: Vec<String> = paths.iter().map(|p| super::shown(p)).collect();
        format!("gclone restore{flag} {}", shown.join(" "))
    } else {
        format!("gclone restore{flag} with the same paths")
    }
}

pub async fn run(g: &GlobalOpts, args: RmArgs) -> anyhow::Result<i32> {
    let mut paths = Vec::with_capacity(args.paths.len());
    for arg in &args.paths {
        let path = remote_arg(arg)?;
        if path.is_empty() {
            return Err(usage(
                "refusing to remove the whole vault (remove its top-level entries by name)",
            ));
        }
        paths.push(path);
    }
    let ctx = open_ctx(g, OpenOpts::mutating()).await?;
    ctx.require_commit()?;
    let removed = remote_ops::rm(&ctx.vault, &paths, args.recursive).await?;
    ctx.vault.finish_mutation().await?;
    ctx.ui.out(&format!(
        "Removed {} {} (files stay restorable for 25 days: {}).",
        group_thousands(removed),
        if removed == 1 { "entry" } else { "entries" },
        restore_hint(&paths, args.recursive)
    ));
    Ok(0)
}
