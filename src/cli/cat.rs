//! `gclone cat` (SPEC §4.2, §6.3, §10) — owned by WP7.

use tokio::io::AsyncWriteExt as _;

use super::{GlobalOpts, OpenOpts, open_ctx, remote_arg, shown, usage};
use crate::error::TransferError;
use crate::state::LedgerDir;
use crate::transfer::read_range;
use crate::types::EntryKind;
use crate::util;

#[derive(clap::Args, Clone, Debug)]
pub struct CatArgs {
    /// Remote file (`:PATH`).
    pub path: String,
    /// Start at this byte offset.
    #[arg(long, value_name = "N")]
    pub offset: Option<u64>,
    /// Write at most this many bytes.
    #[arg(long, value_name = "N")]
    pub count: Option<u64>,
}

/// The reader of the pipe went away (`gclone cat :f | head`): not a failure of this command.
fn closed_pipe(e: &TransferError) -> bool {
    matches!(e, TransferError::Io(io) if io.kind() == std::io::ErrorKind::BrokenPipe)
}

pub async fn run(g: &GlobalOpts, args: CatArgs) -> anyhow::Result<i32> {
    let path = remote_arg(&args.path)?;
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let head = match ctx.vault.head(&path)? {
        Some(head) if head.entry.kind == EntryKind::File => head,
        Some(_) => return Err(usage(format!("{} is a directory", shown(&path)))),
        None if !path.is_empty() && ctx.vault.exists_dir(&path)? => {
            return Err(usage(format!("{} is a directory", shown(&path))));
        }
        None if path.is_empty() => return Err(usage(": is the vault root, not a file")),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{}: no such file in the vault", shown(&path)),
            )
            .into());
        }
    };
    let start = args.offset.unwrap_or(0).min(head.entry.size);
    let end = match args.count {
        Some(count) => start.saturating_add(count).min(head.entry.size),
        None => head.entry.size,
    };
    let Some(loc) = head.entry.loc.as_ref().filter(|_| start < end) else {
        return Ok(0);
    };
    let blob = ctx
        .vault
        .blob(&loc.blob)?
        .ok_or_else(|| TransferError::BlobMissing(loc.blob.hex()))?;
    let mut out = tokio::io::stdout();
    let written = read_range(
        &**ctx.vault.backend(),
        ctx.vault.keys(),
        &blob,
        &head,
        start..end,
        &mut out,
    )
    .await;
    match written {
        Ok(n) => {
            match out.flush().await {
                Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e.into()),
                _ => {}
            }
            ctx.vault
                .db()
                .ledger_add(util::now_ms(), LedgerDir::Down, n)?;
            Ok(0)
        }
        Err(e) if closed_pipe(&e) => Ok(0),
        Err(e) => Err(e.into()),
    }
}
