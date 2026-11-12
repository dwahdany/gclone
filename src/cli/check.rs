//! `gclone check` (SPEC §5.9, §10) — owned by WP7.

use super::{GlobalOpts, OpenOpts, open_ctx, usage};
use crate::path::{Arg, parse_arg};
use crate::sync::{self, CheckReport};
use crate::types::EntryKind;
use crate::util::group_thousands;

#[derive(clap::Args, Clone, Debug)]
pub struct CheckArgs {
    /// Download and authenticate every file under the given remote path.
    #[arg(long)]
    pub download: bool,
    /// Nothing (check the blobs), `LOCAL :REMOTE`, or `:PATH` with `--download`.
    #[arg(num_args = 0..=2)]
    pub args: Vec<String>,
}

enum What {
    Blobs,
    Local(std::path::PathBuf, String),
    Download(String),
}

fn what(args: &CheckArgs) -> anyhow::Result<What> {
    let parse = |arg: &str| parse_arg(arg).map_err(|e| usage(format!("{arg}: {e}")));
    let forms = "gclone check | gclone check LOCAL :REMOTE | gclone check --download [:PATH]";
    match (args.download, args.args.as_slice()) {
        (false, []) => Ok(What::Blobs),
        (false, [local, remote]) => match (parse(local)?, parse(remote)?) {
            (Arg::Local(local), Arg::Remote(remote)) => Ok(What::Local(local, remote)),
            _ => Err(usage(format!(
                "expected a local path, then a remote one: {forms}"
            ))),
        },
        (true, []) => Ok(What::Download(String::new())),
        (true, [remote]) => match parse(remote)? {
            Arg::Remote(remote) => Ok(What::Download(remote)),
            Arg::Local(_) => Err(usage(format!("--download takes a remote path: {forms}"))),
        },
        _ => Err(usage(forms)),
    }
}

pub async fn run(g: &GlobalOpts, args: CheckArgs) -> anyhow::Result<i32> {
    let what = what(&args)?;
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let vault = &ctx.vault;
    let (report, unit): (CheckReport, &str) = match &what {
        What::Blobs => (sync::check_blobs(vault).await?, "blobs"),
        What::Local(local, remote) => (sync::check_local(vault, local, remote).await?, "files"),
        What::Download(prefix) => {
            let files: Vec<u64> = vault
                .walk(prefix)?
                .iter()
                .filter(|h| h.entry.kind == EntryKind::File)
                .map(|h| h.entry.size)
                .collect();
            let progress =
                ctx.ui
                    .transfer_progress("Checking", files.iter().sum(), files.len() as u64);
            let report = sync::check_download(vault, prefix, progress.clone()).await;
            progress.finish();
            (report?, "files")
        }
    };

    for name in &report.untrashed {
        ctx.ui.info(&format!(
            "note: {name} was in the trash and has been restored"
        ));
    }
    if report.listed_late > 0 && ctx.ui.verbose() > 0 {
        ctx.ui.info(&format!(
            "note: {} blob(s) were missing from the listing and found by id (list lag)",
            report.listed_late
        ));
    }
    if report.orphans > 0 {
        ctx.ui.info(&format!(
            "note: {} object(s) in the data folders belong to no known blob (gclone gc --orphans)",
            report.orphans
        ));
    }
    for name in &report.missing {
        ctx.ui.error(&format!("missing: {name}"));
    }
    for name in &report.mismatched {
        ctx.ui.error(&format!("damaged: {name}"));
    }
    for name in &report.differing {
        ctx.ui.error(&format!("differs: {name}"));
    }
    let checked = group_thousands(report.checked);
    if report.ok() {
        ctx.ui.out(&format!("Checked {checked} {unit}: all good."));
        Ok(0)
    } else {
        ctx.ui.out(&format!(
            "Checked {checked} {unit}: {} missing, {} damaged, {} different.",
            report.missing.len(),
            report.mismatched.len(),
            report.differing.len()
        ));
        Ok(3)
    }
}
