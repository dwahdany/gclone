//! `gclone check` (SPEC §5.9, §10) — owned by WP7.

use super::{GlobalOpts, OpenOpts, open_ctx, usage};
use crate::consts::ORPHAN_GRACE;
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

/// What `check` says about objects in the data folders that are no known blob (§5.9). A device
/// uploads its blobs before it publishes the index segment that names them, so during another
/// device's upload such objects are expected: they are counted apart from the old ones, which
/// are what `gc --orphans` exists for.
fn orphan_notes(orphans: u64, recent: u64) -> Vec<String> {
    let days = ORPHAN_GRACE.as_secs() / 86_400;
    let mut notes = Vec::new();
    if recent > 0 {
        notes.push(format!(
            "note: {recent} recent object(s) in the data folders are not in the index yet — \
             probably another device's upload in progress; nothing to do (`gclone gc --orphans` \
             only collects such objects once they are older than {days} days)"
        ));
    }
    let old = orphans.saturating_sub(recent);
    if old > 0 {
        notes.push(format!(
            "note: {old} object(s) in the data folders belong to no known blob and are older \
             than {days} days (leftovers of interrupted uploads); `gclone gc --orphans` \
             collects them"
        ));
    }
    notes
}

/// What `check` says when the vault folder holds more than one object under a keyfile's name
/// (`keyfiles`: highest generation first).
fn keyfiles_note(keyfiles: &[crate::backend::ObjMeta]) -> Option<String> {
    if keyfiles.len() < 2 {
        return None;
    }
    let names: Vec<&str> = keyfiles.iter().map(|m| m.name.as_str()).collect();
    Some(format!(
        "{} objects under a keyfile's name are in the vault folder: {}. Each that is a keyfile \
         attaches new devices with its own passphrase — an OLD passphrase among them, if a \
         `gclone passwd` was interrupted before it retired the old keyfile. Run `gclone passwd` \
         again (it retires every lower generation); an object nobody of yours put there can \
         be deleted in drive.google.com.",
        keyfiles.len(),
        names.join(", ")
    ))
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
    for note in orphan_notes(report.orphans, report.orphans_recent) {
        ctx.ui.info(&note);
    }
    // More than one keyfile in the vault folder: each opens with its own passphrase. A
    // `gclone passwd` that was killed between writing the new keyfile and retiring the old
    // one leaves exactly this, and nothing else would ever say so (§2.7).
    if matches!(what, What::Blobs) {
        match vault.keyfiles().await {
            Ok(keyfiles) => {
                if let Some(warning) = keyfiles_note(&keyfiles) {
                    ctx.ui.warn(&warning);
                }
            }
            Err(e) => tracing::debug!("the keyfiles could not be listed: {e}"),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphans_of_an_upload_in_progress_are_not_called_garbage() {
        assert!(orphan_notes(0, 0).is_empty());
        let recent = orphan_notes(3, 3);
        assert_eq!(recent.len(), 1, "{recent:?}");
        assert!(
            recent[0].starts_with("note: 3 recent object(s)"),
            "{recent:?}"
        );
        assert!(recent[0].contains("another device's upload in progress"));
        assert!(recent[0].contains("older than 14 days"), "{recent:?}");
        let old = orphan_notes(2, 0);
        assert_eq!(old.len(), 1, "{old:?}");
        assert!(old[0].starts_with("note: 2 object(s)"), "{old:?}");
        assert!(old[0].contains("`gclone gc --orphans` collects them"));
        let both = orphan_notes(5, 3);
        assert_eq!(both.len(), 2, "{both:?}");
        assert!(both[0].starts_with("note: 3 recent") && both[1].starts_with("note: 2 object(s)"));
    }
}
