//! `gclone gc` (SPEC §5.9, §10) — owned by WP7.

use super::{GlobalOpts, LockMode, OpenOpts, RefreshPolicy, open_ctx};
use crate::consts::TRANSFERS_DEFAULT;
use crate::error::IndexError;
use crate::index::RefreshReport;
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
    /// Permanently delete blobs that gclone trashed (the only permanent deletion of data).
    #[arg(long)]
    pub purge: bool,
}

/// A replica that is missing index state must not judge what is dead (§5.9) — in none of the
/// three steps: `Some(what to print)` unless the refresh of this command ran, returned no
/// verdict, applied everything it was shown and ignored nothing. An index object that failed
/// verification, or a newer snapshot that could not be used, may be exactly the one that
/// gives a blob its head: the device knows its view is incomplete, so it does not collect.
pub(crate) fn refusal(refresh: Option<&Result<RefreshReport, IndexError>>) -> Option<String> {
    const START: &str = "gc needs a complete index and did nothing";
    let report = match refresh {
        Some(Ok(report)) => report,
        Some(Err(e)) => {
            return Some(format!(
                "{START}: {e}. Try again later; for a gap or a rollback run `gclone repair`."
            ));
        }
        None => {
            return Some(format!(
                "{START}: the index was not refreshed. Try again later."
            ));
        }
    };
    let why = report.incomplete()?;
    let advice = if !report.corrupt_objects.is_empty() || report.unused_snapshot.is_some() {
        "Run `gclone repair` on a device that has seen the object: it puts an intact copy \
         back. An object that no device has (planted, or damaged beyond repair) has to be \
         removed from the vault's `index` folder in drive.google.com before gc runs again."
    } else {
        "Try again later."
    };
    Some(format!("{START}: {why}. {advice}"))
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
    if let Some(text) = refusal(ctx.refresh.as_ref()) {
        ctx.ui.error(&text);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeviceId;

    /// §5.9: every state in which the replica may lack index state refuses, and the text names
    /// the object.
    #[test]
    fn gc_refuses_whenever_the_replica_may_be_incomplete() {
        let clean = RefreshReport::default();
        assert_eq!(refusal(Some(&Ok(clean.clone()))), None);
        // Applied segments, conflicts, an adopted snapshot or a stuck outbox are no reason.
        let busy = RefreshReport {
            applied: 3,
            conflicts: 1,
            adopted: Some("c-1".into()),
            outbox_stuck: true,
            ..clean.clone()
        };
        assert_eq!(refusal(Some(&Ok(busy))), None);

        let not_refreshed = refusal(None).unwrap();
        assert!(
            not_refreshed.contains("was not refreshed"),
            "{not_refreshed}"
        );

        let rollback = refusal(Some(&Err(IndexError::Rollback {
            device: DeviceId([1; 8]),
            seq: 4,
        })))
        .unwrap();
        assert!(rollback.contains("rolled back") && rollback.contains("gclone repair"));

        let blocked = refusal(Some(&Ok(RefreshReport {
            blocked_young: 2,
            ..clean.clone()
        })))
        .unwrap();
        assert!(blocked.contains("2 index segment(s) cannot be applied yet"));
        assert!(blocked.ends_with("Try again later."), "{blocked}");

        // An ignored index object (L3 of the audit): named, and the way out is said.
        let corrupt = refusal(Some(&Ok(RefreshReport {
            corrupt_objects: vec!["s-aa-01".into(), "c-02".into()],
            ..clean.clone()
        })))
        .unwrap();
        assert!(corrupt.contains("2 index object(s) failed verification"));
        assert!(corrupt.contains("s-aa-01, c-02") && corrupt.contains("gclone repair"));

        // A newer snapshot that was left unused.
        let unused = refusal(Some(&Ok(RefreshReport {
            unused_snapshot: Some("c-0000000000000009-aa-bb".into()),
            ..clean
        })))
        .unwrap();
        assert!(unused.contains("snapshot c-0000000000000009-aa-bb covers index segments"));
        assert!(unused.contains("gclone repair"), "{unused}");
    }
}
