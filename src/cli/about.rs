//! `gclone about` (SPEC §7.3, §10) — owned by WP7.

use super::status::{ago, idle_warning};
use super::{GlobalOpts, OpenOpts, open_ctx};
use crate::backend::Backend as _;
use crate::config::BackendCfg;
use crate::consts::{LEDGER_DL_WARN, LEDGER_WARN};
use crate::state::LedgerDir;
use crate::util::{self, group_thousands, human_size};

#[derive(clap::Args, Clone, Debug)]
pub struct AboutArgs {}

pub async fn run(g: &GlobalOpts, _args: AboutArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let vault = &ctx.vault;
    let backend = &**vault.backend();
    let now = backend.now_ms();
    let stats = vault.stats(now)?;
    let line = |label: &str, text: String| ctx.ui.out(&format!("{label:<15} {text}"));

    match backend.about().await {
        Ok(quota) => {
            let used = match quota.limit {
                Some(limit) => format!("{} of {} used", human_size(quota.usage), human_size(limit)),
                None => format!("{} used", human_size(quota.usage)),
            };
            let mut trash = format!("{} in trash", human_size(quota.usage_in_trash));
            if stats.trashed_blob_bytes > 0 {
                trash.push_str(&format!(
                    ", {} of it trashed by gclone: gclone gc --purge",
                    human_size(stats.trashed_blob_bytes)
                ));
            }
            let label = match ctx.config.backend {
                BackendCfg::Drive => "Drive storage",
                BackendCfg::Dir { .. } => "Storage",
            };
            line(label, format!("{used} ({trash})"));
        }
        Err(e) => ctx.ui.warn(&format!("storage usage is not available: {e}")),
    }

    let name = match vault.vault_name() {
        name if !name.is_empty() => name,
        _ => ctx.config.vault_name.clone(),
    };
    let mut notes = Vec::new();
    if stats.dead_blob_bytes > 0 {
        notes.push(format!(
            "{} dead: gclone gc",
            human_size(stats.dead_blob_bytes)
        ));
    }
    if stats.pack_dead_bytes > 0 {
        notes.push(format!(
            "{} dead space inside packs",
            human_size(stats.pack_dead_bytes)
        ));
    }
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join("; "))
    };
    line(
        &format!("Vault {name:?}"),
        format!(
            "{} files, {} in {} blobs{notes}",
            group_thousands(stats.files),
            human_size(stats.bytes),
            group_thousands(stats.blobs)
        ),
    );
    let plural = |n: u64, what: &str| format!("{n} {what}{}", if n == 1 { "" } else { "s" });
    let last = match (stats.last_change_ms, &stats.last_change_by) {
        (Some(ms), Some(by)) => format!("last change {} from {by:?}", ago(now, ms)),
        _ => "no changes yet".to_string(),
    };
    line(
        "Index",
        format!(
            "{} + {}; {last}",
            plural(stats.snapshots, "snapshot"),
            plural(stats.segments, "segment")
        ),
    );
    let wall = util::now_ms();
    let up = vault.db().ledger_sum_24h(wall, LedgerDir::Up)?;
    let down = vault.db().ledger_sum_24h(wall, LedgerDir::Down)?;
    line(
        "Transferred",
        format!(
            "{} up, {} down in the last 24 h",
            human_size(up),
            human_size(down)
        ),
    );

    if up >= LEDGER_WARN {
        ctx.ui
            .warn("close to Google's daily upload limit (750 GB); uploads may stop until tomorrow");
    }
    if down >= LEDGER_DL_WARN {
        ctx.ui
            .warn("close to Google's daily download allowance; downloads may stop until tomorrow");
    }
    if stats.conflicts > 0 {
        ctx.ui.warn(&format!(
            "{} unresolved conflict(s); the next sync resolves them",
            stats.conflicts
        ));
    }
    idle_warning(&ctx);
    Ok(0)
}
