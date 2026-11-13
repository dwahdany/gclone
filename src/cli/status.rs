//! `gclone status` (SPEC §7.3, §10) — owned by WP7.

use super::{Ctx, GlobalOpts, OpenOpts, open_ctx};
use crate::backend::Backend as _;
use crate::config::{BackendCfg, secret_store};
use crate::consts::IDLE_WARN_DAYS;
use crate::format::DESCRIPTOR_NAME;
use crate::util;

#[derive(clap::Args, Clone, Debug)]
pub struct StatusArgs {}

const DAY_MS: u64 = 86_400_000;

/// "12 min ago" for a past moment; "just now" when the clocks disagree.
pub(crate) fn ago(now_ms: u64, then_ms: u64) -> String {
    match now_ms.checked_sub(then_ms) {
        Some(ms) if ms >= 1000 => format!("{} ago", util::human_age(ms)),
        _ => "just now".to_string(),
    }
}

/// §2.8: a refresh token dies after six months without use.
pub(crate) fn idle_warning(ctx: &Ctx) {
    if let Some(last) = ctx.tokens.as_ref().and_then(|t| t.last_refresh_ms())
        && util::now_ms().saturating_sub(last) > IDLE_WARN_DAYS * DAY_MS
    {
        ctx.ui.warn(&format!(
            "this device's Google login was last refreshed {}; Google drops a login that is \
             unused for six months",
            ago(util::now_ms(), last)
        ));
    }
}

pub async fn run(g: &GlobalOpts, _args: StatusArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(g, OpenOpts::read_only()).await?;
    ctx.report_refresh();
    let vault = &ctx.vault;
    let backend = &**vault.backend();
    // `status -q` is the keep-alive of rarely used machines: it has refreshed by now and prints
    // warnings only.
    let line = |label: &str, text: String| {
        if !ctx.ui.quiet() {
            ctx.ui.out(&format!("{label:<12} {text}"));
        }
    };

    let secrets = secret_store(&ctx.paths).load()?;
    match &ctx.config.backend {
        BackendCfg::Drive => {
            let s = secrets.as_ref();
            let email = s.and_then(|s| s.email.as_deref()).unwrap_or("signed in");
            let url = s.and_then(|s| s.auth_url.as_deref()).unwrap_or("?");
            let refreshed = match ctx.tokens.as_ref().and_then(|t| t.last_refresh_ms()) {
                Some(ms) => format!("last refresh {}", ago(util::now_ms(), ms)),
                None => "not refreshed yet".to_string(),
            };
            line("Login", format!("ok — {email} via {url} ({refreshed})"));
        }
        BackendCfg::Dir { path } => line(
            "Login",
            format!("none needed — directory vault at {}", path.display()),
        ),
    }
    let name = match vault.vault_name() {
        name if !name.is_empty() => name,
        _ => ctx.config.vault_name.clone(),
    };
    let format = vault.db().meta_get_u64("vault_format")?.unwrap_or(0);
    line(
        "Vault",
        format!("{name} ({}…), format {format}", &ctx.config.vault_id[..8]),
    );
    let stats = vault.stats(backend.now_ms())?;
    line(
        "Head",
        format!(
            "{} ({} files) — the same on every device that is up to date",
            vault.head_fingerprint()?,
            util::group_thousands(stats.files)
        ),
    );
    let me = vault.device_id();
    let devices = vault.devices()?;
    let my_name = devices
        .iter()
        .find(|d| d.id == me)
        .map(|d| d.name.clone())
        .unwrap_or_else(|| "not registered yet".to_string());
    line("This device", format!("{my_name} ({me})"));
    let now = backend.now_ms();
    let listed: Vec<String> = devices
        .iter()
        .map(|d| format!("{} ({})", d.name, ago(now, d.last_ms)))
        .collect();
    line("Devices", listed.join(", "));
    let pending = vault.db().pending_count()?;
    line(
        "Pending",
        match (pending, vault.outbox_stuck()) {
            (0, _) => "none".to_string(),
            (n, None) => format!("{n} change(s) not published yet"),
            (n, Some(cause)) => format!("{n} change(s) not published yet — {cause}"),
        },
    );
    // §8.2: where this device's login and key are kept, and what the trial has seen.
    let (key_store, key_store_warnings) = super::keystore::status_lines(&ctx.paths);
    line("Key store", key_store);
    if stats.conflicts > 0 {
        line(
            "Conflicts",
            format!(
                "{} unresolved; the next sync resolves them",
                stats.conflicts
            ),
        );
    }

    idle_warning(&ctx);
    for warning in &key_store_warnings {
        ctx.ui.warn(warning);
    }
    // §17.18, §17.22: a login from before 0.2.0 is refreshed only by an auth Worker older than
    // 0.4.0; the 0.4.0 Worker answers it `invalid_grant`.
    if matches!(ctx.config.backend, BackendCfg::Drive)
        && secrets
            .as_ref()
            .is_some_and(|s| s.has_login() && s.client.is_legacy())
    {
        ctx.ui.warn(
            "this device's Google login was made with the browser sign-in of gclone before \
             0.2.0; run `gclone login` to renew it — the auth Worker of gclone 0.4.0 and later \
             no longer serves it",
        );
    }
    if let Some(end) = secrets.as_ref().and_then(|s| s.refresh_expires_at_ms) {
        let days = end
            .saturating_sub(util::now_ms())
            .saturating_add(DAY_MS / 2)
            / DAY_MS;
        ctx.ui.warn(&format!(
            "Login expires in {days} days (OAuth app in Testing? → Publish app, then `gclone login`)"
        ));
    }
    // §2.6 "two first devices", step 3: list lag can hide a second vault from `login`.
    if matches!(ctx.config.backend, BackendCfg::Drive) && ctx.lock.is_some() {
        match backend.find_by_name(DESCRIPTOR_NAME).await {
            Ok(hits) => {
                if hits.iter().any(|d| d.parent.0 != ctx.config.root_id) {
                    ctx.ui.warn(
                        "Another gclone vault exists in this Drive. If it was created by \
                         accident on another device, run `gclone logout --forget` there and \
                         `gclone login` again.",
                    );
                }
            }
            Err(e) => tracing::debug!("could not look for other vaults: {e}"),
        }
    }
    Ok(0)
}
