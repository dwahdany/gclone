//! `gclone probe` (hidden; the automatable day-0 probes of SPEC §2.9) — owned by WP7.

use super::{GlobalOpts, drive_backend, note_config, note_secrets, test_env, ui_for, usage};
use crate::backend::drive::{DriveConfig, ProbeOutcome, run_probes};
use crate::config::{BackendCfg, Config, Paths, secret_store};
use crate::consts::TRANSFERS_DEFAULT;
use crate::error::ConfigError;

#[derive(clap::Args, Clone, Debug)]
pub struct ProbeArgs {}

pub async fn run(g: &GlobalOpts, _args: ProbeArgs) -> anyhow::Result<i32> {
    let ui = ui_for(g);
    let paths = Paths::resolve()?;
    let config = Config::load(&paths)?;
    note_config(&paths, &config);
    if !matches!(config.backend, BackendCfg::Drive) {
        return Err(usage(
            "the probes question Google Drive; this device is attached to a directory vault",
        ));
    }
    let secrets = secret_store(&paths)
        .load()?
        .ok_or(ConfigError::NotLoggedIn)?;
    note_secrets(&secrets);
    let token = secrets
        .refresh_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or(ConfigError::NotLoggedIn)?;
    let (_, tokens) = drive_backend(
        secrets.endpoints()?,
        token,
        secrets.client,
        &paths,
        TRANSFERS_DEFAULT,
        true,
    )?;
    let mut cfg = DriveConfig::default();
    if let Some(api) = test_env("GCLONE_TEST_DRIVE_API") {
        cfg.endpoints.api = api;
    }
    if let Some(upload) = test_env("GCLONE_TEST_DRIVE_UPLOAD") {
        cfg.endpoints.upload = upload;
    }

    let mut failed = false;
    for line in run_probes(tokens, cfg).await {
        let (verdict, text) = match &line.outcome {
            ProbeOutcome::Pass(text) => ("pass", text),
            ProbeOutcome::Fail(text) => {
                failed = true;
                ("FAIL", text)
            }
            ProbeOutcome::Info(text) => ("info", text),
            ProbeOutcome::Skipped(text) => ("skip", text),
        };
        ui.out(&format!(
            "{:>2}  {verdict}  {} — {text}",
            line.id, line.question
        ));
    }
    Ok(i32::from(failed))
}
