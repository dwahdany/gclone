//! `gclone passwd` (SPEC §2.7, §10) — owned by WP7.

use std::sync::Arc;

use super::{
    GlobalOpts, LockMode, OpenOpts, RefreshPolicy, blocking, explained, kdf_params, open_ctx,
    read_new_passphrase, stored_device_name, ui_for,
};
use crate::consts::TRANSFERS_DEFAULT;
use crate::format::{KeyfilePayload, open_keyfile, parse_keyfile_name, seal_keyfile};
use crate::util;

#[derive(clap::Args, Clone, Debug)]
pub struct PasswdArgs {
    /// Read the new passphrase from the first line of this file (e.g. /dev/fd/3).
    #[arg(long, value_name = "PATH")]
    pub passphrase_file: Option<std::path::PathBuf>,
}

pub async fn run(g: &GlobalOpts, args: PasswdArgs) -> anyhow::Result<i32> {
    let ctx = open_ctx(
        g,
        OpenOpts {
            lock: LockMode::Exclusive,
            refresh: RefreshPolicy::Required,
            settle: false,
            transfers: TRANSFERS_DEFAULT,
        },
    )
    .await?;
    let pass = {
        let (ui, file) = (Arc::new(ui_for(g)), args.passphrase_file.clone());
        blocking(move || read_new_passphrase(&ui, file.as_deref())).await?
    };

    // The names are all this device can read of the listed keyfiles — it holds no passphrase —
    // so the highest generation is an unauthenticated number: never trusted without an overflow
    // check (a planted `gclone-key-ffffffff-…` must not wrap or panic).
    let newest = ctx
        .vault
        .keyfiles()
        .await?
        .into_iter()
        .filter_map(|meta| parse_keyfile_name(&meta.name).map(|(g, _)| (g, meta.name)))
        .max_by_key(|(g, _)| *g);
    let generation = match &newest {
        None => 1,
        Some((g, name)) => g.checked_add(1).ok_or_else(|| {
            explained(
                std::io::Error::other("keyfile generation exhausted"),
                format!(
                    "keyfile generation exhausted by {name}; remove that object in \
                     drive.google.com and run `gclone passwd` again"
                ),
            )
        })?,
    };

    let device = stored_device_name(ctx.vault.db())?;
    let payload =
        KeyfilePayload::from_keyring(ctx.vault.keys(), generation, &device, util::now_ms());
    let params = kdf_params();
    let keyfile = blocking(move || {
        let sealed = seal_keyfile(&payload, &pass, params)?;
        // Self-test before the old keyfiles are retired.
        if open_keyfile(&sealed.name, &sealed.bytes, &pass)? != payload {
            anyhow::bail!("the new keyfile does not open to what was sealed");
        }
        Ok(sealed)
    })
    .await?;
    ctx.vault.replace_keyfile(&keyfile).await?;

    ctx.ui.out(
        "Passphrase changed. New devices need the new passphrase; connected devices are unaffected.",
    );
    ctx.ui.info(
        "Copies of the old keyfile (Drive trash for 30 days, backups at Google) still open with \
         the old passphrase — changing the passphrase does not re-encrypt anything.",
    );
    Ok(0)
}
