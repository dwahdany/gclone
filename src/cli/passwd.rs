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
    /// Delete the old keyfiles for good instead of moving them to the Drive trash — also the
    /// ones earlier runs left in the trash. For when an old passphrase may have leaked.
    #[arg(long)]
    pub purge_old: bool,
}

/// What `passwd` says after it retired the old keyfiles: what is left of them, and what the
/// command did not do (§2.7). A warning, so that `-q` does not hide it.
///
/// `left` is what a listing after the retirement shows beside the new keyfile: the names of
/// the objects under a keyfile's name that are still in the vault folder, and of those in its
/// trash. "Gone" is said only when that listing shows it; `None` = it could not be made.
fn caveat(purged: bool, left: Option<(&[String], &[String])>) -> String {
    let (live, trashed) = left.unwrap_or_default();
    let mut left = if purged && left.is_some_and(|(_, trashed)| trashed.is_empty()) {
        "The old keyfiles are gone from this Google account, trash included. Copies outside \
         its reach stay what they were — Google's own backups, a download or Takeout of the \
         vault folder, a keyfile somebody copied earlier — and each still opens with its old \
         passphrase."
            .to_string()
    } else if purged {
        let mut text = String::from(
            "The old keyfiles this run found were deleted for good, but it is not shown that \
             every keyfile of an earlier passphrase is gone from this Google account.",
        );
        if trashed.is_empty() {
            text.push_str(
                " The vault folder could not be listed again: look for objects named \
                 gclone-key-… in the folder and in the trash in drive.google.com, or run \
                 `gclone passwd --purge-old` again.",
            );
        } else {
            text.push_str(&format!(
                " Still in the Drive trash: {}. Delete them there by hand (drive.google.com → \
                 Trash), or run `gclone passwd --purge-old` again.",
                trashed.join(", ")
            ));
        }
        text.push_str(
            " Copies outside the account's reach — Google's own backups, a download or \
             Takeout of the vault folder — stay what they were, and each opens with its old \
             passphrase.",
        );
        text
    } else {
        "The old keyfile stays in the Drive trash for 30 days and opens with the old \
         passphrase, like every copy made of it before (Google's backups, a download of the \
         vault folder). `gclone passwd --purge-old` deletes it from the account now."
            .to_string()
    };
    if !live.is_empty() {
        left.push_str(&format!(
            " The vault folder holds {} more object(s) under a keyfile's name of the same or a \
             higher generation, which this run did not touch: {}. Each that is a keyfile \
             opens with its own passphrase — another `gclone passwd` that ran at the same \
             time, or an object put there by somebody else. If none of them is yours, delete \
             them in drive.google.com.",
            live.len(),
            live.join(", ")
        ));
    }
    format!(
        "{left} The vault's key is unchanged: changing the passphrase re-encrypts nothing, so \
         whoever holds an old keyfile with its passphrase — or a copy of a device's \
         secrets.json — can still decrypt the vault, including what is uploaded from now on. \
         There is no re-keying yet; see \"If a passphrase or a device's key file leaked\" in \
         docs/SECURITY.md."
    )
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

    // Everything that needs an answer is asked BEFORE anything is written: from the put of
    // the new keyfile to the retirement of the old ones the command does not wait for
    // anybody, so an interrupt at the question changes nothing — the old passphrase is the
    // passphrase, and nothing has said otherwise. (Asked after the put, an interrupt left the
    // old keyfile in the vault folder, opening with the old passphrase for good, under the
    // words "Passphrase changed".) Trashing is the default: a trashed keyfile is the way back
    // when the new passphrase is lost together with the last connected device. Deleting is
    // for a leaked passphrase. As in `login`, questions are for a person who typed the
    // passphrase: with `--passphrase-file` nothing is asked.
    let purge = args.purge_old
        || (args.passphrase_file.is_none()
            && ctx.ui.confirm(
                "Delete the old keyfiles for good — also the ones in the Drive trash — \
                 instead of leaving the retired one in the trash for 30 days? Yes if the old \
                 passphrase may have leaked; no keeps a way back if the new one is lost.",
            ));

    // The names are all this device can read of the listed keyfiles — it holds no passphrase —
    // so the highest generation is an unauthenticated number: never trusted without an overflow
    // check (a planted `gclone-key-ffffffff-…` must not wrap or panic). The trash counts too:
    // a generation is never used twice, also when the current keyfile was trashed by hand.
    let (live, trashed) = ctx.vault.keyfiles_and_trashed().await?;
    let newest = live
        .iter()
        .map(|meta| (meta, "in drive.google.com"))
        .chain(trashed.iter().map(|meta| {
            (
                meta,
                "from the trash in drive.google.com (delete it forever)",
            )
        }))
        .filter_map(|(meta, place)| parse_keyfile_name(&meta.name).map(|(g, _)| (g, meta, place)))
        .max_by_key(|(g, ..)| *g);
    let generation = match &newest {
        None => 1,
        Some((g, meta, place)) => g.checked_add(1).ok_or_else(|| {
            explained(
                std::io::Error::other("keyfile generation exhausted"),
                format!(
                    "keyfile generation exhausted by {}; remove that object {place} and run \
                     `gclone passwd` again",
                    meta.name
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
    // The store holds the new keyfile, read back and compared, before anything is retired —
    // and the old ones are retired in the same breath.
    let new = ctx.vault.put_keyfile(&keyfile).await?;
    let retired = ctx.vault.retire_keyfiles(&new, purge).await.map_err(|e| {
        explained(
            e,
            format!(
                "The new keyfile {} is in the vault folder and opens with the new passphrase, \
                 but retiring the old keyfiles failed: an old keyfile is STILL in the vault \
                 folder and still attaches new devices with the OLD passphrase. Run `gclone \
                 passwd` again (with the new passphrase, or another one) until it reports \
                 \"Passphrase changed.\"",
                new.name
            ),
        )
    })?;
    ctx.ui.out(
        "Passphrase changed. New devices need the new passphrase; connected devices are unaffected.",
    );
    if purge {
        ctx.ui.out(&format!(
            "Deleted for good: {} old keyfile(s) in the vault folder, {} in the Drive trash.",
            retired.deleted, retired.deleted_from_trash
        ));
    }
    // What is said about the old keyfiles is what a fresh listing shows.
    let names = |found: Vec<crate::backend::ObjMeta>| -> Vec<String> {
        found
            .into_iter()
            .filter(|m| m.handle != new.handle)
            .map(|m| m.name)
            .collect()
    };
    let left = match ctx.vault.keyfiles_and_trashed().await {
        Ok((live, trashed)) => Some((names(live), names(trashed))),
        Err(e) => {
            tracing::warn!("the vault folder could not be listed after the change: {e}");
            None
        }
    };
    ctx.ui.warn(&caveat(
        purge,
        left.as_ref()
            .map(|(live, trashed)| (&live[..], &trashed[..])),
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::caveat;

    /// "Gone, trash included" is a statement about a listing, not about the flag.
    #[test]
    fn gone_is_said_only_when_a_listing_shows_it() {
        let none: &[String] = &[];
        let one = &["gclone-key-00000002-d6c356f9".to_string()][..];
        let gone = "The old keyfiles are gone from this Google account, trash included";
        assert!(caveat(true, Some((none, none))).contains(gone));
        for text in [
            caveat(true, Some((none, one))),
            caveat(true, None),
            caveat(false, Some((none, none))),
        ] {
            assert!(!text.contains(gone), "{text}");
        }
        assert!(
            caveat(true, Some((none, one)))
                .contains("Still in the Drive trash: gclone-key-00000002-d6c356f9")
        );
        assert!(caveat(true, None).contains("could not be listed again"));
        // An untouched keyfile of the same or a higher generation is named in every case.
        for purged in [true, false] {
            let text = caveat(purged, Some((one, none)));
            assert!(
                text.contains("1 more object(s) under a keyfile's name"),
                "{text}"
            );
            assert!(text.contains("gclone-key-00000002-d6c356f9"), "{text}");
        }
        // What the command did not do is said in every case.
        for text in [caveat(true, Some((none, none))), caveat(false, None)] {
            assert!(text.contains("The vault's key is unchanged"));
        }
    }
}
