# Setting up gclone

gclone has no shared service behind it. To use it with Google Drive, each person runs two
small things of their own:

- **A Google OAuth client**, in a Google Cloud project of yours. Google lets a program into
  a Drive only through such a client, and the client comes with a secret.
- **The auth Worker** (`worker/`), a small stateless Cloudflare Worker that holds that
  secret, so that no device and no binary has to. It turns one consent at Google into a
  login for one device and refreshes that login afterwards, and it lets in only the Google
  accounts named in its `ALLOWED_EMAILS` secret. File data never passes through it: devices
  talk to Google Drive directly.

You set this up **once per person, never per device**. Every device — the first or the
tenth, with or without a browser of its own — is then connected with one command and one
short code entered at Google.

A vault in a local directory needs none of it: `gclone login --vault-dir DIR`
([Using a vault without Google](USAGE.md#using-a-vault-without-google)).

- [One-time setup](#one-time-setup)
- [Connect the first device](#connect-the-first-device)
- [Adding a device](#adding-a-device)
- [Day-0 checklist (before the first real use)](#day-0-checklist-before-the-first-real-use)

## One-time setup

You need a Google account, a Cloudflare account (the free plan is enough), Node 20 or newer
and `curl`. Nothing in this repository deploys anything by itself.

`worker/setup.sh` walks through steps 1, 3 and 4 interactively and prints the checklist of
step 2 with your URLs filled in. It asks first whether the Worker is to be served on its
`workers.dev` host or on a host name of your own. **Decide that before step 1**: the URL
goes into the Google app's branding and into every device's login, so starting with the
custom domain of step 5 saves doing the Google configuration twice and signing in again on
every device.

[`worker/README.md`](../worker/README.md#one-time-setup) is the authoritative version of
these steps: the console's click path in full, the Worker's configuration, and
troubleshooting by error code. In short, by hand:

1. **Deploy the Worker.**

   ```sh
   cd worker
   npm install
   npx wrangler login          # opens a browser: sign in to Cloudflare
   node scripts/stub-dist.mjs  # a placeholder for the web viewer's files, which wrangler uploads with the Worker
   npx wrangler deploy
   ```

   Note the URL it prints, `https://gclone-auth.<acct>.workers.dev`. This is your **auth
   URL**; `<host>` below is its host name. (With a custom domain from the start, do step 1
   of [`worker/README.md`, "Custom domain and rate-limiting rule"](../worker/README.md#custom-domain-and-rate-limiting-rule-recommended)
   **instead of** this plain deploy; the auth URL is then your own
   `https://auth.example.org`.) Until step 3 is done its home page says
   `Status: not configured` — expected: the branding of step 2 needs the Worker's host
   name, so the Worker has to exist first.

2. **Create the Google OAuth client** in the Google Cloud console
   ([the click path](../worker/README.md#2-google-cloud-console)): a project with the Drive
   API enabled; the Google Auth Platform with Audience **External** and no logo (a logo
   triggers brand verification); under Branding `<acct>.workers.dev` as authorized domain
   (for a host of your own its *registrable* domain: `example.org` for `auth.example.org` —
   Google refuses a subdomain there), `https://<host>/` as home page and
   `https://<host>/privacy` as privacy policy — the Worker serves both pages; **Publish
   app**, so that the status reads **In production** (without it Google ends every login
   after 7 days, and `gclone login` detects that and refuses), but no "Submit for
   verification": `openid`, `email` and `drive.file` are non-sensitive scopes; and a client
   of type **TVs and Limited Input devices**, which has no redirect URI. Copy the client ID
   and the client secret **at once**: the secret is shown only once. Workspace accounts may
   choose Audience **Internal** instead of External + Publish. Console changes can take
   from five minutes to a few hours to apply.

3. **Give the Worker its three secrets.**

   ```sh
   cd worker
   npx wrangler secret put GOOGLE_CLIENT_ID        # the client ID from step 2
   npx wrangler secret put GOOGLE_CLIENT_SECRET    # its secret
   npx wrangler secret put ALLOWED_EMAILS          # your Google address; several: comma-separated
   ```

   Each `wrangler secret put` deploys a new version at once; no further `wrangler deploy`
   is needed. `ALLOWED_EMAILS` decides who may sign in — empty or missing means **nobody**.
   It must stay a secret and never become a `vars` entry in `wrangler.jsonc`.

4. **Check.**

   ```sh
   curl https://<host>/        # 200, and the page contains "Status: ready"
   ```

5. **Recommended: a custom domain.** On the `workers.dev` host anyone can spend the free
   plan's daily request quota and thereby stop your logins and token refreshes until
   midnight UTC (data is never at risk). A custom domain with a zone rate-limiting rule
   over **all** of the Worker's paths stops any single sender from doing that (it counts
   per address; only the paid Workers plan removes the daily cap):
   [`worker/README.md`, "Custom domain and rate-limiting rule"](../worker/README.md#custom-domain-and-rate-limiting-rule-recommended).
   If you chose your own host name in step 1, only the rule is left to do.

**The hosted viewer** is optional and set up separately: three more secrets and a second
OAuth client ([`worker/README.md`, "The hosted viewer: setup"](../worker/README.md#the-hosted-viewer-setup)).
Read [what you trust when you use it](SECURITY.md#the-hosted-viewer-what-you-trust) first.

**A binary that knows your URL.** A device needs the auth URL once, at its first
`gclone login https://<host>`. To spare even that, build gclone with the URL compiled in
([DEVELOPMENT.md, "Building"](../DEVELOPMENT.md#building)); a fork's release workflow does
the same from the repository variable `GCLONE_DEFAULT_AUTH_URL`.

(Coming from gclone before 0.2.0, which signed in through a browser redirect and a "Web
application" client? A device that has not run `gclone login` since then has to do it once:
the Worker of 0.4.0 no longer serves those logins. [`worker/README.md`, "Moving from the
browser sign-in"](../worker/README.md#moving-from-the-browser-sign-in-gclone-before-020) has the
order to do it in — before the new Worker is deployed.)

## Connect the first device

The first login creates the vault.

```sh
gclone login https://<host>
```

The terminal shows an address and a code:

```
To sign in, open  https://www.google.com/device
and enter the code  ABCD-EFGH
(enter only a code shown in this terminal; waiting…)
```

Open the address in any browser — this machine's (gclone opens it for you when it can), your
phone's — enter the code, choose your Google account and approve. The terminal continues by
itself a few seconds later; a code is good for 30 minutes, and Ctrl-C stops the login. gclone
then finds no vault, asks for a new passphrase (leave it empty and it generates a strong one —
26 characters, 130 bits, shown once — recommended) and creates the vault, a folder named
`gclone` in your Drive.

**Store the passphrase in your password manager.** It is needed once on every new device and
cannot be recovered. It is also the only thing that protects the vault against Google and
Cloudflare, so prefer the generated one — and choose it well the first time: `gclone passwd`
changes the passphrase for future devices, but it cannot take back a weak one (see
[If a passphrase or a device's key file leaked](SECURITY.md#if-a-passphrase-or-a-devices-key-file-leaked)).
A generated passphrase can be typed in any case and with any spacing (`O` reads as `0`, `I`
and `L` as `1`) — from gclone 0.5.0 on, in the CLI and in a hosted viewer deployed from
0.5.0; gclone 0.4.0 and a viewer still on 0.4.0 want the 26-character one exactly as it was
displayed (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`), so deploy the new viewer before you rely on
sloppy typing there. Anything else is taken exactly as typed. That includes a passphrase of
your own that merely *looks* like a generated one — 26 letters and digits without a `u`,
five short words for instance: it is kept exactly as you entered it when you set it
(gclone says so at that moment), capitals and spaces included, on every version.

## Adding a device

On the new device, [install gclone](../README.md#install) (one command), then sign in with
the same command as on the first device:

```sh
gclone login https://<host>                 # shows a code; enter it at google.com/device in any browser
gclone login https://<host> --no-browser    # the same, without trying to open a browser on this machine
gclone login                                # a binary that has your auth URL built in
```

A binary that you built with your URL compiled in — or the release binary of your own fork —
needs no argument; `gclone --version` shows the URL a binary carries. A release binary of this repository can carry its maintainer's URL, whose
Worker does not let you in: pass yours, which takes precedence and is remembered.

The sign-in is the same everywhere — a laptop, an SSH session, a headless server: the terminal
shows `https://www.google.com/device` and a short code, you enter the code in a browser on
whatever device is at hand, and the terminal continues. On a machine with a graphical session
gclone also opens that page in the local browser (not over SSH, and not with `--no-browser`).
It opens a `google.com` address only: should the auth Worker ever name another one, gclone
prints it with a warning and leaves the decision to you.

gclone finds the existing vault and asks for the passphrase — once; the device caches the key
afterwards. (If the vault was created with gclone before 0.2.0, first run `gclone login` on a
device that is already attached and wait for `Vault unchanged.`: it is not yet verified that a
new sign-in sees such a vault, and a new device that sees none would offer to create a second
one. Do not run `gclone logout` on a device from before 0.2.0 until then — its old login cannot
be issued again. See [`worker/README.md`](../worker/README.md), "Moving from the browser
sign-in".) At the end it prints a **head fingerprint**:

```
Connected to vault "gclone" (38,201 files). This device: "nas".
Compare with `gclone status` on a device you trust (run it there now): head 7QK2-M9XA, 38,201 files.
```

Do compare it: a new device trusts the vault as Google serves it, and equal head values on two
devices mean both have applied the same index history. Take the device that **wrote last** as
the reference, and run `gclone status` there *after* the new device attached. What the value
is and is not: eight characters (40 bits) computed from the index objects' hashes — nothing
secret goes into it, so Google can compute it too. It shows that the new device was not handed
an *older* state than the reference device has. It does not show that the reference device is
itself current (a device can be kept on an old state by withholding the newest objects from
it), and it is a comparison for a person to make, not an authentication.

Useful options: `--device-name NAME` (default: the host name; give two machines with the same
host name different names), `--passphrase-file PATH` (first line of the file; never pass a
passphrase as an argument), `--all-keyfiles` (below). The auth URL is needed once per device; it is remembered and
survives `gclone logout`. Running `gclone login` again on a connected device repairs whatever
is missing (an expired login, an interrupted attach) and changes nothing else. If the vault's
index is incomplete at that moment (a gap or a rollback), the login still completes and tells
you to run `gclone repair`; until then nothing can be changed in the vault. It keeps a
login that still works without asking; to sign in with a different Google account run
`gclone logout` first. (The exception is a login made by gclone before 0.2.0: `gclone login`
always replaces it with a new sign-in — but only once that sign-in has seen a vault; a device
from before 0.2.0 that is attached to none does not create one unless asked with
`--new-vault`.) A sign-in that cannot see the vault the device is attached to (the wrong
account) is not kept, and nothing on the device changes.

**If the passphrase is refused although it is right.** A new device tries the passphrase on
the vault's four newest keyfiles (the passphrase-wrapped copies of the key; each try costs
about a second and 256 MiB). Anyone who can write to the vault folder can put keyfiles of
their own in front of the real one. gclone ignores the ones that are no keyfiles at all, and
when more real-looking keyfiles exist than it tried it does not say "Wrong passphrase" — it
says how many were not tried, asks at a terminal whether to try them, and
`gclone login --all-keyfiles` tries every one. `gclone passwd` on a device that is still
connected removes the cause: it writes a keyfile ahead of all others and retires the rest.

Nothing is ever copied between devices: each has its own Google login (refresh token), and the
vault key is unlocked on each device with the passphrase. Never copy `secrets.json` from one
machine to another. (A Mac's `secrets.sealed` cannot be copied at all in any useful sense: it
opens only on the Mac that made it — see
[Where a device keeps its key](SECURITY.md#where-a-device-keeps-its-key).)

Google drops a device's login after six months without use (one `gclone login` brings it
back; `gclone status` warns after 150 idle days). For rarely used machines, a monthly cron job
`gclone status -q` keeps the login alive.

## Day-0 checklist (before the first real use)

Several behaviours of Google and Cloudflare that the design relies on are documented but not
verified by any automated test (§2.9 of [the spec](SPEC.md)). After the one-time setup:

1. Run `gclone probe` (a hidden command). It answers the automatable rows against a throwaway
   folder and prints one line per row: `409` handling with pre-generated IDs (6), list lag and
   read-after-write (8), fields in the upload completion body (9), `generateIds` batch size
   (10), the multipart size boundary (12), visibility of unfinished resumable uploads (13).
2. Tick the manual rows below once. They need a browser, a second device, or days of waiting.
3. Run the opt-in live tests once (see [Development](../DEVELOPMENT.md#tests)): the backend conformance
   suite and a small two-device run against the real Drive, inside a throwaway folder.

| ✓ | # | Check | If the answer is bad |
|---|---|---|---|
| ☐ | 1 | Publish the app (client of type *TVs and Limited Input devices*) with `openid email drive.file`: no verification, no warning screen; the Worker-hosted home and privacy pages are accepted; once published, `gclone login` does **not** report a time-limited login (in Testing it does). | Setup text changes; a login that expires weekly is not an acceptable resting state. `login` detects the Testing case itself. |
| ☐ | 2 | Two devices, two logins of the same account: both keep working side by side, and device 2 discovers and reads the vault device 1 created. | The design depends on it. No fallback short of sharing one token. |
| ☐ | 3 | `gclone logout --revoke` on device 2: is device 1 signed out too (documented: yes)? After a new `gclone login`: is the vault listed again? **Keep a web download of the vault folder before trying.** | Revoke is per token after all → make it the default of `logout`. Files not visible after re-consent → the lost-device procedure must go through web download + `--vault-dir`. |
| ☐ | 4 | A second OAuth client in the same Cloud project sees the files the first one created — the hosted viewer's "Web application" client after a vault was created through the device client (the viewer finds the vault), and the device client after a vault was created through the "Web application" client of 0.1.0 (`gclone login` on such a device: "Signed in again … Vault unchanged."). | The hosted viewer cannot be used with that vault. For a login from before 0.2.0: `gclone login` reports it and changes nothing; the vault is moved while a Worker older than 0.4.0 is still deployed (`worker/README.md`, "Moving from the browser sign-in"). The "Worker cannot authenticate" recovery must use a web download. |
| ☐ | 5 | The first real `gclone login` succeeds: Google's device-code endpoint accepts the client with `openid email drive.file` (verified 2026-11-12), and the token answer after the consent carries an **ID token** with the verified e-mail address and a refresh token, with a `scope` that holds nothing but `openid`, `email` / `…/auth/userinfo.email` and `…/auth/drive.file`. | No ID token → every login ends right after the approval with "Sign-in was not completed (Google approved the sign-in, but its answer carried no ID token …)" — the Worker's `403 grant_unusable`; it fails closed, because it cannot apply the allowlist. The Worker then has to ask Google's userinfo endpoint instead. Login refused with `scope_not_allowed` naming a harmless scope → Google spells a granted scope differently; add it to `ALLOWED_SCOPES` in `worker/src/google.ts`. |
| ☐ | 7 | Sustained create rate; does session initiation count against it? | Tune the pack size and the pacer's start rate. |
| ☐ | 11 | A trashed file is still downloadable by ID. | Affects self-heal wording only. For `serve restic`: a file that another machine deleted answers "not found" one listing earlier — nothing breaks. |
| ☐ | 14 | `gclone passwd`, then `gclone passwd --purge-old`: the second run reports "1 in the Drive trash", and the keyfile the first run trashed is gone from the trash in drive.google.com. | Google does not list an app's trashed files to it: `--purge-old` then deletes the keyfiles that are still in the folder only — empty the Drive trash by hand after a `passwd`. |

`gclone serve restic` adds nothing to the table but leans on rows 2, 7, 8 and 11: its first
real run — `restic init`, a backup from two machines, `restic check --read-data`, a
`forget --prune` — is the check (see [Limitations](USAGE.md#limitations) for what is assumed).

The first real `gclone login` on two devices answers rows 1, 2 and 5. Repeat the checklist
after any Google policy change. The hosted viewer has a checklist of its own for its first
deployment, and a fifteen-minute test for the phone:
[`worker/README.md`](../worker/README.md#first-deployment-what-to-check).
