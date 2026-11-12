# gclone

gclone is a single-binary Rust command-line tool that stores files on Google Drive with
client-side authenticated encryption, for **one person with several devices**. It is an
rsync-style sync tool (`copy`, `sync`, `ls`, `cat`, …), not a mount.

- Everything is encrypted and authenticated on the device before it leaves: file contents,
  names, the directory tree, modification times and hashes. Google stores opaque objects.
- Drive is used as a dumb store of immutable, put-once ciphertext objects. The directory tree
  lives in an encrypted, append-only, per-device journal that every device replicates into a
  local SQLite database, so listing, renaming, moving, deleting and deduplicating never walk
  the remote and never move data.
- Files smaller than 1 MiB are packed together (up to 16 MiB per pack); larger files are one
  object each.
- Safe multi-device use: nothing is silently overwritten, conflicting edits become conflict
  copies, deleting means "trash" with a 25-day undelete (`gclone restore`, for one file or a
  whole directory), and permanent deletion happens only through an explicit
  `gclone gc --purge`.
- You set up OAuth **once in your life**: one Google OAuth client and one small stateless
  Cloudflare Worker (`worker/`) that holds the client's secret. Every device — the first or the
  tenth, with or without a browser of its own — is then connected with one command and one
  short code entered at Google. File data flows
  device ↔ Google directly and never through the Worker.

The design contract is the implementation spec, [`docs/SPEC.md`](docs/SPEC.md); section
numbers such as "§2.9" below refer to it.

## Status

Feature-complete for the MVP and tested against fakes only. **It has never talked to the real
Google Drive or to a deployed Cloudflare Worker.** The test suite and a manual smoke test drive
the real binary end to end over directory vaults and against a fake Google Drive + fake auth
Worker; the Worker's own tests run inside the Workers runtime against a fake Google. Before
trusting it with data, work through the [day-0 checklist](#day-0-checklist-before-the-first-real-use).
Tested on macOS (Apple silicon) and on Linux — the whole test suite and a two-device run of the
release binary, on aarch64 and x86_64, in containers; not yet on a Linux machine of its own.
Windows is not supported; inside WSL2 the Linux binary applies.

## Install

Prebuilt binaries for Linux (x86_64 and aarch64) and macOS on Apple silicon are attached to
this repository's GitHub Releases. The Linux ones are static: they need no particular
distribution or libc, and run inside WSL2 as well. `install.sh` picks the build for the
machine, checks it against the release's `SHA256SUMS` and puts it into `~/.local/bin` — no
sudo, nothing else is touched.

There is **no prebuilt binary for Intel Macs**: `install.sh` says so there and stops.
[Build from source](#building-from-source) instead — gclone itself runs on them.

```sh
curl -fsSL https://raw.githubusercontent.com/dwahdany/gclone/main/install.sh | sh
```

The released binaries have the repository owner's auth URL built in (`gclone --version` shows
it). To use your own auth Worker, pass its URL once: `gclone login https://<your-host>`.

For a private fork, `install.sh` reads `GITHUB_TOKEN` / `GH_TOKEN` or uses a signed-in
[GitHub CLI](https://cli.github.com); point it at the fork with `--repo OWNER/NAME`.

Options go after `sh -s --`, or into the environment: `--version v0.2.0` (`GCLONE_VERSION`;
default: the latest release), `--dir DIR` (`GCLONE_INSTALL_DIR`; default `~/.local/bin`),
`--repo OWNER/NAME` (`GCLONE_REPO`). If `~/.local/bin` is not on your `PATH`, the script says
so and names the line to add and the file it goes into (on Debian and Ubuntu, logging in again
is enough). It needs `curl` (`wget` is enough for a public repository), `tar`, `gzip` and
`sha256sum` (or `shasum` / `openssl`).

A `GITHUB_TOKEN` / `GH_TOKEN` in the environment, or a `gh` login, is used when there is one.
If GitHub refuses it (stale, expired, or for another repository), the script says so and
downloads without it, which is all a public repository needs.

Without GitHub — release archives copied to the machine, or built by hand —
`sh install.sh --base-url DIR` installs from a directory (a path, `file:///…` or `https://…`)
that holds `gclone-<target>.tar.gz` and `SHA256SUMS`.

Android/Termux and Intel Macs have no prebuilt binary (the script refuses there): build from
source — on Android, inside Termux.

`gclone --version` names the build and the auth URL that is compiled in — release binaries
carry the one from the repository variable `GCLONE_DEFAULT_AUTH_URL`, so that `gclone login`
needs no argument:

```
gclone 0.2.0 (aarch64-unknown-linux-musl, auth URL https://auth.example.org)
```

On Linux gclone uses the system's CA certificates (the `ca-certificates` package — present on
any regular installation, missing in minimal containers, where every connection fails with "No
CA certificates were loaded from the system"); `SSL_CERT_FILE` names another bundle.

### Updating

Run the install command again: it replaces the binary with the latest release (or the one named
by `--version`, which is also the way back to an older one) and touches nothing else — the
login, the configuration and the local index stay. Update all devices in reasonable time: a
device that meets index objects written by a newer gclone stops with exit code 3 until it is
updated (see [Limitations](#limitations)).

### Building from source

Unix only (macOS — Apple silicon and Intel — and Linux). Rust edition 2024, MSRV 1.89, and a C
compiler (bundled SQLite and the TLS crypto provider). With rustup, `rust-toolchain.toml` selects the compiler that CI and
the releases use; a Rust from the system's packages or from nix ignores that file.

```sh
cargo build --release --locked
install -m 755 target/release/gclone ~/.local/bin/      # or anywhere on your PATH
```

Optional: bake your auth URL into your own binary so that no device ever needs it typed. Use
the URL your devices will keep using — with a [custom domain](#5-recommended-a-custom-domain)
that is the custom host, because the `workers.dev` URL stops answering once the domain is
attached:

```sh
GCLONE_DEFAULT_AUTH_URL=https://auth.example.org cargo build --release --locked
```

A static Linux binary like the released ones (on Debian/Ubuntu: `apt install musl-tools`):

```sh
rustup target add x86_64-unknown-linux-musl          # or aarch64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
```

On a machine where `cargo` is a rustup shim without a toolchain, use nix:
`nix-shell -p cargo rustc --run 'cargo build --release --locked'`.

### Publishing a release

`.github/workflows/release.yml` builds, tests and publishes the binaries when a tag `v<version>`
is pushed (the tag must match `version` in `Cargo.toml`): `gclone-<target>.tar.gz` for
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`, plus
`SHA256SUMS` (no `x86_64-apple-darwin`: Intel Macs build from source). Set the repository
variable `GCLONE_DEFAULT_AUTH_URL`
(Settings → Secrets and variables → Actions → Variables) to your auth URL first; it is not a
secret — it is readable in the binary — and without it the binaries simply have no built-in
URL. `SHA256SUMS` guards against a damaged or swapped download, not against someone who can
publish releases in the repository.

## One-time setup

Done **once per person, never per device**. You need a Google account, a Cloudflare account
(the free plan is enough), Node 20 or newer and `curl`. Nothing in this repository
deploys anything by itself.

`worker/setup.sh` walks through steps 1, 3 and 4 interactively and prints the checklist of
step 2 with your URLs filled in. It asks first whether the Worker is to be served on its
`workers.dev` host or on a host name of your own. **Decide that before step 1**: the URL goes
into the Google app's branding and into every device's login, so starting with the custom domain of
step 5 saves doing the Google configuration twice and signing in again on every device. [`worker/README.md`](worker/README.md) is the authoritative
version of this list, with troubleshooting by error code. The steps by hand:

### 1. Deploy the Worker

```sh
cd worker
npm install
npx wrangler login          # opens a browser: sign in to Cloudflare
npx wrangler deploy
```

Note the URL it prints, `https://gclone-auth.<acct>.workers.dev`. This is your **auth URL**;
`<host>` below is its host name. (With a custom domain from the start — step 1 of the custom
domain section of `worker/README.md` instead of this plain deploy — the auth URL is your own
`https://auth.example.org`.) Until step 3 is done its home page says
`Status: not configured` — expected: the branding of step 2 needs the Worker's host name,
so the Worker has to exist first.

### 2. Create the Google OAuth client

In the Google Cloud console (labels drift now and then; the items stay the same):

1. **Project**: create one at <https://console.cloud.google.com/projectcreate> (any name), then
   enable the Drive API at
   <https://console.cloud.google.com/apis/library/drive.googleapis.com> → **Enable**.
2. **Google Auth Platform** → **Get started** (<https://console.cloud.google.com/auth/overview>):
   app name `gclone`, your e-mail address as support and contact address, Audience
   **External**. Do **not** upload a logo (it triggers brand verification).
3. **Branding**: Authorized domain `<acct>.workers.dev` (for a host of your own its
   *registrable* domain: `example.org` for `auth.example.org` — Google refuses a subdomain
   there); Application home page `https://<host>/`; Privacy policy `https://<host>/privacy`.
   The Worker serves both pages.
4. **Audience** → **Publish app**. The status must read **In production**. Do **not** click
   "Submit for verification" — `openid`, `email` and `drive.file` are non-sensitive scopes.
   If you skip publishing, Google ends every login after 7 days; `gclone login` detects that
   and refuses.
5. **Clients** → **Create client** → Application type **TVs and Limited Input devices** (any
   name). Nothing else to fill in: this client type has no redirect URI. Copy the client ID
   and the client secret **now**: the secret is shown only once.

Workspace accounts may choose Audience **Internal** instead of External + Publish. Console
changes can take from five minutes to a few hours to apply.

### 3. Give the Worker its three secrets

```sh
cd worker
npx wrangler secret put GOOGLE_CLIENT_ID        # the client ID from step 2.5
npx wrangler secret put GOOGLE_CLIENT_SECRET    # its secret
npx wrangler secret put ALLOWED_EMAILS          # your Google address; several: comma-separated
```

Each `wrangler secret put` deploys a new version at once; no further `wrangler deploy` is
needed. `ALLOWED_EMAILS` decides who may sign in — empty or missing means **nobody**. It must
stay a secret and never become a `vars` entry in `wrangler.jsonc` (see `worker/README.md`).

(Coming from gclone before 0.2.0, which signed in through a browser redirect and a "Web
application" client? [`worker/README.md`, "Moving from the browser
sign-in"](worker/README.md#moving-from-the-browser-sign-in-gclone-before-020) has the five
steps; devices that are signed in keep working meanwhile.)

### 4. Check

```sh
curl https://<host>/        # 200, and the page contains "Status: ready"
```

### 5. Recommended: a custom domain

On the `workers.dev` host anyone can spend the free plan's daily request quota and thereby stop
your logins and token refreshes until midnight UTC (data is never at risk). A custom domain
with a zone rate-limiting rule over **all** of the Worker's paths stops any single sender from
doing that (it counts per address; only the paid Workers plan removes the daily cap):
[`worker/README.md`, "Custom domain and rate-limiting rule"](worker/README.md#custom-domain-and-rate-limiting-rule-recommended).
If you chose your own host name in step 1, only the rule is left to do.

### 6. Connect the first device — this creates the vault

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
recommended) and creates the vault, a folder named `gclone` in your Drive.

**Store the passphrase in your password manager.** It is needed once on every new device and
cannot be recovered. It is also the only thing that protects the vault against Google and
Cloudflare, so prefer the generated one.

## Adding a device

On the new device, [install gclone](#install) (one command), then sign in with the same
command as on the first device. A release binary knows the auth URL (`gclone --version` shows
it), so there is nothing to type; a binary without one takes the URL as an argument, once:

```sh
gclone login                                # shows a code; enter it at google.com/device in any browser
gclone login --no-browser                   # the same, without trying to open a browser on this machine
gclone login https://<host>                 # a binary without a built-in auth URL
```

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
be issued again. See [`worker/README.md`](worker/README.md), "Moving from the browser
sign-in".) At the end it prints a **head fingerprint**:

```
Connected to vault "gclone" (38,201 files). This device: "nas".
Compare with `gclone status` on a device you trust (run it there now): head 7QK2-M9XA, 38,201 files.
```

Do compare it: a new device trusts the vault as Google serves it, and equal head values on two
devices mean both see the same history.

Useful options: `--device-name NAME` (default: the host name; give two machines with the same
host name different names), `--passphrase-file PATH` (first line of the file; never pass a
passphrase as an argument). The auth URL is needed once per device; it is remembered and
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

Nothing is ever copied between devices: each has its own Google login (refresh token), and the
vault key is unlocked on each device with the passphrase. Never copy `secrets.json` from one
machine to another.

Google drops a device's login after six months without use (one `gclone login` brings it
back; `gclone status` warns after 150 idle days). For rarely used machines, a monthly cron job
`gclone status -q` keeps the login alive.

## Everyday commands

Remote paths start with `:` (`:` alone is the vault root). `copy` and `sync` take one local
directory and one remote directory; the direction follows from which one has the `:`. The
**contents** of the source go into the destination, as with `rsync SRC/ DST/`:
`gclone copy ~/Photos :Photos` puts `~/Photos/a.jpg` at `:Photos/a.jpg`; a trailing slash
changes nothing. A single file cannot be the source (`gclone cat :PATH > FILE` fetches one).

```sh
gclone copy ~/Documents :Documents          # upload; never deletes anything
gclone copy :Documents ~/Documents          # download; never deletes anything
gclone sync ~/Photos :Photos                # upload, and delete remotely what was deleted locally
gclone sync :Photos ~/Photos                # download, and delete locally what was deleted remotely
gclone sync -n ~/Photos :Photos             # dry run: show the plan, change nothing

gclone ls -l :Photos/2026                   # list; -R is recursive
gclone tree :Photos
gclone cat :Documents/notes.txt             # to stdout; --offset N --count N read a range
gclone mkdir :Archive/2027
gclone mv :Photos/old :Archive              # into an existing directory: :Archive/old (no data is transferred)
gclone mv :Photos/old :Photos/2019          # otherwise a rename; replaces nothing without --force
gclone rm -r :Archive/tmp                   # files stay restorable for 25 days
gclone restore --list :Archive              # what can be restored under a directory (`:` = everywhere)
gclone restore -r :Archive/tmp              # bring back every deleted file under it, in one step
gclone restore --list :Documents/notes.txt  # one file: versions overwritten or deleted in the last 25 days
gclone restore :Documents/notes.txt --version 2

gclone status                               # login, vault, head fingerprint, devices, pending changes
gclone about                                # storage use, dead space, index shape
gclone check                                # every blob present, right size and md5 (cheap)
gclone check --download [:PATH]             # download and authenticate every file
gclone check ~/Photos :Photos               # compare a local tree with the vault by content
gclone gc                                   # trash data unreferenced for more than 30 days
gclone gc --purge                           # ...and delete for good what gc trashed earlier
gclone repair                               # republish missing index objects from this device's cache
gclone passwd                               # new passphrase (for future devices)
gclone logout                               # remove this device's login and cached key
```

How `copy` and `sync` behave:

- **Change detection** is size + mtime + ctime, with content hashes (BLAKE3) where those do not
  settle it; `--checksum` hashes everything.
- **Nothing unseen is overwritten.** gclone remembers what each local directory looked like
  when it was last in sync with its remote path (a three-way comparison). If the other side
  changed meanwhile, the file is skipped and reported (`! skip … remote is newer`), and when
  both sides changed the remote version is kept as `name.conflict-<device>-<n>.ext` (uploads)
  or the local one as `name.conflict-local-<time>.ext` (downloads). `--force` overwrites
  such a skipped file (and uploads again what was deleted in the vault); it does nothing else.
  A run with skipped files exits with code 6. With `-q` the skip lines are not printed, so the
  first ten reasons go to stderr instead.
- **`sync` deletes only what this directory pair has synced before**: a file that was
  transferred earlier and has since been removed from the source is removed from the
  destination. Entries that exist *only* at the destination and were never synced — what
  another device uploaded, what was always only there — are **never** deleted, not with
  `--force` either. `sync` keeps them, reports them (`! skip … only in the vault and never
  synced here`) and exits 6 on every run until you decide: fetch them with a `copy` in the
  other direction (`gclone copy :Photos ~/Photos`), or remove them (`gclone rm`, or by hand
  locally). Two devices that share one remote directory therefore run `copy` or `sync` *down*
  as well as up. A first sync never deletes anything.
- **Deletions are guarded.** More than 100 deletions, or 10 or more that are over a quarter
  of the destination, need a confirmation at the terminal or `--yes`. `--max-delete N` is a
  hard limit instead: up to N deletions run without a question, and a run that would delete
  more is refused whatever else is given — `--yes` does not lift it — so
  `gclone sync … --yes --max-delete 20` in a cron job never deletes more than 20 entries.
  What `sync` deletes in the vault stays restorable for 25 days (`gclone restore -r :PATH`);
  what it deletes locally is gone.
- **The safety guards say what to do** (exit code 5, nothing changed): a source directory
  that does not exist, or is empty although it was synced before (an unmounted disk), is
  refused — `--force` if it is meant; a local tree that looks restored from an older copy
  likewise. When the local directory is not the one last synced with that remote path (it was
  replaced, restored from a backup, or sits on a file system without stable inode numbers),
  gclone asks — and off a terminal needs — one of **`--keep-pair`** (it is the same
  directory: keep the sync state) and **`--reset-pair`** (start over: a first sync that
  deletes and overwrites nothing).
- **A remote path that does not exist is an error** for everything that reads from it:
  `gclone copy :Documnets ~/restore` fails with exit code 1 and creates nothing instead of
  reporting an empty success, and so do `check --download :PATH` and `check LOCAL :PATH`.
  (Uploading *to* a new path creates it.)
- **Excludes**: `--exclude GLOB` (repeatable, gitignore syntax) and a `.gcloneignore` file in
  the root of the local tree. Excluded files are neither transferred nor deleted, on either
  side — also when the other side spells the name differently (case, Unicode form). As in
  git, nothing under an excluded directory can be re-included: `build/` + `!build/keep.txt`
  keeps the file excluded; write `build/*` + `!build/keep.txt` instead.
- **gclone's own files are never synced**: when the local directory contains gclone's
  configuration or state directory (`~/.config/gclone`, `~/.local/state/gclone` — as when you
  back up your whole home directory) or the directory of a `--vault-dir` vault, those are
  skipped in both directions with a note, and a local directory *inside* one of them is
  refused.
- **`--reset-pair`** makes gclone forget what it last saw in this local directory: the run is
  then a first sync that deletes and overwrites nothing. Use it after the directory was
  restored from a backup or damaged; gclone asks for it (or `--keep-pair`) by itself when the
  directory was replaced. On a file system without stable inode numbers (some network
  mounts) pass `--keep-pair` on every run.
- **Identical content is uploaded once**: a renamed, moved or copied file whose content is
  already in the vault costs an index entry, not an upload (`= reuse`).
- **Ctrl-C** during `copy` / `sync` ends the transfers within about five seconds — also the
  ones that wait for a network that has gone away — then commits what is finished and exits
  130; running the same command again continues. (The commit itself needs the network; a
  second Ctrl-C exits at once.) A killed process loses nothing that was reported as done.
- **Files that change or disappear while a run is in progress** (an editor's swap file, a
  build's temporary files) are skipped and reported (`changed while it was uploaded`, exit
  code 6); the next run picks them up or forgets them. A skip does not hold back the deletes
  of a `sync`. A file that fails — it exists but cannot be read, an upload or download
  that kept failing — does: then nothing is deleted in that run.
- **When Google throttles** (a quota, or a rate limit that outlasts gclone's own retries),
  the run stops starting transfers in either direction, keeps what is finished and exits with
  code 75; run the same command again later.
- `--transfers N` (1–64, default 4) sets the number of parallel uploads; `--json` prints
  NDJSON events for `copy` / `sync` and is refused (exit code 2) by every other command, which
  has no JSON output; `-v` / `-vv` / `-vvv` or `GCLONE_LOG=debug` raise the log level (log
  lines go to stderr).

How `mv`, `rm` and `restore` behave (all three change only the index; no data moves):

- **`mv :SRC :DST`** follows the shell: if `:DST` is an existing directory, the source moves
  *into* it and keeps its name; otherwise it is renamed to `:DST`. Nothing that exists at the
  destination is touched unless you pass `--force`: then a file replaces a file, and a
  directory is merged into a directory of the same name, replacing files of the same name.
  The command reports how many files were replaced; they stay restorable for 25 days. A file
  never replaces a directory, nor a directory a file.
- **`rm` and `restore`.** Deleted and overwritten file versions stay restorable for 25 days.
  `restore --list :DIR` lists the restorable files under a directory (`deleted`, or
  `overwritten` when the path exists again in a newer version); `restore -r :DIR` brings back
  the newest removed version of every *deleted* file under it in one step and leaves files
  that exist now alone; `restore :FILE [--version K]` brings back one version of one file,
  replacing the current one (which stays restorable). Several paths can be given. Empty
  directories are not restored.

Not synced: symlinks, special files, names that are not UTF-8 (counted and reported),
permission bits other than "executable or not", directory mtimes, extended attributes. A
download that replaces an existing file keeps that file's permission bits (a `chmod 600` file
stays private); a file that is new on a device gets 0644 / 0755 under your umask.

### Using a vault without Google

`gclone login --vault-dir DIR` uses a local directory as the store — no Google account, no
Worker. It is the recovery path (download the vault folder from drive.google.com, unzip it,
`gclone login --vault-dir <folder> && gclone copy : ./out`, with the passphrase), and it is
also a complete backend of its own, for example on a NAS mount or an external disk. A device
is attached to one vault at a time; switch with `gclone logout --forget`.

To simulate a second device on one machine (or keep two vaults apart), give each its own pair
of directories — set **both**, and let gclone create them (it refuses a state directory that
is readable by other users):

```sh
GCLONE_CONFIG_DIR=~/dev2/config GCLONE_STATE_DIR=~/dev2/state gclone login --vault-dir /mnt/vault
```

## Security model in brief

How login and token refresh work, with diagrams: [`docs/AUTH.md`](docs/AUTH.md).

Full version: §1.3 (threat model), §4 (formats) and §15 (accepted risks) of the spec.

- **Cryptography.** One random 256-bit master key per vault. Every object is a stream of
  64 KiB chunks sealed with ChaCha20-Poly1305 under a one-time key derived (HKDF-SHA-256) from
  the master key, the object's purpose and a fresh random salt; chunk position and a final
  flag are authenticated, so truncation, reordering and splicing are detected. File contents
  are additionally pinned by BLAKE3 hashes inside the authenticated index.
- **The passphrase** wraps the master key in a *keyfile* stored in the vault (Argon2id,
  256 MiB, t = 3). That keyfile is what Google or Cloudflare could attack offline, so the
  passphrase is the root of confidentiality against them: the generated passphrase (100 bits)
  is out of reach, a weak typed one is not. `gclone passwd` writes a new keyfile but does not
  re-encrypt anything — it does not help against someone who already copied the old keyfile.
- **What Google learns**: the number and sizes of objects (files of 1 MiB or more to within
  0.03 %; smaller files are hidden in packs), when you write, which device wrote index
  objects, IP addresses and your account. Not names, tree shape, mtimes, hashes or contents.
- **What Google can do**: modify, swap, truncate, replay or delete objects. Every modification
  is detected. A rollback of the journal or withheld journal objects are detected by every
  device that has seen newer state (`gclone status`, and a warning on every command). A
  **fresh** device trusts the first state it is served — that is what the head fingerprint
  comparison at `login` is for. Deletion is a denial of service: detected, not prevented.
- **The auth Worker / Cloudflare** sees the OAuth client secret and the refresh and access
  tokens that pass through it, so it has the same reach as Google and no more: ciphertext and
  deletion. It never sees the passphrase, the master key or any file data. It is stateless and
  only lets the Google accounts in `ALLOWED_EMAILS` sign in. The app's Google scope is
  `drive.file`: it can only touch files it created itself, not the rest of your Drive. The
  Worker enforces that: it asks Google for nothing else, and it hands out no token for a grant
  that carries any other scope.
- **On the device** the refresh token and the cached master key sit in plaintext in
  `secrets.json` (mode 0600; gclone refuses to use it if it or its directory is accessible to
  others). Anyone who can read that file as you has the vault. At-rest protection is disk
  encryption. Treat the file like an SSH private key: never copy it to another machine, and
  exclude the state directory from backups that leave the machine (gclone itself never
  uploads its configuration or state directory, even when you sync your whole home).
- **Login phishing.** The sign-in is Google's device-code flow, and starting one needs no
  credentials. Someone can therefore start a login of *their own* and try to talk you into
  entering *their* code at `google.com/device`; the allowlist does not help, because the
  account that approves is yours. **Enter only a code that your own terminal shows right
  now** — nobody ever has a reason to send you one. If it happens anyway, the attacker's login
  reaches what every gclone login reaches: ciphertext, which it could trash (restorable for 30
  days) but not read. Remove the app at <https://myaccount.google.com/permissions> and sign
  in again. Details: [`docs/AUTH.md`](docs/AUTH.md).

### Lost or stolen device

Run `gclone logout --revoke` on any other device (or remove the app at
<https://myaccount.google.com/permissions>). Google can only revoke the login of **all**
devices at once; afterwards run `gclone login` on each device you keep. Whether the vault
stays visible to the app after a revoke and a new sign-in is unverified (day-0 row 3) — keep a
web download of the vault folder first. The thief still holds the master key the device had
cached: data it could already download stays exposed, because re-keying is not implemented.

## Limitations

- **Never run against the real services** (see Status). The Drive wire format, quota
  behaviour, OAuth details and the Worker's Cloudflare configuration are implemented from
  documentation and verified only against fakes.
- Tested on macOS and, in containers, on Linux; no Windows (WSL2 runs the Linux binary — keep
  the synced directories inside the Linux file system, not under `/mnt/c`); no FUSE mount; no
  shared drives; no sharing between users.
- `copy` / `sync` work on **directories** — a single file cannot be the source or the
  destination (use `cat` to fetch one file). There is no two-way sync in one command: run
  `sync` up and then down, or use `copy` in both directions. A `sync` in one direction only
  keeps reporting what exists just at its destination (exit code 6) — it never deletes it.
- No symlinks, special files, extended attributes, directory mtimes or full permission bits:
  only the executable bit travels. A file you made private (`chmod 600`) keeps its mode on
  your device when a newer version is downloaded over it, but arrives on every *other* device
  as a new file with 0644 / 0755 under that device's umask — set `umask 077` there, or tighten
  the files, if that matters. A rename that only changes the case of a name is not
  propagated.
- When two devices upload the same content with different modification times, the vault
  keeps the first uploader's time and the other device keeps its own until it syncs down.
- No re-keying: the master key cannot be rotated, so a leaked passphrase + keyfile copy or a
  stolen unlocked device is permanent for the data that existed then. No per-device
  revocation either (Google revokes all devices' logins or none).
- No way back in when the passphrase is forgotten **and** no connected device is left (a
  connected device can always set a new one with `gclone passwd`).
- The index is critical state and cannot be rebuilt from the data blobs alone. Its redundancy
  is every device's local replica (`gclone repair`), two retained snapshots and Drive's
  30-day trash.
- Space comes back slowly: deleted data stays restorable for 25 days, `gc` trashes it after
  30, and `gc --purge` deletes what an earlier `gc` trashed. Index changes that could not be
  published (a full Drive, a device that was off) are checked again before they go out: if
  their uploaded data is more than a week old, or was cleaned up meanwhile by another device,
  the change is dropped and the next sync uploads those files again. Dead space inside partly dead
  packs (at most 16 MiB each) is never reclaimed; `gclone about` reports it.
- Two **new** files with identical content in the same run are both uploaded; deduplication
  only works against content already in the vault. Deduplication is per whole file.
- Downloaded files are made durable in batches of up to 512 files or 16 MiB — each file
  synced through the descriptor it was written with, the batch flushed to the disk before its
  files are renamed into place, and the renames flushed before gclone records the files as
  synced — so a power cut leaves no half-written file where a good one is expected. The same
  order holds for everything else a download run records: files it finds already equal to the
  vault's, a changed modification time or executable bit, an empty directory it created, a
  file it deleted — first durable, then recorded. If the disk refuses, the files concerned are
  reported as failed (exit code 6) and the next run takes them up again.
  **Not covered:** files *you* wrote and gclone uploaded. gclone does not flush your files; if
  a power cut takes one back before your system had written it to disk, the next `sync` to the
  vault sees a file that was synced and is gone, and deletes it there (it stays restorable
  for 25 days, and the delete limits apply).
  Restoring many small files is fast (10,000 files in a bit over a second on a Mac's internal
  SSD, plus the wait below); a file of 1 MiB or more still costs two disk flushes of its own
  (a few milliseconds each on macOS), and while a batch is open, up to 16 MiB per download
  stream sit in `.gclone-partial-*` files next to the files they will replace. Every run
  that downloads something waits up to 2 seconds at the end to settle timestamps. The
  batching was measured on macOS (APFS); on Linux it is tested (in a container) but its speed
  on real hardware is not measured.
- Files with identical content are downloaded once and written one after another, however
  many there are. For content above 1 MiB the further files are local copies of the first one
  written; if that one cannot be written (disk full), all of them fail in that run.
- Scale: comfortable to about 300,000 files, works to about a million (the index snapshot is
  held in memory, roughly 130 bytes per file). No single index object may exceed 1 GiB.
- Mixed versions: when a newer gclone has written index objects this version cannot read,
  commands stop with exit code 3 and name the object ("this vault needs a newer gclone")
  instead of working on an incomplete index — update gclone on that device. Anyone who can
  write to the vault folder can provoke the same stop with a planted file; the message names
  it, and removing it from the `index` folder in drive.google.com ends it.
- An upload interrupted in the middle of a large file starts that file again from the
  beginning on the next run (finished files are never re-sent).
- Uploads need about 64 kbit/s of uplink **per parallel upload** (8 KiB/s; the default is 4
  uploads at once). A request that is slower than that, or that sends nothing for a minute,
  is treated as dead and retried. On a very slow connection use `--transfers 1`.
- The auth Worker is a single point of failure for logins and token refreshes, not for data:
  when it is down, devices work until their access token expires (at most an hour). After
  that `ls`, `tree`, `status` and `about` still answer from the local replica, with a warning;
  everything that needs Drive fails with exit 4 until the Worker is back. It is stateless and
  can be redeployed from `worker/` in minutes; the `--vault-dir` path needs neither it nor
  OAuth.
- `--json` exists for `copy` / `sync` only; every other command refuses it (exit code 2).
- `restore -r` brings back files, not empty directories, and takes the newest removed version
  of each deleted file — a directory cannot be restored "as of" an earlier day.
- `ls` and `tree` print names as they are, control characters included.

## Local files

| What | Where | Mode |
|---|---|---|
| `config.json` — which vault, the auth Worker URL (no secrets) | `$GCLONE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gclone`, else `~/.config/gclone` | 0600 |
| `secrets.json` — this device's refresh token and the cached master key | `$GCLONE_STATE_DIR`, else `$XDG_STATE_HOME/gclone`, else `~/.local/state/gclone` | 0600 |
| `token.json` — cached access token | same directory | 0600 |
| `state.db`, `lock`, `index-cache/` — the index replica and sync state | `<state root>/<vault id>/` | 0600 / 0700 |

`gclone logout` deletes `secrets.json` and `token.json` (and temp copies of them that an
interrupted write may have left in that directory); `gclone logout --forget` also deletes
`config.json` and the vault's state directory. `state.db` contains plaintext paths and hashes
and is as sensitive as the synced files themselves.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error — also a remote path that does not exist |
| 2 | usage error |
| 3 | integrity: crypto failure, index gap or rollback, vault trashed or missing, the vault needs a newer gclone, `check` found damage |
| 4 | fixed by `gclone login`: not connected, signed out, wrong passphrase, expired login, Worker problems |
| 5 | a safety guard refused; the message names the flag that answers it (`--yes`, a higher `--max-delete`, `--force`, `--keep-pair` / `--reset-pair`) |
| 6 | partial: some files were skipped or failed |
| 75 | temporary failure: quota or rate limit, index changes could not be published yet |
| 130 | interrupted |

## Day-0 checklist (before the first real use)

Several behaviours of Google and Cloudflare that the design relies on are documented but not
verified by any automated test (§2.9). After the one-time setup:

1. Run `gclone probe` (a hidden command). It answers the automatable rows against a throwaway
   folder and prints one line per row: `409` handling with pre-generated IDs (6), list lag and
   read-after-write (8), fields in the upload completion body (9), `generateIds` batch size
   (10), the multipart size boundary (12), visibility of unfinished resumable uploads (13).
2. Tick the manual rows below once. They need a browser, a second device, or days of waiting.
3. Run the opt-in live tests once (see [Development](#development)): the backend conformance
   suite and a small two-device run against the real Drive, inside a throwaway folder.

| ✓ | # | Check | If the answer is bad |
|---|---|---|---|
| ☐ | 1 | Publish the app (client of type *TVs and Limited Input devices*) with `openid email drive.file`: no verification, no warning screen; the Worker-hosted home and privacy pages are accepted; once published, `gclone login` does **not** report a time-limited login (in Testing it does). | Setup text changes; a login that expires weekly is not an acceptable resting state. `login` detects the Testing case itself. |
| ☐ | 2 | Two devices, two logins of the same account: both keep working side by side, and device 2 discovers and reads the vault device 1 created. | The design depends on it. No fallback short of sharing one token. |
| ☐ | 3 | `gclone logout --revoke` on device 2: is device 1 signed out too (documented: yes)? After a new `gclone login`: is the vault listed again? **Keep a web download of the vault folder before trying.** | Revoke is per token after all → make it the default of `logout`. Files not visible after re-consent → the lost-device procedure must go through web download + `--vault-dir`. |
| ☐ | 4 | A second OAuth client in the same Cloud project sees the files the first one created — in particular the device-flow client of 0.2.0 after a vault was created through the "Web application" client of 0.1.0 (`gclone login` on such a device: "Signed in again … Vault unchanged."). | `gclone login` reports it and changes nothing; the legacy secrets stay on the Worker, or the vault is moved (`worker/README.md`, "Moving from the browser sign-in"). The "Worker cannot authenticate" recovery must use a web download. |
| ☐ | 5 | The first real `gclone login` succeeds: Google's device-code endpoint accepts the client with `openid email drive.file` (verified 2026-11-12), and the token answer after the consent carries an **ID token** with the verified e-mail address and a refresh token, with a `scope` that holds nothing but `openid`, `email` / `…/auth/userinfo.email` and `…/auth/drive.file`. | No ID token → every login ends right after the approval with "Sign-in was not completed (Google approved the sign-in, but its answer carried no ID token …)" — the Worker's `403 grant_unusable`; it fails closed, because it cannot apply the allowlist. The Worker then has to ask Google's userinfo endpoint instead. Login refused with `scope_not_allowed` naming a harmless scope → Google spells a granted scope differently; add it to `ALLOWED_SCOPES` in `worker/src/google.ts`. |
| ☐ | 7 | Sustained create rate; does session initiation count against it? | Tune the pack size and the pacer's start rate. |
| ☐ | 11 | A trashed file is still downloadable by ID. | Affects self-heal wording only. |

The first real `gclone login` on two devices answers rows 1, 2 and 5. Repeat the checklist
after any Google policy change.

## Development

```sh
cargo test --locked                  # everything; no network, no credentials
cargo clippy --locked --all-targets
cargo fmt --check
cd worker && npm ci && npm run typecheck && npm test
sh tests/install/test.sh             # install.sh against a fake release and a fake GitHub (python3, curl)
```

`.github/workflows/ci.yml` runs all of it on every push to `main` and on pull requests, the
Rust part on Linux and on macOS, with the Rust version pinned in `rust-toolchain.toml` (clippy
runs with `-D warnings`: bump the version deliberately). The workflows pin every action to a
commit; `.github/dependabot.yml` proposes the updates.

(With nix: `nix-shell -p cargo rustc clippy rustfmt --run '…'` and
`nix-shell -p nodejs --run '…'`.)

- `Cargo.lock` is committed; build with `--locked`. Dependencies are compiled with
  `opt-level = 3` in dev and test builds too: the keyfile KDF is Argon2id at 256 MiB.
- Property tests use a seeded PRNG (`tests/support/prng.rs`). A failing case prints its seed;
  re-run it with `GCLONE_TEST_SEED=<seed> cargo test …`.
- `tests/cli_e2e.rs` spawns the debug binary, over directory vaults and against a fake Google
  Drive + auth Worker (`tests/support/fake_drive.rs`). The `GCLONE_TEST_*` switches it uses
  (fast KDF, Drive and revoke endpoints) are honoured only by builds with debug assertions; a
  release build ignores them.
- Opt-in live run against the real service (needs a device signed in with `gclone login`; it
  works inside one throwaway top-level folder `gclone-live-test-<hex>`, which it trashes at
  the end — the vault itself is not touched):
  `GCLONE_LIVE=1 cargo test --test live -- --ignored --test-threads 1`.
  `GCLONE_LIVE=mem` rehearses the same code against an in-memory backend (no network).
- The Worker's tests need no account, no secrets and no network; see `worker/README.md`,
  "Development".

### Repository layout

```
Cargo.toml, Cargo.lock      manifest and committed lock file
build.rs                    hands the target triple to `gclone --version`
install.sh                  installer of the released binaries (tests: tests/install/)
rust-toolchain.toml         the Rust version of CI and of the release binaries (for rustup)
.github/workflows/          ci.yml (fmt, clippy, tests, Worker, install.sh), release.yml (binaries on a tag)
.github/dependabot.yml      keeps the pinned actions current
docs/SPEC.md                the implementation spec (design contract, errata in §17)
src/lib.rs, src/main.rs     module declarations; main → cli::run
src/{consts,types,error,util,path,ui}.rs    shared: constants, plain types, errors + exit codes,
                                            helpers, path rules, terminal output
src/crypto/, src/format/    stream container, keys, KDF; index objects, blobs, keyfile, descriptor
src/backend/                storage trait, in-memory / directory / fault-injecting backends, Drive
src/auth/                   client of the auth Worker (login, token refresh)
src/state/, src/index/      SQLite replica; journal, merge, refresh, commit, repair
src/transfer/               upload pipeline (packing), downloads, ranged reads
src/sync/                   scan, planner, executor, remote-only commands, gc, check
src/config.rs, src/cli/     local configuration; one file per command
tests/                      integration tests; cli_e2e.rs drives the binary, live.rs is opt-in
tests/support/              seeded PRNG for property tests, the fake Google Drive + auth Worker
worker/                     the auth Worker (TypeScript); see worker/README.md
```

## Licence and warranty

MIT, see [`LICENSE`](LICENSE). gclone is provided "as is", without warranty of any kind: use it at
your own risk and keep an independent backup of anything you cannot afford to lose.
