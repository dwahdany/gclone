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
- The vault in a browser, two ways, both read-only: `gclone web` on a device that has gclone,
  and — optional — a page served by your Worker that decrypts in the browser, for a phone or
  a computer without gclone ([Browse from any browser](#browse-from-any-browser-the-hosted-viewer)).

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

The hosted viewer (0.4.0) is in the same state: built, and tested in desktop Chrome, WebKit
and Firefox against a fake Google Drive and a fake of the Worker's sign-in — **never deployed,
never run against the real Drive, never run on a phone**. Its own checklist for the first
deployment is in [`worker/README.md`](worker/README.md#first-deployment-what-to-check).

0.5.0 adds a backend for [restic](https://restic.net): `gclone serve restic` keeps a restic
repository on Drive, beside the vault ([Back up with restic](#back-up-with-restic)). It is
tested with the real restic against the fake Google Drive — **it, too, has not run against
the real Google Drive yet**.

0.5.0 also adds a second place for a Mac's login and key: a file that only that Mac's Secure
Enclave can open ([Where a device keeps its key](#where-a-device-keeps-its-key)). It was run
with the real Secure Enclave of one Mac (Apple silicon, macOS 27) from a terminal; **not
yet across a restart or a system update, and not from ssh or a daemon** — which is what the
built-in trial and `gclone keystore check` are for. Nothing moves there on its own: the
plain file stays until you run `gclone keystore use enclave`. Releases are now published
from a draft by a script on the maintainer's Mac that also signs the macOS build
([Publishing a release](#publishing-a-release)); **that script has only run against a fake
release so far**. For this first release made that way the order matters: the tag is pushed
alone, and `main` only after the release is published — until then `main` keeps the
previous `install.sh`, which installs old and new releases alike.

## Install

Prebuilt binaries for Linux (x86_64 and aarch64) and macOS on Apple silicon are attached to
this repository's GitHub Releases. The Linux ones are static: they need no particular
distribution or libc, and run inside WSL2 as well. `install.sh` picks the build for the
machine, checks it and puts it into `~/.local/bin` — no sudo, nothing else is touched.

What "checks it" is worth depends on whether the [GitHub CLI](https://cli.github.com) is
installed and signed in (`gh auth login`):

- **With `gh`**: the script verifies the archive's **build-provenance attestation**
  (`gh attestation verify`) — GitHub's signed statement, kept outside the release's files,
  that exactly these bytes were built by this repository's release workflow on the release's
  tag. A release whose files were replaced afterwards is refused.
- **Without `gh`**: the archive is checked against the release's `SHA256SUMS` only, and the
  script says so in one line. That shows a damaged download. It does not show a replaced
  release: the checksum list comes from the same place as the archive.
- **How new `gh` has to be**: **2.68.0** for the attestation (the script asks for the release's
  tag with `--source-ref`, which older versions do not know), **2.75.0** to check in addition
  that a signed macOS archive is a file of the published release (`gh release verify-asset`).
  An older `gh` counts as "too old": the script says which check it left out and goes on as
  without `gh` — or stops, under `--require-attestation`. `gh --version` shows yours.

Neither helps against someone who controls the repository itself: they can publish a
malicious release that is attested correctly, or change `install.sh`, which the command
below pipes into `sh`. To read the script first, download it instead of piping it.

**On a Mac**, a release can also carry a **signed build**
(`gclone-aarch64-apple-darwin-signed.tar.gz`): the very binary the release workflow built
and attested, with a Developer ID signature added on the maintainer's Mac. Where a release
has one, `install.sh` installs it, after checking that

- the signature is valid and comes from an Apple-issued Developer ID certificate, with the
  hardened runtime and nothing else — no entitlements, no other flag;
- the signed binary is the unsigned one of the same release apart from the signature (it
  removes both signatures and compares the rest byte for byte);
- with `gh`: the unsigned archive is what the release workflow attested, and the signed
  archive is a file of the published release (`gh release verify-asset`);
- **the signer did not change**: if the gclone already installed is signed, the new one has
  to be signed by the same team under the same identifier. Replacing a signed gclone with an
  unsigned one — or with one signed by somebody else — stops, unless you pass
  `--allow-signer-change`.

The first signed install has nothing to compare with and trusts the signer it finds; the
script prints the team identifier. `--unsigned` installs the unsigned, attested build
instead. The signature buys a stable code identity on macOS and a check that an update comes
from the same signer; it is **not** what protects the key (see
[Where a device keeps its key](#where-a-device-keeps-its-key)), and the same limit applies:
whoever controls the repository controls the script.

There is **no prebuilt binary for Intel Macs**: `install.sh` says so there and stops.
[Build from source](#building-from-source) instead — gclone itself runs on them.

```sh
curl -fsSL https://raw.githubusercontent.com/dwahdany/gclone/main/install.sh | sh
```

The released binaries have the repository owner's auth URL built in (`gclone --version` shows
it). To use your own auth Worker, pass its URL once: `gclone login https://<your-host>`.

For a private fork, `install.sh` reads `GITHUB_TOKEN` / `GH_TOKEN` or uses a signed-in
[GitHub CLI](https://cli.github.com); point it at the fork with `--repo OWNER/NAME`.

Options go after `sh -s --`, or into the environment: `--version v0.5.0` (`GCLONE_VERSION`;
default: the latest release), `--dir DIR` (`GCLONE_INSTALL_DIR`; default `~/.local/bin`),
`--repo OWNER/NAME` (`GCLONE_REPO`), `--require-attestation` (install nothing that `gh` did
not verify), `--no-attestation` (checksum only: releases before 0.5.0 carry no attestation
of the binaries, so with a signed-in `gh` an older version installs only with this), and on
a Mac `--unsigned` (`GCLONE_UNSIGNED=1`) and `--allow-signer-change`
(`GCLONE_ALLOW_SIGNER_CHANGE=1`). If `~/.local/bin` is not on your `PATH`, the script says
so and names the line to add and the file it goes into (on Debian and Ubuntu, logging in again
is enough). It needs `curl` (`wget` is enough for a public repository), `tar`, `gzip` and
`sha256sum` (or `shasum` / `openssl`); `gh` is optional.

A `GITHUB_TOKEN` / `GH_TOKEN` in the environment, or a `gh` login, is used when there is one.
If GitHub refuses it (stale, expired, or for another repository), the script says so and
downloads without it, which is all a public repository needs.

Without GitHub — release archives copied to the machine, or built by hand —
`sh install.sh --base-url DIR` installs from a directory (a path, `file:///…` or `https://…`)
that holds `gclone-<target>.tar.gz` and `SHA256SUMS` (checksum only: a directory is not a
GitHub release).

Android/Termux and Intel Macs have no prebuilt binary (the script refuses there): build from
source — on Android, inside Termux.

`gclone --version` names the build and the auth URL that is compiled in — release binaries
carry the one from the repository variable `GCLONE_DEFAULT_AUTH_URL`, so that `gclone login`
needs no argument:

```
gclone 0.5.0 (aarch64-unknown-linux-musl, auth URL https://auth.example.org)
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

`.github/workflows/release.yml` builds and tests the binaries when a tag `v<version>` is pushed
(the tag must match `version` in `Cargo.toml`) and puts them into a **draft** release: `gclone-<target>.tar.gz` for
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`, plus
`SHA256SUMS` (no `x86_64-apple-darwin`: Intel Macs build from source). Set the repository
variable `GCLONE_DEFAULT_AUTH_URL`
(Settings → Secrets and variables → Actions → Variables) to your auth URL first; it is not a
secret — it is readable in the binary — and without it the binaries simply have no built-in
URL. Each archive is signed with a GitHub **build-provenance attestation** in the job that
builds it, and the release job verifies every attestation again before it creates the draft;
`install.sh` verifies it on the installing machine when `gh` is there. `SHA256SUMS` guards
against a damaged download only. None of it guards against someone who can push to the
repository: they can publish a release of their own.

The same run builds the hosted viewer's files, `gclone-viewer-<version>.tar.gz` (what the auth
Worker serves as static files), in a job of its own that installs no npm package, and signs
that tarball with a GitHub **build-provenance attestation**. The Worker's deploy scripts verify
the attestation — not `SHA256SUMS` — before they use the bundle
([`worker/README.md`, "Deploying the viewer"](worker/README.md#deploying-the-viewer)). The
bundle is then tested in three browsers before anything is published; a failure there stops
the whole release.

**The workflow does not publish.** A draft is invisible to `install.sh` and to everyone
without write access. Publishing is one command on the maintainer's Apple-silicon Mac, from a
checkout that has the tag:

```sh
git fetch --tags
scripts/release-sign-macos.sh v0.5.0
```

It verifies every file of the draft against its attestation and `SHA256SUMS`, signs a copy of
the attested macOS binary with the Developer ID identity of that Mac (hardened runtime, no
entitlements), proves that the signed binary is the attested one apart from the signature,
runs it, adds `gclone-aarch64-apple-darwin-signed.tar.gz` and its line in `SHA256SUMS`,
downloads the whole draft again and checks it once more, and publishes after you type
`publish v0.5.0`. Then it verifies the published release (`gh release verify`,
`gh release verify-asset`, `install.sh --require-attestation`). It refuses to go on as soon as
anything does not verify, and until it publishes it can simply be run again — also after an
upload that was cut off (the draft may then be without `SHA256SUMS` or without the signed
archive; the script makes both again from the attested archives).

After publishing nothing can be changed, so the last step tells two things apart. *"THE
PUBLISHED RELEASE COULD NOT BE VERIFIED YET"*: a question to GitHub was not answered (a
network error, a rate limit, an attestation that is not served yet). That is not a verdict;
run

```sh
scripts/release-sign-macos.sh --verify-published v0.5.0
```

which needs no draft and no signing identity, changes nothing, and can be repeated: it
downloads every file of the published release and checks all of the above again. *"THE
PUBLISHED RELEASE DOES NOT VERIFY"* is only said when a published file is another one than
the one that was checked — that cannot be repaired, and means a new patch release.

The script uses the system's own `tar`, `file`, `otool`, `lipo` and `codesign` whatever
`PATH` says, so it also runs from inside a nix shell. What it needs and what you should know
before the first signed release:

- **Immutable releases must be on** (below) — the script checks and stops otherwise.
- **Exactly one identity of type "Developer ID Application"** in the keychain, or its hash in
  `GCLONE_SIGN_IDENTITY`. Other identity types beside it are ignored.
- **Keep that identity in a keychain of its own that is locked except while the script
  runs.** With the identity in the login keychain, *every program running as you can sign as
  you, silently* — `codesign` asks nobody — and such a binary would pass every "same signer"
  check. One-time setup (the file name and the password are yours to choose; the identity is
  exported from Keychain Access as a `.p12` first, and removed from the login keychain
  afterwards):

  ```sh
  security create-keychain gclone-signing.keychain-db
  security set-keychain-settings -lut 900 gclone-signing.keychain-db    # locks itself after 15 minutes
  security import DeveloperID.p12 -k gclone-signing.keychain-db -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple: -s gclone-signing.keychain-db
  export GCLONE_SIGN_KEYCHAIN=~/Library/Keychains/gclone-signing.keychain-db
  ```

  With `GCLONE_SIGN_KEYCHAIN` set, the script unlocks that keychain at the start (it asks for
  its password on the terminal) and locks it again on every way out.
- **The signature publishes who you are, for good.** The certificate inside every signed
  binary carries the team identifier, the certificate's name and — for an individual
  developer account — the name registered with Apple. Anyone reads it with `codesign -dvv`,
  and an immutable release cannot be withdrawn. The script writes none of it into the
  repository; the binary carries it all the same. If you do not want that, do not sign:
  publish the draft as it is (`gh release edit <tag> --draft=false --latest`, after removing
  the first paragraph of its notes) — `install.sh` then installs the attested build, and the
  key store works exactly the same. A Mac that already has a signed gclone will then ask for
  `--allow-signer-change`.
- **Notarization** is optional: with `GCLONE_NOTARY_PROFILE` set to a
  `xcrun notarytool store-credentials` profile the script submits the binary and requires
  "Accepted". Without it Gatekeeper calls a browser download "Unnotarized Developer ID";
  installs through `install.sh` are not affected.
- The identifier `io.github.dwahdany.gclone` is reserved for what this script signs. Sign
  nothing else with it — and never anything with an entitlement.
- `scripts/release-sign-macos.sh --selftest` runs the whole procedure against a fake release
  directory, a fake `gh` and an ad hoc signature, including the cases it has to refuse. It
  touches neither GitHub nor a keychain; run it before a release day.

**Order on a release day** — the tag first, `main` last:

```sh
git push origin v0.5.0                 # the tag ALONE: it carries the commit and starts release.yml
#   … wait for the workflow: a draft release
scripts/release-sign-macos.sh v0.5.0   # verify, sign, publish
#   … deploy the viewer (worker/README.md)
git push origin main                   # only now
```

Why `main` waits: the install one-liner pipes `install.sh` from `main`, the `install.sh` of
0.5.0 refuses a release whose binaries have no attestation when `gh` is signed in, and until
the draft is published the *latest* release is still the previous one — which has none.
With `main` pushed together with the tag, every install with a signed-in `gh` would fail for
the hour the workflow runs and until you have signed. The old `install.sh` installs old and
new releases alike, so nothing is lost by leaving it on `main` a little longer. Then deploy
the viewer ([`worker/README.md`](worker/README.md#deploying-the-viewer)).

**Before the first release, in the repository's settings:** turn on **immutable releases**
(a published file cannot be replaced and a release's tag cannot be moved; the Worker's deploy
scripts check for it with `gh release verify-asset` and refuse a release that is not
immutable), and under Advanced Security **Dependabot alerts** and **Dependabot security
updates**. `.github/dependabot.yml` and the weekly `.github/workflows/audit.yml`
(`cargo audit` on both lockfiles) only do their part once those are on. An advisory for a TLS
crate or for the encryption path is a reason to release again, reinstall on every device and
redeploy the viewer: the binaries are static and nothing updates itself.

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
node scripts/stub-dist.mjs  # a placeholder for the web viewer's files, which wrangler uploads with the Worker
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
application" client? A device that has not run `gclone login` since then has to do it once:
the Worker of 0.4.0 no longer serves those logins. [`worker/README.md`, "Moving from the
browser sign-in"](worker/README.md#moving-from-the-browser-sign-in-gclone-before-020) has the
order to do it in — before the new Worker is deployed.)

The hosted viewer needs three more secrets and a second OAuth client; it is optional and set
up separately ([`worker/README.md`, "The hosted viewer: setup"](worker/README.md#the-hosted-viewer-setup)).

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
26 characters, 130 bits, shown once — recommended) and creates the vault, a folder named
`gclone` in your Drive.

**Store the passphrase in your password manager.** It is needed once on every new device and
cannot be recovered. It is also the only thing that protects the vault against Google and
Cloudflare, so prefer the generated one — and choose it well the first time: `gclone passwd`
changes the passphrase for future devices, but it cannot take back a weak one (see
[If a passphrase or a device's key file leaked](#if-a-passphrase-or-a-devices-key-file-leaked)).
A generated passphrase can be typed in any case and with any spacing (`O` reads as `0`, `I`
and `L` as `1`) — from gclone 0.5.0 on, in the CLI and in a hosted viewer deployed from
0.5.0; gclone 0.4.0 and a viewer still on 0.4.0 want the 26-character one exactly as it was
displayed (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`), so deploy the new viewer before you rely on
sloppy typing there. Anything else is taken exactly as typed. That includes a passphrase of
your own that merely *looks* like a generated one — 26 letters and digits without a `u`,
five short words for instance: it is kept exactly as you entered it when you set it
(gclone says so at that moment), capitals and spaces included, on every version.

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
[Where a device keeps its key](#where-a-device-keeps-its-key).)

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
gclone web                                  # browse the vault in your browser (read-only; below)
gclone mkdir :Archive/2027
gclone mv :Photos/old :Archive              # into an existing directory: :Archive/old (no data is transferred)
gclone mv :Photos/old :Photos/2019          # otherwise a rename; replaces nothing without --force
gclone rm -r :Archive/tmp                   # files stay restorable for 25 days
gclone restore --list :Archive              # what can be restored under a directory (`:` = everywhere)
gclone restore -r :Archive/tmp              # bring back every deleted file under it, in one step
gclone restore --list :Documents/notes.txt  # one file: versions overwritten or deleted in the last 25 days
gclone restore :Documents/notes.txt --version 2

gclone status                               # login, vault, head fingerprint, devices, pending changes, key store
gclone about                                # storage use, dead space, index shape
gclone check                                # every blob present, right size and md5 (cheap)
gclone check --download [:PATH]             # download and authenticate every file
gclone check ~/Photos :Photos               # compare a local tree with the vault by content
gclone gc                                   # trash data unreferenced for more than 30 days
gclone gc --purge                           # ...and delete for good what gc trashed earlier
gclone repair                               # republish missing index objects from this device's cache
gclone passwd                               # new passphrase (for future devices); the old keyfile goes to the trash
gclone passwd --purge-old                   # ...and the old keyfiles are deleted for good, trash included
gclone keystore                             # where this device keeps its login and key; the Secure Enclave trial (macOS)
gclone keystore check                       # can this session (cron, ssh, a LaunchAgent) use the Secure Enclave? exit 0 = yes
gclone keystore use enclave                 # macOS: move the key out of the plain file (checks the passphrase first)
gclone keystore use file                    # ...and back
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

How `gc`, `repair` and `passwd` behave:

- **`gc` runs only on a complete index.** It is the one command that judges what is dead, so
  it does nothing (exit code 3, in all three steps: plain, `--orphans`, `--purge`) whenever
  this device knows that its view of the vault may be incomplete: the index has a gap or was
  rolled back, a segment still waits for its predecessors, **an index object failed
  verification and was ignored**, or a newer snapshot could not be used. The message names
  the object. Run `gclone repair` on a device that has seen it; an object that no device has
  (a planted or destroyed one) has to be removed from the vault's `index` folder in
  drive.google.com before `gc` runs again. `gc` also does nothing (exit code 5) while
  Google's clock and this device's are more than a day apart, because every age it judges by
  is measured on Google's clock.
- **`repair`** puts back what this device's local index cache holds and the vault no longer
  does — also an index object that still stands under its name but with other bytes (it was
  overwritten or replaced; the impostor goes to the trash) — and then publishes a snapshot of
  everything this device knows. Any device that has applied the missing objects can repair
  the vault for all.
- **`passwd`** needs no old passphrase (the device already has the key). It writes a new
  keyfile, reads it back from the vault and compares it, and only then retires the old one:
  into the Drive trash by default, where it — and the old passphrase with it — keeps working
  for 30 more days, which is also your way back if the new passphrase gets lost together with
  the last connected device. `--purge-old` (or a yes to the question at a terminal, which is
  asked **before** anything is written — Ctrl-C there changes nothing) deletes the old
  keyfiles for good instead, together with **every** keyfile in the Drive trash, whatever
  put it there: that is the choice when an old passphrase may have leaked. It says "gone …
  trash included" only after listing the folder and its trash again, and names what is
  left otherwise. If `passwd` is ever cut off between writing the new keyfile and retiring
  the old one, `gclone check` warns that two keyfiles are in the vault folder; running
  `gclone passwd` again settles it. **Neither changes the vault's
  key**; what a passphrase change can and cannot do is the next section's subject:
  [If a passphrase or a device's key file leaked](#if-a-passphrase-or-a-devices-key-file-leaked).

Not synced: symlinks, special files, names that are not UTF-8 (counted and reported),
permission bits other than "executable or not", directory mtimes, extended attributes. A
download that replaces an existing file keeps that file's permission bits (a `chmod 600` file
stays private); a file that is new on a device gets 0644 / 0755 under your umask.

### Browse the vault in your browser

Everything on Drive is ciphertext, so Google's own pages show nothing useful. `gclone web`
starts a small web server on this machine and opens the **decrypted** vault as a file browser
in your default browser: folders with breadcrumbs, a list sortable by name, size and time, a
search over every file and folder name in the vault, previews (images, PDF, audio and video
with seeking, text and code) and downloads.

```sh
gclone web                             # opens the browser; Ctrl-C in the terminal ends it
gclone web --no-browser --port 8377    # only print the link; a fixed port instead of a free one
```

It is **read-only**: no upload, rename, delete or restore — those stay with the commands
above. It shows what this device's index knows; **Refresh** in the page reads the vault's
index again, so that uploads from other devices appear. The viewer holds no lock while it
runs: `gclone sync` in another terminal works as usual. Keys: arrows, Enter, Backspace (up
one folder), Esc, and `/` for the search.

Security, in three sentences. The server listens on this machine only (`127.0.0.1` and `::1`;
there is no option for anything else) and answers only to a browser that came in through a
one-time link — printed in the terminal, or, when gclone opens the browser itself, handed
over in a private file rather than on a command line that other users of the machine could
read — which is traded for a session cookie that the browser sends to this server and to no
other program on the machine; another user, or a web page that guesses the port, gets a `403`
and nothing else, and requests under a foreign host name or from another site are refused as
well. Files are decrypted on their way to the browser, never written to disk, and treated as
untrusted content: an HTML or SVG file from the vault never runs as a page of the viewer
(HTML is shown as text, anything unknown is a download). The names of your files and folders
stay out of the browser's address bar, tab title and history — the address never changes
while you browse, and files are fetched under opaque ids — so nothing of the vault ends up
in a history that the browser may sync to its vendor.

What remains: anyone who can already read your files or your browser profile can read the
vault through the viewer too; the places you visited in a tab stay in the browser's
session-restore data (so that reload and "restore tabs" work) until the tab and its "recently
closed" entry are gone; and a file you download is in the
browser's download list under its name, like any download.

**A new link ends the old sessions.** Press Enter in the terminal for a new link — to move
to another browser, or after closing the first. Every link and every browser session from
before stops working at that moment, downloads included. So if a link ever answers "has been used
already" although you did not open it, press Enter: whoever was faster is shut out.

**Signing out ends the viewer.** `gclone logout` on this device stops a viewer that is still
running in another terminal within a second or so (it exits with a message); it does not go
on serving a device you have just signed out.

**From another machine.** The viewer never listens on the network. To browse the vault of a
machine without a display from your laptop, forward the port over SSH — the same number on
both ends — and open the printed link on the laptop:

```sh
ssh -t -L 8377:127.0.0.1:8377 nas gclone web --port 8377
```

(`-t` gives the remote gclone a terminal, so that Ctrl-C and a closed connection end it; under
SSH it prints the link and does not look for a browser.)

### Browse from any browser (the hosted viewer)

`gclone web` needs a device that is attached to the vault. The **hosted viewer** needs only a
browser: a read-only page at your Worker's address, `https://<host>/`, for a phone or a
computer without gclone. You sign in with Google, the password manager fills in the vault
passphrase, and you get the same file browser as `gclone web` — folders, sorting, search over
every name, previews (images, audio and video with seeking, text; a PDF opens in a tab of its
own) and downloads of any size.

It is optional and off until you set it up:
[`worker/README.md`, "The hosted viewer: setup"](worker/README.md#the-hosted-viewer-setup).

**How it works.** The page signs your browser in to Google with a redirect; the Worker keeps
that sign-in sealed in a cookie that scripts cannot read, and hands the page a short-lived
access token. With it the browser fetches **ciphertext** straight from Google Drive and
decrypts it itself, with gclone's own read path compiled to WebAssembly. The Worker never
sees a file, a name, the passphrase or a key. Nothing derived from the passphrase is stored
anywhere: it is asked for on every page load, and the keys live in the tab's memory until you
lock, reload or close it.

**What you trust when you use it.** Without the hosted viewer, the Worker and Cloudflare
reach ciphertext only. With it, **whoever serves the page — your Cloudflare account, the
Worker's secrets, the domain — can serve a page that takes the passphrase, and with it every
file.** No header, hash or integrity attribute changes that, because the same party serves
them. What limits it:

- The viewer's **static files** are built by the release workflow, signed with a
  build-provenance attestation, and the deploy scripts verify that before they upload
  anything. Afterwards `verify-deployed` compares what the host serves with the release, from
  any machine, at any time. That finds an accident, a stale deployment or a changed file — not
  a Worker that answers one visitor differently.
- **The Worker's own code is outside that signature.** The attestation covers the files the
  browser loads; the script that serves the page — it answers `/` and the sign-in routes, and
  sets every header of the page — is bundled by `wrangler` on your machine, from your
  checkout, with the npm packages of the deploy toolchain. Nothing signs it and nothing
  compares what was uploaded with the release. Deploy it from a clean checkout of the tag
  (the deploy scripts check the commit and list local changes), on a machine you trust.
- **A check of the host says nothing about a browser.** If someone else served your viewer's
  address even briefly, a browser that visited then can keep *their* page — it survives the
  redeploy, and `verify-deployed` cannot see it. What to do:
  [After a change of hands](#after-a-change-of-hands-the-hosted-viewer).
- A device that never opens the hosted viewer is exposed exactly as before.

If you would rather not extend that trust, do not set the viewer up; `gclone web` over SSH
([above](#browse-the-vault-in-your-browser)) covers a machine you can reach.

The second thing you trust is the browser you use it in. An extension, or anything else that
runs script in the viewer's page, sees what the page sees: **the passphrase, whenever it is
typed or filled in while the script is there, and every name and the contents of every file
for as long as the vault is unlocked.** What it cannot take after the unlock is a key: the
keys stay in workers the page cannot read, and the per-file keys that the page's channel
carries cross it encrypted to the Service Worker (before 0.5.0 they did not, and such a
script could collect the key of every file in milliseconds and decrypt the vault later).
So a script that is **gone before the passphrase is entered again** carries away only what
it actually read. Two things it can still do, said plainly: it can **keep that tab from
locking or signing out** — the Lock button, the idle lock and Sign out are code of the page
it runs in — and then it keeps the open vault for as long as the tab lives; and if it is
still there the next time the passphrase is entered in that tab (it can show you the
page's own unlock screen when you press Lock), it has the passphrase. **If anything about
the page looks wrong, close the tab or the browser instead of pressing Lock, and do not
type the passphrase into that tab again.** All of this is a limit on the damage, not a
defence: use the viewer in a browser profile whose extensions you trust.

**Three habits against phishing.** The viewer gives a web page a reason to ask for the vault
passphrase, and that is new: a page that only *looks* like the viewer can get a Google token
out of you with a device code (see "Login phishing" below) and then ask for the passphrase —
which is everything. Three habits make that fail:

1. **A web page never shows a code.** The viewer signs in with a redirect to Google and
   nothing else. It never shows a code and never asks you to enter one at
   `google.com/device`. Codes belong to a terminal in which you started `gclone login`; a web
   page with a code is not gclone.
2. **Let the password manager fill the passphrase — never type it into a web page.** The
   passphrase field is a login field, so a password manager offers the passphrase on the real
   address and not on a look-alike. If it stays silent, check the address.
3. **Open the viewer from a bookmark or the home-screen icon**, with `https://`, never from a
   link in a message.

**Where to save the passphrase.** In a password manager that Google cannot read: iCloud
Keychain, a separate manager, or Google Password Manager with on-device encryption turned
on. If the browser offers to save it into a Google account with standard encryption (Chrome
signed in to the same account that holds the vault), decline — Google would then hold the
ciphertext, the keyfile and the passphrase, and "Google learns no names and no contents"
would no longer be true. The viewer cannot see or stop that offer; its unlock screen says the
same.

**Locking and signing out.** The Lock button forgets the keys, in every tab of the viewer
that is open in that browser; so do, for each tab by itself, 15 minutes without input and 5
minutes in the background (by the clock, so a phone that was put away comes back at the
passphrase screen), and any reload. A session lasts 12 hours, or 30 days with "Stay signed
in" — tick that on your own devices only. "Sign out" ends the viewer's session, clears what
the page kept and takes every other tab of the viewer to the sign-in screen; it does **not**
sign the browser out of Google, so on a computer that is not yours sign out of Google as
well (the signed-out screen links to it). **A file that you opened in a tab of its own** —
a PDF (the only way the viewer shows one), or an image or text through "Open in a new tab" —
**has left the viewer: it stays on the screen after Lock and after Sign out. Close that tab
yourself.** To end
every browser session at once — a lost phone — put a new `SEAL_KEY` on the Worker
(`worker/README.md`, "Operating it"); devices are not affected.

**Limits.**

- Read-only, like `gclone web`: no upload, rename, delete or restore. (The Google token the
  page holds *could* overwrite or trash ciphertext — Google has no read-only form of
  `drive.file`; that the viewer never does is a property of its code.)
- Every visit is a fresh device: the viewer trusts the vault state it is served and cannot
  notice a rollback between visits. The info panel shows the **head fingerprint**; compare
  it with `gclone status` on the device that wrote last when it matters (what the value does
  and does not prove: [Adding a device](#adding-a-device)).
- The index is downloaded on every unlock and kept in memory: measured to 100,000 files
  (15 MB per visit, about 100 MiB of memory). Above 64 MiB of index the viewer asks before
  it loads; much larger vaults may not open on a phone.
- The unlock itself needs 256 MiB of memory for a moment (the keyfile's Argon2id). Whether
  your phone can do that repeatedly is what
  [the phone test](worker/README.md#the-phone-test-15-minutes) answers — it has not been
  run yet.
- A download streams through the tab: it needs the viewer's tab to stay open, and on a phone
  in the foreground. Whole-file hashes are not checked for streamed downloads; every chunk
  is authenticated, so a wrong, missing or reordered byte still fails the download (as with
  `gclone cat` into a pipe).
- A PDF is not shown inside the viewer's page but in a tab of its own, behind an "Open"
  button: a link in a PDF would otherwise take the unlocked viewer's tab to an address of the
  file's choosing with one click. Audio and video have no "Open in a new tab".
- No file name goes into the browser's history: the address and the title never carry one,
  and a file in a tab of its own is titled by a random id. A file you **download** is in the
  browser's download list under its name, as any download.
- A refresh downloads at most 64 MiB of new index without asking; beyond that it says so,
  and the next unlock asks.
- It needs a browser with Service Workers (current Chrome, Firefox, Safari, also on iOS; not
  some private-browsing modes). Without one the viewer says so and stops.
- The viewer signs in through a second OAuth client. Whether Google shows that login the
  vault that `gclone login` created is not verified yet — the first deployment tells.
- Devices that signed in before gclone 0.2.0 must run `gclone login` once (see the one-time
  setup).

### Back up with restic

[restic](https://restic.net) makes deduplicated, encrypted snapshots; `gclone serve restic`
lets it keep its repository on Google Drive. restic does the encrypting, deduplicating and
packing — gclone adds no second encryption and its vault is not involved. What gclone
contributes is the Google sign-in (no OAuth setup, no rclone configuration) and its Drive
client: resumable uploads, retries, rate limiting. **A signed-in device is all it takes**; the
vault passphrase is never asked for.

There is no daemon and no port. restic starts gclone itself, through its `rclone` backend,
and stops it when it is done (restic 0.17 or later):

```sh
export RESTIC_REPOSITORY=rclone:laptop      # the name after "rclone:" is the repository on Drive
export RESTIC_PACK_SIZE=64                  # MiB; Drive is slow per file
alias restic='restic -o rclone.program=gclone'

restic init                                 # about a minute: it creates the repository's 262 folders
restic backup ~/Documents
restic snapshots
restic restore latest --target /tmp/restore
restic forget --keep-daily 7 --keep-weekly 8 --prune
restic check                                # --read-data downloads every pack
```

A repository name is 1 to 63 characters of `a-z`, `0-9`, `.`, `_` and `-`. Systemd units,
cron jobs, resticprofile, Backrest and the like need the same two settings: the option
`rclone.program=gclone` and a repository `rclone:NAME`. restic looks the program up on its
`PATH`, and what starts restic there usually has a short one that leaves out `~/.local/bin`,
where the installer puts gclone — name it in full (`-o
rclone.program=/home/you/.local/bin/gclone`), and run restic as the user who signed in:
gclone finds the sign-in under that user's home directory.

- **Pack size.** restic's default is 16 MiB per pack; use 64 (`--pack-size 64` or
  `RESTIC_PACK_SIZE=64`, on every command that writes — it is not stored in the repository).
  Every file costs Drive API calls, and `check` and `prune` list every pack: 1 TiB is about
  65,000 packs at 16 MiB and 16,000 at 64. restic needs (connections + 1) × pack size of
  temporary disk space; gclone holds up to 33 MiB of memory per upload in flight (five at once
  by default; `-o rclone.connections=2` on a small machine).
- **Where the files are.** `My Drive/gclone-restic/<name>/` with `config`, `keys/`, `locks/`,
  `snapshots/`, `index/` and `data/00` … `data/ff` — restic's own local layout. Downloaded
  from drive.google.com and unzipped, the folder is a restic repository that restic opens
  directly (`restic -r ./laptop snapshots`), without gclone. **The reverse does not work**:
  files put into `gclone-restic/` through drive.google.com or another tool are invisible to
  gclone, which sees only files it created itself. To move an existing repository to Drive,
  use `restic copy`.
- **Leave the folders alone.** Do not rename, move or half-delete anything under
  `gclone-restic/` in the Drive UI. A folder that is missing, in the trash or there twice is
  an error that stops restic within seconds, with a line that names the folder — never an
  empty listing, which would let `prune` remove live data.
- **Deletes go to the Drive trash**, as everywhere in gclone: what `forget`, `prune` or
  `unlock` remove can be restored in drive.google.com for about 30 days, and its space is
  freed only when the trash is emptied (there, by hand, to free it sooner). A file restored by
  hand is back for restic too — also for a `--port` listener that is still running, at the
  latest half a minute after the delete: a restored lock is a stale lock (`restic unlock`), a
  restored pack is unreferenced data (`restic prune`).
- **`--append-only`** refuses every delete except locks, like rest-server's flag: `backup` and
  `check` work, `forget`, `prune` and `key remove` fail within about 20 seconds (restic retries the refusal a few times).

  ```sh
  restic -o rclone.program=gclone -o rclone.args="serve restic --stdio --append-only" backup ~/Documents
  ```

  It is a guard against mistakes and scripts gone wrong, **not a security boundary**: the same
  machine holds a Google login that can trash or delete those files directly.
- **Several machines, one repository.** Run `restic init` on one machine, once; then each
  machine signs in (`gclone login`) and uses the same name. (A second `init` for the name
  that starts seconds after the first fails, as it should, and says so — but the key file it
  wrote first stays in `keys/`: remove it with `restic key list` and `restic key remove`.)
  restic's locks keep the machines apart: gclone answers every listing from Drive at that
  moment, never from memory, and acknowledges a lock only once a listing shows it. `backup`
  runs alongside other backups; `forget`, `prune` and `check` need the repository to
  themselves and say "already locked" otherwise. A lock left by a killed restic is removed
  with `restic unlock`.
- **Speed.** Drive is slow per file, not per byte. `forget --prune` deletes one file per
  call — thousands of packs take minutes — and `check` and `prune` list 256 folders first
  (some 25 seconds at the rate gclone starts with).
- **A machine that only runs restic.** Run `gclone login`. When it asks for the vault
  passphrase, stop with Ctrl-C: the sign-in is saved by then, and `serve restic` needs nothing
  else.
- **`sudo restic …`** runs gclone as root, which has its own (empty) configuration and is
  refused the user's files. Sign in once as root (`sudo gclone login`), or run restic as the
  user.
- **The daily upload limit.** Google accepts about 750 GB of uploads per account and day,
  restic's and the vault's together (restic's are not counted in gclone's own warning). Once
  it is reached nothing can be uploaded for up to 24 hours — not even restic's lock file, so
  every restic command that takes a lock fails, on every machine. It does not fail at once:
  restic and gclone keep trying, restic sits silent for about four minutes and gives up after
  about twelve. The first line it shows (`rclone: gclone: POST …:locks: rate limited …`)
  already names the daily limit and the way out — stop restic there. Read-only commands
  (`snapshots`, `restore`, `ls`, `check`) work in that state with `--no-lock`, within a
  second. For a first backup of more than about 700 GB, limit it from the start: `restic
  backup --limit-upload 8000 …` (KiB/s).
- **Stopping.** Ctrl-C or SIGTERM to restic. gclone ends when restic does, and ignores those
  signals itself, so that restic can still remove its lock. If restic is stopped in the middle
  of an upload, gclone stays a moment longer (at most ten seconds) to take the unfinished
  file back — after restic has exited: restic does not wait for it. Where everything that is
  left is killed the moment restic exits (restic as the main process of a container, the end
  of a CI step), that does not happen, and a lock restic was just creating can stay behind:
  `restic unlock` removes it. An index file is never taken back — another machine may be
  relying on it already.

**The listener.** For tools that can only speak restic's `rest:` backend, `gclone serve
restic --port 8765` listens on 127.0.0.1 and prints a token, new at every start:

```
Serving restic repositories on http://127.0.0.1:8765/NAME/ — Ctrl-C stops.
export RESTIC_REST_USERNAME=gclone
export RESTIC_REST_PASSWORD=3f0c…
restic -r rest:http://127.0.0.1:8765/NAME/ snapshots
```

Every request must carry the token (restic takes it from those two variables): a loopback port
is reachable by every user of the machine and, through a browser, by any web page. Use
`127.0.0.1` in the URL as printed. It serves every repository of the signed-in account and
takes `--append-only` as well. It stops with Ctrl-C, with SIGTERM or SIGHUP (`kill`, a service
manager, `docker stop`, a closing terminal) — exit code 0, after taking back uploads restic
was not answered for — and with `gclone logout` (exit code 4). For unattended runs the first
form is the better one: nothing listens, and nothing has to be kept running.

The token keeps other users of the machine from the data, **not from the port**: a local
program that opens connections and sends nothing can keep the listener busy, so that restic
waits. It cannot read or change anything. On a machine you share with people you would not
trust that far, use the first form.

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
  Keys are wiped from memory when their holders are dropped, as far as that goes: it is best
  effort — copies made when a key is moved or handed to a library are not all covered — and
  it protects nothing on a device whose `secrets.json` holds the key in the clear anyway.
- **The passphrase** wraps the master key in a *keyfile* stored in the vault (Argon2id,
  256 MiB, t = 3). That keyfile is what Google or Cloudflare could attack offline, for as long
  as they like — Google keeps every version it ever held — so the passphrase is the root of
  confidentiality against them: the generated passphrase (26 characters, 130 bits; 20
  characters and 100 bits when it was generated by gclone before 0.5.0) is out of reach, a
  weak typed one is not, and the only rule gclone enforces on a typed one is its length.
  `gclone passwd` writes a new keyfile under a new passphrase and retires the old one — into
  the Drive trash for 30 days, or for good with `--purge-old`. It re-encrypts nothing and
  changes no key: it does not help against someone who already copied an old keyfile.
- **What Google learns** (and anyone else who can read the vault folder — a phished login, a
  browser signed in to the hosted viewer): **the exact size of every file and the number of
  files**; the order in which the files of one upload were sorted; when you write; which
  device uploaded what (device ids are in the names of index objects and data folders); how
  many commits there were and how often the passphrase was changed (counters in object
  names); IP addresses and your account. Small files are packed together, which saves
  requests — it does **not** hide their sizes: each file in a pack begins with a recognisable
  unencrypted header, so the pack can be split into its members without any key. The length
  of an index object also grows with the lengths of the paths in it. Sizes in sequence can
  be enough to recognise a known set of files — a public repository's checkout, a published
  album. **Not** learned: names, the tree, modification times, hashes, contents.
- **What Google can do**: modify, swap, truncate, replay, delete or withhold objects, and
  choose their creation times. Every changed byte is detected, in file data and in the index.
  A rollback of the index — objects that a device has applied are deleted, or overwritten or
  re-created under the same name — is detected by every device that had applied them
  (`gclone status`, a warning on every read-only command, exit code 3 on every other). What
  is **not** detected: the *newest* objects withheld from a device before anything it is shown
  refers to them — that device simply stays on the older state, and two devices can be kept
  on different states — and a **fresh** device, which trusts the first state it is served.
  The head fingerprint compared between devices is the check for both (what it proves:
  [Adding a device](#adding-a-device)). Deletion is a denial of service: detected, not
  prevented. Creation times cannot shorten the 25-day restore window or the 30-day `gc`
  grace: a removal counts from the later of Google's time and the time the removing device
  sealed into the index.
- **The auth Worker / Cloudflare** sees the OAuth client secret and the refresh and access
  tokens that pass through it, so it has the same reach as Google and no more: ciphertext and
  deletion. It never sees the passphrase, the master key or any file data — **as long as you
  do not use the hosted viewer**, whose page it serves (the hosted-viewer bullet below). It is stateless and
  only lets the Google accounts in `ALLOWED_EMAILS` sign in. The app's Google scope is
  `drive.file`: it can only touch files it created itself, not the rest of your Drive. The
  Worker enforces that: it asks Google for nothing else, and it hands out no token for a grant
  that carries any other scope.
- **On the device** the refresh token and the cached master key sit in plaintext in
  `secrets.json` (mode 0600; gclone refuses to use it if it or its directory is accessible to
  others). Anyone who can read that file as you has the vault. At-rest protection is disk
  encryption. Treat the file like an SSH private key: never copy it to another machine.
  gclone keeps its state directory out of Time Machine backups and marks it for other backup
  tools, and never uploads its configuration or state directory itself, even when you sync
  your whole home. **On a Mac you can move the key out of the plain file**, into a file that
  only that Mac's Secure Enclave can open: `gclone keystore use enclave` —
  [Where a device keeps its key](#where-a-device-keeps-its-key) says what that does and does
  not protect against.
- **Login phishing.** The sign-in is Google's device-code flow, and starting one needs no
  credentials. Someone can therefore start a login of *their own* and try to talk you into
  entering *their* code at `google.com/device`; the allowlist does not help, because the
  account that approves is yours. **Enter only a code that your own terminal shows right
  now** — nobody ever has a reason to send you one. If it happens anyway, the attacker's login
  reaches what every gclone login reaches: ciphertext, which it could trash (restorable for 30
  days) but not read. Remove the app at <https://myaccount.google.com/permissions> and sign
  in again. Details: [`docs/AUTH.md`](docs/AUTH.md). With the hosted viewer set up the stakes
  are higher — a fake page can ask for the passphrase as well — and the rule gains a second
  half: **a web page never shows a code, and the passphrase is filled by the password
  manager, not typed** ([the three habits](#browse-from-any-browser-the-hosted-viewer)).
- **The hosted viewer** moves the decryption into a browser, and the page that does it is
  served by the Worker: whoever controls the Worker, its secrets or the domain can take the
  passphrase from anyone who uses it. That is accepted, optional, and limited by a signed
  release bundle that the deployed *static files* can be compared with — the Worker's own
  script is not part of that signature, and what a hostile host left in a browser outlives
  the redeploy ([After a change of hands](#after-a-change-of-hands-the-hosted-viewer)). In the
  browser the keys exist in memory only, in workers the page cannot read; a script in the page
  reads files while the vault is unlocked — and can keep its tab unlocked for as long as the
  tab lives — but gets no key, and gets the passphrase only if it is there when the
  passphrase is entered; the long-lived Google credential is sealed in a cookie that scripts cannot
  read; file names stay out of the address, the title and the history; vault files are
  served as untrusted content exactly as in `gclone web`. See
  [Browse from any browser](#browse-from-any-browser-the-hosted-viewer) and §1.3 and §7.5 of
  the spec.
- **The browser view** (`gclone web`) serves plaintext, so it is locked down: loopback only,
  every request needs the session that a one-time link hands out (the link never appears on
  a command line, the cookie is not sent to other local servers), foreign `Host` names and
  cross-site requests are refused, vault files are served as untrusted content (nothing from
  the vault runs as a page), and file names stay out of the browser's history. It is
  read-only, and `gclone logout` ends it. See
  [Browse the vault in your browser](#browse-the-vault-in-your-browser) for what it does not
  protect against.

### Where a device keeps its key

A connected device holds two secrets: its Google login (a refresh token) and the vault's
master key. They are one small document, and there are two places for it.

**The plain file** — `secrets.json` in `~/.local/state/gclone`, mode 0600. This is the
default everywhere and the only store on Linux. *What a copy is worth:* everything. Whoever
obtains the file — from a backup, a synced folder, a disk image, another program's bug that
reads files — has the vault key for good (it cannot be changed, see below) and the login
until you revoke it.

**The sealed file (Macs with a Secure Enclave)** — `secrets.sealed`, the same document
encrypted to a key that lives in that Mac's Secure Enclave and cannot leave it. *What a copy
is worth:* nothing, anywhere but on that Mac. gclone opens it without a prompt, in a
terminal, from a LaunchAgent and from cron alike; it needs no Keychain and no signature.

What the sealed file does **not** stop: **a program running as you on that Mac.** Such a
program can ask the Secure Enclave exactly as gclone does — or simply run
`gclone copy : /somewhere`, or `gclone passwd` and read the new keyfile. It is protection for
the file at rest and in copies, not a wall between your programs.

What it costs: **if the Mac is erased, repaired (a new logic board) or restored onto other
hardware, the sealed file is dead, and the passphrase is the only way back for that device**
(`gclone login`, as on a new device). That is why the move checks your passphrase first.

**The trial.** Before you decide, gclone finds out whether the Secure Enclave works wherever
you run gclone. On a Mac it keeps a Secure Enclave key that seals a random test value —
never your secrets — and opens it in every run. `gclone status` shows what it has seen:

```
Key store    plain file secrets.json (0600) — Secure Enclave trial: 2 of 3 days, no restart seen yet
Key store    plain file secrets.json (0600) — Secure Enclave trial complete: `gclone keystore use enclave`
```

"Complete" means it worked on three different days, after a restart, and never failed.
`gclone keystore` shows the details — which sessions were seen (a terminal has "graphic
access", cron has not) and every failure. If gclone runs from a scheduler, run
`gclone keystore check` from that scheduler once: it exits 0 when the Secure Enclave is
usable right there. The trial changes nothing and decides nothing; a Mac whose owner does
nothing stays on the plain file. It also never holds a command up: its step is given two
seconds, and one that does not come back is written down as a failure and not tried again in
that session for a day. A session that cannot make a Secure Enclave key at all — some
schedulers' — is reported as that session (`no Secure Enclave key could be made in session
0x2 … on <date>`), not as a Mac without a Secure Enclave, and the trial starts in the first
session that can; it then keeps that failure on its record, so "complete" waits until you
have looked at it (`gclone keystore`, then `gclone keystore check --new-trial`). If you run
gclone unattended and want none of this: `gclone keystore use file`, or
`GCLONE_KEYSTORE_TRIAL=0` in the scheduler's environment.

**The move** is one command, run by you at a terminal:

```sh
gclone keystore use enclave
```

It proves this device's key against the vault, asks for your passphrase and checks that it
opens the vault's keyfile (not sure of it? `gclone passwd` on this device sets a new one
first), tells you what the trial has and has not seen, seals the secrets, reads them back
through the Secure Enclave, and only then removes `secrets.json`. `--passphrase-file PATH`
and `--yes` make it scriptable.

**The way back** needs no passphrase:

```sh
gclone keystore use file
```

It writes `secrets.json` — byte for byte the file there was — reads it back and then removes
`secrets.sealed`. It also records that you want the plain file: no trial, no hint.

**Older gclone on the same Mac.** gclone 0.4.0 and older know only `secrets.json`. After the
move they say "not signed in" — and **their `gclone logout` does not sign the device out**
(they see nothing to remove; `secrets.sealed` stays). Use the new binary to sign out. If
something on that Mac still starts an older gclone — restic starts whatever `gclone` is first
on its `PATH` — update it first, or stay on the plain file; `keystore use enclave` lists the
other `gclone` binaries it finds. A `gclone web` of an older version that is running stops
when the move happens.

**Scheduling on macOS.** A LaunchAgent of the logged-in user and cron both work with the
sealed file (measured). ssh sessions and LaunchDaemons are expected to, and were not
measured: `gclone keystore check` from there tells. Before the first login after a restart
nothing runs at all with FileVault on (the disk is locked); a Mac without FileVault that
runs gclone before anyone logs in should stay on the plain file. If a sealed device ever
says *"The Secure Enclave cannot be used in this session"*, the key is fine — run gclone
from a session of the logged-in user, and do **not** sign in again. If it says *"the stored
key cannot be used any more"* (it has then tried the key twice, and a new key worked), the
Mac's Secure Enclave no longer has the key: `gclone login` with the passphrase puts it back.
That login never throws the sealed file away before it has the key again: if you get the
passphrase wrong or give up, the file is exactly what it was — and should the Secure Enclave
have recovered meanwhile, the device simply works again, with the new login in `secrets.json`
beside the sealed key (`gclone keystore` says so, and a `gclone login` that completes makes
them one file).

If `gclone status` ever warns about *plain copies of this device's login and key* in the
state folder: a write was interrupted at some point and left a temporary copy behind.
`gclone keystore use enclave` (or `use file`, whichever store you use) removes them; while
they are there, a copy of the state folder is not worthless elsewhere.

**Backups.** Whichever store is in use, gclone keeps its state folder out of backups as far
as it can: on a Mac the folder is excluded from Time Machine (gclone says so once), and on
every system it carries a `CACHEDIR.TAG`, which restic, borg and tar honour when asked to
(`--exclude-caches`; restic also `--exclude-if-present CACHEDIR.TAG`). Linux has no mark
that backup tools honour unasked: add one of those flags, or exclude
`~/.local/state/gclone`. **Backups made before this version still contain `secrets.json`
with the vault key in plain** — delete it from them if they leave your hands; the key cannot
be changed afterwards. A sealed file in a backup is useless elsewhere, and a restored Mac
signs in again with `gclone login` and the passphrase.

### Lost or stolen device

Run `gclone logout --revoke` on any other device (or remove the app at
<https://myaccount.google.com/permissions>). Google can only revoke the login of **all**
devices at once; afterwards run `gclone login` on each device you keep. Whether the vault
stays visible to the app after a revoke and a new sign-in is unverified (day-0 row 3) — keep a
web download of the vault folder first. The thief still holds the master key the device had
cached, and the revoke does not change that: see the next section.

### If a passphrase or a device's key file leaked

**There is no re-keying yet.** A vault has one master key for its whole life. `gclone passwd`
wraps that same key under a new passphrase; nothing is re-encrypted. So:

- Whoever holds **the master key** — a copy of a device's `secrets.json` (a stolen unlocked
  device, malware, a backup of `~/.local/state/gclone` made before gclone kept that folder
  out of backups; a copy of a Mac's `secrets.sealed` is *not* one) — can decrypt every object of the
  vault that they can get hold of, **including everything uploaded later**, for as long as
  the vault exists. Nothing gclone can do takes the key back.
- Whoever holds **a passphrase together with a keyfile it opens** — any keyfile generation,
  also one that was retired since — has the master key. A passphrase alone is worth nothing
  without a keyfile; keyfiles are in the vault folder, so Google holds every version there
  ever was, and so does anyone who downloaded the folder or held a login for it.

What limits the damage is whether that party can also get the **ciphertext**: Google, anyone
with the Google account's login, and whoever controls the auth Worker can; a thief whose
login was revoked cannot fetch anything new (what they already downloaded stays readable).

What to do, most complete first:

1. **The only full remedy: a new vault.** It gets a new key, and what you upload to it is out
   of the old key's reach.
   1. Make sure you have every file in plaintext: `gclone sync :PATH ~/somewhere` (or
      `copy`) for everything that exists only in the vault.
   2. If a device or its login is involved: `gclone logout --revoke` on a device you trust
      (ends the Google login of every device).
   3. On **every** device: `gclone logout --forget`.
   4. On one device: `gclone login --new-vault` and a **new** passphrase (leave the prompt
      empty for a generated one); `gclone login` on the others.
   5. Upload again (`gclone copy` / `sync`).
   6. Delete the old vault folder in drive.google.com, and empty the Drive trash.

   This protects what you upload from now on. **What was in the old vault stays exposed** to
   whoever has the old key and a copy of the old ciphertext — deleting the folder removes it
   from your Drive, not from a copy someone made, and not from Google's own backups.
2. **A passphrase leaked, and you believe nobody had access to the vault folder yet**:
   `gclone passwd --purge-old` with a new passphrase. The old keyfiles are deleted from the
   account — the ones in the vault folder and **every** keyfile in the Drive trash, also one
   you moved there by hand — so the leaked passphrase opens nothing that can still be fetched
   there. The command lists the folder and its trash again afterwards and says "gone" only
   if that is what it sees. It is worthless against anyone who already copied a keyfile — and against Google,
   which may keep deleted files in its backups. If in doubt, take remedy 1.
3. **Only a device's Google login leaked** (a phished code, a token) and not its key: remove
   the app at <https://myaccount.google.com/permissions> or `gclone logout --revoke`, then
   `gclone login` on each device. The login reached ciphertext and the keyfile, not the key —
   it is as good as your passphrase is strong.

### After a change of hands (the hosted viewer)

If someone else may have served your viewer's address — your Cloudflare account or its deploy
token was in other hands, the domain's DNS was changed, the Worker was replaced — then for
that time they could serve a page of their own: one that takes the passphrase. Taking the
host back is not the end of it, because **a browser that opened the viewer in that time can
keep their page**: a page can install a Service Worker that answers the viewer's address from
inside the browser from then on, without asking the host. It survives your redeploy, a
browser restart and an ordinary reload, and it shows their page under the real address.
`verify-deployed` asks the host, not your browsers, and reports everything in order.

1. **Take the host back and rotate**: the Cloudflare credentials, both Google client secrets,
   `SEAL_KEY`. Deploy the release again from a clean checkout of the tag
   ([`worker/README.md`](worker/README.md), "Deploying the viewer"), then run
   `node scripts/verify-deployed.mjs https://<host> <tag>`.
2. **In every browser that had the viewer open in that time — every phone, laptop and
   browser profile — clear the site's data before you type the passphrase there again.**
   It is under the browser's settings for the site ("site data", "cookies and site data",
   "website data"); the menu paths are in [`docs/AUTH.md`](docs/AUTH.md), "If something is
   lost or stolen". Then close every tab of the viewer and open it from your bookmark.
   If you are not sure which browsers that was: all of them.
3. **If the passphrase was typed into the viewer in that time**, whoever served the page has
   it — and with the access the page had, the vault's key:
   [the section above](#if-a-passphrase-or-a-devices-key-file-leaked) applies.

Two things help without being a substitute for step 2. The Worker answers a browser that asks
for the script of any Service Worker but the viewer's own with `Clear-Site-Data`, which makes
Chrome drop such a worker the next time it checks it for an update — after a visit that
still showed the other page (browsers built on Chrome should do the same; only Chrome was
tested); Firefox ignores that header on this
request, Safari's engine kept the worker when we tested it, and a worker whose script was
placed among the viewer's static files is never asked of the Worker. And the viewer's page
removes Service Workers that are not its own whenever it loads — which a foreign worker for
the whole address is there to prevent.

A lost phone or laptop that was only **signed in to the hosted viewer** holds no key — the
viewer stores none, and it locks by the clock. What it holds is a session: ciphertext and the
keyfile, until the session's end. Put a new `SEAL_KEY` on the Worker to end every browser
session at once. If that browser's password manager had the passphrase saved and the device
can be unlocked, treat it like the stolen device above.

## Limitations

- **Never run against the real services** (see Status). The Drive wire format, quota
  behaviour, OAuth details and the Worker's Cloudflare configuration are implemented from
  documentation and verified only against fakes.
- Tested on macOS and, in containers, on Linux; no Windows (WSL2 runs the Linux binary — keep
  the synced directories inside the Linux file system, not under `/mnt/c`); no FUSE mount; no
  shared drives; no sharing between users.
- **The sealed key store** ([Where a device keeps its key](#where-a-device-keeps-its-key)) is
  for Macs with a Secure Enclave; Linux keeps the plain 0600 file (no desktop keyring is used:
  on a headless machine there is none to rely on after a reboot). It protects copies of the
  file, not against programs running as you. Not measured yet: a sealed file across a
  restart or a macOS update, ssh sessions, daemons, a locked screen — the trial and
  `gclone keystore check` exist to find out on your Mac before you depend on it. Nothing is
  ever moved there automatically, so a Mac whose owner never runs `gclone keystore use enclave`
  stays on the plain file. The access token cache (`token.json`, valid for about an hour)
  stays a plain file. There is still no way to change the vault key: a `secrets.json` that
  was copied or backed up in the past stays a key to the vault.
- `gclone web` is a viewer, not a file manager: read-only, no thumbnails, no list of deleted
  files (`gclone restore --list` has it), and what the browser cannot show (HEIC outside
  Safari, most video containers) is a download. A folder cannot be bookmarked or opened in a
  second tab (the address is always the same, on purpose). Its page is tested in Chrome,
  WebKit and Firefox on macOS; on Linux, a browser installed as a snap or flatpak may not be able to read the file
  gclone hands it — press Enter (or use `--no-browser`) and paste the link.
- The hosted viewer has limits of its own — vault size, memory on a phone, downloads that
  need the tab, no rollback detection between visits:
  [Browse from any browser](#browse-from-any-browser-the-hosted-viewer).
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
- No re-keying: the master key cannot be rotated. A leaked passphrase + keyfile copy, or the
  key file of a stolen unlocked device, stays good for as long as the vault exists — for the
  data that was there, and for everything uploaded afterwards that the holder can still
  fetch (Google, the holder of the Google account, whoever controls the auth Worker). The
  only full remedy is a new vault
  ([If a passphrase or a device's key file leaked](#if-a-passphrase-or-a-devices-key-file-leaked)).
  No per-device revocation either (Google revokes all devices' logins or none).
- File sizes and the number of files are not hidden — not for small files either
  ([Security model](#security-model-in-brief)).
- A new device looks at no more than 32 objects with keyfile names (1024 with
  `gclone login --all-keyfiles`). Someone who can write to the vault folder can plant more
  than that and lock new devices out until `gclone passwd` runs on a connected device or
  the planted objects are removed in drive.google.com. That is a denial of service; it
  discloses nothing.
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
- **`gclone serve restic` rests on two assumptions about Drive's listings** that are not
  verified against the real service: once a listing has shown a file, later listings show it
  too until it is trashed; and once a listing made after a file was trashed has left it out,
  later listings leave it out too. gclone waits for the listing in both directions before it
  tells restic "stored" or "deleted", so nothing depends on timing. If Drive broke the first,
  two machines could both get conflicting locks, or a `prune` could miss a snapshot — restic
  has that exposure on every eventually consistent store. If it broke the second, a `backup`
  on another machine could deduplicate against packs a `prune` just removed; `restic check`
  finds it, and the packs are in the Drive trash for 30 days. Also unverified for restic: that
  a trashed file still downloads by ID (if not, a file another machine deleted answers "not
  found" one listing earlier), that an upload into a trashed folder is reported as trashed,
  that two logins of one account see each other's files (checklist row 2 — "several
  machines, one repository" depends on it), and how Drive signals the daily upload limit.
- restic's traffic is not counted in gclone's daily-upload warning (700 GiB), and restic's
  files are not covered by `gclone check`, `gc` or the viewers: `restic check` is their check.
- In `--port` mode restic gives up on a request that moves no byte for five minutes; on a very
  slow uplink that can hit the end of a large pack (the last 32 MiB go to Drive after restic
  has sent them). The `--stdio` form has no such timer. The listener's token protects the
  data, not the listener's availability against other local users (see there).
- `--json` exists for `copy` / `sync` only; every other command refuses it (exit code 2).
- `restore -r` brings back files, not empty directories, and takes the newest removed version
  of each deleted file — a directory cannot be restored "as of" an earlier day.
- `ls` and `tree` print names as they are, control characters included.

## Local files

| What | Where | Mode |
|---|---|---|
| `config.json` — which vault, the auth Worker URL (no secrets) | `$GCLONE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/gclone`, else `~/.config/gclone` | 0600 |
| `secrets.json` — this device's refresh token and the cached master key | `$GCLONE_STATE_DIR`, else `$XDG_STATE_HOME/gclone`, else `~/.local/state/gclone` | 0600 |
| `secrets.sealed` — the same, sealed by the Mac's Secure Enclave, **instead of** `secrets.json` after `gclone keystore use enclave` | same directory | 0600 |
| `keystore.json` — which of the two you chose with `gclone keystore use` (no secret) | same directory | 0600 |
| `keystore-trial.json` — macOS: the Secure Enclave trial's own key, test value and record (no secret of the vault) | same directory | 0600 |
| `keystore-trial.lock` — macOS: an empty lock file for changes of that record; `backup-note.due` — an empty marker while the one-time note about older backups is still owed to a terminal | same directory | 0600 |
| `secrets.lock`, `CACHEDIR.TAG` — a lock file; the mark that keeps the folder out of backups | same directory | 0600 |
| `token.json` — cached access token | same directory | 0600 |
| `state.db`, `lock`, `index-cache/` — the index replica and sync state | `<state root>/<vault id>/` | 0600 / 0700 |

`gclone serve restic` reads the secrets (`secrets.json` or `secrets.sealed`) and `token.json`,
writes only `token.json` — and, on a Mac that is still on the plain file, the trial's record —
and uses neither `config.json` nor a vault's state: it takes no lock, and runs beside any other
gclone command.

`gclone logout` deletes `secrets.json`, `secrets.sealed` and `token.json` (and temp copies of
them that an interrupted write may have left in that directory); `gclone logout --forget` also
deletes `config.json` and the vault's state directory. `keystore.json`, `keystore-trial.json`,
`secrets.lock` and `CACHEDIR.TAG` stay: none of them holds a secret. The state folder is left
out of Time Machine backups (macOS) and marked with `CACHEDIR.TAG`
([Where a device keeps its key](#where-a-device-keeps-its-key)). `state.db` contains plaintext paths and hashes
and is as sensitive as the synced files themselves.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error — also a remote path that does not exist |
| 2 | usage error |
| 3 | integrity: crypto failure, index gap or rollback, vault trashed or missing, the vault needs a newer gclone, `check` found damage |
| 4 | fixed by `gclone login`: not connected, signed out, wrong passphrase, expired login, Worker problems — and a sealed key store that cannot be opened (the message says whether `gclone login` is the fix or the session is) |
| 5 | a safety guard refused; the message names the flag that answers it (`--yes`, a higher `--max-delete`, `--force`, `--keep-pair` / `--reset-pair`) |
| 6 | partial: some files were skipped or failed |
| 75 | temporary failure: quota or rate limit, index changes could not be published yet |
| 130 | interrupted |

`gclone serve restic` reports what goes wrong while it serves to restic, as HTTP statuses, and
has exit codes only for its start and end:

| Code | `serve restic` |
|---|---|
| 0 | `--stdio`: restic closed the connection; `--port`: Ctrl-C, SIGTERM or SIGHUP |
| 1 | `--port`: the port is in use, on 127.0.0.1 or on [::1]; `--stdio`: the connection to restic broke in a way that is not "closed" |
| 2 | usage: a bad repository name, `--stdio` on a terminal |
| 4 | not signed in, an unsafe `secrets.json`, or a sealed key store that does not open; `--port`: the device was signed out while it ran |
| 130 | `--port` only: a second Ctrl-C |

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
| ☐ | 4 | A second OAuth client in the same Cloud project sees the files the first one created — the hosted viewer's "Web application" client after a vault was created through the device client (the viewer finds the vault), and the device client after a vault was created through the "Web application" client of 0.1.0 (`gclone login` on such a device: "Signed in again … Vault unchanged."). | The hosted viewer cannot be used with that vault. For a login from before 0.2.0: `gclone login` reports it and changes nothing; the vault is moved while a Worker older than 0.4.0 is still deployed (`worker/README.md`, "Moving from the browser sign-in"). The "Worker cannot authenticate" recovery must use a web download. |
| ☐ | 5 | The first real `gclone login` succeeds: Google's device-code endpoint accepts the client with `openid email drive.file` (verified 2026-11-12), and the token answer after the consent carries an **ID token** with the verified e-mail address and a refresh token, with a `scope` that holds nothing but `openid`, `email` / `…/auth/userinfo.email` and `…/auth/drive.file`. | No ID token → every login ends right after the approval with "Sign-in was not completed (Google approved the sign-in, but its answer carried no ID token …)" — the Worker's `403 grant_unusable`; it fails closed, because it cannot apply the allowlist. The Worker then has to ask Google's userinfo endpoint instead. Login refused with `scope_not_allowed` naming a harmless scope → Google spells a granted scope differently; add it to `ALLOWED_SCOPES` in `worker/src/google.ts`. |
| ☐ | 7 | Sustained create rate; does session initiation count against it? | Tune the pack size and the pacer's start rate. |
| ☐ | 11 | A trashed file is still downloadable by ID. | Affects self-heal wording only. For `serve restic`: a file that another machine deleted answers "not found" one listing earlier — nothing breaks. |
| ☐ | 14 | `gclone passwd`, then `gclone passwd --purge-old`: the second run reports "1 in the Drive trash", and the keyfile the first run trashed is gone from the trash in drive.google.com. | Google does not list an app's trashed files to it: `--purge-old` then deletes the keyfiles that are still in the folder only — empty the Drive trash by hand after a `passwd`. |

`gclone serve restic` adds nothing to the table but leans on rows 2, 7, 8 and 11: its first
real run — `restic init`, a backup from two machines, `restic check --read-data`, a
`forget --prune` — is the check (see [Limitations](#limitations) for what is assumed).

The first real `gclone login` on two devices answers rows 1, 2 and 5. Repeat the checklist
after any Google policy change. The hosted viewer has a checklist of its own for its first
deployment, and a fifteen-minute test for the phone:
[`worker/README.md`](worker/README.md#first-deployment-what-to-check).

## Development

```sh
cargo test --locked                  # everything; no network, no credentials (restic on PATH: see below)
cargo clippy --locked --all-targets
cargo fmt --check
cd worker && npm ci && npm run typecheck && npm test
sh tests/install/test.sh             # install.sh against a fake release and a fake GitHub (python3, curl; on a Mac
                                     # also the signed build: codesign and cc)
bash tests/release/selftest.sh       # macOS: scripts/release-sign-macos.sh against a fake release and a fake gh
                                     # (needs target/release/gclone; runs inside or outside a nix shell —
                                     # the script takes the system's tar, file and codesign either way)

# the hosted viewer (needs the wasm target and wasm-bindgen: web-core/README.md)
sh web-core/build.sh                 # the read path as WebAssembly → web-core/pkg/
sh web-core/test/run.sh              # … against vaults written by the native binary (cargo build --release first)
cd worker && npm run viewer:build && npm run smoke && npm run test:viewer
cd worker && npm run test:browser    # Chrome, WebKit, Firefox (worker/viewer/README.md)
```

`.github/workflows/ci.yml` runs all of it on every push to `main` and on pull requests, the
Rust part on Linux and on macOS, with the Rust version pinned in `rust-toolchain.toml` (clippy
runs with `-D warnings`: bump the version deliberately). The browser suite runs on macOS only
(Playwright's WebKit there is the one whose media stack matches Safari), with the installed
Google Chrome, on the bundle that the Linux job built. The workflows pin every action to a
commit; `.github/dependabot.yml` proposes the updates — of the actions, of both Cargo
lockfiles and of the Worker's npm toolchain, a version only once it is two weeks old.
`.github/workflows/audit.yml` runs `cargo audit` over both lockfiles every week and on every
push to `main`; a red run there is about a dependency, not about your change, and an advisory
for a TLS crate or for the encryption path means: update, release, reinstall, redeploy.

(With nix: `nix-shell -p cargo rustc clippy rustfmt restic --run '…'` and
`nix-shell -p nodejs --run '…'`; for the wasm build
`nix-shell -p cargo rustc lld wasm-bindgen-cli nodejs --run 'sh web-core/build.sh'` — a
development build: nixpkgs' compiler is not the pinned one, and the bundle's manifest says
so.)

- `Cargo.lock` is committed; build with `--locked`. Dependencies are compiled with
  `opt-level = 3` in dev and test builds too: the keyfile KDF is Argon2id at 256 MiB.
- The key store ([Where a device keeps its key](#where-a-device-keeps-its-key)): a debug build
  uses no Secure Enclave and runs no trial; the tests select a stand-in with
  `GCLONE_TEST_KEYSTORE_SEALER=fake`. On a Mac with a Secure Enclave, `cargo test` also runs two
  tests against the real one (names starting with `hardware_`; they make keys that are stored
  nowhere); elsewhere those print `SKIPPED: no Secure Enclave on this machine` and pass.
  `GCLONE_REQUIRE_ENCLAVE=1` turns that skip into a failure — set it on the Mac that signs
  releases. `GCLONE_TEST_OLD_GCLONE=/path/to/gclone-0.4.0 cargo test --test keystore` also runs
  the released 0.4.0 binary beside the new files.
- Property tests use a seeded PRNG (`tests/support/prng.rs`). A failing case prints its seed;
  re-run it with `GCLONE_TEST_SEED=<seed> cargo test …`.
- `tests/cli_e2e.rs` spawns the debug binary, over directory vaults and against a fake Google
  Drive + auth Worker (`tests/support/fake_drive.rs`). The `GCLONE_TEST_*` switches it uses
  (fast KDF, Drive and revoke endpoints) are honoured only by builds with debug assertions; a
  release build ignores them.
- `tests/restic_e2e.rs` runs the real restic (0.17 or later: `restic` on `PATH`, or the
  binary named by `GCLONE_TEST_RESTIC`) against the fake Google Drive, through the debug
  binary. Without restic those tests are skipped, each with a line `note: restic 0.17 or later
  is not installed — skipped: <test>`; with `GCLONE_REQUIRE_RESTIC=1` a missing restic is a
  failure. CI sets it and installs a pinned restic (`.github/scripts/install-restic.sh`,
  usable locally too). The release workflow runs the tests without restic.
- Opt-in live run against the real service (needs a device signed in with `gclone login`; it
  works inside one throwaway top-level folder `gclone-live-test-<hex>`, which it trashes at
  the end — the vault itself is not touched):
  `GCLONE_LIVE=1 cargo test --test live -- --ignored --test-threads 1`.
  `GCLONE_LIVE=mem` rehearses the same code against an in-memory backend (no network).
- The Worker's tests need no account, no secrets and no network; see `worker/README.md`,
  "Development".
- `web-core/` is a crate of its own (own workspace, own lockfile) that compiles the main
  crate's source files a second time, for `wasm32-unknown-unknown`. The CLI's `Cargo.toml`,
  `Cargo.lock` and release build do not know it. After a version bump or a dependency change
  in the root, regenerate `web-core/Cargo.lock` (`cargo check` in `web-core/`);
  `web-core/build.sh` fails when the two lockfiles disagree.
- The viewer's browser tests use `playwright-core`, pinned in `worker/test/e2e/package.json`
  — kept out of `worker/package.json`, which is the Worker's deploy toolchain.

### Repository layout

```
Cargo.toml, Cargo.lock      manifest and committed lock file
build.rs                    hands the target triple to `gclone --version`
install.sh                  installer of the released binaries (tests: tests/install/)
scripts/release-sign-macos.sh   the maintainer's release day: verify the draft release, sign the macOS build,
                            publish (self-test: tests/release/, against a fake release and a fake gh)
rust-toolchain.toml         the Rust version of CI and of the release binaries (for rustup)
.github/workflows/          ci.yml (fmt, clippy, tests, Worker, install.sh, the wasm core, the viewer and its
                            browser suite), release.yml (attested binaries and the attested viewer bundle in a
                            DRAFT release on a tag), audit.yml (cargo audit on both lockfiles: weekly and on
                            every push)
.github/scripts/            install-wasm-bindgen.sh: the command in the lockfile's version;
                            install-restic.sh: a pinned, checksummed restic for the tests
.github/dependabot.yml      proposes updates: the pinned actions, both Cargo lockfiles, the Worker's npm toolchain
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
src/web/                    `gclone web`: the loopback HTTP server, and its page in assets/ (no build step);
                            rules.rs: what both viewers answer identically (order, search, JSON shapes, ranges)
src/restic/                 `gclone serve restic`: restic's REST protocol in front of Drive — the wire grammar,
                            the folder tree, the store (cache, listings, uploads, deletes), HTTP, stdio
web-core/                   the read path for the hosted viewer: a crate of its own that includes src/ files by
                            path and builds to WebAssembly (build.sh → pkg/); tests against the native binary
src/config.rs, src/cli/     local configuration; one file per command (serve.rs: `serve restic`)
src/keystore/               where a device keeps its secrets: the plain file or the Secure Enclave store, the
                            moves between them, the trial, the backup exclusion (macos.rs: the framework calls)
tests/                      integration tests; cli_e2e.rs, web.rs and keystore.rs drive the binary, live.rs is
                            opt-in;
                            restic_http.rs (the protocol, in process) and restic_e2e.rs (the binary, and the
                            real restic against the fake Drive)
tests/vectors/              frozen known-answer vectors: the stream container and the formats (stream_v1.json),
                            keyfiles sealed by gclone 0.4.0 (passphrase_v0_4_0.json)
tests/support/              seeded PRNG for property tests, the fake Google Drive + auth Worker, an HTTP/2
                            test client
worker/                     the auth Worker (TypeScript); see worker/README.md
worker/viewer/              the hosted viewer's browser app (plain scripts) and build.mjs → worker/dist/
worker/scripts/             check-config, check-dist, the release tooling (release-bundle, fetch-viewer,
                            check-release, verify-deployed), smoke
worker/test/e2e/            the viewer in three browsers: fake Drive, fixture vault, media fixtures
```

## Licence and warranty

MIT, see [`LICENSE`](LICENSE). gclone is provided "as is", without warranty of any kind: use it at
your own risk and keep an independent backup of anything you cannot afford to lose.
