# Developing gclone

Building, testing and releasing. What gclone does and how it is used is in
[README.md](README.md) and [docs/USAGE.md](docs/USAGE.md); the design contract is the
implementation spec, [docs/SPEC.md](docs/SPEC.md) (errata in §17), and section numbers such
as "§2.9" refer to it. The auth Worker, the hosted viewer's browser app and its WebAssembly
core have notes of their own: [worker/README.md](worker/README.md#development),
[worker/viewer/README.md](worker/viewer/README.md), [web-core/README.md](web-core/README.md).

- [Building](#building)
- [Tests](#tests)
- [CI](#ci)
- [Screenshots](#screenshots)
- [Publishing a release](#publishing-a-release)
- [Repository layout](#repository-layout)

## Building

Unix only (macOS — Apple silicon and Intel — and Linux). Rust edition 2024, MSRV 1.89, and a C
compiler (bundled SQLite and the TLS crypto provider). With rustup, `rust-toolchain.toml` selects the compiler that CI and
the releases use; a Rust from the system's packages or from nix ignores that file.

```sh
cargo build --release --locked
mkdir -p ~/.local/bin && install -m 755 target/release/gclone ~/.local/bin/      # or anywhere on your PATH
```

Optional: bake your auth URL into your own binary so that no device ever needs it typed. Use
the URL your devices will keep using — with a [custom domain](docs/SETUP.md#one-time-setup)
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

## Tests

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

(With nix: `nix-shell -p cargo rustc clippy rustfmt restic --run '…'` and
`nix-shell -p nodejs --run '…'`; for the wasm build
`nix-shell -p cargo rustc lld wasm-bindgen-cli nodejs --run 'sh web-core/build.sh'` — a
development build: nixpkgs' compiler is not the pinned one, and the bundle's manifest says
so.)

- `Cargo.lock` is committed; build with `--locked`. Dependencies are compiled with
  `opt-level = 3` in dev and test builds too: the keyfile KDF is Argon2id at 256 MiB.
- The key store ([Where a device keeps its key](docs/SECURITY.md#where-a-device-keeps-its-key)): a debug build
  uses no Secure Enclave, seals nothing and runs no trial; the tests select a stand-in with
  `GCLONE_TEST_KEYSTORE_SEALER=fake`. On a Mac with a Secure Enclave, `cargo test` also runs
  three tests against the real one (names starting with `hardware_`; they make keys that are
  stored nowhere); elsewhere those print `SKIPPED: no Secure Enclave on this machine` and pass.
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
- The time machine of the viewers (SPEC §7.4) is one pure file, `src/web/past.rs`, compiled
  into both crates like `rules.rs`. It reads no clock and no database: each caller gives it a
  `Source`. There are three: `index::SqlSource` (the SQL replica, `src/index/history.rs`),
  `past::MemSource` (the in-memory index: the hosted core, and the tests), and a plain vector
  in `src/web/past_tests.rs`. Change an answer there and `web-core/tests/parity.rs` compares
  both viewers again, byte for byte.
- A vault with history for a test: the binary has no clock to set, so history is made by real
  runs a little over a second apart, and the moments to ask about are taken from what the API
  reports. `tests/web.rs` has `vault_with_history()`; the browser suites use `addHistory()` of
  `worker/test/e2e/vault.mjs`, which also records `gclone tree` after each run — what the
  viewers' answers for those moments are compared with, folders included.
  `worker/test/e2e/timemachine.mjs` holds the checks that both viewers get: `run.mjs` runs
  them as its step `timemachine` (`GCLONE_E2E_ONLY=timemachine` for that step alone),
  `local.mjs` after its own. `shots.mjs <dir> chrome time` shoots only the time machine.
- The hosted core has a size limit (`WASM_MAX` in `web-core/test/check-module.mjs`), and
  `build.sh` fails above it. Generic code that is instantiated once more per type — a sort, a
  map — is what grows it: see `rules::listing_order` and `past::order_by` before adding one.

## CI

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

## Screenshots

The pictures of the README (and one in `docs/USAGE.md`) are in `docs/images/`, each as
`-light.png` and `-dark.png` for a `<picture>` element. Three scripts in
`worker/test/e2e/readme/` make them from an invented demo vault, so that no picture shows a
real file, name or account:

- `content.mjs <dir>` writes the demo tree: photos and two films drawn procedurally and
  encoded with ffmpeg, PDFs, a ZIP, Markdown, CSV and SVG files, with set modification
  times. It takes about 80 seconds.
- `viewer.mjs <out> [<content dir>]` builds a vault from that tree with the native binary,
  serves it through the browser suite's fake Drive and fake Worker routes, and shoots
  `viewer-*.png` in the installed Google Chrome.
- `timemachine.mjs <out>` makes a vault from the demo's documents (no ffmpeg), gives it some
  history — edits, a deleted file, a deleted folder, a move — and shoots
  `viewer-timemachine-*.png`: the vault before those changes. The binary has no clock to
  set, so the changes in that picture are a minute old.
- `terminal.mjs <out> [<content dir>]` runs gclone in a temporary lab with two devices
  (`laptop`, `desktop`) over a directory vault, prints each scene's text and renders
  `terminal-*.png` with the same Chrome. The text is what the binary printed, with three
  changes: the lab's path prefix is stripped, lines over 100 columns are wrapped at a
  space, and the `Key store` line of `gclone status` is left out (the lab keeps the plain
  file on purpose, which says nothing about a reader's machine).

From the repository root (`$T` is any scratch directory):

```sh
# the native binary and the viewer's wasm core
nix-shell -p cargo rustc --run 'cargo build --release --locked'
nix-shell -p cargo rustc lld wasm-bindgen-cli_0_2_130 nodejs --run 'sh web-core/build.sh'   # -> web-core/pkg
# the Playwright driver (the browser is the installed Google Chrome; nothing is downloaded)
(cd worker/test/e2e && npm ci --ignore-scripts)
export GCLONE_PLAYWRIGHT_CORE=$PWD/worker/test/e2e/node_modules/playwright-core
# content, viewer shots, terminal pictures
nix-shell -p ffmpeg nodejs --run "node worker/test/e2e/readme/content.mjs $T/demo"
node worker/test/e2e/readme/viewer.mjs   docs/images $T/demo
node worker/test/e2e/readme/timemachine.mjs docs/images
node worker/test/e2e/readme/terminal.mjs docs/images $T/demo
# optimise
(cd docs/images && nix-shell -p pngquant oxipng --run \
  'pngquant --force --ext .png --quality 70-95 --speed 1 --strip *.png && oxipng -o 4 --strip safe *.png')
```

- The wasm-bindgen attribute has to match the version in `web-core/Cargo.lock` (0.2.130
  today).
- `GCLONE_BIN` and `GCLONE_WEB_CORE_PKG` name a binary and a wasm package elsewhere, instead
  of `target/release/gclone` and `web-core/pkg`.
- Every gclone run of the scripts has a temporary home and `GCLONE_KEYSTORE_TRIAL=0`: they
  touch no real login, no vault of yours and no Secure Enclave.
- The date field in the time machine's bar is the browser's own control. The scripts start
  Chrome with `--lang=en-GB`, which sets its format on Linux; on a Mac Chrome takes it from
  the system's region, so there the field is written the way that region writes dates.
- The image and video previews are shot at 1.375x (1760 pixels wide, twice the README's
  880), the rest at 2x; the dates in the terminal pictures are the day of the run.
- Look at every picture before committing it. The repository is public: no real name,
  address, path or file name belongs in one.

## Publishing a release

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
scripts/release-sign-macos.sh v0.6.1
```

It verifies every file of the draft against its attestation and `SHA256SUMS`, signs a copy of
the attested macOS binary with the Developer ID identity of that Mac (hardened runtime, no
entitlements), proves that the signed binary is the attested one apart from the signature,
runs it — in a temporary home: a login to a directory vault, which has to seal its secrets
with that Mac's Secure Enclave as every Mac's first login does since 0.5.1, then a copy and
a read from the sealed store, and `gclone keystore check` —, adds
`gclone-aarch64-apple-darwin-signed.tar.gz` and its line in `SHA256SUMS`,
downloads the whole draft again and checks it once more, and publishes after you type
`publish v0.6.1`. Then it verifies the published release (`gh release verify`,
`gh release verify-asset`, `install.sh --require-attestation`). It refuses to go on as soon as
anything does not verify, and until it publishes it can simply be run again — also after an
upload that was cut off (the draft may then be without `SHA256SUMS` or without the signed
archive; the script makes both again from the attested archives).

After publishing nothing can be changed, so the last step tells two things apart. *"THE
PUBLISHED RELEASE COULD NOT BE VERIFIED YET"*: a question to GitHub was not answered (a
network error, a rate limit, an attestation that is not served yet). That is not a verdict;
run

```sh
scripts/release-sign-macos.sh --verify-published v0.6.1
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
git push origin v0.6.1                 # the tag ALONE: it carries the commit and starts release.yml
#   … wait for the workflow: a draft release
scripts/release-sign-macos.sh v0.6.1   # verify, sign, publish
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

## Repository layout

```
README.md                   what gclone is, install, quick start
DEVELOPMENT.md              this file
docs/USAGE.md               every command, the viewers, restic, local files, exit codes, limitations
docs/SETUP.md               the one-time setup, adding a device, the day-0 checklist
docs/SECURITY.md            the security model, the device key store, what to do after a loss or a leak
docs/AUTH.md                how login and token refresh work, with diagrams
docs/SPEC.md                the implementation spec (design contract, errata in §17)
docs/images/                the README's screenshots (made by worker/test/e2e/readme/)
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
                            rules.rs: what both viewers answer identically (order, search, JSON shapes, ranges);
                            past.rs: the vault as it was (versions, deleted entries, a view at a moment)
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
worker/test/e2e/readme/     the README's screenshots: demo content, viewer shots, terminal pictures
```
