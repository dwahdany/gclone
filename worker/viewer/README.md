# The hosted viewer's browser app

The files in this directory are the part of the read-only web viewer that runs in the browser
at `https://<worker-domain>/`. The Worker (`../src/`) serves the page and signs in; everything
here is static. Files are decrypted in the browser by the core (`../../web-core/`, the CLI's
read path compiled to WebAssembly).

No bundler, no transpiler, no npm package, no network resource: every `.js` file is a classic
script that attaches to `self.gclone`.

| File | Runs in | Job |
|---|---|---|
| `index.html` | — | The page: the sign-in, unlock, progress and signed-out screens as static markup, the status marker, and `<template id="app">`, which the build fills with the body of `gclone web`'s page. |
| `shell.js`, `shell.css`, `noscript.css` | page | Sign-in, Service Worker start, vault discovery, unlock, index load, Lock (wall clock; a lock is a reload; the Lock button and Sign out reach every tab of the viewer over a `BroadcastChannel`), sign-out. |
| `provider.js` | page | The page's Trusted Types policy, the vault worker's client, the ticket channel and `window.gcloneProvider` — the seam of `src/web/assets/app.js`. The hosted provider shows no PDF in a frame of the page (`pdfInline: false`: a tab of its own) and offers no "Open in a new tab" for audio and video. |
| `token.js` | page, vault worker, Service Worker | Access tokens from `POST /web/refresh`: kept in memory, single flight. |
| `drive.js` | vault worker, Service Worker | Google Drive, read-only: `files.list`, `files.get`, content with `Range`; the CLI's retry rules, with a patience the caller sets (the index load: the CLI's schedule; a read someone is looking at: ten seconds). The Drive host is named here once. |
| `loader.js` | vault worker | Finding the vault, the keyfile candidates (what is no keyfile takes no place among them), loading and refreshing the index, with bounds on what a listing can make the tab download — a refresh never more than 64 MiB — and on what of a listing is shown (no name that is not of gclone's form). |
| `vault-worker.js` | vault worker | Holds the keyring and the index; answers the five API calls; issues tickets to the Service Worker. |
| `kdf-worker.js` | KDF worker | Argon2id and the keyfile candidate loop; hands the key bundle to the vault worker; is terminated. |
| `sw.js` | Service Worker (`/sw.js`) | `GET /v/<id>`: decrypted bytes with `Range`, from tickets; the store is read one window of 16 MiB at a time and the core fed a mebibyte per call, so its memory does not depend on the engine or the line. The build stamps the build id in. |
| `build.mjs` | Node | Writes the bundle (`../dist/`). |
| `bench/` | — | The device test of the unlock (not part of the bundle). |

`app.js`, `app.css` and `icon.svg` are not here: the build copies them byte for byte from
`src/web/assets/`, where `gclone web` embeds the same files.

## Build

```sh
sh web-core/build.sh                 # web-core/pkg/{core.js,core.wasm,build.json}
node worker/viewer/build.mjs         # worker/dist/   (--out <dir>, --pkg <dir>)
node worker/scripts/check-dist.mjs   # the rules of a dist/ that may be deployed
```

(`npm run viewer:build` in `worker/` runs the three.) This is a development build. The bundle that is
deployed is the one the release workflow builds on a tag and signs —
`gclone-viewer-<version>.tar.gz`, fetched and verified by `worker/scripts/fetch-viewer.mjs`; see
`worker/README.md`, "Deploying the viewer". `GCLONE_VIEWER_TAG` and `GCLONE_VIEWER_COMMIT` set the
manifest's `tag` and `commit` (the release workflow sets both; a local build has no tag, and
`+changes` after the commit when the tree is dirty).

`dist/` then holds `index.html`, `sw.js`, `_headers` and `a/<build>/` with `app.css`, `app.js`,
`core.js`, `core.wasm`, `drive.js`, `icon.svg`, `kdf-worker.js`, `loader.js`, `manifest.json`,
`noscript.css`, `provider.js`, `shell.css`, `shell.js`, `token.js`, `vault-worker.js`. The build id
is a hash over all of them; two builds of the same inputs are identical.

## Tests

Node (no browser; needs the native `gclone` binary and `web-core/pkg`):

```sh
cd worker && node --test test/viewer/token.node.mjs test/viewer/drive.node.mjs test/viewer/loader.node.mjs
```

Browsers: the installed Google Chrome (never Playwright's Chromium, which has no H.264 and AAC), and
Playwright's WebKit and Firefox. `playwright-core` is pinned in `worker/test/e2e/package.json` —
deliberately not in `worker/package.json`, which is the Worker's deploy toolchain:

```sh
cd worker/test/e2e && npm ci --ignore-scripts && node node_modules/playwright-core/cli.js install webkit firefox
```

(`GCLONE_PLAYWRIGHT_CORE` names another copy of the package, `PLAYWRIGHT_BROWSERS_PATH` another place
for its browsers.) macOS only: Playwright's Linux WebKit has another media stack than Safari, and the
byte budgets in the tests were measured on the macOS build.

```sh
node worker/test/e2e/run.mjs [chrome] [webkit] [firefox]   # the viewer end to end
node worker/test/e2e/signin.mjs                             # the sign-in through the real Worker code (Chrome)
node worker/test/e2e/local.mjs [chrome] [webkit] [firefox]  # the shared page under `gclone web`
node worker/test/e2e/shots.mjs <dir>                        # screenshots
node worker/test/e2e/serve.mjs [port]                       # the viewer on this machine, to look at
```

`GCLONE_BIN` names the native binary (default `target/release/gclone`); `GCLONE_E2E_BIG` names a
large video made by `test/e2e/fixtures/make-big.sh` and adds the streaming and throughput steps;
`GCLONE_VIEWER_DIST` names a built `dist/` to test as it is (CI and the release workflow test the
bundle they built), instead of a fresh build from this tree.
All of them use a fixture vault written by the native binary into a temporary directory, a fake
Google Drive (`test/e2e/fake-drive.mjs`) and a fake of the Worker's browser routes
(`test/e2e/server.mjs`). The test server serves the bundle as built, with one swap on the way
out: the Drive host, in `connect-src` of the policy and in `drive.js`, is the fake Drive's
origin.

## The device test

`bench/` answers one question on the owner's phone: can it run the unlock (256 MiB of Argon2id)
in the cycles the viewer produces — with a reload between rounds, with a reused worker, and
without reloads.

```sh
FEATURES=bench sh web-core/build.sh . worker/viewer/bench/pkg
node worker/viewer/bench/serve.mjs 8787 <address of this computer on the LAN>
```

Open `http://<that address>:8787/` on the phone and tap "Start". The result is shown on the page
and printed by `serve.mjs`. The step-by-step version, with what each outcome means, is
`worker/README.md`, "The phone test (15 minutes)". `node worker/viewer/bench/check.mjs [chrome]
[webkit] [firefox]` runs the page once in desktop browsers, to see that it still works.
