# gclone auth Worker

A small, stateless Cloudflare Worker that is the **one OAuth client** of your gclone devices. It holds the Google
client ID and secret, so no device ever does. It turns one consent at Google into a refresh token for one device
(`gclone login`) and turns refresh tokens into access tokens afterwards. File data never passes through it: devices
talk to Google Drive directly.

The login of a device is Google's device authorization grant (RFC 8628): `gclone login` shows a code, you enter it
at `https://www.google.com/device` in any browser, and the device — which polls the Worker meanwhile — is signed in.
No redirect leads back to the Worker or to the device.

Optionally the same Worker serves the **hosted viewer**: a read-only web page at `https://<host>/` that signs your
browser in to Google — with a redirect, through a second OAuth client of type "Web application" — and then reads and
decrypts the vault in the browser. For that the Worker serves the page and its static files, and four routes under
`/web/` that keep the browser's Google sign-in in a sealed cookie ([How it works](#how-it-works),
[The viewer's files](#the-viewers-files)). Without the viewer's three secrets and files the Worker is the plain
sign-in helper for `gclone login`, and everything about devices below is unchanged. Setting the viewer up is
[its own section](#the-hosted-viewer-setup); what it means for the vault's security — the page that asks for the
passphrase is served by this Worker — is in [`docs/SECURITY.md`, "The hosted viewer: what you trust"](../docs/SECURITY.md#the-hosted-viewer-what-you-trust).

You set it up **once** — not once per device. Afterwards every device is connected with
`gclone login https://<host>`.

Nothing in this directory is deployed by a test or a build. Deploying is the one-time setup below, done by you.

- [One-time setup](#one-time-setup)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Custom domain and rate-limiting rule (recommended)](#custom-domain-and-rate-limiting-rule-recommended)
- [The hosted viewer: setup](#the-hosted-viewer-setup)
- [Deploying the viewer](#deploying-the-viewer)
- [First deployment: what to check](#first-deployment-what-to-check)
- [The phone test (15 minutes)](#the-phone-test-15-minutes)
- [What is logged](#what-is-logged)
- [Troubleshooting by error code](#troubleshooting-by-error-code)
- [How it works](#how-it-works)
- [The viewer's files](#the-viewers-files)
- [Phishing: codes, and look-alike pages](#phishing-codes-and-look-alike-pages)
- [Moving from the browser sign-in (gclone before 0.2.0)](#moving-from-the-browser-sign-in-gclone-before-020)
- [Development](#development)

## One-time setup

You need a Cloudflare account (the free plan is enough), a Google account, Node 20 or newer, and `curl`.

`./setup.sh` walks through steps 1, 3 and 4 and prints the checklist of step 2 with your URLs filled in. It first
asks where the Worker is to be served: on its `workers.dev` host, or on a host name of your own.

**Decide that before step 1.** The Worker's URL goes into the Google app's branding (home page and privacy links,
authorized domain) and into every device's login. If you want a
[custom domain](#custom-domain-and-rate-limiting-rule-recommended) — recommended, and the only way to put a
rate-limiting rule in front of the Worker — start with it: do step 1 of that section (the `routes` entry in
`wrangler.jsonc`; `node scripts/custom-domain.mjs auth.example.org` writes it) **instead of** the plain deploy
below, and read `https://auth.example.org` wherever the steps say `https://<host>`. Moving later works too, but
means changing the Google configuration a second time and running `gclone login` again on every device, because
the `workers.dev` URL they stored stops answering.

The steps by hand:

### 1. Deploy the Worker

```sh
cd worker
npm install
npx wrangler login
node scripts/stub-dist.mjs      # writes a placeholder ./dist unless a built web viewer is there (see "The viewer's files")
npx wrangler deploy
```

Note the URL it prints, `https://gclone-auth.<acct>.workers.dev`. This is your **auth URL**; `<host>` below is its
host name and `<acct>.workers.dev` its domain. (With a custom domain from the start the auth URL is
`https://auth.example.org`, `<host>` is `auth.example.org`, and the domain for step 2.3 is the **registrable**
domain, `example.org`.) Until step 3 is done the home page says `Status: not configured` and
every other route answers `500 server_misconfigured`. That is expected: the branding of step 2 needs the
Worker's host name, so the Worker has to exist first.

### 2. Google Cloud console

The console's labels change now and then; the items to find are the same.

1. **Project.** Create one at <https://console.cloud.google.com/projectcreate> (any name). Enable the Drive API:
   <https://console.cloud.google.com/apis/library/drive.googleapis.com> → **Enable**.
2. **Google Auth Platform** → **Get started** (<https://console.cloud.google.com/auth/overview>): app name `gclone`,
   your e-mail address as support and as contact address, Audience **External**. Do **not** upload a logo — a logo
   triggers brand verification.
3. **Branding**: Authorized domain `<acct>.workers.dev` (for a host of your own: its registrable domain, e.g.
   `example.org` for `auth.example.org` — Google refuses a subdomain in that field); Application home page
   `https://<host>/`; Privacy policy `https://<host>/privacy`. The Worker serves both pages; Google requires the two links for every external
   production app.
4. **Audience** → **Publish app**. The status must read **In production**. Do **not** click "Submit for
   verification": `openid`, `email` and `drive.file` are non-sensitive scopes and need none.
   If you skip publishing, Google ends every login after 7 days; `gclone login` detects that and tells you.
5. **Clients** → **Create client** → Application type **TVs and Limited Input devices** (any name). There is
   nothing else to fill in: this client type has no redirect URI and no JavaScript origin. Copy the client ID and
   the client secret **now**: the secret is shown only once.

Workspace users may choose Audience **Internal** instead of External + Publish. Console changes can take from five
minutes to a few hours to apply.

### 3. The three secrets

```sh
npx wrangler secret put GOOGLE_CLIENT_ID        # the client ID from step 2.5
npx wrangler secret put GOOGLE_CLIENT_SECRET    # its secret
npx wrangler secret put ALLOWED_EMAILS          # your Google account address; several: comma-separated
```

Each `wrangler secret put` deploys a new version at once; no further `wrangler deploy` is needed.

`ALLOWED_EMAILS` decides who may sign in. Empty or missing means **nobody**. It is a secret and only a secret —
see [Configuration](#configuration) for why it must never become a `vars` entry.

### 4. Check

```sh
curl https://<host>/
```

answers 200 and contains `Status: ready`.

### 5. Recommended: a custom domain

On the `workers.dev` host anyone can use up the plan's daily request quota and thereby stop your logins and token
refreshes until the quota resets. See
[Custom domain and rate-limiting rule](#custom-domain-and-rate-limiting-rule-recommended) — if you started with
your own host name, only its last step (the rule) is left.

### Then, on every device

```sh
gclone login https://<host>
```

The URL is needed once per device; gclone remembers it. The terminal shows where to go and a code:

```
To sign in, open  https://www.google.com/device
and enter the code  ABCD-EFGH
(enter only a code shown in this terminal; waiting…)
```

Open that address in any browser — on this machine, a phone, anything — enter the code, choose your Google account
and approve. The terminal continues by itself within a few seconds. A code is good for 30 minutes; Ctrl-C stops the
login. **Never enter a code that someone sent you** (see [Device-code phishing](#phishing-codes-and-look-alike-pages)).

## Configuration

| Binding | Kind | Value |
|---|---|---|
| `GOOGLE_CLIENT_ID` | secret | the ID of the "TVs and Limited Input devices" client |
| `GOOGLE_CLIENT_SECRET` | secret | its secret — it exists nowhere else |
| `ALLOWED_EMAILS` | secret | comma-separated Google account addresses; empty or not set = nobody. Compared exactly, except for the case of the letters A–Z; an entry with a space inside or a character outside ASCII matches nobody. |
| `GOOGLE_LEGACY_CLIENT_ID`, `GOOGLE_LEGACY_CLIENT_SECRET` | secrets, optional, used only when **both** are set | the ID and secret of the "Web application" client: the hosted viewer's sign-in (`/web/*`), and nothing else. The names date from gclone before 0.2.0, when this client served the browser sign-in of the devices; they were kept so that an existing deployment needs no change. Its Authorized redirect URI in the Google console is exactly `https://<host>/callback`. |
| `SEAL_KEY` | secret, optional | 32 random bytes in base64 (`openssl rand -base64 32 \| npx wrangler secret put SEAL_KEY`): the key that seals the viewer's session cookie. Anything that is not 32 bytes of base64 counts as not set. Putting a **new** value ends every browser session at once and no device login. |
| `RATE_LIMIT` | rate-limit binding in `wrangler.jsonc` | 30 requests per 60 s and client address (an IPv6 client: per /64) |
| `ASSETS` | static-assets binding in `wrangler.jsonc` | the viewer's files in `./dist`, read-only, uploaded with the Worker. The Worker reads `index.html` from it; `/a/*` and `/sw.js` are served by Cloudflare's asset layer without running the Worker. |

The page at `/` says `Status: ready` when the first two are set — the Worker then serves every `gclone login` and
every device. The hosted viewer's sign-in is switched on by the web client's pair **and** `SEAL_KEY` together; while
one of the three is missing (or `SEAL_KEY` is not 32 bytes) the page says `Status: ready. The web viewer is not
configured: it needs GOOGLE_LEGACY_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET and SEAL_KEY.`, the three routes
`/web/start`, `/web/token` and `/web/refresh` answer `500 server_misconfigured`, and nothing else is affected.
(Each `wrangler secret put` / `delete` is deployed at once, so the Worker is in that state for a moment whenever
one of the three is added or removed.)

There is no KV, D1, R2, Durable Object, queue, cron or service binding: the Worker stores nothing. The assets
binding is not storage: its files are part of the deployment and change only with a deploy.

These things in `wrangler.jsonc` are **security requirements**. `scripts/check-config.mjs` asserts them before the
tests on every `npm test`; do not change them. The check is an **allowlist**: the file may hold the keys of the
shipped file — `$schema`, `name`, `main`, `compatibility_date`, `compatibility_flags`, `workers_dev`,
`preview_urls`, `routes`, `observability`, `ratelimits`, `assets` — and nothing else, whatever it is called. In
particular:

- **No other binding of any kind** — no KV, D1, R2, Durable Object, queue, service, AI, browser, e-mail, … — and
  no `unsafe` key, whose `unsafe.bindings` can attach any binding type under another name.
- **No `env`.** A wrangler environment does not inherit bindings: `wrangler deploy --env <name>` would deploy a
  Worker without the rate limiter (and the Worker lets every request through when the binding is missing).
  Deploy with plain `wrangler deploy` only.
- **Plain line feeds.** The check reads the file as JSON plus whole-line `//` comments, a line ending at a line
  feed. wrangler ends a comment at a lone carriage return and at the Unicode separators U+2028 and U+2029 as well,
  so `// note<CR>"kv_namespaces": […]` would be one comment line to the check and a binding to wrangler — and one
  line in most diff views. A file that holds a carriage return without a line feed, or one of the two separators,
  is refused outright. (Windows line ends, CR LF, are fine.)

- **The `assets` entry is fixed, key by key and value by value:**

  ```jsonc
  "assets": { "directory": "./dist", "binding": "ASSETS",
              "run_worker_first": ["/*", "!/a/*", "!/sw.js"],
              "html_handling": "none", "not_found_handling": "none" }
  ```

  The Worker runs first for every path except `/a/*` and `/sw.js`, and it alone decides what a path means: no file
  of `./dist` is reachable under its own name (`/index.html`, `/_headers` and anything else there are the Worker's
  `404`). The asset layer does no routing of its own — no HTML path rewriting, no single-page fallback. The two
  exceptions are what keeps a page load cheap: requests to `/a/*` and `/sw.js` do not run the Worker, so they cost
  no Worker request and do not meet the rate limit. `run_worker_first: true` would be as safe and is refused only
  for that reason; any other value is refused because it would hand files out without the Worker.
- **`main` is `src/entry.ts`**, the module that exports the handler and nothing else (with assets configured,
  wrangler refuses a main module that has other named exports).
- **Nothing of a request is stored beyond the Worker's own log line.** Device codes and tokens travel in POST
  bodies, which are not part of Cloudflare's request logs. One URL does carry a secret: Google's redirect to
  `/callback` has the authorization code of a browser sign-in in its query string — single-use, and worth nothing
  without the verifier that stays in the browser tab. These four settings under `observability` keep it out of
  what Cloudflare stores. They stay as they are:
  - `logs.invocation_logs` is `false`: with invocation logs on, Cloudflare stores one log entry per request with the
    full URL and its headers, kept for days and readable by anyone with log access to the account.
  - `redact_query_string` is `true`: Cloudflare attaches the request that triggered an invocation to **every**
    stored log event — also to the Worker's own one-line logs — and to traces. This switch removes the query string
    from those URLs. It needs wrangler 4.160 or newer (`package.json` requires it); an older wrangler would ignore
    the key.
  - `traces.enabled` is `false`: traces record requests too, and are not needed.
  - no `destinations` under `logs` or `traces`, no `tail_consumers`, no `logpush`: nothing exports logs or traces
    out of the account.
- **`preview_urls` is `false`.** Preview URLs would keep every uploaded version of the Worker reachable under its
  own `<version>-gclone-auth.<acct>.workers.dev` host — also an old version from before a fix, and outside any
  zone rule of a custom domain.
- **There is no `vars` key.** Vars and secrets share one namespace: while a deployed version has a var
  `ALLOWED_EMAILS`, `wrangler secret put ALLOWED_EMAILS` is refused, and every `wrangler deploy` from a file with
  `"vars": { "ALLOWED_EMAILS": "" }` would put the empty list back — every login refused. The allowlist therefore
  is a secret only, and it never sits in a tracked file.
- **The `ratelimits` entry** (`RATE_LIMIT`, 30 / 60 s) is, with `ASSETS`, the only binding, with exactly these values.
  `namespace_id` is any integer, as a string, that is unique within your account; change it if another Worker of
  yours already uses `1001`. Besides bounding what one sender can relay to Google, the limit is what keeps one
  sender from mass-producing sign-in codes (see [Device-code phishing](#phishing-codes-and-look-alike-pages)).

`secrets.required` is deliberately not declared: with it `wrangler deploy` fails while a secret is missing, and the
first deploy has to happen before the Google app's branding can name the Worker's host. The Worker checks its configuration on every request
instead.

## Operating it

- **Rotate the client secret.** Google console → the client → add a secret → `npx wrangler secret put
  GOOGLE_CLIENT_SECRET` → delete the old secret in the console. Devices are not affected.
- **Change the allowlist.** `npx wrangler secret put ALLOWED_EMAILS` with the new comma-separated list. It takes
  effect at once, without `wrangler deploy`. Never add a `vars` entry of that name. Removing an address stops new
  logins for it. Its existing device tokens are cut off at their next refresh **only if** Google returns an ID token
  there, which is not guaranteed — to be sure, revoke: `gclone logout --revoke`, or remove the app at
  <https://myaccount.google.com/permissions>. A browser session of the hosted viewer is cut off at its next refresh
  in every case: the address is inside the sealed cookie.
- **End every browser session of the hosted viewer.** `openssl rand -base64 32 | npx wrangler secret put SEAL_KEY`:
  no cookie sealed under the old key opens any more, and no other route accepts what was inside one. Devices
  (`gclone login`) are not affected.
- **After a suspected leak** of the Worker's secrets: rotate the client secret, run
  `gclone logout --revoke` on one device (this ends the login of every device), then `gclone login` on each device.
- **After a change of hands** — someone else may have deployed to the Worker, or pointed the domain elsewhere,
  while the hosted viewer was in use: deploying the release again is not the end of it. A browser that opened the
  viewer in that time can keep the other party's page (a Service Worker of theirs answers the address from inside
  the browser), and `verify-deployed` cannot see a browser. **Clear the site's data in every browser that had the
  viewer open, before the passphrase is typed there again**: the steps are in `docs/SECURITY.md`, "After a
  change of hands (the hosted viewer)", and `docs/AUTH.md`. What the Worker does about it by itself, and where that
  stops, is under [What the Worker guarantees](#what-the-worker-guarantees).
- **Cost and limits.** A login is one start plus one poll every 5 seconds while you enter the code (a minute at
  Google is about 13 requests); a refresh is 1 per device and hour of use — far inside the free plan's
  100,000 requests per day for your own use. The built-in limit of 30 requests per 60 s and client address (answer
  `429`) limits how much junk one sender can relay to Google through your OAuth client. An IPv6 client is counted
  by its /64 prefix — one host owns at least a whole /64, so a per-address count would not limit it at all. The
  limit is approximate (Cloudflare counts per location) and it does not stop a sender with many networks. It also
  runs inside the Worker: a refused request is still a request. On `*.workers.dev` a flood of about one request per
  second uses up the free plan's daily quota and stops all token refreshes until midnight UTC. The custom domain
  below with a zone rate-limiting rule stops that for any single sender (the rule counts per address, so it bounds
  each sender, not all of them together); the paid plan has no daily cap at all.
- **If the Worker is lost.** Deploy again from this directory and put the three secrets again (a new client secret
  can be added to the same Google client) — with the hosted viewer, its three as well, `SEAL_KEY` as a new value:
  browsers then sign in again, which is all a lost `SEAL_KEY` costs. Devices keep their refresh tokens; nothing else changes as long as the
  host name and the Google client stay the same. With a custom domain the host name comes back by itself only if
  it is in `wrangler.jsonc` (the `routes` entry below); a domain that was attached in the dashboard has to be
  attached again, and until then every device's token refresh fails.
- **Google deletes OAuth clients that were idle for six months** (it sends a warning e-mail 30 days before, and the
  client can be restored for about 30 days). A device that runs gclone now and then keeps the client in use.

## Custom domain and rate-limiting rule (recommended)

Zone-level rate-limiting rules cannot be attached to `*.workers.dev`, so the flood described above can only be
stopped in front of the Worker when it is served from a domain of your own (a zone on the same Cloudflare account):

1. Attach the domain, for example `auth.example.org`, **in `wrangler.jsonc`** and run `npx wrangler deploy`.
   `node scripts/custom-domain.mjs auth.example.org` makes exactly this edit (and `./setup.sh` runs it when you
   answer "a host name of your own"):

   ```jsonc
   "workers_dev": false,
   "preview_urls": false,
   "routes": [{ "pattern": "auth.example.org", "custom_domain": true }],
   ```

   Wrangler creates the DNS record and the certificate. `"workers_dev": false` makes the `workers.dev` host stop
   answering, so the zone rule of step 5 cannot be bypassed; `"preview_urls": false` is already in the shipped file.
   Keeping the domain in the file — rather than adding it in the dashboard (Workers & Pages → `gclone-auth` →
   Settings → Domains & Routes) — means a later deploy, or a redeploy after the Worker was lost, restores it.
   `scripts/check-config.mjs` accepts this change.
2. Google console: under Branding → **Authorized domains** add the **registrable domain** — `example.org` for
   `auth.example.org`; Google refuses a subdomain in that field (under a suffix like `.co.uk` the registrable
   domain has three labels: `example.co.uk`). Change the home page and privacy links to
   `https://auth.example.org/` and `https://auth.example.org/privacy`. The OAuth client itself needs no change: it
   names no URL.
3. Check: `curl https://auth.example.org/` answers `Status: ready`, and the old `workers.dev` URL no longer answers.
4. On every device: `gclone login https://auth.example.org`.
5. Add one zone rate-limiting rule (Security → WAF → Rate limiting rules) that covers **every path of the
   Worker's host**. Not only `/device/start`, `/device/poll` and `/refresh`: the home page, `/privacy` and any
   path that does not exist are answered by the Worker too, and each of those requests counts against the daily
   quota exactly like a login does.

   - Counted per IP address, action **Block**, **5 requests per 10 seconds**. A login that waits for you polls once
     every 5 seconds — 2 requests per 10 seconds — and a refresh is 1; a blocked poll only delays the login (gclone
     waits and goes on polling). Raise the number to 10 if two devices behind one address often sign in at the same
     time. Do not go higher: 20 per 10 seconds would let one address send 172,800 requests a day without ever being
     blocked — more than the whole free quota.
   - Which requests the rule matches depends on the zone's plan:
     - **Pro and above**: the host — `http.host eq "auth.example.org"`.
     - **Free** (one rule; the expression can use the URI path only; 10-second period and 10-second block):
       the rule cannot name a host, so it applies to the whole zone. `starts_with(http.request.uri.path, "/")`
       matches everything — the right rule when the zone serves nothing but the Worker (a spare domain is the
       simple way), and too strict for a zone that also serves a website, where a page view is many requests. On
       such a zone the Free plan has no rule that covers the Worker's unknown paths without also limiting the
       site; use a zone of its own for the Worker, the Pro plan, or the Workers paid plan (no daily cap).

   - **With the hosted viewer** the rule changes: **10 requests per 10 seconds** over every path **except** the
     viewer's static files —

     ```
     not starts_with(http.request.uri.path, "/a/") and http.request.uri.path ne "/sw.js"
     ```

     (on Pro and above, `and http.host eq "auth.example.org"`). Those files are served without running the Worker,
     so they cost no Worker request and need no limit; with them counted, one page load (about twenty requests)
     would trip the rule. What is left counts 2 requests for a page load (`/` and `/web/refresh`) and 5 for a
     sign-in. Whether the Free plan's rule builder accepts this expression is **not verified**
     ([First deployment](#first-deployment-what-to-check), item 7). If it does not: a rule over all paths blocks
     the viewer's own page load, so the choice is the Pro plan, or no zone rule — the Worker's built-in limit
     stays either way.

   Requests blocked by the rule never reach the Worker and do not count against its quota; gclone treats the
   block (`429`) like the Worker's own limit and waits. What the rule does **not** do: it counts per address, so
   it bounds each sender — at 5 per 10 seconds one address gets at most 43,200 requests a day through — not the
   total. A flood from many addresses can still exhaust the free quota; only the paid plan removes that limit.
   (Plan details as documented by Cloudflare in late 2026; they change — check the rule builder.)

## The hosted viewer: setup

Optional. Without it the Worker is the sign-in helper of `gclone login` and nothing else. With it,
`https://<host>/` is a read-only file browser for the vault: you sign in with Google, the vault passphrase is
filled in by your password manager, and the browser fetches ciphertext from Google Drive and decrypts it itself.

**Decide first whether you want it.** The page that asks for the passphrase is served by this Worker. Whoever
controls the Worker, its secrets, the Cloudflare account or the domain can serve a page that takes the passphrase —
and with it everything. A device that never opens the hosted viewer is not affected. `docs/SECURITY.md`
("The hosted viewer: what you trust") and `docs/SPEC.md` §1.3 say what that means; the three habits against phishing are
[below](#phishing-codes-and-look-alike-pages).

It needs a **custom domain** ([above](#custom-domain-and-rate-limiting-rule-recommended)): two of the settings below
belong to a zone and cannot be made for `workers.dev`.

### 1. Google console: the "Web application" client

The viewer signs in with a redirect, which the device client ("TVs and Limited Input devices") cannot do. It uses a
second client **in the same Cloud project**:

1. **Clients.** If you used gclone before 0.2.0, the client of type **Web application** from back then still
   exists: use it. Otherwise **Create client** → Application type **Web application** (any name), and copy its ID
   and secret.
2. **Authorized redirect URIs** of that client: exactly one, `https://<host>/callback` — scheme, host, path, no
   trailing slash. **Authorized JavaScript origins**: none; leave the list empty.
3. **Audience** still reads **In production** (in Testing a browser session ends after 7 days), and the scopes are
   `openid`, `email` and `drive.file` as before. Branding stays `https://<host>/` and `https://<host>/privacy`.
4. **Do not delete this client** while you use the viewer, and never put its secret anywhere but the Worker.

### 2. The viewer's three secrets

```sh
npx wrangler secret put GOOGLE_LEGACY_CLIENT_ID        # the Web application client's ID
npx wrangler secret put GOOGLE_LEGACY_CLIENT_SECRET    # its secret
openssl rand -base64 32 | npx wrangler secret put SEAL_KEY
```

`SEAL_KEY` is 32 random bytes in base64: the key that seals the browser's session cookie. **Generate a new one**
as shown — never reuse a value that is left over from a Worker before 0.2.0, and keep no copy: nothing ever needs
it again, and putting another new value is how every browser session is ended at once
([Operating it](#operating-it)). The names `GOOGLE_LEGACY_CLIENT_*` are historical (see
[Configuration](#configuration)).

`curl https://<host>/` then says `Status: ready` without the "web viewer is not configured" remark.

### 3. Cloudflare: two zone settings

1. **SSL/TLS → Edge Certificates → Always Use HTTPS: on.** The Worker itself answers plain `http` with a redirect
   or a refusal, but the viewer's static files are served without the Worker; this setting is what covers them. It
   applies to every host of the zone, so every host of the zone must work over `https`.
2. **The zone rate-limiting rule** in the viewer's form: 10 requests per 10 seconds over every path except `/a/`
   and `/sw.js` ([the rule](#custom-domain-and-rate-limiting-rule-recommended), last item).
3. *Optional, and a commitment:* HSTS with `includeSubDomains; preload` on the **apex** domain, and submitting it to
   the browsers' preload list. The Worker's own HSTS header protects a browser only after its first `https` visit;
   preloading closes that gap for a new browser — and makes **every** host under the apex `https`-only for good.
   Only do it if that is true of all of them.

### 4. GitHub: where the viewer's files come from

The files are not built on your machine. Each release of this repository carries them as
`gclone-viewer-<version>.tar.gz`, built by the release workflow in a job that runs no npm package, and signed with
a **build-provenance attestation** — a statement by GitHub that these bytes were built by this repository's
`.github/workflows/release.yml` at this tag. The deploy scripts verify that attestation; without it they stop.

1. The machine you deploy from needs the GitHub CLI: `gh` (`nix-shell -p gh`, or <https://cli.github.com>), signed
   in once (`gh auth login`).
2. The repository's releases have to be **immutable** (a repository setting: a published file can then not be
   replaced and the tag of a release can not be moved). The deploy scripts check that themselves — `gh release
   verify-asset` passes only for a file of an immutable release — and stop if it is not so: the build's
   attestation follows the *tag*, and whoever can push a tag could otherwise move it and have the release
   workflow attest another viewer under the same name. The setting holds for releases published **after** it was
   turned on. For one that was published before (v0.4.0 of this repository is one), name it:
   `GCLONE_MUTABLE_RELEASE=v0.4.0 node scripts/…` — the scripts then go on with a warning, and what protects you
   is comparing the tarball's SHA-256 and the commit they print with what they printed the first time.
3. If you release from **your own fork**: turn that setting on before the first release, make sure artifact
   attestations are available to the repository (they are for public repositories), and set
   `GCLONE_REPO=<owner>/<name>` when you run the scripts below.

**Release-day order.** Since 0.5.0 the release workflow stops at a *draft* release: pushing the tag
builds, tests and attests the files, and nothing is public yet. The order is: push the tag **alone**
(`git push origin v0.5.1` — not `main` yet) → wait for the workflow → on the owner's Mac
`scripts/release-sign-macos.sh <tag>` (it verifies the draft, adds the signed macOS build and
publishes; `DEVELOPMENT.md`, "Publishing a release") → deploy the viewer as below → `git push origin
main`. `fetch-viewer` finds nothing to fetch while the release is still a draft, and `main` waits
because the install one-liner pipes `install.sh` from it: the new script refuses a latest release
without attested binaries, which is what the previous release is until this one is published.
Deploy the 0.5.0 viewer before anybody relies on typing a generated passphrase in another case or
spacing in the browser: the viewer of 0.4.0 wants it exactly as displayed.

Then [deploy](#deploying-the-viewer), and go through the [checklist](#first-deployment-what-to-check).

## Deploying the viewer

From a checkout of the release's tag (`git checkout v0.5.1`: the Worker's code and the header set the scripts
compare against come from the checkout; the viewer's files come from the release):

```sh
cd worker
node scripts/fetch-viewer.mjs v0.5.1                       # 1
npm ci                                                     # 2
npm run deploy                                             # 3
node scripts/verify-deployed.mjs https://<host> v0.5.1     # 4
```

1. **`fetch-viewer`** downloads `gclone-viewer-0.5.1.tar.gz` from the tag's release into a temporary directory,
   verifies its attestation and that the release is immutable —

   ```sh
   gh attestation verify gclone-viewer-0.5.1.tar.gz --repo <owner>/<repo> \
     --signer-workflow <owner>/<repo>/.github/workflows/release.yml \
     --source-ref refs/tags/v0.5.1 --deny-self-hosted-runners \
     --source-digest <the commit this checkout is at>
   gh release verify-asset v0.5.1 gclone-viewer-0.5.1.tar.gz --repo <owner>/<repo>
   ```

   — and only then unpacks it, checks it (`scripts/check-dist.mjs`) and replaces `./dist` with it. The first
   command says: built by this repository's release workflow, on this tag, **from the commit you have checked
   out** — the Worker's code is deployed from the checkout and the viewer from the release, and the two belong
   to one commit (if the checkout is somewhere else, the script says `git checkout v0.5.1`). The second says:
   this file belongs to a release whose tag and files GitHub has fixed. It prints the version, the build id, the
   commit and the tarball's SHA-256 — **keep those four lines**. It uses Node's built-in modules, `gh` and `git`
   only, which is why it runs **before** `npm ci`: nothing of npm has run when the bundle is verified.
2. **`npm ci`** installs wrangler (the locked versions of `package-lock.json`).
3. **`npm run deploy`** runs `scripts/check-config.mjs`, then `scripts/check-release.mjs` — which reads the tag
   from `dist`'s manifest, fetches and verifies the release **again** (both commands above), and compares every
   file of `./dist` with it: nothing missing, nothing extra, every hash equal — and only then `wrangler deploy`.
   A `./dist` that anything changed since the fetch does not deploy. It also lists what in the working tree
   below `worker/` differs from the commit (your `routes` entry in `wrangler.jsonc` is expected there; anything
   else is code that is not the release's).
4. **`verify-deployed`** fetches and verifies the release a third time and compares it with what the host serves:
   the page at `/` and `/callback` (around the status line), `/sw.js`, and every file of `/a/<build>/`, each with
   the release's headers. It never reads `./dist`. Run it after every deploy, and whenever you want to — from any
   machine with `gh` and Node; it needs no Cloudflare access and no checkout of the tag (it deploys nothing, so
   it holds the release to no commit of yours; it prints the release's commit).

**When a check that passed before fails.** `check-release` and `verify-deployed` compare with the release *as it
is now*. If they stop matching, either your copy or deployment changed — or the release did: a tag that was
moved and built again. The messages say which it looks like (they name the build and the commit on both sides).
If the release is what changed, **do not fetch it again** — that deploys exactly the bytes that were swapped in.
Compare with the four lines `fetch-viewer` printed when you deployed, and find out why they differ first. With
immutable releases this cannot happen to a published release at all, which is why the scripts insist on it.

What `verify-deployed` proves: the static files and the page **served to these requests** are the release's. It
finds a stale deployment, a mix-up and a changed file. It cannot prove that the Worker does not answer someone
else differently — whoever controls the Worker can do that, and no check from outside rules it out. (It asks with
its own `User-Agent` and without a browser's headers, and it checks that the release's headers are present, not
that there are no others.) And it says nothing about any **browser**: what a page served by someone else left in
a browser's profile is not on the host ("After a change of hands", under [Operating it](#operating-it)).

**The Worker's script is not part of the signed release.** The attestation, `check-release` and `verify-deployed`
are about the viewer's static files. The code in `src/` — which answers `/` and `/callback` by putting the status
line into the bundle's `index.html`, sets that answer's headers, and runs the sign-in — is bundled by `wrangler`
and its `esbuild` on your machine, after `npm ci` (186 packages, three of them with install scripts), from your
working tree. `fetch-viewer` and `check-release` refuse a checkout that is not at the release's commit and list
local changes below `worker/` (a `routes` entry in `wrangler.jsonc` is expected); they do not refuse those
changes, nothing signs the bundled script, and nothing compares what Cloudflare runs with the tag. So: deploy from
a clean checkout of the tag, on a machine you trust, and treat the Cloudflare account like the vault's passphrase.

The viewer shows what it is in its info panel ("Build"), to compare with the release notes: a convenience, not
evidence — the page reports it about itself.

Every step fails closed: no `gh`, no attestation, an attestation from another workflow, another ref or another
commit, a release that is not immutable, a tarball that holds anything but a bundle → nothing is unpacked,
deployed or compared. `SHA256SUMS` of the release is not
used for any of this: it is made by the same workflow run as the files it lists.

**Other ways to deploy.**

- **Without the viewer** (the plain sign-in helper): `npm run deploy:dev`. It writes the placeholder into `./dist`
  if nothing is there, says in one line what it deploys, and runs `wrangler deploy` without the release check.
  (`./setup.sh` and step 1 of the one-time setup do the same by hand.)
- **A build of your own** (development, or a repository without attestations):

  ```sh
  npm run viewer:build        # ../web-core/build.sh, viewer/build.mjs, scripts/check-dist.mjs  →  ./dist
  npm run deploy:dev          # prints: NOT a release build … (version, build, rustc), then wrangler deploy
  node scripts/verify-deployed.mjs https://<host> --dist ./dist
  ```

  `viewer:build` needs the Rust toolchain of `rust-toolchain.toml` with the `wasm32-unknown-unknown` target and
  the `wasm-bindgen` command in the version of `web-core/Cargo.lock` (`../web-core/README.md`). A build with other
  tools (for example from nix) works and is visibly not the release's: the manifest names its compiler.
- **Going back**: fetch and deploy an older tag the same way. Browser sessions survive a deploy; open pages notice
  the new build when they next load a file and ask for a reload.

## First deployment: what to check

None of this can be checked before the Worker is deployed with real secrets. Go through it once, in this order;
note what you saw.

- [ ] **1. Sign-in.** Open `https://<host>/`, "Sign in with Google", approve. You arrive at the passphrase
      screen, which shows your address. (Google returned a refresh token and an ID token with the right nonce;
      otherwise the page says which part failed.)
- [ ] **2. The vault is found and opens.** The passphrase screen names the vault's folder, and after the
      passphrase the listing appears. This is also the answer to an open question: whether the Web application
      client's login **sees the vault that was created through the device client**. If the viewer says there is no
      vault although `gclone ls` shows one, it does not — the viewer then cannot be used with this vault, and
      nothing is lost. Open a file larger than a few MiB as well (ranged reads from Drive, straight from the
      browser).
- [ ] **3. Static files do not run the Worker.** In one terminal `npx wrangler tail`; in another:

      ```sh
      curl -sI https://<host>/sw.js | grep -i -e '^HTTP' -e content-security-policy
      curl -sI https://<host>/a/<build>/core.js | grep -i -e '^HTTP' -e content-security-policy
      curl -s -o /dev/null -w '%{http_code}\n' https://<host>/a/nope
      ```

      `200` with the policy, `200` with the policy, `404` — and `tail` shows **no** line for any of the three.
      (`<build>` is printed by `fetch-viewer`.) `node scripts/verify-deployed.mjs https://<host> v0.5.1` passes.
- [ ] **4. Cloudflare accepted the deployment** (`npm run deploy` ended without an error about the main module
      `src/entry.ts` or the assets).
- [ ] **5. The phone** (iOS Safari; see also [the phone test](#the-phone-test-15-minutes)):
      - sign-in works (the tab comes back from Google and continues), and with "Stay signed in" the session is
        still there the next day;
      - unlock works, and five times in a row: unlock, Lock, unlock, …; note the seconds an unlock takes;
      - a long video seeks; a 4K recording from the phone's camera plays without stalling;
      - a download of about 2 GB finishes (keep the tab open and in front);
      - "Download" on a `.txt`, a `.jpg` and a `.pdf` saves the file, and the viewer is still unlocked afterwards;
      - a PDF opens in a new tab ("Open" on its card), and so does an image ("Open in a new tab");
      - put the phone away for ten minutes with the vault open: it comes back at the passphrase screen;
      - the password manager you use offers the passphrase on this page.
- [ ] **6. Desktop Chrome and Firefox:** a download that runs longer than five minutes finishes.
- [ ] **7. The zone rule**: Cloudflare took the expression; a cold page load and a sign-in go through; a burst
      (`for i in $(seq 30); do curl -s -o /dev/null -w '%{http_code} ' https://<host>/; done`) is blocked.
- [ ] **8. `SEAL_KEY` rotation**: put a new one. A viewer that is opened or reloaded now shows "Sign in with
      Google". A viewer that is open and unlocked keeps working on the access token it holds — **up to an hour** —
      and goes to "Sign in with Google" ("Your sign-in has ended") when that runs out and it next opens a file or
      refreshes; press Refresh after the hour to see it. `gclone ls` on a device works as before. (Sign in again.)
- [ ] **9. The release**: the tag's workflow run shows the attestation; `fetch-viewer` accepted the tarball. A
      re-packed copy is refused: `gh attestation verify` (the command above) on a tarball you unpacked and packed
      again fails. With immutable releases on, replacing a release file is refused by GitHub, and
      `gh release verify-asset <tag> <tarball>` passes (the scripts run it).
- [ ] **10. Plain http is not served:** `curl -sI http://<host>/` is a redirect to `https://`;
      `curl -s -X POST http://<host>/web/refresh` is a redirect or `https_required`, never a session answer.
- [ ] **11. Old logins are closed:** `curl -s -X POST -H 'content-type: application/json' -d '{"refresh_token":"1//0aaaaaaaaaaaaaaaaaaaaaaaaaaa"}' https://<host>/refresh`
      answers `400 invalid_grant` ("…no longer serves…"); a device of gclone 0.2.0 or later syncs as before.
- [ ] **12. Local development** (only if you work on the Worker): `npm run dev` serves the page instead of
      redirecting in a loop.
- [ ] **13. The Service Worker on the phone:** an image and a video open in the viewer on iOS Safari (item 5
      covers it; a failure here shows as previews that never load). Since 0.5.0 this also shows that the worker
      holding the vault's keys reaches the Service Worker with a request of its own, which the per-file keys are
      sealed through — tested in desktop Chrome and in Playwright's WebKit and Firefox, **not in Safari itself and
      not on a phone**. If it does not, the viewer stops before the passphrase screen with "The viewer's Service
      Worker does not answer the worker that holds the vault's keys…": then that browser cannot use the viewer
      (nothing is exposed; report it). Check Safari on a Mac the same way, and Firefox.
- [ ] **14. The session cookie among other cookies.** Sign in, then give the host a second cookie — in the
      browser's developer tools, on the viewer's page: `document.cookie = "probe=1; Path=/; Secure"` — and
      reload: the passphrase screen comes, not "Sign in with Google". (Over HTTP/2 and HTTP/3 a browser sends one
      `Cookie` field per cookie. The Worker finds the session whether Cloudflare hands those over joined with
      `; ` or with `, `; this confirms it on the real edge, where it could not be tested.) Remove the cookie
      afterwards: `document.cookie = "probe=; Path=/; Secure; Max-Age=0"`.
- [ ] **15. Two tabs.** Open the viewer in two tabs and unlock both. "Lock" in one: the other shows the
      passphrase screen too ("The vault was locked in another tab"). Unlock both again, "Sign out" in one: the
      other shows "Sign in with Google".
- [ ] **16. A PDF.** It is offered as a card with "Open" and opens in a tab of its own, in desktop browsers
      too. In the browser's history that tab's entry carries no file name (an id instead).
- [ ] **17. The answer to a foreign Service Worker** (0.5.0):

      ```sh
      curl -s -o /dev/null -D - -H 'Service-Worker: script' -H 'Sec-Fetch-Dest: serviceworker' https://<host>/not-the-viewers.js | grep -i -e '^HTTP' -e clear-site-data
      curl -s -o /dev/null -D - -H 'Service-Worker: script' -H 'Sec-Fetch-Dest: serviceworker' https://<host>/a/nope.js | grep -i -e '^HTTP' -e clear-site-data
      curl -s -o /dev/null -D - -H 'Service-Worker: script' -H 'Sec-Fetch-Dest: serviceworker' https://<host>/sw.js | grep -i -e '^HTTP' -e clear-site-data
      ```

      `404` with `clear-site-data: "cache", "storage"`; `404` without it (the asset layer answers under `/a/`; if
      the header *is* there, a miss under `/a/` runs the Worker in production — better than expected, tell the
      project); `200` without it.

If something fails:

- **Unlock on the phone** (5): the phone cannot run the key derivation at 256 MiB. The choice is between a keyfile
  that costs less memory (not built) and no phone support. Nothing else is affected.
- **Long downloads** (5, 6): a limit to know about; use `gclone copy` for large files.
- **The attestation** (9) — for a private repository on a plan without attestations: the release bundle then has
  no trust anchor and the scripts will not use it. Build from a checkout of the tag with the pinned toolchain
  (`npm run viewer:build`), deploy with `npm run deploy:dev`, compare with `verify-deployed … --dist ./dist`.

## The phone test (15 minutes)

One question decides how the viewer's Lock is built, and only your phone can answer it: can it run the unlock —
Argon2id over 256 MiB — **repeatedly**, the way the viewer does it (a page reload for every Lock)? Phones give a
web page little memory, and some browsers do not return it at once. The test page runs the cycles by itself. It
needs no deployment, no Google account and no vault.

You need the computer and the phone in the same Wi-Fi, and on the computer what builds the viewer's core (below
with nix; otherwise the toolchain of `../web-core/README.md`).

- [ ] **1. Build the test's core** (repository root; a few minutes the first time):

      ```sh
      nix-shell -p cargo rustc lld wasm-bindgen-cli nodejs --run 'FEATURES=bench sh web-core/build.sh . worker/viewer/bench/pkg'
      ```

- [ ] **2. Find the computer's address in the Wi-Fi:** `ipconfig getifaddr en0` (macOS) or `hostname -I` (Linux)
      — something like `192.168.1.23`.
- [ ] **3. Serve the page:** `node worker/viewer/bench/serve.mjs 8787 192.168.1.23` (your address). If macOS asks
      whether `node` may accept incoming connections: allow.
- [ ] **4. On the phone:** close the other tabs of the browser you will use the viewer in (Safari on an iPhone),
      open `http://192.168.1.23:8787/` and tap **Start**. Keep the phone awake and the page in front for about a
      minute. It reloads itself several times; that is the test.
- [ ] **5. Read the last line**, on the phone and in the terminal (between `RESULT-BEGIN` and `RESULT-END`):
      - `A and B pass: this device unlocks with Lock = reload, as the viewer is built.` — nothing to do.
      - `A or B fails, C passes: …` — the phone cannot unlock again after a reload. The viewer needs its other
        Lock (it ends its workers instead of reloading the page); that variant is specified and not built.
      - `A and C fail: …` — this phone cannot unlock a vault whose keyfile asks for 256 MiB.
- [ ] **6. Note the numbers** (the "derive … ms" lines: how long an unlock will take on this phone) and whether
      the browser closed the page in between (the result then says so). Tap "Run it again" once to see whether it
      repeats.
- [ ] **7. Stop the server** (Ctrl-C). Nothing was stored anywhere.

What this page cannot test: media and downloads through the Service Worker, which need `https` — they are item 5
of [the first-deployment checklist](#first-deployment-what-to-check).

## What is logged

- The Worker writes at most one line per request: `{"route": "/device/poll", "status": 400, "error": "authorization_pending"}` —
  the route, the status and an error code. `route` is one of the Worker's own paths (`/`, `/callback`, `/privacy`,
  `/device/start`, `/device/poll`, `/refresh`, `/web/start`, `/web/token`, `/web/refresh`, `/web/logout`) or
  `other`. Never a request body, a query string, a header, a cookie, a device code, a user code, an authorization
  code, a verifier, a token or an e-mail address. (A login that waits therefore logs one `authorization_pending`
  line every 5 seconds: that is the normal state, not a fault.) Requests for the viewer's static files (`/a/*`,
  `/sw.js`) do not run the Worker and write no line.
- The Workers Logs view stores these lines. Cloudflare attaches the triggering request to each stored event; the
  configuration removes the query string from that URL and keeps invocation logs and traces off (see
  [Configuration](#configuration)). Do not relax those settings, and do not add Logpush, a tail consumer or an
  observability destination.
- `npx wrangler tail` prints the method and the URL of every request on your terminal while it runs; request bodies
  are not shown. One URL carries a secret: while `tail` runs, a browser sign-in shows as
  `GET /callback?code=…&state=…` with Google's authorization code — single-use, redeemed seconds later, and useless
  without the verifier in the browser tab. No other route carries a secret in its URL.
- Cloudflare still processes request metadata (IP address, time, URL path) at the platform level. The Worker's
  privacy page says so.

## Troubleshooting by error code

Every error — on the JSON routes and for anything else the Worker refuses — is answered as
`{ "error": "<code>", "message": "…" }`; gclone turns the codes into its own messages.

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `authorization_pending` | 400 | `/device/poll`: nobody has entered the code at Google yet. Not a fault: gclone polls again. | Enter the code the terminal shows at `https://www.google.com/device`. |
| `slow_down` | 400 | `/device/poll`: Google wants fewer polls. gclone waits 5 seconds longer between them from then on. | Nothing. |
| `expired_token` | 400 | `/device/poll`: the code was not entered within its lifetime (30 minutes). | Run `gclone login` again. |
| `access_denied` | 403 | The consent was refused at Google — by you ("Cancel"), by an administrator's policy, or because an Internal app was used from outside the organisation. The message carries Google's code. | Run `gclone login` again and approve; otherwise check the Audience setting and the Workspace policy. |
| `invalid_grant` | 400 | `/device/poll`: the device code is unknown, or its login was already completed (a code is good for one login). `/refresh`: the refresh token is revoked, expired or was unused for six months — or the request names no `"client"`: a login from gclone before 0.2.0, which this Worker no longer serves (the message says so). `/web/token`: Google refused the code or the verifier, or the code was not issued for this sign-in. `/web/refresh`: Google no longer honours the session's token; the cookie is cleared. | A device: run `gclone login` again. The viewer: sign in again. |
| `server_misconfigured` | 500 | On the device routes: `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_SECRET` is missing; the page at `/` says `Status: not configured`. On `/web/start`, `/web/token`, `/web/refresh` (the message names the three secrets): the hosted viewer is not configured — the web client's pair or `SEAL_KEY` is missing, or `SEAL_KEY` is not 32 bytes of base64; the page says `Status: ready. The web viewer is not configured: …`, and everything else works. | Put the secrets (step 3; for the viewer: the three of [Configuration](#configuration)). |
| `client_invalid` | 500 | Google does not accept the OAuth client: wrong client ID or secret, a deleted client, a client that is not of type "TVs and Limited Input devices" (`invalid_client` on `/device/start`), or one that may not ask for gclone's scopes. On `/web/token` also: the "Web application" client does not list `https://<host>/callback` as an Authorized redirect URI (`redirect_uri_mismatch`). The message carries Google's code. | Compare the two secrets with the console and check the client's type; for the viewer, the redirect URI — scheme, host, path, no trailing slash. A deleted client can be restored in the console for about 30 days. |
| `no_session` | 401 | `/web/refresh`: the browser is not signed in to the viewer — it sent no session cookie, or one that no longer opens: past its lifetime (12 hours, or 30 days with "stay signed in"), sealed under a `SEAL_KEY` that was replaced, or damaged. The cookie is cleared; Google was not asked. | Sign in again. |
| `cross_origin` | 403 | A `/web/*` route was called by something other than the viewer's own page: the `Origin` header is missing or names another origin, or the browser says the request is not same-origin. Or a device route (`/device/start`, `/device/poll`, `/refresh`) was called by a web page: the request carries an `Origin` or `Sec-Fetch-Site` header, which the gclone command never sends. Such requests are refused before the rate limiter counts them. | Nothing: the `/web/*` routes are for the page at `https://<host>/` only, the device routes for the gclone command only. |
| `https_required` | 400 | A request other than `GET` or `HEAD` came over plain `http`. (`GET` and `HEAD` are redirected to `https` with `308`.) | Use the `https://` URL. |
| `email_not_allowed` | 403 | The Google account that signed in is not in `ALLOWED_EMAILS`, or its address is not verified. The Worker revoked that grant. The message shows the account masked — first character and domain, `s***@example.net` — enough to see which of your accounts was chosen; the full address is never returned, because anyone can poll. | Sign in with the right account, or add the address (`npx wrangler secret put ALLOWED_EMAILS`). An empty list allows nobody. |
| `grant_unusable` | 403 | `/device/poll` and `/web/token`, right after you approved: Google issued the login — the code is used up — but its answer lacks something the Worker needs, and the message says what: no ID token (without the account's address `ALLOWED_EMAILS` cannot be applied), an ID token that is not Google's for this client, or no refresh token. Nothing was handed out. gclone stops at once and shows the message. | Once: run `gclone login` again. Every time: see "Other symptoms" below. |
| `scope_missing` | 403 | Google did not grant access to Drive files (the box was unticked on the consent screen). | Run `gclone login` again and approve every permission on the consent screen. |
| `scope_not_allowed` | 403 | Google granted **more** than `openid`, `email` and `drive.file` — the message names what. The Worker hands out no token for such a grant, on `/device/poll`, `/refresh`, `/web/token` or `/web/refresh`. The Worker itself only ever asks for those three, so this is not expected; it would mean that the account holds an older, wider grant for this Cloud project and Google reports it. | Remove gclone at <https://myaccount.google.com/permissions> (this signs out every device), then `gclone login` on each device. |
| `invalid_request` | 400 | The request is malformed. | Update gclone. |
| `rate_limited` | 429 | More than 30 requests in 60 s from one address. `Retry-After: 60`. | Wait a minute. gclone waits by itself; a login in progress goes on afterwards. |
| `upstream_error` | 502 | Google gave no answer the Worker could use: its sign-in service was unreachable, timed out, rate-limited the client, or answered with an error the Worker does not know. Nothing was consumed. | Try again later. A login in progress polls again by itself, with a longer pause after every failure in a row (up to a minute). |
| `payload_too_large`, `unsupported_media_type`, `method_not_allowed`, `not_found` | 413, 415, 405, 404 | Not a gclone request, a wrong auth URL — or a gclone older than 0.2.0, whose `/login` and `/token` routes no longer exist (`/callback` is the hosted viewer's page now). | Check the URL given to `gclone login`: it is the Worker's base URL, without a path. Update gclone. |

Other symptoms:

- **`gclone login` says the auth Worker "is an older version without the code sign-in"**: the deployed Worker is
  from before 0.2.0. Deploy this directory (and see
  [Moving from the browser sign-in](#moving-from-the-browser-sign-in-gclone-before-020)).
- **Google's page says the code is invalid**: it expired (30 minutes), or it was mistyped. Codes are
  case-sensitive as shown. Run `gclone login` again for a new one.
- **Google shows "Access blocked" or a testing warning**, or `gclone login` reports that the login expires in 7
  days: the app is still in Testing — Audience → **Publish app**.
- **Every login ends right after you approved with "Sign-in was not completed (Google approved the sign-in, but
  …)"** (`grant_unusable`): Google's token answer did not carry what the Worker needs — an ID token with the
  account's e-mail address (the Worker asks for `openid email`) and a refresh token; the message names the missing
  part. The Worker fails closed here on purpose: without the address it cannot apply `ALLOWED_EMAILS`. Running
  `gclone login` again will end the same way; the Worker has to be changed (for a missing ID token: ask Google's
  userinfo endpoint for the address instead).
- **`gclone login` warns "that is not a google.com address" and does not open a browser**: the Worker passed on a
  sign-in address that is not under `google.com`. Google's page is `https://www.google.com/device`. If Google has
  really moved it, open the printed address yourself; if not, the answer did not come from your Worker as you
  deployed it — check the auth URL (`gclone --version`, `gclone status`) and the Worker.
- **Someone asks you to enter a code, or a code arrives that you did not just get from your own terminal**: do not
  enter it. See [Device-code phishing](#phishing-codes-and-look-alike-pages).

## How it works

| Route | Called by | Served by | Purpose |
|---|---|---|---|
| `GET /`, `GET /callback` | browser, Google reviewers | Worker | the hosted viewer's page: the bytes of `dist/index.html` with the status line (`Status: ready`, `Status: ready. The web viewer is not configured: …` or `Status: not configured`) in place of the marker `<!--gclone-status-->`. The same bytes for both paths and for every query. `/callback` is the redirect URI of the browser sign-in. |
| `GET /privacy` | browser | Worker | privacy statement |
| `GET /a/<build>/<file>`, `GET /sw.js` | the viewer's page | asset layer (the Worker does not run) | the viewer's static files ([The viewer's files](#the-viewers-files)) |
| `POST /device/start` | device | Worker | asks Google for a device code and a user code (the Worker's client ID, the fixed scope `openid email drive.file`) and passes Google's answer on |
| `POST /device/poll` | device, every few seconds | Worker | asks Google's token endpoint for the device code, adding the client ID and secret; passes the pending states on; on success checks the grant and hands out this device's refresh token |
| `POST /refresh` | device | Worker | refresh token → access token, **for the device client only** |
| `POST /web/start`, `/web/token`, `/web/refresh`, `/web/logout` | the viewer's page | Worker | the browser sign-in of the hosted viewer |
| anything else — `/index.html`, `/_headers`, `/v/…` included | | Worker | `404 not_found` |

**https only.** Before anything else: a request whose URL is not `https` is not served. `GET` and `HEAD` are answered
`308` to the same URL under `https:` (path and query unchanged, no body); every other method `400 https_required`,
without looking at its body or cookie. The hosts `localhost`, `127.0.0.1` and `[::1]` are exempt (development).
The zone setting "Always Use HTTPS" does the same one layer earlier — and is what covers the static files, which
do not run the Worker.

### Devices

**`POST /device/start`** — body: any JSON object (`{}`; nothing in it is used). Answer `200`:
`{ "device_code", "user_code", "verification_url", "expires_in", "interval" }`, exactly as Google gave them
(`expires_in` 1800 and `interval` 5 seconds today; should Google leave `interval` out, the Worker says 5, the
default of RFC 8628). gclone opens `verification_url` in a browser only when it is a `google.com` address.

**`POST /device/poll`** — body `{ "device_code": "…" }`. Answer `200`:
`{ "refresh_token", "access_token", "expires_in", "scope", "email" }`, plus `"refresh_token_expires_in"` when
Google time-limited the grant (an app still in Testing). Before that: `400 authorization_pending`, `400 slow_down`,
`400 expired_token`, `403 access_denied`, `400 invalid_grant` (see the table above). Google answers some of these
states with other statuses (`428`, `403`); the Worker goes by Google's error code and answers as listed. Once
Google has issued the tokens the device code is used up, so every refusal from then on is final and is never a
`5xx` (which gclone would poll again on): `403 grant_unusable`, `403 email_not_allowed`, `403 scope_not_allowed`,
`403 scope_missing`.

**`POST /refresh`** — body `{ "refresh_token": "…", "client": "device" }`. Answer `200`:
`{ "access_token", "expires_in", "scope" }`. `"client"` names the OAuth client that issued the token, and
`"device"` is the only one this route serves. A body **without** `"client"` — a login made before gclone 0.2.0,
through the "Web application" client — is answered `400 invalid_grant` ("This login was made with gclone's earlier
browser sign-in, which this sign-in helper no longer serves. Run `gclone login` again."), whatever is configured
and without asking Google; any other value of `"client"` is `400 invalid_request`. The reason: the Web application
client now issues the hosted viewer's refresh tokens, and those are honoured in the sealed cookie only
(`/web/refresh`) — there they have an end, the allowlist is applied on every use, and a new `SEAL_KEY` cuts them
all off. A route that accepted such a token bare would undo all three.

The device routes take `application/json` bodies of at most 8 KiB, are rate-limited, and pre-filter what they pass
to Google (a device code or refresh token of the wrong shape never leaves the Worker). They set no cookie and read
none. **They are not for web pages:** a request that carries an `Origin` or a `Sec-Fetch-Site` header — a browser
puts them on what a page sends, the gclone command sends neither — is `403 cross_origin`, checked after the method
and **before the rate limit**. A page somewhere else can send such a request without anyone's permission (a
"no-cors" POST); counted, any page open in the owner's browser could keep the budget of the owner's address used
up, and with it the viewer's token refresh and the devices behind the same address.

### The hosted viewer's sign-in

Google's authorization-code flow with PKCE, through the "Web application" client. The tab that starts is the tab
that finishes; the Worker keeps nothing in between.

1. The page makes a `verifier` (32 random bytes, base64url), `challenge = base64url(SHA-256(verifier))` and a
   `state` (16 random bytes, base64url), and keeps them in the tab's `sessionStorage`.
2. `POST /web/start` formats the address at Google; the page checks that it starts with
   `https://accounts.google.com/o/oauth2/v2/auth?` and navigates there.
3. Google redirects to `https://<host>/callback?code=…&state=…`. The page compares `state`, removes the query from
   the address bar, and
4. sends `code` and `verifier` to `POST /web/token`. The Worker redeems the code with the client secret and the
   verifier, checks the grant as `/device/poll` does, and answers with an access token — and with the refresh
   token **sealed in a cookie** that scripts cannot read.
5. `POST /web/refresh` turns the cookie into a fresh access token, as often as needed, until the session's sealed
   end. `POST /web/logout` drops the cookie.

Rules of all four routes: `POST` only (`405` with `Allow: POST`); the request must come from the viewer's own page
— the `Origin` header equals the Worker's own origin and `Sec-Fetch-Site`, when the browser sends it, is
`same-origin`; a request without `Origin` is refused (`403 cross_origin`); the shared rate limit (`429`,
`Retry-After: 60`; **not `/web/logout`**); the web client's pair and `SEAL_KEY` are set (`500
server_misconfigured`; not required by `/web/logout`); `Content-Type: application/json` (`415`), a body of at most
8 KiB (`413`) that is a JSON object (`400 invalid_request`). The checks run in that order. The origin comes before
the limit so that another site's requests — refused, and costing nothing — are never counted against the owner's
address; sign-out is not limited at all, because it uses no secret, asks nobody and answers a constant, and a
sign-out that is turned away would leave the cookie in a browser its owner believes signed out. No answer carries a
CORS header, so no other origin can call these routes from a browser or read their answers. Every answer is
`Cache-Control: no-store`. The session cookie is looked for among the request's cookies however they arrive: in one
`Cookie` field separated by `; `, or in several fields, which the runtime joins with `, `.

**`POST /web/start`** — body `{ "challenge": "<43 characters base64url>", "state": "<22 to 128 characters base64url>" }`.
Answer `200`: `{ "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?…" }` with exactly these
parameters: `client_id` (the web client), `redirect_uri=https://<host>/callback`, `response_type=code`,
`scope=openid email https://www.googleapis.com/auth/drive.file`, `access_type=offline`, `prompt=consent`,
`code_challenge`, `code_challenge_method=S256`, `state`, and `nonce` = base64url(SHA-256(`"gclone-auth/v2/nonce"` ‖
challenge)). Nothing else of the request gets into it; Google is not contacted. `400 invalid_request`: a challenge
that is not the canonical base64url of 32 bytes, or a malformed state.

**`POST /web/token`** — body `{ "code": "…", "verifier": "<43 to 128 characters>", "remember": true }`
(`remember` is optional and a boolean). Answer `200`:

```
{ "access_token": "…", "expires_in": 3599, "scope": "…", "email": "you@example.com", "session_expires_in": 43200 }
Set-Cookie: __Host-gclone-web=<blob>; Path=/; Secure; HttpOnly; SameSite=Strict
```

`session_expires_in` is the session's whole lifetime in seconds: 43200 (12 hours), or 2592000 (30 days) with
`"remember": true` — then the cookie also carries `; Max-Age=2592000`; without it the cookie ends with the browser
session. Errors: `400 invalid_request` (malformed; Google was not asked, the code is not spent);
`400 invalid_grant` (Google refused the code or the verifier — or the code was issued for an address that
`/web/start` did not build for this verifier: the ID token's `nonce` does not match; nothing is revoked);
`403 grant_unusable`; `403 email_not_allowed` (the grant is revoked; the address is shown masked);
`403 scope_not_allowed`, `403 scope_missing`; `403 access_denied`; `500 client_invalid`; `502 upstream_error`.
No error answer sets a cookie.

**`POST /web/refresh`** — body `{}`, with the cookie. Answer `200`: the same five fields, `session_expires_in` now
being the seconds **left**; no `Set-Cookie` (the lifetime is not extended by use). Errors: `401 no_session` — no
cookie; or a cookie that does not open or has run out, in which case the answer clears it and Google is not asked;
`403 email_not_allowed` — the sealed address is no longer in `ALLOWED_EMAILS` (the grant is revoked, the cookie
cleared); `400 invalid_grant` — Google no longer honours the token (cookie cleared); `403 scope_not_allowed`,
`403 access_denied`, `500 client_invalid`, `502 upstream_error` (cookie kept: the session may work again).

**`POST /web/logout`** — body `{}`. Answer `200`: `{}` with
`Set-Cookie: __Host-gclone-web=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0` and
`Clear-Site-Data: "storage"` (not `"cookies"`, which would clear the cookies of the whole registrable domain). It
needs no secret and works while the viewer is not configured. Nothing is revoked at Google — that would sign every
device out; the page links to <https://myaccount.google.com/permissions> instead. The Worker keeps no list of
sessions: a **copy** of a cookie stays valid until its sealed end, or until `SEAL_KEY` is replaced.

**The cookie.** `<blob>` is base64url of `0x02 ‖ 0x04 ‖ nonce(12) ‖ AES-256-GCM(key, nonce, aad = the first two
bytes, iat u32 ‖ exp u32 ‖ len(email) u8 ‖ email ‖ refresh token)`, key = HKDF-SHA-256(`SEAL_KEY`, salt = 32 zero
bytes, info = `gclone-auth/v2/web-session`). About 240 characters; at most 1092 bytes with the name. The lifetime
(`exp`) is inside the seal and absolute. The refresh token appears in no response body and in no log; the access
token only in the bodies of `/web/token` and `/web/refresh`.

### Pages and headers

`/` and `/callback` carry `Cache-Control: no-store` and the header set of `src/headers.json`; the build writes the
same set into `dist/_headers` for `/a/*` and `/sw.js`:

```
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  img-src 'self'; media-src 'self'; frame-src 'self'; worker-src 'self';
  connect-src 'self' https://www.googleapis.com; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types gclone
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

In a deployment without the viewer's files (no `index.html` in the assets) `/` and `/callback` are the Worker's own
small home page instead, with the status line; `/privacy` is always the Worker's own page. Those two pages carry
their own, stricter policy (no script at all) and the same `Strict-Transport-Security`.

### What the Worker guarantees

The Worker keeps no state: Google holds a pending device login, the device carries its device code from one
request to the next, and the browser carries its sealed session. `/device/poll` and `/web/token` hand out tokens
only when Google's ID token names a verified address in `ALLOWED_EMAILS` (they revoke the grant of anyone else),
and only when Google granted exactly gclone's scopes — `openid`, `email`, `drive.file` — and nothing beyond them;
`/refresh` checks the allowlist (when Google sends an ID token) and the scopes again; `/web/refresh` checks the
allowlist on every call. The only redirect the Worker ever answers is the one from `http` to `https`.

**A Service Worker that is not the viewer's.** The viewer registers one Service Worker, `/sw.js`, which the asset
layer serves. When a browser asks the Worker for the *script of a Service Worker* at any other path (the request
header `Service-Worker: script`, with `Sec-Fetch-Dest: serviceworker` where the browser sends it), that
registration was made by someone else — while they served this address, or by whatever used the domain before. The
Worker answers as it would anyway (`404` for an unknown path) and adds `Clear-Site-Data: "cache", "storage"`, which
asks the browser to drop this site's storage, Service Workers included, and its cache. What that is worth, as
measured on this code (Chrome 157, Playwright's WebKit 27.2 and Firefox 159, on `http://127.0.0.1` — not on a
deployment):

| Browser | On that answer |
|---|---|
| Chrome (browsers built on it should do the same; not tested) | drops the registration, storage and cache — at the registration's next update check, which is after a visit that still showed the other page |
| Firefox | nothing: it does not act on `Clear-Site-Data` in the answer to a Service Worker's script |
| WebKit (Safari's engine) | cleared the storage and **kept the registration** |

And it only reaches paths that run the Worker: a script someone placed under `/a/` (with a `Service-Worker-Allowed`
header to give it the whole address) is answered by the asset layer, without the header. It is an aid, not the
remedy. The viewer's own page also unregisters every Service Worker of this address that is not `/sw.js` for `/`,
each time it loads.

Source: `src/entry.ts` (the module the runtime loads), `src/index.ts` (routing, the https rule, the device routes),
`src/web.ts` (the four routes of the viewer's sign-in), `src/seal.ts` (the sealed session), `src/google.ts`
(everything said to Google), `src/pages.ts` and `src/headers.json` (the pages and their headers), `src/reply.ts`
(the JSON answers). No runtime dependency.

## The viewer's files

`wrangler.jsonc` uploads the directory `./dist` (git-ignored) as the Worker's static assets. It holds one of three
things: the viewer of a release, put there by `scripts/fetch-viewer.mjs` ([Deploying the viewer](#deploying-the-viewer));
a build of your own (`npm run viewer:build`); or the placeholder (below). The Worker and its configuration expect
this layout, and `scripts/check-dist.mjs` (`npm run viewer:check`) asserts it:

```
dist/
  index.html              the page; contains the marker <!--gclone-status--> exactly once; references only /a/<build>/…
  sw.js                   the Service Worker script, served as /sw.js
  _headers                the header rules for /a/* and /sw.js: the text of `node scripts/headers-file.mjs`
  a/<build>/…             every other file (js, css, svg, wasm, json); <build> is 16 hex digits, one directory per build
  a/<build>/manifest.json the build: {build, commit, files: {name: sha256}, rustc, tag, version, wasm_bindgen}
```

`check-dist` refuses: anything else at the top level (a `_redirects` file would act before the Worker), a second
build directory, a file of the build directory that is not listed in the manifest with its SHA-256 or has another
extension than `js`, `css`, `svg`, `wasm`, `json` or is larger than 25 MiB, a `_headers` that is not the text of
`scripts/headers-file.mjs`, and a page with an inline script or style, an event-handler attribute, a `<base>`, a
`<meta http-equiv>` or a resource from anywhere but `/a/<build>/`. A built viewer names the Drive host in exactly
one place (`drive.js`). `tag` is the release tag for the bundle of a release and empty for every other build.

- `index.html` is never served under its own name: the Worker reads it and answers `/` and `/callback` with it.
  It must not rely on anything the Worker's headers forbid: no inline script or style, no event-handler attribute,
  no resource outside this origin.
- `/a/<build>/*` and `/sw.js` are answered by the asset layer with the headers of `_headers` and Cloudflare's
  default `Cache-Control: public, max-age=0, must-revalidate` plus an `ETag` (a revisit costs one `304` per file).
  A file that is not there is an empty `404` from the asset layer. There is deliberately no long cache lifetime: a
  `_headers` rule would also apply to that `404`. The per-build directory is what keeps a loaded page from mixing
  the files of two deployments.
- `_headers` must be exactly what `scripts/headers-file.mjs` writes from `src/headers.json` — the same header set
  the Worker puts on the page. A worker script (the Service Worker, and everything it or another worker loads from
  `/a/`) is governed by the policy of its own response, which is why the whole set is on both rules.
- No `_redirects` file: it would act before the Worker.

**Without a built viewer**, `node scripts/stub-dist.mjs` writes a placeholder of the same layout into `./dist`: a
static page with the home-page text and the status line, an empty `sw.js`, `_headers`, and
`a/0000000000000000/` with a stylesheet and a manifest that says `"stub": true`. `npm test`, `npm run dev`,
`npm run smoke`, `npm run deploy:dev` and `./setup.sh` run it first; it never touches a `./dist` that holds anything
but a placeholder. A Worker deployed with the placeholder is the plain sign-in helper. (`npm run deploy` does not
write it: that command deploys the viewer of a release and nothing else.)

## Phishing: codes, and look-alike pages

### Device codes

`/device/start` cannot ask for credentials — a device that logs in has none yet. So anyone who knows the Worker's
URL can start a login of their own, get a user code, and then try to make **you** enter **their** code at
`https://www.google.com/device` ("gclone needs re-authorising, please enter WXYZ-ABCD"). If you enter it and
approve, their poll receives a refresh token for your Google account's gclone files. `ALLOWED_EMAILS` does not stop
this: the account that consented is yours, the allowed one. This is a known weakness of the device grant itself
(RFC 8628 §5.4), not of this Worker.

What is done about it:

- gclone prints, with every code: *enter only a code shown in this terminal*. The Worker's home page says the same.
  Nobody ever has a reason to send you a code; a code you did not just get from your own `gclone login` is someone
  else's login.
- `/device/start` and `/device/poll` are rate-limited like every route (30 requests per 60 s and address, plus the
  zone rule of a custom domain), so one sender cannot mass-produce codes through your client.
- Nothing a caller sends reaches Google except a device code of the right shape; the scope is fixed in the Worker.
- Device codes, user codes and tokens are never logged, and no answer is cacheable.
- A caller whose code was entered by someone outside `ALLOWED_EMAILS` gets no token and not that person's address
  either: the `email_not_allowed` answer shows it masked (`s***@example.net`).
- gclone opens a browser only on a `google.com` address. Whoever answers under the Worker's name cannot make
  `gclone login` open a page of their own that asks for your Google password.

What is left if it happens anyway: the attacker holds a refresh token with the `drive.file` scope. It reaches only
the files gclone created, and those are **ciphertext** — without your passphrase nothing can be read. They could
move the vault to the Drive trash or overwrite its objects; trashed files can be restored for 30 days, and gclone
detects every modified object. To end it: remove gclone at <https://myaccount.google.com/permissions> (or
`gclone logout --revoke`), then `gclone login` on each of your devices.

### A page that looks like the viewer

The hosted viewer gives a web page a reason to ask for the vault passphrase — and with that, a phisher a pretext
that did not exist before. A look-alike page does not need this Worker's cooperation or its redirect sign-in: it
can call the open `/device/start` from its own server, show you the code with "to sign in, enter this code at
google.com/device" (Google's real page, naming the real app), collect the token when you do, and then ask for the
passphrase in its own form. Token **and** passphrase: everything. This is the worst case the viewer adds, and it
is an accepted risk; what stands against it is three habits.

1. **A web page never shows a code.** The viewer signs in with a redirect to Google and nothing else. It never
   shows a code and never asks you to enter one at `google.com/device`; its sign-in and unlock screens say so. A
   code belongs to a terminal that you started `gclone login` in. A web page with a code is not gclone.
2. **Let the password manager fill the passphrase; do not type it into a web page.** The passphrase field is a
   login field, so a password manager offers the passphrase on the real address and **not** on a look-alike. If
   it does not offer it, look at the address before anything else.
3. **Open the viewer from your bookmark or home-screen icon**, never from a link in a message, and with
   `https://` — a new browser that is sent to the plain-`http` address by an attacker on the network can be given
   a fake page before the real one ever told it to use `https` only.

**Where to save the passphrase.** In a password manager that Google cannot read: iCloud Keychain, a separate
manager, or Google Password Manager with on-device encryption turned on. If the browser offers to save it and that
would put it into a Google account with standard encryption — Chrome signed in to the same Google account that
holds the vault — decline: Google would then hold the ciphertext, the keyfile and the passphrase. The viewer
cannot see or prevent that prompt; the unlock screen says the same in one sentence.

**On a computer that is not yours.** "Sign out" ends the viewer's session, clears what the page stored and takes
every other tab of the viewer in that browser to the sign-in screen (the Lock button likewise locks them all).
What it cannot reach is **a file you opened in a tab of its own** — a PDF, which the viewer never shows inside its
own page, or an image or text through "Open in a new tab": that tab stays as it is. Close it yourself. It does
**not** sign the browser out of Google: the next person passes Google's page with one click and gets a new viewer
session — ciphertext, the keyfile, the ability to trash — and your Google account. Sign out of Google there too
(the signed-out screen links to it), never tick "Stay signed in" there, and never let that browser save the
passphrase.

**If a browser or device is lost** while signed in to the viewer: `openssl rand -base64 32 | npx wrangler secret
put SEAL_KEY` ends every browser session at once (devices are not affected). The vault was locked when the device
was put away — the viewer locks after 15 minutes without input and after 5 minutes in the background — so what the
finder has is the session: ciphertext and the keyfile, until the cookie's sealed end or the new `SEAL_KEY`. If the
browser had the passphrase saved, treat it as a stolen unlocked device (`docs/SECURITY.md`, "Lost or stolen
device").

## Moving from the browser sign-in (gclone before 0.2.0)

Until 0.2.0 a device logged in through a browser redirect (`/login`, `/callback`, `/token`), a "Web application"
OAuth client and a fourth secret, `SEAL_KEY`. Devices have used the code sign-in since. A device that signed in back
then still holds a refresh token of the **old** client, and Google refreshes a token only for the client that
issued it.

**This Worker no longer refreshes such a login.** `/refresh` serves the device client only; a request of a login
from before 0.2.0 is answered `400 invalid_grant`, and gclone says "This device's login was made with the browser
sign-in of gclone before 0.2.0, and the auth Worker no longer serves it … Run `gclone login`." (exit 4). The device
runs `gclone login` once and is fine after it. (The Workers of gclone 0.2.0 to 0.3.x kept the old client for
`/refresh` in the two `GOOGLE_LEGACY_CLIENT_*` secrets. That branch is closed: the Web application client is the
hosted viewer's now, and its refresh tokens are honoured in the viewer's sealed cookie only — see
[How it works](#how-it-works).)

What that means for the secrets of an existing deployment:

- `GOOGLE_LEGACY_CLIENT_ID` and `GOOGLE_LEGACY_CLIENT_SECRET` **stay** if you use the hosted viewer: they are its
  sign-in. Do not delete the Web application client in the Google console either; its Authorized redirect URI must
  be `https://<host>/callback`. If you do not use the viewer, delete both secrets and the client.
- `SEAL_KEY` is the viewer's session key. Put a **new** value
  (`openssl rand -base64 32 | npx wrangler secret put SEAL_KEY`) — never one that is left over from before 0.2.0.

**Do this before you deploy this version of the Worker**, while the deployed one still serves the old logins: on
every device that signed in before gclone 0.2.0 (its `gclone status` warns about it), update gclone and run
`gclone login` —

- **an attached device first**, and wait for `Signed in again as <you>. Vault unchanged.` before you run
  `gclone login` on any **new** device. A new device whose login sees no vault takes itself for the first device
  and creates a second vault — with `--passphrase-file` without a single question.
- **Do not run `gclone logout`** (nor `--forget` or `--revoke`) on such a device until that line has appeared
  there. `logout` discards the old login, and it cannot be issued again.

Until that line appears nothing on the device is changed: the old login stays on file. The device's `secrets.json`
then carries `"client": "device"`.

If you are coming from a Worker of before 0.2.0 directly: create the device client first (Google console, same
Cloud project: Clients → Create client → **TVs and Limited Input devices**), put its ID and secret as
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, and put the old (Web application) client's pair as
`GOOGLE_LEGACY_CLIENT_ID` and `GOOGLE_LEGACY_CLIENT_SECRET` if you want the viewer. Every device then has to run
`gclone login`; there is no version of the Worker any more that serves both.

**If `gclone login` says the new login cannot see the vault.** It is not yet verified that Google shows files which
were created through one OAuth client to another client of the same Cloud project (the `drive.file` scope gives an
app access to "its own" files). If it does not, the new login finds no vault; gclone then keeps nothing of the new
login and changes nothing on the device. First make sure the right Google account was chosen at Google. If it was:

- **While a Worker of 0.2.0 to 0.3.x is still deployed** (the reason to do the logins before deploying this one),
  the device's old login still works there. Move the vault to the new client: on that device
  `gclone copy : ~/gclone-export` (everything, decrypted, to a local directory); then `gclone logout --forget` and
  `gclone login`, which creates a new vault through the new client (choose a `--vault-name` other than the old one
  to tell the two Drive folders apart); `gclone copy ~/gclone-export :` uploads everything again. On every other
  device: `gclone logout --forget`, then `gclone login`. The old vault folder stays in Drive until you delete it at
  drive.google.com. History and the trash of the old vault are not carried over.
- **With this Worker deployed**, the old login is gone for good. What is left is Google's own interface: download
  the old vault folder at drive.google.com, unzip it, and attach to it as a directory vault
  (`gclone logout --forget`, `gclone login --vault-dir DIR`) — the last resort the error message of
  `VaultNotVisible` has always named. From there `gclone copy : ~/gclone-export` and a new vault as above.

The same open question decides whether the hosted viewer — which signs in through the Web application client —
sees a vault that was made through the device client. It is checked on the first deployment.

## Development

```sh
npm ci
npm run typecheck          # wrangler types && tsc, for src/ and test/
npm test                   # scripts/check-config.mjs, the placeholder ./dist, the scripts' own tests (node --test), then Vitest inside the Workers runtime
npm run smoke              # wrangler dev on ./dist: which paths the asset layer answers, which the Worker, the headers, the https rule
npx wrangler deploy --dry-run   # builds the Worker's script, uploads nothing

npm run viewer:build       # the viewer's bundle into ./dist: ../web-core/build.sh, viewer/build.mjs, scripts/check-dist.mjs
npm run viewer:check       # scripts/check-dist.mjs on ./dist
npm run test:viewer        # the viewer's data layer and the ticket seal in Node (needs ../web-core/pkg and the native gclone binary)
npm run test:browser       # the viewer in Chrome, WebKit and Firefox (viewer/README.md: what it needs)
```

The scripts' own tests (`scripts/*.selftest.mjs`) include the release tooling: `release-bundle.mjs`,
`fetch-viewer.mjs`, `check-release.mjs` and `verify-deployed.mjs` run against a stand-in for `gh` and a local
server — a failing verification stops each of them, a `./dist` with one changed byte or one extra file does not
pass the deploy check, and a host that serves one different byte is reported. `npm run smoke` also runs
`verify-deployed`'s comparison against the local Worker.

The tests need no account, no secrets and no network: Google is a fake behind the injected `fetch`, and nothing is
read from `.dev.vars`. `test/contract.json` is the Worker's boundary as data: the device ↔ Worker routes — the Rust
side (`tests/auth.rs`) checks its fake auth Worker and its client against those cases, so a change to them is a
change for both — and the routes of the hosted viewer (`/`, `/callback`, `/web/*`), which the Rust side only checks
for their shape and which a fake of the `/web/*` routes in the viewer's own tests can be held to.

`npm test` and `npm run smoke` write the placeholder into `./dist` when there is no built viewer
([The viewer's files](#the-viewers-files)). `npm run smoke` starts `wrangler dev` twice on free local ports (once
as `https://viewer.example`, once as `http://viewer.example`), with made-up secrets, and calls only routes that
answer without asking Google.

To run the Worker locally, copy `.dev.vars.example` to `.dev.vars`, fill it in and run `npm run dev`
(`http://localhost:8787`). `npm run dev` is `wrangler dev --upstream-protocol https`: the Worker then sees its
requests as `https://<the host of "routes">/…`, as it does when deployed (wrangler maps the local address,
`Origin` header included). Without that flag wrangler 4.160 hands the Worker `http://` URLs, and the https rule
answers every page with a redirect. With placeholder credentials

```sh
curl -X POST -H 'content-type: application/json' -d '{}' http://localhost:8787/device/start
```

answers `500 client_invalid` (with real ones `200` and a code for `https://www.google.com/device`): Google was
reached and answered. `502 upstream_error` there would mean the Worker cannot reach Google at all.
