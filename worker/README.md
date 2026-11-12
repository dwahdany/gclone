# gclone auth Worker

A small, stateless Cloudflare Worker that is the **one OAuth client** of your gclone devices. It holds the Google
client ID and secret, so no device ever does. It turns one browser consent into a refresh token for one device
(`gclone login`) and turns refresh tokens into access tokens afterwards. File data never passes through it: devices
talk to Google Drive directly.

You set it up **once** — not once per device. Afterwards every device is connected with
`gclone login https://<host>`.

Nothing in this directory is deployed by a test or a build. Deploying is the one-time setup below, done by you.

- [One-time setup](#one-time-setup)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Custom domain and rate-limiting rule (recommended)](#custom-domain-and-rate-limiting-rule-recommended)
- [What is logged](#what-is-logged)
- [Troubleshooting by error code](#troubleshooting-by-error-code)
- [How it works](#how-it-works)
- [Development](#development)

## One-time setup

You need a Cloudflare account (the free plan is enough), a Google account, Node 20 or newer, and `openssl` and `curl`.

`./setup.sh` walks through steps 1, 3 and 4 and prints the checklist of step 2 with your URLs filled in. It first
asks where the Worker is to be served: on its `workers.dev` host, or on a host name of your own.

**Decide that before step 1.** The Worker's URL goes into the Google client (redirect URI, home page and privacy
links, authorized domain) and into every device's login. If you want a
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
npx wrangler deploy
```

Note the URL it prints, `https://gclone-auth.<acct>.workers.dev`. This is your **auth URL**; `<host>` below is its
host name and `<acct>.workers.dev` its domain. (With a custom domain from the start the auth URL is
`https://auth.example.org`, `<host>` is `auth.example.org`, and the domain for step 2.3 is the **registrable**
domain, `example.org`.) Until step 3 is done the home page says `Status: not configured` and
every other route answers `500 server_misconfigured`. That is expected: the Google client of step 2 needs the
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
5. **Clients** → **Create client** → Application type **Web application** → Authorized redirect URI
   `https://<host>/callback` — exactly that, and no JavaScript origins. Copy the client ID and the client secret
   **now**: the secret is shown only once.

Workspace users may choose Audience **Internal** instead of External + Publish. Console changes can take from five
minutes to a few hours to apply.

### 3. The four secrets

```sh
npx wrangler secret put GOOGLE_CLIENT_ID        # the client ID from step 2.5
npx wrangler secret put GOOGLE_CLIENT_SECRET    # its secret
openssl rand -base64 32 | npx wrangler secret put SEAL_KEY
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

The URL is needed once per device; gclone remembers it. The browser shows a confirmation page with a **check code**
before Google's consent screen and again after it; continue only if the terminal shows the same code. The second
page is the one that counts: nothing is signed in until you follow its link.

## Configuration

| Binding | Kind | Value |
|---|---|---|
| `GOOGLE_CLIENT_ID` | secret | the Web-application client's ID |
| `GOOGLE_CLIENT_SECRET` | secret | its secret — it exists nowhere else |
| `SEAL_KEY` | secret | 32 random bytes in base64 (`openssl rand -base64 32`) |
| `ALLOWED_EMAILS` | secret | comma-separated Google account addresses; empty or not set = nobody |
| `RATE_LIMIT` | rate-limit binding in `wrangler.jsonc` | 30 requests per 60 s and client address (an IPv6 client: per /64) |

There is no KV, D1, R2, Durable Object, queue, cron or service binding: the Worker stores nothing.

These things in `wrangler.jsonc` are **security requirements**. `scripts/check-config.mjs` asserts them before the
tests on every `npm test`; do not change them:

- **No request URL with its query string is stored.** The query string of `/callback` carries Google's
  authorization code. Four settings under `observability` keep it out of the account's logs, and all four are
  needed:
  - `logs.invocation_logs` is `false`: with invocation logs on, Cloudflare stores one log entry per request with the
    full URL, kept for days and readable by anyone with log access to the account.
  - `redact_query_string` is `true`: Cloudflare attaches the request that triggered an invocation to **every**
    stored log event — also to the Worker's own one-line logs — and to traces. This switch removes the query string
    from those URLs. It needs wrangler 4.160 or newer (`package.json` requires it); an older wrangler would ignore
    the key.
  - `traces.enabled` is `false`: traces record request URLs too, and are not needed.
  - no `destinations` under `logs` or `traces`, no `tail_consumers`, no `logpush`: nothing exports logs or traces
    out of the account.

  This is Cloudflare's documented behaviour, not something a test here can observe. **Check it once after the first
  real login**: dashboard → Workers & Pages → `gclone-auth` → Observability → open the event of a `/callback`
  request and look at its URL field (`$metadata.url` / `$workers.event.request.url`). It must end at `/callback`,
  without `?code=…`. If the query string is there, set `"observability": { "enabled": false }` (Workers Logs off
  altogether; adjust `scripts/check-config.mjs` accordingly) and deploy again.
- **`preview_urls` is `false`.** Preview URLs would keep every uploaded version of the Worker reachable under its
  own `<version>-gclone-auth.<acct>.workers.dev` host — also an old version from before a fix, and outside any
  zone rule of a custom domain.
- **There is no `vars` key.** Vars and secrets share one namespace: while a deployed version has a var
  `ALLOWED_EMAILS`, `wrangler secret put ALLOWED_EMAILS` is refused, and every `wrangler deploy` from a file with
  `"vars": { "ALLOWED_EMAILS": "" }` would put the empty list back — every login refused. The allowlist therefore
  is a secret only, and it never sits in a tracked file.
- **The `ratelimits` entry** (`RATE_LIMIT`, 30 / 60 s) is the only binding. `namespace_id` is any integer, as a
  string, that is unique within your account; change it if another Worker of yours already uses `1001`.

`secrets.required` is deliberately not declared: with it `wrangler deploy` fails while a secret is missing, and the
first deploy has to happen before the Google client exists. The Worker checks its configuration on every request
instead.

## Operating it

- **Rotate the client secret.** Google console → the client → add a secret → `npx wrangler secret put
  GOOGLE_CLIENT_SECRET` → delete the old secret in the console. Devices are not affected.
- **Rotate `SEAL_KEY`.** `openssl rand -base64 32 | npx wrangler secret put SEAL_KEY`. Only logins that are in
  flight at that moment fail; run `gclone login` again.
- **Change the allowlist.** `npx wrangler secret put ALLOWED_EMAILS` with the new comma-separated list. It takes
  effect at once, without `wrangler deploy`. Never add a `vars` entry of that name. Removing an address stops new
  logins for it. Its existing tokens are cut off at their next refresh **only if** Google returns an ID token
  there, which is not guaranteed — to be sure, revoke: `gclone logout --revoke`, or remove the app at
  <https://myaccount.google.com/permissions>.
- **After a suspected leak** of the Worker's secrets: rotate the client secret and `SEAL_KEY`, run
  `gclone logout --revoke` on one device (this ends the login of every device), then `gclone login` on each device.
- **Cost and limits.** A login is 4 requests, a refresh 1 per device and hour of use — far inside the free plan's
  100,000 requests per day for your own use. The built-in limit of 30 requests per 60 s and client address (answer
  `429`) limits how much junk one sender can relay to Google through your OAuth client. An IPv6 client is counted
  by its /64 prefix — one host owns at least a whole /64, so a per-address count would not limit it at all. The
  limit is approximate (Cloudflare counts per location) and it does not stop a sender with many networks. It also
  runs inside the Worker: a refused request is still a request. On `*.workers.dev` a flood of about one request per
  second uses up the free plan's daily quota and stops all token refreshes until midnight UTC. The custom domain
  below with a zone rate-limiting rule stops that for any single sender (the rule counts per address, so it bounds
  each sender, not all of them together); the paid plan has no daily cap at all.
- **If the Worker is lost.** Deploy again from this directory and put the four secrets again (a new client secret
  can be added to the same Google client). Devices keep their refresh tokens; nothing else changes as long as the
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
   `https://auth.example.org/` and `https://auth.example.org/privacy`, and add `https://auth.example.org/callback`
   as a second **Authorized redirect URI** of the client.
3. Check: `curl https://auth.example.org/` answers `Status: ready`, and the old `workers.dev` URL no longer answers.
4. On every device: `gclone login https://auth.example.org`.
5. Add one zone rate-limiting rule (Security → WAF → Rate limiting rules) that covers **every path of the
   Worker's host**. Not only `/login`, `/callback`, `/token` and `/refresh`: the home page, `/privacy` and any
   path that does not exist are answered by the Worker too, and each of those requests counts against the daily
   quota exactly like a login does.

   - Counted per IP address, action **Block**, **5 requests per 10 seconds**. A login is 4 requests spread over
     the time it takes to read two pages, a refresh is 1; if a login ever gets blocked, wait ten seconds, and raise
     the number to 10 if it keeps happening. Do not go higher: 20 per 10 seconds would let one address send
     172,800 requests a day without ever being blocked — more than the whole free quota.
   - Which requests the rule matches depends on the zone's plan:
     - **Pro and above**: the host — `http.host eq "auth.example.org"`.
     - **Free** (one rule; the expression can use the URI path only; 10-second period and 10-second block):
       the rule cannot name a host, so it applies to the whole zone. `starts_with(http.request.uri.path, "/")`
       matches everything — the right rule when the zone serves nothing but the Worker (a spare domain is the
       simple way), and too strict for a zone that also serves a website, where a page view is many requests. On
       such a zone the Free plan has no rule that covers the Worker's unknown paths without also limiting the
       site; use a zone of its own for the Worker, the Pro plan, or the Workers paid plan (no daily cap).

   Requests blocked by the rule never reach the Worker and do not count against its quota; gclone treats the
   block (`429`) like the Worker's own limit and waits. What the rule does **not** do: it counts per address, so
   it bounds each sender — at 5 per 10 seconds one address gets at most 43,200 requests a day through — not the
   total. A flood from many addresses can still exhaust the free quota; only the paid plan removes that limit.
   (Plan details as documented by Cloudflare in late 2026; they change — check the rule builder.)

## What is logged

- The Worker writes at most one line per request: `{"route": "/token", "status": 400, "error": "invalid_grant"}` —
  the route, the status and an error code. Never a request body, a query string, a header, a code, a token or an
  e-mail address.
- The Workers Logs view stores these lines. Cloudflare attaches the triggering request to each stored event; the
  configuration removes the query string from that URL and keeps invocation logs and traces off (see
  [Configuration](#configuration), including the one-time check). Do not relax those settings, and do not add
  Logpush, a tail consumer or an observability destination: each would store or export every `/callback` URL with
  Google's authorization code in it.
- **`npx wrangler tail` is different: it prints the method and the full URL of every request**, query string
  included, on your terminal while it runs — the Worker's configuration has no say in that. Nothing is stored, but
  do not run it during a login with the output going anywhere you would not put a sign-in code (a shared screen, a
  saved log, a ticket). A code seen there is single-use and useless without the device's verifier.
- Cloudflare still processes request metadata (IP address, time, URL path) at the platform level. The Worker's
  privacy page says so.

## Troubleshooting by error code

The JSON routes (`/token`, `/refresh`) answer errors as `{ "error": "<code>", "message": "…" }`; gclone turns them
into its own messages. The browser routes show a page instead.

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `server_misconfigured` | 500 | `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_SECRET` is missing, or `SEAL_KEY` does not decode to exactly 32 bytes. The home page says `Status: not configured`. | Put the secrets (step 3). `SEAL_KEY` must be the output of `openssl rand -base64 32`. |
| `client_invalid` | 500 | Google does not accept the OAuth client: wrong client ID or secret, a deleted client, or the redirect URI the Worker sent is not registered. | Compare the two secrets with the console. The redirect URI must be exactly `https://<host>/callback` for the host the devices use. A deleted client can be restored in the console for about 30 days. |
| `email_not_allowed` | 403 | The Google account that signed in is not in `ALLOWED_EMAILS`, or its address is not verified. The Worker revoked that grant. | Sign in with the right account, or add the address (`npx wrangler secret put ALLOWED_EMAILS`). An empty list allows nobody. |
| `scope_missing` | 403 | Google did not grant access to Drive files. | Run `gclone login` again and approve every permission on the consent screen. |
| `scope_not_allowed` | 403 | Google granted **more** than `openid`, `email` and `drive.file` — the message names what. The Worker hands out no token for such a grant, on `/token` or on `/refresh`. The consent screen you approved did not come from an unmodified `gclone login` link (someone changed its `scope`), or the account holds an older, wider grant for this app. | If you did not expect it: remove gclone at <https://myaccount.google.com/permissions> (this signs out every device), then `gclone login` on each device. Never approve a consent screen for gclone that asks for more than the specific Google Drive files you use with this app — all of your Drive, for example. |
| `access_denied` | 403 | Google refused: an administrator's policy, or an Internal app used from outside the organisation. The message carries Google's code. | Check the Audience setting and the Workspace policy. |
| `invalid_grant` | 400 | `/token`: the sign-in code expired (2 minutes), was already used, was made for another device, or Google's ID token did not carry the nonce of this login. `/refresh`: the refresh token is revoked, expired or was unused for six months. | Run `gclone login` again. If **every** login ends here, see the note below the table. |
| `invalid_request` | 400 | The request is malformed. | Update gclone. |
| `rate_limited` | 429 | More than 30 requests in 60 s from one address. `Retry-After: 60`. | Wait a minute. gclone retries once by itself. |
| `upstream_error` | 502 | Google's token service was unreachable, timed out or gave an unusable answer. | Try again later. |
| `payload_too_large`, `unsupported_media_type`, `method_not_allowed`, `not_found` | 413, 415, 405, 404 | Not a gclone request, or a wrong auth URL. | Check the URL given to `gclone login`: it is the Worker's base URL, without a path. |

Other symptoms:

- **Google shows "Error 400: redirect_uri_mismatch"** after *Continue with Google*: the client has no redirect URI
  `https://<host>/callback` for the host in the address bar (scheme, host and path must match exactly).
- **Google shows "Access blocked" or a testing warning**, or `gclone login` reports that the login expires in 7
  days: the app is still in Testing — Audience → **Publish app**.
- **A page says "This sign-in link is invalid or has expired"**: more than 10 minutes passed on Google's consent
  screen, more than 2 minutes on the confirmation page after it, or `SEAL_KEY` was rotated meanwhile. Run
  `gclone login` again.
- **Every login ends in `invalid_grant` although the code is fresh**: Google's ID token would have to lack the
  `nonce` the Worker sent. OpenID Connect requires Google to echo it, so this is not expected; the Worker fails
  closed here on purpose, because the nonce is what ties Google's code to the device that started the login.
- **The check code on a page differs from the terminal's, or a page with a check code appears although you did not
  just run `gclone login`**: close the page. The link did not come from a login of yours. The page shown after
  Google's consent screen is the one nobody can make you skip; as long as you do not follow its link, nothing is
  signed in.

## How it works

| Route | Called by | Purpose |
|---|---|---|
| `GET /` | browser, Google reviewers | home page with `Status: ready` or `Status: not configured` |
| `GET /privacy` | browser | privacy statement |
| `GET /login` | browser, opened by the device | seals the request into `state`; shows the confirmation page with the check code and the link to Google — it never redirects |
| `GET /callback` | browser, redirected by Google | shows the check code again, with one link that carries Google's authorization code in a sealed blob — no redirect and no grant yet |
| `GET /callback?confirmed=…` | browser, the link of that page | seals Google's code into a *grant* and hands it to the device: a redirect to `http://127.0.0.1:<port>/`, or a page with a `gclone-code1_…` string to paste |
| `POST /token` | device | redeems a grant for this device's refresh token |
| `POST /refresh` | device | refresh token → access token |

The Worker keeps no state. `state`, the blob in the confirmation link and the grant are AES-256-GCM blobs under
keys derived from `SEAL_KEY`; a grant opens only with the verifier of the device that started the login, and Google's
code is redeemed at most 120 seconds after the second confirmation page was served. Google's code is tied to that device by an OpenID
Connect nonce derived from the device's challenge, which `/token` checks in the ID token it receives from Google.
`/token` hands out tokens only for an account in `ALLOWED_EMAILS` (it revokes the grant of anyone else) and only
when Google granted exactly gclone's scopes — `openid`, `email`, `drive.file` — and nothing beyond them; `/refresh`
checks the scopes again. The only redirect target the Worker has is `http://127.0.0.1:<port>/`.

Why two confirmation pages: `/login` is unauthenticated, so anyone can fetch it and send the link to Google's
consent screen to someone else, who then never sees the first page. Google sends every consent back to `/callback`,
so the check code is shown there, and only the link on that page completes the login.

Source: `src/index.ts` (routing and the six routes), `src/seal.ts` (sealed blobs, check code, nonce),
`src/google.ts` (everything said to Google), `src/pages.ts` (the HTML pages). No runtime dependency.

## Development

```sh
npm ci
npm run typecheck          # wrangler types && tsc, for src/ and test/
npm test                   # scripts/check-config.mjs, the scripts' own tests (node --test), then Vitest inside the Workers runtime
npx wrangler deploy --dry-run   # builds the bundle, uploads nothing
```

The tests need no account, no secrets and no network: Google is a fake behind the injected `fetch`, the clock is
fixed, and nothing is read from `.dev.vars`. `test/contract.json` is the device ↔ Worker contract as data; the Rust
side (`tests/auth.rs`) checks its fake auth Worker and its client against the same file, so a change to it is a
change for both.

To run the Worker locally, copy `.dev.vars.example` to `.dev.vars`, fill it in and run `npm run dev`
(`http://localhost:8787`). With placeholder credentials

```sh
curl -X POST -H 'content-type: application/json' -d '{"refresh_token":"xxxxxxxxxxxxxxxxxxxxxxxx"}' http://localhost:8787/refresh
```

answers `500 client_invalid` (with real ones `400 invalid_grant`): Google was reached and answered. `502
upstream_error` there would mean the Worker cannot reach Google at all.
