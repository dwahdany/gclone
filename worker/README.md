# gclone auth Worker

A small, stateless Cloudflare Worker that is the **one OAuth client** of your gclone devices. It holds the Google
client ID and secret, so no device ever does. It turns one consent at Google into a refresh token for one device
(`gclone login`) and turns refresh tokens into access tokens afterwards. File data never passes through it: devices
talk to Google Drive directly.

The login is Google's device authorization grant (RFC 8628): `gclone login` shows a code, you enter it at
`https://www.google.com/device` in any browser, and the device — which polls the Worker meanwhile — is signed in.
No redirect leads back to the Worker or to the device, so the Worker serves no sign-in pages at all.

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
- [Device-code phishing](#device-code-phishing)
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
login. **Never enter a code that someone sent you** (see [Device-code phishing](#device-code-phishing)).

## Configuration

| Binding | Kind | Value |
|---|---|---|
| `GOOGLE_CLIENT_ID` | secret | the ID of the "TVs and Limited Input devices" client |
| `GOOGLE_CLIENT_SECRET` | secret | its secret — it exists nowhere else |
| `ALLOWED_EMAILS` | secret | comma-separated Google account addresses; empty or not set = nobody. Compared exactly, except for the case of the letters A–Z; an entry with a space inside or a character outside ASCII matches nobody. |
| `GOOGLE_LEGACY_CLIENT_ID`, `GOOGLE_LEGACY_CLIENT_SECRET` | secrets, optional, used only when **both** are set | the "Web application" client of gclone before 0.2.0, for `/refresh` only — see [Moving from the browser sign-in](#moving-from-the-browser-sign-in-gclone-before-020). Not needed for a new setup. |
| `RATE_LIMIT` | rate-limit binding in `wrangler.jsonc` | 30 requests per 60 s and client address (an IPv6 client: per /64) |

The home page says `Status: ready` when the first two are set. With exactly **one** of the two legacy secrets set
it says `Status: ready. Warning: only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set …`: every
login and every device that signed in with gclone 0.2.0 or later works as usual, and only a device that still
holds a login from before 0.2.0 is told `500 server_misconfigured` until both are set or both are deleted. (Each
`wrangler secret put` / `delete` is deployed at once, so the Worker is in that state for a moment whenever the
pair is added or removed.)

There is no KV, D1, R2, Durable Object, queue, cron or service binding: the Worker stores nothing.

These things in `wrangler.jsonc` are **security requirements**. `scripts/check-config.mjs` asserts them before the
tests on every `npm test`; do not change them. The check is an **allowlist**: the file may hold the keys of the
shipped file — `$schema`, `name`, `main`, `compatibility_date`, `compatibility_flags`, `workers_dev`,
`preview_urls`, `routes`, `observability`, `ratelimits` — and nothing else, whatever it is called. In particular:

- **No other binding of any kind** — no KV, D1, R2, Durable Object, queue, service, AI, browser, e-mail, … — and
  no `unsafe` key, whose `unsafe.bindings` can attach any binding type under another name.
- **No `env`.** A wrangler environment does not inherit bindings: `wrangler deploy --env <name>` would deploy a
  Worker without the rate limiter (and the Worker lets every request through when the binding is missing).
  Deploy with plain `wrangler deploy` only.

- **Nothing of a request is stored beyond the Worker's own log line.** No route carries a secret in its URL —
  device codes and tokens travel in POST bodies, which are not part of Cloudflare's request logs — so these four settings under
  `observability` are a second line of defence rather than the only one. They stay as they are:
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
- **The `ratelimits` entry** (`RATE_LIMIT`, 30 / 60 s) is the only binding, with exactly these values.
  `namespace_id` is any integer, as a string, that is unique within your account; change it if another Worker of
  yours already uses `1001`. Besides bounding what one sender can relay to Google, the limit is what keeps one
  sender from mass-producing sign-in codes (see [Device-code phishing](#device-code-phishing)).

`secrets.required` is deliberately not declared: with it `wrangler deploy` fails while a secret is missing, and the
first deploy has to happen before the Google app's branding can name the Worker's host. The Worker checks its configuration on every request
instead.

## Operating it

- **Rotate the client secret.** Google console → the client → add a secret → `npx wrangler secret put
  GOOGLE_CLIENT_SECRET` → delete the old secret in the console. Devices are not affected.
- **Change the allowlist.** `npx wrangler secret put ALLOWED_EMAILS` with the new comma-separated list. It takes
  effect at once, without `wrangler deploy`. Never add a `vars` entry of that name. Removing an address stops new
  logins for it. Its existing tokens are cut off at their next refresh **only if** Google returns an ID token
  there, which is not guaranteed — to be sure, revoke: `gclone logout --revoke`, or remove the app at
  <https://myaccount.google.com/permissions>.
- **After a suspected leak** of the Worker's secrets: rotate the client secret, run
  `gclone logout --revoke` on one device (this ends the login of every device), then `gclone login` on each device.
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

   Requests blocked by the rule never reach the Worker and do not count against its quota; gclone treats the
   block (`429`) like the Worker's own limit and waits. What the rule does **not** do: it counts per address, so
   it bounds each sender — at 5 per 10 seconds one address gets at most 43,200 requests a day through — not the
   total. A flood from many addresses can still exhaust the free quota; only the paid plan removes that limit.
   (Plan details as documented by Cloudflare in late 2026; they change — check the rule builder.)

## What is logged

- The Worker writes at most one line per request: `{"route": "/device/poll", "status": 400, "error": "authorization_pending"}` —
  the route, the status and an error code. Never a request body, a query string, a header, a device code, a user
  code, a token or an e-mail address. (A login that waits therefore logs one `authorization_pending` line every 5
  seconds: that is the normal state, not a fault.)
- The Workers Logs view stores these lines. Cloudflare attaches the triggering request to each stored event; the
  configuration removes the query string from that URL and keeps invocation logs and traces off (see
  [Configuration](#configuration)). Do not relax those settings, and do not add Logpush, a tail consumer or an
  observability destination.
- `npx wrangler tail` prints the method and the URL of every request on your terminal while it runs. No route of
  this Worker carries a secret in its URL, and request bodies are not shown.
- Cloudflare still processes request metadata (IP address, time, URL path) at the platform level. The Worker's
  privacy page says so.

## Troubleshooting by error code

Every error — on the three JSON routes and for anything else the Worker refuses — is answered as
`{ "error": "<code>", "message": "…" }`; gclone turns the codes into its own messages.

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `authorization_pending` | 400 | `/device/poll`: nobody has entered the code at Google yet. Not a fault: gclone polls again. | Enter the code the terminal shows at `https://www.google.com/device`. |
| `slow_down` | 400 | `/device/poll`: Google wants fewer polls. gclone waits 5 seconds longer between them from then on. | Nothing. |
| `expired_token` | 400 | `/device/poll`: the code was not entered within its lifetime (30 minutes). | Run `gclone login` again. |
| `access_denied` | 403 | The consent was refused at Google — by you ("Cancel"), by an administrator's policy, or because an Internal app was used from outside the organisation. The message carries Google's code. | Run `gclone login` again and approve; otherwise check the Audience setting and the Workspace policy. |
| `invalid_grant` | 400 | `/device/poll`: the device code is unknown, or its login was already completed (a code is good for one login). `/refresh`: the refresh token is revoked, expired or was unused for six months — or it is a login from gclone before 0.2.0 and the Worker has no legacy client (the message says so). | Run `gclone login` again. |
| `server_misconfigured` | 500 | On every route: `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_SECRET` is missing; the home page says `Status: not configured`. On `/refresh` for a login from before gclone 0.2.0 only (the message names the pair): exactly one of the two `GOOGLE_LEGACY_CLIENT_*` secrets is set; the home page says `Status: ready` with a warning, and everything else works. | Put the secrets (step 3). The legacy pair: set both, or delete both. |
| `client_invalid` | 500 | Google does not accept the OAuth client: wrong client ID or secret, a deleted client, a client that is not of type "TVs and Limited Input devices" (`invalid_client` on `/device/start`), or one that may not ask for gclone's scopes. The message carries Google's code. | Compare the two secrets with the console and check the client's type. A deleted client can be restored in the console for about 30 days. |
| `email_not_allowed` | 403 | The Google account that signed in is not in `ALLOWED_EMAILS`, or its address is not verified. The Worker revoked that grant. The message shows the account masked — first character and domain, `s***@example.net` — enough to see which of your accounts was chosen; the full address is never returned, because anyone can poll. | Sign in with the right account, or add the address (`npx wrangler secret put ALLOWED_EMAILS`). An empty list allows nobody. |
| `grant_unusable` | 403 | `/device/poll`, right after you approved: Google issued the login — the code is used up — but its answer lacks something the Worker needs, and the message says what: no ID token (without the account's address `ALLOWED_EMAILS` cannot be applied), an ID token that is not Google's for this client, or no refresh token. Nothing was handed out. gclone stops at once and shows the message. | Once: run `gclone login` again. Every time: see "Other symptoms" below. |
| `scope_missing` | 403 | Google did not grant access to Drive files (the box was unticked on the consent screen). | Run `gclone login` again and approve every permission on the consent screen. |
| `scope_not_allowed` | 403 | Google granted **more** than `openid`, `email` and `drive.file` — the message names what. The Worker hands out no token for such a grant, on `/device/poll` or on `/refresh`. The Worker itself only ever asks for those three, so this is not expected; it would mean that the account holds an older, wider grant for this Cloud project and Google reports it. | Remove gclone at <https://myaccount.google.com/permissions> (this signs out every device), then `gclone login` on each device. |
| `invalid_request` | 400 | The request is malformed. | Update gclone. |
| `rate_limited` | 429 | More than 30 requests in 60 s from one address. `Retry-After: 60`. | Wait a minute. gclone waits by itself; a login in progress goes on afterwards. |
| `upstream_error` | 502 | Google gave no answer the Worker could use: its sign-in service was unreachable, timed out, rate-limited the client, or answered with an error the Worker does not know. Nothing was consumed. | Try again later. A login in progress polls again by itself, with a longer pause after every failure in a row (up to a minute). |
| `payload_too_large`, `unsupported_media_type`, `method_not_allowed`, `not_found` | 413, 415, 405, 404 | Not a gclone request, a wrong auth URL — or a gclone older than 0.2.0, whose `/login`, `/callback` and `/token` routes no longer exist. | Check the URL given to `gclone login`: it is the Worker's base URL, without a path. Update gclone. |

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
  enter it. See [Device-code phishing](#device-code-phishing).

## How it works

| Route | Called by | Purpose |
|---|---|---|
| `GET /` | browser, Google reviewers | home page with `Status: ready` or `Status: not configured` |
| `GET /privacy` | browser | privacy statement |
| `POST /device/start` | device | asks Google for a device code and a user code (the Worker's client ID, the fixed scope `openid email drive.file`) and passes Google's answer on |
| `POST /device/poll` | device, every few seconds | asks Google's token endpoint for the device code, adding the client ID and secret; passes the pending states on; on success checks the grant and hands out this device's refresh token |
| `POST /refresh` | device | refresh token → access token |

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
`{ "access_token", "expires_in", "scope" }`. `"client"` names the OAuth client that issued the token: `"device"`,
or absent for a login made before gclone 0.2.0. Then the legacy client is used when both of its secrets are set;
with neither the answer is `400 invalid_grant` ("run `gclone login` again"), with only one
`500 server_misconfigured`.

Every answer carries `Cache-Control: no-store`; there are no cookies and no CORS headers. The three JSON routes take
`application/json` bodies of at most 8 KiB, are rate-limited, and pre-filter what they pass to Google (a device code
or refresh token of the wrong shape never leaves the Worker).

The Worker keeps no state: Google holds the pending login, and the device carries its device code from one request
to the next. `/device/poll` hands out tokens only when Google's ID token names a verified address in
`ALLOWED_EMAILS` (it revokes the grant of anyone else), and only when Google granted exactly gclone's scopes —
`openid`, `email`, `drive.file` — and nothing beyond them; `/refresh` checks the allowlist (when Google sends an ID
token) and the scopes again. The Worker never redirects anywhere.

Source: `src/index.ts` (routing and the three JSON routes), `src/google.ts` (everything said to Google),
`src/pages.ts` (the two HTML pages). No runtime dependency.

## Device-code phishing

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

## Moving from the browser sign-in (gclone before 0.2.0)

Until 0.2.0 the login went through a browser redirect (`/login`, `/callback`, `/token`), a "Web application" OAuth
client and a fourth secret, `SEAL_KEY`. All of that is gone. A device that signed in back then still holds a refresh
token of the **old** client, and Google refreshes a token only for the client that issued it — so the Worker can
keep the old client for `/refresh`, in two optional secrets, until every device has signed in again.

1. **Google console**, same Cloud project: Clients → Create client → **TVs and Limited Input devices**. Do not
   delete the old client yet.
2. **The Worker**, in this order (the device that is already signed in keeps working throughout):

   ```sh
   npx wrangler secret put GOOGLE_LEGACY_CLIENT_ID       # the OLD (Web application) client's ID
   npx wrangler secret put GOOGLE_LEGACY_CLIENT_SECRET   # its secret; lost it? add a second secret to the old client in the console
   npx wrangler deploy                                   # this version of the Worker
   npx wrangler secret put GOOGLE_CLIENT_ID              # the NEW (TVs and Limited Input devices) client's ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET          # its secret
   npx wrangler secret delete SEAL_KEY                   # no longer used
   ```

   `curl https://<host>/` must answer `Status: ready`.
3. **Each device**: update gclone to 0.2.0 or newer. An older gclone goes on refreshing through the legacy client
   but can no longer log in (its routes are gone).

   **Before step 4, two things that can cost you the only login that is known to see the vault** (whether a login
   of the new client sees a vault made through the old one is not verified yet — see below):

   - **Start with a device that is already attached to the vault**, and wait for
     `Signed in again as <you>. Vault unchanged.` before you run `gclone login` on any **new** device. A new device
     whose login sees no vault takes itself for the first device and creates a second vault — with
     `--passphrase-file` without a single question.
   - **Do not run `gclone logout`** (nor `--forget` or `--revoke`) on a device from before 0.2.0 until that line
     has appeared there. `logout` discards the old login, and it cannot be issued again: gclone 0.2.0 and this
     Worker only know the code sign-in.

   (A device from before 0.2.0 that holds a login but was never attached to a vault is covered by gclone itself:
   its `gclone login` does not create a vault when the new login sees none, and keeps the old login; it says so and
   names `--new-vault` for the case that there really is none.)
4. **Each device**, an attached one first: `gclone login`. It says that the login on file is from the browser
   sign-in, shows a code, and ends with `Signed in again as <you>. Vault unchanged.` The device's `secrets.json`
   now carries `"client": "device"`. Until that line appears nothing on the device is changed: the old login stays
   in use.
5. **When every device has done that**: `npx wrangler secret delete GOOGLE_LEGACY_CLIENT_ID`,
   `npx wrangler secret delete GOOGLE_LEGACY_CLIENT_SECRET`, and delete the old client in the Google console.
   Each of the two commands is deployed at once; between them the Worker has half a pair, which stops nothing but
   a refresh of a login from before 0.2.0 (the home page shows a warning until the second delete — do run it).
   A device that was forgotten gets "This device's login was made with the browser sign-in of gclone before 0.2.0
   … Run `gclone login`." at its next command (exit 4) and is fine after it.

**If `gclone login` says the new login cannot see the vault.** It is not yet verified that Google shows files which
were created through one OAuth client to another client of the same Cloud project (the `drive.file` scope gives an
app access to "its own" files). If it does not, the new login finds no vault. gclone then keeps nothing of the new
login and changes nothing on the device — it goes on using the legacy login, which works as long as the two legacy
secrets are there. First make sure the right Google account was chosen at Google. If it was, the ways out are:

- **Stay as you are for now.** Keep the legacy secrets and the old client. Devices that are already attached keep
  working. A *new* device cannot join that vault, though: it would find no vault and create a second one — stop
  it with Ctrl-C at the passphrase prompt, and do not give it `--passphrase-file`, with which there is no prompt.
- **Move the vault to the new client.** On a device that still works: `gclone copy : ~/gclone-export` (everything,
  decrypted, to a local directory). Then `gclone logout --forget` and `gclone login`: this creates a new vault
  through the new client (choose a `--vault-name` other than the old one to tell the two Drive folders apart).
  `gclone copy ~/gclone-export :` uploads everything again. On every other device: `gclone logout --forget`, then
  `gclone login`. The old vault folder stays in Drive until you delete it at drive.google.com. History and the
  trash of the old vault are not carried over.
- **Leave Google's API behind for the old vault**: download the old vault folder at drive.google.com, unzip it, and
  attach to it as a directory vault (`gclone logout --forget`, `gclone login --vault-dir DIR`) — the last resort
  the error message of `VaultNotVisible` has always named.

## Development

```sh
npm ci
npm run typecheck          # wrangler types && tsc, for src/ and test/
npm test                   # scripts/check-config.mjs, the scripts' own tests (node --test), then Vitest inside the Workers runtime
npx wrangler deploy --dry-run   # builds the bundle, uploads nothing
```

The tests need no account, no secrets and no network: Google is a fake behind the injected `fetch`, and nothing is
read from `.dev.vars`. `test/contract.json` is the device ↔ Worker contract as data; the Rust
side (`tests/auth.rs`) checks its fake auth Worker and its client against the same file, so a change to it is a
change for both.

To run the Worker locally, copy `.dev.vars.example` to `.dev.vars`, fill it in and run `npm run dev`
(`http://localhost:8787`). With placeholder credentials

```sh
curl -X POST -H 'content-type: application/json' -d '{}' http://localhost:8787/device/start
```

answers `500 client_invalid` (with real ones `200` and a code for `https://www.google.com/device`): Google was
reached and answered. `502 upstream_error` there would mean the Worker cannot reach Google at all.
