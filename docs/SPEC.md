# gclone — final implementation spec (v1.2, 2026-11-11, review round 2 + auth redesign + review round 3 applied; errata of WP0 and of integration waves 1 (WP1, WP2, WP8), 2 (WP3, WP4, WP5), 3 (WP6) and 4 (WP7), and of the final pass: §17; review round 4 — worker security: §17.7, crypto and formats: §17.8, auth client: §17.9, Drive API: §17.10, index and local state: §17.11, sync engine: §17.12, transfer: §17.13, command line and setup: §17.14; download durability in batches: §17.15, and its review — a barrier for every writer of base state, sync through the writing descriptor: §17.16; Linux builds, releases and the installer: §17.17; **0.2.0 — the login is Google's device authorization grant, proxied by the Worker: §0.6, §2, §16, §17.18; its review: §17.19; 0.3.0 — `gclone web`, the vault in a browser: §7.4, §17.20; its review: §17.21**)

Single-binary Rust CLI that stores files on Google Drive with client-side authenticated encryption, for ONE user with several devices — an rsync-style sync tool (no mount) — plus one small Cloudflare Worker (`worker/`, TypeScript) that is the user's single OAuth client. This document is the contract for parallel implementation. Companion: `RESEARCH.md` (verified facts; every `[U]` there is still unverified; its §6 covers the auth redesign).

Conventions: all integers big-endian unless stated; `‖` is concatenation; KiB/MiB are binary; "MUST/NEVER" are normative. Section numbers are referenced from the work packages (§12).

Build note for this machine: plain `cargo` is a rustup shim without a toolchain. Use `nix-shell -p cargo rustc --run 'cargo …'`. The Worker's tests need Node ≥ 20: `nix-shell -p nodejs --run 'cd worker && npm ci && npm test'`. Nothing in this spec is deployed by the implementation work — deploying the Worker is the user's one-time setup (§2.1).

---

## 0. Architecture in one page

- **Drive is a dumb, ID-addressed store of immutable, put-once ciphertext objects.** No mirrored tree, no encrypted file names, no `appProperties`, no Changes API, no object is ever overwritten.
- **The directory tree lives in an encrypted, append-only, per-device journal** (`index/`): small immutable *segments* plus periodic *snapshots*. Every device keeps a full replica in SQLite. Listing `index/` (normally one API call) is the only remote listing a normal command performs.
- **Small files (< 1 MiB) are packed** into ~16 MiB blobs; larger files are one blob each. An index entry is `(blob, offset, length, salt)`.
- **Merge = version heads with base pointers** (§5.2): causal successors replace, concurrent writes produce deterministic conflict copies, a put beats a concurrent delete. **Planner = three-way** over a per-device base table (§5.5): a stale device can neither overwrite nor delete what it has not seen.
- **Crypto**: one container format (HKDF-SHA-256 per-object key + ChaCha20-Poly1305 STREAM with age's nonce layout + key-commitment tag). Sealed bytes are only ever replayed, never regenerated: a new salt always means a new object ID.
- **Auth**: ONE Google OAuth client of type *TVs and Limited Input devices*, scopes `openid email drive.file`, "In production". Its ID and secret live only in a small stateless Cloudflare Worker (§16); no device ever holds them. `gclone login` — the same command for the first and for every later device, with or without a browser on the machine — is Google's **device authorization grant** (RFC 8628) proxied by the Worker: the device asks the Worker for a code, shows it, the user enters it at `https://www.google.com/device`, and the device polls the Worker until Google hands out **its own** refresh token (§2.3, §2.4). Access tokens are refreshed through the Worker; file data flows device ↔ Google directly, never through the Worker.
- **Key distribution**: a random master key, wrapped under a user **passphrase** (Argon2id, 256 MiB) and stored as a small keyfile object in the vault (§2.6). A new device logs in, finds the vault, asks for the passphrase once and caches the unwrapped key in a 0600 file. No secret is ever copied between devices: there is no kit and no `link`/`join`.

### 0.1 Where this spec takes each idea from
| Area | Source | Notes |
|---|---|---|
| Journal with inner identity, `prev` chain, `seen` refs, coverage sets, rollback marks | security design | made fork-tolerant, with repair paths, auto-compaction, process lock; marks are trust-on-first-use on a new device since v1.2 |
| Merge rule + 3-way planner + conflict copies | security design | reformulated as order-independent "heads" (§5.2) |
| SQLite state, kernel lock, durable pending ops, md5 verify, upload ledger, quota-unit pacer, per-device data folders, pre-generated IDs for everything | perf design | cross-restart resume, inode cache and blob manifest trailer cut |
| Zero daily prompts, `:path` syntax, `--vault-dir`, targeted error messages, excluded-never-deleted, path-ordered packs | UX design | the kit / `link` / `join` of that design are replaced by `login` + passphrase keyfile (§0.4) |
| One OAuth client behind a stateless Worker, per-device refresh tokens, passphrase-wrapped keyfile on Drive | user decision (v1.2) | §2, §16 |

### 0.2 Decision log for the critiques' MUST-FIX items
Applied: never re-seal under an existing salt (replay buffers, §6.2); new ID whenever the salt changes + size/md5 check on 409 (§6.2); secrets (passphrase, tokens, keys) never in argv/env (§2.6, §7.1); inner identity + hash chain + exact coverage sets for every index object (§4.6, §5.3); index objects fully buffered and authenticated before parsing (§4.6); KDF parameter floors/ceilings + constant-time compares (§4.3); `key_epoch` in the v1 header (§4.2); three-way planning + causal merge + conflict copies (§5); ctime in the stat signature + racy-timestamp rule, no inode-keyed hash cache (§5.4); scan errors suppress deletes (§5.4); re-stat before every destructive local op (§5.7); explicit case/NFC handling with exact name bytes stored (§5.1); file-vs-directory conflict rule (§5.2.3); blobs verified before pending ops are published, GC two-phase with 30-day grace (§5.8, §5.9); process lock (§8.3); recovery paths for Rollback/Gap, fork tolerance (§5.3, §5.10); automatic compaction, snapshots carry all heads and removed versions (§5.6); durable intent transactions (`synchronous=FULL`); delete guard trips on either threshold (§5.5.2); filters applied to both sides; deletes after uploads; GC scoped to this vault's own data folders (§5.9); unit-aware pacing (§6.5); multipart only ≤ 4 MiB (§6.2); 308 without `Range` = offset 0, status query 200/201 = done (§6.2); `trashed = false` + `nextPageToken` loop + trashed-vault detection (§3.3); setup covers homepage/privacy URL (served by the Worker) and the show-once client secret (§2.1); orphan grace 14 days, server-time ages (§5.9); undelete (`restore`), index republish (`repair`).

Consciously **not** applied (with reason):
1. *Seal local secrets + index cache under a device key (keychain default).* Rejected for the MVP: the user requirement is zero prompts after the one-time unlock, on macOS and headless Linux alike; a device key stored next to the sealed file is theatre; SQLite cannot be sealed cheaply. Secrets are a 0600 file in a 0700 directory, same trust level as an SSH key; at-rest protection is disk encryption (documented, §1.3). `config::SecretStore` is a trait so a keychain store can be added without touching callers (§11).
2. *Rendezvous object / split enrollment.* Cut (two of three critiques): it needs both devices online within minutes and rests on unverified list consistency. (v1.2: nothing is handed from device to device any more; the master key reaches a new device through the passphrase keyfile, §2.6.)
3. *`rotate` / re-key.* Cut (deferred, §14); the header carries `key_epoch` so rotation needs no format break. Grant-wide revocation ships as `gclone logout --revoke` (§2.7).
4. *Argon2 `p=4`.* Not adopted: the `argon2` crate computes lanes sequentially without its `parallel` feature, so `p > 1` would cost the defender time and the attacker nothing; `p = 1` with 256 MiB is used. Passphrase normalisation (NFC) **is** specified now that a human passphrase exists (§2.6).
5. *64 MiB packs / 8 MiB members.* Not adopted until pack compaction exists (1 MiB / 16 MiB instead).
6. *Blob manifest trailer written from day one.* Cut in review round 2: its only reader (`repair --from-blobs`) is deferred, it put a second, under-specified format on the hot path of every upload, and a blob without the `GCBLOB01` footer simply has no manifest, so adding it later is backward compatible. Stream type 0x04 and the footer magic stay reserved (§4.5).

### 0.3 Review round 2 — what changed (details in the sections named; its kit / shared-token / `init` items are superseded by §0.4)
- **Index** (§4.6, §5.2, §5.3, §5.6): snapshot coverage is an exact set of segment identities (`covered`), not a per-device sequence number; rollback marks are statements about the local replica, plus a separate remote-presence check; no collapse in `apply` (identical heads are deduplicated by `resolve_conflicts`); listed snapshots are adopted instead of re-written; cleanup trashes only what every retained snapshot covers; clone detection by own-segment history and a machine fingerprint; a stuck outbox no longer blocks reads.
- **Sync** (§5.1, §5.4, §5.5, §5.7): leftover staged ops are committed before planning; full case folding; one spelling per key; base rows are refreshed after a matching re-hash and after downloads; filters match parents on both sides; file↔directory type changes are ordered groups; the pair identity is `(st_ino, birth time)` and is never dropped silently.
- **Drive / auth** (§2.4, §6.2–§6.5): `refresh_token_expires_in` stops a Testing-mode login; pinned wire shapes; `fields=` on upload initiation; 401 handling inside sessions; `gc --purge`.
- **Formats** (§4.2–§4.5): `Loc` carries `suite`/`flags`; decoder error precedence fixed; the blob manifest trailer is cut.
- **Architecture** (§9, §12): `ui.rs`, time helpers and the conformance suite moved so that WP1–WP6 need no later package; the transfer layer no longer depends on `Vault`; one upload entry point (`upload_batch`); `Vault::finish_mutation`; fallible `HeadStore`; `open_ctx(OpenOpts)`.

### 0.4 v1.2 — auth and key-distribution redesign (user decision: "I never want to set up OAuth clients again, so that Worker is my one OAuth client")
What changed, and what it reverses:
- **One Web-application OAuth client behind a stateless Cloudflare Worker** replaces the Desktop client whose JSON every first device needed. The Worker is specified in §16 and built by WP8 (`worker/**`). No device holds `client_id` or `client_secret`.
- **Every device has its own refresh token**, obtained by `gclone login` through the Worker (§2.3, §2.4). The shared refresh token and its concurrency probe are gone.
- **`login` / `logout` / `passwd` replace `init` / `auth` / `link` / `join`** (§7.1). `login` detects whether a vault exists: none → it creates one; one → it attaches this device (§2.6).
- **A passphrase-wrapped master key is stored on Drive** (keyfile, §2.6). This reverses the earlier MUST-FIX "nothing passphrase-derived on Drive": the user accepted that Google — and Cloudflare, which can obtain a token (§1.3) — can attack a weak passphrase offline; Argon2id at 256 MiB, a 12-character minimum and a generated 100-bit default are the mitigation.
- **The kit format, the pairing code and `format/kit.rs` are removed.** Recovery = Google account + passphrase (or a downloaded vault folder + passphrase, `--vault-dir`). `gclone key export` is deferred (§14).
- **Rollback marks no longer travel**: a new device trusts the first state it is served (trust on first use, §1.3, §5.3); `hw.inherited` and `index::seed_marks` are gone.
- **`gclone logout` does not revoke at Google by default**: Google documents revocation as grant-wide — it "removes all OAuth 2.0 scopes previously granted to a project, invalidating any issued access or refresh tokens for all clients" (RESEARCH §6.3) — so revoking one device's token would sign out every device. `logout` discards the local token; `logout --revoke` is the deliberate "sign out everywhere" (§2.7). *This deviates from the wording of the decision ("logout revokes this device's token"); manual probe 3 (§2.9) decides whether the default can be flipped.*
- Sections touched: §0, §1, §2 (rewritten), §3.1, §3.3, §4.1–§4.3, §4.7, §5.3, §6.4.1, §7, §8, §9.1–§9.4, §9.6, §9.7, §9.10, §10–§15, new §16.

### 0.5 Review round 3 — what changed in the auth and login parts (details in the sections named)
- **Worker** (§2.3, §16): the check-code confirmation page is shown in **both** login modes (no direct redirect to Google); Google's authorization code is bound to the device's challenge by an OIDC `nonce` that `/token` verifies itself; a per-address rate limit (`429 rate_limited`) and syntactic pre-filters stand in front of every call to Google; `/refresh` re-checks the allowlist when Google returns an ID token; no `login_hint`; `ALLOWED_EMAILS` is a secret; invocation logs are off; `defaultDeps` is pinned and tested in the Workers runtime.
- **Contract fixture** (§16.5): `worker/test/contract.json` is checked by the Worker's tests and by WP3's `tests/auth.rs` — WP3 now needs WP8's fixture (§12).
- **Keyfile** (§2.6, §2.7, §9.4): tighter accepted KDF bounds, at most 4 keyfiles tried, overflow-checked generation; the Rust field is `generation` (`gen` is a reserved word in edition 2024), the JSON name stays `"gen"`.
- **Device** (§2.4–§2.8, §8, §9.10, §10): `secrets.json` and `token.json` live under the state root and are refused when their permissions are too open; `auth_url` is also kept in `config.json`; the login fields of `Secrets` are optional; `NotLoggedIn` / `Locked` and the backend choice of `login` are defined for both backends; ATTACH saves the key only after the device registered itself; `login` never writes `token.json`; a **head fingerprint** gives a new device a value to compare (§2.6).
- **Packages** (§9.2, §12): `tests/live.rs` (WP7), `worker/package-lock.json` and `worker/scripts/check-config.mjs` (WP8), `Cargo.lock` and the root `.gitignore` (WP0).

### 0.6 v1.3 (gclone 0.2.0) — the login is the device authorization grant (user decision: "can we do polling oauth instead of the localhost thing?")
What changed, and what it reverses (errata and transition: §17.18):
- **`gclone login` uses only Google's device authorization grant** (RFC 8628, client type *TVs and Limited Input devices*): `POST /device/start` → the user enters a code at `https://www.google.com/device` → `POST /device/poll` until the tokens arrive (§2.3, §2.4). One flow for every machine; `--no-browser` only means "do not try to open a browser".
- **The browser-redirect flow is removed**: the Worker's `/login`, `/callback` and `/token` routes and its confirmation pages, the sealed state / pending / grant blobs and `SEAL_KEY`, the OIDC nonce and the check code; on the device the loopback listener, the paste flow and the verifier / challenge. The items of §0.5 that describe them are history.
- **The Worker stays stateless** — now without any blob of its own: Google holds the pending login, the device carries the device code.
- **Two OAuth clients for a while**: refresh tokens issued before 0.2.0 belong to the old *Web application* client. `/refresh` serves them through optional legacy secrets; the device names its client in every `/refresh` and in `secrets.json` (`"client": "device"`; absent = legacy) (§2.3, §8.2).
- **New residual risk: device-code phishing** (§1.3, §2.3.2) in place of the hand-over phishing of the redirect flow.
- Sections touched: §0, §1.1, §1.3, §2.1–§2.6, §2.8, §2.9, §7, §8.2, §9.2, §9.3, §9.6, §9.10, §10–§16; new §17.18.

---

## 1. Goals, non-goals, threat model

### 1.1 Goals
1. One-time setup for the user's lifetime: one Google OAuth client plus one small Cloudflare Worker (§2.1). Every device — the first or the tenth — is connected with one command (`gclone login`), one code entered at Google and, once, the passphrase. No device ever holds OAuth client credentials and no secret is copied between devices.
2. No recurring re-authentication on a device that runs gclone at least once per ~5 months (an idle device needs one `gclone login`, i.e. one code entered at Google).
3. All content, names, tree shape, mtimes and hashes are encrypted and authenticated client-side.
4. Fast: no remote tree walks; small files packed; rename/move/delete/dedup are index-only; parallel transfers; adaptive pacing without tuning flags.
5. Safe multi-device use by default: no silent overwrite, no lockout states, crash-safe, trash instead of delete (permanent deletion only by the explicit `gc --purge`), 25-day undelete.
6. Testable end to end without Google credentials.

### 1.2 Non-goals (MVP)
FUSE mount; two-way `bisync` as one command; multi-user sharing; shared drives; Windows; hiding large-file sizes, object counts or activity timing; snapshots/dedup at chunk level; migrating an existing rclone crypt remote (invisible under `drive.file`).

### 1.3 Threat model
| Adversary | Capability | Outcome |
|---|---|---|
| Curious Google | reads everything stored + request metadata | Learns blob count/sizes (files ≥ 1 MiB to within 0.03 %; smaller files hidden in packs), write timing, per-device journal activity (device IDs and sequence numbers are in index object names), IPs, the account e-mail. Learns no names, tree, mtimes, hashes, contents — **as long as the passphrase resists guessing**: the keyfile (§2.6) lets Google test passphrase guesses offline at Argon2id cost (256 MiB, t = 3 per guess). The generated passphrase (100 bits) is out of reach; a weak typed one is not. Accepted by the user (§0.4). |
| Malicious Google | modify, swap, truncate, reorder, duplicate, delete, withhold, roll back objects | Any byte change, swap, slice, truncation: detected (AEAD + final flag + salt/size/BLAKE3 in the authenticated index). Journal rollback / withheld segments: detected by any device that saw newer state (`Rollback`, `Gap`). A **fresh** device has no marks: it trusts the first state it is served (trust on first use) and detects rollbacks only relative to that; `login` prints a **head fingerprint** to compare with `gclone status` on a device the user trusts — the one check that exposes a stale or truncated journal (§2.6). Deletion is DoS: detected, not prevented. A substituted or old keyfile gains nothing: it either fails to open (leaking nothing — nothing derived from the passphrase is ever sent) or wraps the same master key. Drive-reported md5 is used only against accidental corruption, never as tamper evidence. |
| Cloudflare / whoever controls the Worker or its secrets | sees the OAuth client secret and every refresh and access token passing through `/device/poll` and `/refresh`; can mint access tokens for the account's gclone files | Same reach as Google and no more: ciphertext, metadata, the keyfile (offline passphrase guessing), deletion (DoS; detected as above). Never sees the passphrase, the master key or any file data (data flows device ↔ Google). What the Worker makes the device **show** is bounded too: the sign-in address of `/device/start` is opened in a browser only when it is a `google.com` address, and anything the device prints from the Worker's answers is checked plain text (§2.4) — a Worker controller cannot put a page of his own, or terminal control sequences, in front of the user through `gclone login`. Remedy after a suspected leak: rotate the client secret in the Google console, `gclone logout --revoke`, `gclone login` on each device. |
| Someone else using the Worker | calls its public endpoints (the URL is not a secret) | `/device/start` hands anyone a device code and a user code for a login of their own — which is worth something only if the **owner** then enters that user code at Google (the Phisher row); `/device/poll` hands a refresh token only to an account in `ALLOWED_EMAILS` (others are refused and their grant revoked — and the refusal shows that account's address only masked, so the route is no way to learn who entered a code) and only for a grant that carries nothing beyond the Worker's own scopes; `/refresh` only relays to Google: a string that is not a live refresh token of one of the Worker's clients gets nothing back. Abuse of the relay is limited by a rate limit per client address — per /64 prefix for IPv6, where one host owns a whole /64 — and syntactic pre-filters (§2.3); the limit is approximate and does not stop a sender with many networks — and every request, refused or not, counts against the Worker plan's daily request quota, so on the `workers.dev` host a flood can stop logins and token refreshes until the quota resets (DoS only; mitigation: a custom-domain route with a zone rate-limiting rule, §15, §16.6). Google additionally limits device-code requests per client ID; someone who exhausts that quota through `/device/start` delays logins, nothing else. The Worker never redirects. |
| Network attacker | MITM | TLS everywhere (rustls + platform verifier); the device talks to the Worker over HTTPS only (`http://` is accepted for loopback hosts, for tests). Login: the device code — the only thing that can collect the tokens — travels only inside TLS, in the answer of `/device/start` and the bodies of `/device/poll`; the user code is typed by the user into Google's own page; the refresh token never appears in a URL (§2.3.2). |
| Phisher | **device-code phishing**: calls `/device/start` himself (it is unauthenticated — a device that logs in has no credentials yet), receives a user code, and talks the owner into entering **that** code at `https://www.google.com/device` and approving ("gclone needs re-authorising, please enter WXYZ-ABCD") | Needs the owner to type a code they did not get from their own terminal into Google's page and to approve the consent — within the code's lifetime (30 min), and a new code per attempt. If they do, the phisher's `/device/poll` receives a refresh token for the vault's files: the keyfile (offline passphrase guessing) and the ability to trash or overwrite every vault object — not the file contents, and **nothing outside the vault**: the Worker asks Google for `SCOPES` only and hands out no token for a grant that carries anything else (§2.3). **The e-mail allowlist does not help**: the account that consents is the owner's, the allowed one. Mitigations: the terminal says with every code *"enter only a code shown in this terminal"*, and the Worker's home page says the same; Google's consent screen names the app; `/device/start` and `/device/poll` are rate-limited, take no input that reaches Google except a pre-filtered device code, and log neither codes nor tokens. Residual risk, **accepted**: a known weakness of the grant itself (RFC 8628 §5.4). A phished grant reaches only ciphertext but could trash it — trashed objects are restorable for 30 days and every modification is detected; the remedy is removing the app at https://myaccount.google.com/permissions (or `gclone logout --revoke`) and `gclone login` on each device. |
| Thief of an unlocked device / malware as the user | reads `secrets.json` | Full compromise (cached master key + this device's refresh token). Remedy: `gclone logout --revoke` on any other device (or remove the app at https://myaccount.google.com/permissions ) — this ends the login of **every** device — then `gclone login` on each device you keep. Data already copied stays exposed and the master key is unchanged; re-keying is deferred. |
| Another user of the machine, or any local process that is not the user's | connects to the port of a running `gclone web` (§7.4); can read process lists; can run servers of their own on loopback | Gets `403` on every route: the session secret is 256 random bits, handed out only for the key of a one-time link. The link is printed on the user's terminal or, when gclone opens the browser itself, written into a `0600` page in the `0700` state directory whose **path** is what the launcher gets — the key is in no argument list. The cookie is scoped to a random path (`/s-<128 bits>/`), so the browser does not attach it to requests for that user's server on another loopback port. Whoever gets hold of a link first all the same (a shoulder, a screenshot of the terminal) makes the user's own link fail with a text that says so and what to do: a new link (Enter) starts a new session and ends every session before it, downloads included. |
| A web page in the user's browser | makes the browser send requests to `127.0.0.1:<port>` (cross-site requests, DNS rebinding) | Nothing: the cookie is `SameSite=Strict`; a request whose `Host` is not one of the three loopback authorities of the listening port, whose `Origin` is not the viewer's, or whose `Sec-Fetch-Site` is not `same-origin` / `none` is refused before the session is looked at; no response carries a CORS header, every response carries `Cross-Origin-Resource-Policy: same-origin`. |
| Content of the vault | a file that someone got into the vault (a downloaded HTML page, an SVG, a PDF) is opened in the viewer | It never becomes a document of the viewer's origin with script: HTML, XHTML, XML and JavaScript are served as `text/plain`, SVG as an image under `CSP: sandbox`, everything unknown as an attachment; types come from the file name, `nosniff` everywhere; the page builds its DOM from text nodes only and runs under a CSP without inline script (§7.4). A PDF is shown by the browser's own viewer, whose script sandbox is the browser's business. |
| Thief of a powered-off device | offline disk access | Protected only by disk encryption (FileVault/LUKS). Explicitly accepted; see §0.2 item 1. |
| Someone who learns the passphrase | — | Passphrase alone: nothing without access to the Google account (or a copy of the vault folder). Passphrase + vault folder copy, or + Google login: full compromise. `gclone passwd` does not undo a leak for anyone who already copied the old keyfile (same master key); re-keying is deferred. |

Local `state.db` and the index cache contain plaintext paths/hashes resp. ciphertext; same sensitivity as the synced files themselves.

---

## 2. Auth, enrollment and key distribution

**Roles.** *Google*: authorization server and Drive. *Auth Worker* (§16): a stateless Cloudflare Worker and the only holder of the OAuth client's ID and secret; it turns one consent at Google into a refresh token for one device and turns refresh tokens into access tokens. It has no storage (no KV, no D1, no Durable Object) and never sees file data. *Device*: the gclone CLI; it holds the Worker's URL, its **own** refresh token and — after the one-time unlock — the master key. All Drive calls go device ↔ Google directly. The login is Google's **device authorization grant** (RFC 8628): there is no redirect, so neither the Worker nor the device has to be reachable from a browser.

```
 device (gclone login)                    auth Worker                                 Google                      the user, any browser
   POST /device/start {} ───────────────►  POST device/code (client_id, SCOPES) ───►
   ◄── {device_code, user_code,           ◄── {device_code, user_code, verification_url,
        verification_url, expires_in,          expires_in: 1800, interval: 5}
        interval}
   print: "To sign in, open  <verification_url>" / "and enter the code  <user_code>"
   every `interval` s:
   POST /device/poll {device_code} ─────►  POST token (grant_type=device_code,
                                            device_code, client_id, client_secret) ─►  428 authorization_pending
   ◄── 400 authorization_pending ────────
                                                                                        ◄── opens google.com/device, enters the code,
                                                                                            chooses the account, consents
   POST /device/poll {device_code} ─────►  POST token (…) ─────────────────────────►  200 {refresh_token, access_token, id_token, scope}
   ◄── {refresh_token, access_token,       check id_token: e-mail verified ∈ ALLOWED_EMAILS (else revoke);
        expires_in, scope, email}          scope ⊆ ALLOWED_SCOPES and ∋ drive.file
   …later:  POST /refresh {refresh_token, client: "device"} ──►  + client_id, client_secret ──► token endpoint
   ◄── {access_token, expires_in, scope}
```

### 2.1 One-time setup (once per user — never per device; the authoritative step list is `worker/README.md`, WP8; URLs are [K] and may drift)
1. **Deploy the Worker**: `cd worker && npm install && npx wrangler login && npx wrangler deploy`. Note the printed URL `https://gclone-auth.<acct>.workers.dev` — this is `AUTH_URL`; `<host>` below is its host name. Until step 3 the Worker answers `500 server_misconfigured`. **The host is chosen before this step** (§17.14): the URL goes into the Google app's branding and into every device's login, so a user who wants the custom domain of step 5 puts its `routes` entry into `wrangler.jsonc` first (`node scripts/custom-domain.mjs <host>`, §16.1) and uses `https://<host>` from the start — `<host>` is then the custom host and the Authorized domain of step 2.3 its registrable domain. Moving later means a second round in the Google console and a new `gclone login` on every device.
2. **Google Cloud console**:
   1. Create a project: https://console.cloud.google.com/projectcreate (any name). Enable the Drive API: https://console.cloud.google.com/apis/library/drive.googleapis.com → **Enable**.
   2. Google Auth Platform → **Get started** (https://console.cloud.google.com/auth/overview): app name `gclone`, your e-mail as support and contact address, Audience **External**. Do **not** upload a logo (a logo triggers brand verification).
   3. Branding: Authorized domain `<acct>.workers.dev`; Application home page `https://<host>/`; Privacy policy `https://<host>/privacy` (the Worker serves both pages — Google requires the two links for every external production app, RESEARCH §6.1).
   4. Audience → **Publish app** → status must read **In production**. Do **not** click "Submit for verification": `openid`, `email` and `drive.file` are non-sensitive. *(If you skip this step, Google ends every login after 7 days; `gclone login` detects it, §2.4.)*
   5. Clients → **Create client** → Application type **TVs and Limited Input devices** (any name; this client type has no redirect URI and no JavaScript origin). Copy the client ID and the client secret now — the secret is shown only once.
3. **Worker secrets** (three; each `wrangler secret put` deploys a new version at once, no further `wrangler deploy` is needed): `npx wrangler secret put GOOGLE_CLIENT_ID`, `npx wrangler secret put GOOGLE_CLIENT_SECRET`, `npx wrangler secret put ALLOWED_EMAILS` (comma-separated Google account addresses). `ALLOWED_EMAILS` is a secret, not a `vars` entry: the address never sits in a tracked file, and a later `wrangler deploy` cannot reset it (§16.2). (Two more, optional: `GOOGLE_LEGACY_CLIENT_ID` / `GOOGLE_LEGACY_CLIENT_SECRET`, only while a device still holds a login from gclone before 0.2.0 — §2.3 `/refresh`, §17.18.)
4. **Check**: `curl https://<host>/` answers 200 and contains `Status: ready`.
5. *Recommended*: put the Worker on a custom domain with a zone rate-limiting rule over all of its paths (§16.6) — on the `workers.dev` host anyone can use up the plan's daily request quota. With the host chosen in step 1 only the rule is left.

`worker/setup.sh` walks through steps 1, 3 and 4 interactively: it asks first whether the Worker is served on its `workers.dev` host or on a host name of the user's own (then it writes the `routes` entry before the first deploy and uses that host everywhere), and it prints the console checklist of step 2 at the right moment. Google console changes can take "5 minutes to a few hours" to apply. Workspace users may choose Audience **Internal** instead of External/Publish.

After that, on every device: `gclone login https://<host>` (the URL is needed once per device — it is remembered in `config.json` and survives `logout`; §2.2).

### 2.2 Constants
```
GOOGLE_DEVICE_CODE_URL = https://oauth2.googleapis.com/device/code      (used by the Worker only)
GOOGLE_TOKEN_URL   = https://oauth2.googleapis.com/token                (used by the Worker only)
GOOGLE_REVOKE_URL  = https://oauth2.googleapis.com/revoke               (Worker: refused logins; device: `logout --revoke`)
SCOPES             = "openid email https://www.googleapis.com/auth/drive.file"      what the Worker asks Google for; fixed, never taken from a request
SCOPE_DRIVE_FILE   = https://www.googleapis.com/auth/drive.file
ALLOWED_SCOPES     = { openid, email, https://www.googleapis.com/auth/userinfo.email, SCOPE_DRIVE_FILE }
                     everything a grant of the Worker's clients may carry: SCOPES plus Google's spelling of the granted `email` scope (Worker, §2.3)
DEVICE_GRANT       = urn:ietf:params:oauth:grant-type:device_code       (the grant_type of a poll, Worker → Google)
AUTH_TIMEOUT       = 1800 s    the longest a device waits for a sign-in: the lifetime Google gives a device code, and the cap on `expires_in`
AUTH_POLL_SLOW_DOWN = 5 s      `slow_down`: the device's poll interval grows by this much (RFC 8628 §3.5)
AUTH_POLL_INTERVAL_DEFAULT = 5 s   the poll interval when none is named (RFC 8628 §3.5) — by Google to the Worker, by the Worker to the device
AUTH_RETRY_AFTER_MAX = 60 s    cap on a `Retry-After` the device honours, on the `interval` it accepts from /device/start,
                               and on the pause between two polls that failed (§2.4 step 3)
AUTH_REFRESH_ATTEMPTS = 5      tries of /refresh and of /device/start on 5xx / network errors
ACCESS_TOKEN_SKEW  = 60 s      (refresh when < 60 s to expiry)
IDLE_WARN_DAYS     = 150
AUTH_BODY_MAX      = 8 KiB     largest request body the Worker reads
AUTH_RATE_LIMIT    = 30 requests per 60 s per client address (IPv6: per /64 prefix), over /device/start, /device/poll and /refresh together (Worker, §2.3)
PASSPHRASE_MIN_CHARS = 12      Unicode scalar values, for a typed passphrase; a generated one has 20 Crockford symbols (100 bits)
KEYFILE_MAX        = 64 KiB
KEYFILE_TRY_MAX    = 4         a new device looks at the 4 keyfiles with the highest generation only (§2.6)
KEYFILE KDF        = Argon2id v1.3, m = 262144 KiB (256 MiB), t = 3, p = 1, 16-byte salt      (accepted on decode: §2.6)
```
Device-side URLs are injectable for tests (`AuthEndpoints { base, revoke_url }`, `DriveEndpoints`); the Worker's Google URLs are injectable through its `deps` (§16.3). A poll every 5 s is 12 requests per minute: inside `AUTH_RATE_LIMIT` for two devices behind one address signing in at once.

**Auth URL** (`AUTH_URL`, the Worker's base URL). `gclone login [AUTH_URL]` resolves it as: the argument, else env `GCLONE_AUTH_URL`, else the value stored in `secrets.json` by an earlier login, else the one in `config.json` (it is not a secret and is written there when the device is attached, so it survives `gclone logout`), else the compile-time default `option_env!("GCLONE_DEFAULT_AUTH_URL")` (set when building one's own binary), else an error that names the three ways. Every other command uses the value in `secrets.json` only. Validation (`auth::validate_auth_url`; a stored value is validated when it is **used** — `Secrets::endpoints()`, §9.10 — never when a file is merely loaded, so the secrets of a directory vault, which have no `auth_url`, load fine): it parses as a URL with scheme `https`, a host, no userinfo, no query, no fragment; scheme `http` is accepted **only** for the hosts `127.0.0.1`, `localhost` and `[::1]` (tests); a trailing `/` is removed. Routes are appended to it (`<AUTH_URL>/device/start`, `/device/poll`, `/refresh`). The HTTP client used for the Worker is built with `redirect(Policy::none())`: a 3xx answer is an error, so a device code or a refresh token is never re-sent to another host.

### 2.3 Auth Worker HTTP API (normative for `worker/` — WP8 — and for the fake auth endpoints of `FakeDrive` — WP3)

General rules:
- JSON answers: `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. **Every** error answer, on every path and method, is `{ "error": "<code>", "message": "<one English sentence>" }`.
- The two HTML pages (`/`, `/privacy`): `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `Content-Type: text/html; charset=utf-8`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. They are static: no script, no form, and nothing taken from a request.
- No CORS headers on any route, no cookies, no storage, no redirect.
- `POST` routes require `Content-Type: application/json` (else `415 unsupported_media_type`), a body of at most `AUTH_BODY_MAX` (else `413 payload_too_large`) that is a JSON object whose required fields are strings within the stated bounds (else `400 invalid_request`). Unknown fields are ignored. (`/device/start` uses nothing of its body and still requires the JSON object: a request that needs `Content-Type: application/json` cannot be made by a cross-site form, and without CORS headers not by a cross-site script either.)
- Unknown path → `404 not_found`; known path with another method → `405 method_not_allowed` + `Allow` (`GET` for the two pages — `HEAD` is not accepted — `POST` for the three JSON routes).
- An unexpected exception inside the Worker answers `500 internal_error` without detail. The code is outside the mapped list below on purpose: a device treats it as "other 5xx" (§2.4).
- **Rate limit** (`AUTH_RATE_LIMIT`, §2.2): `/device/start`, `/device/poll` and `/refresh` — after the path/method check and before anything else — ask the Worker's rate-limit binding (§16.2) with a key made from the `cf-connecting-ip` header: an IPv4 address as it is; an IPv6 address as its /64 prefix, written as the first four groups in lower-case hexadecimal without leading zeros followed by `::/64` (`2001:db8::1` → `2001:db8:0:0::/64`) — one IPv6 host owns at least a /64, so a key per address would give it 2^64 budgets; an IPv4-mapped address (`::ffff:a.b.c.d`) as that IPv4 address; `"unknown"` when the header is absent or empty; any other text as it is. Over the limit → `429 rate_limited` with `Retry-After: 60`; Google is not contacted. Without the binding (unit tests) the check is skipped. The limit is per Cloudflare location and approximate; it bounds what one sender can relay to Google through the OAuth client — a sender with addresses in many networks (many IPv4 addresses, an IPv6 allocation larger than a /64) has one budget per network, which only a zone rule in front of the Worker can stop (§16.6) — and it does **not** keep refused requests from counting against the Worker plan's daily quota (§16.6).
- Configuration is checked on every request: `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` non-empty; otherwise the three JSON routes answer `500 server_misconfigured` and the home page says `Status: not configured`. The legacy client exists when `GOOGLE_LEGACY_CLIENT_ID` **and** `GOOGLE_LEGACY_CLIENT_SECRET` are non-empty. Exactly one of the two (a **half-set pair**) is not a reason to stop: every Worker passes through that state, because the pair is put and deleted with two `wrangler secret` commands that are each deployed at once. Then there is no legacy client, the device client's routes work as always, the home page says `Status: ready` followed by a warning that names the two secrets, and only a `/refresh` without `client` answers `500 server_misconfigured` (below; §17.19). An empty or missing `ALLOWED_EMAILS` is not a misconfiguration: it allows nobody (fail closed).
- Nothing secret is ever logged or echoed: no request bodies, device codes, user codes, tokens, client secrets. Log lines carry route, status and error code only. No route carries a secret in its URL; the platform is nevertheless configured so that no request is stored beyond that log line: invocation logs off, query-string redaction on, traces off, no log export (security requirements of `wrangler.jsonc`, §16.2).

| Route | Called by | Purpose |
|---|---|---|
| `GET /` | browser, Google reviewers | static home page: what this is, a warning never to enter a code that someone sent, link to `/privacy`, a line `Status: ready` or `Status: not configured` |
| `GET /privacy` | browser | static privacy statement (stores nothing; uses `drive.file` + e-mail only to sign the owner in) |
| `POST /device/start` | device | start a login at Google; pass Google's device code, user code and verification URL on |
| `POST /device/poll` | device, every `interval` seconds | ask Google whether the code was entered; on success check the grant and hand out this device's refresh token |
| `POST /refresh` | device | refresh token → access token |

**`POST /device/start`** — body: a JSON object; nothing in it is used. The Worker sends `POST GOOGLE_DEVICE_CODE_URL`, form-encoded: `client_id=<GOOGLE_CLIENT_ID>`, `scope=<SCOPES>` (no secret; timeout 10 s). On `200` it requires `device_code` (16..=512 characters of `[A-Za-z0-9_/.~+=-]`), `user_code` (2..=64 printable ASCII characters, no leading or trailing space), `verification_url` (`https://` followed by 1..=200 printable non-space ASCII characters), `expires_in` (a number > 0) and — when present — `interval` (a number > 0; RFC 8628 §3.2 makes the field optional, and an absent one is `AUTH_POLL_INTERVAL_DEFAULT`, 5) — else `502 upstream_error` — and answers `200`: `{ "device_code": "…", "user_code": "GQVQ-JKEC", "verification_url": "https://www.google.com/device", "expires_in": 1800, "interval": 5 }` — those five fields exactly as Google sent them (`interval`: 5 when Google sent none). The Worker does not judge the host of `verification_url`: its upstream is Google's own endpoint, and a host rule here would only break every login on the day Google moves its page. The party that has reason to distrust the address is the device, which opens it only when it is a `google.com` address (§2.4). Error answers of Google are mapped by the table below (a client that is not of the device type → `500 client_invalid`; Google's own limit on device-code requests, `403 {"error_code": "rate_limit_exceeded"}` → `502 upstream_error`).

**`POST /device/poll`** — body `{ "device_code": "<16..=512 characters of [A-Za-z0-9_/.~+=-]>" }`; anything else → `400 invalid_request` without contacting Google (a pre-filter against malformed input; it does not assume Google's current code format).
1. `POST GOOGLE_TOKEN_URL`, form-encoded: `grant_type=<DEVICE_GRANT>`, `device_code`, `client_id`, `client_secret`. Timeout 10 s.
2. The states of a device code are passed on under Google's own error names, whatever HTTP status Google used for them (it answers `428` for `authorization_pending` and `403` for `slow_down`; the Worker goes by the `error` field): `authorization_pending` → `400 authorization_pending`; `slow_down` → `400 slow_down`; `expired_token` → `400 expired_token`; `access_denied` → `403 access_denied`; `invalid_grant` (unknown or already redeemed code) → `400 invalid_grant`. Other errors: the table below.
3. On `200` without an `error` field (an answer that names an error is that error under any status) — Google has now consumed the device code, so **nothing from here on is answered with a 5xx**: a device repeats a poll that got one (§2.4), and repeating can only bring `invalid_grant` and hide the reason. The Worker requires, in this order:
   - `refresh_token` and `access_token` present, `expires_in` a number, and an `id_token` whose payload (the middle `.`-separated part, base64url JSON) decodes with `aud == GOOGLE_CLIENT_ID` and `iss ∈ {"https://accounts.google.com", "accounts.google.com"}` — else `403 grant_unusable` with a message that says which part was missing (*"Google approved the sign-in, but its answer carried no ID token (the account cannot be checked without one), so nothing was handed out and the code is used up. …"*; at most 300 characters). Nothing is revoked: without a readable ID token the Worker does not know whose grant it is, and a revoke is grant-wide. The signature is **not** verified: the token was received directly from Google's token endpoint over TLS, authenticated with the client secret (Google's own guidance, RESEARCH §6.2). An ID token from any other source is never accepted. (That Google's device-grant answer carries an ID token when `openid email` was requested follows its "Sign-In on TVs" guide; first confirmed by probe 5, §2.9.)
   - `email_verified === true` and `email` is an entry of `ALLOWED_EMAILS` (comma-separated; entries trimmed). **The comparison is byte for byte, except that the 26 ASCII letters match in either case** — no Unicode case mapping, which would turn other code points into ASCII letters (U+212A KELVIN SIGN lower-cases to `k`). An `email` claim, or an entry, that is not 3..=254 characters of printable ASCII (`0x21..=0x7e`) matches nothing. Else: best-effort `POST GOOGLE_REVOKE_URL` with `token=<refresh_token>` (so no grant for a stranger's account stays behind; revocation is grant-wide, which is exactly right here), then `403 email_not_allowed`. Its message shows the address **masked** — the first character, `***`, and everything from the last `@` on: *"The Google account s\*\*\*@example.net is not allowed to sign in here."* — or *"This Google account …"* when the claim is absent or not such printable ASCII. The caller of `/device/poll` is anonymous, and whoever entered its user code at Google agreed to show the address to the app, not to that caller; the masked form still tells the owner which account was picked by mistake.
   - every entry of `scope` (space-separated; empty entries ignored) is a member of `ALLOWED_SCOPES` (§2.2; compared exactly) — else `403 scope_not_allowed`: the tokens are discarded, nothing is handed out, and nothing is revoked (a revoke is grant-wide and would sign out the owner's other devices). The message tells the user to remove the app at https://myaccount.google.com/permissions if this was unexpected and then names up to three of the excess scopes (only entries of at most 100 characters of `[A-Za-z0-9:/._-]`; they come last so that a client that shortens the message keeps the remedy). The Worker itself asks for `SCOPES` only and no request can change that, so this check is defence in depth: the client's secret never turns into a refresh token for more than gclone's own files, whatever Google reports for the grant.
   - `scope` contains `SCOPE_DRIVE_FILE` — else `403 scope_missing` (no revoke, for the same reason; the user unticked the permission on the consent screen).
4. `200`: `{ "refresh_token": "1//…", "access_token": "ya29.…", "expires_in": 3599, "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file", "email": "me@example.com" }`, plus `"refresh_token_expires_in": <seconds>` exactly when Google sent that field (time-limited grant, §2.4).

A refusal in step 3 ends that login for good: the device code is spent, and a further poll gets `400 invalid_grant`. All four refusals are `403` and final for the device.

**`POST /refresh`** — body `{ "refresh_token": "<20..=512 characters of [A-Za-z0-9_/.~+=-]>", "client": "device" }`; a malformed `refresh_token`, or a `client` that is present and not the string `"device"` → `400 invalid_request` without contacting Google (the token filter is a pre-filter against malformed input; it does not assume Google's current `1//…` prefix). **Which client**: Google refreshes a token only for the OAuth client that issued it, and the Worker cannot tell from a token which one that was — the device says so. `"client": "device"` → the client of `GOOGLE_CLIENT_ID`; no `client` field → the **legacy client** of `GOOGLE_LEGACY_CLIENT_ID` / `_SECRET` (the *Web application* client of the browser sign-in before 0.2.0, §17.18). When the field is absent and no legacy client is configured, the answer is `400 invalid_grant` — message: *"This login was made with gclone's earlier browser sign-in, which this sign-in helper no longer serves. Run `gclone login` again."* — **without** contacting Google (a device maps it to `Expired`, exit 4). When the field is absent and the legacy pair is half-set, the answer is `500 server_misconfigured` — *"Only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set on this sign-in helper, so it cannot refresh a login made before gclone 0.2.0: set both, or delete both."* — also without contacting Google, and **not** "log in again": the owner is in the middle of setting or removing the pair, and the login may be perfectly good. The Worker then sends `POST GOOGLE_TOKEN_URL`, form-encoded: `grant_type=refresh_token`, `refresh_token`, `client_id`, `client_secret` of that client (timeout 10 s), maps errors by the table, and answers `200`: `{ "access_token": "ya29.…", "expires_in": 3599, "scope": "…" }`. **Allowlist re-check**: when Google's answer carries an `id_token` (it may, for a grant with `openid`; [U]) whose payload has `aud` = the ID of the client that was used and Google's `iss`, and whose e-mail is not verified or not in `ALLOWED_EMAILS`, the Worker revokes the refresh token (best effort) and answers `403 email_not_allowed` (the address masked, as on `/device/poll`) — so removing an address from the allowlist cuts that account off at its next refresh. Without an `id_token` there is nothing to check: the access token is returned (a refresh token of these clients can only have come out of a login, which checked the allowlist as it was then). **Scope re-check** (after the allowlist re-check): when the `scope` of Google's answer has an entry outside `ALLOWED_SCOPES`, the access token is discarded and the answer is `403 scope_not_allowed` (same message, no revoke) — a refresh token with wider access than gclone's, however it came to exist, gets nothing through the Worker. Only excess is refused here: a missing or empty `scope` field passes.

Mapping of Google's answers (all three routes; the device-code states of `/device/poll` are listed there):
| Google answers | Worker answers |
|---|---|
| `error: invalid_grant` | `400 invalid_grant` (for `/refresh`: the refresh token is revoked, expired or unused for six months; for `/device/poll`: the device code is unknown or was already redeemed) |
| `error: invalid_client`, `deleted_client`, `unauthorized_client`, `invalid_scope` | `500 client_invalid` (message carries Google's code) |
| `error: access_denied`, `admin_policy_enforced`, `org_internal` | `403 access_denied` (message carries Google's code) |
| any 5xx, network failure, timeout, a body that is not a JSON object, any other error | `502 upstream_error` — Google gave no usable answer, and nothing was consumed |
| `/device/poll` only: a `200` token answer that lacks a part the Worker needs (step 3) | `403 grant_unusable` — the code **was** consumed |

All error codes: `invalid_request` 400, `invalid_grant` 400, `authorization_pending` 400, `slow_down` 400, `expired_token` 400, `email_not_allowed` 403, `scope_missing` 403, `scope_not_allowed` 403, `grant_unusable` 403, `access_denied` 403, `not_found` 404, `method_not_allowed` 405, `payload_too_large` 413, `unsupported_media_type` 415, `rate_limited` 429 (+ `Retry-After`), `server_misconfigured` 500, `client_invalid` 500, `upstream_error` 502, `internal_error` 500.

#### 2.3.1 Statelessness
The Worker remembers nothing between two requests and seals nothing: a login in progress exists at Google, under the device code, and the device carries that code from `/device/start` to every `/device/poll`. There is no `SEAL_KEY` and no blob format any more (both existed for the browser-redirect flow before 0.2.0, §17.18). A device code is single-use without any server state because Google's is: once a poll was answered with tokens — whether the Worker then handed them out or refused them — a further poll with the same code gets `invalid_grant`.

Consequence, accepted: a `/device/poll` answer that carries the tokens and is lost on its way to the device (or a Worker invocation that dies between Google's answer and its own) loses that login; the device's next poll gets `400 invalid_grant` and the user runs `gclone login` again. Nothing else is affected.

#### 2.3.2 Why this is safe — and where it is not
- **The client secret never leaves the Worker.** The device-code request needs none; every token request is made by the Worker. A device holds a device code for at most 30 minutes and its own refresh token afterwards.
- **Binding.** The tokens of a login go to whoever polls with its device code; only the party that called `/device/start` has it (TLS answer, never printed, never in a URL). The user code is useless to anyone but Google's page. There is no browser hop back to the device, so there is no state to forge, no code to inject and no redirect to bend: the CSRF, code-injection, open-redirect and mix-up questions of a redirect flow do not arise.
- **Token theft.** The refresh token never appears in a URL or a page; it exists only in the TLS response of the `/device/poll` that completes the login.
- **Scope.** The access a login yields is fixed by the Worker: `/device/start` sends the constant `SCOPES`, `/device/poll` hands out tokens only when every scope Google reports for the grant is in `ALLOWED_SCOPES` and `drive.file` is among them, and `/refresh` refuses a refresh token whose grant is wider. (Google restricts the device grant to a short list of scopes anyway; `drive.file` and the OpenID scopes are on it, full `drive` is not.)
- **Cross-site requests.** No CORS headers and JSON-only POST bodies: a web page cannot call the three routes through a visitor's browser — and what it could start with `/device/start` it could not read.
- **Strangers.** Anyone can start a login and reach Google's consent screen with their **own** account; `/device/poll` refuses (and revokes) any account outside `ALLOWED_EMAILS`: nobody else obtains tokens. Anyone can also send junk to the three routes; the pre-filters and the rate limit per client address (per /64 for IPv6, §2.3) bound what one sender can relay toward Google, but they do not stop a sender with many networks, and they do not keep anyone from using up the Worker's own request quota or Google's per-client quota of device-code requests (§1.3, §16.6) — a denial of logins, nothing more.
- **Device-code phishing** (residual, **accepted**): see the Phisher row of §1.3. `/device/start` is unauthenticated by nature, so a phisher can start a login and try to make the **owner** enter the phisher's user code at Google. The allowlist cannot notice it — the consenting account is the allowed one — and the Worker, being stateless and never seeing the user's browser, has no place to put a confirmation step: Google's page is the only page there is. What is done: (1) the device prints, with every code, *"(enter only a code shown in this terminal; waiting…)"*, and the Worker's home page carries the same warning; (2) the routes are rate-limited and pre-filtered, and nothing in a `/device/start` request can change what Google is asked for; (3) device codes, user codes and tokens are never logged, and every answer is `no-store`. What a phished grant yields is bounded as for every gclone login: ciphertext and the keyfile, the ability to trash or overwrite vault objects (trash is recoverable for 30 days; modifications are detected), nothing outside the vault.

### 2.4 Login on the device, token handling

`auth::login_interactive` has **one** flow, the same on every machine.

1. **Start** (`auth::device_start`): `POST <AUTH_URL>/device/start` with `{}` → `DeviceCode { device_code, user_code, verification_url, expires_in, interval }`. The route is repeatable (it only leaves an unused code behind): 5 tries on 5xx / network errors, one more after a `429` (mapping table below). The answer is checked before any of it is shown, because the user code and the URL end up in a terminal and the URL in a browser: `device_code` non-empty; `user_code` 1..=64 bytes of printable ASCII (`0x20..=0x7e`) without leading or trailing space; `verification_url` at most 256 bytes of printable ASCII without a space that parses as an `https` URL with a host and **without a user name or password** (`https://www.google.com@other.example/` reads like a host it is not); `expires_in` a number > 0; `interval` a number > 0, or absent — then `AUTH_POLL_INTERVAL_DEFAULT` (fractions count; `expires_in` is capped at `AUTH_TIMEOUT`, `interval` at `AUTH_RETRY_AFTER_MAX`). Anything else → `Network("unexpected answer from the auth Worker")`, with nothing printed.
2. **Show** (`InteractiveOpts.print`; stderr in production, also with `-q` and `--json` — the lines are needed to get through the sign-in at all). Exactly these three lines ▸:
   ```
   To sign in, open  https://www.google.com/device
   and enter the code  GQVQ-JKEC
   (enter only a code shown in this terminal; waiting…)
   ```
   The URL and the code are the Worker's answer verbatim. Then, unless the CLI decided against it, `InteractiveOpts.open(verification_url)` opens the page in the local browser (the `open` crate in production) — a convenience whose failure changes nothing; the code still has to be typed there. **Only a Google page is opened** (`auth::is_google_page`: scheme `https`, host `google.com` or a host ending in `.google.com`). For any other address — the Worker's word is all the device has for it — a fourth line is printed after the code ▸ `(warning: that is not a google.com address, and it was not opened. Google's page for this is https://www.google.com/device; open another one only if you trust this auth Worker)` (`auth::NOT_GOOGLE_NOTE`), nothing is opened, and the login goes on: should Google ever move its page, the user can still follow the printed address. The CLI does not try to open a browser when `--no-browser` is given, when `SSH_CONNECTION` or `SSH_TTY` is set, or on Linux when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set (`want_headless`, §9.10).
3. **Poll** (`auth::device_wait`): sleep `interval`, then `POST <AUTH_URL>/device/poll` with `{ "device_code": … }`, until an answer ends the login (table below): the tokens (`LoginGrant { refresh_token, access_token, expires_at_ms, scope, email, refresh_expires_in }`; the device also requires `scope` to contain `SCOPE_DRIVE_FILE`, else `AuthError::ScopeMissing`, and `email` — which it prints and stores — to be at most 254 bytes of printable ASCII without a space (`0x21..=0x7e`) containing an `@`, else `Network("unexpected answer from the auth Worker")`), a refusal, or the end of the code. `slow_down` adds `AUTH_POLL_SLOW_DOWN` to the interval for the rest of the login. **A poll that fails without an answer about the login** — a network error, `502 upstream_error` or another 5xx, `429` (then the device first waits `Retry-After`, capped) — is followed by the next one: the Worker answers 5xx only where Google has not consumed the device code (§2.3), so repeating is harmless. **The device backs off** (RFC 8628 §3.5: "clients MUST unilaterally reduce their polling frequency"): after `n` polls in a row that failed with a network error or a 5xx it waits `interval · 2ⁿ`, at most `AUTH_RETRY_AFTER_MAX` — but never less than `interval`, so `slow_down` increments are kept in full, and never so long that the last poll the plain interval would still have made is skipped (the wait is cut to `time left − interval`). A `429` is not counted: its `Retry-After` is the back-off. The first poll that is answered about the login (`authorization_pending`, `slow_down`) ends the streak, and the wait is `interval` again. The first failure of a streak is reported through `print` (*"(cannot reach the sign-in service right now: … — still trying)"*), the rest silently. The device stops by itself when the next poll would lie past `expires_in` after the start: `AuthError::Timeout` — or `AuthError::Network(<the last failure>)` when the polls were failing at that point.
4. **Ctrl-C** ends the process with exit 130 (§7.2); nothing was stored, and the abandoned device code simply expires.

**Expiring-grant check.** `refresh_token_expires_in` (seconds of refresh-token lifetime left; Google sends it only for time-limited grants — its Testing-mode value ≈ 604799 is [U], manual probe 1) arrives as `LoginGrant.refresh_expires_in`. If it is present, `gclone login` stops **before** storing the token or touching a vault: *"Google will expire this login in N days — the OAuth app is still in Testing (Google Auth Platform → Audience → Publish app), or time-limited access was chosen. Publish the app, then run `gclone login` again."* (exit 4). `--allow-expiring-login` overrides; then `refresh_expires_at_ms = now + n·1000` is stored in `secrets.json` (§8.2), shown by `status` and used by the Expired message (§2.8). Field absent → `refresh_expires_at_ms = null`.

**Token handling.**
- Refresh (`auth::refresh`): `POST <AUTH_URL>/refresh` with `{ "refresh_token": …, "client": "device" }` → `access_token`, `expires_in`. The `client` field is `Secrets.client` (§8.2): `"device"` for every login made by 0.2.0 or later; **omitted** for a login on file from before (`AuthClient::Legacy`), which the Worker then refreshes through its legacy client or refuses with `400 invalid_grant` (§2.3).
- `TokenProvider` caches `{access_token, expires_at_ms, refreshed_at_ms}` in `<state root>/token.json` (0600, §8.1) so most commands make no request to the Worker at all; single-flight in-process. On a Drive API `401`: `force_refresh()` once, retry once, then `AuthError::Expired`. The cache file is written only after a **real** refresh; `prime()` (the access token that came with a fresh login) is memory-only. `gclone login` builds its providers **without** a cache file and deletes `token.json` after every interactive sign-in, whatever its outcome (§2.6): an access token obtained during a login — possibly for the wrong Google account — is never left on disk for later commands.
- Every *real* refresh stores `refreshed_at_ms`; `status` warns when the newest refresh is > `IDLE_WARN_DAYS` old. A refresh token dies after six months without use — per device. Recommended keep-alive for rarely used machines (documented, not installed): monthly cron `gclone status -q`.

Mapping of Worker answers to `AuthError` (`auth/login.rs`; identical for the fake):
| Worker answer | from `/device/start` | from `/device/poll` | from `/refresh` |
|---|---|---|---|
| `400 authorization_pending` | unexpected | poll again after `interval` | unexpected |
| `400 slow_down` | unexpected | `interval += 5 s`, poll again | unexpected |
| `400 expired_token` | unexpected | `Timeout` | unexpected |
| `400 invalid_grant` | unexpected | `LoginFailed("the code is no longer valid: it expired, or this sign-in was already completed")` | `Expired` |
| `403 grant_unusable` | unexpected | `LoginFailed(message)` — the Worker's own sentence; final, no further poll | unexpected |
| `403 email_not_allowed` | `NotAllowed(message)` | `NotAllowed(message)` | `NotAllowed(message)` |
| `403 scope_missing` | `ScopeMissing` | `ScopeMissing` | `ScopeMissing` |
| `403 access_denied`, `403 scope_not_allowed` | `Denied(message)` | `Denied(message)` | `Denied(message)` |
| `500 client_invalid`, `500 server_misconfigured` | `WorkerMisconfigured(message)` | `WorkerMisconfigured(message)` | `WorkerMisconfigured(message)` |
| `404 not_found` | `LoginFailed("the auth Worker at this URL is an older version without the code sign-in; deploy the current worker/ first (worker/README.md)")` | unexpected | unexpected |
| `429 rate_limited` | wait `Retry-After` (capped at 60 s), retry **once**, then `Network("the auth Worker is rate-limiting this address")` | wait `Retry-After` (capped), poll again | as `/device/start` |
| `502 upstream_error`, other 5xx, connect/read errors | retried 5× with backoff, then `Network(…)` | poll again, backing off (step 3) | retried 5× with backoff, then `Network(…)` |
| any 3xx, a non-JSON body, any other status | `Network("unexpected answer from the auth Worker")` — the "unexpected" of this table | same | same |

### 2.5 What is stored where
| Item | Location | Protection |
|---|---|---|
| OAuth `client_id`, `client_secret`, `ALLOWED_EMAILS` (and, during the transition of §17.18, the legacy client's ID and secret) | the Worker's configuration at Cloudflare (§16.2) | Cloudflare account; never on a device, never in the repository |
| `auth_url`, this device's `refresh_token` and the `client` it belongs to, account `email`, `refresh_expires_at_ms`, cached master key(s), `min_epoch` | `<state root>/secrets.json` — under `~/.local/state`, not `~/.config`, which is what dotfile repositories and synced home folders pick up | 0600, dir 0700, plaintext JSON (§8.2); refused when the file or its directory is owned by someone else or readable by group/others (§8.1). Never copy it to another machine. |
| access token | `<state root>/token.json` | 0600 |
| vault id/name, Drive folder IDs, backend kind, `auth_url` (not a secret) | `<config>/config.json` | 0600 |
| index replica, base tables, pending ops, device id | `<state>/state.db` | 0600 |
| On Drive | vault folder | ciphertext under random 256-bit keys + one plaintext descriptor hint + the **keyfile**: the master key wrapped under the passphrase (§2.6) |
| Passphrase | the user's password manager | — ; gclone never stores it |

### 2.6 Passphrase, keyfile, and the vault part of `gclone login`

**Passphrase.**
- *Normalisation* (`Passphrase::from_input`, applied identically when a passphrase is set and when it is entered): drop one trailing `\n` or `\r\n`; apply Unicode NFC; then, if the text with ASCII whitespace and `-` removed is exactly 20 characters, each a Crockford symbol in either case or one of `I L O i l o`, it is rewritten to the canonical generated form (upper case, `I`/`L` → `1`, `O` → `0`, regrouped `XXXXX-XXXXX-XXXXX-XXXXX`). Any other text is used as is (case-sensitive, inner spaces kept). The KDF input `P` is the UTF-8 encoding of the result.
- *Setting one* (vault creation, `passwd`). Prompt: *"New passphrase (leave empty to let gclone generate a strong one):"*.
  - empty → `Passphrase::generate()`: 20 symbols drawn uniformly from the Crockford alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` with the OS CSPRNG (100 bits), shown once in the canonical form with *"Store it in your password manager. It is needed once on every new device and cannot be recovered."*
  - typed → at least `PASSPHRASE_MIN_CHARS` Unicode scalar values, else `FormatError::WeakPassphrase` and ask again; fewer than 20 → warning *"Anyone who can read the vault folder, Google included, can try guesses offline. Prefer five or more random words, or the generated passphrase."* and a confirmation; then typed a second time (must match).
  - non-interactive: `--passphrase-file PATH` (first line of the file, e.g. `/dev/fd/3`; same minimum — so an empty line is refused; no warning, no confirmation). Neither a TTY nor the flag → error. A passphrase is never accepted in argv or the environment.
- *Entering one* (new device): no-echo TTY prompt, 3 attempts; or `--passphrase-file`.

**Keyfile** (byte-exact; stored in the vault root, §3.1):
```
keyfile     = KdfPreamble(36) ‖ Stream(type = 0x05 Bundle, key_epoch = 0, chunk_log2 = 16, key = K_pass)       (§4.2; one chunk in practice)
KdfPreamble = "GCK1"(4) ‖ alg = 0x01 (Argon2id) ‖ version = 0x13 ‖ 0x00 0x00 ‖ m_kib u32 BE ‖ t u32 BE ‖ p u32 BE ‖ salt(16)        (big-endian, like every other integer of the formats)
K_pass      = HKDF-SHA-256(salt = the 36 KdfPreamble bytes, ikm = Argon2id(P, salt = preamble.salt, m_kib, t, p, 32 bytes out),
                           info = "gclone/v1/passphrase/keyfile", L = 32)
plaintext   = UTF-8 JSON KeyfilePayload
name        = "gclone-key-" ‖ gen (8 lowercase hex digits) ‖ "-" ‖ h8          h8 = first 8 hex characters of BLAKE3(keyfile bytes)
```
- Written parameters: `m_kib = 262144` (256 MiB), `t = 3`, `p = 1`, fresh random salt per keyfile. Accepted on decode: `8192 ≤ m_kib ≤ 524288`, `1 ≤ t ≤ 4`, `p = 1`, `alg = 1`, `version = 0x13`; anything else → `FormatError::KdfParams` **before** running Argon2 or allocating its memory. The upper bounds cap the work a planted keyfile can demand — the parameters are read before anything is authenticated, and anyone who can write to the folder can plant one: at most 512 MiB and four passes per attempt (writers only ever emit 262144 / 3 / 1; raising a ceiling later is a reader-side change). The lower bounds are sanity limits only: a keyfile that opens was written by someone who knows the passphrase, and a substituted keyfile with cheap parameters merely fails to open — the device never sends anything derived from the passphrase anywhere.
- AEAD and binding: the body is the standard stream container — ChaCha20-Poly1305 STREAM with the key-commitment tag (§4.2). That construction uses an empty AEAD associated-data field; every context byte is bound through key derivation instead: the KDF parameters and salt are the HKDF salt of `K_pass`; suite, chunk size, stream type, flags and epoch are in the HKDF `info` of the stream key; the vault id and the generation are inside the authenticated plaintext and are compared after opening. A wrong passphrase fails at the commit tag and is reported as `CryptoError::WrongKey`, distinguishable from damage (`Corrupt`).
- Versioning: preamble magic `GCK1` + `alg` + `version`; stream magic `GCS1` + `suite`; payload `v`. Unknown anywhere → fail closed ("needs a newer gclone").

`KeyfilePayload` (JSON; unknown fields ignored; `v` must be 1):
```json
{ "v": 1, "vault_id": "<32 hex>", "gen": 1,
  "keys": [ { "epoch": 1, "key": "<base64url-nopad 32 bytes>" } ], "min_epoch": 1,
  "created_ms": 1794400000000, "by": "mbp" }
```
`gen` (the *generation*; the Rust field is `KeyfilePayload::generation`, serialized as `"gen"` — `gen` is a reserved word in edition 2024, §9.4) starts at 1 and grows by one per `passwd`. Keyfiles are put-once objects like everything else (§3.2): a new passphrase is a **new** object; older generations are trashed (§2.7). The generation in an object's *name* is unauthenticated until the keyfile opens: it only orders candidates (ATTACH) and is never trusted as a number without overflow checks (§2.7).

Opening (`format::keyfile::open_keyfile(name, bytes, passphrase)`), in this order: `36 + 76 ≤ len ≤ KEYFILE_MAX` and the name parses, else `FormatError::KeyfileDamaged` → `BLAKE3(bytes)` matches the name's `h8` (`KeyfileDamaged`; an accidental-corruption check, not an authentication) → preamble bounds (`KdfParams`) → Argon2id → stream header, commit check (`CryptoError::WrongKey` = wrong passphrase) → chunk authentication (`CryptoError::Corrupt`) → JSON with `v == 1` (`FormatError::KeyfileVersion`) → `gen` equals the name's, `keys` non-empty, every key 32 bytes, every epoch ≥ `min_epoch` (`KeyfileDamaged`). The caller then requires `payload.vault_id` to equal the vault id it is attaching to.

**`gclone login`, the whole command** (idempotent and resumable: run it again after any failure).
```
0. Backend  (cli::login_backend, §9.10)
      --vault-dir DIR                                           → directory backend at DIR; skip A
      no --vault-dir, no AUTH_URL argument, config.json says
        kind: dir                                               → directory backend at config.backend.path; skip A
      otherwise                                                 → Drive backend
      mixing kinds on an attached device (--vault-dir on a Drive-attached one; AUTH_URL, or another DIR, on a directory-attached
      one) is a usage error: "this device is attached to <…>; run `gclone logout --forget` first".

A. Sign in  (Drive backend only)
   1. auth_url = resolve (§2.2).
   2. If secrets.json holds a refresh token for the same auth_url AND its `client` is "device": force_refresh().
        Ok                       → "Already signed in as <email>."; go to B
        Expired / anything else  → continue with 3
      A login on file WITHOUT `client` (the legacy client, gclone before 0.2.0) is never kept, working or not: `gclone login`
      is how a device moves to the device client (§17.18). stderr: "This device's Google login was made with the browser
      sign-in of gclone before 0.2.0. Signing in again replaces it; until that has worked, nothing on this device changes."
   3. login_interactive (§2.4) → LoginGrant; expiring-grant check. The login it yields has client = "device".
   4. No config.json (a device that is not attached to a vault yet): save it now { auth_url, refresh_token, client, email,
      consent_ms, refresh_expires_at_ms, keys: [] } so the grant survives a later failure.
      EXCEPT when the sign-in replaces a login of the legacy client (step 2) — a device that signed in with gclone before
      0.2.0 and never finished the vault part: there the new token is saved only once B.2 found a vault (or `--new-vault`
      was given). A vault made through the legacy client may exist and be invisible to the new login (§17.18), and the
      legacy login cannot be issued again. If B.2 finds nothing: VaultNotVisible with the text of §2.8 for this case,
      secrets.json untouched, nothing created (§17.19).
      config.json exists: the new token is saved only once the attached vault was seen with it — after B.1 succeeded (cached
      key: re-login of a connected device) or as soon as B.2 found config.vault_id among the discovered vaults (no cached key:
      after `logout`, or an interrupted first login), with keys: [] and before the passphrase is asked. A login with the wrong
      Google account must neither replace the token on file nor become it: step 2 would find a login that works on every later
      run and never ask again (§17.9). The price: a failure between the sign-in and that point costs one more sign-in.
   Token cache: every TokenProvider `login` builds has NO cache file (drive_backend(.., cache = false)) and `prime` is
   memory-only, so `login` never writes token.json. After step 3 ran, token.json is deleted — on success and on failure of B.

B. Vault
   1. config.json exists and secrets.json has keys (a re-login):  Vault::verify_visible(backend, stored handles)
        Ok      → save the new token (if step A.3 ran); "Signed in again. Vault unchanged."
        failure → VaultNotVisible / VaultTrashed (§2.8); secrets.json is untouched: the old token stays in use
   2. Otherwise discover: found = Vault::discover(backend)     — every vault this login can see (§3.3)
        config.json exists (keys were removed by `logout`)  → the entry with config.vault_id (found: save the token of step
                                                               A.3 now, A.4), else VaultNotVisible with secrets.json untouched; → ATTACH
      VaultNotVisible in B.1 or B.2 while step A.2 kept the login on file (nobody was asked to sign in): the message adds that
      this device is signed in as <email> and that `gclone logout`, then `gclone login`, signs in with another account (§2.8).
      VaultNotVisible in B.1 or B.2 after step A.3 ran (a sign-in was just made and does not see the attached vault): the
      message of §2.8 for a fresh login — what was (not) changed, and the two causes: another Google account, or a vault that
      was created through another OAuth client (the legacy client of §17.18). Never CREATE on a device with a config.json.
                                                               (on an attached device — with or without cached keys — `--new-vault`, or
                                                               a `--vault-id` other than the attached vault, is a usage error naming
                                                               `gclone logout --forget`, checked before step 0; §17.5)
        --new-vault                                          → CREATE
        --vault-id HEX                                       → that entry, else a usage error listing what was found — also when
                                                               nothing was found: a vault asked for by id is never created; → ATTACH
        found is empty                                       → CREATE — except after a sign-in that replaced a legacy login
                                                               on this unattached device (A.4): VaultNotVisible, §2.8
        exactly one entry                                    → ATTACH
        several entries                                      → on a TTY ask which (name, creation date, id prefix); otherwise an
                                                               error listing them and asking for --vault-id; → ATTACH

CREATE (first device)
   passphrase (set, above) → vault_id = 16 random bytes; MK = MasterKey::generate(); Keyring(epoch 1)
   → keyfile generation 1 = seal_keyfile(payload, passphrase, KdfParams::default()), then open_keyfile on the result as a self-test
   → lock → Db::open → Vault::create(…, keyfile)      objects are written in this order: root folder, index/, data/, README.txt,
                                                        the keyfile, the first segment [VaultInit, Device], and the descriptor LAST —
                                                        a vault exists for discovery only once it is complete
   → save config.json (handles, auth_url), then secrets.json (keys)       in this order (§17.5): a cached key never exists
                                                        without the config it belongs to; a kill in between leaves `Locked` (Drive)
                                                        or `NotLoggedIn` (directory), which the next `login` repairs through ATTACH
   → race check (below) → print "Vault created" (§7.3)
   (killed between Vault::create and the save: the next `login` discovers the finished vault and takes ATTACH with the passphrase
    just chosen; the state directory still holds the device id.)

ATTACH (every later device)
   pick the vault's keyfiles (FoundVault.keyfiles: highest generation first) and keep the first KEYFILE_TRY_MAX = 4;
   none → error "this vault has no keyfile" (exit 3)
   → download each (get_all; an object larger than KEYFILE_MAX is skipped) → ask for the passphrase
   → try the candidates in order with it: the first that opens wins. Work is bounded: each (keyfile, passphrase) pair runs at
     most once — a candidate that fails with anything other than WrongKey (damaged, bad KDF parameters, unknown version) is
     dropped for the rest of the command, and a passphrase equal to an earlier attempt is not run again.
     None opens and at least one answered WrongKey → "wrong passphrase", ask again (3 attempts, then
     ConfigError::WrongPassphrase, exit 4). No candidate left → exit 3.
   → payload.vault_id must equal the descriptor's → Keyring, held in memory only
   → lock → Db::open → Vault::open → refresh()        the authoritative identity check: every index object's inner vault_id (§4.6)
        refresh ends with Gap or Rollback (§5.3)      → nothing is published from this device (as for every mutating command);
                                                         continue at the save, and print the verdict as a warning instead of the head
                                                         line: "… This device is connected, but nothing can be changed in the vault
                                                         until the index is repaired: run `gclone repair` …" (exit 0). See below.
        any other refresh error                       → the login fails, nothing is saved
   → commit_ops([Device{id, name}])                   skipped when the replica already lists this device id under this name
   → finish_mutation()
   → ONLY NOW save config.json (handles, auth_url), then secrets.json (keys, min_epoch)      (the same order as in CREATE)
   → print: vault name, file count, device name, and
     "Compare with `gclone status` on a device you trust (run it there now): head XXXX-XXXX, N files.
      A new device trusts the vault as Google serves it; equal head values mean both devices see the same history."
   A failure or kill anywhere before the save leaves the device unconnected (no cached key): the next `gclone login` runs ATTACH
   again — the passphrase is asked again, the state directory keeps the device id, an already published Device op is not
   repeated. A device therefore never counts as connected before the other devices can see it — with one exception:
   A Gap / Rollback verdict does not stop ATTACH (§17.11). The verdict is computed at the end of the refresh, after every
   accepted object was checked against the vault id, so the identity check has passed; what is wrong is the index, and the
   cure is `gclone repair` — which needs the cached key, and for which this device's index cache may hold the only copy of
   the missing objects. A device that had run `gclone logout` could otherwise never log in again while its replica (which
   keeps its marks and `blocked` rows across a logout, §2.7) has such a verdict, and its only way out, `logout --forget`,
   deletes that cache. The device's `Device` op is then not published by `login`; `commit()` announces a device id the
   vault does not list by itself (§5.6) once the index is repaired.
```
**Trust on first use, and the head fingerprint.** A new device has no rollback marks: whatever consistent state it is served first becomes its baseline (§5.3); from then on it detects rollbacks and gaps like any other device. (v1.1 carried marks inside the kit; v1.2 has no channel between devices.) A file count cannot expose a stale baseline — any rollback that keeps the count passes — so the user gets a real comparison value instead:
```
head = Crockford32( BLAKE3( "gclone/v1/head" ‖ for every row of `hw` (§5.3) in ascending device order:
                                                 device (8) ‖ seq (u64 BE) ‖ segment hash (32) ) [0..5] )        40 bits, shown XXXX-XXXX
```
`hw` holds, per device, the greatest `(seq, hash)` this replica has applied or adopted; because every segment names its predecessor and what it has seen by hash (§4.6), two replicas with equal tips have applied the same journal. `Vault::head_fingerprint()` computes it; `gclone status` prints it on every device (after its refresh), and ATTACH prints it at the end. The values are equal on any two devices that are up to date with each other — the trusted device must run `gclone status` *after* the new device attached, so that it has applied the new device's first segment. A new device that was served a rolled-back or truncated journal shows a different value. This needs no channel between devices and no format change; the e-mail shown after login remains the check for "the right account".

**Two first devices at the same time.** Two devices that both find no vault each create one. Handling:
1. The descriptor is written last, so a half-created vault is never discovered; an interrupted creation leaves an orphan folder without descriptor that `login` ignores (the user may delete it in drive.google.com) and the next `login` starts over. **Directory backend**: the orphan keeps the path `DIR/<vault_name>`, and a directory cannot hold a second folder of that name (§9.5) — the next `login --vault-dir DIR` gets `BackendError::Fatal{409, "nameConflict"}` from `Vault::create`, which `cli/login.rs` reports as *"`DIR/<vault_name>` exists but holds no complete vault (an interrupted `gclone login`?). Delete that folder, or choose another name with `--vault-name`."* (exit 1); the same applies to `--new-vault` with a name already present in `DIR`.
2. Right after CREATE (unless `--new-vault`): `found = Vault::discover(backend)`; this device's own vault always counts, listed or not. If another vault is visible, the **winner** is the one with the smallest `(descriptor createdTime, vault_id)` — server clock first, id as the tie-break; both devices evaluate the same rule.
   - This device won: print a warning naming the other vault; nothing else. (The other device discards its vault when it sees this one.)
   - This device lost: trash its own root folder (`backend.trash(root)` — the vault holds nothing but this run's first segment), delete its `config.json`, state directory and cached key, and continue with ATTACH on the winner: *"Another device created the vault a moment earlier; using that one. The passphrase you just set here is NOT in use — enter the passphrase chosen on the other device."*
3. List lag can hide the other vault from this check. Therefore `gclone status` (Drive backend) runs one `find_by_name(DESCRIPTOR_NAME)` and warns when a descriptor whose parent is not the configured root is listed (no download needed): *"Another gclone vault exists in this Drive. If it was created by accident on another device, run `gclone logout --forget` there and `gclone login` again."* A later `login` on a third device sees both and asks (step B.2).

**Recovery.** Google account + passphrase are sufficient on any machine: `gclone login <AUTH_URL>`. Without OAuth at all: download the vault folder from drive.google.com (or Takeout), unzip, `gclone login --vault-dir DIR`, enter the passphrase. A forgotten passphrase is repaired from any still-connected device with `gclone passwd` (it needs no old passphrase). All devices lost **and** passphrase lost = data lost; a printable master-key export (`gclone key export`) is deferred (§14).

### 2.7 `gclone passwd` and `gclone logout`

**`gclone passwd [--passphrase-file PATH]`** (on any connected device; the old passphrase is not asked for — the device already holds the master key):
1. `open_ctx{Exclusive, Required, no settle}`.
2. New passphrase by the setting rules of §2.6.
3. `generation = 1 + max(generation in the names of the listed keyfiles)` (`vault.keyfiles()`; 1 if none is listed), computed with `checked_add`. The device cannot open the listed keyfiles (it has no passphrase), so these numbers are unauthenticated names: an overflow — a stray or planted `gclone-key-ffffffff-…` — is a plain error (exit 1) that names the object: *"keyfile generation exhausted by <name>; remove that object in drive.google.com and run `gclone passwd` again"*; it never panics or wraps. payload = `KeyfilePayload::from_keyring(vault.keys(), generation, device name, now)`; `seal_keyfile(…, KdfParams::default())`; `open_keyfile` on the result as a self-test.
4. `vault.replace_keyfile(&kf)`: `put` into the vault root under a pre-generated ID; the returned size and md5 must match (else trash it and fail); **then** trash every listed keyfile with a lower generation (junk planted under a lower number goes with them).
5. Print: *"Passphrase changed. New devices need the new passphrase; connected devices are unaffected. Copies of the old keyfile (Drive trash for 30 days, backups at Google) still open with the old passphrase — changing the passphrase does not re-encrypt anything."*
Two devices running `passwd` concurrently leave two keyfiles of the same generation; both passphrases work until the next `passwd` retires both. No index operation is written.

**`gclone logout [--revoke] [--forget] [--yes]`**
- Default: delete `<state root>/token.json` and `<state root>/secrets.json` (this device's refresh token and the cached master key), in this order — a logout that stops between the two is still "signed in" for the next one — together with the temp files `.token.json.tmp-<16 hex>` / `.secrets.json.tmp-<16 hex>` that a write killed before its rename left beside them (`util::remove_atomic_leftovers`, §8.1; a temp copy of `secrets.json` holds the refresh token and the cached key). `config.json` — which also remembers the auth Worker URL (§2.2) — and the vault's state directory stay, so a later plain `gclone login` (no URL needed; for a directory vault no `--vault-dir` needed, §2.6 step 0) re-attaches as the same device (same device id, base rows, rollback marks) after asking for the passphrase again. Output: *"Signed out on this device. The Google token was discarded, not revoked — Google can only revoke the login of all devices at once (`gclone logout --revoke`)."* Not signed in (no `secrets.json`) → exit 0 with a note; a `token.json` or temp copy that is there nevertheless is removed, and the note says so (§17.9).
- `--revoke` ("sign out everywhere"; for a lost or stolen device): after a confirmation (TTY, or `--yes`) — *"This ends the Google login of ALL your gclone devices; each needs `gclone login` again. Continue?"* — `POST GOOGLE_REVOKE_URL`, form-encoded `token=<refresh_token>`, no client credentials. `200` → revoked. `400` (`invalid_token`: already revoked or expired) → treated as done. Network failure → error, and the local secrets are kept so the command can be repeated. Then the default deletion. Everything that can still stop the command comes **before** the request, which cannot be taken back: with `--forget`, the unpublished-changes question below is asked after this confirmation and before the revoke; declining it ends the command with exit 5, nothing revoked and nothing removed (§17.9). *Why this is not the default:* Google documents that revocation "removes all OAuth 2.0 scopes previously granted to a project, invalidating any issued access or refresh tokens for all clients registered under that project" (RESEARCH §6.3) — there is no per-token revoke. Whether files stay visible after revoke + new consent is manual probe 3; in v1 the confirmation text **always** carries that warning (*"It is unverified whether the vault stays visible after a new sign-in — keep a web download of the vault folder first."*). Removing the sentence is an Errata change to this spec once probe 3 has passed; the binary has no way to know.
- `--forget`: additionally delete `config.json` (and with it the remembered auth Worker URL: the next `gclone login` needs `AUTH_URL` again) and this vault's state directory (index replica with plaintext paths, base tables, device id). If `pending`/`outbox` hold unpublished changes this needs `--yes` or a TTY confirmation.
- Directory-backend vaults: `--revoke` is a usage error; the rest applies.
A discarded-but-not-revoked refresh token stays valid at Google until it is unused for six months or falls out of the 100 newest tokens of the account; it existed only on this device.

### 2.8 Failure modes (exact user-facing text is owned by `cli/`)
| Condition | Message core | Exit |
|---|---|---|
| `ConfigError::NotConfigured` (no `config.json`) | "This device is not connected. Run `gclone login <AUTH_URL>`." — "Run `gclone login`" when the build has `GCLONE_DEFAULT_AUTH_URL` or the environment has `GCLONE_AUTH_URL` (§2.2: the argument is then not needed, §17.14) | 4 |
| `ConfigError::NotLoggedIn` (`config.json` exists but there is no `secrets.json` — after `logout`, **either backend** — or a Drive vault whose secrets hold no refresh token) | "This device is not connected (signed out). Run `gclone login`." — for a directory vault: "… Run `gclone login --vault-dir <config.backend.path>`." | 4 |
| `ConfigError::Locked` (`secrets.json` exists with `keys == []`: signed in, but the vault part of `login` did not finish) | "Run `gclone login` to finish connecting this device (it will ask for the passphrase)." | 4 |
| `ConfigError::InsecurePermissions` (`secrets.json` or its directory is owned by another user or has group/other permission bits, §8.1) | "Refusing to use <path>: it is readable by others. Fix with `chmod 700 <dir>; chmod 600 <file>` — and if it was copied or restored from somewhere, treat the login and the key as exposed." | 4 |
| `ConfigError::WrongPassphrase` | "Wrong passphrase." (after 3 attempts, or at once with `--passphrase-file`) | 4 |
| `AuthError::Expired` (`/refresh` → `invalid_grant`) | "Google no longer accepts this device's login (revoked, signed out everywhere, or unused for 6 months). Run `gclone login`." On a TTY, offer to run it now. | 4 |
| same, and the login on file belongs to the legacy client (`secrets.json` without `client`; the usual cause is that the Worker has no legacy secrets any more and refused without asking Google, §2.3) | instead: "This device's login was made with the browser sign-in of gclone before 0.2.0, and the auth Worker no longer serves it (or Google ended it). Run `gclone login`." | 4 |
| same, and `refresh_expires_at_ms` is set and `now ≥ refresh_expires_at_ms − 1 day` | instead: "This login was time-limited by Google and ended on DATE: the OAuth app is still in *Testing*. Open Google Auth Platform → Audience → Publish app, then run `gclone login`." | 4 |
| token response carries `refresh_token_expires_in` (during `login`) | §2.4 expiring-grant text; nothing is stored unless `--allow-expiring-login` | 4 |
| `AuthError::NotAllowed` | "The auth Worker does not allow this Google account (<the Worker's message, which shows the address masked: `s***@example.net`>). Sign in with the right Google account, or add the address to ALLOWED_EMAILS (worker/README.md)." | 4 |
| `AuthError::WorkerMisconfigured` | "The auth Worker cannot authenticate to Google: its secrets are missing or wrong, or the OAuth client was deleted (Google removes clients idle for 6 months; restorable for 30 days). Fix it per worker/README.md — restore the client, or create a new "TVs and Limited Input devices" client **in the same Cloud project** and `wrangler secret put` its ID and secret — then retry." | 4 |
| `AuthError::Denied` / `ScopeMissing` / `LoginFailed` / `Timeout` | "Sign-in was not completed (<reason>). Run `gclone login` again." — `Timeout`'s reason: "the code was not entered at Google before it expired; a code is good for 30 minutes"; for the Worker's `403 grant_unusable` the reason is the Worker's own sentence ("Google approved the sign-in, but its answer carried no ID token …") | 4 |
| `gclone login` on a device that holds a login of the legacy client and is attached to no vault, when the new sign-in sees no vault (§2.6 A.4) | "The Google login just made (signed in as <email>) sees no gclone vault. This device's previous login was made with the browser sign-in of gclone before 0.2.0, so a vault created back then may exist without being visible to the new login. Nothing was changed: the previous login stays on file. First run `gclone login` on a device that is attached to the vault and wait for "Vault unchanged."; then run it here again (see "Moving from the browser sign-in" in worker/README.md). If there really is no vault yet, create one with `gclone login --new-vault`." | 4 |
| `AuthError::BadAuthUrl` | "The auth Worker URL must be https://… (given: <url>)." | 4 |
| `AuthError::Network` | "Could not reach the auth Worker at <AUTH_URL> (<detail>)." Read-only commands print it as a warning and show the last state this device has seen (§9.10). | 4 |
| `IndexError::VaultNotVisible` (`403 appNotAuthorizedToFile`; or, in `login` on an attached device, the stored vault cannot be found with the new login) | "This Google login cannot see the vault this device is attached to (another Google account, a new Cloud project, or the app was removed and approved again). Sign in with the account that owns the vault. If the files are really out of the app's reach: download the vault folder from drive.google.com, unzip it, and run `gclone logout --forget`, then `gclone login --vault-dir DIR`." In `login`, when the login on file was kept (§2.6 A.2), followed by: "This device is signed in as <email>, and `gclone login` keeps a login that still works: to sign in with another account run `gclone logout` first, then `gclone login`." In `login`, when a sign-in was just made (§2.6 A.3), **instead**: "The Google login just made (signed in as <email>) cannot see the vault this device is attached to. <kept> If that was not the Google account that owns the vault: run `gclone login` again and choose the right one. If it was: Google does not show the vault's files to this login — they were created through another OAuth client (the browser sign-in of gclone before 0.2.0, or another Cloud project), or the app was removed and approved again. See "Moving from the browser sign-in" in worker/README.md for the ways out (keep the legacy secrets on the Worker, or move the vault); the last resort is to download the vault folder from drive.google.com, unzip it, and run `gclone logout --forget`, then `gclone login --vault-dir DIR`." with `<kept>` = "Nothing was changed: this device keeps its previous login, which goes on working as long as the auth Worker has its GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET secrets." when the sign-in was to replace a login of the legacy client, else "Nothing was changed on this device, and the new sign-in was not kept." | 4 |
| vault root trashed | "The vault folder is in the Drive trash. Restore it in drive.google.com (it is deleted for good after 30 days)." | 3 |
| `IndexError::UnsupportedObject` (an index object in a format this build does not read, §4.6) | "index object <name> is in a format this gclone cannot read (<what>): this vault needs a newer gclone. Update gclone on this device. If no newer gclone has ever written to this vault, the object was not written by gclone: remove it from the vault's `index` folder in drive.google.com." Read-only commands print the first sentence as a warning and show the last state this device has seen. | 3 |
| keyfile missing or damaged (ATTACH) | "The vault's keyfile is missing or damaged. Run `gclone passwd` on a connected device to write a new one." | 3 |
| last refresh > 150 days | warning line in `status`/`about` | 0 |
| `refresh_expires_at_ms` set | `status`: "Login expires in N days (OAuth app in Testing? → Publish app, then `gclone login`)" | 0 |
| OAuth unusable entirely | Download the vault folder from drive.google.com (or Takeout), unzip, then `gclone login --vault-dir ./gclone` (passphrase) and `gclone copy : ./out`. `./gclone` is the downloaded vault folder itself (the one containing `gclone-vault.json`); see §3.3. Works because nothing essential lives in Drive metadata. | — |
| lost device | Printed by `logout --help`/docs: `gclone logout --revoke` on any other device (or remove the app at https://myaccount.google.com/permissions ) — ends the login of **all** devices — then `gclone login` on each one you keep. Warning: whether files stay visible after revoke + re-consent is unverified (manual probe 3) — keep a web download first. The thief still holds the cached master key: data he could already download stays exposed (re-keying is deferred). | — |

### 2.9 Day-0 probes (gate the first real use)
`gclone probe` (hidden command) runs the rows marked **A** against a throwaway folder and prints one line per row. Rows marked **M** need a consent at Google, a second device or days of waiting; they are a checklist in `README.md` (WP0) to be ticked by hand once.

| # | How | Question | If the answer is bad |
|---|---|---|---|
| 1 | M | Publish the app (client of type *TVs and Limited Input devices*) with `openid email drive.file`: no verification, no warning screen; the Worker-hosted home and privacy pages are accepted; the `/device/poll` answer has **no** `refresh_token_expires_in` once published (and has it in Testing) | Setup text changes; in the worst case weekly `gclone login` (unacceptable resting state). `login` itself detects the Testing case (§2.4). |
| 2 | M | Two devices, two logins of the same account: both refresh tokens keep working side by side, and device 2 discovers and reads the vault device 1 created | The design depends on it (documented behaviour: up to 100 live tokens per account and client; one app identity because one client). No fallback short of sharing one token. |
| 3 | M | `gclone logout --revoke` on device 2: is device 1 signed out too (documented: yes)? After a new `login`: is the vault listed again? | If a revoke is per token after all: make it the default of `logout`. If files are not visible after re-consent: the lost-device procedure must go through web download + `--vault-dir` (`VaultNotVisible`). |
| 4 | M | A second OAuth client in the same project sees the files the first one created — in particular the device client of 0.2.0 for a vault created through the *Web application* client before it (§17.18): `gclone login` on such a device ends with "Signed in again … Vault unchanged." | `login` reports `VaultNotVisible` with the fresh-login text of §2.8 and changes nothing; the legacy secrets stay on the Worker or the vault is moved (worker/README.md). `WorkerMisconfigured` recovery must use web download. |
| 5 | M | The first real `gclone login`: Google's device-code endpoint accepts the client with `SCOPES` (verified 2026-11-12: `{device_code, user_code, expires_in: 1800, interval: 5, verification_url: "https://www.google.com/device"}`); after the consent, the token answer carries an **ID token** with `email` / `email_verified` (without it `/device/poll` says `403 grant_unusable` and the device ends the login with that sentence) and a refresh token; the `scope` of that answer holds nothing but members of `ALLOWED_SCOPES` (otherwise `/device/poll` says `scope_not_allowed` and names the entry); the error code Google uses for a code that ran out is `expired_token` | No ID token → every login fails closed; the Worker must then ask Google's userinfo endpoint with the access token instead (Errata). A harmless scope spelling outside `ALLOWED_SCOPES` → add it to the set in `worker/src/google.ts` and here (Errata). Another code for an expired device code (e.g. `invalid_grant`) → harmless: the device stops at its own deadline or reports "the code is no longer valid". |
| 6 | A | `409` with a pre-generated ID — at resumable initiation or at completion? multipart? Does `stat` right after the 409 find the object? | all paths are implemented (§6.2 conflict rule). |
| 7 | M | Sustained create rate; does session initiation count? | tune `PACK_MEMBER_MAX`/pacer start. |
| 8 | A (timing printout) | `files.list` lag after a write; `files.get` read-after-write | `GAP_GRACE` tuning; first-device race window (§2.6). |
| 9 | A | `size`, `md5Checksum`, `createdTime` present in the completion body when `fields=` was sent at initiation | the follow-up `stat` fallback (§6.2) carries the load. |
| 10 | A | `generateIds` max `count` | pool falls back to 10. |
| 11 | M | Trashed file downloadable by ID | affects self-heal wording only. |
| 12 | A | Exact multipart size boundary | we stay at ≤ 4 MiB. |
| 13 | A | Is a resumable upload invisible to `files.list` until finalised? | index never references unfinished objects anyway. |

---

## 3. Remote layout on Drive

### 3.1 Tree
```
My Drive/
  <vault_name>/                      folder, default name "gclone"   (root)
    gclone-vault.json                plaintext descriptor (hint only), written once — and written LAST when a vault is created (§2.6)
    gclone-key-<gen:08x>-<h8>        keyfile: the master key wrapped under the passphrase (§2.6); a new object per `passwd`, older ones trashed
    README.txt                       "Encrypted gclone vault. Do not rename, edit or delete anything in here."
    index/                           folder
      s-<dev16>-<seq:016x>-<h8>      journal segment   (Stream type 0x02)
      c-<lamport:016x>-<dev16>-<h8>  snapshot          (Stream type 0x03)
    data/                            folder
      <dev16>-<n:04>/                per-device data folder, rolled at DATA_FOLDER_MAX = 100,000 objects
        <blob_id:32 hex>             data blob: one large file or a pack (§4.5)
```
`dev16` = 16 lowercase hex chars of the 8-byte device id; `h8` = first 8 hex chars of BLAKE3(object bytes); `gen` = keyfile generation; all numbers lowercase hex, zero padded — except the data-folder counter `<n:04>`, which is **decimal** (`format::blob::data_folder_name`; nothing parses that name, the folder is found by its stored ID or by listing `data/`).

### 3.2 Rules
- Every object is **put once** with a pre-generated Drive ID and never updated. `mimeType` = `application/octet-stream`; folders `application/vnd.google-apps.folder`. No `appProperties`, `description`, `modifiedTime` writes.
- Drive fields read (`FIELDS`): `id, name, size, md5Checksum, createdTime, mimeType, trashed, parents` (wire shapes: §6.4.1).
- **Identity**: the index stores each blob's Drive file ID (fast path) *and* the blob name is its `blob_id` (portable path). If a stored ID yields `NotFound`, readers resolve by name (`find_by_name`) — this is what makes web-download/Takeout recovery and account moves work.
- A device writes blobs only into its own current data folder (created lazily, ID pre-generated; folder ID and object count kept in `state.db` meta `data_folder_id`, `data_folder_n`, `data_folder_count`).
- Deletion is `trashed = true` (30-day undo by Google). gclone never calls `files.emptyTrash` (it is account-wide). `files.delete` is called by exactly one code path, `gclone gc --purge`, and only on file IDs taken from the local blob table (§5.9).
- `appDataFolder` is not used (Google deletes it when the app is disconnected).

### 3.3 Discovery, descriptor, versioning
Descriptor `gclone-vault.json` (plaintext, untrusted hint):
```json
{ "gclone_vault": 1, "min_reader": 1, "vault_id": "<32 hex>", "created_ms": 1794400000000 }
```
- **Discovery** (`Vault::discover`, used only by `gclone login`, by the first-device race check and by the `status` warning of §2.6): `find_by_name("gclone-vault.json")` returns every descriptor this login can see. Under `drive.file` that is exactly the set of vaults created through this OAuth client for this account — every device signs in through the same client, so every device sees the same set (manual probe 2). For each hit: download and parse the descriptor (an unparsable one, or one with `min_reader` above this build, is skipped with a warning; so is one longer than `DESCRIPTOR_MAX` = 64 KiB — by its listed size, and again by what arrives: the read is `get_bounded`, §9.5, because the listed size is the store's claim and the descriptor is plaintext that anyone with access to the account can plant); the vault root is the **parent of the descriptor, at whatever depth** — for a vault created by `login --vault-dir DIR` that is `DIR/<vault_name>`, for a downloaded vault folder passed as `--vault-dir` it is the backend's top level (`Handle::top()`, §9.5); `index` and `data` are the root's children of those names (exactly one each, else an explicit error: "two folders named index in the vault; remove the stray one in drive.google.com" — never a silent pick); the keyfiles are the root's children whose names parse as `gclone-key-<gen>-<h8>`. No hit → no vault → `login` creates one. Which vault `login` uses when several exist: §2.6 step B.2. All other commands use the IDs stored in `config.json`; a re-login checks them with `Vault::verify_visible` (`stat` by ID, never a listing).
- Authoritative vault identity is the `vault_id` inside every authenticated index object, and the `VaultInit` op. The descriptor's and the keyfile's `vault_id` are hints that must agree with it.
- Versioning: descriptor `gclone_vault`/`min_reader`; stream magic `GCS1` + `suite` byte; index payload `codec` byte + versioned postcard enum; `VaultInit.format`. Unknown version anywhere → fail closed: "this vault needs a newer gclone" — for an index object that means the refresh stops (`IndexError::UnsupportedObject`, §4.6 "Unreadable is not corrupt"); it is never skipped as damaged.
- All listings use `trashed = false` and loop on `nextPageToken` (short pages happen). If `list(index)` is empty while the local replica is not: `stat(root)`; `trashed` → `IndexError::VaultTrashed`; missing → `IndexError::VaultMissing`.

---

## 4. Crypto and on-disk formats (byte level)

Primitives: HKDF-SHA-256 (RFC 5869); ChaCha20-Poly1305, 96-bit nonce (RFC 8439); Argon2id v1.3 (RFC 9106); BLAKE3 (plaintext hashes, object hashes); MD5 (only to compare with Drive's `md5Checksum`). Randomness: `getrandom::fill`. All secret byte arrays live in `zeroize::Zeroizing`. Check values are compared with `util::ct_eq` (constant time).

### 4.1 Key hierarchy
```
MK_e            32 random bytes per key epoch e (MVP: only e = 1 exists)
K_{e,label}   = HKDF-SHA-256(salt = vault_id(16), ikm = MK_e, info = "gclone/v1/key/" ‖ label, L = 32)
                labels: "data" (file content), "index" (segments, snapshots)
K_pass          see §2.6 (keyfile only; key_epoch field = 0): derived from the passphrase, wraps the MK_e
```
(The auth Worker performs no cryptography of its own since 0.2.0: the sealed login blobs and their `SEAL_KEY` went with the browser-redirect flow, §2.3.1.)
`Keyring` holds `{epoch → MK}`, `vault_id` and `min_epoch`. A stream whose `key_epoch` is unknown → `CryptoError::UnknownEpoch`; `< min_epoch` → `CryptoError::EpochTooOld`. `min_epoch` is local and monotonic (never lowered).

### 4.2 Stream container (the only ciphertext format)
Header, `HEADER_LEN = 60` bytes:
```
off len field
0   4   magic        "GCS1" = 47 43 53 31
4   1   suite        0x01 = HKDF-SHA-256 + ChaCha20-Poly1305 STREAM
5   1   chunk_log2   12..=24 accepted; writers always use 16 (64 KiB)
6   1   type         0x01 Data, 0x02 Segment, 0x03 Snapshot, 0x05 Bundle   (0x04 is reserved for a future blob manifest, §4.5; v1 rejects it)
7   1   flags        0x00 (reserved: bit 0 = "plaintext is zero-padded"; v1 readers reject ≠ 0)
8   4   key_epoch    u32 BE (0 for Bundle)
12  16  salt         OS CSPRNG, fresh for every stream ever sealed
28  32  commit
```
Purpose key by type: Data → `K_{e,"data"}`; Segment, Snapshot → `K_{e,"index"}`; Bundle → `K_pass` (the keyfile body, §2.6).
```
PRK        = HKDF-Extract(salt = hdr[12..28], ikm = K_purpose)
OKM        = HKDF-Expand(PRK, info = "gclone/v1/stream" ‖ 0x00 ‖ hdr[0..12], L = 64)
stream_key = OKM[0..32]
commit     = OKM[32..64]          checked in constant time before any chunk is opened
```
`hdr[0..12]` in `info` authenticates suite, chunk size, type (domain separation), flags and epoch.

**Error precedence when opening a stream** (normative; the first failing check decides the error):
1. fewer than 60 header bytes → `Truncated`; magic ≠ `GCS1` → `BadMagic`.
2. `Unsupported` (reported to the user as "needs a newer gclone"), checked in this order and before any key derivation: suite ≠ 0x01; `chunk_log2` outside 12..=24; type byte not one of {0x01, 0x02, 0x03, 0x05}; flags ≠ 0. (`Header::decode` performs steps 1–2.)
3. Through a `Keyring` only: epoch < `min_epoch` → `EpochTooOld`; else epoch not held → `UnknownEpoch`. (In this order: `Keyring::new` refuses held epochs below `min_epoch`, so checked the other way round `EpochTooOld` could never be reported.)
4. Header type ≠ the type the caller expects → `WrongKey` (also when both types share a purpose key, e.g. Segment vs Snapshot).
5. Commit mismatch → `WrongKey`.
6. Chunk errors: `Corrupt` (tag failure, wrong final flag), `Truncated`, `TrailingData`.

Chunks: plaintext split into `C = 2^chunk_log2` bytes.
```
chunk i  = ChaCha20-Poly1305(key = stream_key, nonce = 0x000000 ‖ u64_be(i) ‖ final, aad = "", pt_i) → ct_i ‖ tag(16)
final    = 0x01 for the last chunk, else 0x00            (nonce = 11-byte BE counter ‖ flag, as in age)
```
Rules (age): only the last chunk may be shorter than `C`; the last chunk is empty **only** if the whole plaintext is empty (then exactly one empty final chunk); end of input without a verified final chunk is an error (`Truncated`); bytes after the final chunk are an error (`TrailingData`); `i ≥ 2^64 − 1` is an error.

Lengths and offsets (`n` = plaintext length):
```
chunks(n)          = max(1, ceil(n / C))
ciphertext_len(n)  = 60 + n + 16 * chunks(n)
chunk i occupies   [60 + i*(C+16), 60 + i*(C+16) + len(pt_i) + 16)   relative to the container start
plaintext_len(L)   : None if L < 76; else b = L − 60, q = b div (C+16), r = b mod (C+16):
                       r = 0        → q·C                      (the last chunk is full)
                       0 < r < 16   → None                     (shorter than a tag)
                       r = 16       → 0 if q = 0, else None    (an empty chunk is legal only as the single chunk of an empty plaintext)
                       r > 16       → q·C + r − 16
```

Misuse resistance (normative for the API, §9.4):
- `Sealer::new` draws the salt itself; no public constructor takes a salt or nonce.
- A `Sealer` seals chunks strictly in order, exactly once each; there is no "re-seal chunk i".
- Sealed bytes may be replayed (retries) but are never regenerated. If an upload must restart from plaintext, a **new** `Sealer` (new salt) and a **new** blob id / Drive ID are used.
- Openers release plaintext only after the chunk's tag verified.

**Data streams and the index.** For type Data the index entry (`Loc`, §4.4) stores `suite`, `flags`, `salt`, `chunk_log2`, `epoch`, and (in `Entry`) `size`. Readers construct the opener **from the index entry** (`Keyring::data_opener(&Loc)`), never from the stored header: an unknown `Loc.suite` or a non-zero `Loc.flags` is rejected with `Unsupported` *before any key derivation* (a future writer's file reads as "needs a newer gclone", not as tampering); otherwise the expected 60 header bytes are recomputed from the `Loc`; a full read compares them with the stored header (mismatch = `Corrupt`), a ranged read skips the header entirely. Which chunk is final is decided from the authenticated `Entry.size`, never from Drive's size. A swapped, sliced, older or truncated object therefore fails on the first chunk touched; full reads additionally check BLAKE3 against `Entry.hash`.

**`cat` to a pipe** emits verified chunks as they arrive; a later failure is signalled only by a non-zero exit code. Documented in `cat --help`.

### 4.3 KDF (keyfile only)
See §2.6 for the preamble, the written parameters (256 MiB, t = 3, p = 1), the accepted bounds (at most 512 MiB, t ≤ 4, p = 1 — checked before any allocation) and the passphrase normalisation. `argon2` crate: `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m_kib, t, p, Some(32)))`, `hash_password_into(passphrase_bytes, salt, &mut out)`; the 256 MiB working memory is allocated by the crate (`alloc` feature) and the call runs on a blocking thread. One derivation takes roughly a second on a laptop and a few seconds on a small ARM board; it happens once per device (`login`; at most `KEYFILE_TRY_MAX` × 3 derivations when keyfiles or passphrase attempts fail) and once per `passwd`.

### 4.4 Shared plain types (serialized with postcard inside index objects; field order is frozen, enums append-only)
```rust
pub struct DeviceId(pub [u8; 8]);
pub struct BlobId(pub [u8; 16]);
pub struct Stamp { pub lamport: u64, pub device: DeviceId, pub idx: u32 }   // Ord = lexicographic (lamport, device, idx)
pub struct Loc { pub blob: BlobId, pub off: u64, pub clen: u64, pub salt: [u8; 16], pub chunk_log2: u8, pub epoch: u32,
                 pub suite: u8, pub flags: u8 }   // the Data stream's header bytes 4 and 7; v1 writers emit 1 and 0
pub enum EntryKind { File, Dir }
pub struct Entry { pub kind: EntryKind, pub size: u64, pub mtime_ns: i64, pub exec: bool,
                   pub hash: [u8; 32],            // BLAKE3(plaintext); all-zero for Dir
                   pub loc: Option<Loc> }         // None for Dir and for zero-length files
pub struct BlobRec { pub id: BlobId, pub file_id: String, pub clen: u64, pub md5: [u8; 16], pub created_ms: u64 }
pub struct SegRef  { pub device: DeviceId, pub seq: u64, pub hash: [u8; 32], pub file_id: String }
pub struct CoveredSeg { pub device: DeviceId, pub seq: u64, pub h4: [u8; 4] }   // h4 = hash[0..4] = the name's h8; Ord = (device, seq, h4)
```
`Loc.off` is the byte offset of the member's 60-byte header inside the blob; `Loc.clen = ciphertext_len(size, chunk_log2)`.

### 4.5 Data blob
```
blob     = member_0 ‖ member_1 ‖ … ‖ member_{k-1}
member_j = Stream(type Data) of one file's content            (k = 1 for a large file; k ≥ 1 for a pack)
blob_len = Σ ciphertext_len(size_j)                            exact before streaming (needed for Content-Length)
```
- **No trailer in v1.** Reserved for a later version (so that `repair --from-blobs` can be added without a format break): the bytes after the last member may one day be `manifest ‖ u64_be(len(manifest)) ‖ "GCBLOB01"` with the manifest sealed as stream type 0x04. v1 readers never look at blob bytes that no `Loc` names, so such blobs stay readable; when the trailer is specified it must come with acceptance rules as strict as those of §4.6 (bound to vault id and blob id, members contiguous and in range).
- Read-side bound (transfer layer, before any range request): `loc.off + loc.clen ≤ BlobRec.clen`, else `TransferError::Verify`.
- Pack parameters (`PACK_MEMBER_MAX`, `PACK_TARGET`) are client tunables, not part of the format.

### 4.6 Index objects
Both kinds are one Stream whose plaintext is `codec u8 (0x00 = postcard; 0x01 reserved for zstd+postcard)` ‖ postcard(body).
```rust
pub enum SegmentBody  { V1(SegmentV1) }
pub enum SnapshotBody { V1(SnapshotV1) }

pub struct SegmentV1 {
    pub vault_id: [u8; 16], pub device: DeviceId, pub seq: u64,     // seq starts at 1 per device
    pub lamport: u64,                    // all ops of this segment share it; op i has Stamp{lamport, device, idx: i}
    pub prev: Option<SegRef>,            // this device's previous segment (None iff seq == 1 after a device-id birth)
    pub seen: Vec<SegRef>,               // per OTHER device: the greatest (seq, hash) known when writing (sorted by device)
    pub created_ms: u64, pub host: String,
    pub ops: Vec<Op>,
}
pub enum Op {
    VaultInit { format: u16, name: String },
    Device    { id: DeviceId, name: String },
    Blob      (BlobRec),
    Put       { path: String, entry: Entry, base: Option<Stamp>, origin: Option<Stamp> },
    Del       { path: String, base: Stamp },
}
pub struct HeadRec    { pub path: String, pub stamp: Stamp, pub entry: Entry, pub origin: Option<Stamp> }
pub struct RemovedRec { pub path: String, pub stamp: Stamp, pub entry: Entry, pub removed_ms: u64, pub by: Stamp }   // `by` = the superseding op (§5.2.2)
pub struct DeviceRec  { pub id: DeviceId, pub name: String, pub first_ms: u64 }
pub struct SnapshotV1 {
    pub vault_id: [u8; 16], pub device: DeviceId, pub lamport: u64, pub created_ms: u64,
    pub vault_format: u16, pub vault_name: String,
    pub covers: Vec<SegRef>,             // tips: per device the covered segment with the greatest (seq, hash), with its file id (sorted by device)
    pub covered: Vec<CoveredSeg>,        // EVERY segment folded into this snapshot — exact identities, fork branches included (sorted, unique)
    pub devices: Vec<DeviceRec>,
    pub blobs: Vec<BlobRec>,             // every blob referenced by `heads` or `removed`
    pub heads: Vec<HeadRec>,             // ALL heads (winners and conflict losers), sorted by (path, stamp, entry.hash)
    pub removed: Vec<RemovedRec>,        // versions removed within HISTORY_KEEP (35 days), sorted by (path, stamp, entry.hash)
}
```
Names: segment `s-<dev16>-<seq:016x>-<h8>`, snapshot `c-<lamport:016x>-<dev16>-<h8>` (§3.1).

**Coverage is an exact set.** "Snapshot S covers segment (d, seq, hash)" means `(d, seq, hash[0..4]) ∈ S.covered` — nothing else. No rule anywhere compares a sequence number with a snapshot's tip. `covered` grows by about 14 bytes per segment ever written (§15); `covers` exists so that `prev`/`seen`/rollback marks have a full `SegRef` for each device's tip.

**Acceptance of an index object** (all MUST hold, else the object is reported as `corrupt index object <name>` and counts as **missing** for every reference or mark that points at it, §5.3 — with one exception, "Unreadable is not corrupt" below: a refusal that is about the object's *version* stops the refresh instead):
1. The whole object is downloaded into memory — it is at most `INDEX_OBJECT_MAX` (1 GiB, §6.1) long; `BLAKE3(bytes)[0..4]` equals the name's `h8`. The bound is part of the format: writers refuse to seal a larger object (`seal_segment` / `seal_snapshot` → `BadEntry`), and a reader never buffers more — an object *listed* with a larger size is not requested, and a download stops as soon as more than the bound has arrived (`backend::get_bounded`; the listed size is a claim of the store). Nothing in the object is authenticated at that point, so its own length must not decide how much memory is spent.
2. Header type matches the name prefix (`s-` ↔ 0x02, `c-` ↔ 0x03); commit and **every** chunk verify (`open_all`). No partial/streaming parse.
3. `codec` is known; the body version (the tag of the versioned postcard enum) is known; postcard decodes with no trailing bytes.
4. Inner `vault_id` equals the local vault id; inner `device` and `seq` (segments) or `lamport` and `device` (snapshots) equal the name's.
5. Every `Put`/`Del` path (segments) and every head/removed path (snapshots) passes `path::validate` (§5.1); one invalid path rejects the object as a whole.
6. Every `Entry` is well-formed: with a `Loc` → kind File, `size > 0`, `chunk_log2` in 12..=24, `clen == ciphertext_len(size, chunk_log2)`; without → kind Dir, or kind File with `size == 0`. (An unknown `Loc.suite` or non-zero `Loc.flags` is **not** a rejection: the entry is kept and reading it fails with `Unsupported`.)
7. Snapshots: `covers` is sorted with one entry per device, `covered` is sorted and unique, and every `covers` tip is in `covered`.

A replayed old object has the identity of one already applied or already in the base snapshot's `covered` set → inert. A renamed object fails 1 or 4.

**Unreadable is not corrupt.** An object of the store that passes rule 1 and is then refused **because of a version** was written by a newer gclone. It is not reported as corrupt and does not count as missing — a device that skipped it would plan and write against an index that lacks another device's newest state and exit 0. The refresh stops with `IndexError::UnsupportedObject { name, what }` (exit 3, text in §2.8) and returns no report; accepted segments it applied before it met the object stay applied (they are authentic), nothing is derived from the object itself. `repair` starts with the same refresh and stops the same way, so it never republishes or snapshots around such an object, and `--accept-loss` cannot be used to step over it. The version reasons are exactly (`FormatError::newer_format`):

| Refusal | `what` | Authenticated? |
|---|---|---|
| `CryptoError::Unsupported` — header suite ≠ 0x01, `chunk_log2` outside 12..=24, type byte not a v1 type (0x04 included), flags ≠ 0 (§4.2 step 2) | `unsupported stream suite` / `… chunk size` / `… type` / `… flags` | no — read before any key is derived |
| `CryptoError::UnknownEpoch` — a key epoch this device does not hold (§4.2 step 3) | `key epoch <e>` | no |
| `FormatError::Codec` — codec byte ≠ 0x00 (rule 3) | `index codec <c>` | yes — inside the plaintext, after every chunk verified |
| `FormatError::BodyVersion` — body enum tag ≠ 0 (rule 3) | `body version <v>` | yes |

Everything else stays "corrupt … counts as missing": `BadMagic` (v1 never changes the magic; a later format changes `suite`), `EpochTooOld` (a refusal by local policy, not a version), `WrongKey`, `Corrupt`, `Truncated`, `TrailingData`, a postcard error, rules 4–7, an object above `INDEX_OBJECT_MAX`.

The header rows are **not authenticated** — a suite this build does not implement cannot be checked by it — and `h8` is an unkeyed hash, so anyone who can write to the `index` folder can plant such an object and stop every device until it is removed (the message names the object and says so). That is a denial of service of the kind §1.3 already accepts from the same parties (they can also trash the journal), it is loud, and it never changes a replica; the alternative, skipping, fails open on exactly the objects a format change produces. The stop applies to bytes that came from the store (listed, or fetched by the id a reference carries). A copy in the local index cache that does not open is only dropped and the store asked again — the cache holds accepted objects only, and it must not be able to keep a refresh stopped after the object was removed from the store.

### 4.7 Test-vector expectations (WP1 produces and freezes them; see §13)
Fixed inputs for known-answer tests: `MK = 00 01 … 1f`, `vault_id = a0 … af`, `salt = c0 … cf`, epoch 1, chunk_log2 16 (and 12 for small multi-chunk cases), plaintext `pt[i] = (i * 7 + 3) mod 256`.
- **KAT** (fixed salt, therefore **unit tests inside `src/crypto/stream.rs`** — integration tests cannot reach the `#[cfg(test)]` fixed-salt constructor): for plaintext lengths {0, 1, 4095, 4096, 4097 (chunk_log2 12)} the test computes the expected container independently from raw `hkdf` + `chacha20poly1305` calls *and* compares with the frozen file, loaded by `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/stream_v1.json"))` (generated once by `GCLONE_GEN_VECTORS=1 cargo test -- --ignored gen_vectors`, then committed; without that variable the `gen_vectors` test returns at once, so the live run of §13 item 10 — which also passes `--ignored` — never rewrites the frozen file). RFC 5869 / RFC 8439 / RFC 9106 vectors pass for the underlying crates. Everything below needs only the public API and lives in `tests/crypto_format.rs`.
- **Round trip**: lengths {0, 1, C−1, C, C+1, 2C, 2C+5, 3C} seal → open equal; `ciphertext_len`/`plaintext_len` inverse; `plaintext_len` is `None` for L ∈ {0, 59, 75}, for a last chunk of 1..15 bytes, and for an empty non-first chunk; `Sealer` output length equals `ciphertext_len`.
- **Tamper** (each MUST fail with the stated error; "via Keyring" = `Keyring::open`, "raw" = `Opener::from_header` with the right purpose key):
  | Flipped bit in | Error |
  |---|---|
  | magic (bytes 0..4) | `BadMagic` |
  | suite (byte 4) | `Unsupported` |
  | chunk_log2 (byte 5) | `Unsupported` if the value leaves 12..=24, else `WrongKey` |
  | type (byte 6) | `Unsupported` if the value is not a v1 type, else `WrongKey` |
  | flags (byte 7) | `Unsupported` |
  | key_epoch (bytes 8..12) | via Keyring: `UnknownEpoch` (or `EpochTooOld`); raw: `WrongKey` |
  | salt, commit | `WrongKey` |
  | any chunk or tag | `Corrupt` |
- **Truncation**: cut at every chunk boundary, cut to header only, cut mid-chunk → `Truncated`/`Corrupt`; append one byte → `TrailingData` **when the final chunk is full** (plaintext length a non-zero multiple of `C`), otherwise `Corrupt` or `TrailingData`: the container does not record its length, so a byte appended to a shorter final chunk (or to an empty stream) cannot be told from damage to that chunk. Readers that know the size from the authenticated index entry (data blobs, §4.2) always can.
- **Swap/reorder**: swap chunks i and j; duplicate a chunk; drop a middle chunk; present a non-final chunk as final and vice versa → `Corrupt`.
- **Cross-stream swap**: open stream A's bytes with a `Loc` carrying B's salt → fails on the first chunk; a chunk-aligned slice of A presented as a whole stream → fails; an old version of the same path (different salt) → fails.
- **Wrong context**: right bytes, wrong expected `StreamType` → `WrongKey` (Data vs Segment and Segment vs Snapshot); wrong epoch key → `WrongKey`/`UnknownEpoch`; `data_opener` with `Loc.suite = 2` or `Loc.flags = 1` → `Unsupported` without touching a key; `Keyring::seal(StreamType::Bundle, …)` → `Misuse`.
- **Random access**: for random `(off, len)`, `chunk_range` + ranged open equals `pt[off..off+len]`.
- **Keyfile** (tests use small explicit `KdfParams { m_kib: 8192, t: 1, p: 1 }`, plus one round trip at `KdfParams::default()`): seal → open round trip; the name carries `gen` and the `h8` of the bytes; wrong passphrase → `Crypto(WrongKey)`; a flipped byte in the stream body → `Crypto(Corrupt)`; a flipped byte with the name unchanged → `KeyfileDamaged` (h8); a flipped preamble byte with a recomputed name → `WrongKey` (the preamble is the HKDF salt) or `KdfParams`; out-of-bounds KDF parameters (`m_kib = 4096`, `m_kib = 524289`, `m_kib = 1048576`, `t = 0`, `t = 5`, `p = 2`, `alg = 2`) rejected **without** running Argon2 — while `m_kib = 524288, t = 4` is accepted; payload `v = 2` → `KeyfileVersion`; `gen` in the name ≠ payload → `KeyfileDamaged`; a keyfile larger than `KEYFILE_MAX` → `KeyfileDamaged`.
- **Passphrase**: `from_input` table — trailing newline dropped; NFC (`"e\u{301}…"` equals `"é…"`); the generated shape is canonicalised (`"abcde-fghjk-mnpqr-stvwx"`, `"ABCDE FGHJK MNPQR STVWX"`, `"ilo…"` → `1`, `1`, `0`) while a 19- or 21-symbol text and a text with other characters are left untouched; `generate()` yields 20 Crockford symbols in the `XXXXX-XXXXX-XXXXX-XXXXX` form and `from_input(generate().display())` is the identity; `set_checked` rejects 11 characters and accepts 12 (counted in scalar values, not bytes).
- **Index objects**: acceptance rules 1–7 each have a negative test (renamed object, wrong vault, truncated at a chunk boundary, trailing postcard bytes, path `../x`, `Loc.clen` off by one, `chunk_log2 = 11`, unsorted `covered`, a tip missing from `covered`; an object of `INDEX_OBJECT_MAX + 1` bytes → `BadEntry` without being hashed). Codec byte 1 → `Codec(1)`, body tag 1 → `BodyVersion(1)`; `FormatError::newer_format` is `Some` for exactly the four refusals of the §4.6 table.
- **Blob**: `blob_len` equals the bytes actually produced for packs of {1, 2, 500} members.

---

## 5. Sync engine

### 5.1 Paths and names
- A remote path is a UTF-8 string of `/`-separated components. `path::validate` rejects: empty path, leading or trailing `/`, empty component, `.` or `..`, NUL, any component > 255 bytes, total > 4096 bytes. Validation runs when ops are created, when index objects are accepted, and again before any local write.
- The index stores the **exact** name as found on disk (no normalisation). Local names that are not valid UTF-8 are skipped and counted.
- **Comparison key** (planner only): `cmp_key(path, fold) = NFC(path)` if `!fold`, else `NFC(casefold(NFD(path)))`, where `casefold` is Unicode **full case folding** (`caseless::default_case_fold_str`; never `str::to_lowercase`, which is context-sensitive — final sigma — and can leave non-NFC output). `fold` = the local file system of the sync root is case-insensitive. Local and remote entries with the same key are the *same file* even if spelled differently; which spelling an action uses is fixed by §5.5 ("one spelling per key"); spelling differences are not propagated in the MVP (reported with `-v`). No user-space key reproduces every file system's folding exactly; §5.7 step 3 is the backstop.
- **Fold probe** (`sync::probe_fold_case`, once per sync root): macOS → `pathconf(root, _PC_CASE_SENSITIVE)` when it answers. Otherwise, writable root → create `.gclone-probe-<rand>`, `lstat` its upper-cased name, remove it. Read-only root → `lstat` a case-swapped spelling of an existing entry whose name contains a cased letter (or of the root's own basename through its parent) and compare `st_ino`. Nothing to compare → assume `fold = true` (the conservative answer: more collision skips, never an overwrite).
- **Collisions**: two local entries, or two remote entries, with the same key → both are skipped and reported (`SkipReason::KeyCollision`); never pick one silently.
- **Conflict copy name** (deterministic, in the index): for final component `c`, let `i` = last `.` in `c` with `i > 0`; `stem = c[..i]`, `ext = c[i..]` (or `stem = c`, `ext = ""`). Name = `stem ‖ ".conflict-" ‖ dev8 ‖ "-" ‖ lamport_decimal ‖ ext`, with `dev8`/`lamport` taken from the **loser's stamp**. If that exceeds 255 bytes, truncate `stem` at a char boundary. The copy is always a valid path (§17.11): the name is also cut — `stem` first, then `ext` — so that the whole path stays within 4096 bytes; and where not even the bare `.conflict-<dev8>-<lamport>` fits beside the parent (a parent within about 40 bytes of the limit), the copy is placed in the nearest ancestor directory that has room for the name (the vault root always has), still cut to 255 bytes. (A copy that cannot be named would fail `stage` — and with it every resolution, i.e. every mutating command and `repair`, on every device that sees the conflict.)
- **Local conflict name** (when a local file must be moved aside): `stem.conflict-local-<YYYYMMDDTHHMMSSZ>ext` (UTC now, `util::format_utc_compact`); if taken append `-2`, `-3`, ….
- Always ignored locally (never uploaded, never deleted): names starting with `.gclone-partial-` or `.gclone-probe-`, and gclone's own directories where they lie under the sync root (§5.5.3). The root's `.gcloneignore` is honoured (gitignore syntax, §5.5.3) and itself synced like any file.

### 5.2 Index state and merge rule

#### 5.2.1 State
Per path the state is a **set of heads**: the applied `Put` versions that no applied op has superseded — under causal application (§5.3) exactly those whose stamp no applied op names as its `base`. Usually one. Additionally: a `removed` list (versions that stopped being heads, with removal time and the superseding op, kept `HISTORY_KEEP` = 35 days), the blob table, the device table.

`winner(path)` = the head with the greatest stamp. The visible tree is `{path → winner}`. Other heads are *conflict losers* until resolved (§5.2.3).

#### 5.2.2 Applying ops (the whole merge rule)
Op `i` of segment `S` has `stamp = (S.lamport, S.device, i)`; `removed_ms` = Drive `createdTime` of the segment object (server clock; `ObjMeta.created_ms`).
```
apply(Put{path, entry, base, origin}, stamp):
    if base is Some(b): supersede(path, b, by = stamp)
    insert head (path, stamp, entry, origin)
apply(Del{path, base}, stamp):
    supersede(path, base, by = stamp)             // no head (path, base): nothing happens — the deleter had not seen the
                                                  // current version, so a put beats a concurrent delete
supersede(path, b, by):
    every head (path, b) moves to `removed` with (removed_ms, by)
    a `removed` row (path, b) whose recorded `by` is greater than this `by` gets (removed_ms, by) replaced
                                                  // several ops may supersede one version: the smallest superseding stamp is recorded,
                                                  // whatever the application order
apply(Blob(rec)):   upsert blob
apply(Device{..}):  upsert device (first_ms = removed_ms of the segment)
apply(VaultInit{format,..}): format > SUPPORTED_FORMAT → IndexError::NeedsNewerGclone
```
There is **no collapse step**: two heads with identical content are two heads until `resolve_conflicts` removes one (§5.2.3 rule 1). (A collapse inside `apply` would make the result depend on the application order.)

Properties (property-tested, §13): segments are applied in **causal order** (§5.3: a segment is applied only after its `prev` and all its `seen` references), and under that condition the resulting state — heads **and** the `removed` list with its `removed_ms`/`by` — is the same for every causal order and every grouping; `state(snapshot ⊕ uncovered segments) == state(all segments)`. No tombstones exist: a deleted path simply has no heads. An ancestor of the winner is never a head, so it never becomes a spurious conflict.

`lamport` rule: a new segment gets `lamport = 1 + max(local lamport, lamport of everything applied)`; applying a segment raises the local lamport to at least its value. Causal successors therefore always carry greater stamps than their bases.

Writer-side invariant: one segment never contains two `Put`s for the same path (drafts cannot name a stamp of their own segment as `base`). `commit()` debug-asserts it and §12.1 tests it; it holds because leftover staged ops are always committed before a new plan is made (§5.8). Receivers apply whatever an authenticated segment contains.

Forks (two different accepted segments with the same `(device, seq)` — cloned device state, §5.3) are both applied; because coverage is hash-exact (§4.6) a fork branch is never mistaken for a covered or already-applied segment, however late it arrives. Stamps may then tie: two heads of one path with equal stamps are ordered by `entry.hash` (bytewise) — a head's full identity is therefore `(path, stamp, entry.hash)` — and an op whose `base` equals such a stamp removes **all** heads of that path carrying it (they stay restorable in `removed`). A warning is printed once per fork. Two further tie rules keep fork results independent of the application order (§17.3): when two superseding ops carry the **same** stamp (fork twins), the `removed` row keeps the smaller `removed_ms` (the comparison is on `(by, removed_ms)`); when two versions collide on `(path, stamp, entry.hash)`, the one whose postcard encoding is smaller is kept. Histories without forks are unaffected.

#### 5.2.3 Deterministic resolution (`Vault::resolve_conflicts`)
Run by every mutating command right after `refresh` and the commit of leftover staged ops (§5.8, §10), again by `finish_mutation`, and before writing a snapshot. All resolutions are ordinary ops in one new segment; they are idempotent if several devices emit them. `resolve_conflicts` always ends with `commit()`, even with zero resolutions (so nothing staged can outlive it).
1. **Multiple heads at a path** (winner `W`, each loser `L`):
   - `L.entry.same_content(W.entry)` (equal `kind`, `size`, `hash`; `loc`, mtime and exec are ignored): emit only `Del{ path, base: L.stamp }`. No conflict copy — this covers two devices uploading the same content concurrently (first sync of the same folder) and two devices resolving the same conflict.
   - otherwise: emit `Put{ path: conflict_name(path, L.stamp), entry: L.entry, base: None, origin: Some(L.stamp) }` and `Del{ path, base: L.stamp }`. (Two devices doing this produce two identical heads at the conflict path; the next resolution drops one by the same-content rule.)
2. **File vs directory**: a winner `F` of kind File at path `p` while any other path with prefix `p ‖ "/"` has a head: the *file* moves: `Put{ conflict_name(p, F.stamp), F.entry, base: None, origin: Some(F.stamp) }` + `Del{ p, base: F.stamp }`.
3. A `Dir` head at `p` and a File head at `p`: handled by rule 1 (the greater stamp wins, the loser becomes a conflict copy; a losing `Dir` entry is just deleted, no copy).
Read-only commands show winners only and print `N unresolved conflicts — any sync will materialise them` when losers exist.

Cost (as implemented, §17.11): resolution runs at least twice per mutating command and "are there losers?" once per refresh, so none of it may scan `heads`. The losers are read through the partial index `heads_losers` (§8.4). Rule 2 can only become true when the heads of a path change — the file's own, or those of a path below it — so `apply` records every path whose heads it changes in the table `touched` (§8.4), and a round looks only at those paths and their ancestors; the table is emptied when a round finds nothing left to do. The whole table is scanned instead, once, after the replica's content was replaced by a snapshot (`rebuild_from`) or when more than 16,384 paths were touched (`meta.resolve_all`).

### 5.3 Refresh (pull) — `Vault::refresh`
Local persistent sets (in `state.db`, §8.4):
- `applied{(dev, seq, hash) → file_id, name, lamport, created_ms, size}` — segments applied since the base snapshot (rows the base covers are pruned).
- `base_covered{(dev, seq, h4)}` — the `covered` set of the *base snapshot* (the snapshot this replica was last rebuilt from, wrote, or adopted; empty if none) and `base_covers{dev → (seq, hash, file_id)}`, its tips.
- `hw{dev → (seq, hash, file_id)}` — the rollback marks: per device the greatest `(seq, hash)` this replica ever applied or adopted through a snapshot. Never lowered except by `repair --accept-loss`. A new device starts with an empty table (trust on first use, §2.6): marks are never imported from anywhere. The **head fingerprint** shown by `status` and `login` is a hash over this table (§2.6).
- `own{seq → (hash, file_id)}` — every segment this replica sealed under its current device id (cleared when the id rotates); its last row is the `prev` of the next segment.
- `blocked{name → first_seen_ms}` — **local** clock (`Vault`'s clock, `util::now_ms` by default); server-supplied times are never used for grace periods.

Definitions — all hash-exact:
- An identity `(dev, seq, hash)` is **known** iff it is in `applied` or `(dev, seq, hash[0..4]) ∈ base_covered`.
- A segment is **inert** iff it is known. A reference (`prev`, a `seen` entry, a mark) is **satisfied** iff it is known. A mark is thus a statement about the local replica, never about a listing.
- An object is **available** iff its bytes are in hand (just downloaded, or in the index cache), `BLAKE3(bytes)` equals the hash the reference or name claims, and it passes §4.6. A listed name or a successful `stat` never makes anything available. An object that fails acceptance counts as missing for whatever points at it (it stays blocked → `Gap`, or the mark stays unsatisfied → `Rollback`) — **except** an object refused for its version, which ends the refresh with `UnsupportedObject` (§4.6 "Unreadable is not corrupt").
- A segment is **applicable** iff it is available, not inert, its `prev` is `None` or satisfied, and every `seen` ref is satisfied.

```
refresh():
  L = backend.list(index)                          // one paged call; names + handles + sizes. Names are unauthenticated hints.
  if L is empty and the replica is not: check root (§3.3) → VaultTrashed / VaultMissing / continue
  recover_outbox()                                 // §5.8. A temporary failure (QuotaExceeded, RateLimited, Transient) is NOT an error here:
                                                   //   report.outbox_stuck = true and refresh continues
  if machine_fingerprint() != meta.machine_fp: rotate_device_id()        // copied or restored state directory (below)
  cand = segments of L that are not inert ∪ cached segments that are not inert
  fetch (parallel, 8) every cand object not in the cache; keep the available ones; store their ciphertext in the cache
                                                   //   every fetch of an index object, here and below, reads at most INDEX_OBJECT_MAX bytes (§4.6 rule 1);
                                                   //   objects listed above INDEX_PARALLEL_MAX are fetched one at a time, after the others;
                                                   //   an object in a newer format → Err(IndexError::UnsupportedObject) (§4.6)
  if ∃ accepted segment in cand with inner device == my device and (seq, hash) ∉ own ∪ outbox: rotate_device_id()    // clone
  tried = {}; rebuilt = false
  loop:
      repeat: A = applicable segments of cand, sorted by (lamport, device, seq, hash)
              apply all of A in ONE SQLite transaction (ops per §5.2.2; insert into `applied`; raise hw; raise lamport)
      until A is empty
      U  = unsatisfied prev/seen references of (cand − applied)  ∪  unsatisfied marks of hw
      S* = snapshot_news(L)
      if U is empty and S* is None: break
      if S* is Some and S*.covered ⊆ known:                 // it covers nothing this replica lacks
            if S*.covered ⊇ base_covered: adopt(S*)
            meta.snap_checked = S*.name; continue
      if not rebuilt:
            S = best_snapshot(L, U ∪ (S*.covered − known))
            if S exists: rebuild_from(S); rebuilt = true; meta.snap_checked = S.name; recompute cand; continue
      added = false
      for r in U − tried:                                   // list lag; objects trashed by a cleanup are still readable by ID
            tried += r
            bytes = backend.get(r.file_id); on NotFound: the object L lists under r's segment name, if any
            if available(bytes, r): add the segment to cand; added = true
      if not added: break
  update `blocked` (local clock) for the segments still in cand − applied; drop rows that are no longer blocked
  verdict, in this order:
      a mark in hw is unsatisfied                                   → Err(IndexError::Rollback{device, seq})   // defensive, no grace: marks are raised only by
                                                                                                                 // applying or covering, so this means a damaged or
                                                                                                                 // partly restored state.db
      a blocked row has local_now − first_seen_ms ≥ GAP_GRACE      → Err(IndexError::Gap{names})
      presence_check() fails                                        → Err(IndexError::Rollback{device, seq})
  return RefreshReport{applied, blocked_young, conflicts, forks, rotated_device, rebuilt_from, adopted, outbox_stuck, corrupt_objects}

snapshot_news(L):   the accepted snapshot in L with the greatest inner lamport (candidates are tried newest name first; one that fails
    acceptance is reported and skipped) — unless its name equals meta.snap_checked or the base snapshot's name, then None.
    Each new snapshot is therefore downloaded and parsed once per device (cached like every index object). A newest snapshot that
    covers something this replica lacks but is not usable stays unchecked and is reported as a warning on every refresh.

adopt(S):           base_covered := S.covered; base_covers := S.covers; base_snapshot_{name, lamport, size} := S; delete the `applied` rows
    S covers. Heads are untouched (the replica already contains everything S does). This is how a device follows another device's
    compaction without re-loading state and without writing a snapshot of its own.

best_snapshot(L, W): accepted snapshots in L, greatest inner lamport first (downloaded on demand). Return the first S that is
    useful:  S.covered contains at least one identity of W                        (never rebuild for nothing), and
    usable:  every identity in (applied ∪ base_covered ∪ hw) that S does not cover is available (cache or L)
             (it is re-applied after the rebuild, so nothing this replica knows is lost — "never go backwards", stated exactly).

rebuild_from(S):    one transaction: clear heads, removed, devices, applied and the blob rows without `trashed_ms`; load S;
    base_covered := S.covered; base_covers := S.covers; base_snapshot_{name, lamport, size} := S; hw := max(hw, S.covers).
    Everything S does not cover is then re-applied by the normal loop (from L and the cache). `base` rows, `pending`, `outbox`, `own` stay.

presence_check():   every row of `applied` and every mark in hw must be *remotely present*:
        (a) L lists the segment name (dev, seq, h8); or
        (b) an accepted listed snapshot has the identity in its `covered` (the base snapshot first — answered from `base_covered`
            without reading it, see "as implemented"; then snapshots parsed in this refresh; others on demand); or
        (c) backend.stat(file_id) returns the object un-trashed            // list lag; evaluated only when (a) and (b) fail
    and the base must still be on offer: base_covered is empty, or L lists the base snapshot's name, or an accepted listed
    snapshot's `covered` ⊇ base_covered.
    Presence is about what the remote still holds for *other* devices; names suffice for it because the replica already has the data.
    A failure means objects this device has seen are gone: `gclone repair` republishes them (§5.10).

rotate_device_id(): new random device id, next_seq := 1 (prev = None), clear `own` and the data-folder meta, store the current
    machine fingerprint, warn once. A stuck outbox row stays as sealed (old id) and is published later. Triggers:
        • an **accepted** segment whose inner device is this device's id but whose (seq, hash) this replica never sealed (not in `own`,
          not the outbox row) — at any seq, lower than next_seq or not. A listed name alone never triggers a rotation.
        • machine_fingerprint() = BLAKE3(host id ‖ u64_be(st_ino of the index-cache directory)) differs from meta.machine_fp; host id =
          `gethostuuid(2)` on macOS, the contents of /etc/machine-id on Linux (empty if unreadable). The hostname is deliberately not part
          of it. A state directory copied to another machine or restored from a backup rotates **before** it seals anything.
          First run: store the fingerprint, no rotation. (Tests may pin it through `OpenParams.machine_fp`.)
```
Applying a segment whose `(device, seq)` is already known under another hash counts as a fork (`report.forks`, one warning).

As implemented (WP4, §17.3) — precisions of the pseudo-code above, same resulting state:
- The "repeat … until A is empty" rounds are one priority topological order (`causal_order`: among the ready segments the smallest `(lamport, device, seq, hash)` first, O(n log n)), applied in one transaction.
- The by-ID fetch of an unsatisfied reference (`for r in U − tried`) additionally requires that `stat(file_id)` still shows the object **under the expected segment name**; presence check (c) requires the name as well. A renamed segment is therefore missing for whatever references it (§12.1 adversary case), and `gclone repair` on a device that holds it republishes it.
- "An accepted listed snapshot" — in the presence check (b), in `cleanup_index` (set `K`) and in `repair`'s republish step — counts only if a listed object is known to hold the accepted bytes (downloaded now, or its size and md5 equal the cached copy). A cached copy alone still serves as a state source (adopt / rebuild / candidates). The base also counts as "still on offer" when `stat(base_snapshot_id)` shows it un-trashed (list lag right after writing or adopting a snapshot).
- The machine-fingerprint check also runs in `Vault::open` and at the start of `commit`, so a copied state directory rotates before it seals anything even if `commit` is called without a `refresh`; the next `refresh` reports `rotated_device = true`.
- With an empty listing and a non-empty replica, `refresh` stats the index folder as well as the root (trashed → `VaultTrashed`, absent → `VaultMissing`).
- `IndexError::Gap.names` holds the names of the **missing** objects the blocked segments wait for, not the names of the blocked segments.
- Examining another device's snapshot (adopting it, or only marking it `snap_checked`) raises the local lamport to the snapshot's (see §5.6 for why).
- Warnings of the library (forks, rotation, dropped staged ops, corrupt objects, skipped descriptors) go through `tracing::warn!`, not through `Ui`.
- Presence rule (b) for the **base snapshot** needs no parse (§17.11): its coverage is `base_covered`, and it counts as an accepted listed snapshot when the listing shows an object of its name with the size and md5 this replica recorded when it accepted it (`base_snapshot_size`, `base_snapshot_md5`; a backend without md5: the size). Only when that does not settle an identity are other snapshots loaded. (Before, every rollback mark whose segment a cleanup had trashed — the tip of every device that has not written since — made every refresh of every device read and decode a whole snapshot.)
- A cached segment that is a candidate while the listing does not show it (list lag, or trashed by a cleanup) is recorded with the **place this replica knew**: after a rebuild the old `applied` rows (id and creation time) and the old base tips and marks (id), which the rebuild transaction also stores in `meta.remembered` until the segments are applied again, so that a crash in between loses nothing; else the id that `own`, `hw` or `base_covers` hold for its name. Where only the id is known, one `stat(id)` supplies the creation time (the object must still carry the name; a trashed one counts). Only when nothing is on record, or that object is gone, is the segment recorded without an id and with the writer's `created_ms` — and such an `applied` row takes the id of the listed object as soon as a listing shows one of its size (and md5, against the cached copy). Without the id, presence rule (c) cannot be evaluated — a segment of this device that is merely not listed yet then ended the refresh in `Rollback` — and this device's `seen` references and snapshot tips carried an empty id (§17.11). In the presence check an `applied` row without an id uses the id of the mark for the same segment.

Error policy: `Gap`/`Rollback` make **mutating** commands exit 3 with the advice `gclone repair`; read-only commands print the warning and continue on the consistent replica (`RefreshPolicy::Tolerant`, §9.10). A stuck outbox (`outbox_stuck`) blocks only operations that must publish a new segment (they fail with `IndexError::OutboxStuck`, exit 75); `ls`, `cat`, downloads, `check` and `gc` keep working. Blocked segments younger than `GAP_GRACE` are silently retried on the next run (they are list lag in practice). Nothing is ever applied out of causal order except by `repair --accept-loss`.

### 5.4 Local scan (`sync::scan`)
- Walker: `ignore::WalkBuilder` with `standard_filters(false)`, `hidden(false)`, `follow_links(false)`, parallel, and **no** ignore-file support of its own (no `add_custom_ignore_filename`): the one `Filter` of §5.5.3 is applied through `filter_entry` only, so local and remote exclusion can never disagree. What the filter prunes is recorded in `LocalScan.excluded` (root-relative, as spelled on disk; nothing under a pruned directory is visited) — the local part of the per-key exclusion of §5.5.3.
- Per entry `lstat`: regular file → `File`; directory → descend, and record as `Dir` **only if it ends up with no included children**; symlink, FIFO, socket, device → skipped, counted per type, **and its relative path recorded in `LocalScan.skipped_paths`**; non-UTF-8 name → skipped and counted.
- `StatSig { size, mtime_ns, ctime_ns, ino, mode }` — ctime is part of the signature (it cannot be forged by `touch -r`/`cp -p`). `LocalEntry.observed_ns` is the local time at which `sig` was taken.
- **Scan errors**: a failed `readdir`/`lstat` adds the directory's relative path to `LocalScan.failed_dirs`. Everything under a failed directory is *unknown*, not absent (§5.5.2 rule G1).
- **Unsupported replacements**: a base-known key that is now at or under a path in `skipped_paths` (a synced directory replaced by a symlink, a file replaced by a FIFO) is *unknown* as well — `Skip(Unsupported)`, never "absent", so it can never turn into a `DelRemote`.
- Stale `.gclone-partial-*` files are deleted when encountered: regular files to which nothing was done for 24 h (`PARTIAL_STALE`), judged by the **newer of mtime and ctime**. The mtime alone does not tell: a download gives a complete file the mtime of the file it will be — years back, as a rule — and the file then waits under its partial name for its batch (§5.7 step 3a). The ctime moves with everything a download does to the file (create, write, `fchmod`, `futimens`) and cannot be set by anybody, so a file that some gclone process is still working on is never stale (§17.16).
- **Racy-timestamp rule**: a base row stores `observed_ns` (when the signature was taken). A row is *trusted* iff `max(mtime_ns, ctime_ns) + RACY_WINDOW (2 s) < observed_ns`. Untrusted rows never short-cut hashing. A row that had to be re-hashed and matched is **refreshed** (`RecordBase`, §5.5.1 row 1), and files written by a download are re-observed at the end of the run (§5.7 step 5); a file is therefore hashed at most once per change of its signature, not on every sync.
- **Hash resolution** (`sync::resolve_hashes`, I/O, before planning): BLAKE3 the local file iff (a) a base row exists and (`sig` ≠ base sig or the row is untrusted), or (b) no base row and a remote entry exists at the same key, or (c) no remote entry at the key and some live index entry has the same size (reuse candidate), or (d) `--checksum`. Files are opened `O_NOFOLLOW | O_NONBLOCK`, `fstat`ed before and after; equal → `sig` and `observed_ns` are taken from that `fstat` pair; a difference → the entry is marked `changed_during_scan` and skipped this run. The function returns the number of files hashed (`Summary.hashed`).
- `scan` and `resolve_hashes` are plain synchronous functions (parallel through the walker / `std::thread::scope`); `sync::run` calls them inside one `spawn_blocking` with owned inputs.

### 5.5 Planner (`sync::plan`, a pure function)
Inputs per comparison key: `L` local entry (or absent / unknown), `R` remote winner under the prefix (or absent), `B` base row (or absent). Base rows live per *pair* = (canonical local root, remote prefix).

**Pair identity.** A pair records the root directory's `(st_ino, birth time)` (`Metadata::created()`: `st_birthtime` on macOS, `statx` btime on Linux; 0 where unavailable — then `st_ino` alone decides). `st_dev` is deliberately **not** part of it: device numbers change across reboots and remounts (external disks, NFS/SMB, LVM, btrfs/ZFS, macOS mount order). If the identity differs from the recorded one, nothing is discarded silently: `sync::run` stops with `GuardKind::RootChanged` (exit 5) — *"local root X is not the directory last synced with :P (it was replaced, restored, or its file system has no stable inode numbers)"* — unless the user passes `--reset-pair` (drop the pair's base rows; the run is a conservative first sync that deletes and overwrites nothing) or `--keep-pair` (it is the same directory: keep the rows, record the new identity). On a TTY the user is asked which. **`--reset-pair` is honoured whether or not the identity changed** (§17.12): a tree that was damaged or restored *inside* the same directory keeps its inode, the guard does not fire, and the flag must still give the first sync it promises. `--keep-pair` with an unchanged identity asks for what happens anyway and is accepted silently. A dry run with `--reset-pair` plans without base rows and drops nothing.

Classification:
```
local:   absent | unknown (under failed_dirs, changed_during_scan, or base-known and at/under skipped_paths)
         same      B exists and (sig == B.sig and B trusted, or hash == B.hash)
         changed   B exists and hash != B.hash
         new       B absent
remote:  absent
         same      B exists and R.stamp == B.remote_stamp
         changed   B exists and R.stamp != B.remote_stamp
         new       B absent
"equal content" = same kind and (size, hash) equal.
```

**One spelling per key** (normative). Local and remote may spell a key differently (NFC vs NFD between macOS and Linux, case on a folding file system). If `R` exists, every remote op for the key — `Put`, `Del`, base effect — uses **`R`'s exact path**; if `L` exists, every local op uses **`L.rel`**. Only when one side is absent is the other side's spelling used for the new entry, and then each **ancestor directory** is mapped to the spelling that already exists on the destination side (longest key-prefix match against existing remote paths for uploads, against existing local directories for downloads): a new local file `Foo/new` goes to remote `foo/new` when the index has `foo/…`. `plan()` asserts `base.is_some() ⇒ remote_path == R.path`. Without this rule a `Put` under a new spelling with `base = R.stamp` would supersede nothing and leave both spellings in the index.

#### 5.5.1 Decision table (`copy` = table without the two delete rows; `sync` = full table)
| # | local | remote | UP (local → remote) | DOWN (remote → local) |
|---|---|---|---|---|
| 1 | same | same | — ; `RecordBase` (current sig, its `observed_ns`, `remote_stamp` unchanged) if *same* had to be established by hashing; `SetRemoteMeta` if exec differs or \|Δmtime\| ≥ 2 s between `L` and `R` **and the local metadata changed since `B`** (exec, or mtime at all — see the precision below) | — ; `RecordBase` likewise; `SetLocalMeta` if exec differs or \|Δmtime\| ≥ 2 s between `L` and `R` |
| 2 | changed | same | `Upload` (base = R.stamp) | `Skip(LocalChanged)`; `--force`: `Download` |
| 3 | same | changed | equal content: `RecordBase`; else `Skip(RemoteNewer)`; `--force`: `Upload` (base = R.stamp) | `Download` (or `SetLocalMeta` if equal content) |
| 4 | new | absent | `Upload` (base = None) | `Skip(LocalOnly)` — never deleted |
| 5 | absent, B absent | new | `Skip(RemoteOnly)` — never deleted | `Download` |
| 6 | new/changed | new/changed, equal content | `RecordBase` | `RecordBase` |
| 7 | new/changed | new/changed, different | `Upload` with **base = B.remote_stamp** (or None) → the index keeps both: the remote version becomes a conflict copy (§5.2.3) | move local aside to the local conflict name, then `Download` |
| 8 | absent, B exists | same | **`DelRemote`** (base = R.stamp) *(sync only)* | `Download` |
| 9 | same | absent, B exists | `Skip(RemoteDeleted)`; `--force`: `Upload` | **`DelLocal`** *(sync only)* |
| 10 | absent, B exists | changed | `Skip(RemoteNewer)` | `Download` |
| 11 | changed | absent, B exists | `Upload` (base = None; a put beats the delete) | `Skip(LocalChanged)` |
| 12 | absent | absent, B exists | `ForgetBase` | `ForgetBase` |
| 13 | unknown | any | `Skip(ScanError)` / `Skip(Unsupported)` | `Skip(ScanError)` / `Skip(Unsupported)` |
`Upload` becomes `Reuse` (index-only, zero bytes sent) when a live index entry has equal `(size, hash)`; it becomes `MkdirRemote` for `Dir`. `Download` becomes `MkdirLocal` for `Dir`. Rows 8/9 for `Dir` entries: `DelRemote` / `RmdirLocal` (plain `rmdir`, failure ignored — never recursive).
First sync (no base rows at all) can therefore never delete or overwrite anything.

Precisions (as implemented, §17.4):
- **`copy` and destination-only entries.** Rows 4-DOWN and 5-UP are planned as `Skip(LocalOnly)` / `Skip(RemoteOnly)` in both modes, but in `copy` mode the executor neither adds them to `Summary.skipped` nor emits a skip event (debug log only): leaving what exists only at the destination alone is what `copy` means, and counting it would make every `copy` into a destination that holds other files exit 6. In `sync` mode they are reported and the run exits 6 — on **every** run until the user copies them to the source side or removes them; there is no `--force` variant of these two rows. Because that is the steady state of two devices that only ever `sync` up into one remote directory, the texts say so (§17.14): the skip reasons read "only in the vault and never synced here; kept (copy it down, or gclone rm)" / "only local and never synced; kept (copy it up, or delete it yourself)", and after the result line `copy.rs` prints one `hint:` line on stderr with the count and the exact `gclone copy DST SRC` command, stating that `--force` does not delete such entries.
- **Empty-directory marker facing a directory with content** (a `Dir` entry exists only while the directory is empty, so one side can hold the marker while the other holds files under it — typical after a `copy`): a remote `Dir` head whose local directory has entries plans only a `RecordBase` of kind `Dir` (zeroed signature; `Dir` rows compare by kind), and nothing once that row exists; a local empty-directory entry whose remote side has rows under it plans nothing — unless the run is a `sync` upload whose plan deletes **every** remote row under it (the user emptied the directory and kept it): then a `MkdirRemote` (base `None`) is planned for it in the same run, so the vault keeps the directory instead of losing it with its last entry and getting it back as a new directory only from the next upload (in between, other devices pruned theirs and a download on this device reported it as "only local", exit 6). If step 3 suppresses the deletes, the marker merely faces content until the next run. Removing the directory later then follows rows 8 / 12 as for any synced entry. The planner lists every such local directory in `Plan.keep_dirs` (local spelling), and the executor never prunes it (§5.7 step 3): when the same run deletes the directory's last file, the directory stays, because the remote still says it exists — pruned, the next upload would read its absence as the user's delete (row 8) and remove the marker, and with it the directory on every device (§17.12).
- **Row 1 UP pushes only metadata that changed here** (§17.12). A base row recorded for *equal content* (rows 3 UP and 6) stores the local signature next to a remote entry whose mtime or exec bit may differ; that difference is not a change this device made. Pushing it (as the table once said: whenever `L` and `R` differ) made two devices that both only upload the same bytes with different mtimes rewrite each other's entry forever — `RecordBase` on one run, `SetRemoteMeta` on the next, one index `Put` per file per device every second run. `SetRemoteMeta` therefore also requires `L.sig.mtime_ns ≠ B.sig.mtime_ns` or `L.exec ≠ B.exec`: a `touch` or `chmod ±x` after the row was written goes up as before; an inherited difference stays until a download (`SetLocalMeta`, rows 1 and 3 DOWN, unchanged: downward the remote entry is the truth) aligns the local file. Consequence: after two devices upload identical content, the remote keeps the first uploader's mtime and exec bit, and the second device's file keeps its own until it syncs down.
- **Row 7 DOWN with a remote directory and an unsynced local file**: `MkdirLocal { expect_local: Absent }`; the executor moves the file aside to the local conflict name (keep both) and then creates the directory.
- **The remote prefix is a directory.** `sync::run` refuses (`SyncError::Usage`, exit 2, before any work, both directions and modes) a prefix that is a file in the index or has a file among its ancestors: the planner sees type changes only *below* the prefix, so an upload would put entries under a file — the index would then move that file to a conflict name (§5.2.3 rule 2) while the run reported success — and a download would find nothing and exit 0. An empty-directory marker is fine in both directions, and so is — for an **upload** — a prefix that does not exist yet (the upload creates it). A **download from a prefix that does not exist** (not the root, no `Dir` head, no winner under it) is refused with `SyncError::Io(NotFound)` — "`:P`: no such directory in the vault", exit 1 — before the local root is created, in both modes and for a dry run (§17.14): a mistyped path in a restore must not end as "nothing to transfer", exit 0, with an empty directory left behind. One exception keeps `sync` whole: when the pair already has base rows, the directory was synced before and has been removed from the vault since, and the run proceeds — `sync` down then deletes what it had downloaded (rows 9 / 12, under G4). `check --download :P` (nothing at or under `P`) and `check LOCAL :P` (no such directory) fail the same way instead of reporting "Checked 0 files: all good" (§5.9). Copying a single file by naming it is not part of the MVP; a local root that is a file is `Usage` with that explanation and a pointer to `gclone cat`.

**Type changes (file ↔ directory).** `plan()` detects every key `p` that is a file on one side while the other side has entries under `p/`, and emits the actions involved as an ordered group in `Plan.groups` (`TypeChange { first, then }`, indices into `Plan.actions`):
- DOWN, `sync`: `first` = the guarded local deletes of the old type (`DelLocal p`; or `DelLocal` of every base-known child followed by `RmdirLocal p`), `then` = the `MkdirLocal`/`Download` actions that need the path. `execute` runs `first` before the transfer phase; if any of them is skipped or fails (signature mismatch, directory not empty because of local-only files), every `then` action becomes `Skip(UnsafeTarget)`. Nothing is moved aside.
- UP, `sync`: `first` = the `DelRemote`s of the old type, `then` = the uploads of the new type. The `Del` drafts are staged **in the same `stage()` call as the group's first `Put`** and therefore land in the same segment: no other device ever sees the file and the directory together (§5.2.3 rule 2 would move the fresh file to a conflict name). If none of the group's uploads succeeds, its `Del`s are not staged.
- `copy` (either direction) cannot delete: every action of the group becomes `Skip(Unsupported("type change: use sync"))`.
- Within one key (remote `Dir` at `p` vs local file `p`, or remote file vs local empty directory): `MkdirLocal` / `Download` carry `expect_local` (`LocalExpect::File(sig)` / `LocalExpect::EmptyDir`); the executor removes exactly that expected entry (`unlink` after the signature check, or `rmdir`) and then creates the new one. Anything else in the way → `Skip(UnsafeTarget)` (exception: the row-7 case above, where an unsynced local file is moved aside).
- As implemented (§17.4): a group whose old type cannot be removed **completely** — an old-type key whose action is not a delete (a remote child this device never saw, an included local-only file) — is settled at plan time: its new-type actions become `Skip(UnsafeTarget)`, no group is formed, and the deletes that were planned stay ordinary step-3 deletes. The run-time path above remains for what only the executor can see (signature mismatch, a directory kept by a file the scan does not show). There is **no** separate `RmdirLocal p` action for a directory that becomes a file on download (it would be a second action on key `p`): the group's `Download p` carries `LocalExpect::EmptyDir` and the executor removes the emptied directory after the group's `DelLocal`s. An upload-side group whose uploads are all skipped at run time leaves its `Del`s unstaged and unreported; the next sync plans them again.

#### 5.5.2 Guards (evaluated on the finished plan; failure = exit 5 unless stated)
- **G1 scan errors**: no `DelRemote`/`DelLocal` is ever planned for a key under `failed_dirs` or at/under `skipped_paths`.
- **G2 empty/missing root** (uploads only — it judges the local tree as a *source*; downward an empty or missing root is the normal first download, and `sync::run` creates a missing root before it opens the pair, so the recorded identity is the real directory's): local root missing, or it has zero entries while the pair has base rows → abort ("source is empty or not mounted"), overridable with `--force`. The CLI tells the two apart (§17.14): "the source X does not exist (mistyped, or its volume is not mounted)" / "the source X is empty although it was synced with :P before".
- **G3 reverted tree** (uploads only, as G2): if ≥ 10 `changed` local files and more than half of them have `mtime < B.mtime` → abort ("local tree looks restored from an older copy"), overridable with `--force`.
- **G4 delete guard**: let `d` = planned deletes (type-change groups included), `n` = entries at the destination under the prefix. Trips if `d > MAX_DELETE_ABS (100)` **or** (`d ≥ 10` and `4·d > n`). When the default test trips (`GuardKind::DeleteLimit`): on a TTY ask `Delete d of n files? [y/N]`; otherwise require `--yes`. **`--max-delete N` replaces both tests by `d > N` and is a hard limit** (`GuardKind::MaxDelete { deletes, limit }`, §17.14): with `d ≤ N` the run deletes without a question, with `d > N` it is refused — no question is asked and `--yes` does not lift it; the way to let it run is a higher `N`. (Until §17.14 an explicit limit tripped the same confirmable `DeleteLimit`, so `sync --yes --max-delete 20` — the form an unattended job has to use — deleted any number of entries, local unlinks included, while the flag's help said "Refuse to delete more than N entries".) `d` counts **every** `DelRemote` / `DelLocal`, directory markers and deletes whose content is reused elsewhere in the same plan included — so renaming most of a tree (locally, or with `mv` on another device) trips G4 on the next `sync` and needs `--yes` or a sufficient `--max-delete` (§17.4). A dry run only warns, naming `--yes` or `--max-delete N` as the case may be.
- **G5 collisions**: key collisions are skipped and make the run exit 6.
- **G6 root identity**: `GuardKind::RootChanged` (above); checked before the scan.

**What a refused guard says** (`cli/copy.rs::explain_guard`, §17.14). Off a terminal — cron, a pipe — the error text is all the user gets, so each refusal names what was found, that nothing was changed, and the flag that answers it: G2 / G3 `--force` (G2 only for `sync`: `copy` deletes nothing, so there is nothing `--force` would add), G4 `-n` to look and `--yes` (or the terminal), an explicit `--max-delete` "raise --max-delete (--yes does not lift it)", G6 the local root, the remote path and both `--keep-pair` and `--reset-pair` with their meaning. `GuardKind`'s own `Display` stays the short form (library callers, logs).

#### 5.5.3 Filters
One `Filter` = one `ignore::gitignore::Gitignore` rooted at the local root, built from the root's `.gcloneignore` (if present; nested ignore files are not honoured in the MVP) plus every `--exclude GLOB` (repeatable, gitignore syntax), plus gclone's own directories (below).

**The answer for one path** — `Filter::excluded_at(rel, is_dir) -> Option<&str>` (the shortest excluded leading part of `rel`; `excluded` is its yes/no). The ancestors of `rel` are asked **from the top down**, each as a directory (`Gitignore::matched(ancestor, true)`), and only when none of them is ignored the path itself (`matched(rel, is_dir)`). So the pattern `node_modules/` excludes the remote row `node_modules/a.js` exactly as it prunes the local directory, and — as in git — **a `!` pattern cannot re-include anything under an ignored directory**: with `build/` + `!build/keep.txt` the file stays excluded, on every side (`build/*` + `!build/keep.txt` works: there the directory itself is not ignored). This is by construction the walker's answer: the walker prunes an ignored directory and never visits its children, so a child is visible locally iff no ancestor and not the child itself is ignored. (Until §17.12 the function was `matched_path_or_any_parents(rel, is_dir).is_ignore()`, which tests the path first and returns a whitelist match without looking at the parents: `build/keep.txt` was hidden locally but visible as a remote row and as a base row, so `sync` up deleted the remote copy and every download moved the local file aside and fetched it again.) `excluded_at` additionally answers for any path with a `.gclone-partial-*` or `.gclone-probe-*` component (§5.1) and for anything at or under one of gclone's own directories: a remote entry of such a name would otherwise be downloaded and then ignored by every later scan.

**One answer per key** (`sync::hide_excluded`, normative). Patterns match one spelling — case-sensitively and by exact Unicode form — while the planner joins its inputs by comparison key (§5.1). A key is therefore excluded as soon as **any** of its spellings is: the local one (what the walker pruned, `LocalScan.excluded`), the remote row's, or the base row's, each judged with `excluded_at`. The comparison key of every excluded leading part found this way is collected, and every local entry, local collision, remote row and base row whose key is at or under one of them is removed **before** hashing, collision detection on the remote side and planning. `sync::run` reads the base rows and the remote rows unfiltered (`remote_rows_unfiltered`), scans with the filter, and then calls `hide_excluded`; `remote_rows(.., filter, ..)` and `filter_base`, which judge each row by its own spelling, remain for callers without excludes (`check_local`). An excluded key is thus invisible everywhere and adding an exclude never deletes anything, on either side, whether or not base rows exist and however the two sides spell the name (planner invariant test and `sync::scan` unit tests, §12.1). Without the per-key step a pattern that matched only the remote spelling (`Cache/` against a local `cache/` on a folding file system — routine, since `.gcloneignore` is synced between devices) hid the remote rows while the local files and their base rows stayed: `sync` down deleted the local files (row 9). The former known limit in the other direction (a remote row escaping an exclude that hides its local twin) is gone with it.

**gclone's own directories** (§8.1; `SyncRequest.own_dirs`, filled by `cli/copy.rs` with the configuration directory, the state root and — for a directory vault — the vault directory; `Filter::with_own_dirs`). The defaults lie under the home directory, and the home directory is the obvious thing to back up. `sync::run` canonicalises them as it does the root and
- **refuses** (`SyncError::Usage`, exit 2, before anything is created) a local root that is one of them or lies inside one;
- where they lie **under** the root, excludes them — compared by key, regardless of the patterns, on all three inputs like the reserved names — and prints `note: gclone's own files are not synced: <paths>`.
Without this `copy ~ :home` uploaded `secrets.json` (refresh token and master key), `config.json`, `token.json` and the live `state.db` with its `-wal`/`-shm` — never converging, because the run rewrites `state.db` — and `copy :home ~` on another device moved that device's **open** `state.db` aside and renamed a foreign one into place (§17.12). Entries of these names that are already in a vault stay there, invisible to `copy` / `sync` on a device whose own directories they would land in; remove them with `gclone rm -r`.

#### 5.5.4 Remote-only commands (index-only, one segment each)
`mkdir :p` → `Put{p, Dir, base: None}` (no-op if a winner exists; `Ok(false)`, and the CLI says "exists already"). `rm [-r] :p` → `Del{q, base: winner(q).stamp}` for `p` (and every winner under `p/` with `-r`; without `-r` a non-empty prefix is refused). `rm` / `mv` of a path that does not exist → `SyncError::Io(NotFound)` (exit 1). Cases this section is silent on are **refused** with `SyncError::Usage` (exit 2) instead of letting the index move a file to a conflict name (§5.2.3 rule 2): `mkdir` / `mv` / `restore` under a path one of whose ancestors is a file, `mkdir` of a path that is a file, `restore` of a non-file version.

**`mv :a :b [--force]`** (rewritten in §17.14; `remote_ops::mv(vault, from, to, force) -> Moved { to, entries, replaced }`). The destination follows the shell command:
- `b` is an **existing directory** — the root, a `Dir` head, or anything with a winner under it (`exists_dir`) → the source moves **into** it and keeps its name: `dest = b/<last component of a>`;
- otherwise the source is renamed: `dest = b`.

Then, for every winner `q` at `a` or under `a/`: `Put{dest‖suffix, entry: same, base: winner(target).stamp or None, origin: Some(q.stamp)}` then `Del{q, base: q.stamp}`; puts precede dels in the one segment. Refused (`Usage`, nothing committed): `dest` equal to `a` or inside `a`; a file among the ancestors of `dest`. **Nothing that exists at `dest` is replaced or merged into without `force`**:

| source | at `dest` | without `force` | with `force` |
|---|---|---|---|
| file | nothing | rename | rename |
| file | a file | refused ("exists already … --force to replace it") | replaced; `replaced = 1` |
| file | a directory (marker or content) | refused | refused — a file never replaces a directory |
| directory | nothing | rename | rename |
| directory | a file | refused | refused — a directory never replaces a file |
| directory | a directory | refused ("exists already … --force to merge into it") | merged: each entry goes to `dest‖suffix`; a file there is replaced and counted in `replaced`; a source directory marker whose directory exists there is only deleted; a file facing a directory (or the reverse) anywhere in the merge, or a file above a target, refuses the whole command |

Replaced versions go to `removed` like any superseded version and stay restorable (§5.2); the CLI prints "Moved :a to :dest (N entries; no data was transferred)." and, when `replaced > 0`, "Replaced K file(s) there; … restorable for 25 days (gclone restore --list :dest)". Before §17.14 `dest` was always `b` and `base` the target's winner: a tree moved onto an existing directory was merged into it and a file moved onto a file replaced it, both silently — `gclone mv :Photos/old :Archive` mixed `old`'s files into `:Archive` instead of creating `:Archive/old`, and a file moved onto an empty directory turned the directory into a file.

**`restore`** (extended in §17.14). One version of one file: `restore :p [--version K]` → `Put{p, entry: chosen removed version, base: winner(p).stamp or None, origin: Some(old stamp)}`; only versions with `removed_ms` newer than `RESTORE_WINDOW` (25 days) whose blob is still present (`transfer::locate_blob`; un-trash and clear `trashed_ms` if needed) are offered. As implemented (§17.4): `restore_candidates` only checks presence (size, and md5 where the backend reports one) — the un-trash happens in `restore`; `restore` onto a path that is now a directory is refused.

A **directory** has no versions of its own — its files have. `rm -r` and `sync` remove many files at once and both say "restorable for 25 days", so the same command has to work on what they removed:
- `remote_ops::restorable_under(vault, prefix, now_ms) -> Vec<Restorable { version, live }>`: for every path strictly under `prefix/` (`""` = the whole vault) the **newest** removed file version inside the window whose blob is present, sorted by path (`Vault::removed_under`; blob lookups are remembered per blob, so the files of one pack cost one). `live` = the path has a winner now (the version was overwritten, not deleted). A removed version with the same `(size, hash)` as the live entry is skipped — it would bring nothing back (it was restored already, or the same bytes were uploaded again).
- `restore --list :P` prints the versions of the file `P` (as before) and, below, the restorable files under `P` — `removed  size  state (deleted | overwritten)  path` — with a count and the commands; `:` lists the whole vault. "No restorable version …" is printed only when neither exists.
- `restore -r :P` restores the newest removed version of every **deleted** file under `P` (`live == false`) **in one segment** (`remote_ops::restore_many`); files that exist now are left alone and counted in a note. Without `-r`, a `P` that has no version of its own but restorable files under it is `Usage` naming `restore -r :P` and `--list` — not "no restorable version". `P` itself is restored as a file when it has versions and (with `-r`) is not a directory now. Nothing deleted under `P` → `Io(NotFound)`, exit 1.
- Several `:PATH` arguments are accepted (one segment for all); `--version` takes exactly one file path.
- `restore_many(vault, versions) -> Restored { restored, skipped: Vec<(path, why)> }`: a version that cannot go back is **skipped and reported**, the others are restored — its blob is gone or is not the uploaded object, a file stands where one of its directories is needed, the path is a directory now, or another version of the same call needs the name as a directory (a path that was a file and, at another time, a directory: the one **removed later** wins, so what existed last comes back and nothing lands under a file). The CLI prints each skip as a warning and exits 6; a call that selects exactly one version goes through `restore` and reports every obstacle as an error, as before. Empty-directory markers are not restored.
- `rm` prints the command that undoes it: "Removed N entries (files stay restorable for 25 days: gclone restore [-r] :paths)"; `copy` / `sync` print a `note:` with `gclone restore --list :P` after a run that deleted in the vault.

### 5.6 Commit, compaction, index cleanup
```
commit():                                  // Vault::commit — turns durable pending ops into one segment
  drafts = all rows of `pending` (in id order); if none: return Ok          // a stuck outbox is retried by the next refresh
  if `outbox` has a row: recover_outbox(); temporary failure → Err(IndexError::OutboxStuck)
                                           // §5.8: a segment whose blobs are no longer trustworthy is withdrawn — its surviving ops
                                           //   are staged again and become part of `drafts`; the dropped ones count in dropped_ops
  verify_pending_blobs(drafts)             // §5.8 — only for rows staged by an earlier process
  seq = next_seq; lamport = local_lamport + 1
  seg = SegmentV1{ vault_id, device, seq, lamport, prev = my previous SegRef (from `own`),
                   seen = per other device the greatest known (seq, hash) with its file id (from `applied` and `base_covers`),
                   created_ms = now, host, ops = drafts in order (Blob ops first, then Puts, then Dels) }
  debug_assert: no two Puts for one path (§5.2.2)
  bytes = seal(seg); name = segment_name(...); id = backend.new_ids(1)
  TXN(FULL): insert outbox(seq, name, id, bytes); insert own(seq, hash, id); delete those pending rows but keep their BaseEffects in outbox.effects
  backend.put(id, index, name, Small(bytes) if len ≤ MULTIPART_MAX else Stream)      // idempotent: same id, same bytes
                                           // (this first put is not preceded by the blob check of recover_outbox: the blobs were
                                           //  uploaded by this run or have just passed verify_pending_blobs)
      temporary failure (QuotaExceeded, RateLimited, Transient) → the row stays in `outbox`; Err(IndexError::OutboxStuck)
  TXN: apply seg locally (as §5.2.2, removed_ms = returned created_ms); insert applied; hw; next_seq += 1; local_lamport = lamport;
       apply BaseEffects (remote_stamp = the op's stamp); delete outbox row; write the object into the index cache
```
Long runs commit every `COMMIT_INTERVAL` (120 s) or `COMMIT_MAX_OPS` (4096) staged ops, at the end, and on Ctrl-C. `commit()` prepends `Op::Device { id, name }` by itself when the replica does not list this device id and the drafts carry no `Device` op for it (needed after a device-id rotation; the explicit ATTACH op of the CLI suppresses it). `stage()` validates every draft (path rules, entry/`loc` consistency including the `chunk_log2` range) and returns `IndexError::Format` for a bad one; the "no two `Put`s for one path" `debug_assert` fires in debug builds — which is what `cargo test` runs — so a caller that stages two `Put`s for one path into one segment panics there (§17.3).

**Compaction** (`maybe_compact`): if `|applied| ≥ COMPACT_MIN_SEGMENTS (64)` or the applied segments' bytes exceed `max(1 MiB, 25 % of the base snapshot's size)`, and nothing is blocked, no conflicts are unresolved and the outbox is empty: `write_snapshot()`. Because `refresh` adopts other devices' snapshots (§5.3) and adoption prunes `applied`, the trigger counts only segments beyond the newest snapshot any device has published — one device per cycle writes a snapshot, not every device.
`write_snapshot()`: serialise the SQLite state with `covered = base_covered ∪ {identities in applied}` and `covers` = per device the greatest `(seq, hash)` of `covered` with its file id; `lamport` = local lamport **+ 1**, and the local clock advances to it (§17.3: with the bare local lamport, snapshots written in a row — `repair`, or two concurrent compactors followed by a third snapshot — tie, "newest snapshot" and `SNAPSHOT_KEEP` were then decided by the random `h8` of the name, and the two-compactor cleanup could never finish); upload (resumable if > 4 MiB); then, in one transaction, `base_covered := covered`, `base_covers := covers`, delete all `applied` rows, record `base_snapshot_{name,lamport,size}`, `last_snapshot_{name,size,id,created_ms}` and `snap_checked := name`.

**Index cleanup** (`cleanup_index`): only the device that **wrote** snapshot `S` (`last_snapshot_*`) cleans up, and only when (a) `backend.now_ms() − S.created_ms ≥ INDEX_TRASH_DELAY (7 days)` using server times, (b) `stat(S)` shows it present, un-trashed, with the recorded size/md5. Let `K` = every accepted snapshot in the listing (`S` among them; parsed from the cache). Then:
1. a snapshot `S' ≠ S` is trashed iff `S.covered ⊇ S'.covered` (S dominates it) — but the newest `SNAPSHOT_KEEP = 2` snapshots (by inner lamport) are always kept. Let `K'` = the snapshots that remain.
2. a listed segment is trashed iff its identity `(dev, seq, h8)` is in the `covered` set of **every** snapshot in `K'`.
A listed object that fails acceptance is never trashed. Two devices that compacted concurrently leave two incomparable snapshots: both are kept, only their common coverage is trashed, and every segment stays reachable from *each* retained snapshot plus the listing; the next snapshot written after both were seen dominates both and lets cleanup finish. A pass that ran to its end records `meta.cleanup_done` = BLAKE3 over `S`'s name and the snapshots the listing shows once the pass's own victims are gone (name, object id, size, md5 of each); as long as `S` and that set are unchanged there is nothing new to decide — what a pass trashes is a function of the listed snapshots — and the pass is skipped before `stat(S)` and before any snapshot is read: `cleanup_index()` then costs one listing, and the cleanup of `finish_mutation` nothing at all, because it compares against the listing that the command's own `refresh` saw (§17.11; before, every mutating command decoded every listed snapshot again once `S` was a week old). The local index cache keeps every object until it is covered by the base **and** older than 30 days (it feeds `repair`). Local `removed` rows older than `HISTORY_KEEP` are pruned when this device writes a snapshot (§17.3).

**`finish_mutation()`** — the end-of-command sequence, called **exactly once, by the CLI layer** (§10), never by `sync::execute` or `remote_ops`: if the outbox is stuck → return Ok (nothing can be published; the command's own commit already reported it). Otherwise `commit()` → `resolve_conflicts()` → `maybe_compact()` → `cleanup_index()`; a temporary backend failure in the last two is a warning, not an error.

### 5.7 Executing a plan (`sync::execute`)
Order:
0. type-change groups, DOWN: their local `first` actions (§5.5.1);
1. `MkdirLocal` / `MkdirRemote`;
2. transfers (`Upload`, `Reuse`, `Download`, meta ops, `RecordBase`, `ForgetBase`) with periodic commits;
3. deletes — **only if no transfer of step 2 failed**: `DelRemote` ops staged and committed; `DelLocal`; then `RmdirLocal` for directories emptied by this run — except directories this run created (`MkdirLocal`) and those in `Plan.keep_dirs` (a remote empty-directory marker names them, §5.5.1);
4. the re-observation pass (step 5 below) and the final `commit()`.
A transfer has *failed* when it ended in an error (`Summary.failed`). A `Skip` — planned, or decided at run time (`UnsafeTarget`, `ChangedDuringUpload`, `KeyCollision`, a type-change group that could not start) — is **not** a failure and never suppresses the deletes of other keys. `ChangedDuringUpload` is the skip for a source that changed after the scan: one that was rewritten while it was read, and equally one that is **gone, or no longer a regular file**, when the upload opens it (`Failed(_, SourceChanged)`, §6.2, §17.13); a source that is still there and cannot be read (`SourceUnreadable`: permissions, an I/O error) is a failure. If transfers failed, the deletes of step 3 are skipped and reported; exit 6. `execute` ends at its final `commit()`; conflict resolution, compaction and cleanup happen once in `Vault::finish_mutation` (§5.6).

**How a run ends** (as implemented, §17.4). `Ok(Summary)` — exit 0, or 6 when `skipped` or `failed` is non-empty or `deletes_suppressed` is set (`copy` does not count destination-only entries, §5.5.1). A transfer — upload or download (§17.13) — that hits a quota or rate limit stops the launch of further work; what completed is committed, and `run` / `execute` return **`Err(SyncError::Backend(QuotaExceeded(kind)))`** or **`Err(Backend(RateLimited))`** (exit 75) — not a `Summary`; a failing final commit is not reported on top of it. Cancellation returns `Err(SyncError::Interrupted)` (exit 130) after the staged ops were committed. A dry run returns the plan's counts with `dry_run = true` and touches neither the index nor the tree (the pair row of an existing root may be created in `state.db`).

Upload side (details §6.2): all uploads go through `transfer::upload_batch`, fed in path order in slices of at most `UPLOAD_BATCH_FILES` with `vault.data_folder()` re-read per slice. For every `UploadEvent::Blob` the executor calls `vault.note_blob_created()`, adds the blob's length to the upload ledger, builds the drafts (`transfer::drafts_for`, plus the `Del`s of a type-change group) and stages them in one durable transaction; it commits per §5.6. The base effect stored with a `Put` uses the `fstat` taken on the open descriptor **before** reading, and an upload is only accepted if the `fstat` after the last byte is identical. Large sources are re-`fstat`ed every 64 MiB and aborted early if they change (up to 3 attempts per file, each with a new salt/blob/ID; then `Skip(ChangedDuringUpload)`). A `RateLimited` upload failure while the ledger shows ≥ `LEDGER_WARN` in 24 h is reported as `QuotaExceeded(DailyUpload)` (§6.5).

Download side:
1. Before any local write: every ancestor of the target inside the root must `lstat` as a real directory (not a symlink) → else `Skip(UnsafeTarget)`; `path::validate` again. Missing parent directories of the target — and a missing root — are created by the transfer layer (`download_group` / `materialize_empty`), level by level, each level `lstat`-checked; `check_target_safe` accepts ancestors that do not exist yet and creates nothing. An unexpected directory at the target is reported as `UnsafeTarget` **before** any request as well as at the re-stat of step 3 (§17.3).
2. Write to `<dir>/.gclone-partial-<8 random hex>` opened `O_CREAT|O_EXCL`, mode 0600. Only verified chunks are written. After the last chunk: BLAKE3 must equal `Entry.hash`; set mtime and mode. The file is now **staged**: complete and verified, and handed — name and still open descriptor — to its batch, which syncs it through that descriptor, closes it and renames it (step 3a, §17.15, §17.16); it is neither flushed nor renamed on its own. **Mode** (§17.12): the index records only `exec`. If a regular file exists at the target at this moment — the one the rename will replace, or one that step 3 moves aside — the new file takes over its permission bits (`st_mode & 0777`; set-id and sticky bits are not carried), with the x bits following `exec` exactly as `SetLocalMeta` sets them (`exec`: add `u+x`, and `g+x` / `o+x` where the matching read bit is set; not `exec`: clear all x bits). A file that the user made private (0600) is therefore never widened by a download of a newer version. Only a file that is new at its path gets 0644 or 0755 by `exec`, masked by the umask.
   **Files open at a time** (§17.13): paths with the same content share one `Loc` (`Reuse`, §5.5) and are one member with many targets, so the targets are written **one after another** — the number of open descriptors must not grow with the number of paths (the default soft limit is 256 on macOS). A member of at most `PACK_MEMBER_MAX` plaintext bytes (every pack member) is kept in memory until its last chunk verified and its hash matched; only then each target's partial file is created, written, given its mtime and mode and staged, in turn — no partial file exists for a member that fails verification. A larger member goes, chunk by verified chunk, into the partial file of the first target that can be created; once it is complete and its hash matched, every other target is filled by a local copy of that file (read back and BLAKE3-checked again while it is copied, `Verify` on a mismatch) and staged before the next one is opened; the file that took the stream is staged last. At most two descriptors are open per member while it is written. A batch keeps names, and descriptors only as far as the content barrier needs them (step 3a): at most `DOWNLOAD_OPEN_FILES` staged files that are not handed over yet — 1 on macOS, where each file is synced and closed as it is staged; 32 on Linux — plus one per device; all batches of a process together hold at most `DOWNLOAD_OPEN_TOTAL` such files. Each target keeps its own outcome (`UnsafeTarget`, collision, moved aside, mode, mtime); the one shared failure is a write error (disk full, I/O error) on the file that takes the stream, which fails every target of that member.
3. **Re-stat the target** immediately before the rename and compare with the plan's `expect_local`:
   - as expected (absent; or exactly the expected file signature, which the rename replaces; or the expected empty directory, which is `rmdir`ed first) → proceed;
   - a **directory** that was not expected → `Skip(UnsafeTarget)`. A directory is never moved aside or replaced;
   - anything else unexpected: read the parent directory. If no entry has exactly the target's file-name bytes, the existing entry is a *different spelling that the file system folds onto ours* → `Skip(KeyCollision)` (never alternate between two remote spellings on a folding file system). Otherwise it is a concurrent local change → move it aside to the local conflict name (keep both).
   Then `rename` (atomic) and `lstat` the result (`sig`, `observed_ns` = time of that `lstat`). The outcome is held back until the rename barrier of step 3a; only then the executor records the base row.
   3a. **Batches and barriers** (§17.15, §17.16; normative). Making a file durable costs one flush of the drive's write cache, whatever its size (≈ 4 ms on an Apple SSD — Rust's `File::sync_all` is `F_FULLFSYNC` on macOS), and one flush covers everything handed to the drive before it. Files are therefore not flushed one by one. Staged files (step 2) are collected in a **batch**: one sequence of batches per blob group (`download_group`, across its coalesced requests), another for zero-length files (`materialize_empties`). A batch is closed after `DOWNLOAD_BATCH_FILES` files or `DOWNLOAD_BATCH_BYTES` of content, whichever comes first; by a file that arrives `DOWNLOAD_BATCH_AGE` or more after the batch's first one (on a slow link finished files do not wait for a full batch — there is no timer, the age is looked at when a file is added); and at the end of its group. Closing a batch is, in this order:
   1. **content barrier**, in two halves. *Hand-over*: every staged file is synced **through the descriptor it was written with** (`fsync(2)`), and that descriptor is closed with the answer of `close(2)` looked at. Files are handed over as they are staged — at once where `fsync` is cheap by itself (macOS, where it only hands the data to the drive: `DOWNLOAD_OPEN_FILES` = 1), in groups of `DOWNLOAD_OPEN_FILES` = 32 behind one `syncfs(2)` on Linux — and whatever is still open when the batch closes. A file whose sync or close fails is failed **alone**, with that I/O error, and its partial file removed. *Flush*: one flush per drive (`st_dev`) ends the batch's hand-overs — on macOS one `F_FULLFSYNC`, through the writing descriptor of the first file handed over on that device, which stays open for it; elsewhere `fsync` was the durable operation already;
   2. the re-stat and `rename` above, file by file. A partial file that is no longer there fails its own file, not the batch;
   3. **rename barrier** — every directory in which a rename happened, and each of its ancestors up to and including the sync root (the transfer layer may have created them for these files), is made durable. A directory that alone cannot be opened or synced fails the files in and below it;
   4. the outcomes are released; the executor writes the base rows (`Exec::downloaded` — the only place that does for downloads).

   Two invariants follow, and both are needed. **(I1) No file is renamed into place before its content and attributes are durable.** Otherwise a power loss could leave an empty or half-written file at a target with no base row or an older one, and the next upload would take it for a local edit and publish it (§5.5.1 rows 2 and 7). **(I2) No base row is written — and none is forgotten — before what it rests on is durable**: for a download, the file's rename and the directory entries from the sync root down to it; for every other writer of base state on this side, step 3b. Otherwise the row could outlive the file: "in sync" over lost content, or — the file gone — a local delete that `sync` carries to the vault (row 8). A base row becoming durable *later* than its file is harmless (rows 5 and 6: the file is fetched again, or recognised by its content). A barrier that fails **as a whole** (the `syncfs`, the flush of a drive) fails every file behind it with that I/O error: after a failed content barrier nothing is renamed and the partial files are removed; after a failed rename barrier the files are in place and none is reported — the next run finds them equal by content and records them (row 6), behind a barrier of its own (step 3b). The error of **one path** — a file's `fsync` or `close`, a directory that cannot be opened or synced — fails what rests on that path and nothing else.
   **The barriers** (`transfer::durable`, crate-private) rely only on documented behaviour, and there are two ways in because there are two kinds of paths. *Files this process wrote* are never opened a second time: `hand_over(files, &mut drives)` takes each with its writing descriptor, and `Drives::flush(written)` ends the batch. The reason is what `fsync(2)` promises on Linux (man-pages text as quoted in the review of §17.16; not fetched again): "errors from write-back will be reported to all file descriptors that might have written the data which triggered the error. Some filesystems (e.g., NFS) keep close track of which data came through which file descriptor, and give more precise reporting. Other filesystems (e.g., most local filesystems) will report errors to all file descriptors that were open on the file when the error was recorded." A descriptor that is opened after the writes is promised nothing; and a file system that sends data only when a file is closed, or meets a quota then, reports the failure from `close(2)`. *Everything else* — directories, and files that were already there (step 3b) — goes through `make_durable(paths) -> io::Result<Vec<(usize, io::Error)>>` ("everything done so far to these paths survives a power loss"), which opens each path (`O_RDONLY | O_NONBLOCK`, one after another: its open descriptors are one per device, not one per path). `Err` is the failure of the barrier as a whole; the list names the paths — by position — that failed alone. *macOS*: plain `fsync(2)` on every path — it hands the data to the drive and costs microseconds — then **one `F_FULLFSYNC` per device** (`st_dev`; a batch may span mount points). `fcntl(2)`: "F_FULLFSYNC: Does the same thing as fsync(2) then asks the drive to flush all buffered data to the permanent storage device. As this drains the entire queue of the device and acts as a barrier, data that had been fsync'd on the same device before is guaranteed to be persisted when this call returns." The promise covers data that **was `fsync`ed** — not other files' dirty pages still in the page cache — which is why every path gets its own `fsync(2)` first. *Linux*: `fsync(2)` on every path is the guarantee. Where several paths are synced together, one `syncfs(2)` per file system goes first so that those `fsync`s find their work done (one journal commit for the group instead of one per file), and its error **is the barrier's error**: since Linux 5.8 it reports an inode that could not be written back, before that it reports nothing and the `fsync`s are all there is; only `ENOSYS` is ignored. A path that is synced alone gets no `syncfs`. *Other Unix*: `fsync(2)` per path.
   Consequences: a file of `DOWNLOAD_BATCH_BYTES` or more closes its batch by itself, and a blob that holds one large file is one batch — two flushes per file, as before; the gain is for packed files. Up to one batch per download stream (≤ `DOWNLOAD_BATCH_BYTES` plus one file) exists as partial files next to the files it is about to replace. Outcomes reach the executor per blob group, as before — a group's base rows are written when the group has returned, so a crash costs at most the re-hashing of the groups that were in flight (their files are in place; row 6); zero-length files are handed over in slices of `DOWNLOAD_BATCH_FILES`. After a cancellation the files already staged are still finished (two barriers): they are complete and verified. A file that takes over a mode without owner-read from the file it replaces (step 2) needs no exception: nothing opens it again.
   3b. **Every other writer of base state on the download side** (§17.16; normative). I2 is not a property of downloads. Whatever writes or forgets a base row first makes durable what that row rests on, through `make_durable` — one call per phase (`RecordBase`: per `RECORD_SLICE` = 4096 rows), each path synced once:

   | writer | waits for |
   |---|---|
   | `RecordBase` for a file (§5.5.1 rows 3 and 6: found equal to the remote entry) | the file — content and attributes — and every directory from the one that holds it up to and including the sync root |
   | `RecordBase` for a directory | every directory from its parent up to and including the sync root |
   | `SetLocalMeta` | the file: its new mtime and mode are attributes of the inode |
   | `MkdirLocal` | every directory from the created one's parent up to and including the sync root (what was removed or moved aside to make room is a change of the parent, too) |
   | forgetting the row after `DelLocal` (step 4: deleted, or found absent) | the directory the entry was removed from — if that is gone as well, the nearest one above it that is left |

   A `RecordBase` row that only **refreshes** its predecessor — same key, kind, content hash and remote stamp; a new signature or observation time (row 1; likewise the re-observation pass of step 5) — claims nothing its predecessor did not, and is written at once. An entry whose barrier fails — one of its paths, or the barrier as a whole — gets no row (a removed entry keeps its row) and is reported as **failed**: exit 6, deletes suppressed as after any failure; the next run decides again from what it finds.
   Why each: a `RecordBase` row over a rename that a power loss takes back leaves the *old* file under a row for the *new* version — the next upload publishes the old content over the newer remote one (row 2) — or no file at all under a row, which `sync` reads as a local delete (row 8). That is exactly the row a file gets that an earlier run renamed and could not report (a failed rename barrier, a killed process). A row over an mtime that fell back makes the next upload push the old mtime as a change made here (row 1, `SetRemoteMeta`). A row for a created directory that is lost reads as "removed here" and deletes the empty-directory marker in the vault (row 8) — and no later download makes an empty directory durable in passing. A forgotten row over a removal that is undone leaves a file without a row: a new file, uploaded again although it was deleted in the vault (row 4).
   **Not covered** (known limits). (a) Rows the *upload* side writes — the base effect of a `Put`: the local file is the user's, gclone neither wrote nor syncs it, so a source file that a power loss takes back after its upload reads as deleted here and `sync` up deletes it in the vault (row 8; restorable for 25 days, and the delete guard of §5.5.2 bounds how many). (b) `ForgetBase` (both sides gone): the local absence is the user's own deletion. (c) The entry of the sync root in *its* parent when this run created the root (the `RootChanged` / `EmptySource` guards of §5.5.2 stand behind that case). (d) For a file gclone did not write (`RecordBase`, `SetLocalMeta`) the barrier is an `fsync` through a descriptor opened for it: it makes durable what the kernel holds, and it reports a failed write-back only as far as the kernel still remembers one.
4. `DelLocal{expect}`: `lstat` must equal `expect`, else skip (`Skip(LocalChanged)`); then `unlink`. Directories: `rmdir` only. The base row is forgotten behind the barrier of step 3b.
5. **Re-observation pass** (end of the run). A file this run wrote is born untrusted (its ctime ≈ its `observed_ns`, §5.4) and would otherwise be re-hashed by every later sync. After its last local write the executor waits until `RACY_WINDOW` has passed (≤ 2 s, once per run), `lstat`s every file it downloaded or meta-set, and where the signature is unchanged rewrites the base row with `observed_ns = now`; changed files keep their untrusted row. A second no-change sync after a download hashes nothing (`Summary.hashed == 0`, §12.1).

Ctrl-C (first): stop launching work, let in-flight parts finish or abort within 5 s, commit staged ops, exit 130. Precisely (§17.13): in `upload_batch` **every** wait for the backend — the put, and the calls around it: the id request before it, the `stat`s (acceptance without an md5, a put whose answer was lost) and the `trash` of a rejected object after it — ends at the latest `CANCEL_GRACE` = 5 s after the cancellation, one deadline for the whole batch rather than one per call; a call that is dropped there ends its transfer with `Cancelled` (an object it left behind unverified or untrashed is an orphan for `gc --orphans`). No put is started after the cancellation, also not with an id that arrives inside the grace period. A dropped receiver aborts everything at once. Downloads have no grace: every backend call of `download_group` (the `get`, the by-name lookup, the `stat` after a body that ended early) is dropped at the cancellation; zero-length files not yet written, and the targets of a shared member not yet written, come back `Cancelled`. Second Ctrl-C: exit immediately (staged ops stay durable in `pending` and are committed by the next mutating command before it plans, §5.8).

### 5.8 Crash safety and idempotency
- Order is always: blob uploaded and verified → ops staged durably (`pending`, `synchronous=FULL`) → segment uploaded → applied locally. A crash leaves at worst orphan blobs, never an index entry pointing at an unfinished object.
- **Leftover staged ops are published before anything is planned** (normative). Every index-mutating command starts with `refresh()` → `commit()` (including `verify_pending_blobs`) → `resolve_conflicts()` — done by `open_ctx` (`settle`, §9.10) — before any scan or plan. Ops left in `pending` by a crashed, killed or interrupted run are then in the replica, and their base effects in `base`, when the planner looks: the files are `same`/`same` and nothing is uploaded twice. (Planning over un-applied pending `Put`s would stage a second `Put{f, base: None}` beside the first and manufacture one conflict copy per file of the interrupted batch.)
- Every create (folders, blobs, segments, snapshots) uses a pre-generated Drive ID. A retried create answering `409` is success **only after** `stat(id)` returns the expected size and md5; a `409` whose `stat` stays empty is retried under a fresh Drive ID (§6.2 conflict rule).
- `recover_outbox` (start of every refresh, and of every commit that has work): if `outbox` has a row, **check the blobs it names** (next item), then re-put it (same id, same bytes; after `SessionLost` a fresh Drive ID with the same name and bytes, `outbox`/`own` updated) and finish the commit transaction. It runs before the clone check so a crash after the put cannot be mistaken for a clone. A **temporary** failure (`QuotaExceeded`, `RateLimited`, `Transient`) leaves the row and is not an error for `refresh` (§5.3): a full Drive or an exhausted daily quota must not lock the user out of reading, downloading or `gc`.
- `verify_pending_blobs`: for staged ops left by an earlier process, `stat` each referenced blob: trashed → `untrash`; missing or wrong size/md5 → drop the ops that reference it and warn (the files are simply re-planned next sync); **created more than `ORPHAN_GRACE / 2` (7 days, server time) ago → drop them as well**: another device's orphan sweep may be about to trash a blob this old that no published segment references yet, so it is re-uploaded instead of trusted. (As implemented, §17.3: "left by an earlier process" = the `pending` rows that existed when this `Vault` was opened; the 7-day rule applies only to blobs whose `Blob` record is itself still unpublished — a staged `Put` that reuses an old, already published blob is kept.)
- **A waiting segment is published only while its blobs are trustworthy** (§17.11). A sealed segment can wait in the outbox for any length of time (a full Drive, a crash between the outbox transaction and the put, a device that is switched off), and until it is public every other device takes its blobs for unknown objects: `gc --orphans` trashes them after `ORPHAN_GRACE`, and a `gc` elsewhere may collect an old blob that a sealed `restore` or `mv` reuses. `recover_outbox` therefore `stat`s every blob the segment's `Blob` and `Put` ops name (a blob without a `Blob` op in the segment must be in the blob table) before the put: trashed → `untrash`; and if a blob is missing, has another size/md5, or — its record unpublished — was created more than `ORPHAN_GRACE / 2` ago, the segment is **withdrawn**: one transaction deletes the outbox row and its `own` row (the sequence number is used again) and stages the segment's ops again, with their base effects, except the ops that name such a blob, which are dropped with a warning (their files are uploaded again by the next sync — no head on a trashed or deleted blob, no base row that says "in sync"). `refresh` then reports no stuck outbox; `commit` counts the dropped ops in `CommitReport.dropped_ops`. Exception: if `stat(file_id)` shows the sealed segment itself in the store with the sealed size and md5 (the process died after the put), other devices may have applied it — it is finished as sealed, trashed blobs are un-trashed and a missing one is a warning that points to `gclone check`. The check costs one `stat` per named blob per attempt, so the put that `commit()` makes right after sealing skips it. A `Device` op that announces a device id this replica has left since (rotation) is not staged again.
- No cross-restart upload resume in the MVP: an interrupted large upload restarts with a new salt/blob/ID. (Safe design for later: §14.)
- One process per vault mutates state: kernel lock (§8.3), released by the OS on process death — no stale-lock lockout.

### 5.9 Garbage collection and checking
`gclone gc [--dry-run] [--orphans] [--purge]` refuses to run (exit 3) while `refresh` reports `Gap`, `Rollback` or any blocked segment: a replica that is missing index state must not judge what is dead.
1. **Dead blobs**: a blob with no head referencing it — **and none of this device's unpublished ops naming it** (`pending` drafts and the ops of the outbox segment: the `Blob` records and the data locations of `Put`s; §17.11) — whose newest `removed` reference is older than `GC_GRACE` (30 days; if no `removed` row references it, use `BlobRec.created_ms`) → `trash` (Google keeps it 30 more days) and set the local `blobs.trashed_ms`. The record leaves the snapshots with the next compaction; the local row stays until the blob is purged or `trashed_ms + 30 d` has passed. `NotFound`/already trashed = fine.
2. **Orphans** (`--orphans` only): `list` each child folder of `data/` (this vault's own folders — never an unscoped listing); objects whose name is not a known blob id, not referenced by this device's `pending`/`outbox`, and whose `created_ms` is older than `ORPHAN_GRACE` (14 days, server time) → `trash`. (Other devices' unpublished work is protected on their side, §5.8: staged ops by the 7-day rule of `verify_pending_blobs`, a sealed segment in the outbox by the blob check of `recover_outbox` — a blob that was swept is un-trashed or its ops are withdrawn, never published as they were.)
3. **Purge** (`--purge` only — the single place where gclone deletes permanently): for every local `blobs` row with `trashed_ms` set that no head, no `removed` row younger than `RESTORE_WINDOW` and no unpublished op of this device (as in step 1) references: `stat(file_id)` must show the object **trashed** with the recorded size and md5 → `backend.delete(file_id)` (`DELETE /drive/v3/files/{id}`) and drop the row; anything else (not trashed, different size/md5) is skipped and reported. Only IDs from the blob table are ever deleted; `files.emptyTrash` is never called. Trashed blobs count against the storage quota until Google purges them after 30 days — `--purge` is how a full Drive gets space back now. As implemented (§17.4): a backend that reports no md5 is judged by size alone (in `gc --purge`, `check_blobs` and `restore`, as in `verify_pending_blobs`; an md5 that is present must match); an object `stat` no longer finds is dropped from the blob table without counting as purged; step 1 takes its list from `Vault::dead_blobs(backend.now_ms())`, which already applies `GC_GRACE`; a `--dry-run --purge` also counts what step 1 would trash.
Versions overwritten or deleted stay restorable for 25 days (`restore`), are collected after 30, and survive in Drive's trash until day 60 unless purged. Steps 1 and 3 count unpublished ops as references because `gc` runs with a stuck outbox (§5.3) — on a full Drive, which is both what keeps a `restore`'s segment in the outbox and what `gc --purge` is run for: judged by heads alone, the blob of a version restored on day 24 was trashed and deleted for good on day 30, and the outbox then published a head for it (§17.11). A `restore` that is stuck on **another** device is not visible here; that device's `recover_outbox` finds the blob trashed (un-trashes it) or gone (withdraws the op, §5.8).

`gclone check`:
- no arguments: list this vault's data folders and compare with the blob table. A blob that is absent from the listing is **confirmed by ID** before it is reported (listings lag writes; a listing never proves absence): `stat(file_id)`, then the by-name fallback (`transfer::locate_blob`). Only "not found", or a size/md5 mismatch (labelled "accidental corruption check; md5 is reported by Google"), counts as missing/damaged → exit 3. Referenced-but-trashed → `untrash` (self-heal). Blobs that were only listed late are counted and shown at `-v`; orphans: counted only, in two groups (§17.20) — objects younger than `ORPHAN_GRACE` (server time, the rule of `gc --orphans`) are in all likelihood another device's upload in progress, because a device puts its blobs before it publishes the segment that names them, and `check` says so ("nothing to do"); only the older ones are called leftovers that `gclone gc --orphans` collects. The number of days in both notes is taken from `ORPHAN_GRACE`.
- `check LOCAL :REMOTE`: hash local files and compare `(size, BLAKE3)` with the index; no download.
- `check --download [:PATH]`: download, authenticate every chunk and compare BLAKE3 for every file under PATH.
Wherever a `stat` of a referenced blob shows `trashed` (`check`, `restore`, `verify_pending_blobs`), the blob is un-trashed on the spot.

A remote path that does not exist is an error for both path-taking forms (§5.5.1, §17.14): `check --download :P` with nothing at or under `P`, and `check LOCAL :P` with no directory `P` → `SyncError::Io(NotFound)`, exit 1. The vault root always exists; `check --download :file` checks that one file.

### 5.10 `gclone repair`
1. Take the lock; `refresh()` with its verdicts collected instead of returned.
2. Republish: every object in the local index cache that is neither listed nor covered by an accepted listed snapshot (in the sense of §5.3 "as implemented"): `stat(file_id)` → trashed: `untrash`; missing: `put` again under a new ID (same name, same bytes).
3. `refresh()` again. If it is clean — **or its only failure is the presence check** (the replica is complete, but the remote lost objects that are no longer in this cache) — run `resolve_conflicts` and `write_snapshot()` (always: this is "index publish"; its `covered` set holds everything this replica knows, which cures a presence failure for every device). Done.
4. If a `Gap` or an unsatisfied mark remains: without `--accept-loss` print exactly what is missing (device, seq, age) and exit 3. (`Vault::repair(false)` reports this case as `Ok(RepairReport { still_missing: non-empty, .. })`, not as an error: **the CLI prints the list and exits 3 whenever `still_missing` is non-empty**. Blocked segments younger than `GAP_GRACE` are not treated as loss. §17.3.) With `--accept-loss`: apply all blocked segments ignoring unsatisfied references (order by stamp), drop the unsatisfied marks and set `hw` to the current state, `write_snapshot()` so every other device can rebuild from it, print a summary of what was accepted. That snapshot's `covered` lists **only segments that were actually applied** — a skipped segment is never claimed as covered.
Nothing is dropped silently elsewhere: a device that still holds a skipped segment (applied, or in its cache) keeps it through any rebuild (`usable`, §5.3), fails the presence check on its next refresh and is pointed to `gclone repair`, which republishes the segment (step 2) or a snapshot containing its effects (step 3); every device then converges on it as on any late segment. Any device that still has the missing objects cached can fix a gap for everyone by running plain `gclone repair`.

---

## 6. Transfer pipeline, concurrency, pacing

### 6.1 Constants (all in `src/consts.rs`; none is part of the on-disk format unless marked F)
```
CHUNK_LOG2            = 16            (F: written in every header)
HEADER_LEN = 60, TAG_LEN = 16         (F)
PACK_MEMBER_MAX       = 1 MiB         files with 0 < size < 1 MiB are packed
PACK_TARGET           = 16 MiB        a pack is closed when the next member would push its plaintext past this
MULTIPART_MAX         = 4 MiB         objects ≤ this go up as one uploadType=multipart request
PART_SIZE             = 16 MiB        resumable upload part (64 × UPLOAD_GRANULE)
UPLOAD_GRANULE        = 256 KiB
TRANSFERS_DEFAULT     = 4             concurrent blob uploads; download streams = 2 × transfers
UPLOAD_BATCH_FILES    = 10_000        sources handed to one upload_batch call
RANGE_COALESCE_GAP    = 256 KiB
SOURCE_RECHECK_BYTES  = 64 MiB
UPLOAD_ATTEMPTS       = 3             per file, each with new salt + blob id + Drive ID
DOWNLOAD_RETRIES      = 5
DOWNLOAD_BATCH_FILES  = 512           downloaded files are flushed, renamed and reported in batches of at most this many files …
DOWNLOAD_BATCH_BYTES  = 16 MiB        … or this much content …
DOWNLOAD_BATCH_AGE    = 1 s           … and a file that arrives this long after the batch's first one closes it (§5.7 step 3a)
DOWNLOAD_OPEN_FILES   = 32 on Linux, 1 elsewhere   written files of a batch that are still open, to be synced together through their writing descriptors (§5.7 step 3a)
DOWNLOAD_OPEN_TOTAL   = 256           … and in all batches of the process together
COMMIT_INTERVAL = 120 s, COMMIT_MAX_OPS = 4096
COMPACT_MIN_SEGMENTS = 64, SNAPSHOT_KEEP = 2, INDEX_TRASH_DELAY = 7 d
INDEX_OBJECT_MAX      = 1 GiB         (F: no segment or snapshot is written or read beyond this, §4.6 rule 1)
INDEX_PARALLEL_MAX    = 16 MiB        index objects listed larger than this are fetched one at a time (§5.3)
DESCRIPTOR_MAX        = 64 KiB        gclone-vault.json: nothing longer is read (§3.3)
GC_GRACE = 30 d, RESTORE_WINDOW = 25 d, HISTORY_KEEP = 35 d, ORPHAN_GRACE = 14 d
GAP_GRACE = 10 min (local clock), RACY_WINDOW = 2 s, DATA_FOLDER_MAX = 100_000, MAX_DELETE_ABS = 100
ID_POOL_BATCH = 100 (fallback 10)
HTTP_CONNECT_TIMEOUT = 10 s, HTTP_READ_TIMEOUT = 60 s
UPLOAD_MIN_RATE = 8 KiB/s, UPLOAD_SLICE = 16 KiB      upload requests: total time ≤ HTTP_READ_TIMEOUT + len / UPLOAD_MIN_RATE; bodies go out in UPLOAD_SLICE pieces (§6.4)
PACER: WRITE {start 4/s, min 0.5/s, max 20/s}; READ {start 10/s, min 1/s, max 25/s};
       INCREASE = +0.5/s per 10 s without throttling; DECREASE = ×0.5;
       BACKOFF(n) = min(2^n s + rand(0..1000 ms), 64 s); MAX_ATTEMPTS = 10;
       UNITS_PER_MIN_CAP = 250_000; costs: list 100, download 200, create/update/trash/delete 50, get/about/generateIds 5, upload part 0
       WRITE_BREAKER = 10 min of continuous write throttling without one success
LEDGER_WARN    = 700 GiB uploaded in the trailing 24 h      (Google's cap: 750 GB/day)
LEDGER_DL_WARN = 900 GiB downloaded in the trailing 24 h    (documented egress allowance: 1 TB/project/day)
```
Peak buffer memory at defaults ≈ `2 × PART_SIZE × transfers` (128 MiB) + one pack under construction (≤ 17 MiB). `--transfers N` is the only knob.

**Types in `src/consts.rs`** (fixed by WP0 so every package casts the same way): sizes of files and objects and byte offsets are `u64` (`PACK_MEMBER_MAX`, `PACK_TARGET`, `MULTIPART_MAX`, `PART_SIZE`, `UPLOAD_GRANULE`, `RANGE_COALESCE_GAP`, `SOURCE_RECHECK_BYTES`, `DOWNLOAD_BATCH_BYTES`, `KEYFILE_MAX`, `INDEX_OBJECT_MAX`, `INDEX_PARALLEL_MAX`, `DESCRIPTOR_MAX`, `LEDGER_*`, `DATA_FOLDER_MAX`, `MAX_DELETE_ABS`; also `UPLOAD_MIN_RATE`, bytes per second); fixed format lengths are `usize` (`HEADER_LEN`, `TAG_LEN`; also the buffer size `UPLOAD_SLICE`); `CHUNK_LOG2: u8`; counts are `usize` or `u32` as their use suggests (`TRANSFERS_DEFAULT`, `UPLOAD_BATCH_FILES`, `DOWNLOAD_BATCH_FILES`, `DOWNLOAD_OPEN_FILES`, `DOWNLOAD_OPEN_TOTAL`, `COMMIT_MAX_OPS`, `SNAPSHOT_KEEP`, `KEYFILE_TRY_MAX`, `ID_POOL_BATCH`: `usize`; `UPLOAD_ATTEMPTS`, `DOWNLOAD_RETRIES`: `u32`; `COMPACT_MIN_SEGMENTS: u64`). Time spans are `std::time::Duration` under the name used here, with an integer companion where the span is compared against stored timestamps: `GC_GRACE_MS`, `RESTORE_WINDOW_MS`, `HISTORY_KEEP_MS`, `ORPHAN_GRACE_MS`, `INDEX_TRASH_DELAY_MS`, `GAP_GRACE_MS`, `ACCESS_TOKEN_SKEW_MS` (`u64` milliseconds) and `RACY_WINDOW_NS` (`i64`). Pacer values are `PACER_WRITE_START` … `PACER_READ_MAX`, `PACER_INCREASE`, `PACER_DECREASE` (`f64`), `PACER_MAX_ATTEMPTS`, `PACER_BACKOFF_MAX`, `UNITS_PER_MIN_CAP`, `UNITS_{LIST,DOWNLOAD,WRITE,GET,UPLOAD_PART}`, `WRITE_BREAKER`. The file also names values this spec states only in prose (`CHUNK_LOG2_MIN/MAX`, `COMPACT_MIN_BYTES`, `KDF_*`, `PATH_COMPONENT_MAX`, `PATH_MAX`, `PARTIAL_PREFIX`, `PROBE_PREFIX`, `IGNORE_FILE`, `LOCK_WAIT`, `PROMPT_ATTEMPTS`, …); `KIB`/`MIB`/`GIB` are `u64`.

### 6.2 Upload

**One entry point: `transfer::upload_batch`** (WP5; the only upload API the sync engine calls). Input: upload sources in path order, the data-folder handle, `transfers`. Output: a channel of `UploadEvent`s (`Blob(BlobUpload)` per accepted blob or empty file, `Failed(source, error)` per file that could not be uploaded); every source appears in exactly one event. `upload_batch` owns:
- **classification by the size seen at open** (`fstat` on the open descriptor — not the planner's `Action::Upload.size`, the file may have crossed 1 MiB since the scan): `n = 0` → no blob (`BlobUpload { blob: None, .. }`, entry `loc = None`, `hash = BLAKE3("")`); `0 < n < PACK_MEMBER_MAX` → packer; otherwise → single-member blob;
- the single packer task, the `transfers` concurrent blob puts, and the memory bound of §6.1;
- attempts: a small file whose before/after `fstat` differ is re-read up to `UPLOAD_ATTEMPTS` times, then `Failed(SourceChanged)`; a source that cannot be opened because it is **gone** (`ENOENT`; `ENOTDIR`), **replaced by a symlink** (`ELOOP` from `O_NOFOLLOW`) or **no regular file** any more (directory, FIFO, device) is `Failed(SourceChanged)` at once — at classification and when a large file is opened again for a new attempt; sources are files a scan just saw as regular files, so this is a change, not an unreadable file. Only a file that is still there and cannot be opened or read (`EACCES`, `EIO`, …) is `Failed(SourceUnreadable)` (§17.13); large files as below; a sealed pack is replayed byte-identically under a new Drive ID after `SessionLost` or a failed acceptance (up to `UPLOAD_ATTEMPTS`);
- acceptance of every finished blob (below);
- stopping: cancellation, a dropped receiver, and the first `QuotaExceeded(_)` or `RateLimited` (no new put is started; the remaining sources are reported `Failed` with that error).
The caller (`sync::execute`, §5.7) supplies the data folder and, per `Blob` event, does everything that touches the index or the database: `note_blob_created`, the upload ledger, drafts, staging, periodic commits.

**Packer** (one task): takes small files in **path order**; for each: open (`O_NOFOLLOW|O_NONBLOCK`), `fstat`, read fully, `fstat` again (must match), BLAKE3, seal as a Data stream into the pack buffer; when the next member would push the pack's plaintext past `PACK_TARGET`, when its sealed bytes would pass `PACK_TARGET` + 1 MiB (many tiny members carry 76 bytes of overhead each; this keeps the buffer inside the §6.1 estimate, §17.3), or when input ends: compute MD5, hand the finished `Bytes` to a transfer slot. The pack's blob id, Drive ID and all salts are fresh.

**Single-member blob** (one blocking sealer thread per transfer): `blob_len = ciphertext_len(size at open)`; read the file sequentially in 1 MiB reads; BLAKE3 the plaintext; seal 64 KiB chunks into a `PART_SIZE` buffer; update a running MD5 over the ciphertext; push each full part (`Bytes`) into a bounded channel (capacity 1) consumed by `Backend::put`; `fstat` every `SOURCE_RECHECK_BYTES` and at the end — any change (or a read that ends before or after `size`) drops the channel with an `io::Error` (the backend aborts the session) and the attempt is retried with everything new (max `UPLOAD_ATTEMPTS`).

**Acceptance of a finished upload** (for every blob): returned `ObjMeta.size == blob_len` and `ObjMeta.md5 == local MD5`; otherwise `trash` the object and retry as a new attempt. If the backend returns no md5 (probe 9), `stat` once; still none → accept on size and log at debug level. Then the `BlobUpload` is emitted; the caller stages `[Blob(rec), Put…]` with their base effects in one durable transaction (§5.8) and adds `blob_len` to the upload ledger.

**Drive protocol** (inside `DriveBackend::put`). `FIELDS` = `id,name,size,md5Checksum,createdTime,mimeType,trashed,parents`.
- `fields=FIELDS` MUST be a query parameter of the multipart POST **and of the resumable initiation POST** (`…/files?uploadType=resumable&fields=…`): the initiation answers with an empty body, and the completing `200/201` of the session carries the projection requested *at initiation* — without it Drive returns its default projection (`kind,id,name,mimeType`: no size, no md5, no `createdTime`). The session URI from `Location` is opaque and is used **verbatim** (nothing appended, nothing re-encoded). If a completion body nevertheless lacks `size`, `md5Checksum` or `createdTime`: one follow-up `stat(id)`.
- *Small* (`len ≤ MULTIPART_MAX`): `POST {upload}/drive/v3/files?uploadType=multipart&fields=FIELDS`, `Content-Type: multipart/related; boundary=<random>`; part 1 `application/json; charset=UTF-8`: `{"id","name","parents":[p],"mimeType":"application/octet-stream"}`; part 2 `application/octet-stream`: the bytes. The body is a single `Bytes` → fully replayable; it is sent as an upload body in the sense of §6.4 (explicit `Content-Length`, stall watch, total time by length). `409` → conflict rule (below).
- *Stream* (`len > MULTIPART_MAX`):
  1. Initiate: `POST {upload}/drive/v3/files?uploadType=resumable&fields=FIELDS` with headers `X-Upload-Content-Type: application/octet-stream`, `X-Upload-Content-Length: <total>`, JSON metadata body as above → `200` + `Location` (session URI). `409` here → conflict rule.
  2. Send loop. State: `acked` (bytes the server holds), a deque of retained parts covering `[acked, …)`. Each `PUT <session>` carries `Content-Length` and `Content-Range: bytes a-b/total` with `a = acked` and a body built from the retained `Bytes` slices (an upload body in the sense of §6.4: a stream over the slices, cut to `UPLOAD_SLICE` without copying, explicit `Content-Length`). The body length is the **largest multiple of `UPLOAD_GRANULE` available** in the retained parts, or everything up to `total` if the final part is retained. More parts are pulled from the channel as needed; parts entirely below `acked` are dropped. Every part PUT and status query takes its bearer token from `TokenProvider` **at send time** (uploads routinely outlive the one-hour access token).
  3. Response `308`: `Range: bytes=0-N` → `acked = N + 1`; **no `Range` header → `acked = 0`** (if bytes below the retained window would be needed again → `BackendError::SessionLost`). `200/201` → parse the File resource, done. `409` at completion → conflict rule.
  4. On a network error or `5xx`: status query `PUT <session>` with `Content-Length: 0`, `Content-Range: bytes */<total>` → `308` (update `acked` as in 3, continue), `200/201` (**already complete** → done), `404`/`410` → `SessionLost`.
  5. `401` on a part PUT or a status query is handled **first**: `force_refresh()` once → status query → continue from `acked` with the fresh token. Only a second consecutive `401` ends the put, with `Auth(Expired)`. A `401` is never `SessionLost`.
  6. Rate-limit `403`/`429` → pacer backoff, then status query. Any other `4xx` on the session → `SessionLost`.
  7. Rounds and progress. A **round** is one part PUT (or, when every byte is acknowledged and the session is still not complete, one status query in its place) together with the status query that follows a failed one. The session **made progress** when a `308` — the part's own answer **or the status query after a part that failed** — reports more bytes than the server ever held before (a high-water mark, so a session that forgets bytes and takes them again does not count twice). Progress resets the round counter, the backoff exponent and the write breaker's run; a link that cuts every part PUT while Drive keeps what arrived therefore advances for as long as it advances. Every round without progress is counted and followed by a wait before the next request: `BACKOFF(n)` after a network error, a `5xx`, **a part answered `308` without new bytes, and a `308` with the full `Range` on a session that is not complete**; the pacer's sleep after a throttle. `MAX_ATTEMPTS` such rounds in a row end the put (`Transient`; `RateLimited` if the last was a throttle; `Auth(Expired)` per step 5).
  `SessionLost` propagates to the transfer layer, which starts a **new attempt with a new salt, blob id and Drive ID** (bytes are never re-sealed under the old salt).
- **Conflict rule** (`409` at multipart, at initiation or at completion — where it arrives is probe 6): `stat(id)`. `Some(meta)` → return it; the caller verifies size and md5. `None` (the first attempt is still committing, or the ID is reserved by a session that never finished): retry the `stat` up to 3 times with `BACKOFF` (3 `stat`s in total, with `BACKOFF(0)` and `BACKOFF(1)` between them — what §12.1 counts); still absent → `BackendError::SessionLost`, for Small and Stream bodies alike. The transfer layer then retries under a new Drive ID (packs replay the same bytes; large files use a new salt and blob id); an index object in `outbox` takes a fresh Drive ID with the same name and bytes (§5.8). `put` never returns `AlreadyExists` or `NotFound`.
- The channel yielding `Err` (source changed) → the backend stops sending and returns `BackendError::Io`; the session is abandoned (it expires server-side).

**Retry classification in `upload_batch` where the above is silent** (WP5, §17.3): `Transient` / `Io` on a **pack** put → the same bytes under the **same** Drive ID (the put-once idempotent path); `SessionLost` or a failed acceptance → the same bytes under a new Drive ID. `Transient` / `Io` on a **single-member** blob whose body was sent completely → one `stat(id)`, accepted if size and md5 match, else a new attempt with a new salt, blob id and Drive ID. Acceptance failing `UPLOAD_ATTEMPTS` times → `TransferError::Verify`. `Auth`, `AppNotAuthorized` and `Fatal` fail that blob without a retry and do **not** stop the batch — only `QuotaExceeded`, `RateLimited`, cancellation and a dropped receiver stop it. After a stop, zero-length files not classified yet are reported `Failed` with the stop error like every other remaining source; several zero-length files may share one `Blob { blob: None }` event. A file ≥ `PACK_MEMBER_MAX` whose blob fits `MULTIPART_MAX` goes up as `PutBody::Small` and is still re-read (new salt and blob id) on a retry. `observed_ns` is taken just **before** the `fstat` / `lstat` it belongs to; `Progress` counts plaintext bytes and counts a re-read large file again.

**`DriveBackend` behaviour where the protocol text is silent** (WP3, §17.3): `PutBody::Stream { total: 0 }` is sent as multipart; `PutBody::Small` above `MULTIPART_MAX` is refused with `Fatal{400, "badRequest"}` before any request (as the fakes do); a `404` at create is `Fatal{404, "notFound"}`; `list` of a folder Drive answers `404` for is empty; `get` with an empty range does one `stat` instead of a download; a `416` is an empty stream; a `200` answer to a ranged GET is cut client-side; `trash` / `untrash` / `delete` / `put` / `create_folder` on `Handle::top()` are `Fatal{400}`; a session that makes no progress for `MAX_ATTEMPTS` rounds in a row ends in `Transient` (`Auth(Expired)` if the rounds were `401`s); what counts as progress and what happens between the rounds is step 7 of the protocol above (§17.10). Real Drive reports My Drive's root id as the parent of top-level objects: `DriveBackend` learns that id (from creates at top level, `list(top)`, `stat(top)`) and otherwise asks `files/root?fields=id` at most once per backend, only when a parent has to be judged; if that lookup is refused (possible under `drive.file` — unverified), top-level parents are reported by their raw id.

### 6.3 Download
- Plan items are grouped by blob and sorted by `Loc.off`; members whose gap is ≤ `RANGE_COALESCE_GAP` are fetched with one `GET {api}/drive/v3/files/{id}?alt=media` + `Range: bytes=a-b`; gap bytes are discarded. Before any request: `loc.off + loc.clen ≤ BlobRec.clen`, else `TransferError::Verify` (§4.5).
- Each member: `Keyring::data_opener(&loc)`; header bytes (when in range) must equal `expected_header()`; chunks verified one by one; BLAKE3 over the plaintext; written and finished per §5.7 step 2 (a member up to `PACK_MEMBER_MAX` from memory once it is complete, a larger one through the partial file of one target).
- Retry: on a stream error, re-request from the offset of the first unverified chunk (max `DOWNLOAD_RETRIES` consecutive failed requests **without progress** — the counter resets once a further chunk verified; the pause between retries is 250 ms doubling to 4 s inside the transfer layer, because the pacer is private to `DriveBackend` and not reachable through the `Backend` trait). A response body that ends early without an error triggers one `stat`; an object shorter than the range needed fails at once with `TransferError::Verify("blob … is truncated")` instead of using up the retries. Items of one `download_group` that share a `Loc` are fetched once (§17.3) and written one after another (§5.7 step 2, §17.13).
- `NotFound` on a stored file id → `find_by_name(blob_id hex)`; exactly one hit → use it; else the file fails with `TransferError::BlobMissing` (`transfer::locate_blob` is the same rule with a `stat` first).
- `403` with reason `cannotDownloadAbusiveFile` (matched loosely: reason or message contains `Abusive`) → retry once with `&acknowledgeAbuse=true`.
- `QuotaExceeded(DailyDownload)` and `RateLimited` (§6.5; the latter is what `get` returns once the pacer's attempts are spent on `429` / `userRateLimitExceeded`): stop launching downloads, keep what is finished, exit 75 (§17.13). The executor records downloaded ciphertext bytes in the ledger (direction *down*); `about` and running transfers warn once the trailing 24 h reach `LEDGER_DL_WARN`.
- `cat :p --offset o --count c`: `chunk_range` → one Range GET → open → trim.
- Single-stream per file in the MVP (parallel ranged download of one large file is deferred).

### 6.4 HTTP clients
- **API client** (metadata calls): HTTP/2 via ALPN, `connect_timeout`, `read_timeout`, `User-Agent: gclone/<version>`. No gzip (feature not enabled; listings are small because only `index/` is listed and `fields=` is always set).
- **Transfer client** (`alt=media` downloads): `.http1_only()`, `pool_max_idle_per_host = 3 × transfers`, `tcp_nodelay(true)`, `connect_timeout`, `read_timeout`, **no total timeout**.
- **Upload client** (multipart POST, resumable initiation, part PUTs, status queries; §17.10): as the transfer client, but **without `read_timeout`**. reqwest's read timeout restarts with every read of a *response body* only; until the response headers arrive it is one fixed deadline that connecting, **sending the whole request body** and waiting for the headers must all fit into, however steadily the body flows — on this client it would cap every upload request at 60 s (a 4 MiB multipart body would need 560 kbit/s per stream, a 16 MiB part 2.2 Mbit/s). Instead:
  - every request has a **total timeout**: `HTTP_READ_TIMEOUT` by default (the client's `timeout`; initiation and status queries), and `HTTP_READ_TIMEOUT + ⌈len / UPLOAD_MIN_RATE⌉ s` for a request that carries an **upload body** of `len` bytes (the multipart body, a part) — 9.5 min for 4 MiB, 35 min for a 16 MiB part. It also bounds the read of the answer's body;
  - an upload body is a stream of `UPLOAD_SLICE` pieces of the caller's `Bytes` (no copy) with an explicit `Content-Length`, and a **stall watch** runs beside the request: when the HTTP stack has taken no further piece for `HTTP_READ_TIMEOUT`, the request is dropped (which closes its connection) and counts as a transient failure ("the upload stalled…"). The watch ends when the last piece is taken — how much of the body then still sits in the stack's and the kernel's buffers cannot be seen, so from there only the total timeout applies. hyper's HTTP/1 writer queues at most 16 pieces (256 KiB) before it flushes them all, so the watch tolerates any stream faster than about 4.3 KiB/s; `UPLOAD_MIN_RATE` (8 KiB/s ≈ 64 kbit/s **per stream**) is therefore the one rate below which an upload is treated as dead.
  `DriveConfig.read_timeout` stands for `HTTP_READ_TIMEOUT` in all three clients (tests shorten it).
- **All three clients are built with `redirect(reqwest::redirect::Policy::none())`**: `308 Resume Incomplete` is a status of the upload protocol, carries no `Location`, and must reach the state machine untouched.
- Endpoints (`DriveEndpoints`, injectable): `api = https://www.googleapis.com`, `upload = https://www.googleapis.com/upload` (paths `/drive/v3/...` appended).
- Other calls: `GET /drive/v3/files/generateIds?count=100&space=drive&type=files` (on `400` retry with `count=10`); folder create `POST /drive/v3/files?fields=FIELDS` `{id,name,mimeType:"application/vnd.google-apps.folder",parents:[p]}` (`parents` omitted for `Handle::top()`; `409` = exists = ok); list `GET /drive/v3/files?q=<q>&pageSize=1000&spaces=drive&fields=nextPageToken,files(FIELDS)` with `q = '<id>' in parents and trashed = false` (`'root'` for `Handle::top()`) or `name = '<escaped>' and trashed = false` (escape `\` and `'`); a rejected `pageToken` restarts the listing; stat `GET /drive/v3/files/{id}?fields=FIELDS` (`404` → `None`); trash/untrash `PATCH /drive/v3/files/{id}?fields=FIELDS` `{"trashed": true|false}`; permanent delete `DELETE /drive/v3/files/{id}` (`204`; used only by `gc --purge`); about `GET /drive/v3/about?fields=storageQuota,user(emailAddress)` (a missing `user` is tolerated).
- `Backend::now_ms()` for Drive = local clock + offset learned from the most recent `Date` response header (`util::parse_http_date_ms`). It is used for object ages (GC, cleanup), never for the grace periods of §5.3.

#### 6.4.1 Drive wire shapes (normative for `DriveBackend` **and** for `FakeDrive`, which MUST emit exactly these)
Shapes as documented in the Drive v3 reference ([K]: written from the reference, not re-fetched for this revision; the live conformance run of §13 item 10 confirms them). int64 values are JSON **strings**.
```
File (fields=FIELDS)        {"id":"1AbC","name":"s-0a…","mimeType":"application/octet-stream","parents":["1Par"],
                             "size":"16777216","md5Checksum":"9e107d9d372bb6826bd81d3542a419d6",
                             "createdTime":"2026-11-11T09:14:03.123Z","trashed":false}
Folder (fields=FIELDS)      {"id":"1Fld","name":"index","mimeType":"application/vnd.google-apps.folder","parents":["1Par"],
                             "createdTime":"2026-11-11T09:14:03.123Z","trashed":false}                 no size, no md5Checksum
File, no fields= given      {"kind":"drive#file","id":"1AbC","name":"s-0a…","mimeType":"application/octet-stream"}
files.list                  {"nextPageToken":"tok","files":[ <File>, … ]}                               nextPageToken absent on the last page
files.generateIds           {"kind":"drive#generatedIds","space":"drive","ids":["1a…","1b…"]}
about                       {"storageQuota":{"limit":"2199023255552","usage":"442630144000","usageInDrive":"…","usageInDriveTrash":"3328599654"},
                             "user":{"emailAddress":"me@example.com"}}                                  limit absent = unlimited
error envelope              {"error":{"code":403,"message":"User rate limit exceeded.","status":"PERMISSION_DENIED",
                             "errors":[{"domain":"usageLimits","reason":"userRateLimitExceeded","message":"User rate limit exceeded."}]}}
                            `status` and `errors` may be missing; upload/session endpoints and front ends may answer plain text or HTML
resumable                   initiation: 200, empty body, `Location: <session URI>`
                            progress:   308, empty body, `Range: bytes=0-N` (absent = nothing stored), NO `Location`
                            completion: 200 or 201 + File in the projection requested at initiation
```
The device never talks to Google's token endpoint. The shapes of the auth Worker's answers (`/device/start`, `/device/poll`, `/refresh`, the error object) are normative in §2.3 — for the Worker and for `FakeDrive`'s auth routes alike; Google's token-endpoint shapes are used only inside the Worker and are listed in §16.4.
Decoding rules: `size` (string; a JSON number is accepted too) and `md5Checksum` are **optional** — a folder decodes to `size = 0`, `md5 = None`; `parents` missing → `ObjMeta.parent = Handle::top()`; `createdTime` → `util::parse_rfc3339_ms`; unknown fields are ignored; `classify()` never fails on a body that is not JSON (it falls back to the status code).

### 6.5 Pacer and error classification (all inside `DriveBackend`; callers see only terminal errors)
- Two AIMD token buckets: **write** (initiate, multipart create, folder create, trash/untrash, delete) and **read** (list, get, about, generateIds, downloads). Upload part PUTs and status queries are not paced (they still honour throttling responses).
- A 60 s sliding window of quota units keeps usage ≤ `UNITS_PER_MIN_CAP`; `acquire()` waits when the window is full.
- Classification of an HTTP response (`backend/drive/errors.rs`). `reasons` = **all** `error.errors[*].reason` values; `status` = `error.status`; `message` = `error.message`; a non-JSON body has none of them. Rows are tested top to bottom:
| Condition | Class | Action |
|---|---|---|
| `401` | auth | `force_refresh()` once, retry once → `Auth(Expired)` (inside an upload session: §6.2 step 5) |
| `404` | — | `NotFound` |
| `409` | — | conflict rule of §6.2 |
| `403`, reasons ∋ `storageQuotaExceeded` | terminal | `QuotaExceeded(StorageFull)` |
| `403`, a reason or the message contains `uploadLimit`; **or** WRITE_BREAKER tripped | terminal | `QuotaExceeded(DailyUpload)` |
| `403`, a reason or the message contains `downloadQuota` | terminal | `QuotaExceeded(DailyDownload)` |
| `403`, reasons ∋ `dailyLimitExceeded` | terminal | `QuotaExceeded(ProjectApiQuota)` — Google defines it as the Cloud project's API quota, not the 750 GB cap |
| `403`, reasons ∋ `appNotAuthorizedToFile` | terminal | `AppNotAuthorized` (→ `IndexError::VaultNotVisible`, §2.8) |
| `403`, a reason or the message contains `Abusive` (downloads) | — | `AbuseFlag` (§6.3) |
| `429`; `403` with reasons ∋ `rateLimitExceeded` / `userRateLimitExceeded`; `403` with `status == "RESOURCE_EXHAUSTED"`; `403` with no recognised reason whose message matches `rate limit` or `quota` (case-insensitive) | throttle | halve the class rate, sleep `max(Retry-After, BACKOFF(n))`, retry (≤ MAX_ATTEMPTS) → then `RateLimited` |
| `500/502/503/504`, connect/read errors, an upload body that stalled or outran its total timeout (§6.4) | transient | sleep `BACKOFF(n)`, retry (≤ MAX_ATTEMPTS) → then `Transient` |
| other `4xx` (including `403 numChildrenInNonRootLimitExceeded`, unreachable below `DATA_FOLDER_MAX`) | terminal | `Fatal{status, reason, message}` |
- The 750 GB/day cap has no documented reason of its own (rclone sees it as `userRateLimitExceeded`): it surfaces as the write breaker, or as `RateLimited`, which `sync::execute` reports as `QuotaExceeded(DailyUpload)` when the upload ledger shows ≥ `LEDGER_WARN` in the trailing 24 h. The backend itself does not read the ledger.
- `QuotaExceeded(_)` / `RateLimited`: the sync engine stops launching transfers, commits what completed (the commit may itself end in `OutboxStuck`; later reads still work, §5.3) and exits 75 with:
  - `StorageFull`: "Drive is full. Files in the trash still count: `gclone gc` then `gclone gc --purge` frees what was deleted more than 30 days ago; `gclone about` shows the numbers."
  - `DailyUpload`: "Google's 750 GB/day upload limit reached; re-run tomorrow — finished work is saved."
  - `DailyDownload`: "Google's download quota for today is used up; re-run tomorrow — finished files are kept."
  - `ProjectApiQuota`: "The API quota of your Google Cloud project is used up (console.cloud.google.com → APIs & Services → Quotas)."

### 6.6 Expected cost (assertable on the fake backends via call counters, §13)
| Operation | API calls |
|---|---|
| no-change `sync` | 1 list (+0 if the token is cached; + one snapshot download the first time another device's snapshot is listed, §5.3) |
| upload of N small files totalling T bytes | ≤ ceil(T / 16 MiB) + 1 blob creates + 1 segment create (+ generateIds) |
| rename of a directory with any number of files, then `sync` | 1 segment create, 0 data bytes |
| `ls` | 1 list + downloads of new segments only |

---

## 7. CLI

Remote paths start with `:` (`:` alone is the vault root). `copy`/`sync` take exactly one local and one remote argument; the direction follows from which one has the `:`.

### 7.1 Commands
```
gclone login  [AUTH_URL] [--no-browser] [--device-name NAME] [--vault-name NAME] [--new-vault] [--vault-id HEX] [--vault-dir DIR]
              [--passphrase-file PATH] [--allow-expiring-login]
gclone logout [--revoke] [--forget] [--yes]
gclone passwd [--passphrase-file PATH]
gclone status [-q]
gclone about

gclone copy SRC DST   [-n|--dry-run] [--checksum] [--force] [--exclude GLOB]... [--transfers N] [--reset-pair | --keep-pair]
gclone sync SRC DST   [-n|--dry-run] [--checksum] [--force] [--exclude GLOB]... [--transfers N] [--reset-pair | --keep-pair]
                      [--max-delete N] [--yes]
gclone ls    [-l] [-R] [:PATH]
gclone tree  [:PATH]
gclone cat   :PATH [--offset N] [--count N]
gclone web   [--port N] [--no-browser]        (§7.4: the vault in a browser; read-only; runs until Ctrl-C)
gclone mkdir :PATH
gclone rm    [-r] :PATH...
gclone mv    :SRC :DST [--force]
gclone restore [-r] :PATH... [--list] [--version K]
gclone check [LOCAL :REMOTE | --download [:PATH]]
gclone gc    [-n|--dry-run] [--orphans] [--purge]
gclone repair [--accept-loss]
gclone probe                                  (hidden; the automatable day-0 probes of §2.9)

Global: -v/--verbose (repeatable)   -q/--quiet   --json (copy and sync only: NDJSON events on stdout, one final {"event":"summary",…})
Env:    GCLONE_CONFIG_DIR, GCLONE_STATE_DIR (override the two directories of §8.1 — set BOTH for a second device or vault: the login
        and the cached key live under the state root; used by tests)
        GCLONE_AUTH_URL (the auth Worker's URL for `login`, §2.2)
Build:  GCLONE_DEFAULT_AUTH_URL (compile-time default for the same; read with option_env!)
```
- `login` is the one command that connects a device — the first or any later one. It signs in through the auth Worker (§2.4) and then creates the vault if this Google login sees none, or attaches to the existing one after asking for the passphrase (§2.6). Run again, it repairs whatever is missing (expired login, interrupted unlock) and changes nothing else. `AUTH_URL` is needed the first time only: it is remembered in `config.json` and survives `logout` (not `logout --forget`). `--vault-name` applies when a vault is created; `--new-vault` creates one although others exist; `--vault-id` picks one of several.
- `login --vault-dir DIR` selects the directory backend (no OAuth, no Worker) and records it in `config.json`; it cannot be combined with `AUTH_URL`. On a device attached to a directory vault a plain `gclone login` means the same directory; switching a device between a Drive vault and a directory vault (or between two directories) needs `logout --forget` first (§2.6 step 0).
- `logout` removes this device's token and cached key; `--revoke` ends the Google login of every device; `--forget` also removes the local vault state (§2.7). `passwd` sets a new passphrase by writing a new keyfile (§2.7).
- `copy` and `sync` take **directories**: the contents of `SRC` go into `DST` (as `rsync SRC/ DST/`; a trailing slash changes nothing; a file as the local argument is `Usage`). `sync` deletes at the destination what this pair synced before and the source no longer has (rows 8/9 of §5.5.1) under guard G4; `copy` never deletes. Entries that exist only at the destination and were never synced are never deleted by either (§5.5.1 precisions). Both skip-and-report instead of overwriting unseen changes; `--force` enables the overrides listed in the table and G2/G3 — nothing else, and the help texts of the flag and of both commands say this in user terms instead of citing section numbers (§17.14). `--max-delete N` is a hard limit (G4).
- `mv` moves into an existing directory, renames otherwise, and replaces nothing without `--force`; `restore` works on files and, with `-r` / `--list`, on directories (§5.5.4).
- Read-only commands (`ls`, `tree`, `cat`, `about`, `status`, `check`, and `web` when it starts) try the lock; if another gclone holds it they use the replica as is and print `note: index not refreshed (another gclone is running)`. `web` lets go of the lock as soon as it has started (§7.4).
- `gc --purge` is the only command that permanently deletes remote objects (§5.9). `--reset-pair` / `--keep-pair` answer the root-identity guard (§5.5); `--reset-pair` also works when the guard did not fire (the run is then a first sync for that pair: nothing is deleted or overwritten). `--allow-expiring-login` accepts a time-limited Google login (§2.4).
- Secrets never appear in argv or the environment: the passphrase comes from a no-echo prompt or `--passphrase-file`; tokens and keys only ever live in the 0600 files of §8; the one-time link of `gclone web` reaches the browser through a 0600 file, never as an argument of the launcher (§7.4). (`AUTH_URL` is not a secret.)
- Test-only switches, honoured **only by builds with debug assertions** (`cfg!(debug_assertions)`; release builds ignore them): `GCLONE_TEST_FAST_KDF=1` (keyfiles are written with `m_kib = 8192, t = 1`), `GCLONE_TEST_DRIVE_API` / `GCLONE_TEST_DRIVE_UPLOAD` (Drive endpoints), `GCLONE_TEST_REVOKE_URL`, `GCLONE_TEST_BROWSER` (`gclone web`: a file that receives what the browser launcher would have been given — nothing is launched, §17.21). They let `tests/cli_e2e.rs` drive the real binary against `FakeDrive` (§12.1). All of them are read through one function (`cli::context::test_env`); the integrator checked on a release build that `GCLONE_TEST_FAST_KDF=1` is ignored (§17.5).
- Argument rules enforced by clap (§17.5): `--transfers` is 1..=64; `--vault-dir` conflicts with `AUTH_URL`; `--new-vault` conflicts with `--vault-id`; `restore --list` conflicts with `--version`; `--version` is ≥ 1.
- Ctrl-C (§17.5): during `copy` / `sync` the first Ctrl-C cancels the run — what completed is committed, exit 130 — and a second one exits at once; every other command exits 130 immediately, after restoring the terminal's echo setting (every command tolerates being killed, §5.8). `web` is ended by Ctrl-C: it stops serving and exits **0** (`cli::SERVING`).
- `status -q` prints warnings only (it is the keep-alive of §2.4). `--json` is implemented by `copy` / `sync` only. Every other command **refuses it** (`Usage`, exit 2, "--json is supported by copy and sync only", §17.14): `Ui::out` is silent under `--json`, so those commands printed nothing on stdout and exited 0 — `gclone --json ls :` was indistinguishable from an empty vault, and `login --json` dropped the head fingerprint. The flag's help text carries the restriction. A JSON form of the other commands' results stays undone (§14).
- `-q` suppresses plan and skip lines. A run that skipped files still exits 6, so under `-q` (and not `--json`) `copy` / `sync` print the first ten skips with their reasons as `warning: skipped <path>: <reason>` on stderr, plus a count of the rest (§17.14).
- A dry run or a run that only creates directories reports them (`Summary.dirs_created`: "Would create 1 directory.", "… 2 directories created") instead of "Nothing to do" after a `+ mkdir` line.

### 7.2 Exit codes
| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error — including a remote path that does not exist (`ls`, `cat`, `rm`, `mv`, `restore`, a download with `copy` / `sync`, `check`) |
| 2 | usage error: clap's own, and `SyncError::Usage` — a usage error found after argument parsing (mixing backend kinds in `login`, §2.6 step 0; `logout --revoke` on a directory vault) |
| 3 | integrity: crypto failure, index `Gap`/`Rollback`, vault trashed/missing, the vault or one of its index objects needs a newer gclone (`NeedsNewerGclone`, `UnsupportedObject`), `check` found damage, `gc` refused on an incomplete index |
| 4 | fixed by `gclone login`: not connected / signed out / key not unlocked / wrong passphrase / secrets file with unsafe permissions (`ConfigError::{NotConfigured, NotLoggedIn, Locked, WrongPassphrase, InsecurePermissions}`), every `AuthError` (expired or revoked login → "run `gclone login`", Worker problems, expiring login refused), `VaultNotVisible` / `AppNotAuthorized`. An auth Worker that cannot be reached (`AuthError::Network`) is exit 4 for a command that needs the store; a read-only command that can answer from the replica warns and exits 0 (§9.10) |
| 5 | safety guard refused (G2–G4, G6 without confirmation; an explicit `--max-delete` exceeded — never confirmable) |
| 6 | partial: some files were skipped or failed |
| 75 | temporary failure: `QuotaExceeded(_)`, `RateLimited`, `IndexError::OutboxStuck` (a segment could not be published yet) |
| 130 | interrupted |
Precedence when several apply: 3 > 4 > 75 > 5 > 6 > 130 > 2 > 1 (130 and 2 only ever compete with 1 in practice).
Cases settled by WP7 (§17.5): a passphrase is needed and there is neither a terminal nor `--passphrase-file` → 2; a passphrase file whose first line is empty or shorter than `PASSPHRASE_MIN_CHARS` when a passphrase is being set → 1; `logout --forget` over unpublished changes without `--yes` and without a confirming terminal → 5; `logout --revoke` without `--yes` off a terminal → 2, declined at the prompt → 1; `gc` refuses with 3 for every refresh outcome other than a complete index (a network error included); a login failure (exit 4) during the refresh of a read-only command or of `gc` is passed on as 4 (§9.10 `RefreshPolicy::Tolerant`) — except `AuthError::Network` / `AuthError::Io`, which say nothing about the login and are treated like any other network error: read-only commands continue on the replica, `gc` refuses with 3 (§17.9).

### 7.3 Example output (wording is normative for tests only where marked ▸)
```
$ gclone login https://gclone-auth.example.workers.dev            (first device; the browser opens on google.com/device)
▸ To sign in, open  https://www.google.com/device
▸ and enter the code  GQVQ-JKEC
▸ (enter only a code shown in this terminal; waiting…)
▸ Signed in as me@example.com.
No gclone vault found in this Drive.
New passphrase (leave empty to let gclone generate a strong one):
Generated passphrase:  7K2M9-QXA41-TBZR8-D0HNW
Store it in your password manager. It is needed once on every new device and cannot be recovered.
Creating vault "gclone"... done
▸ Vault created. This device: "mbp".

Try:  gclone copy ~/Documents :Documents

$ gclone login https://gclone-auth.example.workers.dev --no-browser      (a later device, here without a browser: the same three lines)
To sign in, open  https://www.google.com/device
and enter the code  WDJB-MJHT
(enter only a code shown in this terminal; waiting…)
▸ Signed in as me@example.com.
Found vault "gclone" (created 2026-11-11).
Passphrase: ********
▸ Connected to vault "gclone" (38,201 files). This device: "nas".
Compare with `gclone status` on a device you trust (run it there now): head 7QK2-M9XA, 38,201 files.
A new device trusts the vault as Google serves it; equal head values mean both devices see the same history.

$ gclone login                                                    (same device, months later: the login had expired)
To sign in, open  https://www.google.com/device
and enter the code  HKPL-RQZC
(enter only a code shown in this terminal; waiting…)
▸ Signed in again as me@example.com. Vault unchanged.

$ gclone passwd
New passphrase (leave empty to let gclone generate a strong one): ********
Repeat: ********
▸ Passphrase changed. New devices need the new passphrase; connected devices are unaffected.

$ gclone logout
▸ Signed out on this device.
The Google token was discarded, not revoked — Google can only revoke the login of all devices at once (gclone logout --revoke).

$ gclone sync -n ~/Photos :Photos
+ upload   2026/IMG_0412.jpg            4.2 MiB
= reuse    2026/trip/IMG_0001.jpg       (same content as 2026/IMG_0001.jpg)
- delete   2025/blurry.jpg
! skip     notes.txt                    remote is newer (changed on "nas"); --force to overwrite
! keep     draft.txt                    both changed; remote version will be kept as draft.conflict-9f2c11aa-412.txt
▸ Would upload 1 (4.2 MiB), reuse 1, delete 1, skip 1, conflict 1. Nothing changed (dry run).

$ gclone sync ~/Photos :Photos
Uploading  [=========>      ] 3.1/4.9 GiB  41 MiB/s  eta 44s  (1,204/4,700 files, 12/317 blobs)
▸ Done in 2m03s: 4,700 uploaded (4.9 GiB), 12 reused, 3 deleted, 1 skipped.

$ gclone ls -l :Photos/2026
          -  2026-08-01 10:12  trip/
    4.2 MiB  2026-11-02 18:31  IMG_0412.jpg

$ gclone restore --list :Photos/2025/blurry.jpg
  K  removed            size      by
  1  2026-11-11 09:14   2.1 MiB   mbp   (deleted)
  2  2026-10-30 21:02   2.0 MiB   nas   (overwritten)

$ gclone about
Drive storage   412.3 GiB of 2 TiB used (3.1 GiB in trash, 0.9 GiB of it trashed by gclone: gclone gc --purge)
Vault "gclone"  38,201 files, 96.4 GiB in 9,412 blobs (1.2 GiB dead: gclone gc; 310 MiB dead space inside packs)
Index           1 snapshot + 7 segments; last change 2 h ago from "mbp"
Transferred     12.4 GiB up, 0 B down in the last 24 h

$ gclone status
Login        ok — me@example.com via https://gclone-auth.example.workers.dev (last refresh 12 min ago)
Vault        gclone (9f2c11aa…), format 1
Head         7QK2-M9XA (38,201 files) — the same on every device that is up to date
This device  mbp (a1b2c3d4e5f60718)
Devices      mbp (2 h ago), nas (3 d ago)
Pending      none
```
`--json` events (one JSON object per line): `{"event":"plan","action":"upload","path":…,"size":…}`, `{"event":"done","action":…,"path":…}`, `{"event":"skip","path":…,"reason":…}`, `{"event":"warn","message":…}`, `{"event":"summary","uploaded":…,"downloaded":…,"reused":…,"deleted":…,"skipped":…,"failed":…,"conflicts":…,"bytes_up":…,"bytes_down":…,"exit":…}`.

### 7.4 `gclone web` — the vault in a browser (0.3.0, §17.20)

Everything on Drive is ciphertext, so Google's pages show nothing. `gclone web [--port N] [--no-browser]` serves a file browser for the **decrypted** vault from the gclone process itself: one embedded page (`src/web/assets/{index.html,app.css,app.js,icon.svg}`, `include_str!`; vanilla JS, no build step, no external resource of any kind) and a small HTTP/1.1 API on loopback. It is **read-only**: no route changes the vault or the index; the only things written are gclone's own download ledger (as `cat`) and, during a refresh, the replica (as every read-only command). Both backends.

**Process.** `open_ctx{TryShared, Tolerant, no settle}` — so not connected / signed out / locked / a dead login fail exactly as for `ls`, with its texts and exit codes — then the lock and that vault are dropped and the server keeps: the backend (`Arc<AnyBackend>`; a Drive backend renews its access token on demand for as long as the process lives), the keyring, a `Vault::open_unlocked` over `Db::open_shared` for all queries and downloads (§8.3: a lock-less reader), and a second `open_shared` connection for the ledger. It binds `127.0.0.1:N` (`N` omitted: port 0, a free one) and, if that address is free too, `[::1]:N` — never anything else; there is no flag for another address, and a peer that is not loopback is dropped. It serves until Ctrl-C (exit 0). A port that cannot be bound is exit 1 before anything is printed.

**The link, and the browser.** With `--no-browser` / `want_headless` (§2.4: SSH session, Linux without a display) the link is printed (stdout, also under `-q`). Otherwise gclone opens the default browser itself — and **not with the link**: an argument list is readable by every account of the machine (`ps`, `/proc/*/cmdline`), and on Linux the browser keeps its arguments for as long as it runs. It writes `<state root>/web-open-<port>.html` (`util::write_atomic`, mode `0600`, in the `0700` directory that holds `secrets.json`): `<meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=LINK">` and the link as an anchor, nothing else; hands **that file's path** to `open::that_detached`; and removes the file as soon as the link is used or replaced, and when the viewer ends (`App::delete_when_used`, `App::close`). A launch page older than ten minutes that a killed viewer left behind — its link died with it — is removed by the next one. If the file cannot be written, the link is printed instead; it is never passed as an argument. The terminal shows no link in this mode, only the port. When stdin is a terminal, every line typed there makes a **new link and a new session** (below); the thread that reads it must not stop the process: a background job (`gclone web &`, Ctrl-Z and `bg`) that reads its terminal gets `SIGTTIN`, whose default action stops every thread — so `SIGTTIN` is ignored, the read fails with `EIO`, and the thread tries again each second until the job is in the foreground or the terminal is gone. The texts say "press Enter" only when the process is in the terminal's foreground group at start (`tcgetpgrp(0) == getpgrp()`), otherwise "run `gclone web` again".

**Refresh.** `POST /api/refresh` (and nothing else: there is no timer) does what the start of a read-only command does — the state lock, `Vault::open` on a fresh connection, `refresh()`, both dropped — with two differences that come from the viewer outliving commands: the lock is taken with `state::try_lock_existing`, which creates neither the state directory nor the lock file, and nothing is opened unless the device guard (below) holds, asked once before the lock and once under it (`gclone logout` holds that lock while it removes things, so the second look cannot be overtaken). A busy lock: the answer says that another gclone is running. The state lock is therefore held only for the length of a pull, and a `gclone sync` in another terminal waits for the viewer no longer than for a `gclone ls`. What another process on this device commits is visible at once (same `state.db`). The outcome (`RefreshState { at_ms, ok, applied, note }`) is kept and shown: `Gap` / `Rollback` / an unreachable store → the text of `report_refresh`; a login that ended at Google → the §2.8 text; the server goes on serving the replica in those cases.

**A device that is signed out stops serving** (`cli::web::DeviceGuard`). The viewer holds the keyring, the backend (for Drive: the refresh token) and an open database in memory; `gclone logout` removes files. Without a check, a viewer forgotten in another terminal would go on serving decrypted files after "Signed out on this device", and after `logout --forget` its next refresh would write the state directory — a plaintext index — back. The guard holds while `config.json` names the vault the viewer started with, `secrets.json` holds the same login and keys (a keyed BLAKE3 digest of refresh token, key entries and `min_epoch`, taken at start; the two files are read again only when their `stat` changed), and `state.db` is the very file the viewer has open (device and inode — a state directory that was removed and made again is another file, which the viewer's open connection would never see). It is asked **for every request**, before the session is looked at — a request after `logout` has returned is answered `403` "The viewer has stopped: …" on every route — **by the refresh**, and **once a second** by the command, which then ends the server, with it every stream, prints the same text and exits **4**. Once tripped it stays tripped: a new login does not revive the viewer. Signing in again to the same vault with the same keys (a directory vault's `gclone login`) is not a change.

**Session.** A session is a random path prefix and a secret: `/s-<128 random bits, base64url>/` and 256 random bits (`util::random`). The secret is the value of the cookie `gclone_web_<port>`, set as `Path=/s-…/; HttpOnly; SameSite=Strict` (a session cookie). **The page, its assets, the API and the files all live under the prefix** — the page's own URLs are relative — and nothing but the link is answered outside it. The prefix is not a credential (it is in the address bar; the cookie is still required, and compared in constant time): it is what keeps the cookie on this server. Cookies are not separated by port, so a cookie with `Path=/` on `127.0.0.1` would be attached to every request the browser makes to **any** server on the loopback host — a development server, another user's listener that a page navigated the browser to — and whoever receives it can read the vault with a plain HTTP client. A cookie scoped to a path that only this server knows is sent to no other (`Referrer-Policy: no-referrer` keeps the path out of requests elsewhere). **Every** route — the page and its assets included — answers `403` with one line of plain text without the session, and so does every path outside the prefix, with or without the cookie. Cookies are read as **bytes** (`Cookie` headers split at `;`, trimmed, split at the first `=`): the browser sends the cookies of every loopback server in one header, and one value that is not ASCII must not hide the session.

The session is handed out for the key of a **one-time link**, `http://127.0.0.1:<port>/?k=<192 random bits>`: `GET /?k=…` with the current key → the key is used up and the answer carries `Set-Cookie` and leads to the prefix — `303 See Other` when the browser says that no other site began the navigation (`Sec-Fetch-Site: none` or `same-origin`: typed, pasted, opened from a terminal), otherwise (`cross-site` navigation — a terminal in a browser tab, the launch page, which is a `file:` document — or a browser that sends no `Sec-Fetch-Site`) `200` with a page that goes there by `<meta http-equiv="refresh">`: a redirect would stay part of a navigation that another site began, to which `SameSite=Strict` does not send the new cookie. The key is one-time, not absent from history: the browser records the address of the link; what it records is spent. A key that was used is `403` "This link has been used already … If it was not you who opened it, another program on this machine did — press Enter …: that ends every session and gives you a new link" (the last sixteen used keys are remembered for that text); any other key is `403` "not a valid link"; there is no way past the key for a browser that already has a session (its cookie is not sent to `/`), so **every key that reaches the server is spent or refused**. **A new link is a new session** (`App::login_url`): new prefix, new secret, the old session's cookie and path are dead on every route and its file streams are cut (`Session::ended`) — the one action that shuts out whoever redeemed a link first. Comparisons are constant-time (`util::ct_eq`). Neither secret is logged — a request is logged at debug level with its method and its route (the path without the prefix), never its query. A query parameter rather than a fragment, because the fragment never reaches the server, which would have had to serve the page without the secret.

**Checks, in this order, for every request.** (0) The request head — request line and header lines as sent — is at most `HEADER_BYTES_MAX` = 64 KiB, else `431` (enforced by the handler; hyper's read buffer, which grows beyond its nominal size before it gives up, only bounds what is read at all; a request target over hyper's own limit is `414`). (1) `Host` — exactly one, equal (ASCII case-insensitively) to `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`, and the same for the authority of an absolute request target; else `403` (DNS rebinding: a foreign name that resolves to loopback still arrives as that name; an SSH tunnel must use the same port on both ends). (2) `Origin`, if present, is `http://` + one of those; `Sec-Fetch-Site`, if present, is `same-origin` or `none`; else `403` (the link's navigation aside) — although nothing but the refresh is state-changing. Each of `Origin`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest` that is sent **twice**, or holds bytes that are not visible ASCII, is `403` as well: a header the server cannot read must not count as absent. (3) The device guard. (4) The link, or the session and its prefix. (5) The route; an unknown path under the prefix is `404`, a known one with another method `405` with `Allow`. A malformed query (`%` not followed by two hex digits, not UTF-8, a parameter given twice, a path that fails `path::validate`, a number out of range, an `id` this viewer did not give out) is `400`. Remote paths are only ever looked up in the index — no file-system access by a path from the client exists.

**Routes.** `/?k=…` at the root; everything else under the session's prefix (`/s-…/api/info`, …; shown here without it). All `GET`/`HEAD` unless noted; JSON unless noted; errors are `text/plain` with one readable line.

| Route | Parameters | Answer |
|---|---|---|
| `/?k=…` (root) | `k` | the link: the cookie, and the way to the prefix (above) |
| `/` | — | the page; `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self'; frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` |
| `/assets/app.css`, `/assets/app.js`, `/assets/icon.svg` | — | the page's style, script, icon |
| `/api/info` | — | `{vault, backend: "drive"\|"dir", device, version, read_only: true, files, bytes, last_change_ms, last_change_by, refresh: RefreshState}` — `Vault::stats`, no call to the store |
| `/api/list` | `path` (absent/empty = root), `sort` = `name`\|`size`\|`mtime`, `order` = `asc`\|`desc`, `offset`, `limit` (default `LIST_PAGE` 2000, max `LIST_PAGE_MAX` 5000) | `{path, sort, order, total, offset, entries: [{name, dir, kind, size, mtime_ms}]}`; `404` if there is no such directory. **Order**: directories first, always; `sort=name` by natural order (case-insensitive, digit runs as numbers, ties by bytes), reversed as a whole under `desc`; `sort=size\|mtime`: files by that key (reversed under `desc`), equal keys by name ascending, directories — which have neither — by name ascending. `kind` is `folder` or `image`\|`pdf`\|`audio`\|`video`\|`text`\|`archive`\|`file`; `size` and `mtime_ms` are `null` for directories |
| `/api/stat` | `path` | one entry, with `path`, and for a file with `id`: the path sealed under a key of this process (XChaCha20-Poly1305, the nonce a keyed BLAKE3 hash of the path, base64url — one file, one id; opaque and authenticated) — what `/file` takes in place of the path; `404` if absent |
| `/api/search` | `q`, `limit` (default `SEARCH_HITS` 200, max 1000), `sort`, `order` (as `/api/list`) | `{q, sort, order, hits: [entry with path], more}` — `Vault::search`: names (last components, directories with or without a head) that contain `q`, NFC + lower case on both sides; the first `limit` matches in path order, `more` = there are further ones; those are then put in **the order of a listing** (the same function: directories first, natural order of the name, equal names by path), so that the same entries come in the same order in a folder and in a search |
| `POST /api/refresh` | — | the `/api/info` object after the refresh |
| `/file` | `id` **or** `path` (not both), `dl=1` | the file's bytes (not JSON), see below. The page uses `id` only, so that no file name is in an address the browser keeps (a tab opened on a file, the download list); `path` is for other clients |

**File content.** `transfer::read_range` (the reader of `cat`) runs in a task and writes into a bounded channel (16 frames of ≤ 64 KiB) that is the response body: nothing is buffered beyond that, nothing is written to disk, and every chunk is authenticated before a byte of it is sent. The answer waits for the first verified bytes, so a blob that is missing or damaged from the start — or a store that cannot be reached, or a login that ended — is `502` with the text the command line would print ("The file could not be read from the vault: …"); a failure after that cuts the connection (the body ends short of `Content-Length`), so a damaged download never looks complete. A client that goes away closes the channel, which ends the task and with it the request to the store — also while the task is waiting for the store (`Sender::closed`). `Accept-Ranges: bytes`; one byte range (`a-b`, `a-`, `-n`) → `206` with `Content-Range`; a range that selects nothing → `416` with `Content-Range: bytes */<size>`; **several ranges, or a `Range` that is not understood → `200` with the whole file** (RFC 9110 §14.2 allows ignoring the header). `ETag` is the BLAKE3 content hash of the entry in quotes; `If-None-Match` → `304`; `If-Range` with another tag → the whole file. `HEAD` answers from the index alone and **ignores `Range`** (RFC 9110 §14.2: the header is defined for `GET`): always `200` with the whole length. An empty file is `200` with no body. At most `STREAMS_MAX` = 16 file streams run at a time; a request waits 5 s for a free one, then `503` with `Retry-After`. A stream ends with its session (a new link, a device that was signed out). Connections: at most 128, 15 s to send the request head, 64 KiB of head (check 0).

**Vault files are untrusted content** (`src/web/mime.rs`). The `Content-Type` comes from the file name's extension through a built-in table, never from the content, and every response carries `X-Content-Type-Options: nosniff`. HTML, XHTML, XML, JavaScript, CSS and every other text format are `text/plain; charset=utf-8`; SVG is `image/svg+xml` (shown through `<img>`, where script does not run); images, audio, video and PDF have their own types; everything else is `application/octet-stream`. `Content-Disposition` is `inline` only for that list (images, PDF, audio, video, `text/plain`) and `attachment` otherwise and whenever `dl=1`, with the name as `filename="<ASCII stand-in>"; filename*=UTF-8''<percent-encoded>` (RFC 6266 / 5987: quotes, non-ASCII, control characters and line breaks cannot end or extend the header). `Content-Security-Policy` on file responses: `sandbox; default-src 'none'; …` plus only what the browser's own image, media or text document needs (`img-src 'self'` / `media-src 'self'`, `style-src 'unsafe-inline'`), `frame-ancestors 'none'`; for PDF `default-src 'none'; frame-ancestors 'self'` **without** `sandbox`, because browsers do not show a PDF in a sandboxed frame. Everything is `Cache-Control: no-store`.

**The page.** Folder navigation with breadcrumbs (a path that does not fit scrolls, and shows its end); a list with name, size, modification time and a type icon, sortable by the three, directories first; search over the whole vault with a note when the cap cut the result, each match with its folder (cut at its beginning when it does not fit); previews — images and SVG in `<img>` on a light checkerboard of their own (a transparent image with dark content is legible in the dark theme), PDF in an `<iframe>`, audio and video with the browser's controls (seeking uses ranges), text of every kind as text (the first 512 KiB; a byte-order mark decides the encoding, else UTF-8 if valid, else Windows-1252; a character split by the cut is dropped), a card with a download button for everything else and for what the browser cannot show; every preview shows "Loading <name> (<size>)…" until its element has something to show; download — asked of the store first (`Range: bytes=0-0`), so that a file it cannot deliver is the server's message in the page instead of a download that fails silently; the vault summary in the footer and behind the info button, redrawn with the clock and fetched again with every listing; refresh; keyboard (arrows, Home/End/Page keys, Enter, Backspace = up, Esc, `/` = search; ←/→ in the preview). The preview is a modal dialog: while it is open everything behind it is `inert`.

**Nothing of the vault's names where the browser keeps it.** The address is the session's prefix and nothing else, and the title is "gclone", always: the place in the vault (`{dir}`, `{file}`, `{search}`) lives in `history.state` (`pushState(state, '')` without a URL), so reload, back and forward work, and the browser's history — which is on disk, and with history sync on a vendor's servers — records one address and one title. Files are fetched by `id` (above). What remains is §15.

Lists are drawn as a window of rows over the loaded entries (a directory of 10,000 entries has some thirty rows in the DOM) and loaded in pages. Names reach the DOM as text nodes and attribute values only (`textContent`, `setAttribute`), never as markup; they are shown as they are — `white-space: pre`, control characters as their pictures (U+2400…) — and commands in messages are `<code>` elements built from text. System fonts, light and dark by `prefers-color-scheme`, usable down to phone width, ARIA grid with `aria-activedescendant` (one tab stop, a visible focus ring also without a selected row, the kind of each entry as hidden text). A list of deleted or restorable versions, thumbnails and any write operation are out of scope (§14).

---

## 8. Local state

### 8.1 Paths (`etcetera::choose_base_strategy()` → XDG on macOS and Linux)
```
<config>     = $GCLONE_CONFIG_DIR or ~/.config/gclone            (0700)
    config.json      0600   non-secret: which vault this device is attached to, and the auth Worker URL
<state root> = $GCLONE_STATE_DIR or ~/.local/state/gclone        (0700)
    secrets.json     0600   secret: this device's refresh token (with the auth Worker URL and e-mail) and the cached master key
    token.json       0600   cached access token (belongs to the login, not to a vault)
<state>      = <state root>/<vault_id hex>                       (0700)
    state.db (+ -wal, -shm)   0600   SQLite (§8.4)
    lock                             kernel lock file (§8.3)
    index-cache/<object name>        raw ciphertext of index objects (feeds `repair`)
```
`gclone logout` deletes `token.json`, `secrets.json` and leftover temp files of either (below); `logout --forget` also deletes `config.json` and the vault's `<state>` directory (§2.7).
All files are written via temp file + `fsync` + `rename` in the same directory (`util::write_atomic`): the temp file is opened `O_CREAT | O_EXCL | O_NOFOLLOW` with its final mode, never chmod-ed afterwards. The temp file is named `.<name>.tmp-<16 lowercase hex digits>`; a process killed between its creation and the rename leaves it behind as a full copy of what was being written, so whatever deletes a secret file also removes these (`util::remove_atomic_leftovers(path)`: `SecretStore::delete` for `secrets.json`, `logout` for `token.json` as well, §2.7). Nothing sweeps them at other times — a concurrent writer's temp file must not be taken away. Directories are created with mode 0700 at creation (`util::create_dir_private` = `DirBuilder::new().recursive(true).mode(0o700)`), not created and then tightened.

**Why the secrets are not in `<config>`.** `~/.config` is what dotfile repositories, synced home folders and selective backups pick up; the master key cannot be rotated in v1 (re-keying is deferred), so one leaked copy is permanent. The state root is machine-local state. `secrets.json` must never be copied to another machine — a new device gets its own login and unlocks with the passphrase. gclone itself never syncs `<config>`, `<state root>` or a directory vault's directory, even when the sync root contains them, and refuses a sync root inside one of them (§5.5.3).

**Strict loading** (like ssh `StrictModes`; `FileSecretStore::load`): before reading `secrets.json`, `lstat` the state root and `fstat` the file opened with `O_NOFOLLOW`; each must be owned by the effective uid and have no group or other permission bits (`mode & 0o077 == 0`), else `ConfigError::InsecurePermissions(path)` (exit 4 with the chmod hint of §2.8) — nothing is read and nothing is repaired silently. An absent file is simply "no secrets" (`Ok(None)`). `token.json` gets the same check; a failure there only discards the cache.

### 8.2 File formats
`config.json`:
```json
{ "version": 1, "vault_id": "<32 hex>", "vault_name": "gclone",
  "backend": { "kind": "drive" } | { "kind": "dir", "path": "/abs/path" },
  "auth_url": "https://gclone-auth.example.workers.dev",
  "root_id": "…", "index_id": "…", "data_id": "…" }
```
`auth_url` (Drive vaults only; the key is absent for directory vaults) is a copy of the Worker URL the device was attached through. It is not a secret; it is here so that `gclone login` after a `logout` needs no URL (§2.2). It is validated when used, like every stored URL.

`secrets.json`:
```json
{ "version": 1, "auth_url": "https://gclone-auth.example.workers.dev", "refresh_token": "1//…", "email": "me@example.com",
  "consent_ms": 1794400000000, "refresh_expires_at_ms": null, "client": "device",
  "keys": [ { "epoch": 1, "key": "<base64url-nopad 32 bytes>" } ], "min_epoch": 1 }
```
There is no OAuth client ID or secret in it — those exist only in the Worker. `client` names which of the Worker's OAuth clients issued `refresh_token` and is sent with every `/refresh` (§2.3): `"device"` for every login made by 0.2.0 or later. **A file without the field is read as a login of the legacy client** (`AuthClient::Legacy`; every `secrets.json` written before 0.2.0) and is written back without it; any other value is a load error. `version` stays 1: an older gclone ignores the field. `keys` is `[]` between a successful sign-in and the end of the vault part of `login` (commands then fail with `ConfigError::Locked`, or `NotConfigured` while no `config.json` exists, §2.8); once filled it is the cached master key, so the passphrase is never asked again on this device. For `--vault-dir` vaults the login fields `auth_url`, `refresh_token`, `email` (and `consent_ms`) are **absent** — they are `Option`s in `config::Secrets`, never empty strings. `refresh_expires_at_ms` is `null` unless Google time-limited the grant (§2.4). **Loading never validates `auth_url`**: `FileSecretStore::load` checks permissions (§8.1), JSON and `version` only. The URL is validated where it is used — `Secrets::endpoints()` (§9.10), which is called only when `has_login()` is true — so a directory vault's secrets load without any URL.
`token.json`: `{ "access_token": "…", "expires_at_ms": …, "refreshed_at_ms": … }`.

### 8.3 Locking
`<state>/lock` with `std::fs::File::lock()` (exclusive, kernel-released on process death). Mutating commands (`login` once the vault id is known, `logout`, `passwd`, `copy`, `sync`, `mkdir`, `rm`, `mv`, `restore`, `gc`, `repair`) block-wait up to 5 s then fail with "another gclone is running on this vault" (the CLI adds that nothing was changed, to run the command again when the other one is done, and how to find it, §17.14); read-only commands `try_lock` and fall back to an unrefreshed replica.

A process **without** the lock writes nothing to the state when it opens it (§17.11): `open_ctx` uses `Db::open_shared` (no file creation, no schema creation or upgrade; `StateError::Locked` if the database has no schema yet — the lock holder is creating it, and two processes that both saw an empty database would both try) and `Vault::open_unlocked` (plain reads of `vault_id`, `device_id` and the pending high-water mark; no device-name write, no machine-fingerprint check, no rotation, no index-cache directory). SQLite's WAL lets such a reader proceed while the lock holder is inside a write transaction of any length (`rebuild_from` loads a whole snapshot in one), whereas the `BEGIN IMMEDIATE` that `Vault::open` uses waits `busy_timeout` (5 s) and then fails with "database is locked" — which is what a read-only command did before, instead of printing "note: index not refreshed (another gclone is running)". The lock holder's `Vault::open` writes `device_name` only when it changed. Not covered: what a lock-less command writes later (the download ledger of `cat` / `check --download`, the `trashed_ms` mark that `check` clears) is a single statement each and still waits for a writer.

`gclone web` (§7.4) is a long-lived process and holds the lock **only** while it starts and while a refresh runs: in between it is a lock-less reader in the sense above (`open_shared` / `open_unlocked` for its whole life), and each refresh opens a locked vault of its own on a fresh connection (`state::try_lock_existing` — which, unlike `try_lock`, creates neither the directory nor the lock file: a viewer must not bring back state that `logout --forget` removed — then `cli::context::open_replica`) and drops it. Its ledger writes go through a separate connection so that one that waits for another process's write transaction holds up no query.

### 8.4 SQLite schema (`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA user_version=1`)
```sql
CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
  -- keys: device_id(8 bytes), device_name, next_seq(u64 BE), lamport(u64 BE), machine_fp(32 bytes),
  --       base_snapshot_name, base_snapshot_lamport, base_snapshot_size, snap_checked, last_snapshot_name, last_snapshot_id, last_snapshot_size,
  --       last_snapshot_created_ms, data_folder_id, data_folder_n, data_folder_count, vault_format, vault_name, last_refresh_ms,
  --       vault_id (16 bytes; Vault::open refuses a state.db of another vault with StateError::Corrupt), base_snapshot_id, last_snapshot_md5   (§17.3; no schema change)
  --       base_snapshot_md5 (16 bytes; presence rule (b), §5.3), cleanup_done (32 bytes; §5.6), remembered (postcard: name, file id, created_ms? of
  --       segments known before a rebuild and not applied again yet; §5.3), resolve_all (present = the next resolution scans every head; §5.2.3)   (§17.11)
CREATE TABLE heads(path TEXT NOT NULL, st_l INTEGER NOT NULL, st_d BLOB NOT NULL, st_i INTEGER NOT NULL,
  kind INTEGER NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, exec INTEGER NOT NULL, hash BLOB NOT NULL,
  blob BLOB, off INTEGER, clen INTEGER, salt BLOB, chunk_log2 INTEGER, epoch INTEGER, suite INTEGER, flags INTEGER,   -- Loc or NULLs
  o_l INTEGER, o_d BLOB, o_i INTEGER,                       -- origin stamp or NULLs
  winner INTEGER NOT NULL,                                  -- 1 for the max-stamp head of the path
  PRIMARY KEY(path, st_l, st_d, st_i, hash)) WITHOUT ROWID;
CREATE INDEX heads_size ON heads(size) WHERE winner = 1;
CREATE INDEX heads_blob ON heads(blob);
CREATE INDEX heads_losers ON heads(path) WHERE winner = 0;                   -- the conflict losers: conflict count and resolution rule 1 in O(losers) (§5.2.3)
CREATE TABLE touched(path TEXT PRIMARY KEY) WITHOUT ROWID;                    -- paths whose heads changed since the last complete resolution (rule 2, §5.2.3)
CREATE TABLE removed( /* same columns as heads without winner */ …, removed_ms INTEGER NOT NULL,
  by_l INTEGER NOT NULL, by_d BLOB NOT NULL, by_i INTEGER NOT NULL,          -- stamp of the superseding op (smallest one, §5.2.2)
  PRIMARY KEY(path, st_l, st_d, st_i, hash)) WITHOUT ROWID;
CREATE INDEX removed_blob ON removed(blob);
CREATE TABLE blobs(id BLOB PRIMARY KEY, file_id TEXT NOT NULL, clen INTEGER NOT NULL, md5 BLOB NOT NULL,
  created_ms INTEGER NOT NULL, trashed_ms INTEGER) WITHOUT ROWID;            -- trashed_ms: set by gc on this device; such rows survive rebuilds (§5.3, §5.9)
CREATE TABLE devices(id BLOB PRIMARY KEY, name TEXT NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE applied(dev BLOB NOT NULL, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL, name TEXT NOT NULL,
  lamport INTEGER NOT NULL, created_ms INTEGER NOT NULL, size INTEGER NOT NULL, PRIMARY KEY(dev, seq, hash)) WITHOUT ROWID;
CREATE TABLE base_covers(dev BLOB PRIMARY KEY, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL) WITHOUT ROWID;   -- tips of the base snapshot
CREATE TABLE base_covered(dev BLOB NOT NULL, seq INTEGER NOT NULL, h4 BLOB NOT NULL, PRIMARY KEY(dev, seq, h4)) WITHOUT ROWID;   -- its exact coverage set
CREATE TABLE hw(dev BLOB PRIMARY KEY, seq INTEGER NOT NULL, hash BLOB NOT NULL, file_id TEXT NOT NULL) WITHOUT ROWID;   -- rollback marks (§5.3)
CREATE TABLE own(seq INTEGER PRIMARY KEY, hash BLOB NOT NULL, file_id TEXT NOT NULL);   -- segments sealed under the current device id
CREATE TABLE blocked(name TEXT PRIMARY KEY, first_seen_ms INTEGER NOT NULL) WITHOUT ROWID;   -- local clock
CREATE TABLE pending(id INTEGER PRIMARY KEY AUTOINCREMENT, draft BLOB NOT NULL, created_ms INTEGER NOT NULL, pid INTEGER NOT NULL);
  -- draft = postcard(OpDraft) (§9.3)
CREATE TABLE outbox(seq INTEGER PRIMARY KEY, name TEXT NOT NULL, file_id TEXT NOT NULL, bytes BLOB NOT NULL, effects BLOB NOT NULL);
CREATE TABLE pairs(id INTEGER PRIMARY KEY, local_root TEXT NOT NULL, remote_prefix TEXT NOT NULL,
  root_ino INTEGER NOT NULL, root_birth_ns INTEGER NOT NULL, fold_case INTEGER NOT NULL, UNIQUE(local_root, remote_prefix));
CREATE TABLE base(pair INTEGER NOT NULL, key TEXT NOT NULL, rel TEXT NOT NULL, kind INTEGER NOT NULL,
  size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, ctime_ns INTEGER NOT NULL, ino INTEGER NOT NULL, mode INTEGER NOT NULL,
  hash BLOB NOT NULL, st_l INTEGER NOT NULL, st_d BLOB NOT NULL, st_i INTEGER NOT NULL, observed_ns INTEGER NOT NULL,
  PRIMARY KEY(pair, key)) WITHOUT ROWID;
CREATE TABLE ledger(ts_ms INTEGER NOT NULL, dir INTEGER NOT NULL /* 0 = uploaded, 1 = downloaded */, bytes INTEGER NOT NULL);
```
Integer binding: rusqlite implements `ToSql`/`FromSql` for `u64` only behind its `fallible_uint` feature (enabled in §9.1); those conversions fail above `i64::MAX`. Therefore inode numbers (`base.ino`, `pairs.root_ino`) — which some network and FUSE file systems set above 2^63 — are stored **bit-cast** (`as i64` when binding, `as u64` when reading), never converted. All other `u64` values (sequence numbers, lamports, sizes, offsets, millisecond timestamps) are below 2^63 by construction and go through the fallible conversions; a failure there is `StateError::Corrupt`.

`heads_losers` and `touched` were added after the first builds (§17.11) and are part of schema version 1: `Db::open` creates them in a version-1 database that lacks them (`CREATE … IF NOT EXISTS` in one transaction that also sets `resolve_all`: nothing tracked the paths touched so far). `Db::open_shared` (§8.3) never does — only the lock holder changes the schema.

`state.db` is rebuildable from Drive except `pending`/`outbox` (unpublished work), `hw` (rollback marks), `own`, the `trashed_ms` marks and `base` (losing it only makes the next sync conservative: nothing is deleted or overwritten).

---

## 9. Rust architecture

One crate `gclone` (library + binary), edition 2024, MSRV 1.89, Unix only (macOS arm64/x86_64, Linux). The engine is generic over `B: Backend`; the binary uses `AnyBackend`.

### 9.1 `Cargo.toml`
```toml
[package]
name = "gclone"
version = "0.2.0"
edition = "2024"
rust-version = "1.89"

[lib]
name = "gclone"
path = "src/lib.rs"

[[bin]]
name = "gclone"
path = "src/main.rs"

[dependencies]
# --- compile-verified set from RESEARCH.md §4 ---
tokio = { version = "1.54", features = ["rt-multi-thread", "macros", "fs", "io-util", "io-std", "net", "sync", "time", "signal"] }   # io-std: tokio::io::stdout() for `cat`
tokio-util = { version = "0.7.20", features = ["io", "rt"] }
futures-util = { version = "0.3.34", default-features = false, features = ["std"] }
bytes = "1.12"
reqwest = { version = "0.13.5", default-features = false, features = ["rustls", "http2", "stream", "json", "query", "form"] }
hyper = { version = "1.12", default-features = false, features = ["http1", "server"] }      # `gclone web` (§7.4): the HTTP/1 server; in the tree through reqwest, only `server` is new code (§17.20)
hyper-util = { version = "0.1.21", default-features = false, features = ["tokio"] }         # TokioIo / TokioTimer for it
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.154"
clap = { version = "4.6", features = ["derive", "env", "wrap_help"] }
rusqlite = { version = "0.42", features = ["bundled", "fallible_uint"] }   # fallible_uint: ToSql/FromSql for u64 (absent without it in 0.42.0)
indicatif = "0.18.6"
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", default-features = false, features = ["fmt", "ansi", "env-filter", "std"] }
ignore = "0.4.34"
anyhow = "1.0.104"
thiserror = "2.0.21"
rpassword = "7.5"
open = "5.4"
filetime = "0.2.29"
blake3 = "1.8.7"
etcetera = "0.11"
url = "2.5.8"
base64 = "0.23"
sha2 = "0.11"
getrandom = "0.4"
zeroize = "1.9"
# --- compile-verified by WP0 (cargo/rustc 1.99.0, 2026-11-11): every entry resolves and compiles as written; resolved versions: §17.1 ---
chacha20poly1305 = { version = "0.11.0", features = ["zeroize"] }   # zeroize: the cipher object wipes its key copy on drop (§17.2)
hkdf = "0.13.0"
argon2 = { version = "0.6.0", default-features = false, features = ["alloc", "zeroize"] }
postcard = { version = "1.1.3", default-features = false, features = ["use-std"] }
md-5 = "0.11.0"                    # 2026 generation (digest 0.11, same trait vocabulary as sha2 0.11); resolves and compiles
caseless = "0.2"                   # Unicode full case folding for path::cmp_key (§5.1)
httpdate = "1"                     # `Date:` header parsing (1.0.3 is already in the dependency tree via hyper)
unicode-normalization = "0.1.24"
libc = "0.2"

[dev-dependencies]
wiremock = "0.6.5"
tempfile = "3.27"
tokio = { version = "1.54", features = ["test-util"] }

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"

[profile.dev.package."*"]
opt-level = 3        # dependencies are optimised in dev/test builds too: the keyfile KDF is Argon2id at 256 MiB (§2.6)
```
Notes: (1) the 2026 RustCrypto generation changed trait names — confine AEAD/HKDF/Argon2 calls to private helper functions in `crypto/stream.rs` / `crypto/kdf.rs` and read docs.rs for 0.11/0.13/0.6. (2) If a pinned feature name does not exist, WP0 fixes `Cargo.toml` and appends an "Errata" section to this spec; nobody else edits `Cargo.toml`. (3) No `proptest`: property tests use the seeded xorshift PRNG in `tests/support/prng.rs`. (4) Not used: `qrcode`, `keyring`, `aes-siv`, any OAuth crate (the device side of §2.4 is two JSON POSTs and a loopback listener), `zstd`, reqwest `gzip`. The v1.2 auth redesign adds no crate: `url` validates the auth URL, `open` launches the browser, `rpassword` reads the passphrase, `unicode-normalization` gives NFC, `sha2` the PKCE challenge. (5) No calendar/time-zone crate: RFC 3339 parsing and civil-date formatting are hand-written in `util.rs`, local time goes through `libc::localtime_r`, HTTP dates through `httpdate` (§9.3). (6) Two rusqlite/tokio features are load-bearing and verified against the local registry sources: `fallible_uint` (rusqlite 0.42.0 gates every `u64` conversion behind it) and `io-std` (tokio gates `stdout()` behind it).

### 9.2 Module tree and ownership (WP = work package, §12)
```
Cargo.toml, Cargo.lock (committed), .gitignore (root: `target/`), README.md (toolchain note, pointer to worker/README.md, manual probe checklist §2.9)   WP0
src/lib.rs            module declarations only                 WP0
src/main.rs           fn main → cli::run                       WP0
src/consts.rs         §6.1 constants + the device-side constants of §2.2   WP0
src/types.rs          shared plain types (§9.3)                WP0
src/error.rs          all error enums + exit_code (§9.3)       WP0
src/util.rs           hex, base64url, crockford, ct_eq, atomic write, clocks, date/time parsing + formatting   WP0
src/path.rs           validate, cmp_key, conflict names, Arg / parse_arg       WP0
src/ui.rs             Ui, Progress, Event, logging — fully implemented by WP0 (§9.3)   WP0
src/crypto/{mod,keys,stream,kdf}.rs                            WP1
src/format/{mod,index,blob,keyfile,descriptor}.rs              WP1
src/backend/{mod,mem,dir,flaky,any,conformance}.rs             WP2
src/backend/drive/{mod,api,upload,errors,pacer,probe}.rs       WP3
src/auth/{mod,login,token}.rs                                  WP3   (client of the auth Worker, §2.3–§2.4; no Google OAuth endpoint is called from Rust except revoke)
src/state/{mod,schema,tables}.rs                               WP4
src/index/{mod,apply,refresh,commit,resolve,repair,query}.rs   WP4
src/transfer/{mod,source,pack,upload,download,durable}.rs      WP5   (`durable`: the barriers of §5.7 steps 3a and 3b, crate-private, §17.15, §17.16)
src/sync/{mod,scan,plan,exec,remote_ops,gc,check}.rs           WP6
src/web/{mod,http,mime}.rs, src/web/assets/{index.html,app.css,app.js,icon.svg}   0.3.0 (§7.4, §17.20): the loopback server of `gclone web`, and its page (embedded with include_str!)
src/config.rs                                                  WP7
src/cli/{mod,context,login,logout,passwd,status,about,copy,ls,cat,web,mkdir,rm,mv,restore,check,gc,repair,probe}.rs   WP7
tests/support/{mod,prng}.rs        (mod.rs declares only `pub mod prng;`)      WP0
tests/vectors/stream_v1.json, tests/crypto_format.rs           WP1   (the fixed-salt KATs are unit tests in src/crypto/stream.rs)
tests/backend_conformance.rs                                   WP2
tests/support/fake_drive.rs, tests/drive_http.rs, tests/auth.rs    WP3   (the fake — Drive **and** auth-Worker routes — is pulled in with `#[path = "support/fake_drive.rs"] mod fake_drive;`; `tests/auth.rs` also reads WP8's `worker/test/contract.json`, read-only, §16.5)
tests/index_props.rs, tests/index_adversary.rs                 WP4
tests/transfer.rs                                              WP5
tests/cross_package.rs                                         integrator (wave 2, §17.3): Vault + transfer on every backend; no work package edits it
tests/sync_e2e.rs, tests/sync_faults.rs                        WP6
tests/cli_e2e.rs                                               WP7   (includes WP3's fake_drive.rs read-only, the same way)
tests/web.rs                                                   0.3.0 (§17.20): `gclone web` over real HTTP — the binary on a free loopback port, a raw TCP client; one Drive-mode test against FakeDrive
tests/live.rs                                                  WP7   (the opt-in live run of §13 item 10: every test is `#[ignore]` and returns at once unless GCLONE_LIVE=1)
worker/{package.json,package-lock.json,wrangler.jsonc,tsconfig.json,vitest.config.ts,.gitignore,.dev.vars.example,README.md,setup.sh}   WP8   (§16)
worker/scripts/{check-config,custom-domain}.mjs                WP8   (plus their `*.selftest.mjs` and `setup.selftest.mjs`, §16.1)
worker/src/{index,seal,google,pages}.ts                        WP8
worker/test/{seal,login,token,refresh,contract}.test.ts, worker/test/{helpers.ts,tsconfig.json,contract.json}   WP8
```
The Rust crate and `worker/` share no code and no build step. Their contract is §2.3 (HTTP API) and the constants of §2.2 — and, so that the two implementations of that text cannot drift apart unnoticed, **one shared data file**: `worker/test/contract.json` (§16.5), written by WP8 and checked by both the Worker's tests (against the real `handle()`) and WP3's `tests/auth.rs` (against `FakeDrive`'s auth routes and the Rust client).
`mod.rs` files re-export the public items listed below so that the paths used in this spec (`crate::crypto::Sealer`, `crate::index::Vault`, …) resolve.

General API rules: public async trait methods are written `fn f(&self, …) -> impl Future<Output = …> + Send` (shown below as `async fn` for brevity — implementers MUST keep futures `Send`); no `unwrap`/`expect` on I/O, crypto, SQL or network results outside tests; raw key material (`MasterKey`, `PurposeKey`, stream keys, exported key bytes, the passphrase) lives in `Zeroizing`; secrets carried as JSON strings (tokens, base64 keys in `Secrets`/`KeyfilePayload`/`LoginGrant`/`AccessGrant`) are plain `String`s inside types that do **not** implement `Debug`; no module other than `crypto` calls an AEAD, and no module other than `state`/`index` executes SQL. Blocking work (file hashing, sealing, SQLite) runs in `spawn_blocking` or scoped threads with **owned** inputs — never `block_in_place` (it panics on the current-thread runtime that `#[tokio::test]` uses).

### 9.3 WP0 — `types`, `error`, `util`, `path`, `consts`, `ui`
```rust
// ---------- src/types.rs ----------  (all: Clone, Debug, PartialEq, Eq; serde Serialize/Deserialize where noted S)
// DeviceId and BlobId print as hex: Debug = `DeviceId(a1b2…)`, and both implement Display (the plain hex).
#[derive(Copy, Hash, PartialOrd, Ord)] pub struct DeviceId(pub [u8; 8]);            // S
#[derive(Copy, Hash, PartialOrd, Ord)] pub struct BlobId(pub [u8; 16]);             // S
#[derive(Copy, Hash, PartialOrd, Ord)] pub struct Stamp { pub lamport: u64, pub device: DeviceId, pub idx: u32 }   // S
pub struct Loc { pub blob: BlobId, pub off: u64, pub clen: u64, pub salt: [u8; 16], pub chunk_log2: u8, pub epoch: u32,
                 pub suite: u8, pub flags: u8 }                                      // S  (field order frozen, §4.4)
#[derive(Copy)] pub enum EntryKind { File, Dir }                                     // S
pub struct Entry { pub kind: EntryKind, pub size: u64, pub mtime_ns: i64, pub exec: bool, pub hash: [u8; 32], pub loc: Option<Loc> }  // S
pub struct BlobRec { pub id: BlobId, pub file_id: String, pub clen: u64, pub md5: [u8; 16], pub created_ms: u64 }   // S
pub struct SegRef { pub device: DeviceId, pub seq: u64, pub hash: [u8; 32], pub file_id: String }                  // S
#[derive(Copy, Hash, PartialOrd, Ord)] pub struct CoveredSeg { pub device: DeviceId, pub seq: u64, pub h4: [u8; 4] }   // S
#[derive(Copy)] pub struct StatSig { pub size: u64, pub mtime_ns: i64, pub ctime_ns: i64, pub ino: u64, pub mode: u32 }   // S
pub struct Head { pub path: String, pub stamp: Stamp, pub entry: Entry, pub origin: Option<Stamp>, pub winner: bool }
pub struct RemovedVersion { pub path: String, pub stamp: Stamp, pub entry: Entry, pub removed_ms: u64, pub by: Stamp }
pub struct BaseRow { pub key: String, pub rel: String, pub kind: EntryKind, pub sig: StatSig, pub hash: [u8; 32],
                     pub remote_stamp: Stamp, pub observed_ns: i64 }
pub enum BaseEffectKind { Set { sig: StatSig, hash: [u8; 32], observed_ns: i64, kind: EntryKind }, Forget }          // S
pub struct BaseEffect { pub pair: i64, pub key: String, pub rel: String, pub kind: BaseEffectKind }                 // S
pub enum OpDraft {                                                                                                   // S
    VaultInit { format: u16, name: String },
    Device { id: DeviceId, name: String },
    Blob(BlobRec),
    Put { path: String, entry: Entry, base: Option<Stamp>, origin: Option<Stamp>, effect: Option<BaseEffect> },
    Del { path: String, base: Stamp, effect: Option<BaseEffect> },
}
impl DeviceId { pub fn random() -> Self; pub fn hex(&self) -> String; pub fn short(&self) -> String /* 8 hex */; pub fn from_hex(s: &str) -> Option<Self>; }
// from_hex (both ids): exactly 16 / 32 LOWERCASE hex characters — one accepted spelling per id (object names)
impl BlobId   { pub fn random() -> Self; pub fn hex(&self) -> String; pub fn from_hex(s: &str) -> Option<Self>; }
impl Entry    { pub fn dir() -> Self; pub fn empty_file(mtime_ns: i64, exec: bool) -> Self;
                pub fn same_content(&self, o: &Entry) -> bool; }   // equal kind, size, hash — loc, mtime, exec ignored
impl SegRef   { pub fn covered(&self) -> CoveredSeg; }             // (device, seq, hash[0..4])
impl StatSig  { pub fn from_metadata(md: &std::fs::Metadata) -> Self; pub fn is_exec(&self) -> bool; }   // is_exec: the owner-execute bit (mode & 0o100)
impl BaseRow  { pub fn trusted(&self) -> bool; }                 // racy-timestamp rule §5.4

// ---------- src/error.rs ----------  (all: Debug, thiserror::Error)
// Wrapping variants (`#[from]`) are `#[error(transparent)]`: Display shows the innermost message once, and `source()` therefore
// SKIPS the wrapped enum. Never walk `source()` by hand to look inside an error: use `error::find::<T>(&e)` or `exit_code`.
// (Exception: `StateError::Sqlite` keeps a prefix.) QuotaKind and GuardKind implement Display (used in the messages).
pub enum CryptoError { BadMagic, Unsupported(&'static str), WrongKey, Corrupt, Truncated, TrailingData,
                       UnknownEpoch(u32), EpochTooOld { epoch: u32, min: u32 }, Misuse(&'static str), Kdf(String) }
#[derive(Clone, Copy, PartialEq, Eq)] pub enum PathError { Empty, Absolute /* leading '/' */, EmptyComponent /* also a trailing '/' */, DotComponent, Nul, ComponentTooLong, TooLong }
pub enum FormatError { KeyfileDamaged, KeyfileVersion(u32), KdfParams, WeakPassphrase, BadName(String), Codec(u8),
                       BodyVersion(u8) /* the tag of an index object's body enum, §4.6 rule 3 */, Decode(String),
                       IdentityMismatch(String), BadEntry(String) /* §4.6 rules 1 (size), 6–7 */, Path(#[from] PathError), Crypto(#[from] CryptoError) }
impl FormatError { pub fn newer_format(&self) -> Option<String>; }   // Some(what) for the version refusals of §4.6 "Unreadable is not corrupt":
                                                                      // Crypto(Unsupported | UnknownEpoch), Codec, BodyVersion — None for damage
pub enum AuthError { Expired /* /refresh answered invalid_grant: "run gclone login" */, WorkerMisconfigured(String), NotAllowed(String),
                     Denied(String), ScopeMissing, Timeout /* the device code ran out */, LoginFailed(String), BadAuthUrl(String), Network(String),
                     Io(#[from] std::io::Error) }                                    // mapping from Worker answers: §2.4
#[derive(Copy, Clone, PartialEq, Eq, Debug)] pub enum QuotaKind { StorageFull, DailyUpload, DailyDownload, ProjectApiQuota }
pub enum BackendError { NotFound, AlreadyExists, RateLimited, Transient(String), SessionLost, QuotaExceeded(QuotaKind), AppNotAuthorized,
                        Auth(#[from] AuthError), Fatal { status: u16, reason: String, message: String }, Io(#[from] std::io::Error) }
impl BackendError { pub fn is_temporary(&self) -> bool; }        // QuotaExceeded(_) | RateLimited | Transient(_)
pub enum StateError { Sqlite(#[from] rusqlite::Error), Locked, Corrupt(String), Io(#[from] std::io::Error) }
pub enum IndexError { Gap { names: Vec<String> }, Rollback { device: DeviceId, seq: u64 }, VaultTrashed, VaultMissing, VaultNotVisible,
                      NeedsNewerGclone, UnsupportedObject { name: String, what: String } /* an index object in a newer format, §4.6 */,
                      OutboxStuck(String) /* a sealed segment could not be published yet; the text names the cause */,
                      Format(#[from] FormatError), Crypto(#[from] CryptoError),
                      Backend(#[from] BackendError), State(#[from] StateError), Io(#[from] std::io::Error) }
#[derive(Clone, PartialEq, Eq, Debug)] pub enum GuardKind { EmptySource, RevertedTree { suspicious: usize }, DeleteLimit { deletes: u64, total: u64 }, MaxDelete { deletes: u64, limit: u64 } /* an explicit --max-delete: never confirmable, §5.5.2 */, RootChanged }
pub enum TransferError { SourceChanged(String), SourceUnreadable { path: String, err: std::io::Error }, BlobMissing(String),
                         Verify(String), UnsafeTarget(String), TargetCollision(String) /* §5.7 step 3: folded spelling in the way */,
                         Cancelled, Backend(#[from] BackendError),
                         Crypto(#[from] CryptoError), Format(#[from] FormatError),
                         Index(#[from] IndexError), State(#[from] StateError), Io(#[from] std::io::Error) }
pub enum SyncError { Guard(GuardKind), Partial { failed: usize, skipped: usize }, Interrupted, Usage(String),
                     Index(#[from] IndexError), Transfer(#[from] TransferError), Backend(#[from] BackendError),
                     State(#[from] StateError), Io(#[from] std::io::Error) }
pub enum ConfigError { NotConfigured /* no config.json */,
                       NotLoggedIn /* config.json but no secrets file (either backend), or a Drive vault without a refresh token */,
                       Locked /* secrets exist with keys == [] */,
                       InsecurePermissions(String) /* secrets file or its directory: foreign owner or group/other bits (§8.1); the path */,
                       WrongPassphrase, Version(u32), Json(String), Auth(#[from] AuthError) /* a stored auth_url that no longer validates */,
                       Crypto(#[from] CryptoError), Io(#[from] std::io::Error) }
/// Walks the whole chain — every link of the anyhow chain, typed values attached with `.context(err)`, and everything nested
/// in a wrapping variant; mapping and precedence of §7.2:
/// 3 ← CryptoError, FormatError::{KeyfileDamaged, KeyfileVersion},
///     IndexError::{Gap, Rollback, VaultTrashed, VaultMissing, NeedsNewerGclone, UnsupportedObject}, TransferError::Verify
///     (a wrong passphrase never reaches this function as CryptoError::WrongKey: the login flow turns the keyfile's WrongKey into
///      ConfigError::WrongPassphrase first, §2.6)
/// 4 ← AuthError, ConfigError::{NotConfigured, NotLoggedIn, Locked, InsecurePermissions, WrongPassphrase}, IndexError::VaultNotVisible,
///     BackendError::AppNotAuthorized
/// 75 ← QuotaExceeded(_), RateLimited, IndexError::OutboxStuck
/// 5 ← SyncError::Guard      6 ← SyncError::Partial      130 ← Interrupted / Cancelled      2 ← SyncError::Usage      1 ← everything else
pub fn exit_code(e: &anyhow::Error) -> i32;
/// The first error of type T anywhere inside `e` (anyhow chain, context values, wrapping variants): e.g. the AuthError inside
/// SyncError::Index(IndexError::Backend(BackendError::Auth(..))). The CLI uses it to pick the §2.8 text.
pub fn find<T: std::error::Error + 'static>(e: &anyhow::Error) -> Option<&T>;

// ---------- src/util.rs ----------
pub fn hex(b: &[u8]) -> String;                         pub fn unhex(s: &str) -> Option<Vec<u8>>;         // lowercase; unhex is STRICT: upper-case digits → None
pub fn b64url(b: &[u8]) -> String;                      pub fn unb64url(s: &str) -> Option<Vec<u8>>;      // no padding
pub fn crockford_encode(b: &[u8]) -> String;            // 5 bits per char, MSB first; len(b)*8 must be a multiple of 5 (head fingerprint, §2.6)
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;               // constant time for equal lengths
pub fn random<const N: usize>() -> [u8; N];             // getrandom::fill; aborts the process on failure
pub fn now_ms() -> u64;                                 pub fn now_ns() -> i64;
pub fn write_atomic(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()>;   // temp (O_CREAT|O_EXCL|O_NOFOLLOW, created with
                                                                                               // `mode`) + fsync + rename + fsync(dir)
pub fn remove_atomic_leftovers(path: &std::path::Path) -> std::io::Result<usize>;              // removes `.<name>.tmp-<16 hex>` beside `path` (what a
                                                                                               // killed write_atomic left); count; missing dir = Ok(0)
pub fn create_dir_private(path: &std::path::Path) -> std::io::Result<()>;                      // mkdir -p; DirBuilder::mode(0o700): 0700 AT creation
/// §8.1 strict loading (used by config::FileSecretStore and auth::TokenProvider): true iff `md` is owned by the effective uid and has no group/other permission bits.
pub fn is_private(md: &std::fs::Metadata) -> bool;
pub fn human_size(n: u64) -> String;                    // binary units, at most one decimal: "0 B", "310 MiB", "4.2 MiB", "2 TiB"
pub fn human_age(ms_ago: u64) -> String;                // one unit, WITHOUT "ago": "45 s", "12 min", "2 h", "3 d"
pub fn group_thousands(n: u64) -> String;               // "38,201"
pub fn hostname() -> String;                            // the SHORT host name (up to the first '.'); "unknown" if unreadable
pub fn host_id() -> Vec<u8>;                            // gethostuuid(2) on macOS, /etc/machine-id on Linux, empty if unavailable (§5.3)
// date/time — no calendar crate: RFC 3339 and civil-date arithmetic are hand-written here (~40 lines), HTTP dates use `httpdate`,
// local time uses libc::localtime_r
pub fn parse_rfc3339_ms(s: &str) -> Option<u64>;        // Drive createdTime "2026-11-11T09:14:03.123Z" (fraction optional, Z or ±hh:mm)
pub fn parse_http_date_ms(s: &str) -> Option<u64>;      // `Date:` response header (IMF-fixdate)
pub fn format_utc_compact(ms: u64) -> String;           // "20261111T091403Z"  (local conflict names)
pub fn format_local_minute(ms: u64) -> String;          // "2026-11-11 10:14" in the local time zone (ls -l, restore --list)

// ---------- src/path.rs ----------
pub fn validate(path: &str) -> Result<(), PathError>;                        // §5.1
pub fn cmp_key(path: &str, fold_case: bool) -> String;                       // NFC(path), or NFC(casefold(NFD(path))) with full case folding
pub fn conflict_name(path: &str, loser: &Stamp) -> String;                   // §5.1, deterministic; a valid path for every valid `path`
pub fn local_conflict_name(file_name: &str, utc_now_ms: u64, attempt: u32) -> String;   // attempt 0 or 1: the plain name; n ≥ 2: "-n" after the
                                                                             // timestamp (callers count 1, 2, 3, … until the name is free)
pub fn join(prefix: &str, rel: &str) -> String;                              // "" prefix = vault root
pub fn strip_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str>;     // component-aware
pub fn parent(path: &str) -> Option<&str>;                                   pub fn file_name(path: &str) -> &str;
pub fn ancestors(path: &str) -> impl Iterator<Item = &str>;                  // proper ancestors, nearest first
pub fn is_ignored_local_name(name: &str) -> bool;                            // .gclone-partial-*, .gclone-probe-*
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg { Local(std::path::PathBuf), Remote(String) }                   // ":" prefix → Remote (validated; ":" alone → ""; trailing
                                                                             // slashes are dropped: ":Photos/" = ":Photos"; ":/" is an error)
pub fn parse_arg(s: &str) -> Result<Arg, PathError>;

// ---------- src/ui.rs ----------   (WP0 implements this file completely — ~150 lines over indicatif — so WP5/WP6 tests can run before WP7)
#[derive(Clone, Debug, Default)] pub struct UiOpts { pub json: bool, pub quiet: bool, pub verbose: u8 }
#[derive(Clone, Debug, serde::Serialize)] #[serde(tag = "event", rename_all = "lowercase")]
pub enum Event { Plan { action: String, path: String, size: Option<u64>, note: Option<String> },   // None fields are omitted from the JSON
                 Done { action: String, path: String, bytes: u64 },
                 Skip { path: String, reason: String },
                 Warn { message: String },
                 Summary { uploaded: u64, downloaded: u64, reused: u64, deleted: u64, skipped: u64, failed: u64, conflicts: u64,
                           bytes_up: u64, bytes_down: u64, exit: i32 } }
pub struct Ui { /* indicatif MultiProgress on stderr, json writer on stdout */ }
#[derive(Clone)] pub struct Progress { /* cloneable handle; Send + Sync + 'static */ }
impl Ui {
    pub fn new(opts: UiOpts) -> Self;          pub fn silent() -> Self;             // silent(): no output, confirm() = false — for tests
    /// "stdout" and "stderr" go into the given sinks; never a TTY, no progress bars — for tests that assert on output.
    #[doc(hidden)] pub fn with_writers(opts: UiOpts, out: Box<dyn std::io::Write + Send>, err: Box<dyn std::io::Write + Send>) -> Self;
    pub fn quiet(&self) -> bool;               pub fn verbose(&self) -> u8;
    pub fn is_tty(&self) -> bool;              pub fn json(&self) -> bool;
    pub fn out(&self, line: &str);             // human result line → stdout (suppressed in --json)
    pub fn info(&self, line: &str);            // stderr unless -q
    pub fn warn(&self, line: &str);            pub fn error(&self, line: &str);     // "warning: …" / "error: …" on stderr, also with -q;
                                                                                // under --json warn() emits a `warn` event on stdout instead
    pub fn event(&self, e: &Event);            // --json: NDJSON on stdout; otherwise rendered like the examples of §7.3:
                                               // Plan / Skip → aligned lines on stdout (not with -q); Done → stderr with -v only;
                                               // Warn → warn(); Summary → NOTHING (the command prints its own ▸ line with out())
    pub fn confirm(&self, question: &str) -> bool;                                       // false when not a TTY
    pub fn choose(&self, question: &str, options: &[&str]) -> Option<usize>;             // None when not a TTY (root-identity guard)
    pub fn prompt_line(&self, question: &str) -> std::io::Result<String>;                // question → stderr; one line from stdin (TTY or pipe);
                                                                                         // EOF → UnexpectedEof. All four prompt methods BLOCK:
                                                                                         // call them from spawn_blocking
    pub fn prompt_secret(&self, question: &str) -> std::io::Result<String>;              // rpassword, /dev/tty
    pub fn transfer_progress(&self, label: &str, total_bytes: u64, total_files: u64) -> Progress;
}
impl Progress { pub fn hidden() -> Self;       // draws nothing — for tests and library callers
                pub fn add_bytes(&self, n: u64); pub fn file_done(&self); pub fn blob_done(&self); pub fn finish(&self);
                pub fn bytes(&self) -> u64; pub fn files(&self) -> u64; pub fn blobs(&self) -> u64; }   // totals over all clones (also when hidden)
pub fn init_logging(verbose: u8);              // tracing-subscriber to stderr; honours GCLONE_LOG (an EnvFilter directive string);
                                               // default warn, -v gclone=info, -vv gclone=debug, -vvv trace; safe to call twice
```

### 9.4 WP1 — `crypto`, `format`
```rust
// ---------- src/crypto/keys.rs ----------
#[derive(Clone)] pub struct MasterKey(/* Zeroizing<[u8; 32]> */);            // Clone: keys are moved into spawn_blocking closures; no Debug
impl MasterKey { pub fn generate() -> Self; pub fn from_bytes(b: [u8; 32]) -> Self; pub fn expose(&self) -> &[u8; 32]; }
#[derive(Copy, Clone, PartialEq, Eq, Debug)] pub enum Purpose { Data, Index }
#[derive(Clone)] pub struct PurposeKey(/* Zeroizing<[u8; 32]> */);
impl PurposeKey { pub fn from_raw(b: [u8; 32]) -> Self; }                    // only for K_pass (keyfile, §2.6)
#[derive(Clone)] pub struct Keyring { /* vault_id, BTreeMap<u32, MasterKey>, min_epoch */ }
impl Keyring {
    pub fn new(vault_id: [u8; 16], keys: Vec<(u32, MasterKey)>, min_epoch: u32) -> Result<Self, CryptoError>;   // ≥ 1 key, all ≥ min_epoch
    pub fn vault_id(&self) -> [u8; 16];
    pub fn current_epoch(&self) -> u32;          pub fn min_epoch(&self) -> u32;
    pub fn purpose(&self, epoch: u32, p: Purpose) -> Result<PurposeKey, CryptoError>;      // UnknownEpoch / EpochTooOld
    pub fn export(&self) -> Vec<(u32, zeroize::Zeroizing<[u8; 32]>)>;
    /// Whole container under the current epoch. `ty` must have a purpose key: Bundle → Err(Misuse).
    pub fn seal(&self, ty: StreamType, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn open(&self, ty: StreamType, container: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;   // precedence of §4.2
    /// Sealer for one Data stream under the current epoch (suite 1, flags 0, CHUNK_LOG2, fresh salt).
    pub fn data_sealer(&self) -> Sealer;
    /// Opener for a Data stream described by an index entry. Order: loc.suite != 1 or loc.flags != 0 → Unsupported (no key is
    /// derived); chunk_log2 outside 12..=24 → Unsupported; then UnknownEpoch / EpochTooOld; then the stream key from the Loc.
    pub fn data_opener(&self, loc: &Loc) -> Result<Opener, CryptoError>;
}

// ---------- src/crypto/stream.rs ----------
pub const HEADER_LEN: usize = 60;   pub const TAG_LEN: usize = 16;   pub const MAGIC: [u8; 4] = *b"GCS1";   pub const SUITE_V1: u8 = 1;
#[repr(u8)] #[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StreamType { Data = 1, Segment = 2, Snapshot = 3, Bundle = 5 }     // 4 is reserved (blob manifest) and rejected as Unsupported
impl StreamType { pub fn from_u8(b: u8) -> Option<Self>; pub fn purpose(self) -> Option<Purpose>; /* Bundle → None */ }
pub struct Header { pub suite: u8, pub chunk_log2: u8, pub ty: StreamType, pub flags: u8, pub epoch: u32,
                    pub salt: [u8; 16], pub commit: [u8; 32] }
impl Header { pub fn encode(&self) -> [u8; HEADER_LEN];
              /// Steps 1–2 of the §4.2 precedence: Truncated, BadMagic, then Unsupported for suite, chunk_log2 range, type, flags (in that order).
              pub fn decode(b: &[u8]) -> Result<Header, CryptoError>; }
pub fn chunk_count(plain_len: u64, chunk_log2: u8) -> u64;
pub fn ciphertext_len(plain_len: u64, chunk_log2: u8) -> u64;
pub fn plaintext_len(cipher_len: u64, chunk_log2: u8) -> Option<u64>;        // exact definition in §4.2
pub struct ChunkSpan { pub first: u64, pub last: u64 /* inclusive */, pub cipher: std::ops::Range<u64> /* relative to container start */,
                       pub skip: usize /* plaintext bytes to drop from chunk `first` */ }
pub fn chunk_range(plain: std::ops::Range<u64>, plain_len: u64, chunk_log2: u8) -> Option<ChunkSpan>;   // None if empty/out of bounds
pub fn chunk_cipher_len(idx: u64, plain_len: u64, chunk_log2: u8) -> usize;                             // ct+tag length of chunk idx
pub struct Sealer { /* stream key, header, next index, finished */ }
impl Sealer {
    pub fn new(key: &PurposeKey, ty: StreamType, epoch: u32, chunk_log2: u8) -> Sealer;     // fresh random salt; NO salt/nonce parameter
    pub fn header(&self) -> [u8; HEADER_LEN];        pub fn salt(&self) -> [u8; 16];
    /// Appends ct‖tag to `out`. Errors (Misuse): called after the final chunk; pt.len() > C; pt.len() < C and !last;
    /// empty pt unless it is the first and final chunk.
    pub fn seal_chunk(&mut self, pt: &[u8], last: bool, out: &mut Vec<u8>) -> Result<(), CryptoError>;
    pub fn is_finished(&self) -> bool;
}
pub struct Opener { /* stream key, header bytes, chunk_log2 */ }
impl Opener {
    /// For self-describing streams (index objects, keyfile): Header::decode, then type != expect → WrongKey, then commit → WrongKey.
    pub fn from_header(key: &PurposeKey, header: &[u8], expect: StreamType) -> Result<Opener, CryptoError>;
    /// For Data streams: everything comes from the index entry; the stored header is never trusted. Callers normally use
    /// Keyring::data_opener, which performs the suite/flags/epoch checks first.
    pub fn for_data(key: &PurposeKey, loc: &Loc) -> Result<Opener, CryptoError>;
    pub fn expected_header(&self) -> [u8; HEADER_LEN];
    pub fn chunk_log2(&self) -> u8;
    /// `ct` = exactly one chunk's ct‖tag; appends plaintext to `out` only after the tag verified. Corrupt on failure.
    pub fn open_chunk(&self, idx: u64, last: bool, ct: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError>;
}
pub fn seal_all(key: &PurposeKey, ty: StreamType, epoch: u32, chunk_log2: u8, pt: &[u8]) -> Vec<u8>;
pub fn open_all(key: &PurposeKey, ty: StreamType, container: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;  // Truncated/TrailingData/Corrupt/WrongKey
// #[cfg(test)] only: Sealer::with_salt_for_tests(key, ty, epoch, chunk_log2, salt). Reachable only from unit tests in this file —
// that is where the fixed-salt KATs of §4.7 live.

// ---------- src/crypto/kdf.rs ----------   (passphrase → K_pass for the keyfile, §2.6; nothing else uses Argon2)
pub const PREAMBLE_LEN: usize = 36;
#[derive(Copy, Clone, PartialEq, Eq, Debug)] pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32 }
impl Default for KdfParams { /* 262144, 3, 1 — what production code writes */ }
impl KdfParams { pub fn validate(&self) -> Result<(), FormatError>; }        // accepted bounds of §2.6: m_kib 8192..=524288, t 1..=4, p == 1
pub struct KdfPreamble { pub params: KdfParams, pub salt: [u8; 16] }
impl KdfPreamble { pub fn generate(params: KdfParams) -> Self;               // fresh random salt
                   pub fn encode(&self) -> [u8; PREAMBLE_LEN]; pub fn decode(b: &[u8]) -> Result<Self, FormatError>; }   // decode validates the bounds
pub struct Passphrase(/* Zeroizing<String>: the normalised text; no Debug, no Display */);
impl Passphrase {
    pub fn from_input(input: &str) -> Self;                                   // normalisation of §2.6; used when entering AND when setting
    pub fn set_checked(input: &str) -> Result<Self, FormatError>;             // from_input + PASSPHRASE_MIN_CHARS → WeakPassphrase
    pub fn generate() -> Self;                                                // 20 Crockford symbols, 100 bits
    pub fn display(&self) -> zeroize::Zeroizing<String>;                      // the text to show once after generate()
    pub fn char_count(&self) -> usize;                                        // Unicode scalar values (for the < 20 warning)
}
/// K_pass (§2.6). Blocking (≈ 1 s, 256 MiB with the default parameters): call it from spawn_blocking.
pub fn derive_pass_key(pass: &Passphrase, pre: &KdfPreamble) -> Result<PurposeKey, CryptoError>;

// ---------- src/format/index.rs ----------   (types of §4.6 with serde derives: SegmentV1, SnapshotV1, Op, HeadRec, RemovedRec, DeviceRec)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexName { Segment { device: DeviceId, seq: u64, h8: [u8; 4] }, Snapshot { lamport: u64, device: DeviceId, h8: [u8; 4] } }
pub fn parse_index_name(name: &str) -> Option<IndexName>;
pub fn segment_name(device: DeviceId, seq: u64, hash: &[u8; 32]) -> String;
pub fn snapshot_name(lamport: u64, device: DeviceId, hash: &[u8; 32]) -> String;
pub struct SealedObject { pub name: String, pub hash: [u8; 32], pub bytes: Vec<u8> }
pub fn seal_segment(keys: &Keyring, seg: &SegmentV1) -> Result<SealedObject, FormatError>;     // validates paths and entries first (§4.6 rules 5–6); > INDEX_OBJECT_MAX → BadEntry (seal_snapshot too)
pub fn seal_snapshot(keys: &Keyring, snap: &SnapshotV1) -> Result<SealedObject, FormatError>;  // rules 5–7
pub fn open_segment(keys: &Keyring, name: &str, bytes: &[u8]) -> Result<(SegmentV1, [u8; 32]), FormatError>;   // acceptance rules §4.6; FormatError::newer_format tells "newer" from "damaged"
pub fn open_snapshot(keys: &Keyring, name: &str, bytes: &[u8]) -> Result<(SnapshotV1, [u8; 32]), FormatError>;
pub fn op_from_draft(d: &OpDraft) -> Op;                                                         // drops the BaseEffect

// ---------- src/format/blob.rs ----------   (v1 blobs have no trailer, §4.5)
pub const RESERVED_FOOTER_MAGIC: [u8; 8] = *b"GCBLOB01";        // reserved for the future manifest trailer; unused in v1
pub fn blob_name(id: &BlobId) -> String;                        pub fn parse_blob_name(name: &str) -> Option<BlobId>;
pub fn data_folder_name(device: DeviceId, n: u32) -> String;
pub fn blob_len(member_plain_sizes: &[u64]) -> u64;             // Σ ciphertext_len(size, CHUNK_LOG2)

// ---------- src/format/keyfile.rs ----------   (§2.6; KeyfileKey and KeyfilePayload hold secrets: NO Debug derive)
pub const KEYFILE_PREFIX: &str = "gclone-key-";
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)] pub struct KeyfileKey { pub epoch: u32, pub key: String }
// `gen` is a reserved keyword in edition 2024: the Rust identifier is `generation` everywhere; only the JSON key and the object name
// keep the wire spelling "gen".
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyfilePayload { pub v: u32, pub vault_id: String, #[serde(rename = "gen")] pub generation: u32, pub keys: Vec<KeyfileKey>,
                            pub min_epoch: u32, pub created_ms: u64, pub by: String }
impl KeyfilePayload { pub fn from_keyring(keys: &Keyring, generation: u32, by: &str, now_ms: u64) -> Self;
                      pub fn keyring(&self) -> Result<Keyring, FormatError>;       // uses self.vault_id
                      pub fn vault_id_bytes(&self) -> Result<[u8; 16], FormatError>; }
pub fn keyfile_name(generation: u32, hash: &[u8; 32]) -> String;                    // "gclone-key-<generation:08x>-<h8>"
pub fn parse_keyfile_name(name: &str) -> Option<(u32 /* generation */, [u8; 4] /* h8 */)>;
/// KdfPreamble::generate(params) → derive_pass_key → Stream(type Bundle, epoch 0) over the JSON payload. Blocking (Argon2id).
/// `params` is KdfParams::default() everywhere outside tests.
pub fn seal_keyfile(p: &KeyfilePayload, pass: &Passphrase, params: KdfParams) -> Result<SealedObject, FormatError>;
/// Open order and errors of §2.6 (size, name, h8, KDF bounds — before any Argon2 allocation —, Argon2id, commit → Crypto(WrongKey),
/// chunks, JSON, generation/keys). Blocking.
pub fn open_keyfile(name: &str, bytes: &[u8], pass: &Passphrase) -> Result<KeyfilePayload, FormatError>;

// ---------- src/format/descriptor.rs ----------
pub const DESCRIPTOR_NAME: &str = "gclone-vault.json";   pub const README_NAME: &str = "README.txt";   pub const README_TEXT: &str = "…";
pub const INDEX_FOLDER: &str = "index";   pub const DATA_FOLDER: &str = "data";   pub const SUPPORTED_FORMAT: u16 = 1;
#[derive(Serialize, Deserialize, Clone, Debug)] pub struct VaultDescriptor { pub gclone_vault: u32, pub min_reader: u32, pub vault_id: String, pub created_ms: u64 }
impl VaultDescriptor { pub fn new(vault_id: [u8; 16]) -> Self; pub fn to_bytes(&self) -> Vec<u8>; pub fn parse(b: &[u8]) -> Result<Self, FormatError>; }
```

### 9.5 WP2 — `backend` (trait + fakes + conformance suite)
```rust
// ---------- src/backend/mod.rs ----------
#[derive(Clone, Debug, PartialEq, Eq, Hash)] pub struct Handle(pub String);          // opaque backend object id (Drive file ID)
impl Handle { pub fn top() -> Handle;          // reserved handle of the backend's top level: Handle(""). Drive: My Drive root; Dir: the directory itself
              pub fn is_top(&self) -> bool; }
#[derive(Clone, Debug)] pub struct ObjMeta { pub handle: Handle, pub name: String, pub parent: Handle /* Handle::top() for top-level objects */,
                                             pub size: u64 /* 0 for folders */, pub md5: Option<[u8; 16]> /* None for folders */,
                                             pub created_ms: u64, pub is_folder: bool, pub trashed: bool }
pub enum PutBody {
    Small(bytes::Bytes),                                                              // len ≤ MULTIPART_MAX
    /// `total` bytes arrive as parts of exactly PART_SIZE (last one shorter). An `Err` item aborts the put with BackendError::Io.
    Stream { total: u64, parts: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>> },
}
#[derive(Clone, Debug, Default)] pub struct Quota { pub limit: Option<u64>, pub usage: u64, pub usage_in_trash: u64, pub account: Option<String> }
pub type ByteStream = std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, BackendError>> + Send>>;

pub trait Backend: Send + Sync + 'static {
    /// Fresh object ids usable in create_folder/put. Never fails for Mem/Dir.
    async fn new_ids(&self, n: usize) -> Result<Vec<Handle>, BackendError>;
    /// Idempotent: creating an existing id is Ok. `parent` may be Handle::top().
    async fn create_folder(&self, id: &Handle, parent: &Handle, name: &str) -> Result<(), BackendError>;
    /// Put-once. If an object with `id` already exists, returns ITS meta without writing (the caller compares size/md5).
    /// Never returns AlreadyExists or NotFound (an unresolvable id conflict is SessionLost, §6.2). On any error the object
    /// either does not exist or is complete (never partial).
    async fn put(&self, id: &Handle, parent: &Handle, name: &str, body: PutBody) -> Result<ObjMeta, BackendError>;
    /// Whole object or a byte range (end exclusive, clamped to size). Trashed objects are still readable. NotFound if absent.
    async fn get(&self, h: &Handle, range: Option<std::ops::Range<u64>>) -> Result<ByteStream, BackendError>;
    async fn stat(&self, h: &Handle) -> Result<Option<ObjMeta>, BackendError>;       // includes trashed objects (trashed = true)
    async fn list(&self, parent: &Handle) -> Result<Vec<ObjMeta>, BackendError>;     // direct, non-trashed children; all pages; Handle::top() allowed
    async fn find_by_name(&self, name: &str) -> Result<Vec<ObjMeta>, BackendError>;  // exact name, non-trashed, anywhere visible
    async fn trash(&self, h: &Handle) -> Result<(), BackendError>;                   // idempotent; NotFound if absent
    async fn untrash(&self, h: &Handle) -> Result<(), BackendError>;
    /// Permanent. Called only by `gc --purge` (§5.9). NotFound if absent.
    async fn delete(&self, h: &Handle) -> Result<(), BackendError>;
    async fn about(&self) -> Result<Quota, BackendError>;
    fn now_ms(&self) -> u64;                                                          // server clock estimate
}
pub async fn get_all<B: Backend>(b: &B, h: &Handle, range: Option<std::ops::Range<u64>>) -> Result<bytes::Bytes, BackendError>;
/// get_all for bytes that are not authenticated yet (index objects §4.6, the descriptor §3.3): asks for 0..max+1 and stops
/// reading as soon as more than `max` bytes have arrived — also when the server ignores the range. Ok(None) = longer than `max`.
pub async fn get_bounded<B: Backend>(b: &B, h: &Handle, max: u64) -> Result<Option<bytes::Bytes>, BackendError>;
pub fn stream_body(data: bytes::Bytes) -> PutBody;                                    // Small if ≤ MULTIPART_MAX else Stream fed from PART_SIZE slices

// ---------- src/backend/conformance.rs ----------   (lives in the library so that WP2's and WP3's test binaries both call it; no `include!`)
/// The generic backend contract of §12.1 (WP2), written with plain asserts. `b` must be empty. Works at Handle::top().
#[doc(hidden)] pub async fn run<B: Backend>(b: B);

// ---------- src/backend/mem.rs ----------
#[derive(Clone)] pub struct MemBackend { /* Arc<Mutex<…>> — clones share one store ("one Drive, many devices") */ }
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters { pub new_ids: u64, pub create_folder: u64, pub put: u64, pub put_bytes: u64, pub get: u64, pub get_bytes: u64,
                      pub stat: u64, pub list: u64, pub find_by_name: u64, pub trash: u64, pub untrash: u64, pub delete: u64, pub about: u64 }
pub struct MemCheckpoint(/* opaque full copy */);
impl MemBackend {
    pub fn new() -> Self;
    pub fn set_now_ms(&self, ms: u64);            pub fn advance_ms(&self, ms: u64);         // logical clock; created_ms comes from it
    pub fn counters(&self) -> Counters;           pub fn reset_counters(&self);
    pub fn all_objects(&self) -> Vec<ObjMeta>;    pub fn read(&self, h: &Handle) -> Option<bytes::Bytes>;
    // adversary hooks
    pub fn tamper(&self, h: &Handle, f: impl FnOnce(&mut Vec<u8>));                          // md5 is recomputed (server-consistent lie)
    pub fn hard_delete(&self, h: &Handle) -> bool;
    pub fn claim_size(&self, h: &Handle, size: u64);                                         // stat/list report `size`, get serves the real bytes (a listed size is a claim)
    pub fn rename(&self, h: &Handle, new_name: &str) -> bool;
    pub fn replace_content(&self, h: &Handle, with: &Handle) -> bool;                        // swap attack
    pub fn checkpoint(&self) -> MemCheckpoint;    pub fn restore(&self, c: &MemCheckpoint);  // rollback attack
}
impl Backend for MemBackend { /* … */ }

// ---------- src/backend/dir.rs ----------
/// Objects are plain files `<root>/<folder path>/<name>`. Ids are mapped through `<root>/.gclone-dir-ids.json` (id → relative path).
/// An object without a map entry (a web download / Takeout copy has no map at all) gets the handle `p:<relative path>` from
/// `list`/`find_by_name`/`stat`; ids recorded elsewhere give NotFound and callers resolve by name. `Handle::top()` is `<root>` itself:
/// `list(top)` lists it, and top-level objects report `parent = Handle::top()`.
/// Trash = move under `<root>/.trash/`; delete = remove from there. md5 computed on demand. created_ms = file mtime.
/// The id map is an append-only journal (one JSON record per line), not one JSON document. `open` needs an EXISTING directory
/// (missing → Io(NotFound); it creates nothing — `login --vault-dir` on a new path creates the directory first, WP7).
/// One name, one object: unlike Drive and Mem, a directory cannot hold two objects of one name. A new id whose path is taken
/// adopts an unbound file/folder or an empty folder; otherwise put/create_folder fail with Fatal{409, "nameConflict"} (§17.2).
/// Names starting with `.` are never objects. Methods must be called inside a tokio runtime (spawn_blocking).
pub struct DirBackend { /* … */ }
impl DirBackend { pub fn open(root: &std::path::Path) -> Result<Self, BackendError>; pub fn root(&self) -> &std::path::Path; }
impl Backend for DirBackend { /* … */ }

// ---------- src/backend/flaky.rs ----------
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpKind { NewIds, CreateFolder, Put, Get, Stat, List, FindByName, Trash, Untrash, Delete, About }
pub struct Flaky<B: Backend> { /* inner + Arc<Mutex<fault plan>> */ }
impl<B: Backend> Flaky<B> {
    pub fn new(inner: B) -> Self;                 pub fn inner(&self) -> &B;
    pub fn fail_next(&self, op: OpKind, times: u32, make: fn() -> BackendError);
    pub fn fail_nth(&self, op: OpKind, nth: u64, make: fn() -> BackendError);               // nth call of that kind from now (1-based)
    pub fn fail_put_named(&self, name_prefix: &str, times: u32, make: fn() -> BackendError); // e.g. ("s-", u32::MAX, quota) = every segment put fails
    pub fn lose_ack_next_put(&self);              // the object IS stored, the caller gets Transient → retry must take the idempotent path
    pub fn cut_next_stream_put(&self, after_bytes: u64);                                    // consumes that much, stores nothing, returns SessionLost
    pub fn on_put_progress(&self, after_bytes: u64, f: Box<dyn FnOnce() + Send>);           // runs `f` once when the next Stream put has consumed
                                                                                            // ≥ after_bytes (e.g. rewrite the source file mid-upload)
    pub fn corrupt_md5_next_put(&self);           // returned ObjMeta.md5 is wrong once → caller must trash + retry
    pub fn cut_next_get(&self, after_bytes: u64); // stream yields that much then Err(Transient)
    pub fn set_list_lag_ms(&self, ms: u64);       // list/find_by_name hide objects younger than ms (by inner.now_ms)
    pub fn hang(&self, op: OpKind);               // every call of `op` from now on NEVER returns (a network that went away; nothing reaches
                                                  // the inner backend, the call counts) — until clear(). Only the caller's cancellation or
                                                  // deadline ends it (§17.13)
    pub fn calls(&self, op: OpKind) -> u64;       pub fn clear(&self);
}
impl<B: Backend> Backend for Flaky<B> { /* … */ }

// ---------- src/backend/any.rs ----------
pub enum AnyBackend { Drive(crate::backend::drive::DriveBackend), Dir(DirBackend), Mem(MemBackend) }
impl Backend for AnyBackend { /* delegation */ }
```

### 9.6 WP3 — `backend::drive`, `auth`
```rust
// ---------- src/auth/mod.rs, login.rs ----------   (the device side of §2.3–§2.4; DeviceCode, LoginGrant and AccessGrant hold secrets: NO Debug derive)
pub const SCOPE_DRIVE_FILE: &str = "https://www.googleapis.com/auth/drive.file";
pub const GOOGLE_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
pub const DEFAULT_AUTH_URL: Option<&str> = option_env!("GCLONE_DEFAULT_AUTH_URL");
/// Which of the Worker's OAuth clients a refresh token belongs to (§2.3 /refresh). serde: "legacy" / "device"; in secrets.json a
/// missing `client` is Legacy — a login made before 0.2.0 through the Web-application client (§8.2, §17.18).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "lowercase")]
pub enum AuthClient { #[default] Legacy, Device }
impl AuthClient { pub fn is_legacy(&self) -> bool; }
/// `base` = the validated auth Worker URL without a trailing slash; routes are appended ("/device/start", "/device/poll", "/refresh").
#[derive(Clone, Debug, PartialEq, Eq)] pub struct AuthEndpoints { pub base: String, pub revoke_url: String }
impl AuthEndpoints { pub fn new(auth_url: &str) -> Result<Self, AuthError>; }        // validate_auth_url + GOOGLE_REVOKE_URL; tests build the struct directly
/// §2.2: https only (http for 127.0.0.1 / localhost / [::1]), host required, no userinfo / query / fragment; returns the normalised URL.
pub fn validate_auth_url(s: &str) -> Result<String, AuthError>;                      // BadAuthUrl
/// arg, else env GCLONE_AUTH_URL (passed in by the caller), else the stored value, else DEFAULT_AUTH_URL; validated. None anywhere → BadAuthUrl
/// with a message naming the three ways to supply it. `stored` = what the caller found on disk: secrets.json's auth_url, else
/// config.json's (§2.2) — the CLI passes `secrets.auth_url.or(config.auth_url)`.
pub fn resolve_auth_url(arg: Option<&str>, env: Option<&str>, stored: Option<&str>) -> Result<String, AuthError>;
/// reqwest client for the Worker and the revoke call: redirect Policy::none(), connect 10 s / read 30 s timeouts, User-Agent gclone/<version>.
pub fn http_client() -> Result<reqwest::Client, AuthError>;
/// The Worker's answer to /device/start, checked as §2.4 step 1 says (printable, https, bounded) before anything is shown.
pub struct DeviceCode { pub device_code: String, pub user_code: String, pub verification_url: String,
                        pub expires_in: std::time::Duration /* ≤ AUTH_TIMEOUT */, pub interval: std::time::Duration /* ≤ AUTH_RETRY_AFTER_MAX */ }
#[derive(Clone)] pub struct LoginGrant { pub refresh_token: String, pub access_token: String, pub expires_at_ms: u64, pub scope: String,
                                         pub email: String, pub refresh_expires_in: Option<u64> /* seconds; Some = time-limited grant, §2.4 */ }
#[derive(Clone)] pub struct AccessGrant { pub access_token: String, pub expires_at_ms: u64 }
pub struct InteractiveOpts { pub no_browser: bool,                                   // do not call `open`; the URL and the code are printed either way
                             pub print: Box<dyn Fn(&str) + Send + Sync>,             // how to show the URL, the code and notes
                             pub open: Box<dyn Fn(&str) + Send + Sync> }             // open a URL in the local browser; best effort
/// §2.4, the whole sign-in: device_start → the three lines → `open` (unless no_browser, and only for a Google page: otherwise
/// NOT_GOOGLE_NOTE is printed as a fourth line and nothing is opened) → device_wait. Returns the grant as received;
/// the CALLER applies the expiring-grant rule (refresh_expires_in.is_some()).
pub const NOT_GOOGLE_NOTE: &str;                              // "(warning: that is not a google.com address, and it was not opened. …)"
pub fn is_google_page(verification_url: &str) -> bool;        // https, host google.com or *.google.com
pub async fn login_interactive(http: &reqwest::Client, ep: &AuthEndpoints, opts: InteractiveOpts) -> Result<LoginGrant, AuthError>;
pub async fn device_start(http: &reqwest::Client, ep: &AuthEndpoints) -> Result<DeviceCode, AuthError>;   // POST /device/start {}; 5 tries on 5xx/network
                                                                                    // (pauses 0.25 s, 0.5 s, 1 s, 2 s); 429: once more after Retry-After
/// Polls POST /device/poll every `code.interval` until the grant, a refusal, or the end of `code.expires_in` (Timeout; Network when the
/// polls were failing then). slow_down: interval += AUTH_POLL_SLOW_DOWN. Failed polls (network, 5xx, 429) are followed by the next
/// one — after `interval · 2ⁿ` (≤ AUTH_RETRY_AFTER_MAX, ≥ interval) for the n-th network/5xx failure in a row; `note` is told about
/// the first of each streak (§2.4 step 3). `403 grant_unusable` ends the login with the Worker's message. The grant's `email` is
/// checked plain text (§2.4).
pub async fn device_wait(http: &reqwest::Client, ep: &AuthEndpoints, code: &DeviceCode, note: &(dyn Fn(&str) + Send + Sync)) -> Result<LoginGrant, AuthError>;
/// POST /refresh, 5 tries on 5xx/network; 429: once more after Retry-After. `client`: Device → `"client": "device"` in the body;
/// Legacy → no `client` field (§2.3).
pub async fn refresh(http: &reqwest::Client, ep: &AuthEndpoints, refresh_token: &str, client: AuthClient) -> Result<AccessGrant, AuthError>;
/// POST ep.revoke_url, form `token=…`. 200 → Ok(true); 400 → Ok(false) (already invalid); anything else → Network. Grant-wide at Google (§2.7).
pub async fn revoke(http: &reqwest::Client, ep: &AuthEndpoints, token: &str) -> Result<bool, AuthError>;

// ---------- src/auth/token.rs ----------
pub struct TokenProvider { /* http, endpoints, refresh token and its client, cache path, Mutex<cached>, single-flight */ }
impl TokenProvider {
    /// `cache_file`: Some = read at construction and rewritten after every REAL refresh (0600, util::write_atomic); a cache file that
    /// fails util::is_private (§8.1) is ignored and replaced. None = memory only — what `gclone login` uses (§2.4, §2.6).
    pub fn new(http: reqwest::Client, ep: AuthEndpoints, refresh_token: String, client: AuthClient, cache_file: Option<std::path::PathBuf>) -> Self;
    /// Seeds the IN-MEMORY cache with the access token that came with a fresh login, so `login` needs no extra /refresh round trip.
    /// Never writes the cache file, whatever `cache_file` is.
    pub fn prime(&self, access_token: &str, expires_at_ms: u64);
    pub async fn access_token(&self) -> Result<String, AuthError>;                    // cached unless < ACCESS_TOKEN_SKEW to expiry
    pub async fn force_refresh(&self) -> Result<String, AuthError>;
    pub fn last_refresh_ms(&self) -> Option<u64>;
}

// ---------- src/backend/drive/mod.rs ----------
#[derive(Clone, Debug)] pub struct DriveEndpoints { pub api: String, pub upload: String }
impl Default for DriveEndpoints { /* https://www.googleapis.com , https://www.googleapis.com/upload */ }
pub struct DriveConfig { pub endpoints: DriveEndpoints, pub transfers: usize, pub pacer: PacerConfig, pub user_agent: String,
                         pub read_timeout: std::time::Duration }       // HTTP_READ_TIMEOUT; a field so that tests can shorten it (§6.4, §17.10)
impl Default for DriveConfig { /* … */ }
pub struct DriveBackend { /* api client (h2), transfer and upload clients (h1), all with redirect Policy::none(); tokens, pacer, id pool, clock offset */ }
impl DriveBackend { pub fn new(tokens: std::sync::Arc<TokenProvider>, cfg: DriveConfig) -> Result<Self, BackendError>;
                    pub fn pacer(&self) -> &Pacer; }
impl Backend for DriveBackend { /* §6.2–6.5; wire shapes §6.4.1 */ }
// Additive (§17.3): `DriveBackend: Clone` (clones share clients, tokens, pacer); `Pacer::set_backoff_unit` (#[doc(hidden)] test hook that scales
// BACKOFF — `Pacer::backoff` itself stays the §6.1 formula).

// ---------- src/backend/drive/pacer.rs ----------
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum CallKind { List, Get, About, GenerateIds, Download, Create, CreateFolder, Trash, Delete, UploadPart, StatusQuery }
impl CallKind { pub fn units(self) -> u32; pub fn class(self) -> Option<Class>; }      // None = unpaced
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum Class { Write, Read }
#[derive(Clone, Debug)] pub struct PacerConfig { pub write_start: f64, pub write_min: f64, pub write_max: f64, pub read_start: f64, pub read_min: f64, pub read_max: f64,
                                                 pub increase_per_10s: f64, pub units_per_min: u32, pub max_attempts: u32, pub breaker: std::time::Duration }
impl Default for PacerConfig { /* §6.1 */ }
#[derive(Clone, Debug)] pub struct PacerStats { pub write_rate: f64, pub read_rate: f64, pub units_last_min: u32, pub throttles: u64 }
pub struct Pacer { /* uses tokio::time so tests can pause/advance */ }
impl Pacer {
    pub fn new(cfg: PacerConfig) -> Self;
    pub async fn acquire(&self, kind: CallKind);                                        // token bucket + unit window
    pub fn on_success(&self, kind: CallKind);
    pub fn on_throttle(&self, kind: CallKind, retry_after: Option<std::time::Duration>, attempt: u32) -> std::time::Duration;   // halves rate; returns sleep
    pub fn backoff(attempt: u32) -> std::time::Duration;                                // min(2^n s + jitter, 64 s)
    pub fn write_breaker_tripped(&self) -> bool;
    pub fn stats(&self) -> PacerStats;
}

// ---------- src/backend/drive/errors.rs ----------
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpClass { Success, Throttle { retry_after: Option<std::time::Duration> }, Transient, Unauthorized, NotFound, Conflict,
                     StorageFull, DailyUpload, DailyDownload, ProjectApiQuota, AppNotAuthorized, AbuseFlag,
                     Fatal { status: u16, reason: String, message: String } }
pub fn classify(status: u16, retry_after: Option<&str>, body: &[u8]) -> HttpClass;      // table of §6.5; `body` need not be JSON
pub fn parse_range_header(v: Option<&str>) -> u64;                                      // "bytes=0-N" → N+1; None → 0

// ---------- src/backend/drive/probe.rs ----------   (only the automatable rows of §2.9: 6, 8, 9, 10, 12, 13)
#[derive(Clone, Debug)] pub enum ProbeOutcome { Pass(String), Fail(String), Info(String), Skipped(String) }
#[derive(Clone, Debug)] pub struct ProbeLine { pub id: u8, pub question: &'static str, pub outcome: ProbeOutcome }
pub async fn run_probes(tokens: std::sync::Arc<TokenProvider>, cfg: DriveConfig) -> Vec<ProbeLine>;   // uses a throwaway folder, trashes it afterwards

// api.rs / upload.rs: private to the drive module (request builders, multipart body, resumable state machine, wire structs of §6.4.1).
```
`tests/support/fake_drive.rs` (WP3, built on `wiremock` with one catch-all `Respond` implementation over shared state; included by `tests/drive_http.rs`, `tests/auth.rs` and — read-only — WP7's `tests/cli_e2e.rs` with `#[path = "support/fake_drive.rs"] mod fake_drive;`). One server plays three parts: Google Drive, the auth Worker (under the path prefix `/auth`) and Google's revoke endpoint (`/revoke`), so the Rust login and token code is tested without Google and without Cloudflare:
```rust
pub struct FakeDrive { /* MockServer + Arc<Mutex<State>> */ }
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Route { AuthStart /* POST /auth/device/start */, AuthPoll /* POST /auth/device/poll */, AuthRefresh, Revoke,
                 GenerateIds, CreateFolder, Multipart, ResumableInit, SessionPut, Media, Stat, List, Patch, Delete, About }
impl FakeDrive {
    pub async fn start() -> Self;
    pub fn endpoints(&self) -> DriveEndpoints;
    pub fn auth(&self) -> AuthEndpoints;              // base = "http://127.0.0.1:<port>/auth", revoke_url = "http://127.0.0.1:<port>/revoke"
    pub fn token_provider(&self) -> std::sync::Arc<TokenProvider>;                      // pre-issued refresh token "rt-ok"
    // --- the fake auth Worker (§2.3) and the fake user at google.com/device
    /// Plays the user: enters `user_code` at "Google" and approves, as the account of set_login_email; the device's next poll gets
    /// its answer. Panics on a code no /device/start handed out, or one that is not pending any more.
    pub fn approve(&self, user_code: &str);
    pub fn deny(&self, user_code: &str);              // the user refuses: the next poll → 403 access_denied
    pub fn expire_codes(&self);                       // every pending login runs out: its next poll → 400 expired_token
    pub fn slow_down(&self, times: u32);              // the next `times` polls of a pending login → 400 slow_down
    pub fn set_poll_interval(&self, secs: f64);       // `interval` of later /device/start answers (default 0.02 — Google: 5)
    pub fn set_code_lifetime(&self, secs: f64);       // `expires_in` of later /device/start answers (default 1800)
    pub fn last_user_code(&self) -> Option<String>;   // the user code of the newest /device/start answer ("TEST-<n>")
    pub fn set_legacy_client(&self, configured: bool); // the Worker has the GOOGLE_LEGACY_CLIENT_* secrets (default: not)
    pub fn add_legacy_token(&self) -> String;         // a live refresh token of the legacy client ("rt-legacy-<n>")
    pub fn set_login_email(&self, email: &str);       // the account the fake user signs in with (default "me@example.com")
    pub fn set_allowed_emails(&self, emails: &[&str]);                                  // default ["me@example.com"]
    pub fn set_granted_scope(&self, scope: &str);     // the `scope` of /auth/device/poll and /auth/refresh answers (default: openid + userinfo.email + drive.file)
    pub fn break_client(&self);                       // /auth/device/start, /auth/device/poll and /auth/refresh → 500 client_invalid
    pub fn revoke_refresh_token(&self);               // as if revoked at Google: every refresh token → 400 invalid_grant at /auth/refresh
    pub fn issued_refresh_tokens(&self) -> Vec<String>;                                 // one per completed login ("rt-1", "rt-2", …), all valid together
    pub fn revoked(&self) -> Vec<String>;             // tokens POSTed to /revoke (which then invalidates ALL refresh tokens, like Google)
    // --- Drive
    pub fn backend(&self) -> DriveBackend;            // DriveConfig with these endpoints and a fast pacer
    pub fn fail_next(&self, route: Route, times: u32, status: u16, reason: &str);       // Drive routes: JSON error envelope of §6.4.1;
                                                                                        // auth routes: the §2.3 error object with `reason` as its code
    pub fn fail_next_raw(&self, route: Route, times: u32, status: u16, body: &str);     // non-JSON body (HTML / plain text)
    pub fn unauthorized_once(&self, route: Route);    // one 401 on that route (e.g. SessionPut for part k), then normal
    pub fn lose_response_once(&self, route: Route);   // perform the effect, answer 503
    pub fn ack_only(&self, bytes: u64);               // next SessionPut persists only `bytes` (rounded down to 256 KiB) then 503
    pub fn omit_range_header_once(&self);             // 308 without Range
    pub fn expire_sessions(&self);                    // SessionPut → 404
    pub fn conflict_at(&self, route: Route);          // 409 for existing ids at Multipart / ResumableInit / completion
    pub fn conflict_then_absent(&self, route: Route); // 409 once although no object with that id exists (stat → 404)
    pub fn set_list_lag(&self, lists: u32);           // new objects invisible for that many list calls
    pub fn set_page_cap(&self, n: usize);             // short pages with nextPageToken
    pub fn set_refresh_expires_in(&self, secs: Option<u64>);                            // /auth/device/poll answers carry refresh_token_expires_in
    pub fn mark_abusive(&self, id: &str);
    pub fn hits(&self, route: Route) -> u64;          pub fn object(&self, id: &str) -> Option<Vec<u8>>;
    pub fn session_requests(&self) -> Vec<(u64 /*start*/, u64 /*len*/, u64 /*total*/)>;  // every Content-Range seen, for 256-KiB assertions
    // --- additions of WP3 (§17.3); FakeDrive is also `Clone` (clones share the server and its state)
    pub fn base(&self) -> &str;                       // "http://127.0.0.1:<port>"
    pub fn token_provider_for(&self, refresh_token: &str) -> std::sync::Arc<TokenProvider>;
    pub fn backend_with(&self, tokens: std::sync::Arc<TokenProvider>, pacer: PacerConfig) -> DriveBackend;   // e.g. PacerConfig::default() = the production pacer
    pub fn strip_completion_body_once(&self);         pub fn reject_page_token_once(&self);
    pub fn object_ids(&self) -> Vec<String>;          pub fn status_queries(&self) -> u64;
    pub fn requests(&self, route: Route) -> Vec<Seen>;                                  // Seen: one recorded request (`param(name)` reads a query parameter)
    // --- additions of §17.10
    pub fn ack_only_times(&self, bytes: u64, times: u32);   // like ack_only for the next `times` part PUTs (u32::MAX: until further notice)
    pub fn drop_parts(&self, times: u32);             // the next `times` part PUTs are not kept: 308 with the Range as it was
    pub fn hold_completion(&self, answers: u32);      // the next `answers` completing requests (last part, then status queries) answer 308 with the
                                                      // full Range; the first status query after them completes the session
}
```
The fake's auth routes implement the three JSON routes of §2.3 literally — same parameter validation, same JSON bodies, status codes and error codes, no CORS, no redirect — with "Google" folded in: `/auth/device/start` opens a login (device code `dc-<n>-…`, user code `TEST-<n>`, `verification_url` = `https://www.google.com/device` — a constant nothing in a test opens — and the `interval` / `expires_in` of `set_poll_interval` / `set_code_lifetime`), and the **test plays the user**: `approve(user_code)` / `deny(user_code)` stand for entering the code at Google, with the account of `set_login_email` at that moment. `/auth/device/poll` answers the state of the login (`authorization_pending`, `slow_down` while `slow_down(n)` lasts, `expired_token` after `expire_codes`, `access_denied`, `invalid_grant` for an unknown or already redeemed code) and — once, for an approved one — applies the checks of §2.3 in their order (allowlist, `scope_not_allowed`, `scope_missing`) before it issues `rt-<n>`; whatever the outcome, the code is spent. `/auth/refresh` takes the `client` field as §2.3 says: `"device"` → the token must be one a login issued (or `rt-ok`); no field → the legacy client, `400 invalid_grant` unless `set_legacy_client(true)` and the token is one of `add_legacy_token`; a token presented under the other client is refused like an unknown one (what Google really answers there is unverified). `/auth/device/poll` and `/auth/refresh` apply the scope rules of §2.3 to `set_granted_scope`: an entry outside `ALLOWED_SCOPES` → `403 scope_not_allowed`. The fake has no rate limiter of its own; `fail_next(Route::AuthStart | Route::AuthPoll | Route::AuthRefresh, n, 429, "rate_limited")` answers `429` with `Retry-After: 1`. It serves no HTML pages. **That these routes really match the Worker is not left to two readings of §2.3**: `tests/auth.rs` checks them against `worker/test/contract.json`, the same fixture the Worker's own tests check `handle()` against (§16.5). `/revoke` takes a form-encoded `token`, answers `200` and invalidates **all** refresh tokens (grant-wide, as documented for Google), or `400 {"error":"invalid_token"}` for an unknown token. Drive routes accept any access token the fake issued — until `revoke_refresh_token()` or `/revoke`, which invalidate every access token too (Drive routes then answer `401`), so a revoked login surfaces as `Auth(Expired)` on the next Drive call (§17.3). Also beyond the list above: the free function `fast_pacer()` and the constant `VERIFICATION_URL`; `conflict_at(Multipart | ResumableInit)` are the default places (no-op) and `conflict_at(SessionPut)` moves the resumable `409` to completion; an injected `3xx` (except `308`) carries a `Location` back to the same route; `session_requests()` records every part `Content-Range` that arrives, including requests answered by an injected fault; `name = '…'` matches case-insensitively and a multipart body above 5 MiB answers `413`, as Drive does; `/auth/refresh` applies the 20..=512 length rule of §2.3 to every token the fake did not issue itself (its own `rt-ok` / `rt-<n>` / `rt-legacy-<n>` pass).

The fake also implements: `generateIds`, folder create, multipart create, resumable init/PUT/status, `alt=media` with `Range`, stat, list with the two `q` shapes of §6.4 + paging, PATCH `trashed`, DELETE, about; md5 computed from stored bytes; `Date` header. It is written by the same package as the client, so it MUST follow §6.4.1 literally rather than mirror the client's assumptions: `size` and quota numbers are JSON **strings**; folders have no `size`/`md5Checksum`; `createdTime` is RFC 3339 text; a `308` has no `Location`; and a create (multipart, or a resumable completion) answers with the **default projection** (`kind,id,name,mimeType`) unless `fields=` was a query parameter of the multipart POST / of the resumable *initiation*.

### 9.7 WP4 — `state`, `index`
```rust
// ---------- src/state/mod.rs ----------  (public surface used by other packages; index tables are pub(crate) in state::tables)
#[derive(Clone)] pub struct Db { /* Arc<Mutex<rusqlite::Connection>> */ }
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum PairIdentity { New, Same, Changed }   // root (st_ino, birth time) vs the recorded one, §5.5
pub struct PairInfo { pub id: i64, pub identity: PairIdentity }
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum LedgerDir { Up, Down }
impl Db {
    pub fn open(path: &std::path::Path) -> Result<Db, StateError>;            // creates schema v1, sets pragmas, file mode 0600
    /// For a process WITHOUT the state lock (§8.3): creates and upgrades nothing; StateError::Locked if there is no schema yet.
    pub fn open_shared(path: &std::path::Path) -> Result<Db, StateError>;
    pub fn open_in_memory() -> Result<Db, StateError>;
    pub fn meta_get(&self, k: &str) -> Result<Option<Vec<u8>>, StateError>;   pub fn meta_set(&self, k: &str, v: &[u8]) -> Result<(), StateError>;
    pub fn meta_get_u64(&self, k: &str) -> Result<Option<u64>, StateError>;   pub fn meta_set_u64(&self, k: &str, v: u64) -> Result<(), StateError>;
    /// Finds or creates the pair and reports how the root identity compares. NEVER discards rows.
    pub fn pair_open(&self, local_root: &str, remote_prefix: &str, root_ino: u64, root_birth_ns: i64, fold_case: bool) -> Result<PairInfo, StateError>;
    pub fn pair_reset(&self, pair: i64, root_ino: u64, root_birth_ns: i64) -> Result<(), StateError>;    // --reset-pair: drop the pair's base rows, record the identity
    pub fn pair_rebind(&self, pair: i64, root_ino: u64, root_birth_ns: i64) -> Result<(), StateError>;   // --keep-pair: keep the rows, record the identity
    pub fn base_all(&self, pair: i64) -> Result<Vec<BaseRow>, StateError>;    // sorted by key
    pub fn base_put(&self, pair: i64, rows: &[BaseRow]) -> Result<(), StateError>;
    pub fn base_forget(&self, pair: i64, keys: &[String]) -> Result<(), StateError>;
    pub fn ledger_add(&self, ts_ms: u64, dir: LedgerDir, bytes: u64) -> Result<(), StateError>;
    pub fn ledger_sum_24h(&self, now_ms: u64, dir: LedgerDir) -> Result<u64, StateError>;   // also prunes older rows
    pub fn pending_count(&self) -> Result<u64, StateError>;                   // staged ops, plus 1 if a sealed segment waits in `outbox`
}
pub struct StateLock { /* open File holding the kernel lock */ }
pub fn lock_exclusive(state_dir: &std::path::Path, wait: std::time::Duration) -> Result<StateLock, StateError>;   // StateError::Locked on timeout
pub fn try_lock(state_dir: &std::path::Path) -> Result<Option<StateLock>, StateError>;
/// `try_lock` that creates nothing (no directory, no lock file) — `gclone web`'s refresh (§7.4, §17.21).
pub enum Existing { Held(StateLock), Busy, Gone }
pub fn try_lock_existing(state_dir: &std::path::Path) -> Result<Existing, StateError>;

// ---------- src/index/apply.rs ----------  (pure merge rule §5.2.2, generic so it is property-testable without SQLite)
pub trait HeadStore {       // every method is fallible: the production implementation is a SQLite transaction; MemIndex always returns Ok
    fn heads(&self, path: &str) -> Result<Vec<Head>, StateError>;
    /// §5.2.2 `supersede`: moves every head (path, stamp) to `removed` with (removed_ms, by); for an existing `removed` row
    /// (path, stamp) whose recorded `by` is greater, replaces (removed_ms, by). Returns the number of heads moved.
    fn supersede(&mut self, path: &str, stamp: &Stamp, removed_ms: u64, by: Stamp) -> Result<usize, StateError>;
    fn insert_head(&mut self, path: &str, stamp: Stamp, entry: &Entry, origin: Option<Stamp>) -> Result<(), StateError>;   // then recompute winner flags
    fn upsert_blob(&mut self, rec: &BlobRec) -> Result<(), StateError>;
    fn upsert_device(&mut self, id: DeviceId, name: &str, seen_ms: u64) -> Result<(), StateError>;
    fn set_vault(&mut self, format: u16, name: &str) -> Result<(), StateError>;
}
#[derive(Default, Clone, Debug, PartialEq, Eq)] pub struct MemIndex { /* BTreeMaps; implements HeadStore; derives Eq for convergence tests */ }
// MemIndex also has blobs(), devices(), vault() (§17.3).
impl MemIndex { pub fn winners(&self) -> Vec<Head>; pub fn all_heads(&self) -> Vec<Head>; pub fn removed(&self) -> Vec<RemovedVersion>;
                pub fn to_snapshot(&self, vault_id: [u8; 16], device: DeviceId, lamport: u64, covers: Vec<SegRef>, covered: Vec<CoveredSeg>,
                                   now_ms: u64) -> SnapshotV1;
                pub fn load_snapshot(s: &SnapshotV1) -> Self; }
#[derive(Default, Clone, Debug)] pub struct ApplyStats { pub puts: u64, pub dels: u64, pub noop_dels: u64, pub new_conflicts: u64 }
pub fn apply_segment<S: HeadStore>(store: &mut S, seg: &SegmentV1, removed_ms: u64) -> Result<ApplyStats, IndexError>;   // storage errors propagate with `?`
/// A priority topological order: among the ready segments the smallest (lamport, device, seq, hash) first (§5.3 "as implemented").
pub fn causal_order(segs: &[(SegmentV1, [u8; 32])], satisfied: &dyn Fn(&SegRef) -> bool) -> (Vec<usize> /* applicable, in order */, Vec<usize> /* blocked */);

// ---------- src/index/mod.rs ----------
#[derive(Clone, Debug)] pub struct VaultHandles { pub root: Handle, pub index: Handle, pub data: Handle }
/// One vault as seen by discovery (§3.3). `keyfiles` = ALL the root's children named gclone-key-<gen>-<h8>, highest generation first (ties: name
/// descending); the caller (ATTACH) looks at the first KEYFILE_TRY_MAX only.
#[derive(Clone, Debug)] pub struct FoundVault { pub vault_id: [u8; 16], pub root_name: String /* "" when the root is Handle::top() */,
                                                pub descriptor_created_ms: u64, pub handles: VaultHandles, pub keyfiles: Vec<ObjMeta> }
pub struct CreateParams { pub vault_id: [u8; 16], pub vault_name: String, pub device_name: String, pub cache_dir: std::path::PathBuf,
                          pub machine_fp: Option<[u8; 32]> /* None = compute (§5.3); tests pin it */,
                          pub keyfile: crate::format::SealedObject /* generation 1, sealed by the caller (§2.6) */ }
pub struct OpenParams   { pub vault_id: [u8; 16], pub handles: VaultHandles, pub device_name: String, pub cache_dir: std::path::PathBuf,
                          pub machine_fp: Option<[u8; 32]> }
#[derive(Clone, Debug, Default)] pub struct RefreshReport { pub applied: u64, pub blocked_young: u64, pub conflicts: u64, pub forks: u64,
                                                           pub rotated_device: bool, pub rebuilt_from: Option<String>, pub adopted: Option<String>,
                                                           pub outbox_stuck: bool, pub corrupt_objects: Vec<String> }
#[derive(Clone, Debug, Default)] pub struct CommitReport { pub segment: Option<String>, pub ops: u64, pub dropped_ops: u64 /* §5.8 */ }
#[derive(Clone, Debug, Default)] pub struct RepairReport { pub republished: Vec<String>, pub untrashed: Vec<String>, pub accepted_loss: Vec<String>,
                                                          pub snapshot: Option<String>, pub still_missing: Vec<String> }
#[derive(Clone, Debug, Default)] pub struct VaultStats { pub files: u64, pub dirs: u64, pub bytes: u64, pub blobs: u64, pub blob_bytes: u64,
                                                        pub dead_blob_bytes: u64, pub pack_dead_bytes: u64, pub trashed_blob_bytes: u64 /* trashed by this device, not yet purged */,
                                                        pub segments: u64, pub snapshots: u64,
                                                        pub conflicts: u64, pub last_change_ms: Option<u64>, pub last_change_by: Option<String> }
#[derive(Clone, Debug)] pub struct ListRow { pub name: String, pub is_dir: bool, pub head: Option<Head> /* None for implied dirs */ }
#[derive(Clone, Debug)] pub struct SearchHit { pub path: String, pub is_dir: bool, pub head: Option<Head> /* None for directories */ }   // §17.20
#[derive(Clone, Debug)] pub struct DeviceInfo { pub id: DeviceId, pub name: String, pub first_ms: u64, pub last_ms: u64 }

/// §2.6 "two first devices": the winner among `found` (which must include one's own vault) = smallest (descriptor_created_ms, vault_id).
pub fn creation_winner(found: &[FoundVault]) -> Option<&FoundVault>;

pub struct Vault<B: Backend> { /* Arc<B>, Db, Keyring, handles, cache dir, device identity, local clock */ }
impl<B: Backend> Vault<B> {
    // --- lifecycle
    /// Creates, in this order (§2.6): the root folder `<vault_name>` under Handle::top(), index/, data/, README, the keyfile
    /// (p.keyfile, verified by size + md5), the first segment [VaultInit, Device] — and the descriptor LAST. Initialises `db`.
    /// Every object uses a pre-generated id. Returns the vault and its own FoundVault (descriptor_created_ms from the put).
    pub async fn create(backend: std::sync::Arc<B>, db: Db, keys: Keyring, p: CreateParams) -> Result<(Self, FoundVault), IndexError>;
    pub async fn open(backend: std::sync::Arc<B>, db: Db, keys: Keyring, p: OpenParams) -> Result<Self, IndexError>;   // no network; creates device id if db is new; for the lock holder
    /// For a process WITHOUT the state lock (§8.3; `db` from Db::open_shared): reads only — no device name, no machine-fingerprint check,
    /// no rotation, no cache directory. Queries and downloads only: never refresh, stage or commit on it. StateError::Locked if the replica
    /// was never initialised.
    pub async fn open_unlocked(backend: std::sync::Arc<B>, db: Db, keys: Keyring, p: OpenParams) -> Result<Self, IndexError>;
    /// Every vault this backend can see (§3.3) — needs no keys: find_by_name(DESCRIPTOR_NAME); per hit: get (at most DESCRIPTOR_MAX
    /// bytes) + parse the descriptor (oversized, unparsable or min_reader too new → skipped with a warning), root = its parent (possibly Handle::top(); otherwise stat(root) for the
    /// name), list(root) → exactly one `index` and one `data` folder (else an error naming the duplicate) and the keyfiles.
    /// Sorted by (descriptor_created_ms, vault_id). An empty Vec means "no vault". BackendError::AppNotAuthorized → VaultNotVisible.
    pub async fn discover(backend: &B) -> Result<Vec<FoundVault>, IndexError>;
    /// Re-login on an attached device (§2.6 B.1): stat(root) must be an un-trashed folder (trashed → VaultTrashed; absent or
    /// AppNotAuthorized → VaultNotVisible); stat(index) and stat(data) must exist with parent == root. Never a listing.
    pub async fn verify_visible(backend: &B, handles: &VaultHandles) -> Result<(), IndexError>;
    pub fn backend(&self) -> &std::sync::Arc<B>;   pub fn db(&self) -> &Db;   pub fn keys(&self) -> &Keyring;
    pub fn handles(&self) -> &VaultHandles;        pub fn device_id(&self) -> DeviceId;   pub fn vault_name(&self) -> String;
    #[doc(hidden)] pub fn set_local_clock(&mut self, now_ms: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>);   // tests: GAP_GRACE without sleeping
    #[doc(hidden)] pub fn set_index_object_max(&mut self, max: u64);   // tests: the read bound of §4.6 rule 1 without gibibyte objects (default INDEX_OBJECT_MAX)
    // --- journal
    pub async fn refresh(&self) -> Result<RefreshReport, IndexError>;                   // §5.3 (includes recover_outbox; a stuck outbox is not an error)
    pub fn outbox_stuck(&self) -> Option<String>;                                       // Some(cause) while a sealed segment is unpublished
    pub fn stage(&self, drafts: Vec<OpDraft>) -> Result<(), IndexError>;                // durable (`pending`), no network; a bad draft → IndexError::Format (§5.6)
    pub async fn commit(&self) -> Result<CommitReport, IndexError>;                     // §5.6; Err(OutboxStuck) on a temporary publish failure
    pub async fn commit_ops(&self, drafts: Vec<OpDraft>) -> Result<CommitReport, IndexError>;   // stage + commit
    pub async fn resolve_conflicts(&self) -> Result<u64, IndexError>;                   // §5.2.3; stages, then ALWAYS commit(); returns #resolutions
    pub async fn maybe_compact(&self) -> Result<Option<String>, IndexError>;
    pub async fn write_snapshot(&self) -> Result<String, IndexError>;
    pub async fn cleanup_index(&self) -> Result<u64, IndexError>;                       // returns #objects trashed; skips a pass that has nothing new to decide (§5.6)
    /// §5.6: commit → resolve_conflicts → maybe_compact → cleanup_index. Called exactly once per mutating command, by the CLI layer.
    pub async fn finish_mutation(&self) -> Result<(), IndexError>;
    pub async fn repair(&self, accept_loss: bool) -> Result<RepairReport, IndexError>;  // §5.10 (refreshes by itself). accept_loss = false and loss remains →
                                                                                        // Ok with `still_missing` non-empty: the CLI exits 3 (§17.3)
    // --- keyfile (§2.6, §2.7)
    pub async fn keyfiles(&self) -> Result<Vec<ObjMeta>, IndexError>;                   // list(root), names that parse as keyfiles, highest generation first
    /// passwd: put `kf` into the root under a pre-generated id (returned size + md5 must match, else trash it and fail), THEN trash every
    /// listed keyfile with a lower generation. Returns the number trashed.
    pub async fn replace_keyfile(&self, kf: &crate::format::SealedObject) -> Result<u64, IndexError>;
    pub async fn data_folder(&self) -> Result<Handle, IndexError>;                      // this device's current data folder (creates / rolls)
    pub fn note_blob_created(&self) -> Result<(), IndexError>;                          // bumps data_folder_count
    // --- queries (local replica only)
    pub fn head(&self, path: &str) -> Result<Option<Head>, IndexError>;                 // winner
    pub fn heads(&self, path: &str) -> Result<Vec<Head>, IndexError>;                   // winner + losers
    pub fn walk(&self, prefix: &str) -> Result<Vec<Head>, IndexError>;                  // winners at/under prefix, sorted by path ("" = everything)
    pub fn list(&self, prefix: &str) -> Result<Vec<ListRow>, IndexError>;               // direct children incl. implied dirs
    pub fn exists_dir(&self, path: &str) -> Result<bool, IndexError>;                   // Dir head or any winner under path/
    pub fn search(&self, needle: &str, limit: usize) -> Result<(Vec<SearchHit>, bool), IndexError>;   // §7.4: names (last components; directories with or without
                                                                                       // a head) containing `needle`, NFC + lower case on both sides, in path order; the
                                                                                       // bool = there are more than `limit`; one pass over the winners' paths; "" finds nothing
    pub fn blob(&self, id: &BlobId) -> Result<Option<BlobRec>, IndexError>;
    pub fn blobs(&self) -> Result<Vec<BlobRec>, IndexError>;
    pub fn dead_blobs(&self, now_ms: u64) -> Result<Vec<(BlobRec, u64 /* dead since ms */)>, IndexError>;   // only blobs dead ≥ GC_GRACE at now_ms, not
                                                                                        // marked trashed and not named by this device's pending/outbox ops (§5.9, §17.11)
                                                                                        // = "what gc would trash now"; VaultStats.dead_blob_bytes: same rule.
                                                                                        // blobs() returns every row, trashed ones included (§17.3)
    pub fn set_blob_trashed(&self, id: &BlobId, trashed_ms: Option<u64>) -> Result<(), IndexError>;   // gc sets, restore/check clear
    pub fn purge_candidates(&self, now_ms: u64) -> Result<Vec<BlobRec>, IndexError>;    // §5.9 step 3: trashed_ms set, unreferenced within RESTORE_WINDOW,
                                                                                        // not named by this device's pending/outbox ops
    pub fn forget_blob(&self, id: &BlobId) -> Result<(), IndexError>;                   // after a successful purge
    pub fn removed_versions(&self, path: &str) -> Result<Vec<RemovedVersion>, IndexError>;   // newest first
    pub fn removed_under(&self, prefix: &str, since_ms: u64) -> Result<Vec<RemovedVersion>, IndexError>;   // strictly under prefix/ ("" = all), removed_ms >= since_ms; by path, newest first within a path (§5.5.4)
    pub fn conflicts(&self) -> Result<Vec<Head>, IndexError>;                           // non-winner heads
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, IndexError>;
    /// §2.6 head fingerprint: "XXXX-XXXX" = Crockford32(BLAKE3("gclone/v1/head" ‖ every `hw` row in device order: device ‖ seq u64 BE ‖ hash)[0..5]).
    /// Equal on replicas that applied the same journal; printed by `status` and at the end of `login`.
    pub fn head_fingerprint(&self) -> Result<String, IndexError>;
    pub fn stats(&self, now_ms: u64) -> Result<VaultStats, IndexError>;
    pub fn pending_blob_names(&self) -> Result<Vec<String>, IndexError>;                // blob names referenced by pending/outbox (for gc --orphans)
    // Notes (§17.3): outbox_stuck() is Some as soon as an outbox row exists — also right after re-opening, before the first refresh;
    // vault_name() is "" until the replica applied the VaultInit op; list() reports a file that also has children as is_dir = true
    // with its head; the data-folder counter starts at 1 (`<dev16>-0001`).
}
```
Reuse lookup and "is there a live entry of this size" are not `Vault` methods: `sync::run` derives both maps from one `vault.walk("")` (§9.9). Resolving a blob to a readable object is `transfer::locate_blob` (§9.8), which needs only the backend.

Internal files: `refresh.rs` (§5.3), `commit.rs` (§5.6 incl. outbox, snapshot writer, cleanup, `finish_mutation`), `resolve.rs` (§5.2.3), `repair.rs` (§5.10), `query.rs` (SQL reads), `state/tables.rs` (`impl HeadStore for` a SQLite transaction wrapper + CRUD for `applied`, `hw`, `own`, `base_covers`, `base_covered`, `blocked`, `pending`, `outbox`). Additive (§17.3): `#[doc(hidden)] pub mod index::testing` (`apply` / `dump` / `winners` / `load_snapshot` / `drop_table` on a `Db`) lets `tests/index_props.rs` compare the SQLite `HeadStore` with `MemIndex` and inject a SQL failure. All journal operations of one `Vault` are serialised by an internal tokio mutex; SQLite and crypto work runs under `spawn_blocking`.

### 9.8 WP5 — `transfer`
The transfer layer uses `backend`, `crypto`, `format` and `ui::Progress` only — **never `index` or `state`**. Everything that needs the vault (data folder, blob records, ledger, staging) is passed in or done by the caller, so WP5 is built and tested on `MemBackend` alone, in parallel with WP4.
```rust
// ---------- src/transfer/mod.rs ----------
pub struct TransferCtx<B: Backend> { pub backend: std::sync::Arc<B>, pub keys: Keyring, pub device: DeviceId,
                                     pub progress: crate::ui::Progress, pub cancel: tokio_util::sync::CancellationToken }
impl<B: Backend> Clone for TransferCtx<B> { /* manual impl: no `B: Clone` bound */ }
#[derive(Clone, Debug)] pub struct UploadSource { pub abs: std::path::PathBuf, pub remote_path: String }
#[derive(Clone, Debug)] pub struct Uploaded { pub remote_path: String, pub entry: Entry, pub sig: StatSig, pub observed_ns: i64 }
#[derive(Clone, Debug)] pub struct BlobUpload { pub blob: Option<BlobRec> /* None: the event carries only zero-length files */, pub files: Vec<Uploaded> }
pub enum UploadEvent { Blob(BlobUpload), Failed(UploadSource, TransferError) }
/// What the plan expects at a local target path (§5.5.1 type changes, §5.7 step 3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum LocalExpect { Absent, File(StatSig), EmptyDir }

// ---------- src/transfer/source.rs ----------
pub fn open_source(path: &std::path::Path) -> std::io::Result<(std::fs::File, StatSig)>;       // O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC; regular files only
pub fn hash_file(path: &std::path::Path) -> Result<(StatSig, i64 /* observed_ns */, [u8; 32]), TransferError>;   // fstat before/after must match → else SourceChanged
pub fn lstat_sig(path: &std::path::Path) -> std::io::Result<Option<StatSig>>;                  // None if absent

// ---------- src/transfer/pack.rs ----------
pub struct SealedPack { pub blob_id: BlobId, pub bytes: bytes::Bytes, pub md5: [u8; 16], pub files: Vec<Uploaded> /* loc.blob = blob_id */ }
pub struct PackBuilder { /* owned Keyring clone, device, buffer, members — 'static, so it can be moved into spawn_blocking and returned */ }
impl PackBuilder {
    pub fn new(keys: Keyring, device: DeviceId) -> Self;
    /// Reads, hashes and seals one small file into the current pack. Returns a finished pack when PACK_TARGET is reached.
    /// Blocking. Err(SourceChanged/SourceUnreadable) leaves the builder unchanged (a source that is gone or no regular file: SourceChanged,
    /// §6.2). A file of size 0 or ≥ PACK_MEMBER_MAX is refused with
    /// TransferError::Io(InvalidInput) (builder unchanged); upload_batch never hits this — it classifies on the open descriptor (§17.3).
    pub fn add(&mut self, src: &UploadSource) -> Result<Option<SealedPack>, TransferError>;
    pub fn finish(self) -> Result<Option<SealedPack>, TransferError>;
}

// ---------- src/transfer/upload.rs ----------
/// THE upload entry point (§6.2) — the only upload function other packages call. Spawns the pipeline on the current runtime and
/// returns at once. Owns: classification by the size seen at open, zero-length files, packing, `transfers` concurrent puts, the
/// memory bound, attempts, acceptance (size + md5), stop on QuotaExceeded/RateLimited, cancellation (every wait for the backend
/// ends CANCEL_GRACE after it at the latest; no put starts after it, §5.7).
/// Events arrive in completion order; every source appears in exactly one event; the channel (capacity = transfers) closes when
/// all are accounted for. Dropping the receiver cancels the batch.
pub fn upload_batch<B: Backend>(cx: TransferCtx<B>, data_folder: Handle, sources: Vec<UploadSource> /* path order */, transfers: usize)
    -> tokio::sync::mpsc::Receiver<UploadEvent>;
/// [Blob (if any), Put…] for one event. `facts(remote_path)` returns planner-side facts only: the base stamp, and
/// Some((pair, key, rel)) when a base row is to be written. The `BaseEffectKind::Set { sig, hash, observed_ns, kind }` is built
/// HERE from `Uploaded.{sig, entry.hash, observed_ns, entry.kind}` — the caller never supplies those.
pub fn drafts_for(up: &BlobUpload, facts: &dyn Fn(&str) -> (Option<Stamp>, Option<(i64, String, String)>)) -> Vec<OpDraft>;
// pack/large-file upload helpers are private to this module.

// ---------- src/transfer/download.rs ----------
#[derive(Clone, Debug)] pub struct DownloadItem { pub head: Head, pub root: std::path::PathBuf, pub rel: String, pub expect_local: LocalExpect }
#[derive(Clone, Debug)] pub struct Downloaded { pub rel: String, pub sig: StatSig, pub observed_ns: i64, pub moved_aside: Option<std::path::PathBuf> }
/// All items must reference `blob`. Coalesces ranges, verifies, writes partial files, finishes per §5.7 steps 1–3.
/// Err(UnsafeTarget) and Err(TargetCollision) are the run-time skips of §5.7 (the caller reports them as Skip, not as failures).
/// A NotFound for blob.file_id is retried through find_by_name(blob name) (exactly one hit), else BlobMissing.
/// Results come back in INPUT order. Missing parent directories (and a missing root) are created, each level lstat-checked. Zero-length
/// entries in `items` are materialized here too. A pump-level failure (blob missing or truncated, quota, cancellation, retries used up)
/// fails every unfinished item of the group with the same error variant (§17.3). Items that share a Loc are written one after
/// another: the number of files open at a time does not grow with `items` (§5.7 step 2, §17.13). An Ok is returned only behind
/// the two barriers of its batch (§5.7 step 3a, §17.15): the caller may write the base row at once.
pub async fn download_group<B: Backend>(cx: &TransferCtx<B>, blob: &BlobRec, items: Vec<DownloadItem>)
    -> Vec<(DownloadItem, Result<Downloaded, TransferError>)>;
pub async fn materialize_empty(item: &DownloadItem) -> Result<Downloaded, TransferError>;       // zero-length files (same target rules)
/// materialize_empty for every item, in batches with the barriers of §5.7 step 3a (an Ok only behind them, §17.15); once `cancel`
/// fires, the items not written yet are Err(Cancelled) (§17.13). `materialize_empty` is this function for one item.
pub async fn materialize_empties(items: Vec<DownloadItem>, cancel: &tokio_util::sync::CancellationToken)
    -> Vec<(DownloadItem, Result<Downloaded, TransferError>)>;
/// Plaintext bytes [range) of one file to `out` (cat). Authenticates every chunk it touches. `blob` = the record of head.entry.loc.blob.
pub async fn read_range<B: Backend>(backend: &B, keys: &Keyring, blob: &BlobRec, head: &Head, range: std::ops::Range<u64>,
                                    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send)) -> Result<u64, TransferError>;
/// Download + authenticate + BLAKE3-compare without writing (check --download).
pub async fn verify_remote<B: Backend>(backend: &B, keys: &Keyring, blob: &BlobRec, head: &Head) -> Result<(), TransferError>;
/// stat(rec.file_id); if absent: find_by_name(blob name) with exactly one hit; else BlobMissing. Returns trashed objects too (caller un-trashes).
pub async fn locate_blob<B: Backend>(backend: &B, rec: &BlobRec) -> Result<ObjMeta, TransferError>;
pub fn check_target_safe(root: &std::path::Path, rel: &str) -> Result<(), TransferError>;       // no symlinked ancestors, path::validate
pub fn move_aside(target: &std::path::Path, now_ms: u64) -> std::io::Result<std::path::PathBuf>; // rename to the local conflict name
```

### 9.9 WP6 — `sync`
```rust
// ---------- src/sync/mod.rs ----------
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum Direction { Up, Down }
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum Mode { Copy, Sync }
#[derive(Clone, Debug)] pub struct SyncOpts { pub dry_run: bool, pub checksum: bool, pub force: bool, pub excludes: Vec<String>,
                                              pub max_delete: Option<u64>, pub assume_yes: bool, pub transfers: usize,
                                              pub reset_pair: bool, pub keep_pair: bool }
#[derive(Clone, Debug)] pub struct SyncRequest { pub direction: Direction, pub mode: Mode, pub local_root: std::path::PathBuf,
                                                 pub remote_prefix: String,
                                                 pub own_dirs: Vec<std::path::PathBuf> /* gclone's own directories, §5.5.3; tests pass none */,
                                                 pub opts: SyncOpts }
#[derive(Clone, Debug, Default)] pub struct Summary { pub uploaded: u64, pub downloaded: u64, pub reused: u64, pub meta_updates: u64, pub dirs_created: u64 /* MkdirRemote / MkdirLocal */,
    pub deleted_remote: u64, pub deleted_local: u64, pub conflicts: u64, pub bytes_up: u64, pub bytes_down: u64, pub hashed: u64 /* files BLAKE3-hashed */,
    pub skipped: Vec<(String, SkipReason)>, pub failed: Vec<(String, String)>, pub deletes_suppressed: bool, pub dry_run: bool, pub elapsed_ms: u64 }
impl Summary { pub fn exit_code(&self) -> i32; }                                         // 0 or 6
/// The caller has already refreshed and settled (open_ctx, §9.10) and calls Vault::finish_mutation afterwards.
/// Up with `vault.outbox_stuck()` → Err(Index(OutboxStuck)) before any work. Then: pair identity (G6) → scan + resolve_hashes
/// (one spawn_blocking; hide_excluded between the two, §5.5.3) → reuse_index → plan → guards (may ask via ui) → execute.
/// Errors (§5.7 "How a run ends"): Guard(..) (G2–G4, G6; G6 asks through ui.choose, G4 through ui.confirm — without a TTY they need
/// --reset-pair / --keep-pair resp. --yes; Guard(MaxDelete) — an explicit max_delete exceeded — is never asked about), Usage (both
/// pair flags; a bad prefix; a root that is not a directory or not UTF-8; a prefix that is, or lies under, a file; a root at or
/// inside one of `own_dirs`), Io(NotFound) (Down from a prefix that does not exist, unless the pair has base rows — §5.5.1; nothing
/// is created), Backend(QuotaExceeded | RateLimited) after committing what completed, Interrupted.
pub async fn run<B: Backend>(vault: &Vault<B>, req: &SyncRequest, ui: &crate::ui::Ui, cancel: tokio_util::sync::CancellationToken) -> Result<Summary, SyncError>;

// ---------- src/sync/scan.rs ----------
pub struct Filter { /* one ignore::gitignore::Gitignore rooted at the local root + gclone's own directories under it (keys) */ }
impl Filter { pub fn new(excludes: &[String], local_root: &std::path::Path) -> Result<Filter, SyncError>;   // reads <local_root>/.gcloneignore if present
              pub fn with_own_dirs(self, rels: &[String], fold_case: bool) -> Filter;    // root-relative; compared by key, §5.5.3
              pub fn excluded_at<'r>(&self, rel: &'r str, is_dir: bool) -> Option<&'r str>;   // shortest excluded leading part: ancestors top-down, then the path, §5.5.3
              pub fn excluded(&self, rel: &str, is_dir: bool) -> bool; }                 // excluded_at(..).is_some()
#[derive(Clone, Debug)] pub struct LocalEntry { pub rel: String, pub key: String, pub kind: EntryKind, pub sig: StatSig, pub observed_ns: i64,
                                                pub hash: Option<[u8; 32]>, pub changed_during_scan: bool }
#[derive(Clone, Debug, Default)] pub struct SkipCounts { pub symlinks: u64, pub special: u64, pub non_utf8: u64 }
#[derive(Clone, Debug)] pub struct LocalScan { pub root: std::path::PathBuf, pub root_ino: u64, pub root_birth_ns: i64 /* 0 if unavailable */, pub fold_case: bool,
    pub entries: Vec<LocalEntry> /* sorted by key */, pub failed_dirs: Vec<String>, pub skipped_paths: Vec<String> /* symlinks + special files, rel */,
    pub collisions: Vec<String> /* keys */, pub excluded: Vec<String> /* what the filter pruned, rel */, pub skipped: SkipCounts, pub root_missing: bool }
pub fn probe_fold_case(root: &std::path::Path) -> std::io::Result<bool>;                 // §5.1; works on read-only roots
pub fn scan(root: &std::path::Path, filter: &Filter) -> Result<LocalScan, SyncError>;    // synchronous (parallel walker inside)
#[derive(Clone, Debug)] pub struct RemoteRow { pub rel: String, pub key: String, pub head: Head }
pub fn remote_rows<B: Backend>(vault: &Vault<B>, prefix: &str, filter: &Filter, fold_case: bool) -> Result<(Vec<RemoteRow>, Vec<String> /* collisions */), SyncError>;   // each row judged by its own spelling
pub fn remote_rows_unfiltered<B: Backend>(vault: &Vault<B>, prefix: &str, fold_case: bool) -> Result<Vec<RemoteRow>, SyncError>;   // sorted by key; collisions still in
pub fn remote_collisions(rows: &mut Vec<RemoteRow>) -> Vec<String>;                      // removes the colliding rows, returns their keys (G5)
/// §5.5.3 "one answer per key": removes from all three inputs every key at or under one that any spelling excludes.
pub fn hide_excluded(filter: &Filter, local: &mut LocalScan, remote: &mut Vec<RemoteRow>, base: &mut Vec<BaseRow>);
/// Built once per run from `vault.walk("")`: live winners that have a `loc`, by content, and the set of their sizes.
pub struct ReuseIndex { pub by_content: std::collections::HashMap<(u64, [u8; 32]), Head>, pub sizes: std::collections::HashSet<u64> }
pub fn reuse_index<B: Backend>(vault: &Vault<B>) -> Result<ReuseIndex, SyncError>;
/// Fills LocalEntry.hash (and refreshes sig/observed_ns) where §5.4 requires it; synchronous, `threads` scoped threads.
/// Returns the number of files hashed.
pub fn resolve_hashes(scan: &mut LocalScan, base: &[BaseRow], remote: &[RemoteRow], sizes: &std::collections::HashSet<u64>,
                      checksum: bool, threads: usize) -> Result<u64, SyncError>;

// ---------- src/sync/plan.rs ----------  (pure: no I/O, no closures over the vault)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason { RemoteNewer, RemoteOnly, RemoteDeleted, LocalChanged, LocalOnly, ScanError, KeyCollision, ChangedDuringUpload,
                      UnsafeTarget, Unsupported(String), Failed(String) }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Upload        { rel: String, key: String, remote_path: String, base: Option<Stamp>, size: u64, conflict: bool },
    Reuse         { rel: String, key: String, remote_path: String, base: Option<Stamp>, from: Head, sig: StatSig, observed_ns: i64, hash: [u8; 32] },
    MkdirRemote   { rel: String, key: String, remote_path: String, base: Option<Stamp> },
    SetRemoteMeta { rel: String, key: String, remote_path: String, base: Stamp, entry: Entry, sig: StatSig, observed_ns: i64 },
    DelRemote     { key: String, remote_path: String, base: Stamp },
    Download      { key: String, rel: String, head: Head, expect_local: LocalExpect, keep_local: bool /* row 7: move the local file aside first */ },
    MkdirLocal    { key: String, rel: String, head: Head, expect_local: LocalExpect },
    SetLocalMeta  { key: String, rel: String, head: Head, expect_local: StatSig },
    DelLocal      { key: String, rel: String, expect_local: StatSig, is_dir: bool },
    RecordBase    { key: String, rel: String, sig: StatSig, observed_ns: i64, hash: [u8; 32], kind: EntryKind, remote_stamp: Stamp },
    ForgetBase    { key: String },
    Skip          { key: String, rel: String, reason: SkipReason },
}
/// One file↔directory type change (§5.5.1): indices into Plan.actions. `first` must succeed before `then` may run.
#[derive(Clone, Debug, PartialEq, Eq)] pub struct TypeChange { pub first: Vec<usize>, pub then: Vec<usize> }
pub struct PlanInput<'a> { pub direction: Direction, pub mode: Mode, pub force: bool, pub remote_prefix: &'a str,
                           pub local: &'a LocalScan, pub remote: &'a [RemoteRow], pub remote_collisions: &'a [String],
                           pub base: &'a [BaseRow] /* already filtered by the Filter, §5.5.3 */,
                           pub reuse: &'a std::collections::HashMap<(u64, [u8; 32]), Head> }     // plain data: PlanInput is Send + Sync
#[derive(Clone, Debug, Default)] pub struct Plan { pub actions: Vec<Action> /* sorted by key */, pub groups: Vec<TypeChange>, pub deletes: u64, pub dest_total: u64,
                                                   pub suspicious_reverts: usize, pub changed_local: usize,
                                                   pub keep_dirs: Vec<String> /* local dirs with content that face a remote Dir marker: never pruned, §5.5.1 */ }
pub fn plan(input: &PlanInput<'_>) -> Plan;                                              // §5.5 exactly; asserts base.is_some() ⇒ remote_path == R.path
pub fn check_guards(plan: &Plan, input: &PlanInput<'_>, max_delete: Option<u64>) -> Result<(), GuardKind>;   // G2–G4 (G4 → DeleteLimit by the default thresholds: the caller may confirm; MaxDelete for max_delete = Some(n): a hard limit)

// ---------- src/sync/exec.rs ----------
/// §5.7. Ends at its final commit(); does NOT resolve conflicts, compact or clean up (Vault::finish_mutation does, once, in the CLI layer).
pub async fn execute<B: Backend>(vault: &Vault<B>, pair: i64, req: &SyncRequest, plan: Plan, ui: &crate::ui::Ui,
                                 cancel: tokio_util::sync::CancellationToken) -> Result<Summary, SyncError>;

// ---------- src/sync/remote_ops.rs ----------  (index-only, §5.5.4; each commits one segment via commit_ops and nothing more)
pub async fn mkdir<B: Backend>(vault: &Vault<B>, path: &str) -> Result<bool, SyncError>;   // true = created, false = it existed
pub async fn rm<B: Backend>(vault: &Vault<B>, paths: &[String], recursive: bool) -> Result<u64, SyncError>;
pub struct Moved { pub to: String /* where the source is now */, pub entries: u64, pub replaced: u64 /* live files replaced; only with force */ }
pub async fn mv<B: Backend>(vault: &Vault<B>, from: &str, to: &str, force: bool) -> Result<Moved, SyncError>;   // into `to` if it is a directory ("" = the root); §5.5.4
pub async fn restore_candidates<B: Backend>(vault: &Vault<B>, path: &str, now_ms: u64) -> Result<Vec<RemovedVersion>, SyncError>;   // within RESTORE_WINDOW, newest first
pub async fn restore<B: Backend>(vault: &Vault<B>, path: &str, version: &RemovedVersion) -> Result<(), SyncError>;   // locate_blob / untrash first
pub struct Restorable { pub version: RemovedVersion /* the newest restorable one of its path */, pub live: bool /* the path has a winner now */ }
pub async fn restorable_under<B: Backend>(vault: &Vault<B>, prefix: &str, now_ms: u64) -> Result<Vec<Restorable>, SyncError>;   // files strictly under prefix/, by path
pub struct Restored { pub restored: u64, pub skipped: Vec<(String, String)> /* (path, why) */ }
pub async fn restore_many<B: Backend>(vault: &Vault<B>, versions: &[RemovedVersion]) -> Result<Restored, SyncError>;   // one segment; skips and reports what cannot go back (§5.5.4)

// ---------- src/sync/gc.rs, check.rs ----------
#[derive(Clone, Debug, Default)] pub struct GcReport { pub dead_blobs: u64, pub dead_bytes: u64, pub orphans: u64, pub orphan_bytes: u64,
                                                      pub purged: u64, pub purged_bytes: u64, pub purge_skipped: Vec<String>, pub dry_run: bool }
pub async fn gc<B: Backend>(vault: &Vault<B>, dry_run: bool, orphans: bool, purge: bool) -> Result<GcReport, SyncError>;   // §5.9; the caller checked the refresh verdict
#[derive(Clone, Debug, Default)] pub struct CheckReport { pub checked: u64, pub missing: Vec<String>, pub mismatched: Vec<String>,
                                                         pub untrashed: Vec<String>, pub listed_late: u64, pub orphans: u64,
                                                         pub orphans_recent: u64 /* of `orphans`: younger than ORPHAN_GRACE (§5.9, §17.20) */, pub differing: Vec<String> }
impl CheckReport { pub fn ok(&self) -> bool; }
pub async fn check_blobs<B: Backend>(vault: &Vault<B>) -> Result<CheckReport, SyncError>;       // absence is confirmed by ID before it is reported (§5.9)
pub async fn check_local<B: Backend>(vault: &Vault<B>, local_root: &std::path::Path, prefix: &str) -> Result<CheckReport, SyncError>;
pub async fn check_download<B: Backend>(vault: &Vault<B>, prefix: &str, progress: crate::ui::Progress) -> Result<CheckReport, SyncError>;
```
Additive public items (§17.4; no signature above changed): `Filter: Clone + Debug`; `sync::filter_base(Vec<BaseRow>, &Filter) -> Vec<BaseRow>`; `Action::key()`, `Action::is_delete()`; `impl Display for SkipReason` (the text of skip events). `CheckReport::ok()` = nothing missing, mismatched or differing. `check_local` honours the root's `.gcloneignore` and reports key collisions and unreadable directories as differences.

### 9.10 WP7 — `config`, `cli`   (`ui.rs` is WP0's, §9.3)
```rust
// ---------- src/config.rs ----------
#[derive(Clone, Debug)] pub struct Paths { pub config_dir: std::path::PathBuf, pub state_root: std::path::PathBuf }
impl Paths { pub fn resolve() -> Result<Paths, ConfigError>;                            // env overrides, §8.1
             pub fn config_file(&self) -> std::path::PathBuf;                            // <config>/config.json
             pub fn secrets_file(&self) -> std::path::PathBuf;                           // <state root>/secrets.json (§8.1: NOT under <config>)
             pub fn token_file(&self) -> std::path::PathBuf;                             // <state root>/token.json — per login, not per vault
             pub fn state_dir(&self, vault_id_hex: &str) -> std::path::PathBuf;
             pub fn db_file(&self, v: &str) -> std::path::PathBuf;
             pub fn index_cache_dir(&self, v: &str) -> std::path::PathBuf; }
#[derive(Serialize, Deserialize, Clone, Debug)] #[serde(tag = "kind", rename_all = "lowercase")]
pub enum BackendCfg { Drive, Dir { path: std::path::PathBuf } }
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config { pub version: u32, pub vault_id: String, pub vault_name: String, pub backend: BackendCfg,
                    #[serde(default, skip_serializing_if = "Option::is_none")] pub auth_url: Option<String>,   // Drive vaults: the Worker URL (not a
                                                                                         // secret; survives `logout`, §2.2). None for directory vaults
                    pub root_id: String, pub index_id: String, pub data_id: String }
#[derive(Serialize, Deserialize, Clone)] pub struct KeyEntry { pub epoch: u32, pub key: String }
/// The four login fields are None for directory vaults (never empty strings); each is `#[serde(default, skip_serializing_if = "Option::is_none")]`.
#[derive(Serialize, Deserialize, Clone)]
pub struct Secrets { pub version: u32, pub auth_url: Option<String>, pub refresh_token: Option<String>, pub email: Option<String>,
                     pub consent_ms: Option<u64>,
                     #[serde(default)] pub refresh_expires_at_ms: Option<u64>,           // §2.4 expiring-grant check
                     #[serde(default, skip_serializing_if = "AuthClient::is_legacy")] pub client: AuthClient,   // §8.2: absent = Legacy (a login from before 0.2.0)
                     #[serde(default)] pub keys: Vec<KeyEntry>,                          // [] = signed in but not unlocked yet; then the cached master key
                     #[serde(default)] pub min_epoch: u32 }                              // Debug is NOT derived; no OAuth client id/secret exists on a device
impl Secrets { pub fn has_login(&self) -> bool;                                          // refresh_token is Some and non-empty
               /// The ONLY place a stored auth_url is validated (never at load, §8.2): auth_url None → NotLoggedIn; else AuthEndpoints::new.
               /// Callers invoke it only when has_login().
               pub fn endpoints(&self) -> Result<AuthEndpoints, ConfigError>;
               pub fn keyring(&self, vault_id: [u8; 16]) -> Result<Keyring, ConfigError>; }   // keys empty → Locked; a CryptoError becomes ConfigError::Crypto
impl Config { pub fn load(p: &Paths) -> Result<Config, ConfigError>;                     // NotConfigured if absent
              pub fn save(&self, p: &Paths) -> Result<(), ConfigError>;
              pub fn delete(p: &Paths) -> Result<(), ConfigError>; }                     // logout --forget; absent = Ok
pub trait SecretStore: Send + Sync { fn load(&self) -> Result<Option<Secrets>, ConfigError>;   // None = no secrets file (never logged in, or logged out)
                                     fn save(&self, s: &Secrets) -> Result<(), ConfigError>;
                                     fn delete(&self) -> Result<(), ConfigError>; }      // logout; absent = Ok; also removes the temp copies of an interrupted save
/// 0600 JSON via util::write_atomic in a 0700 directory (util::create_dir_private). `load` is strict (§8.1): directory and file must
/// pass util::is_private, the file is opened O_NOFOLLOW — else ConfigError::InsecurePermissions(path). It checks JSON and `version`,
/// and does NOT validate auth_url (§8.2). `save` creates the directory when it is missing and refuses (InsecurePermissions) to write
/// into an existing one that is not private — every later `load` would fail there (§17.5); `login` makes the same check on the
/// state root before it signs in.
pub struct FileSecretStore { pub path: std::path::PathBuf }
impl SecretStore for FileSecretStore { /* … */ }
pub fn secret_store(p: &Paths) -> Box<dyn SecretStore>;                                  // MVP: always FileSecretStore

// ---------- src/cli/mod.rs, context.rs ----------
pub async fn run() -> i32;                     // parse (clap derive), dispatch, map errors → exit code (error::exit_code), install Ctrl-C handler
#[derive(clap::Args, Clone, Debug)] pub struct GlobalOpts { pub verbose: u8, pub quiet: bool, pub json: bool }
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum LockMode { Exclusive, TryShared }
#[derive(Copy, Clone, Debug, PartialEq, Eq)] pub enum RefreshPolicy {
    Required,     // refresh errors (Gap, Rollback, …) fail open_ctx                      — mutating commands
    Tolerant,     // the Result is stored in Ctx.refresh and the command continues        — read-only commands, gc
                  // EXCEPT a login failure (exit 4: IndexError::VaultNotVisible, BackendError::AppNotAuthorized, and every
                  // BackendError::Auth(_) other than AuthError::Network / AuthError::Io), which fails open_ctx like `Required`
                  // does — its fix is `gclone login`, not the replica (§17.5). An auth Worker that cannot be reached
                  // (Network) or a local I/O error on the way to a token (Io) says nothing about the login: tolerated
                  // like an unreachable store (§17.9)
    Skip }        // no refresh                                                           — repair (Vault::repair refreshes by itself)
#[derive(Copy, Clone, Debug)] pub struct OpenOpts { pub lock: LockMode, pub refresh: RefreshPolicy,
    pub settle: bool,          // after a successful refresh under the exclusive lock: vault.commit() → vault.resolve_conflicts() (§5.8)
    pub transfers: usize }     // reaches DriveConfig.transfers; TRANSFERS_DEFAULT for commands without --transfers
pub struct Ctx { pub paths: Paths, pub config: Config, pub vault: Vault<AnyBackend>, pub ui: Ui, pub lock: Option<StateLock>,
                 pub refresh: Option<Result<RefreshReport, IndexError>>,   // None: skipped, or the TryShared lock was busy
                 pub commit_blocked: Option<String>,                       // settle hit IndexError::OutboxStuck (not fatal by itself)
                 pub cancel: tokio_util::sync::CancellationToken, pub tokens: Option<std::sync::Arc<TokenProvider>> }
impl Ctx { /// For commands that must publish index changes (copy/sync up, mkdir, rm, mv, restore): Err(IndexError::OutboxStuck) if blocked.
           pub fn require_commit(&self) -> Result<(), IndexError>; }
/// Loads config + secrets, builds the backend, takes the lock, opens the vault, then applies `o.refresh` and `o.settle`.
/// In TryShared mode a busy lock means: no refresh, no settle, replica used as is — opened with Db::open_shared and
/// Vault::open_unlocked, which write nothing (§8.3); with the lock: Db::open and Vault::open.
/// Errors before anything is opened (all exit 4, §2.8), checked in this order — the same for BOTH backends unless stated:
///   no config.json                                      → ConfigError::NotConfigured
///   secrets file with unsafe permissions                → InsecurePermissions
///   no secrets file (e.g. after `logout`)               → NotLoggedIn   (directory vault: the message names `login --vault-dir <path>`)
///   Drive vault whose secrets hold no refresh token     → NotLoggedIn
///   secrets with keys == []                             → Locked
pub async fn open_ctx(g: &GlobalOpts, o: OpenOpts) -> anyhow::Result<Ctx>;
/// The part of open_ctx after the backend exists (§17.20): the replica opened under `lock` — or, with `None` or a busy TryShared,
/// as it is (Db::open_shared + Vault::open_unlocked, §8.3). `gclone web` keeps a lock-less vault; per refresh it takes the lock itself
/// (state::try_lock_existing) and calls `open_replica(.., locked = true)`, the second half of this function.
pub(crate) async fn open_vault(paths: &Paths, config: &Config, backend: std::sync::Arc<AnyBackend>, keys: Keyring, lock: Option<LockMode>)
    -> anyhow::Result<(Vault<AnyBackend>, Option<StateLock>)>;
/// Drive vaults: drive_backend(secrets.endpoints()?, .., secrets.client, .., cache = true).
pub fn build_backend(cfg: &Config, secrets: &Secrets, paths: &Paths, transfers: usize)
    -> anyhow::Result<(AnyBackend, Option<std::sync::Arc<TokenProvider>>)>;
/// The Drive backend for a login alone — `login` needs it before a config exists (discovery, vault creation). `cache`: true = the
/// TokenProvider uses paths.token_file(); false = no cache file at all. `login` ALWAYS passes false (§2.6: an access token obtained
/// while signing in must never reach token.json); every other command passes true. Honours the debug-only GCLONE_TEST_DRIVE_*
/// switches of §7.1 (as build_backend does). `client`: the OAuth client `refresh_token` belongs to (Secrets::client; §2.3 /refresh).
pub fn drive_backend(ep: AuthEndpoints, refresh_token: &str, client: AuthClient, paths: &Paths, transfers: usize, cache: bool)
    -> anyhow::Result<(crate::backend::drive::DriveBackend, std::sync::Arc<TokenProvider>)>;
/// Keyfile KDF parameters for `login` and `passwd`: KdfParams::default() (256 MiB, t = 3, p = 1) — or, only in builds with debug
/// assertions and only when GCLONE_TEST_FAST_KDF=1, { m_kib: 8192, t: 1, p: 1 } (§7.1).
pub fn kdf_params() -> KdfParams;
/// A passphrase for setting (prompt twice / generate on empty input / --passphrase-file) or for entering (prompt / file), per §2.6.
pub fn read_new_passphrase(ui: &Ui, file: Option<&std::path::Path>) -> anyhow::Result<Passphrase>;
pub fn read_passphrase(ui: &Ui, file: Option<&std::path::Path>) -> anyhow::Result<Passphrase>;
// One file per command, each exposing:  pub async fn run(g: &GlobalOpts, args: <Cmd>Args) -> anyhow::Result<i32>;
// with `#[derive(clap::Args, Clone, Debug)] pub struct <Cmd>Args` in the same file (LoginArgs, LogoutArgs, …). Two files host two
// commands (§9.2 lists no sync.rs / tree.rs): copy.rs has `run(g, CopyArgs)` and `run_sync(g, SyncArgs)` (SyncArgs flattens
// CopyArgs and adds --max-delete / --yes); ls.rs has `run(g, LsArgs)` and `run_tree(g, TreeArgs)`. cli/mod.rs holds
// `#[derive(clap::Parser)] pub struct Cli { global: GlobalOpts, command: Command }` and `#[derive(clap::Subcommand)] pub enum Command`.
// Additive public items of WP7 (§17.5): Secrets::empty(), Secrets::set_keys(&Keyring), Config::vault_id_bytes(), Config::handles(),
// OpenOpts::read_only() / OpenOpts::mutating(), Ctx::report_refresh() (the "not refreshed" note, or the refresh verdict as a warning),
// `LoginArgs: Default`.
// 0.3.0 (§17.20): cli/web.rs — `WebArgs { port: Option<u16> /* 1.. */, no_browser: bool }`, `run`; `cli::SERVING` (Ctrl-C cancels quietly, exit 0);
// context.rs — `open_vault`, `open_replica`, `NOT_REFRESHED`, `stale_text`, `corrupt_text` (the texts of report_refresh, shared with the page), `login_failure` pub(crate).

// ---------- src/cli/login.rs ----------   (besides `run`: the pure decisions of §2.4/§2.6, unit-tested without I/O)
/// §2.6 step 0 — which backend this `login` uses. `configured` = config.json's backend, if the device is attached.
///   vault_dir = Some(d): configured None or Dir{path == d} → Dir{d};  configured Dir{other} or Drive → usage error
///   vault_dir = None:    configured Dir{p} and !auth_url_given → Dir{p};  configured Dir and auth_url_given → usage error;
///                        configured Drive or None → Drive
/// The usage error (SyncError::Usage) names what the device is attached to and `gclone logout --forget`. Paths are compared
/// after canonicalisation by the caller.
pub fn login_backend(configured: Option<&BackendCfg>, vault_dir: Option<&std::path::Path>, auth_url_given: bool) -> anyhow::Result<BackendCfg>;
#[derive(Clone, Debug, PartialEq, Eq)] pub enum VaultChoice { Create, Attach(usize /* index into `found` */), Ask }
/// §2.6 step B.2. `configured` = config.json's vault id when the device is attached but has no cached key. Errors: the configured or
/// requested vault is not among `found`; several vaults without --vault-id when not on a TTY.
pub fn choose_vault(found: &[FoundVault], configured: Option<[u8; 16]>, new_vault: bool, vault_id: Option<[u8; 16]>, tty: bool)
    -> anyhow::Result<VaultChoice>;
/// §2.4 expiring-grant check: Ok(None) = normal login; Ok(Some(expires_at_ms)) = time-limited and allowed; Err = refused (exit 4).
pub fn expiring_login_decision(grant: &LoginGrant, allow_expiring: bool, now_ms: u64) -> anyhow::Result<Option<u64>>;
/// §2.4: true = do not try to open a browser (the address and the code are printed either way): --no-browser, SSH_CONNECTION /
/// SSH_TTY set, or Linux without DISPLAY and WAYLAND_DISPLAY.
pub fn want_headless(no_browser: bool, env: &dyn Fn(&str) -> Option<String>, is_linux: bool) -> bool;
#[derive(Clone, Debug, PartialEq, Eq)] pub enum RaceOutcome { Alone, Won { other: [u8; 16] }, Lost { winner: usize /* index into `found` */ } }
/// §2.6 "two first devices": `found` is a fresh discovery plus one's own vault; uses index::creation_winner.
pub fn creation_race(found: &[FoundVault], mine: [u8; 16]) -> RaceOutcome;
```

---

## 10. Command flows (glue owned by WP7; algorithms are owned by the modules named)

`open_ctx{lock, refresh, settle}` below abbreviates `open_ctx(g, OpenOpts{..})` (§9.10). *Settle* = `vault.commit()` (leftover staged ops, §5.8) → `vault.resolve_conflicts()`, run by `open_ctx` after a successful refresh; an `OutboxStuck` there is kept in `ctx.commit_blocked`.
```
login:   Paths::resolve; secrets = store.load(); config = Config::load() (both optional)                       — §2.6 is the authority
         0. backend kind = login_backend(config.backend, --vault-dir, AUTH_URL given?)     (usage error on a mix)
               Dir{p}: backend = DirBackend::open(p); skip A
         A. sign in:  auth_url = auth::resolve_auth_url(arg, env GCLONE_AUTH_URL, secrets.auth_url.or(config.auth_url))
               stored refresh token for the same auth_url with client == Device, and TokenProvider.force_refresh() is Ok → keep it
               (a stored login of the legacy client is always replaced: a note on stderr, then the sign-in — §2.6 A.2)
               else auth::login_interactive(http, ep, InteractiveOpts{ no_browser: want_headless(..), open, print })     — the device grant, §2.4
                    → expiring_login_decision (stop here unless --allow-expiring-login)
                    → no config.json: save secrets{auth_url, refresh_token, client: Device, email, consent_ms, refresh_expires_at_ms, keys: []} now
                      (config.json exists: saved only once the attached vault was seen with the new login, §2.6 A.4;
                       no config.json and the sign-in replaced a legacy login: saved only once a vault was found or with --new-vault)
               backend = drive_backend(ep, refresh_token, client, paths, TRANSFERS_DEFAULT, cache = false); tokens.prime(access token of the grant)
               (no TokenProvider of `login` has a cache file; after an interactive sign-in token.json is removed, whatever B does)
         B. vault:
               config and cached keys exist → Vault::verify_visible(&backend, stored handles)
                                              Ok  → save the new token → "Signed in again. Vault unchanged."     (no lock, no index work)
                                              Err → VaultNotVisible / VaultTrashed; secrets.json untouched
               else found = Vault::discover(&backend) → choose_vault(found, config.vault_id, --new-vault, --vault-id, tty)
                    → config.json exists and step A signed in: save secrets{.., keys: []} now (the attached vault is visible)
               (VaultNotVisible with a kept login — A.2 — carries the `gclone logout` hint of §2.8; after a fresh sign-in — A.3 —
                the fresh-login text of §2.8: nothing was changed, wrong account or another OAuth client)
           CREATE: passphrase (ui prompts or --passphrase-file; Passphrase::set_checked / generate) → vault_id, MasterKey::generate, Keyring
                   → spawn_blocking: seal_keyfile(KeyfilePayload::from_keyring(.., generation 1, ..), pass, kdf_params()) + open_keyfile self-test
                   → lock_exclusive → Db::open → Vault::create(backend, db, keys, CreateParams{.., keyfile})
                   → save config (handles, auth_url), then secrets (keys)
                   → unless --new-vault: creation_race(Vault::discover(&backend) + own, vault_id):
                        Lost → backend.trash(own root), delete config + state dir, drop the keys → ATTACH(winner)
                        Won  → warning naming the other vault
                   → print (§7.3)
           ATTACH: keyfiles = the first KEYFILE_TRY_MAX of found.keyfiles (none → exit 3) → get_all each (≤ KEYFILE_MAX)
                   → passphrase (≤ 3 prompts, or --passphrase-file)
                   → spawn_blocking: open_keyfile per candidate, highest generation first; each (keyfile, passphrase) pair at most once,
                     non-WrongKey failures drop the candidate; WrongKey on all that remain → ConfigError::WrongPassphrase
                   → payload.vault_id == found.vault_id → Keyring in memory (nothing saved yet)
                   → lock_exclusive → Db::open → Vault::open → refresh()
                        (Gap / Rollback: skip the next line, save, and print the verdict with the `gclone repair` advice, §2.6)
                   → commit_ops([Device{id, name}]) unless vault.devices() already has this id with this name → vault.finish_mutation()
                   → save config (handles, auth_url), then secrets (keys, min_epoch)      — only now is the device connected
                   → print, including vault.head_fingerprint() and the file count (§2.6)
logout:  no secrets.json (and no --forget) → remove token.json and temp leftovers, "not signed in", exit 0.
         config present → lock_exclusive(state dir)
         --revoke: Drive vault only (else usage error) → load secrets, endpoints → confirm (ui.confirm or --yes)
         --forget: Db::open → db.pending_count() > 0 (unpublished work would be lost) → confirm or --yes; declined → exit 5,
                   nothing revoked, nothing removed
         --revoke: only now auth::revoke(http, ep, refresh_token)      — after every question that can stop the command
                   (Ok(true) revoked, Ok(false) already invalid; Err → stop, nothing deleted)
         remove token.json and the temp leftovers of token.json / secrets.json; then store.delete() (secrets.json last);
         --forget: Config::delete + remove <state>/<vault_id>/ (after releasing the lock)
passwd:  open_ctx{Exclusive, Required, no settle} → new passphrase (set rules, §2.6)
         → generation = max generation named by vault.keyfiles() (0 if none) .checked_add(1); None → error naming the object (§2.7)
         → spawn_blocking: seal_keyfile(KeyfilePayload::from_keyring(vault.keys(), generation, device name, now), pass, kdf_params())
                           + open_keyfile self-test
         → vault.replace_keyfile(&kf) → print (§2.7)           (no index change: finish_mutation is not called)
copy/sync: parse_arg ×2 (exactly one Remote) → open_ctx{Exclusive, Required, settle, transfers} → sync::run → vault.finish_mutation()
         → print Summary → exit code          (sync::run itself refuses an upload while the outbox is stuck; downloads proceed)
         (-n: open_ctx with settle = false and no finish_mutation — a dry run publishes nothing, leftovers of an interrupted run
          included; after a download an OutboxStuck from finish_mutation is a warning, not a failure — §17.5)
         (Err from sync::run — guard, quota / rate limit, Interrupted, §5.7 "How a run ends" — carries no Summary; execute has already
          committed what completed, so the flow goes straight to error::exit_code. restore passes backend.now_ms() to restore_candidates.)
mkdir/rm/mv/restore: open_ctx{Exclusive, Required, settle} → ctx.require_commit()? → sync::remote_ops::* → vault.finish_mutation()
         (restore --list: open_ctx{TryShared, Tolerant, no settle}; restore of one version → remote_ops::restore, of several →
          restore_many, exit 6 if any was skipped; a Guard error of copy/sync is wrapped by copy.rs::explain_guard — the text
          changes, the exit code does not; dispatch refuses --json for every command but copy and sync, §17.14)
ls/tree/cat/about/status/check: open_ctx{TryShared, Tolerant, no settle} → queries / transfer::read_range(backend, keys, vault.blob(..), ..) / sync::check_*
         a refresh verdict in ctx.refresh (Gap, Rollback) is printed as a warning; the command continues on the replica
         (a login failure — exit 4 — is not tolerated: open_ctx fails with it, §9.10; an unreachable auth Worker is not a
          login failure: warning, replica)
web:     open_ctx{TryShared, Tolerant, no settle} (errors and exit codes of `ls`) → keep backend, keyring, paths, config; drop the vault and the lock
         → open_vault(.., lock = None) for queries and downloads + Db::open_shared for the ledger → web::bind(port) → web::App::new(..)
         → DeviceGuard::new (config, secrets digest, state.db identity) — asked per request, per refresh, and once a second
         → app.login_url(): headless → print it; else write the 0600 launch page and hand its PATH to the launcher (never the link)
         → stdin a terminal: SIGTTIN ignored, a line makes a new link and a new session
         → SERVING = true; web::serve(listeners, app, token) until Ctrl-C → exit 0, or until the guard trips → the text, exit 4
         each POST /api/refresh: guard → state::try_lock_existing → guard → open_replica(locked) → vault.refresh() → drop both (§7.4)
gc:      open_ctx{Exclusive, Tolerant, no settle} → refuse (exit 3) unless ctx.refresh is Some(Ok(r)) with r.blocked_young == 0
         → sync::gc(vault, dry_run, orphans, purge)          (publishes nothing: works on a full Drive and with a stuck outbox)
repair:  open_ctx{Exclusive, Skip, no settle} → vault.repair(accept_loss)          (Vault::repair refreshes by itself and tolerates Gap/Rollback)
probe:   build_backend → backend::drive::probe::run_probes → print one line per row
every command maps errors through error::exit_code and prints the §2.8 text for AuthError / ConfigError / IndexError
(`AuthError::Expired` anywhere — a refresh the Worker answered with invalid_grant — is exit 4 with "run `gclone login`")
```
`Vault::finish_mutation()` (commit → resolve_conflicts → maybe_compact → cleanup_index, §5.6) is called **exactly once**, by the command flows above that publish index changes (`login` when it attaches a device, `copy`, `sync`, `mkdir`, `rm`, `mv`, `restore`); `sync::execute` and `remote_ops` never call it. `gc`, `repair`, `passwd`, `logout`, a `login` that only signs in again or creates the vault (`Vault::create` commits its own first segment), and the read-only commands do not call it.

`about` additionally calls `backend.about()` (trash usage; gclone's share = `VaultStats.trashed_blob_bytes`) and reads both ledger directions (warnings at `LEDGER_WARN` / `LEDGER_DL_WARN`); `status` prints the account e-mail and auth Worker URL from `secrets.json`, token age from `TokenProvider::last_refresh_ms`, the head fingerprint (`vault.head_fingerprint()`, §2.6) with the file count, devices from `vault.devices()`, `db.pending_count()`, `vault.outbox_stuck()`, the 150-day warning, "Login expires in N days" when `refresh_expires_at_ms` is set, and — Drive backend, when the lock was obtained — the other-vault warning of §2.6 (one `find_by_name(DESCRIPTOR_NAME)`).

---

## 11. Extension points kept open (no MVP code beyond the hook)
- `config::SecretStore` → macOS keychain, or a store that keeps the master key wrapped and asks for the passphrase per session.
- `Header.key_epoch`, `Keyring` with several epochs, local `min_epoch`, `KeyfilePayload.keys` as a list → `rotate` / re-key (a new keyfile generation then carries the new epoch).
- `auth::AuthEndpoints` + the Worker's `/device/poll`/`/refresh` JSON → DPoP-bound refresh tokens or another identity check without touching callers.
- `Header.flags` bit 0 → size padding, and a second `suite` (AES-GCM): both are usable for **Data** streams too because `Loc` records `suite` and `flags` (§4.4); v1 readers answer `Unsupported` ("needs a newer gclone"), never "tampered". Index `codec` byte 1 → zstd. For **index objects** every such step — a new suite, a flag, stream type 0x04, a later key epoch, codec 1, a second body version — stops a v1 device's refresh with `UnsupportedObject` (§4.6) instead of being skipped as damage, so a later release may start writing them into an existing vault without first raising `VaultInit.format`: old devices stop, they do not diverge.
- Stream type 0x04 + the `GCBLOB01` footer → blob manifest trailer and `repair --from-blobs` (§4.5).
- Random-access `Opener::open_chunk` + `transfer::read_range` → FUSE mount (reads); writes would go through a local write-back cache into new immutable blobs.
- `Backend` trait → other stores.

---

## 12. Work packages (disjoint file ownership)

WP0 lands first (about a day, one engineer). It creates **every** `src/` file of §9.2 containing exactly the public items of §9.3–§9.10 with `todo!()` bodies — including every derive stated there (`Clone` on the key types, no `Debug` on secret-bearing types) — and **fully implements its own files, `src/ui.rs` included**, so `cargo check --all-targets` passes from day one and no package's tests wait for the CLI package. After that each file has exactly one owner and WP1–WP7 proceed against the signatures in this spec. **WP8 (the auth Worker, `worker/**`, TypeScript) shares no code and no build step with the Rust crate**: it depends only on §2.2–§2.3 and §16, needs nothing from WP0 beyond the repository skeleton (root `.gitignore`, README pointer) and starts as soon as that exists. It **produces** one file the Rust side reads: `worker/test/contract.json` (§16.5), which WP3's `tests/auth.rs` checks `FakeDrive` and the Rust auth client against — so WP3's acceptance run needs WP8 finished. Nobody but WP0 edits `Cargo.toml`, `src/lib.rs`, `src/types.rs`, `src/error.rs`, `src/consts.rs`, `src/util.rs`, `src/ui.rs`; a needed change to those is requested from WP0 and recorded in an "Errata" section appended to this file.

| WP | Scope | Files (exclusive) | Needs at run time (tests) |
|---|---|---|---|
| **WP0** Skeleton + shared | manifest, shared types, errors, constants, utils (incl. date/time), path rules, UI, test PRNG, stubs for **every** Rust source file of §9.2 with the signatures of §9.3–§9.10, README (toolchain note, pointer to `worker/README.md`, manual probe checklist §2.9) | `Cargo.toml`, `Cargo.lock`, `.gitignore` (root), `README.md`, `src/lib.rs`, `src/main.rs`, `src/consts.rs`, `src/types.rs`, `src/error.rs`, `src/util.rs`, `src/path.rs`, `src/ui.rs`, `tests/support/mod.rs`, `tests/support/prng.rs` | — |
| **WP1** Crypto + formats | §4 entirely; passphrase rules and keyfile format of §2.6 | `src/crypto/{mod,keys,stream,kdf}.rs`, `src/format/{mod,index,blob,keyfile,descriptor}.rs`, `tests/crypto_format.rs`, `tests/vectors/stream_v1.json` | WP0 |
| **WP2** Backend trait + fakes | §9.5 incl. the conformance suite | `src/backend/{mod,mem,dir,flaky,any,conformance}.rs`, `tests/backend_conformance.rs` | WP0 (the `Drive` arm of `AnyBackend` only delegates) |
| **WP3** Drive + auth client | §2.2, §2.4 (device side of the login, token handling), the fake auth Worker per §2.3, §6.2 (Drive protocol), §6.3–6.5, §6.4.1, the automatable probes of §2.9 | `src/backend/drive/{mod,api,upload,errors,pacer,probe}.rs`, `src/auth/{mod,login,token}.rs`, `tests/support/fake_drive.rs`, `tests/drive_http.rs`, `tests/auth.rs` | WP0, WP2 (`backend::conformance::run` against the fake server), **WP8** (its `worker/test/contract.json`, read-only: the fake still stands in for the Worker at run time, but must agree with that fixture) |
| **WP4** State + index | §5.2, §5.3, §5.6, §5.8 (journal side), §5.10, §8.3–8.4; vault creation order, discovery and keyfile objects (§2.6, §3.3) | `src/state/{mod,schema,tables}.rs`, `src/index/{mod,apply,refresh,commit,resolve,repair,query}.rs`, `tests/index_props.rs`, `tests/index_adversary.rs` | WP0, WP1, WP2 (`MemBackend`, `Flaky`) |
| **WP5** Transfer | §6.2 (`upload_batch`: the whole client-side upload pipeline), §6.3, §5.7 download steps 1–3 | `src/transfer/{mod,source,pack,upload,download}.rs`, `tests/transfer.rs` | WP0, WP1, WP2 — **not WP4** |
| **WP6** Sync engine | §5.1 (use), §5.4, §5.5, §5.7, §5.9 | `src/sync/{mod,scan,plan,exec,remote_ops,gc,check}.rs`, `tests/sync_e2e.rs`, `tests/sync_faults.rs` | WP0, WP1 (through the vault's keys), WP2, WP4, WP5 |
| **WP7** CLI + config | §2.4 (flow choice, expiring-grant check), §2.6–2.8 (`login` / `passwd` / `logout` flows and texts), §7, §8.1–8.2, §10; the opt-in live run of §13 item 10 | `src/config.rs`, `src/cli/*.rs` (all files listed in §9.2), `tests/cli_e2e.rs`, `tests/live.rs` | WP0–WP6 (every Rust package); e2e tests use `--vault-dir`, plus one Drive-mode run against `FakeDrive`. Not WP8: `tests/live.rs` is ignored unless `GCLONE_LIVE=1` and then needs the *user's deployed* Worker |
| **WP8** Auth Worker | §2.1 (setup doc and script), §2.2–§2.3 (HTTP API), §16; the contract fixture of §16.5 | `worker/**` — exactly the files listed in §9.2 / §16.1 | WP0 (repository skeleton only — no Rust code); Node ≥ 20 and npm (`nix-shell -p nodejs`). **Nothing is deployed by any package or test.** |

Compile-time dependencies are satisfied by the WP0 stubs; the "needs" column says whose real implementation (or, for WP3 → WP8, whose delivered fixture file) a package's *tests* require. **Dependency order: WP0 → {WP1, WP2, WP8} → {WP3 (after WP2 and WP8), WP4, WP5} in parallel → WP6 → WP7.** WP3 can be written in parallel with WP8 against the fixture format of §16.5; only its final acceptance run waits for the file. WP3 has no dependants until WP7's Drive-mode e2e test and the final live run; WP8 has one (WP3's contract test). `plan()` (WP6), `apply_segment` (WP4), the pacer and the HTTP state machine (WP3) are pure/isolated and can be finished before their dependencies land. Integration wave 2 added one test file that belongs to no work package: `tests/cross_package.rs` (owned by the integrator, §17.3) — `Vault` + transfer on every backend. Later packages leave it alone; if a deliberate API change breaks it, the integrator of that wave adapts it.

### 12.1 Acceptance tests per package (WP0–WP7: all must pass under `nix-shell -p cargo rustc --run 'cargo test'`; WP8: `cd worker && npm test`)

**WP0**
- `cargo check --all-targets` and `cargo build --release` succeed with the stubs; the dependency set resolves (Errata written if a version/feature had to change); a `u64` binds and reads back through rusqlite (proves `fallible_uint`); `tokio::io::stdout()` compiles (proves `io-std`).
- `path::validate` table (valid/invalid cases of §5.1); `cmp_key`: NFC vs NFD of `é` equal; fold on/off; full case folding (`Straße` = `STRASSE`, `ΟΔΟΣ` = `οδος` = `οδοσ`, `İ` folds to a key that is NFC) and the result is always NFC; `conflict_name("a/b.tar.gz", stamp)` = `a/b.tar.conflict-<dev8>-<lamport>.gz`; dotfile `.bashrc` → `.bashrc.conflict-…`; 255-byte clamp.
- `util`: hex/base64url/crockford round trips (crockford of 10 bytes = 16 chars); `ct_eq`; `write_atomic` creates mode 0600 and replaces atomically; `remove_atomic_leftovers` removes exactly the `.<name>.tmp-<16 lowercase hex>` files of its path (not another file's, not 15 / 17 digits, upper case or non-hex) and is `Ok(0)` for a missing directory; `create_dir_private` yields 0700 for every level it creates under a permissive umask; `is_private` rejects 0640 / 0604 and accepts 0600 / 0700; `parse_rfc3339_ms` (`…Z`, fractional seconds, `+01:00`, garbage → None); `parse_http_date_ms("Wed, 11 Nov 2026 09:14:03 GMT")`; `format_utc_compact`; `format_local_minute` under `TZ=UTC` and `TZ=Europe/Berlin`.
- `exit_code` mapping table incl. precedence and the newer variants (`OutboxStuck` → 75, `VaultNotVisible` → 4, `RootChanged` → 5, `AuthError::Expired` → 4, `ConfigError::{NotConfigured, NotLoggedIn, Locked, InsecurePermissions, WrongPassphrase}` → 4, `FormatError::KeyfileDamaged` → 3); `BaseRow::trusted` racy-window cases.
- Repository skeleton: `Cargo.lock` is committed and `cargo build --locked` succeeds; the root `.gitignore` ignores `target/`.
- `Ui::silent()` and `Progress::hidden()` work without a TTY; `Ui::new(json)` emits one valid JSON object per `event`.

**WP1** — everything in §4.7, plus: `Keyring` unknown/too-old epoch; `Keyring`, `MasterKey`, `PurposeKey` are `Clone` and `Send + 'static`; `Sealer` misuse errors (chunk after final, short non-final chunk, oversize chunk); segment/snapshot seal→open round trip with names; `parse_index_name` round trip and rejects (`s-zz…`, wrong lengths); `keyfile_name` / `parse_keyfile_name` round trip (including generation `0xffffffff`) and rejects (wrong prefix, 7-digit gen, upper-case hex); `KeyfilePayload::from_keyring(..).keyring()` reproduces the keyring (epochs, `min_epoch`, vault id); the payload's JSON has the key `"gen"` (the Rust field is `generation`) and the literal JSON of §2.6 deserializes; `Passphrase` has neither `Debug` nor `Display`. The `gen_vectors` generator is `#[ignore]` **and** returns at once unless `GCLONE_GEN_VECTORS=1`.

**WP2** — the generic suite `backend::conformance::run<B: Backend>(b)` (in the library, `#[doc(hidden)]`) is called from `tests/backend_conformance.rs` for `MemBackend`, `DirBackend`, `Flaky<MemBackend>`:
- put Small and Stream (3 parts + short tail) → get whole and ranges (start, middle, crossing parts, past end clamps) byte-equal; md5 and size in `ObjMeta` correct.
- put with an existing id returns the existing meta and does not overwrite; `create_folder` idempotent.
- `list` returns direct, non-trashed children only — also for `Handle::top()`; top-level objects report `parent == Handle::top()`; folders report `size == 0`, `md5 == None`; `find_by_name`; `stat` of trashed shows `trashed = true`; `get` of trashed works; `trash`/`untrash` idempotent; `delete` removes for good (`stat` → `None`); `NotFound` cases.
- Stream whose channel yields `Err` → `BackendError::Io`, and afterwards `stat(id)` is `None`.
- `DirBackend`: reopen on the same directory sees everything; a copy of the directory **without** `.gclone-dir-ids.json` still serves `find_by_name`, `list` (incl. `list(Handle::top())`) and `get` via the `p:…` handles those return; opening the **inner** vault folder as the root finds the descriptor with `parent == Handle::top()`.
- `Flaky`: each injector produces the documented effect once (`fail_put_named` for its `times`); `on_put_progress` fires once at the stated offset; counters count; `hang` never answers (an hour of paused time), reaches nothing, counts, and ends with `clear()`.
- The generic suite additionally asserts (so `DriveBackend` on `FakeDrive` must satisfy it too, WP3): `new_ids(0)` → empty; `find_by_name` is byte-exact — case-sensitive and not a prefix match — and finds folders (`DriveBackend` filters the hits client-side by exact name, whatever Drive's `name = '…'` matches); `get` of an absent id fails with `NotFound` from `get` itself, not from the stream; `untrash` of an absent id → `NotFound`; `stat(..).created_ms` equals the `put` result's; `now_ms() > 0`; an existing id answers a **Stream** put with its own meta as well; the Stream object is 3 × `PART_SIZE` + 12,345 bytes (≈ 48 MiB, held in memory by the fake).
- Fake-only behaviour (tested in `tests/backend_conformance.rs`, **not** in the generic suite; details §17.2): `PutBody` contract violations fail (`Fatal{400, "badRequest"}` / `Io(UnexpectedEof)`); `put`/`create_folder` into a missing parent → `Fatal{404, "notFound"}`; `stat(Handle::top())` is a folder meta; the content of a trashed folder reports `trashed = true`, is hidden from listings and stays readable by id.

**WP3** (against `FakeDrive`; no network)
- `backend::conformance::run` passes on `DriveBackend`.
- Wire shapes (§6.4.1): the fake's string `size`, folder without `size`/`md5Checksum`, RFC 3339 `createdTime`, string quota numbers all decode; `classify` on an HTML body falls back to the status code; all three clients are built with `Policy::none()` (a `308` without `Location` reaches the state machine).
- Multipart request shape (boundary, JSON part first, metadata fields, `fields=` in the query); objects of exactly `MULTIPART_MAX` go multipart, `+1` byte goes resumable.
- Resumable: `fields=FIELDS` is on the initiation URL and the session URI is used verbatim — against the fake's default-projection behaviour the returned `ObjMeta` still has size, md5 and `created_ms` without an extra `stat` (`hits(Stat) == 0`); with the completion body stripped, exactly one follow-up `stat`. Every `Content-Range` in `session_requests()` has a length that is a multiple of 256 KiB except the last; `ack_only(k)` → status query → resend from the acked offset with identical bytes (object byte-equal at the end); `omit_range_header_once` → restart from 0 succeeds when parts are still retained, `SessionLost` otherwise; `expire_sessions` → `SessionLost`; `lose_response_once(SessionPut)` on the final part → status query sees 200 → success without resending; `unauthorized_once(SessionPut)` on part k → one refresh, status query, upload completes byte-identical; two consecutive 401 → `Auth(Expired)`; `conflict_at(ResumableInit)` and `conflict_at(Multipart)` → existing meta returned; `conflict_then_absent` → `SessionLost` after 3 `stat`s (Small and Stream). Progress and rounds (§6.2 step 7, §17.10): with `max_attempts = 3`, `ack_only_times(256 KiB, 12)` → the put succeeds after twelve cut parts, each resumed where the status query found it, and `ack_only_times(0, u32::MAX)` → `Transient` after three parts; `drop_parts(2)` → the part goes out three times with at least `BACKOFF(0) + BACKOFF(1)` between the sends; `hold_completion(3)` → the last part is sent once, three status queries follow, spaced the same way; `hold_completion(u32::MAX)` → `Transient` after `MAX_ATTEMPTS` status queries.
- Upload timeouts (§6.4, §17.10), against a raw TCP upload endpoint that reads request bodies at a set pace (`SlowUpload` in `tests/drive_http.rs`; the fake receives every body at loopback speed and cannot show this) with `DriveConfig.read_timeout` shortened: a 4 MiB multipart body read at 64 KiB per 50 ms succeeds although the request lasts longer than the read timeout; a 16 MiB part of which the server reads 1 MiB and then nothing fails with `Transient("the upload stalled…")` about one read timeout later, long before the request's total timeout. Unit tests (paused time): the body stream yields the same bytes in pieces of at most `UPLOAD_SLICE` and ends the watch with the last piece; the watch fires `HTTP_READ_TIMEOUT` after the last piece taken, counted from the send, and never once the body is handed over.
- Listing follows `nextPageToken` with `set_page_cap(2)`; sends `trashed = false`; `delete` sends `DELETE`.
- Error classification table of §6.5 (unit test on `classify`, every row, including: reason only in `errors[1]`; `status: RESOURCE_EXHAUSTED` without `errors`; `storageQuotaExceeded` is not mistaken for a throttle; `dailyLimitExceeded` → `ProjectApiQuota`; `appNotAuthorizedToFile` → `AppNotAuthorized`; `downloadQuotaExceeded` → `DailyDownload`); `401` → one refresh (a `POST /auth/refresh` on the fake) → retry; `revoke_refresh_token` → `Auth(Expired)`; `break_client` → `Auth(WorkerMisconfigured)`; abuse flag → second request carries `acknowledgeAbuse=true`.
- Pacer (tokio paused time): rate halves on throttle and recovers by +0.5/s per 10 s; unit window blocks at 250,000/min; breaker trips after 10 min of throttled writes → `QuotaExceeded(DailyUpload)`; `Retry-After` honoured.
- Auth client (`tests/auth.rs`, against the fake auth Worker of `FakeDrive`; the test plays the user with `FakeDrive::approve` / `deny`). **The sign-in**: `login_interactive` prints exactly the three lines of §2.4 (the URL and the user code of the fake's answer, verbatim), calls `open` with the verification URL — and with `no_browser` prints the same and opens nothing; it polls while nobody has entered the code (≥ 3 polls, no token issued), and after `approve` returns a `LoginGrant` with refresh token, e-mail and scope; `/auth/device/start` got one `POST` with `{}`, every poll `{ "device_code": … }`; the device code is never printed. `deny` → `Denied`; `expire_codes` → `Timeout`, and so does a code whose `expires_in` (0.4 s) passes while the device polls; `slow_down(1)` → the next poll comes ≥ 5 s later and no failure is reported; polls answered `502`, `503` (HTML), `500` and `429` are followed by the next one, the login succeeds, `Retry-After` was honoured and **one** "still trying" note was printed for the streak; a Worker that is gone for good → `Network` when the code ends. A device code is good for one login (a second `device_wait` → `LoginFailed`; an unknown code → `LoginFailed`; a malformed one → `Network("unexpected answer…")`), and two logins side by side do not mix. **Refusals**: `set_login_email("other@example.com")` → `NotAllowed`; `set_granted_scope("openid")` → `ScopeMissing`; a granted scope beyond gclone's own (`… https://www.googleapis.com/auth/drive`) → `Denied` carrying the Worker's message, from `/device/poll` (no refresh token issued) and from `/refresh`; `break_client` → `WorkerMisconfigured` at the poll and at the start (not retried); the device checks the `scope` and the shape of a `200` answer itself; `set_refresh_expires_in(Some(604799))` → `LoginGrant.refresh_expires_in == Some(604799)`, absent → `None`. **Start**: 5xx answers are retried and then succeed, five in a row → `Network`; one `429` is retried after `Retry-After`, two → `Network`; nothing listening → `Network`; `404 not_found` (a Worker from before 0.2.0) → `LoginFailed` naming the older version; an answer whose user code or URL is not plain text (`ESC[2J`, `http://`, `javascript:`), or with a bad number → `Network("unexpected answer…")` with **nothing printed, nothing opened and no poll**. **Refresh**: the body is `{ "refresh_token", "client": "device" }`; `revoke_refresh_token` → `Expired`; `break_client` → `WorkerMisconfigured`; a 502 is retried and then succeeds; one 429 is retried after `Retry-After` and succeeds, two → `Network`; a 3xx answer is an error and is not followed — on `/refresh`, on `/device/start`, and on `/device/poll`, where it ends the login; two logins yield two different refresh tokens that both refresh. **The legacy client** (`a_legacy_login_refreshes_only_while_the_worker_keeps_the_legacy_client`, §17.18): with `set_legacy_client(true)` a token of `add_legacy_token` refreshes through `auth::refresh(.., AuthClient::Legacy)` and through a `TokenProvider` built with it, the request body carrying **no** `client` field; each token works under its own client only; with `set_legacy_client(false)` the same refresh is `Expired` at once (one request, no retry) while a device-client login is unaffected. **Revoke**: `auth::revoke` posts `token=` form-encoded to `revoke_url` → `Ok(true)`, afterwards every refresh is `Expired`; an unknown token → `Ok(false)`. **URL rules**: `validate_auth_url` accepts `https://h`, `https://h/base/` (slash trimmed), `http://127.0.0.1:8787`, `http://localhost:1/x`, `http://[::1]:9`; rejects `http://example.com`, `ftp://h`, userinfo, query, fragment, an empty host; `resolve_auth_url` precedence arg > env > stored > built-in. **TokenProvider**: token cache file reused across instances; `prime` avoids a refresh **and writes no file** (with `cache_file: Some(p)`, `p` does not exist after `prime` + `access_token()`; it appears only after a real refresh); `cache_file: None` never creates a file; a cache file with mode 0644 is ignored; single-flight (N concurrent `access_token()` → 1 `/auth/refresh`). **Review of 0.2.0 (§17.19)**: `the_fake_enforces_the_poll_interval_and_the_lifetime_of_a_code` (the fake answers `slow_down` to a poll that comes sooner than `interval` after the previous one, without redeeming an approved code, and `expired_token` once `expires_in` has passed); `the_device_keeps_to_the_poll_interval` (interval 0.3 s: the first poll no earlier than one interval after `/device/start`, N polls in at least N − 1 intervals, the fake never said `slow_down`); `failed_polls_back_off` (four `502` in a row: gaps of at least 2, 4, 8, 16 intervals, then the plain interval again); `a_grant_the_worker_cannot_use_ends_the_login_with_its_reason` (`403 grant_unusable` → `LoginFailed` with the Worker's sentence after exactly one poll; the fake has consumed the code); `an_address_that_is_not_googles_is_not_opened` (four printed lines, `open` not called, the login completes; a URL with userinfo is refused unprinted); a `/device/poll` answer whose `email` carries control characters, a newline, a space or non-ASCII → `Network`, nothing printed; the half-set legacy pair → `WorkerMisconfigured` for a legacy refresh only. Unit tests in `auth/login.rs`: `only_a_google_page_is_opened`, `failed_polls_back_off_and_never_poll_faster_than_the_interval` (`poll_pause`), `the_account_address_is_plain_text`, `interval` absent → 5 s.
- **Contract fixture** (`tests/auth.rs`; needs WP8's `worker/test/contract.json`, read with `concat!(env!("CARGO_MANIFEST_DIR"), "/worker/test/contract.json")`, format and case list in §16.5): `version == 2`; **every** case is run against `FakeDrive`'s auth routes with a plain HTTP client (no redirect following) after bringing the fake into the case's `given` state through its public hooks, and status, the listed headers and the JSON body (exact key set; literals equal, placeholders by type) all match, and no answer carries a `Location` — an unknown `given` keyword, key or matcher fails the test, so the fixture cannot grow past this harness silently; and for every `/device/start`, `/device/poll` and `/refresh` case the recorded answer is replayed to the Rust client (`auth::device_start` / `auth::device_wait` with a 300 ms code / `auth::refresh`), which must return the value or `AuthError` variant that the mapping table of §2.4 assigns to it — written out a second time in the test — after the number of requests that table implies (one; several for a poll that goes on; two or five for the retried routes).

**WP4** (`MemBackend` / `Flaky`)
- Merge properties (seeded, ≥ 200 random histories of 3 devices): any causal order and any segment grouping yield an identical `MemIndex` **including `removed` with `removed_ms`/`by`**; the specific history "identical heads P1 < P2, op O with base P2 from a writer that had not seen P1" gives the same state for orders P1,P2,O and P2,O,P1; `load_snapshot(to_snapshot(x)) == x`; `state(snapshot ⊕ uncovered) == state(all)`; SQLite `HeadStore` equals `MemIndex` for the same history; a failing SQLite call surfaces as `IndexError::State` from `apply_segment`.
- Rule table: successor replaces; concurrent puts → two heads, winner = max stamp; identical concurrent puts stay two heads until resolved; stale delete is a no-op (put beats concurrent delete); delete of current head empties the path; ancestor of the winner is never a conflict; fork tie-break; two superseding ops → `removed.by` is the smaller stamp in either order.
- `resolve_conflicts`: deterministic conflict path; same-content losers are dropped without a conflict copy (two devices uploading identical content under different `loc`); two devices resolving independently converge with no further conflicts; file-vs-dir rule; it commits staged leftovers even with zero resolutions; a segment never holds two `Put`s for one path.
- Refresh: two/three `Vault`s on one backend converge after interleaved commits; list lag (`set_list_lag_ms`) never causes `Rollback`/`Gap` within `GAP_GRACE` and is healed via `file_id` fetch; `GAP_GRACE` runs on the injected local clock (`set_local_clock`), not on object `created_ms`.
- Head fingerprint (§2.6): `head_fingerprint()` has the form `XXXX-XXXX`; it is equal on two converged `Vault`s — also when one of them was rebuilt from a snapshot and the other applied every segment; it changes with a commit and is equal again once the other device refreshed; a fresh replica opened against a rolled-back store (`restore(checkpoint)`) reports a value **different** from an up-to-date device's.
- Clones: copied `state.db` with the **same** pinned `machine_fp`, both commit the same seq before seeing each other → both rotate, both branches applied, no error; a clone that sees the other's segment at a seq **below** its `next_seq` rotates too; a different `machine_fp` rotates before the first commit; a listed-but-unreadable segment name under the own device id does not rotate.
- Coverage: fork (X,5,h1)/(X,5,h2) plus a snapshot written by a device that saw only h1 → every device (fresh, rebuilt, up to date) ends with both branches applied; a replayed covered segment (un-trashed by the adversary) is inert on fresh and old devices alike.
- Adversary (`tests/index_adversary.rs`): `restore(checkpoint)` after a device saw newer state → `Rollback`; hard-deleting a segment referenced by another device's `seen` → `Gap` after `GAP_GRACE`; renamed segment, segment from another vault, truncated or bit-flipped segment → reported, never applied, and treated as missing by whatever references it; an old snapshot presented alone to a device with higher `hw` → `Rollback`; a garbage snapshot with a huge name-lamport → ignored; a segment absent from the listing but referenced by another device's `seen` and readable by ID → fetched, applied, success. **Newer format**: an object under a matching name with codec byte 1, body version 1 (segment and snapshot), header suite 2, `chunk_log2` 25, type 0x04, flags 1 or key epoch 2 → `UnsupportedObject` naming the object and the reason on an old and on a fresh device, twice in a row (exit 3), nothing cached, `repair` refuses too, and after the object is trashed everything converges; the same kind of bytes without a version reason (bad magic, wrong stream type, undecodable v1 body) → still `corrupt_objects`. **Oversized** (`set_index_object_max(64 KiB)`, `MemBackend::claim_size`, byte counters): a segment and a snapshot listed above the bound are never requested; of an object listed with 100 bytes that serves 2 MiB exactly bound + 1 bytes arrive; an object of exactly the bound is read whole; all are reported in `corrupt_objects` and the real journal still applies. `discover`: of two padded 1 MiB descriptors — one listed honestly, one listed with 200 bytes — nothing and `DESCRIPTOR_MAX + 1` bytes are read, and neither is a vault. (`backend::get_bounded` has unit tests in `src/backend/mod.rs`: a stream that ignores the range and never ends is dropped after the piece that crosses the bound.) **Trust on first use**: a brand-new replica (empty `hw`) opened against a rolled-back store (`restore(checkpoint)`) refreshes without error and adopts that state; once it has then seen newer state, a second rollback → `Rollback`.
- Crash safety (failpoints via `Flaky`): fail the segment put → `pending`/`outbox` survive; re-open → `refresh` re-puts and applies exactly once (`lose_ack_next_put` variant included); **stuck outbox**: `fail_put_named("s-", u32::MAX, quota)` persisting across re-open → `refresh` succeeds with `outbox_stuck`, queries work, `commit()` with new work returns `OutboxStuck`, and after `clear()` the next refresh publishes; staged ops whose blob was hard-deleted, or is older than `ORPHAN_GRACE / 2`, are dropped with a warning; trashed blobs are untrashed.
- Compaction: after 64 segments a snapshot appears; a second device **adopts** it (no snapshot of its own, `applied` pruned, state unchanged) and its next `maybe_compact` does nothing; a fresh `Vault` (new DB) reaches the same state from snapshot + tail — also when every covered segment is trashed and no newer segment exists; a device that was behind rebuilds from the snapshot and keeps its `base` rows and its `trashed_ms` blob rows.
- Cleanup: trashes only after 7 days of mem clock and only by the writer; keeps 2 snapshots; **two concurrent compactors** (S_A{A:10,B:6}, S_B{A:9,B:7}) + cleanup by both → no `Rollback` on either device, A:10 and B:7 stay listed, a fresh device joins without `Gap`, and after the next snapshot the rest is trashed.
- `repair`: device A's cache republishes a hard-deleted segment and device B's `Gap` disappears; a presence failure with an empty cache is cured by A's `write_snapshot`; `--accept-loss` clears `Gap`/`Rollback`, its snapshot's `covered` omits the skipped segment, and a device that still holds that segment gets `Rollback` → its `repair` republishes → all devices converge.
- Create / discover / keyfile: `Vault::create` writes the descriptor **last** (with `Flaky::fail_put_named` on the descriptor name the root folder exists, `discover` returns nothing, and a second `create` succeeds beside the orphan — on `MemBackend`/`Flaky<MemBackend>`, as on Drive; a `DirBackend` cannot hold two folders of one name and answers the second `create` with `Fatal{409, "nameConflict"}`, §2.6 / §17.2) and stores `CreateParams.keyfile` in the root; `discover` on an empty backend → empty; one vault → its handles, `root_name`, `descriptor_created_ms` and keyfiles (highest gen first); two vaults → both, sorted by `(descriptor_created_ms, vault_id)`, and `creation_winner` picks the first; two children named `index` → error; descriptor at depth 1 and at `Handle::top()` (directory copy); an unparsable descriptor is skipped. `verify_visible`: ok with 0 `list` calls; trashed root → `VaultTrashed`; missing root → `VaultNotVisible`; `index` under another parent → error. `replace_keyfile`: the new keyfile is listed, lower generations are trashed only **after** the put was accepted (a failing put leaves the old keyfile untouched), an equal-generation keyfile from a concurrent `passwd` survives.
- Lock: second `lock_exclusive` in another process/handle times out with `Locked`; released on drop.
- Review round 4 (§17.11): a segment sealed and then left in the outbox for 15 days while another device's `gc --orphans` trashes its blob is **withdrawn** on recovery — no head, no blob record, no base row; the blob-less ops are staged again and go out under the same sequence number, the other device sees no gap, fork or rotation; `recover_outbox` case by case (young trashed blob → un-trashed and published; missing blob → its ops dropped, the rest re-staged; `commit` reports the dropped ops; segment already in the store → finished as sealed; unpublished blob older than `ORPHAN_GRACE / 2` → withdrawn; a segment sealed by the same `commit` costs no `stat`). `dead_blobs` / `purge_candidates` / `stats` / `sync::gc` leave a blob alone that a stuck `Put` (outbox) or a staged one names, and collect it once nothing names it. A conflict at a 4095-byte path, and a file-vs-directory clash at a 4089-byte path, are resolved on both devices (`conflict_name` yields a valid path for every valid path — unit test over every length near the limit). With the cached snapshots deleted, a refresh after a cleanup downloads nothing (presence from `base_covered`), an idle `cleanup_index` costs one listing and nothing else, the cleanup of `finish_mutation` after a refresh costs no call, and a new snapshot of another device makes the next pass run. A cached, unlisted segment re-applied after a rebuild keeps its file id (`tests/index_adversary.rs`: no `Rollback` under list lag, the next snapshot's tips carry the id). `Db::open_shared` + `Vault::open_unlocked` succeed at once while another connection holds a write transaction, write nothing, and answer `Locked` for a database without schema. Unit tests: the conflict queries use `heads_losers` and never scan `heads` (`EXPLAIN QUERY PLAN`); rule 2 is found through the touched paths (file below, file above, a deletion that promotes a file) and by a full scan after a snapshot load or more than `TOUCHED_MAX` touched paths; a version-1 database without the later additions gets them at the next `Db::open`, not at `Db::open_shared`.

**WP5** (`MemBackend` / `Flaky`, temp dirs — no `Vault`)
- `upload_batch` → download round trip for sizes {0, 1, 65535, 65536, 65537, 1 MiB − 1, 1 MiB, 5 MiB, 40 MiB}; BLAKE3 and bytes equal; blob length equals `format::blob::blob_len`; every source appears in exactly one event; zero-length files arrive as `BlobUpload { blob: None }`.
- Pack of 500 tiny files = 1 put (+ none per file); members individually downloadable with ≤ ceil(n/…) coalesced GETs (assert via counters); a file that grows past `PACK_MEMBER_MAX` between "scan" and open is uploaded as a single-member blob.
- **No re-seal**: with `lose_ack_next_put`/transient failures the bytes stored equal the bytes first produced (same salt) *or* the retry used a different blob id — never the same blob id with different bytes (assert by recording puts).
- `corrupt_md5_next_put` → object trashed, retried under a new id, success.
- Source changed during the upload (`Flaky::on_put_progress` rewrites the file mid-stream) → retried with a new salt/blob/ID, after `UPLOAD_ATTEMPTS` → `Failed(SourceChanged)`; a FIFO or symlink as source is refused without blocking.
- Stop conditions: a `QuotaExceeded` put → no further puts, the remaining sources come back `Failed` with that error; dropping the receiver stops the pipeline; peak retained bytes stay within the §6.1 bound (a unit test in `src/transfer/upload.rs` — it reads a crate-private buffer meter and uses its own slow `Backend` double; the measured peak is ≈ 81.25 MiB against the nominal 81 MiB at `transfers = 2`, because a part buffer may overshoot `PART_SIZE` by one sealed chunk plus header while it is built; the test allows 2 MiB of slack, §17.3).
- `drafts_for` builds `BaseEffectKind::Set` from the `Uploaded` record (sig, hash, observed_ns, kind), using only (base, pair, key, rel) from the closure.
- Download: `cut_next_get` resumes from the first unverified chunk; tampered blob byte (`MemBackend::tamper`) → `Crypto(Corrupt)`, no target file, no partial left; swapped blob content (`replace_content`) → fails; truncated blob → fails; `loc.off + loc.clen > blob.clen` → `Verify` without a request; `Loc.suite = 2` → `Crypto(Unsupported)`; stored `file_id` gone but name resolvable → works (`locate_blob` likewise).
- Review round 4, transfer (§17.13): a member with 320 targets (and one above `PACK_MEMBER_MAX` with 24) downloads completely while a watcher thread sees the process's open descriptors stay flat; unit tests on the sink count the open partial files directly (none before a small member is verified, exactly one while a large one arrives; a first target that cannot be created hands the stream to the next; a copy that reads back other bytes is `Verify`). Sources that are missing, dangling or real symlinks, directories or FIFOs → `Failed(SourceChanged)`, a mode-000 file → `Failed(SourceUnreadable)`; a large file removed between two attempts → `SourceChanged` without another put. Cancellation with `Flaky::hang` under paused time: `new_ids`, the put, and the `stat` after a lost answer each end exactly 5 s after the cancellation with `Failed(Cancelled)`; an id that arrives 2 s after the cancellation starts no put (unit test with the slow `Backend` double); a download hanging in `find_by_name` or in the `stat` after a short body returns `Cancelled` at once; zero-length files are not written after a cancellation (`materialize_empties`, `download_group`).
- `read_range` equals the plaintext slice for random ranges; target rules: symlinked ancestor → `UnsafeTarget`; an unexpected directory → `UnsafeTarget`, never moved; an unexpected file with exactly the target name → moved aside, not overwritten; `LocalExpect::File(sig)` replaced only when the sig matches; `LocalExpect::EmptyDir` → `rmdir` then write.

- Download durability (§5.7 step 3a, §17.15, §17.16; unit tests in `src/transfer/download.rs` and `src/transfer/durable.rs`, through the test hooks `durable::hook::observe(dir, f)` — `f` sees every barrier that names a path under `dir` and can refuse it — and `durable::hook::observe_files(dir, f)` — `f` sees every single path that is synced, with the descriptor the `fsync` goes through, and can refuse that path alone): after a member is written to three targets nothing is renamed, flushed or reported; `finish` makes exactly two barrier calls — the first names the three partial files (complete, final mtime and mode) while no target exists, the second names each directory of a rename and its ancestors up to the root, once each, with the targets in place and no partial file left; a refused content barrier → every file `Err(Io)`, nothing renamed, no partial file left, no second barrier; a refused rename barrier → every file `Err(Io)` although the files are in place; a batch closes itself at `DOWNLOAD_BATCH_FILES` files (the next three wait), at `DOWNLOAD_BATCH_BYTES`, and when a file arrives after `max_age`, and never holds more than `max_open` written files open; **every partial file is synced exactly once, through a descriptor that is open for writing on that very file** (`F_GETFL`, inode compared), and a file whose sync is refused fails alone — its partial file removed, the other files of the batch arrive; a file that takes over mode 000 from the file it replaces is synced and named like any other and arrives with that mode; a directory whose sync is refused fails the files in and below it and no other; **a staged file whose mtime is years old survives a scan of the tree** (`sync::scan`), and a partial file removed by hand fails its own file with `NotFound` while the rest of the batch arrives; zero-length files (`materialize_empties`, `materialize_empty`) take the same two barriers, a cancelled call none; `make_durable` on files, directories, nothing, a missing path (reported alone, the barrier stands for the paths around it) and a root reached through a symlink; `hand_over` + `Drives::flush` on written files (one descriptor kept per device, a refused flush is an error). `src/sync/scan.rs`: a partial file is stale a day after the newer of its mtime and ctime, whatever the mtime says (also an mtime in the future), and the sweep removes regular files only.
**WP6**
- Base rows and the barriers (§5.7 steps 3a and 3b, §17.15, §17.16; unit tests in `src/sync/exec.rs`, a `Vault` on `MemBackend`, same hooks): during both barriers of a download `state.db` holds no base row of that download (files with content, and zero-length files), afterwards one per file; with the content barrier or the rename barrier refused the run reports every file as failed, writes no base row, and — content barrier — leaves no file; the following run downloads what is missing, or records by content what arrived without a row (`downloaded == 0`), and never plans an upload. Step 3b, each with the barrier observed and with it refused: files in place without rows are recorded behind **one** barrier that names every file and every directory up to the root while `state.db` still holds none of the rows — refused: no row, three failures; one directory refused: only the rows below it are missing, and the next run writes them; a row that only refreshes its predecessor (same bytes rewritten, same mtime) is written without any barrier; `SetLocalMeta`: the barrier names the file, stands between the `utimes` and the row — refused: the row keeps the old mtime, the run fails that file, the next run records it and an upload from that tree pushes no metadata; `MkdirLocal`: the first barrier of the run names the directories above the created one up to the root while no row exists — refused: no row, and an upload from the tree with the directory removed deletes nothing in the vault; `DelLocal`: the barrier names the directory of the removal while the row is still there — refused: the row is kept, a file that comes back is not uploaded, and the next run forgets the row. `chain` / `removed_from` / `settle`: what a row rests on, the nearest directory that is left, each path synced once, an entry failing with any of its paths.
- Planner: one table-driven test per row × direction × mode of §5.5.1 (incl. `--force` variants, the `RecordBase` refresh of row 1 and the equal-content case of row 3 UP), `Reuse` selection, `Dir` rows, meta-only rows; guards G1–G6 (delete guard: 101 deletes trips; 10 of 30 trips; 9 of 30 passes; `--max-delete`; root identity: changed `(ino, birth)` → `RootChanged`, `--reset-pair` drops rows, `--keep-pair` keeps them, a changed `st_dev` alone changes nothing).
- Planner invariants (seeded): first sync never deletes; copy never deletes; no two actions touch one key; `base.is_some() ⇒ remote_path == R.path`; **for any `Filter`, an excluded directory pattern (`node_modules/`, `*.tmp`, a nested path) yields zero actions for keys under it on both sides, with and without base rows**.
- Spelling: local NFC file whose remote twin is NFD on `fold = false` — modify locally and sync up → one remote path (R's), no second entry; modify remotely and sync down → the existing local file is replaced, no second file; new file under local `Foo/` with remote `foo/…` → uploaded as `foo/new`.
- Scan: symlink/FIFO/non-UTF-8 counted and skipped; **a synced directory replaced by a symlink → 0 `DelRemote`, `Skip(Unsupported)`**; unreadable subdirectory → `failed_dirs` and **no deletes** under it after a full sync; NFC/NFD twins → collision skip; partial files ignored; racy rule forces a re-hash for a file modified within 2 s of the previous sync (same size) — once: the following sync hashes nothing; `chmod` on a synced file → one re-hash, then none; `probe_fold_case` on a read-only root.
- End to end on `MemBackend` with two or three `Vault`s + temp dirs (`tests/sync_e2e.rs`): push tree → pull on device 2 → trees byte-equal; **a second no-change sync after that download hashes 0 files** (`Summary.hashed == 0`); modify/rename/delete cycles; **stale device**: device 2 `sync` up without pulling neither deletes device 1's new files nor overwrites its edits (skips reported); concurrent edits of one path → both contents present after both devices sync (winner + `*.conflict-*`); two devices first-syncing identical trees → no conflict copies; delete vs concurrent edit → edit survives; first sync into a non-empty differing destination deletes/overwrites nothing; adding `--exclude` deletes nothing on either side; local rename of a directory then `sync` → 0 blob puts, 1 segment put (counters); no-change `sync` → exactly 1 `list`, 0 puts; 5,000 small files → ≤ ceil(total/16 MiB) + 2 puts.
- Type changes, each in both directions: file → directory and directory → file converge in **one** `sync` run with no conflict name on any device; with a local-only file inside the old directory the download is skipped (`UnsafeTarget`), the directory stays, and deletes of other keys still run; `copy` skips the group.
- Case-insensitive destination (simulate via `fold_case = true`): remote `foo/a` vs local `Foo/a` match; no download+delete pair is ever planned for one key; an unexpected differently-spelled local entry at download time → `Skip(KeyCollision)`, nothing moved aside.
- Faults (`tests/sync_faults.rs`): **kill between blob put and commit** (drop the future after staging) → the re-run (through the settle sequence `refresh → commit → resolve_conflicts`, then `sync::run`) uploads nothing twice, creates no conflict copy and converges; a leftover `Put{p, base: R}` followed by a planned delete of `p` deletes it; failing uploads suppress deletes while run-time skips do not; `QuotaExceeded` stops cleanly with staged work committed; `RateLimited` with a ledger ≥ `LEDGER_WARN` is reported as `DailyUpload`; with the outbox stuck `sync` up fails with `OutboxStuck` before uploading and `sync` down completes; Ctrl-C token → `Interrupted` after commit.
- `rm`/`mv`/`mkdir`/`restore` semantics incl. `restore` after overwrite and after delete, refused after the blob is gone; `gc` trashes only blobs dead ≥ 30 days (mem clock) and with `--orphans` only unknown objects ≥ 14 days inside this vault's data folders (an object in a foreign folder is untouched); `gc --purge` deletes only blobs it trashed itself that `stat` shows trashed with matching size/md5 (an un-trashed or altered one is skipped), and never an orphan or index object; `check_blobs` detects a missing blob, untrashes a trashed one, and with `set_list_lag_ms` reports nothing missing (exit 0, `listed_late > 0`); `check_download` detects tampering.

- Review round 4, sync engine (§17.12): `!` re-includes under an ignored directory change nothing on any side (`sync::scan` unit test against a real tree, the seeded planner invariant with negation patterns, two devices end to end); a pattern that matches only the remote, only the local or only the base spelling of a key hides the key on all three inputs (`hide_excluded` unit test on a folding key; end to end where the file system folds); gclone's own directories under the root are pruned by key and a root inside one is refused (unit; CLI e2e with the home directory as the sync root, the vault directory inside it, and a remote that already holds such files); a download keeps the permission bits of the file it replaces or moves aside (`tests/transfer.rs`, `tests/sync_e2e.rs`); `--reset-pair` with an unchanged root identity, both directions and as a dry run; a directory that faces a remote marker survives the delete of its last file and the marker survives the next upload; row 1 UP with a base row recorded for equal content plans no `SetRemoteMeta`, and two uploaders of equal content with different mtimes settle after one `RecordBase` each.

- Review round 4, command line (§17.14): the planner's G4 test distinguishes `DeleteLimit` (default thresholds) from `MaxDelete` (explicit limit); end to end `--max-delete 9` refuses 10 deletes with and without `assume_yes`, deletes nothing, and only warns on a dry run; `mv` into an existing directory, the root and an empty-directory marker, file onto file and directory onto directory refused without `force` and counted with it, file ↔ directory refused either way, a refusal commits nothing; `restorable_under` lists the newest removed version of every file under a removed directory (and nothing under a name that merely starts alike), marks a path that exists again as live and skips a version equal to the live content; `restore_many` restores in one segment, and of a name that was a file and later a directory brings back what was removed last; a download from, and a `check` of, a remote path that does not exist is `Io(NotFound)` in both modes and as a dry run and creates no local directory, while the root, an existing directory, an empty-directory marker, an upload to a new prefix and a `sync` down of a directory that this pair synced and that was removed since all proceed.

- Review round 4, transfer (§17.13, `tests/sync_faults.rs`): a download answered `RateLimited` ends the run with `Err(Backend(RateLimited))` (exit 75) after exactly the two requests of the streams already running, and with the first blob through and the rest refused keeps that one file and makes at most three requests for six blobs; a source removed after the scan and before the pipeline opens it is `Skip(ChangedDuringUpload)`, nothing is in `failed`, and the planned remote delete of the same run is carried out.

- Review round 4 (§17.11, `tests/sync_faults.rs`): a device whose upload's segment stayed in the outbox goes away for 15 days, another device's `gc --orphans` trashes the blob → on its return the segment is withdrawn, the file is **uploaded again** under a new blob that is not in the trash, and the other device downloads it; the real `restore` with its segment stuck on a full Drive, then `gc --orphans --purge` (dry run and real) on day 31 → nothing trashed, nothing purged, and after the quota clears the restored file is published and downloads byte-equal on another device.

**WP7** (`tests/cli_e2e.rs`, spawning the built debug binary with `GCLONE_CONFIG_DIR`/`GCLONE_STATE_DIR` temp dirs, `GCLONE_TEST_FAST_KDF=1`, `--vault-dir` and `--passphrase-file`; one test drives Drive mode against `FakeDrive`. A "device" below is one **pair** of config and state directories — the login and the key live under the state root. **Every Drive-mode `login` in this file — the re-logins included — passes `--no-browser` and gets its code through the child's stdin**: without the flag the real binary would launch the developer's browser on a desktop and take the paste path under SSH, so the test would behave differently per environment.)
- `login --vault-dir D --passphrase-file F` (creates the vault) → `copy` → second device: the same `login` (attaches; its output carries a head value) → `copy : out` → trees equal; `status` on both devices then prints the **same** `Head` value, equal to the one the second `login` printed once the first device has refreshed; `ls`, `tree`, `cat --offset/--count` (to a pipe), `mv`, `rm -r`, `restore`, `about`, `status` produce the ▸ lines of §7.3. `login` run again on a connected device changes nothing and exits 0.
- Passphrase: attaching with a wrong passphrase → exit 4 with "Wrong passphrase", nothing stored in `secrets.json.keys`; creating with an 11-character passphrase is refused; with no `--passphrase-file` and no TTY → a clear error; an empty passphrase file is refused (generation is offered only at the interactive prompt); a passphrase is never accepted as a positional argument or option value. `passwd`: afterwards a third device attaches with the new passphrase and fails (exit 4) with the old one; the vault directory holds exactly one un-trashed `gclone-key-*` with `gen` 2; connected devices keep working without a prompt; with a planted `gclone-key-ffffffff-00000000` in the vault directory `passwd` fails with the "generation exhausted" text (no panic) and succeeds once the file is removed. **Keyfile work bounds**: with six planted junk keyfiles of higher generations than the real one, a new device's `login` reads at most `KEYFILE_TRY_MAX` of them and exits 3 with the keyfile hint; with three planted and the real one fourth, it attaches.
- `logout`: afterwards `secrets.json` and `token.json` are gone, `ls` exits 4 with the "not connected" hint naming `gclone login --vault-dir <path>` (`NotLoggedIn` — not `Locked` — for a directory vault too), `config.json` and the state directory remain, and a plain `gclone login --passphrase-file F` (**no** `--vault-dir`: the directory comes from `config.json`) continues as the **same device id**; `login --vault-dir <another dir>` on that device is a usage error naming `logout --forget`; `logout --forget` removes `config.json` and the state directory, and asks (`--yes`) when staged ops exist; `logout --revoke` on a directory vault is a usage error; `logout` when not signed in exits 0.
- **Interrupted ATTACH**: with the vault's `index/` directory made read-only, a new device's `login` fails after the passphrase was accepted; `secrets.json` then holds no key and `config.json` does not exist (`ls` exits 4); after restoring the permissions the same `login` succeeds, and `status` on the first device lists the new device. (The key is saved only after the `Device` op was published, §2.6.)
- **Strict secrets**: after `chmod 644 secrets.json` (or `chmod 755` on the state root) `ls` exits 4 with the chmod hint and reads nothing; after restoring the modes it works; a `secrets.json` of a directory vault contains no `auth_url`, `refresh_token` or `email` key and loads.
- **Drive mode against `FakeDrive`** (`GCLONE_TEST_DRIVE_API`/`_UPLOAD`/`GCLONE_TEST_REVOKE_URL` pointing at the fake): `gclone login http://127.0.0.1:<port>/auth --no-browser --passphrase-file F` — the test reads the line "and enter the code  <code>" from the child's stderr and calls `FakeDrive::approve(code)` (stdin is not used; every login passes `--no-browser` so that no test opens a browser) → "Vault created", stderr carrying the three lines of §2.4 with the fake's user code, and `secrets.json` holding `"client": "device"`; a second device logs in the same way → "Connected to vault", and the fake has issued two distinct refresh tokens; `copy` up on one and down on the other; after `revoke_refresh_token` → `ls` exits 4 with "run `gclone login`", and `gclone login --no-browser` (no URL: the stored one is used) → "Signed in again", after which `ls` works. **Wrong account on re-login**: `revoke_refresh_token` again (the stored token is dead, so `login` must sign in interactively), arm `fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile")` (what Drive answers to another account), `gclone login --no-browser` → the fresh-login `VaultNotVisible` text of §2.8 ("The Google login just made (signed in as …) cannot see the vault …", "Nothing was changed on this device, and the new sign-in was not kept."), exit 4; `secrets.json` still holds the **previous** refresh token, `token.json` does not exist, and the next `ls` exits 4 with the plain "run `gclone login`" text (it is not served a cached access token of the wrong login); a further `gclone login --no-browser` → "Signed in again" and `ls` works. **Logout → login**: `gclone logout`, then `gclone login --no-browser --passphrase-file F` **without a URL** (it comes from `config.json`) → connected again as the same device id. `logout --revoke --yes` → the fake's `revoked()` holds this device's token, and the confirmation text carried the web-download warning; `gclone login http://example.com` is refused (`BadAuthUrl`) before any request. With `set_refresh_expires_in(Some(604799))` `login` exits 4 with the Testing text and stores nothing. After any of these logins `token.json` does not exist until the next command that makes a real refresh. **Unreachable auth Worker** (`drive_mode_read_only_commands_survive_an_unreachable_auth_worker`, §17.9): `token.json` deleted and `fail_next(Route::AuthRefresh, u32::MAX, 503, "upstream_error")` → `ls :docs` exits 0, lists the replica and warns "could not reach the auth Worker … Showing the last state this device has seen." without naming `gclone login`; `mkdir` exits 4 with "Could not reach the auth Worker at <AUTH_URL>". **Wrong account after `logout`, and the order of `logout --revoke --forget`** (`drive_mode_wrong_account_after_logout_and_revoke_forget_order`, §17.9): after `logout`, a sign-in as a second allow-listed address whose discovery finds no vault (`fail_next(Route::Media, 1, 404, "notFound")` on the descriptor download) → "Signed in as second@…", the fresh-login `VaultNotVisible` text ("… the new sign-in was not kept", "run `gclone login` again and choose the right one") without the `gclone logout` hint, exit 4, and **no** `secrets.json`; the next `login` makes a new interactive sign-in (`hits(AuthStart)` grows by one) and re-attaches as the same device; with a working login on file and `keys: []` (B.2), and on a connected device with `fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile")` (B.1), `login` prints "Already signed in as …" and the `VaultNotVisible` text **with** "run `gclone logout` first, then `gclone login`", asks nobody, and leaves `secrets.json` byte-identical. Then, on a pseudo-terminal (`openpty`; stdin and stderr are the terminal) with one staged, unpublished op: `logout --revoke --forget`, "y" to "Continue?" and "n" to "Forget this device's vault state anyway?" → exit 5, "nothing was revoked and nothing was removed", the fake's `revoked()` is empty and `hits(Revoke) == 0`, `secrets.json` / `config.json` / the state directory are still there and `ls` works; "n" to the first question → exit 1 without the second; "y" and "y" → revoked, signed out, forgotten. **Leftover login files** (`logout_removes_leftover_login_files`, directory vault): `logout` on a signed-in device removes `token.json`, `.secrets.json.tmp-<16 hex>` and `.token.json.tmp-<16 hex>` and keeps an unrelated `.secrets.json.bak`; `logout` without `secrets.json` but with a `token.json` or a temp copy removes them and says so; a further `logout` → "nothing to do". **The legacy client** (`drive_mode_a_login_of_the_legacy_client_is_replaced_by_gclone_login`, §17.18): a connected device whose `secrets.json` is rewritten the way 0.1.0 left it (no `client`, a token of `add_legacy_token`): with `set_legacy_client(true)` `ls` works and the `/auth/refresh` body is exactly `{ "refresh_token": … }`; `gclone login --no-browser` then signs in again although that login works (stderr names "the browser sign-in of gclone before 0.2.0") — and with `fail_next(Route::Stat, 1, 403, "appNotAuthorizedToFile")` armed it exits 4 with the fresh-login text, "this device keeps its previous login", `GOOGLE_LEGACY_CLIENT_ID` and the README section, `secrets.json` byte-identical, `config.json` and `state.db` in place, and `ls` still working; with `set_legacy_client(false)` `ls` exits 4 with "Run `gclone login`."; `gclone login --no-browser` → "Signed in again as …. Vault unchanged.", `secrets.json` now has `"client": "device"`, the new token and the **same** keys, the device id is unchanged, the next refresh carries `"client": "device"`, and a further `gclone login` says "Already signed in". **Ctrl-C** (`ctrl_c_exits_130`): `gclone login --no-browser` against the fake, SIGINT while it polls → exit 130, nothing more printed, no `secrets.json`. **Review of 0.2.0 (§17.19)**: in the legacy-client test, a half-set legacy pair on the Worker → exit 4 with the Worker's sentence and without "Run `gclone login`"; the legacy secrets gone → the legacy text of §2.8 (not "Google no longer accepts"), and the same device after its move gets the usual text again; `drive_mode_a_legacy_login_without_a_vault_does_not_create_a_second_one` (a `secrets.json` with a legacy login and no key, no `config.json`: the new sign-in sees no vault → exit 4 with the text of §2.8, `secrets.json` byte-identical, nothing on Drive; `--new-vault` creates; on a Drive with the vault the device attaches and keeps the new login).
- Recovery drill, both layouts: (a) copy the outer `DIR` **without** `.gclone-dir-ids.json` and `login --vault-dir` there; (b) copy only the **inner** vault folder `DIR/<vault_name>` (what a web download yields) and `login --vault-dir <copy>` — in both, the passphrase unlocks and `copy : out` succeeds.
- Open policies: with an index gap injected into the directory vault, `ls` prints the warning and exits 0, `sync` exits 3, `gc` exits 3, `repair` runs (it is not blocked by the state it repairs); `--transfers 2` reaches the backend config.
- Exit codes: usage 2; unconfigured 4 with the `gclone login` hint; signed in but not unlocked (`secrets.json` with `keys: []` beside a `config.json`) 4 with the `Locked` text; delete guard 5 without `--yes` (non-TTY); changed root identity 5 without `--reset-pair`/`--keep-pair`; partial 6; `--json` emits valid NDJSON ending in a `summary` event; `-n` changes nothing (directory hash of the vault dir unchanged).
- File modes and places: `secrets.json`, `config.json`, `token.json`, `state.db` are 0600; directories 0700; `secrets.json` and `token.json` are under the **state** root and nothing secret is under the config directory (`config.json` holds no token and no key; it does hold `auth_url` for a Drive vault); no secret appears in `ps`-visible argv in any documented flow; `secrets.json` contains no `client_id`/`client_secret` field.
- Second concurrent mutating command fails fast with "another gclone is running"; a concurrent `ls` prints the "not refreshed" note — also while the lock holder is inside a write transaction on `state.db` (the test holds `BEGIN IMMEDIATE` on a second connection): `ls` and `tree` answer at once from the replica and never say "database is locked" (§8.3, §17.11).
- **Login while the index needs repair** (§2.6, §17.11): a segment that device b has applied is removed from the vault; `mkdir` on b exits 3; after `gclone logout`, `repair` exits 4 and `gclone login` **succeeds** with the verdict and the `gclone repair` advice on stderr and without the head line; b is the same device, mutating commands still exit 3, `repair` republishes the segment from b's cache, and after it everything works and a further login is the ordinary one.
- Pure decisions (unit tests in `src/cli/login.rs`): `expiring_login_decision` with `LoginGrant { refresh_expires_in: Some(..) }` → refused with the §2.4 text unless `--allow-expiring-login`, then the returned expiry lands in `secrets.json` and `status` prints the expiry line; `choose_vault` table (none → `Create`; one → `Attach(0)`; several + TTY → `Ask`; several without TTY → error listing them; `--vault-id` hit / miss; `--new-vault` → `Create`; a configured vault id that is not found → `VaultNotVisible`); `login_backend` table (every row of its doc comment in §9.10: `--vault-dir` on an unattached / same-directory / other-directory / Drive-attached device; no flag on a directory-attached device with and without an `AUTH_URL`; no flag on a Drive-attached or unattached device); `creation_race` (`Alone`; `Won`; `Lost` by earlier `descriptor_created_ms`; equal times decided by `vault_id`; own vault missing from the listing still counts); `want_headless` table (`--no-browser`, `SSH_CONNECTION`, Linux without `DISPLAY`/`WAYLAND_DISPLAY`, macOS default → the browser is opened). Unit tests in `src/auth/login.rs`: the mapping table of §2.4 per route; the checks on a `/device/start` answer (fractions, caps, everything that is not plain text refused). In `src/config.rs`: a `secrets.json` without `client` is a legacy login and is written back without the field; `"client": "device"` round-trips; an unknown value is a load error.
- **Lost creation race** (added by the integrator, §17.5): a `login` whose discovery saw no vault (its passphrase arrives through a FIFO, so another device can create the vault in between) creates its own, finds the older one, trashes its own folder, removes its config, state directory and key, and attaches to the winner with the winner's passphrase; both devices show the same `Head`; a third device sees exactly one vault.
- Review round 4, command line (§17.14, `tests/cli_e2e.rs` unless noted): `rm -r` prints the `restore -r` command; `restore --list :DIR` and `--list :` list the removed files, `restore :DIR` without `-r` exits 2 naming `-r`, `restore -r :DIR` restores them, several paths restore in one command, `--version` with two paths exits 2, an overwritten file is listed as such and left alone by `-r`; `mv` onto a directory prints the real destination, onto a file exits 2 naming `--force` and with it prints the replaced count; `mkdir` of an existing directory says so; `copy` / `sync` / `sync -n` from a remote path that does not exist exit 1 and create nothing, `check --download` and `check LOCAL :P` likewise; `--json` with `ls`, `status`, `about` exits 2 with empty stdout; a file or an empty string as the local argument exits 2 with the explanation; a mkdir-only run prints "Would create 1 directory" / "1 directory created"; `NotConfigured` drops `<AUTH_URL>` when `GCLONE_AUTH_URL` is set. Guards without a terminal: the delete guard names `--yes`; `--max-delete 5 --yes` with 11 deletes exits 5, names `--max-delete 5` and deletes nothing, `-n` warns, `--max-delete 11` runs and prints the restore note, and `restore -r` brings the 11 back; a replaced root names the remote path, `--keep-pair` and `--reset-pair`; a missing source "does not exist" (with `--force` offered by `sync` only), an emptied one "is empty although it was synced … before"; destination-only entries: the reworded skip, the `hint:` line with the count and the exact `gclone copy` command in both directions, the same with `--force`, the skip reasons on stderr under `-q`, and a clean `sync` after the hinted `copy`. Unit tests: `cli::copy::every_guard_names_the_way_out`, `summary_lines_follow_the_examples` (directories), `cli::not_connected_names_a_command_that_works`, `cli::json_is_offered_where_it_is_implemented`.
- `tests/live.rs` (opt-in, §13 item 10): compiles in every run; each test is `#[ignore]` and returns at once unless `GCLONE_LIVE=1` (or `GCLONE_LIVE=mem`: a rehearsal of the same code against an in-memory backend, no network — it checks the test file, not Google; §17.5), so `cargo test` and a bare `cargo test -- --ignored` both pass without credentials. With `GCLONE_LIVE=1` it loads the configured device's `secrets.json` through `config::secret_store`, builds the backend with `cli::drive_backend(secrets.endpoints()?, .., cache = false)`, and runs the conformance checks and the small e2e of §13 item 10 against a throwaway vault, trashing what it created.

**WP8** (`cd worker && npm test` — Vitest inside the Workers runtime, Google replaced by an injected fake `fetch`; no network, no Cloudflare account, **nothing deployed**; details §16.5)
- `/device/start` (`device.test.ts`): the form sent to Google's device-code endpoint is exactly `client_id` + `scope = SCOPES` — nothing of the request body (a `scope`, a `client_id`) reaches Google, no secret is sent, and the legacy client is never used; the answer is Google's five fields; every start is a login of its own; an answer of Google that is not a device code (a missing or malformed `device_code`, a `user_code` with an escape sequence, a line break, a leading space or 65 characters, a `verification_url` that is not `https://…` or has a line break, a non-positive or non-numeric `expires_in` / `interval`, an array, HTML) → `502` and nothing of it is passed on, while a user code with an inner space and a fractional `interval` pass; Google's errors: `invalid_client` / `deleted_client` / `unauthorized_client` / `invalid_scope` → `500 client_invalid`, `org_internal` → `403 access_denied`, `403 {"error_code":"rate_limit_exceeded"}`, a 5xx, a redirect, a thrown fetch → `502`.
- `/device/poll` (`device.test.ts`): happy path — the form sent to Google carries `grant_type = urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`, `client_secret`, and the answer is exactly the §2.3 JSON; **the states of a device code** come back as `400 authorization_pending` (Google: `428`), `400 slow_down` (Google: `403`), `400 expired_token`, `403 access_denied` — one request to Google each, nothing handed out, nothing revoked; the second poll after a login → `400 invalid_grant`; two logins side by side do not mix; a `device_code` of 15 or 513 characters, with a space, a quote, `&`, a line break or `%20`, a non-string, or another field name → `400 invalid_request` with **zero** calls to Google, while 16 and 512 characters of the allowed set reach it; an address outside `ALLOWED_EMAILS` → `403 email_not_allowed` **and** one revoke call carrying the refresh token; `email_verified: false` or an ID token without an e-mail claim → the same; a failing revoke does not change the answer; allowlist matching ignores the case of ASCII letters and trims spaces; empty **or undefined** `ALLOWED_EMAILS` allows nobody; wrong `aud` (also the legacy client's ID) or `iss`, a missing or unreadable `id_token`, a missing `refresh_token` / `access_token` / `expires_in` → `403 grant_unusable` (the message names the missing part) and no revoke, and a further poll with that code → `400 invalid_grant`; `scope` without `drive.file` → `403 scope_missing` and no revoke; **a `scope` with any entry outside `ALLOWED_SCOPES`** (`drive.file` plus full `drive`, `drive` alone, `drive.readonly`, `drive.appdata`, `profile`, `drive.file.extra`, another letter case) → `403 scope_not_allowed` whose body contains no token and the permissions URL, no revoke, the message naming the excess scope and never echoing a hostile scope text; the order unusable grant → allowlist → excess scope → missing scope; Google's error table (`invalid_grant` → `400`, `invalid_client` / `deleted_client` / `unauthorized_client` → `500 client_invalid`, `admin_policy_enforced` / `org_internal` → `403 access_denied`, a 5xx — also one that names a device-code state — a non-JSON `200`, a redirect, a thrown fetch → `502`), after which the login itself still completes; `refresh_token_expires_in` is passed through when present and absent otherwise. Helpers: `idTokenClaims`, `claimsFromGoogle(client, …)`, `emailAllowed`, `excessScopes`, and `configuredClients` (the device pair is required; a half-set legacy pair gives `legacy: null, legacyIncomplete: true`). **Review of 0.2.0 (§17.19)**: a device-code answer without `interval` → `200` with `interval: 5` (present and not a positive number → `502`); a non-Google `verification_url` is passed on; `email_not_allowed` shows the address masked and never in full, also for hostile claims; the allowlist folds ASCII case only — an ID token with `ma<U+212A>@example.com` against the entry `mak@example.com` → `403` and a revoke, and such an entry matches nothing; a `200` answer that names an error is that error (`authorization_pending` under status 200 is not a grant with parts missing).
- `/refresh` and transport rules (`refresh.test.ts`): happy path (`"client": "device"` → the device client's credentials) and the error mapping table (the states of a device code are **not** answers to a refresh: `502`); a refresh token of 19 or 513 characters, or with a space or a quote → `400 invalid_request` with **zero** calls to Google, with and without `client`; a Google answer with an `id_token` for an address outside `ALLOWED_EMAILS` → `403 email_not_allowed` plus one revoke call, with an allowed address or without `id_token` → `200`, and an ID token for another client (also the legacy one) is ignored; a refresh answer whose `scope` has an entry outside `ALLOWED_SCOPES` → `403 scope_not_allowed` without an access token and without a revoke, while gclone's scopes in any order, an empty or a missing `scope` → `200`; **which client**: no `client` field + legacy secrets → the legacy client's ID and secret go to Google; no `client` field and no legacy secrets → `400 invalid_grant` whose message says to run `gclone login` again, with zero calls to Google; any other `client` value (`"legacy"`, `"web"`, `""`, `"Device"`, `null`, a number, an array) → `400 invalid_request`; the allowlist re-check reads an ID token issued for the legacy client when that client refreshed; a login never uses the legacy client; **rate limit**: with an `env.RATE_LIMIT` whose `limit()` answers `{ success: false }`, `/device/start`, `/device/poll` and `/refresh` answer `429 rate_limited` with `Retry-After: 60` and zero calls to Google — the login is still there afterwards — while `/` and `/privacy` still answer `200`; the binding is called with the key of §2.3 — the `cf-connecting-ip` value for IPv4, the /64 for IPv6 (`2001:db8::1` → `2001:db8:0:0::/64`), `"unknown"` without the header — and five addresses of one /64 in different spellings produce **one** key while the neighbouring /64 produces another (`rateLimitKey` table: compressed and full forms, upper case, a zone index, a dotted tail, IPv4-mapped → the IPv4 address, malformed text → unchanged); without the binding nothing is limited; another method → `405` with `Allow` — **as JSON on the two pages too**; `text/plain`, or no body at all on `/device/start` → `415`; a 9 KiB body → `413`; invalid JSON, a missing or non-string field → `400 invalid_request`; unknown path → `404` — **`/login`, `/callback` and `/token` included**; missing secrets of the device client (with or without a legacy pair) → `500 server_misconfigured` on the three JSON routes while `/` shows `Status: not configured`; a left-over `SEAL_KEY` is ignored; no answer carries an `Access-Control-…`, `Set-Cookie`, `Vary` or `Location` header; **every** answer has `Cache-Control: no-store`; the two pages carry the CSP of §2.3 and contain no script, no form and nothing of the request; an exception inside the Worker → `500 internal_error` without detail; the log is one `{route, status, error}` line per request; across the whole suite (the harness checks after every test) no response body, header or log line contains a client secret; a refresh token appears only in a `/device/poll` body, a device code or user code only in a `/device/start` body, and none of them in a log line. **Review of 0.2.0 (§17.19)**: a half-set legacy pair — a whole login and a device-client refresh succeed, a `/refresh` without `client` → `500 server_misconfigured` naming both secrets (not "log in again", Google not asked), the home page says `Status: ready` with the warning; a removed address is masked in the `/refresh` answer.
- **The production wiring** (`refresh.test.ts`, in the Workers runtime — the only tests that do not inject `deps`): `defaultDeps.google` equals the three URL constants of §2.2; `defaultDeps.fetch("http://127.0.0.1:9/")` settles with a network failure whose message does **not** contain `Illegal invocation` (a bare `fetch` stored in an object loses its `this` under workerd and would make every route that asks Google a `502` after deployment); one request through the **default export** — `worker.fetch(new Request("https://auth.test/"), env)` — returns the home page with `Status: ready`.
- **Contract fixture** (`contract.test.ts`): every case of `worker/test/contract.json` (§16.5) is reproduced by `handle()` with the harness's `env` and fake Google; the file contains every case name listed in §16.5; an unknown `given` keyword or matcher fails the test.
- **Configuration** (`scripts/check-config.mjs`, run by `npm test` before Vitest): `wrangler.jsonc` has `observability.logs.invocation_logs === false`, `observability.redact_query_string === true`, `observability.traces.enabled === false`, no `destinations` key anywhere, no tail consumer and no Logpush, `preview_urls === false`, no `vars` key, the `RATE_LIMIT` entry under `ratelimits` with `limit: 30, period: 60`, and no storage binding. `scripts/check-config.selftest.mjs` (`node --test`, run by `npm test` right after the check) proves the checker: the shipped file passes, the configuration as shipped before §17.7 is refused, and each of those keys weakened or removed — at the top level or inside an `env.<name>` — is reported; a custom-domain `routes` entry is accepted. **The check is an allowlist (§16.2, §17.19)**: `scripts/check-config.selftest.mjs` also reports `unsafe` (with a KV namespace in `unsafe.bindings`), `env` in every form (an environment without `ratelimits`, with an empty or a weaker one, with storage or `vars`, a copy of the shipped file), binding types no list of forbidden names had (`ai`, `browser`, `send_email`, `containers`, `vpc_services`, `mtls_certificates`, `images`, a made-up one), unknown keys under `observability`, in a route and in the rate-limit entry, and `logpush` with any value. `scripts/setup.selftest.mjs` (same runner) runs `sh setup.sh --authorized-domain <host>`: `<acct>.workers.dev` for a `workers.dev` host, the registrable domain — never the host itself — for a custom host.
- **Custom domain from the start** (§17.14; `scripts/custom-domain.selftest.mjs` and `scripts/setup.selftest.mjs`, `node --test`): `custom-domain.mjs` turns the shipped `wrangler.jsonc` into one that serves the Worker from the given host only — one `routes` entry with `custom_domain: true`, `workers_dev: false`, every requirement of `check-config.mjs` still met, one line rewritten and one added, comments kept — is idempotent, replaces an earlier host, refuses what is not a bare lower-case host name of one's own (a URL, a port, a path, upper case, an IP address, a `workers.dev` host, text that would inject a key) and a file that is not the shipped shape, and writes only the file it is given; `setup.sh` passes `sh -n` and asks for the host before the first deploy and before the Google checklist.
- `npm ci` works from the committed `package-lock.json`; `npm run typecheck` (= `wrangler types && tsc --noEmit` — a bare `tsc` fails on a fresh checkout because `worker-configuration.d.ts` is generated and git-ignored) passes; `npx wrangler deploy --dry-run` builds the bundle (no upload); `package.json` has no `dependencies`, only `devDependencies`.

---

## 13. Test plan (summary)

1. **Unit / known-answer** (WP1): §4.7. Frozen vectors guard the format against drift.
2. **Property tests** (WP4, WP6; seeded xorshift, reproducible via `GCLONE_TEST_SEED`): merge convergence incl. `removed`, snapshot equivalence, fork + partial snapshot convergence, SQLite ≡ in-memory model, planner invariants ("first sync never deletes", "no action pair touches one key twice", "copy never deletes", "excluded keys produce no actions").
3. **Backend conformance** (WP2/WP3): one suite in the library (`backend::conformance::run`), four implementations (Mem, Dir, Flaky<Mem>, Drive-over-fake-HTTP).
4. **HTTP protocol** (WP3): `FakeDrive` on wiremock, emitting the literal wire shapes of §6.4.1 — resumable state machine, paging, error mapping, pacer with paused tokio time — and playing the auth Worker per §2.3 (fake `/auth/device/start`, `/auth/device/poll`, `/auth/refresh`, `/revoke`): the device-code login with a fake user who enters the code, polling through pending / slow-down / failed polls, refresh for both clients, revoke, every error mapping of §2.4, without Google or Cloudflare.
5. **Adversary modes** (WP4/WP5): rollback, a new device against stale state (trust on first use, then detection), garbage-named state, withheld/renamed/foreign/truncated index objects, index objects in a newer format (stop, never "damaged"), oversized index objects and descriptors (never buffered), blob swap/slice/truncate/tamper — each must yield its specific error and never a wrong plaintext or a silent state change.
6. **Fault injection / crash safety** (WP4–WP6): failpoints at every commit step, lost acknowledgements, cut streams, list lag, cloned state, stuck outbox (incl. one whose blobs were swept or collected meanwhile, §17.11), kill between staging and commit; reruns converge with no duplicate objects referenced and no dangling references.
7. **API budget assertions** (WP6): §6.6 numbers via `Counters`; hash counts via `Summary.hashed`.
8. **CLI end to end** (WP7): two "devices" over a directory vault (`login` creates, `login` attaches, `passwd`, `logout`), recovery drill in both directory layouts, exit codes, JSON output; one run of the real binary against `FakeDrive` (every login with `--no-browser`) covering login → vault creation → second device → expired login → re-login → wrong-account re-login → logout → login without a URL → `logout --revoke`; and the move of a login of the legacy client to the device client (§17.18).
8a. **The browser view** (0.3.0, §7.4; `tests/web.rs`): the built binary serving a directory vault on a free loopback port, driven through a raw TCP client so that every header is the test's own — the session on every route, the one-time link, `Host` / `Origin` / `Sec-Fetch-Site`, listing order and paging, search, ranges, `HEAD`, `ETag` / `304`, type / disposition / CSP per kind of file and for hostile names, a file of twenty chunks, a pack member, an empty file, a damaged and a missing blob, the stream limit and a disconnect, a second device's upload after "refresh", the state lock, the start errors of `ls`, Ctrl-C; one run against `FakeDrive` for token renewal in a running server. Since §17.21: the cookie's path and foreign cookies in the same header, repeated and unreadable `Origin` / `Sec-Fetch-Site`, the 64 KiB head, `HEAD` with `Range`, search order against listing order, files by `id`, `logout` and `logout --forget` under a running viewer, and — on a pseudo-terminal that is the child's controlling terminal — Enter (a new link ends the session and its download) and a viewer that is a background job (it must answer); what the browser launcher is given (`GCLONE_TEST_BROWSER`). Unit tests for the type table, the range parser, the header encoders, the listing order, and that the embedded page references only its own assets and has no inline script.
9. **Auth Worker** (WP8): Vitest in the Workers runtime with an injected fake Google (`fetch`) — every route, every error code, the states of a device code, the two clients of `/refresh`, the rate limit, the allowlist, secret hygiene — plus the few tests that exercise the un-injected production wiring (`defaultDeps`, the default export) and the configuration check (§12.1, §16.5). **Contract** (WP8 + WP3): the Rust fake (item 4) and the Worker implement the same §2.3 text, and `worker/test/contract.json` holds them to it — the Worker's tests reproduce every case with the real `handle()`, WP3's `tests/auth.rs` reproduces every case with `FakeDrive` and feeds the answers through the Rust client. What no automated test covers is the real Google and the real Cloudflare edge: that is item 10.
10. **Live** (manual, opt-in; needs the user's deployed Worker — the implementation work packages deploy nothing): `GCLONE_LIVE=1 cargo test -- --ignored` runs `tests/live.rs` (WP7; without `GCLONE_LIVE=1` its tests return at once, and WP1's `gen_vectors` has its own guard, `GCLONE_GEN_VECTORS=1`, so this command never rewrites frozen vectors) — the conformance suite and a small e2e against a throwaway vault, using the login of the configured device — this is what confirms the wire shapes of §6.4.1 against the real service; `gclone probe` answers the automatable rows of §2.9 and the README checklist the manual ones (first real `gclone login` on two devices = probes 1, 2, 5). Run once before first real use and after any Google policy change.

CI commands: `nix-shell -p cargo rustc --run 'cargo test --locked --all-targets'` and `nix-shell -p nodejs --run 'cd worker && npm ci && npm run typecheck && npm test'` (no credentials, no network beyond the package registries; `npm ci` needs the committed `worker/package-lock.json`, `--locked` the committed `Cargo.lock`).

---

## 14. Deferred features (explicitly out of the MVP), most valuable first
1. **Pack compaction / repack** (`gc --repack`): copy live member ciphertext verbatim into a new pack (no re-encryption), journal the relocation. Until then `about` reports dead space inside packs; raise `PACK_MEMBER_MAX` only after this ships.
2. **Parallel ranged download** of one large file.
3. **`gclone key export` / `key import`**: print the master key as a recovery string for offline storage (a way back in when the passphrase is forgotten and no device is left), and accept it in `login` instead of the passphrase.
4. **Keychain secret store** behind `SecretStore`; a mode that does not cache the master key and asks for the passphrase per session.
5. **`rotate` / re-key** (after manual probe 3): new epoch, snapshot with `min_epoch`, a new keyfile generation carrying the new key, optional re-encrypt — the only real answer to a leaked passphrase or a stolen device.
6. **Cross-restart upload resume**, safe variant only. Constraints any design must meet: (a) the ledger is **write-ahead** — each part's ciphertext (preferred) or at least its hash is persisted and fsynced *before* the part is handed to the HTTP layer, because a part may reach Google without ever being acknowledged; (b) no chunk index is ever sealed twice with different plaintext: either the persisted ciphertext of unacknowledged parts is replayed and nothing is re-sealed, or re-sealing goes through a dedicated `ResumeSealer` that can only be constructed from the ledger and refuses to emit any part whose hash differs from its ledger entry — for **every** part that has a ledger entry, not only up to the server's acknowledged offset; (c) any mismatch abandons the session for a new salt, blob id and Drive ID. The general `Sealer` never gains a salt-taking constructor.
7. `repair --from-blobs` with a blob manifest trailer (stream type 0x04 and the `GCBLOB01` footer are reserved, §4.5; its acceptance rules must be specified with it); `cp :a :b`; propagation of case-only renames; nested `.gcloneignore`; `gc` grace override for a full Drive; `--json` results for the commands other than `copy` / `sync` (they refuse the flag, §7.1); `restore` of a directory as of a point in time, and of empty-directory markers (§5.5.4).
8. Auth hardening: DPoP-bound refresh tokens (the Worker would have to hold or proxy the proof key); verifying the ID-token signature; **Worker-sealed refresh tokens** — `/device/poll` would return the refresh token sealed under a Worker key with the e-mail inside, so that `/refresh` rejects anything it did not issue without contacting Google and re-checks the allowlist on every refresh, with or without an ID token (costs that kept it out of v1: `logout --revoke` could no longer hand the token to Google directly, and rotating the sealing key would sign every device out); **a confirmation step against device-code phishing** (§2.3.2) — the stateless Worker has no page between the user and Google; closing the gap would take state (a short-lived record of who started a login) or a second factor shown only by the real device; a `login --expect-head XXXX-XXXX` that fails closed; excluding the secrets file from Time Machine by extended attribute. (History: v1.1 considered the device-code flow and v1.2 chose a browser redirect with a paste fallback instead; 0.2.0 reversed that, §0.6.)
9. Two-way `bisync` command (the planner already supports running `sync` up then down); `--backup-dir`; `--bwlimit`.
9a. `gclone web` beyond viewing (§7.4 is read-only on purpose): upload, rename, delete and restore from the page; a list of deleted versions; thumbnails.
10. FUSE mount (not planned: gclone is an rsync-style tool); symlinks, xattrs, full permission bits (a download keeps the bits of the file it replaces, §5.7 step 2; they are not transported), directory mtimes.
11. zstd index codec; binary/sharded index for > 1 M files (incl. a coverage summary readable without the whole snapshot); size padding; AES-GCM/aws-lc-rs suite; shared drives; Windows; migration of rclone crypt remotes.

## 15. Known limits and accepted risks
- The index is critical state: redundancy = every device's SQLite replica + ciphertext cache (`repair`), two retained snapshots, 30-day Drive trash. There is no way to rebuild the index from blobs alone in v1 (manifest trailer deferred, §4.5).
- Secrets are plaintext in a 0600 file (this device's refresh token and the cached master key). It lives under the state root rather than `~/.config`, and gclone refuses it when its permissions are too open (§8.1) — but a backup or sync tool that copies `~/.local/state/gclone` copies the key, and the key cannot be rotated in v1: exclude that directory from backups that leave the machine, and never copy `secrets.json` to another device.
- **The passphrase is the root of confidentiality against Google and Cloudflare**: the keyfile on Drive can be attacked offline at Argon2id cost (256 MiB, t = 3). The generated 100-bit passphrase is safe; a typed one is as strong as the user made it (12-character minimum, warning below 20). `passwd` does not help against someone who already copied an older keyfile; only re-keying (deferred) does.
- All devices share one master key. Refresh tokens are per device, but Google can revoke only the whole grant: there is no per-device revocation — `logout` discards a token locally, the lost-device procedure (§2.8) signs out every device, and a stolen device keeps the master key it cached.
- The auth Worker is a single point of failure for *logins and token refreshes* (not for data): if it is down or its Google client is deleted, devices work until their access token expires (≤ 1 h); after that every command that needs Drive fails with exit 4 until it is back, while `ls`, `tree`, `status` and `about` keep answering from the local replica with a warning (§9.10, §17.9). It is stateless and redeployable from `worker/` in minutes; the vault stays reachable through a web download + `--vault-dir`. Its URL is public, and on the `workers.dev` host nothing stops a stranger from spending the plan's daily request quota (Free: 100,000 requests/day; Cloudflare then answers errors until midnight UTC): the Worker's own rate limit runs *inside* the Worker, so refused requests still count, and zone-level rate-limiting rules do not apply to `*.workers.dev`. Every device then loses token refresh within the hour, for as long as the flood is repeated. Data is not at risk and the directory recovery path stays open; the remedy is a custom-domain route with a zone rate-limiting rule in front (§16.6), or the paid plan.
- Each `gclone login` adds one live refresh token; Google keeps the 100 newest per account and client and silently drops older ones. A device's token also dies after six months without use. Both cost one `gclone login`.
- **Device-code phishing** (§1.3, §2.3.2): whoever gets the owner to enter a code from a login the owner did not start, at Google's own page, obtains a refresh token for the vault's files. `/device/start` cannot be authenticated and the allowlist cannot notice it (the consenting account is the allowed one). The terminal's warning with every code, the fixed scope and the rate limit are the mitigations; what a phished grant yields — ciphertext and the keyfile, trash that is recoverable for 30 days, nothing outside the vault — is listed in §1.3.
- **A lost poll answer loses the login** (§2.3.1): Google's device code is single-use and the Worker stores nothing, so tokens that leave Google and do not reach the device are gone; `gclone login` again.
- **Two OAuth clients during the transition of §17.18.** While `GOOGLE_LEGACY_CLIENT_ID` / `_SECRET` are set the Worker holds a second client secret, and devices that have not run `gclone login` since 0.2.0 depend on it. Whether a vault created through the legacy client is visible to the device client is unverified (probe 4): `login` reports it and changes nothing.
- Keyfile handling on a new device trusts unauthenticated listing data only within fixed bounds (4 candidates, 512 MiB / t ≤ 4 each, 3 passphrase attempts). Someone who can write to the vault folder can still hide the real keyfile behind four planted ones or delete it — a denial of service like any deletion; `gclone passwd` on a connected device repairs it.
- A fresh device trusts the vault state it is first served (trust on first use): by itself it cannot detect that Google serves it a stale vault — comparing the **head fingerprint** with `gclone status` on a device that is known to be current is the check (§2.6), and it is manual; withholding of the very newest segments is detected only once another device references them. Remote *presence* of objects this device already applied is judged from listing names (a server that lists a name but withholds the bytes is noticed by the devices that still need them, as `Gap`).
- Snapshots are uncompressed postcard (~130 bytes/file, plus ~14 bytes per segment ever written for `covered`): comfortable to ~300k files, works to ~1 M (≈ 150 MB snapshot, held in RAM while loading). The format's hard limit is `INDEX_OBJECT_MAX` = 1 GiB per index object (§4.6 rule 1; roughly 7 million files in one snapshot): beyond it `write_snapshot` fails with `BadEntry` instead of publishing an object no reader would accept (commits keep working; compaction does not, and the command that tried it reports the error). Every device downloads each newly published snapshot once (to adopt it, §5.3).
- Index objects and the descriptor are read into memory before anything in them is authenticated. The reads are bounded (`INDEX_OBJECT_MAX`, `DESCRIPTOR_MAX`; oversized objects are reported and ignored), but the bound for index objects has to leave room for the largest legitimate snapshot: someone who can write to the `index` folder can still make a refresh buffer up to 1 GiB at a time for an object listed with its true size (objects listed above `INDEX_PARALLEL_MAX` are fetched one by one), and a store that lies about sizes up to eight times that. The same parties can stop every device with one planted object whose header claims a newer format (`UnsupportedObject`, §4.6: those header bytes cannot be authenticated by a build that does not implement them) until the object is removed in drive.google.com. Both are denial of service by parties that can delete the vault anyway (§1.3); neither changes a replica.
- Uploads need an uplink of about `UPLOAD_MIN_RATE` (8 KiB/s ≈ 64 kbit/s) **per upload stream** — `transfers` streams share the link. Below that, requests run into their total timeout (§6.4): a resumable upload then advances only by what Drive kept of each cut part (as long as it advances it is not given up, §6.2 step 7), a multipart upload starts over and fails after its attempts. `--transfers 1` is the remedy on a very slow link. The stall watch sees bytes leave the HTTP stack, not the network: a connection that dies after the whole body was handed to the kernel is noticed only by the total timeout or by TCP itself.
- A sealed segment that waited in the outbox until its blobs could no longer be trusted (older than 7 days and unpublished, trashed by another device's `gc --orphans` and purged, or collected) is withdrawn and its files are uploaded **again** (§5.8) — on a Drive that stayed full for more than a week that costs the space twice until the first copies, now orphans, are swept (`gc --orphans`, then Drive's 30-day trash; `gc --purge` deletes only blobs of the blob table). The check before publishing and another device's sweep are not atomic: a sweep that listed the blob before the segment became public can still trash it afterwards; `gclone check` un-trashes it within Drive's 30 days. A `restore` whose segment is stuck on one device does not stop **another** device's `gc --purge` from deleting that version once it is 30 days dead; the restore is then dropped with a warning instead of published.
- An index object that fails acceptance is downloaded again by every refresh (up to `INDEX_OBJECT_MAX` each time) until it is removed; rejections are remembered for one refresh only. A persistent record would have to be proof against a rejection caused by a damaged transfer rather than by the object (§17.11, deferred).
- Dead space in partly dead packs is not reclaimed (≤ 16 MiB per pack). On a full Drive, space comes back only through `gc` + `gc --purge`, i.e. for data deleted more than 30 days ago.
- Large-file sizes, object counts, timing, and per-device activity are visible to Google.
- Size + mtime + ctime change detection misses content changes that preserve all three (same class as rsync/rclone; `--checksum` available).
- Case folding is Unicode full case folding in user space; a file system with different folding rules is caught by the download-time backstop (§5.7 step 3) as a skipped collision, not resolved.
- A sync root on a file system without stable inode numbers trips the root-identity guard on every remount and needs `--keep-pair`.
- Permission bits are not transported (only `exec`): a file that is private (0600) on the device that created it arrives on every other device with that device's umask default (normally 0644). A download never *widens* an existing file (§5.7 step 2), but the first copy on a new device is as open as the umask allows — set a umask of 077, or tighten the files, where that matters (§17.12).
- Paths that share one content are downloaded once and written one after another (§5.7 step 2). For content above 1 MiB the other paths are local copies of the first file written; a write error on that first file (disk full, I/O error) fails all of them in that run, although some might lie on another file system.
- gclone's own directories are recognised by their canonical paths (§5.5.3). A copy of them elsewhere under the sync root — or another user's, or another gclone installation's — is ordinary data and is synced. Entries of these names uploaded before §17.12 stay in the vault until removed with `gclone rm -r`.
- `gclone web` (§7.4) keeps the vault's names out of the browser's history, title and addresses, **not out of the browser**: the place in the vault is in `history.state`, which the browser writes into its session-restore data on disk for as long as the tab or its "recently closed" entry exists (seen in Chrome's `Sessions/Session_*`; not in `History`, not synced); a file that is downloaded is in the download list with its name, as any download; a PDF or image opened in a tab of its own has whatever title the browser gives it (for a PDF: its embedded title). Decrypted content is `no-store` everywhere. Someone who can read the browser profile can read the vault through the viewer anyway.
- `gclone web`'s session cookie is scoped to a random path so that no other loopback server receives it (§7.4). The path is not a secret from the browser's side: an extension, or anything else that reads the address bar, knows it, and a server on another loopback port that **also** knows it — and can get the browser to request that path from it — would be sent the cookie. Nothing in gclone hands the path out (`Referrer-Policy: no-referrer`, no log line). A new link (Enter) replaces path and cookie.
- A `gclone logout` ends a running viewer within about a second (§7.4), not atomically: a Drive viewer that renews its access token in exactly that second writes `token.json` once more after `logout` removed it (an access token, at most an hour of life; the next `logout` or `login` removes it). Not reproduced; inferred from the code.
- The launch page of `gclone web` (§7.4) is opened by the browser as a local file. A browser that is confined away from gclone's state directory (a snap or flatpak build cannot read `~/.local/state`) shows an error instead; the terminal says to press Enter, which prints a link to paste. Not verified on Linux.
- `gclone web` shows PDFs with the browser's built-in viewer and media with the browser's decoders: a flaw there is the browser's, and gclone's sandboxing of other content does not extend to it. The page was exercised in Chrome only; Firefox and Safari are untested (the PDF response carries `default-src 'none'`, which Chrome's viewer accepts).
- After two devices uploaded identical content with different mtimes or exec bits, the remote keeps the first uploader's metadata and the other device keeps its own until it syncs down (§5.5.1 row 1).
- Unverified Google and Cloudflare behaviours (RESEARCH.md `[U]`/`[M]`, the `[K]` wire shapes of §6.4.1 and §16.4, the scope of a revoke, an ID token in the device grant's token answer (probe 5: without it every login fails closed) and on refresh answers, the error code of an expired device code, what Google answers to a refresh token presented by another client of the project, whether one client's `drive.file` files are visible to another client of the project (probe 4), the exact `scope` text of token answers (the Worker accepts only `ALLOWED_SCOPES`, so an unexpected spelling fails closed with `scope_not_allowed`), the `ratelimits`, `invocation_logs`, `redact_query_string`, `traces` and `preview_urls` keys of `wrangler.jsonc` and what Cloudflare attaches to a stored log event, the form of `cf-connecting-ip`, Wrangler's var/secret name clash) are isolated behind the probes of §2.9, the configuration check and `wrangler deploy --dry-run` of §12.1 (WP8), and the live run of §13, with stated fallbacks.

---

## 16. The auth Worker (`worker/`, WP8)

A Cloudflare Worker in TypeScript: about 700 lines, no runtime dependencies, no storage (its one binding is a rate limiter). It implements exactly the HTTP API of §2.3 — Google's device authorization grant, proxied — and nothing else; this section fixes its files, configuration, code structure and tests. **No work package deploys it** — deployment is the user's one-time setup (§2.1); everything here is built and tested locally.

### 16.1 Files
```
worker/
  package.json          private, "type": "module". Scripts: "dev": "wrangler dev", "deploy": "wrangler deploy",
                        "test": "node scripts/check-config.mjs && node --test scripts/check-config.selftest.mjs
                        scripts/setup.selftest.mjs scripts/custom-domain.selftest.mjs && vitest run", "typecheck": "wrangler types && tsc --noEmit &&
                        tsc --noEmit -p test/tsconfig.json" (the root tsconfig covers src/ only).
                        devDependencies ONLY (wrangler ^4.160.1 — the locked version, in which the `ratelimits` and the
                        `observability.redact_query_string` keys were checked; an older wrangler would silently drop the
                        latter —, typescript ^7.0, vitest ^4.1, @cloudflare/vitest-plugin ^1.0); no "dependencies" at all.
  package-lock.json     committed (CI runs `npm ci`, which fails without it)
  wrangler.jsonc        §16.2
  scripts/check-config.mjs   plain Node, no dependency: reads wrangler.jsonc (strips whole-line `//` comments, then JSON.parse) and exits non-zero unless the
                        file holds ONLY the allowed keys of §16.2 (an allowlist: any other key is refused, so no binding but
                        the rate limiter, no `unsafe`, no `env`, no `vars`) with the security-relevant values as specified
                        (no URL query string in logs or traces and no export of them, no preview hosts, the rate-limit binding)
  scripts/custom-domain.mjs   `node scripts/custom-domain.mjs HOST [file]`: rewrites wrangler.jsonc so that the Worker is served from HOST
                        only — `"workers_dev": false` and `"routes": [{ "pattern": HOST, "custom_domain": true }]`, nothing else,
                        comments kept; idempotent; refuses anything but a bare lower-case host name outside workers.dev, and a
                        result that check-config.mjs would reject. No network, nothing deployed. Called by setup.sh (§17.14).
  scripts/check-config.selftest.mjs, scripts/setup.selftest.mjs, scripts/custom-domain.selftest.mjs   plain Node (`node --test`), run by
                        `npm test`: the checker's own tests; the Authorized-domain line and the step order of setup.sh, that its checklist asks
                        for a "TVs and Limited Input devices" client and that it puts exactly the three secrets; and the
                        wrangler.jsonc edit (§12.1). Named `.selftest.` so that Vitest does not collect them.
  tsconfig.json         strict, target ES2022, module ESNext, moduleResolution "bundler", types from `wrangler types` (worker-configuration.d.ts)
  vitest.config.ts      §16.5
  .gitignore            node_modules/, .wrangler/, .dev.vars*, !.dev.vars.example (the example IS committed), worker-configuration.d.ts
  .dev.vars.example     the three secret names (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, ALLOWED_EMAILS) with placeholder values, and the two
                        optional GOOGLE_LEGACY_CLIENT_* names commented out, for `wrangler dev`
  README.md             the one-time setup of §2.1 in full (with the console click path), secret rotation, changing ALLOWED_EMAILS,
                        custom domain + rate-limiting rule, what is and is not logged, troubleshooting by error code (§2.3), device-code phishing,
                        and the move from the browser sign-in of gclone before 0.2.0 (§17.18)
  setup.sh              interactive helper for §2.1 steps 1, 3, 4 (POSIX sh): ask where the Worker is served — its workers.dev host, or
                        a host name of the user's own, in which case scripts/custom-domain.mjs writes the `routes` entry into
                        wrangler.jsonc BEFORE the first deploy and `https://<host>` is used in everything that follows (§17.14) →
                        deploy → (custom host: wait up to five minutes for it to answer; workers.dev: ask for the printed URL) →
                        print the console checklist with the right URLs (step 5: a client of type "TVs and Limited Input devices", no redirect
                        URI) → `wrangler secret put` ×3 (asked for and piped to `wrangler secret put` — no secret reaches
                        a file; the only tracked file it can change is wrangler.jsonc, for the custom host) → curl the home page. Run by the user only; never by a
                        test or a work package — except as `./setup.sh --authorized-domain <host>`, which prints the checklist's
                        "Authorized domain" value for that host and exits before anything else happens (used by
                        scripts/setup.selftest.mjs). That value is `<acct>.workers.dev` for a workers.dev host and otherwise the
                        host's last two labels with a note that Google wants the registrable domain, not the host (§16.6).
  src/index.ts          default export + `handle()`: routing, transport rules, the two pages and the three JSON routes
  src/google.ts         the configured clients, device-code request, device-code poll, refresh, revoke, ID-token payload, error mapping
  src/pages.ts          the two static HTML pages and their headers
  test/helpers.ts       literal test `Env`, fake Google `fetch` with a call log (device-code, token and revoke endpoints; a started login
                        is approved, denied, expired or slowed down by the test), `makeIdToken()`, fake rate limiter, console spy
                        with the secret-hygiene check after every test, the contract-case runner
  test/device.test.ts, test/refresh.test.ts, test/contract.test.ts      (§12.1 WP8)
  test/contract.json    the device ↔ Worker contract as data (§16.5); also read, read-only, by WP3's tests/auth.rs
  test/tsconfig.json    extends ../tsconfig.json, adds "@cloudflare/vitest-plugin/types"
```

### 16.2 Configuration
| Binding | Kind | Value |
|---|---|---|
| `GOOGLE_CLIENT_ID` | secret (`wrangler secret put`) | the ID of the client of type "TVs and Limited Input devices": every login, and the refresh tokens those logins issue |
| `GOOGLE_CLIENT_SECRET` | secret | its secret — exists nowhere else |
| `GOOGLE_LEGACY_CLIENT_ID`, `GOOGLE_LEGACY_CLIENT_SECRET` | secrets, **optional**, used only when both are set | the "Web application" client of the browser sign-in before 0.2.0; used by `/refresh` only, for requests without `"client": "device"` (§2.3). One without the other takes nothing but that client away (a legacy refresh then answers `500 server_misconfigured`; the home page warns). Deleted once every device has run `gclone login` again (§17.18). |
| `ALLOWED_EMAILS` | secret — **only** a secret, never a `vars` entry | comma-separated Google account addresses; empty or not set = nobody. Compared byte for byte but for the case of ASCII letters; an entry that is not printable ASCII matches nobody (§2.3) |
| `RATE_LIMIT` | rate-limit binding (`ratelimits` in `wrangler.jsonc`; no storage product, no namespace to create) | `AUTH_RATE_LIMIT`: 30 requests / 60 s per key — the client's IPv4 address or IPv6 /64 (§2.3) |

No KV, D1, R2, Durable Object, queue, cron or service binding; no route in the shipped file (the `workers.dev` host is used; a custom domain — recommended, §16.6 — is a `routes` entry the user adds to this file; the OAuth client names no URL and needs no change).
```jsonc
// worker/wrangler.jsonc
{
  "$schema": "./node_modules/wrangler/config-schema.json",
  "name": "gclone-auth",
  "main": "src/index.ts",
  "compatibility_date": "2026-11-01",
  "workers_dev": true,
  "preview_urls": false,
  "observability": {
    "enabled": true,
    "redact_query_string": true,
    "logs": { "invocation_logs": false },
    "traces": { "enabled": false }
  },
  "ratelimits": [ { "name": "RATE_LIMIT", "namespace_id": "1001", "simple": { "limit": 30, "period": 60 } } ]
}
```
These things in this file are **security requirements**, asserted by `scripts/check-config.mjs` on every `npm test`:
- **The file holds the allowed keys and nothing else** (§17.19). Top level: `$schema`, `name`, `main`, `compatibility_date`, `compatibility_flags`, `workers_dev`, `preview_urls`, `routes`, `observability`, `ratelimits`. Under `observability`: `enabled`, `head_sampling_rate`, `redact_query_string`, `logs` (`enabled`, `head_sampling_rate`, `invocation_logs`), `traces` (`enabled`). In a `routes` entry: `pattern`, `custom_domain`, `zone_id`, `zone_name`. In the `ratelimits` entry: `name`, `namespace_id`, `simple` (`limit`, `period`). Every other key is a problem, whatever its name — a list of forbidden names cannot know every binding type Cloudflare has or will have. Two consequences are spelled out in the messages: **no `unsafe`** (`unsafe.bindings` attaches a binding of any type, a KV namespace included) and **no `env`** (a wrangler environment inherits no bindings, so `wrangler deploy --env <name>` would deploy a Worker without the rate limiter — and the Worker lets every request through when `env.RATE_LIMIT` is undefined, §16.3; the limiter is also what keeps one sender from mass-producing device codes, §2.3.2).
- **Nothing of a request is stored beyond the Worker's own log line** — four settings, all required. Since 0.2.0 no route carries a secret in its URL (device codes and tokens travel in POST bodies), so these are a second line rather than the only one; they stay:
  - **`logs.invocation_logs: false`.** With observability on, Cloudflare by default stores one invocation log per request with the method, the full URL and headers, kept for days and readable by anyone with log access to the account, whatever the code passes to `console.log`.
  - **`redact_query_string: true`.** Switching invocation logs off removes only that separate event. Cloudflare attaches the triggering request to **every** stored log event — the Worker's own one-line logs included — and to traces (the telemetry event type carries `$metadata.url`, "Request URL that triggered the Worker invocation", and `$workers.event` on events of type `cf-worker-log`; [K], read from Cloudflare's API types, not observed on an account). This key ("Whether query strings are removed from request URLs in logs and traces", default `false`; present in wrangler 4.160.1, the floor in `package.json`) removes the query string there.
  - **`traces: { enabled: false }`.** Traces record requests as well; nothing here needs them, and the top-level `enabled: true` must not start them when Cloudflare changes that default.
  - **No `destinations`** (under `logs` or `traces`), **no `tail_consumers` / `streaming_tail_consumers`, no `logpush`**: nothing exports logs or traces out of the account.
- **`preview_urls: false`.** Preview URLs serve each uploaded version of the Worker under its own `<version>-gclone-auth.<acct>.workers.dev` host: an old version — one from before a security fix, with the current secrets — would stay reachable, and outside any zone rule of a custom domain. (With the key omitted Cloudflare derives the setting from `workers_dev`; pinning it makes the shipped state independent of that.)
- **No `vars`.** Vars and secrets share one binding namespace: while the deployed version has a var `ALLOWED_EMAILS`, `wrangler secret put ALLOWED_EMAILS` is refused, and every `wrangler deploy` from a file with `"vars": { "ALLOWED_EMAILS": "" }` would re-assert the empty value — an empty allowlist, every login refused ([K]: Wrangler behaviour from memory, not re-checked). The allowlist is therefore a secret only, the shipped file has no `vars` key, and the code treats an undefined `env.ALLOWED_EMAILS` as empty.
- **The `ratelimits` entry** — exactly one, named `RATE_LIMIT`, `simple: { limit: 30, period: 60 }`, and the Worker's only binding (Workers Rate Limiting binding; [K]: key name and shape as of wrangler 4.36 — if the installed wrangler rejects it, WP8 corrects the key and records it in the Errata). `namespace_id` is any integer string unique within the account; `period` must be 10 or 60.

`secrets.required` is deliberately **not** declared: `wrangler deploy` fails while a required secret is missing, and the first deploy has to happen before the Google app's branding can name the Worker's host. The Worker checks its configuration at request time instead (`server_misconfigured`, §2.3). No `compatibility_flags`: no Node API is used.

### 16.3 Code structure (signatures are the contract between the three source files and the tests)
```ts
// ---------- src/index.ts ----------
export interface RateLimiter { limit(options: { key: string }): Promise<{ success: boolean }> }      // the shape of a Workers rate-limit binding
export interface Env { GOOGLE_CLIENT_ID: string; GOOGLE_CLIENT_SECRET: string;            // the device client
                       GOOGLE_LEGACY_CLIENT_ID?: string; GOOGLE_LEGACY_CLIENT_SECRET?: string;   // optional, used when both are set: /refresh only
                       ALLOWED_EMAILS?: string;        // a secret; undefined (not yet put) = empty = nobody
                       RATE_LIMIT?: RateLimiter }      // absent in unit tests: then nothing is limited
export interface Deps {
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;   // every request to Google goes through this — tests inject a fake
  google: { deviceCodeUrl: string; tokenUrl: string; revokeUrl: string };            // §2.2 constants by default
}
export const GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code", GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token",
             GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
/** The production wiring — the only Deps no test injects, hence spelled out here and tested as such (§12.1).
 *  `fetch` MUST be a wrapper: under workerd a bare `fetch` stored in an object is later called with `this = deps`
 *  and throws "TypeError: Illegal invocation", which `handle` would turn into 502 on every route that asks Google. */
export const defaultDeps: Deps = {
  fetch: (input, init) => fetch(input, init),
  google: { deviceCodeUrl: GOOGLE_DEVICE_CODE_URL, tokenUrl: GOOGLE_TOKEN_URL, revokeUrl: GOOGLE_REVOKE_URL },
};
export const BODY_MAX = 8192, RATE_LIMIT_RETRY_AFTER_S = 60;
/** The rate-limit key of §2.3 for a `cf-connecting-ip` value: IPv4 as it is, IPv6 as "<first four groups>::/64", null/"" → "unknown". */
export function rateLimitKey(address: string | null): string;
/** The whole Worker. Pure in (request, env, deps): no globals, no storage, no clock. Never throws: unexpected errors → 500 JSON without detail. */
export async function handle(request: Request, env: Env, deps: Deps): Promise<Response>;
export default { fetch: (request: Request, env: Env) => handle(request, env, defaultDeps) } satisfies ExportedHandler<Env>;

// ---------- src/google.ts ----------
export const SCOPES = "openid email https://www.googleapis.com/auth/drive.file";       // what /device/start asks for; nothing a device sends can change it
export const SCOPE_DRIVE_FILE = "https://www.googleapis.com/auth/drive.file";
export const ALLOWED_SCOPES: readonly string[];        // §2.2: openid, email, …/auth/userinfo.email, SCOPE_DRIVE_FILE
/** The entries of a space-separated `scope` answer outside ALLOWED_SCOPES; empty = fine. Used by /device/poll and /refresh (§2.3). */
export function excessScopes(scope: string): string[];
export const DEVICE_CODE_RE = /^[A-Za-z0-9_\/.~+=-]{16,512}$/, REFRESH_TOKEN_RE = /^[A-Za-z0-9_\/.~+=-]{20,512}$/;      // the pre-filters of §2.3
export interface Client { id: string; secret: string }
export interface Clients { device: Client; legacy: Client | null; legacyIncomplete: boolean }     // legacyIncomplete: exactly one legacy secret is set (then legacy is null)
/** null = the device pair is missing. A half-set legacy pair is NOT null: only the legacy client is gone (§2.3 "Configuration"). */
export function configuredClients(env: Env): Clients | null;
export type GoogleResult<T> = { ok: true; value: T } | { ok: false; status: 400 | 403 | 500 | 502; error: string; message: string };   // already mapped per §2.3
export type GoogleFailure = Exclude<GoogleResult<unknown>, { ok: true }>;
export const DEFAULT_POLL_INTERVAL_S = 5;                                                           // RFC 8628 §3.5, when Google names no interval
/** `403 grant_unusable`: Google issued the grant (the code is consumed) and the Worker cannot hand it out. `what` completes
 *  "Google approved the sign-in, but …". Used by pollDeviceCode and by /device/poll's ID-token checks. */
export function grantUnusable(what: string): GoogleFailure;
export interface DeviceCode { device_code: string; user_code: string; verification_url: string; expires_in: number; interval: number }
/** §2.3 /device/start: client_id + SCOPES to Google's device-code endpoint; the five fields, shape-checked (`interval` absent → 5), or a mapped error. */
export async function requestDeviceCode(client: Client, deps: Deps): Promise<GoogleResult<DeviceCode>>;
export interface DeviceTokens { refresh_token: string; access_token: string; expires_in: number; scope: string; id_token: string; refresh_token_expires_in?: number }
/** §2.3 /device/poll, step 1–2: one token request for the device code. authorization_pending / slow_down / expired_token come back as
 *  status 400 under Google's own code, whatever status Google used; a token answer without refresh token, access token or ID token
 *  as 403 grant_unusable. */
export async function pollDeviceCode(client: Client, deps: Deps, deviceCode: string): Promise<GoogleResult<DeviceTokens>>;
/** `id_token` is passed through when Google sent one, for the allowlist re-check of §2.3 (done by the caller in index.ts). */
export async function refreshAccessToken(client: Client, deps: Deps, refreshToken: string): Promise<GoogleResult<{ access_token: string; expires_in: number; scope: string; id_token?: string }>>;
export async function revokeToken(deps: Deps, token: string): Promise<void>;                                                // best effort, never throws
export interface IdClaims { aud?: string; iss?: string; email?: string; email_verified?: boolean }
export function idTokenClaims(idToken: string): IdClaims | null;                                                            // payload only, no signature check (§2.3)
/** aud == the client's id and iss is Google's; used by /device/poll (else 403 grant_unusable) and by /refresh (else the id_token is ignored). */
export function claimsFromGoogle(client: Client, c: IdClaims | null): boolean;
export function emailAllowed(env: Env, c: IdClaims): boolean;                                                               // email_verified === true, the claim is printable ASCII and — ASCII case aside — a listed address
export function allowedEmails(env: Env): Set<string>;                                                                       // trimmed, ASCII letters lower-cased; empty and non-ASCII entries dropped; undefined → empty
export function maskedEmail(email: string | undefined): string | null;                                                      // "s***@example.net" for error answers; null when there is nothing presentable
export function b64urlDecode(text: string): Uint8Array | null;                                                              // null on any invalid character or length

// ---------- src/pages.ts ----------
export type Status = "ready" | "legacy_incomplete" | "not_configured";
export function homePage(status: Status): Response;                                    // "Status: ready" | "Status: ready. Warning: only one of GOOGLE_LEGACY_CLIENT_ID and
                                                                                       // GOOGLE_LEGACY_CLIENT_SECRET is set; …" | "Status: not configured"; the code warning, links /privacy
export function privacyPage(): Response;
```
Rules for the code:
- **Web standard APIs only**: `fetch`, `Request`/`Response`/`URL`/`URLSearchParams`, `TextEncoder`/`TextDecoder`, `AbortSignal`. No Node built-ins, no `cloudflare:*` import in `src/`, no npm runtime package, **no cryptography**: the Worker neither seals nor compares secrets.
- Stateless: no module-level mutable state, no clock.
- Requests to Google carry `AbortSignal.timeout(10_000)` and `redirect: "manual"` (the client secret is never re-sent to another address); any exception becomes `upstream_error`. `upstream_error` (502) is only ever answered where Google gave no usable answer; once a device-code poll was answered with tokens, every refusal is a 403 (§2.3).
- The request body is read only after the `Content-Type` and `Content-Length` checks, and rejected when longer than `BODY_MAX`.
- Logging: at most one `console.log(JSON.stringify({ route, status, error }))` per request. Never a body, a query string, a header, a device code, a user code or a token. `route` is one of the five paths or `"other"`.
- Order of checks in `handle`: path → method (`404` / `405`) → the two pages are served here (never limited, no secrets needed) → rate limit (`env.RATE_LIMIT?.limit({ key: rateLimitKey(cf-connecting-ip) })`; an exception thrown by the binding counts as "allowed") → configuration (`500 server_misconfigured`) → `Content-Type` / size / JSON → the route's own work. The pre-filters `DEVICE_CODE_RE` (in `/device/poll`) and `REFRESH_TOKEN_RE` (in `/refresh`) run before any request to Google.
- `/device/start` passes nothing of the request to Google; the legacy client is used by `/refresh` only and never starts or completes a login.
- A mapped Google error is decided by Google's `error` field, not by its HTTP status (below 500): Google answers device-code states with `428` and `403`.

Page content (wording free, these elements required): **home** — one paragraph saying that this is the private sign-in helper of one person's gclone (encrypted file sync to their own Google Drive), that only its owner can sign in; that a sign-in starts with `gclone login` in a terminal and that a code which someone sent must never be entered (§2.3.2); a link to `/privacy`; and the status line; **privacy** — which Google data is touched (the account e-mail address, to check the allowlist; access to the Drive files gclone itself created, via `drive.file`), that the Worker stores nothing and logs no request content — only route, status and error code — and shares nothing, that Cloudflare as the hosting platform processes request metadata (IP address, time, URL path) under its own terms (the page must not claim more than this: "nothing is logged" without qualification would be false), that tokens are passed on only to the owner's own devices, and how to withdraw access (https://myaccount.google.com/permissions). There are no other pages. No page loads any external resource or shows anything taken from a request, and no page, header or answer ever contains an address from `ALLOWED_EMAILS` or the address of an account that tried to sign in: the `403 email_not_allowed` answer shows that account's address masked (§2.3).

### 16.4 Google wire shapes used inside the Worker ([H]/[K], RESEARCH §6.1–§6.3; the test fake emits exactly these)
```
POST GOOGLE_DEVICE_CODE_URL (application/x-www-form-urlencoded: client_id, scope)
  success                  {"device_code":"AH-1Ng…","user_code":"GQVQ-JKEC","expires_in":1800,"interval":5,
                            "verification_url":"https://www.google.com/device"}              (verified against the real endpoint, 2026-11-12)
                           (`interval` is OPTIONAL in RFC 8628 §3.2; Google sends it. Absent → the Worker says 5, §2.3)
  quota exceeded           HTTP 403 {"error_code":"rate_limit_exceeded"}                      (no "error" field → 502 upstream_error)
  wrong client type        HTTP 401 {"error":"invalid_client", …}                             (→ 500 client_invalid)
POST GOOGLE_TOKEN_URL (application/x-www-form-urlencoded)
  device grant             grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code, client_id, client_secret
    not entered yet        HTTP 428 {"error":"authorization_pending","error_description":"Precondition Required"}
    polling too fast       HTTP 403 {"error":"slow_down","error_description":"Forbidden"}
    refused by the user    HTTP 403 {"error":"access_denied","error_description":"Forbidden"}
    code ran out           {"error":"expired_token", …}            [U]: Google's page documents no code for this; RFC 8628 names it (probe 5)
    unknown / used code    HTTP 400 {"error":"invalid_grant", …}
    success                {"access_token":"ya29.…","expires_in":3599,"refresh_token":"1//…","token_type":"Bearer",
                            "scope":"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file",
                            "id_token":"<header>.<payload>.<signature>"}       + "refresh_token_expires_in":604799 for time-limited grants
                           (Google spells the granted `email` scope as …/auth/userinfo.email; every entry must be in ALLOWED_SCOPES
                            and drive.file must be among them, §2.3. The id_token: [K] from Google's "Sign-In on TVs" guide; probe 5.)
  id_token payload         {"iss":"https://accounts.google.com","aud":"<client id>","sub":"1234567890","email":"me@example.com",
                            "email_verified":true,"iat":1794400000,"exp":1794403600}
  refresh, success         {"access_token":"ya29.…","expires_in":3599,"scope":"…","token_type":"Bearer"}
                           (an id_token may be present [U]; when it is, its e-mail is re-checked against the allowlist, §2.3)
  error                    HTTP 400/401 {"error":"invalid_grant","error_description":"Token has been expired or revoked."}
POST GOOGLE_REVOKE_URL (application/x-www-form-urlencoded, token=<refresh or access token>)
  success                  200 {}                 error   400 {"error":"invalid_token"}
```

### 16.5 Tests
`npm test` = `vitest run`, inside the Workers runtime through the current Cloudflare integration (RESEARCH §6.5):
```ts
// worker/vitest.config.ts
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
});
```
- Tests call `handle(new Request("https://auth.test/…"), env, deps)` directly with a literal `env` (`GOOGLE_CLIENT_ID: "device-cid.apps.googleusercontent.com"`, `GOOGLE_CLIENT_SECRET: "test-device-secret"`, `ALLOWED_EMAILS: "me@example.com"`; `withLegacy()` adds the legacy pair) and `deps = { fetch: fakeGoogle.fetch, google: { deviceCodeUrl: "https://google.test/device/code", tokenUrl: "https://google.test/token", revokeUrl: "https://google.test/revoke" } }`. No `.dev.vars`, no bindings from the Wrangler file, no MSW, no real network: the fake `fetch` records every call and answers from a script or from the logins and tokens a test set up; an unscripted call — also a refresh with the credentials of the wrong client — fails the test.
- A full-flow test strings the routes together the way a device and its user would: `POST /device/start` → `POST /device/poll` (`authorization_pending`) → the test approves the login at the fake Google by its **user code** → `POST /device/poll` (the tokens) → `POST /refresh` with the returned refresh token and `"client": "device"`.
- **The un-injected path.** Every test above injects `deps`; the production wiring is covered by the three `defaultDeps` / default-export tests of §12.1, which must run **in the Workers runtime**: only workerd checks the `this` of `fetch`.
- The acceptance list is §12.1 (WP8). `npm run typecheck` and `npx wrangler deploy --dry-run` are part of it; `wrangler deploy` (without `--dry-run`) is not run by anyone but the user.
- (The Node fallback that §16.5 once allowed was never needed, §17.2.) A manual check before a first deploy remains possible: `wrangler dev` with `.dev.vars` serves the same code on `http://localhost:8787`, and `curl -X POST -H 'content-type: application/json' -d '{}' http://localhost:8787/device/start` must answer `500 client_invalid` with placeholder credentials (or `200` with real ones): Google was reached and answered — not `502 upstream_error`.

**The contract fixture `worker/test/contract.json`** — the device ↔ Worker boundary as data. WP8 writes it and proves it against the real `handle()` (`contract.test.ts`); WP3's `tests/auth.rs` reads the same file and proves `FakeDrive`'s auth routes and the Rust client against it (§12.1). It contains only what crosses that boundary: every request and answer of `/device/start`, `/device/poll` and `/refresh`, and the paths that no longer exist. Format (**version 2** since 0.2.0; version 1 was the browser-redirect contract):
```jsonc
{ "version": 2,
  "cases": [
    { "name": "poll_ok",
      "given": "approved",                               // precondition keyword, closed list below
      "request":  { "method": "POST", "path": "/device/poll", "headers": { "content-type": "application/json" },
                    "json": { "device_code": "<device_code>" } },                      // or "body": "<raw text>"
      "response": { "status": 200,
                    "headers": { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },   // these must be present and equal
                    "json": { "refresh_token": "<string>", "access_token": "<string>", "expires_in": "<number>",
                              "scope": "<string>", "email": "me@example.com" } } }      // EXACT key set; "<string>" / "<number>" = any value of that type
  ] }
```
`path` is relative to the auth base URL (`AUTH_URL`; `http://127.0.0.1:<port>/auth` on the fake). Header names are lower-case; a header value may be the placeholder `"<string>"` (present, any value — used for `retry-after`, where the Worker sends 60 and the fake 1). No answer may carry a `Location` header. The only keys are `method`, `path`, `headers`, `json`, `body` (request) and `status`, `headers`, `json` (response); a harness refuses anything else. Placeholders in requests, obtained by the harness from its own implementation per `given`: `<device_code>` (a login started through `/device/start`, in the state the keyword names) and `<refresh_token>`. `given` keywords — each harness maps them to its own means (the Worker's: the scripted fake Google, the fake rate limiter, `env`; the Rust side's: `FakeDrive`'s hooks) — and nothing else is allowed: `none`; for `<device_code>`: `pending` (nobody entered the code), `slow_down`, `denied`, `expired`, `used` (approved and already redeemed once), `approved`, `approved_expiring` (Google sends `refresh_token_expires_in: 604799`), `approved_other_account` (consent by an address outside the allowlist), `approved_no_drive_scope`, `approved_wide_scope` (Google granted `drive.file` **and** full `drive`), `approved_no_id_token` (Google's token answer carries no `id_token`); for `<refresh_token>`: `refresh_token` (a valid one of the device client), `refresh_revoked`, `refresh_wide_scope` (its refresh answer reports that wide scope), `legacy_token` (a valid token of the legacy client, and the legacy secrets are configured), `legacy_unconfigured` (such a token, and they are not), `legacy_half_set` (such a token, and exactly one of the two legacy secrets is set), `legacy_half_set_device_token` (a valid token of the **device** client, obtained by a login while the legacy pair is half-set); `client_broken` (Google answers `invalid_client`); `google_down` (Google answers 503); `rate_limited`; `unconfigured`.

Required cases (names are normative; WP8 may add more, WP3's harness then has to handle them). `/device/start`: `start_ok` (`200`, the five fields by type), `start_client_invalid` (`500`), `start_upstream` (`502`), `start_rate_limited` (`429` + `retry-after`), `start_unconfigured` (`500 server_misconfigured`), `start_wrong_content_type` (`415`), `start_get` (`405` + `allow: POST`). `/device/poll`: `poll_pending` (`400 authorization_pending`), `poll_slow_down` (`400 slow_down`), `poll_denied` (`403 access_denied`), `poll_expired` (`400 expired_token`), `poll_used` (`400 invalid_grant`), `poll_ok`, `poll_expiring` (adds `"refresh_token_expires_in": 604799`), `poll_email_not_allowed` (the consenting account is `stranger@example.com`; the message is matched literally: `"The Google account s***@example.com is not allowed to sign in here."`), `poll_scope_missing`, `poll_scope_not_allowed` (`403`), `poll_grant_unusable` (given `approved_no_id_token` → `403 grant_unusable`; on both sides the code is consumed by it), `poll_client_invalid` (`500`), `poll_upstream` (`502`), `poll_rate_limited`, `poll_unconfigured`, `poll_wrong_content_type` (`415`), `poll_too_large` (`413`), `poll_not_json`, `poll_missing_field`, `poll_malformed_code` (`400 invalid_request`), `poll_get` (`405`). `/refresh`: `refresh_ok` (body with `"client": "device"`), `refresh_legacy_ok` (given `legacy_token`, body without `client` → `200`), `refresh_legacy_unconfigured` (given `legacy_unconfigured`, body without `client` → `400 invalid_grant`), `refresh_legacy_half_set` (given `legacy_half_set`, body without `client` → `500 server_misconfigured`), `refresh_half_set_device_ok` (given `legacy_half_set_device_token`, body with `"client": "device"` → `200`), `refresh_bad_client` (`"client": "web"` → `400 invalid_request`), `refresh_invalid_grant` (`400`), `refresh_malformed_token` (`400 invalid_request`), `refresh_scope_not_allowed` (`403`), `refresh_client_invalid`, `refresh_upstream`, `refresh_rate_limited`, `refresh_unconfigured`, `refresh_get`. Elsewhere: `not_found` (`404`), and the routes of the browser sign-in — `login_gone` (`GET /login`), `callback_gone` (`GET /callback`), `token_gone` (`POST /token`) — all `404 not_found`. Error answers match as `{ "error": "<code literal>", "message": "<string>" }` (one message is a literal: `poll_email_not_allowed`). **As delivered the fixture has 48 cases**: the 46 above plus `start_not_json` and `refresh_missing_field` (`400 invalid_request`). The fake of the Rust side answers `google_down`, `rate_limited` and `unconfigured` through `fail_next` on the case's route.

### 16.6 Operating notes (go into `worker/README.md`)
- **Rotate the client secret**: Google console → the client → add a secret → `wrangler secret put GOOGLE_CLIENT_SECRET` → delete the old one. Devices are not affected. (There is no sealing key to rotate any more.)
- **Change the allowlist**: `wrangler secret put ALLOWED_EMAILS` with the new comma-separated list — it takes effect at once, no `wrangler deploy`. Never add a `vars` entry of that name (§16.2). Removing an address stops new logins for it, and cuts off its existing tokens at their next refresh **when** Google returns an ID token there (§2.3; not guaranteed) — to be sure, revoke (`gclone logout --revoke`, or the Google account's permissions page).
- **Logs**: the Workers Logs view stores the Worker's own route / status / error code lines — a login that waits for its user therefore logs one `authorization_pending` line per poll, which is the normal state; the request URL Cloudflare attaches to each stored event has its query string removed, and invocation logs, traces and every kind of log export are off (§16.2) — do not relax any of it. `wrangler tail` prints the method and URL of every live request to the terminal of whoever runs it; no route carries a secret in its URL and bodies are not shown. Cloudflare still sees request metadata at the platform level (the privacy page says so).
- **Cost and limits**: a login is one start plus one poll every 5 s while the user enters the code (about 13 requests for a minute at Google), a refresh 1 per device and hour of use — far inside the Workers free plan (100,000 requests/day) for the owner's own use. The built-in rate limit (30 requests / 60 s per IPv4 address or IPv6 /64, `429`) bounds what one sender can relay to Google through the OAuth client — not a sender with many networks — and it runs inside the Worker: a refused request is still a request, so on `*.workers.dev` a flood of about one request per second uses up the free plan's daily quota and stops all token refreshes until midnight UTC — and zone-level rate-limiting rules cannot be attached to `*.workers.dev`. **Recommended**: serve the Worker from a custom domain (a zone on the same Cloudflare account), attached **in `wrangler.jsonc`** — `"routes": [{ "pattern": "<host>", "custom_domain": true }]` with `"workers_dev": false` (and the shipped `"preview_urls": false`) — so that every deploy, and a redeploy of a lost Worker, restores the host name the devices and the Google branding depend on; a domain attached only in the dashboard is not restored. In the Google console add, under *Authorized domains*, the **registrable domain** of the host (`example.org` for `auth.example.org`; Google refuses a subdomain there — `setup.sh` prints it that way); use `https://<host>` as `AUTH_URL`; and add one zone rate-limiting rule. **The rule must cover every path of the host** (§17.14), not the three limited routes: `/`, `/privacy` and every unknown path invoke the Worker as well (the two pages and `404` are answered before the limiter) and count against the quota like any other request — a rule for `/device/start`, `/device/poll`, `/refresh` alone leaves the flood of §1.3 exactly as possible as before. Per IP address, action Block, **5 requests per 10 seconds** (a login that waits polls once every 5 s — 2 requests per 10 s — and a blocked poll only delays it; 10 at most — the 20 per 10 s once given as the example admits 172,800 requests a day from one address, more than the whole free quota). The expression depends on the zone's plan [K, Cloudflare's rate-limiting documentation, read 2026-11]: Pro and above can match the host (`http.host eq "<host>"`); the Free plan has one rule whose expression can use the URI path only, with a 10 s period and a 10 s block, so there the rule is zone-wide (`starts_with(http.request.uri.path, "/")`) — right for a zone that serves nothing but the Worker, too strict for one that also serves a site; on such a zone only a zone of its own for the Worker, the Pro plan or the paid Workers plan help. Requests blocked by the rule never reach the Worker and do not count; the device treats the `429` like the Worker's own (§17.3). A per-address rule bounds each sender (43,200 requests a day at 5 per 10 s), **not the total**: a flood from many addresses can still exhaust the free quota, and only the paid plan, which has no daily cap, removes that. The custom domain is best chosen **before the first deploy** (§2.1): `setup.sh` asks, and `scripts/custom-domain.mjs <host>` writes the `routes` entry.
- **If the Worker is lost**: redeploy from `worker/` and put the three secrets again (a new client secret can be added to the same Google client). Devices keep their refresh tokens; nothing else needs to change as long as the host name and the Google client stay the same — with a custom domain that means: as long as its `routes` entry is in `wrangler.jsonc` (or the domain is attached again in the dashboard).

### 16.7 What the Worker deliberately does not do
No storage and no sessions (Google holds a pending login, the device its device code); no cookies; no CORS; no redirect, to Google or anywhere; no sign-in page of its own (the user's only page is Google's) and therefore no confirmation step against device-code phishing (§2.3.2); nothing about the owner disclosed to an unauthenticated caller; no proxying of Drive traffic (data never passes through it); no revoke endpoint (devices call Google's directly — it needs no client secret); no user management beyond the e-mail allowlist; no verification of ID-token signatures (the token comes straight from Google's token endpoint over TLS); no request logging beyond route, status and error code; no token for a grant with any scope beyond `ALLOWED_SCOPES`; no cryptography.

---

## 17. Errata

Changes made by a work package to something this spec fixed, in the order they were made. The sections named were edited **in place** as well, so the body of the spec stays the source of truth; this list is the change log.

### 17.1 WP0 — skeleton and shared modules (2026-11-11)

**Dependencies (§9.1).** No version and no feature had to change: the manifest of §9.1 resolves and compiles as written with cargo 1.99.0 / rustc 1.99.0 (`nix-shell -p cargo rustc`), and `cargo update --dry-run` reports nothing newer within the MSRV. `Cargo.lock` (274 packages) is committed. Resolved direct dependencies: tokio 1.54.1, tokio-util 0.7.20, futures-util 0.3.34, bytes 1.12.1, reqwest 0.13.5, serde 1.0.229, serde_json 1.0.154, clap 4.6.7, rusqlite 0.42.0, indicatif 0.18.6, tracing 0.1.44, tracing-subscriber 0.3.23, ignore 0.4.34, anyhow 1.0.104, thiserror 2.0.21, rpassword 7.5.5, open 5.4.5, filetime 0.2.29, blake3 1.8.7, etcetera 0.11.0, url 2.5.8, base64 0.23.1, sha2 0.11.1, getrandom 0.4.3, zeroize 1.9.1, **chacha20poly1305 0.11.0, hkdf 0.13.0, argon2 0.6.0, postcard 1.1.3, md-5 0.11.0, caseless 0.2.2, httpdate 1.0.3, unicode-normalization 0.1.26, libc 0.2.191** (the nine that were not compile-verified before); dev: wiremock 0.6.5, tempfile 3.27.0. `[package]` additionally carries `description` and `publish = false`.

API facts of the 2026 RustCrypto generation, each exercised by a unit test in `src/util.rs` (`dep_*`), for WP1:
- `sha2` / `md-5` 0.11: `Sha256::digest(bytes)`, `Md5::digest(bytes)`, `Digest::{new, update, finalize}`; the output derefs to `[u8]`.
- `hkdf` 0.13: `Hkdf::<Sha256>::extract(Some(salt), ikm) -> (prk, hk)`, `hk.expand(info, &mut okm)`, `Hkdf::<Sha256>::from_prk(&prk)`, `Hkdf::<Sha256>::new(Some(salt), ikm)` (RFC 5869 case 1 passes).
- `chacha20poly1305` 0.11: `ChaCha20Poly1305::new_from_slice(&key)` (trait `KeyInit`), `Nonce::try_from(&bytes[..])`, `aead::Aead::{encrypt, decrypt}` with `&[u8]` or `aead::Payload { msg, aad }` (RFC 8439 §2.8.2 passes). The in-place trait is `aead::AeadInOut` (`encrypt_inout_detached`, …); `AeadInPlace` is deprecated in aead 0.6. The crate's optional `zeroize` feature was off in WP0's manifest and is enabled since integration wave 1 (§17.2).
- `argon2` 0.6 with `default-features = false, features = ["alloc"]` (plus `zeroize` since §17.2): `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m_kib, t, p, Some(32))?)` and `.hash_password_into(pwd, salt, &mut out)` exist.
- `postcard` 1.1: `to_stdvec`, `from_bytes`, and `take_from_bytes` (returns the unread rest — what §4.6 rule 3 "no trailing bytes" needs).
- `rusqlite` 0.42 + `fallible_uint`: a `u64` binds and reads back; binding a value above `i64::MAX` is an error (§8.4).
- `libc` 0.2.191 exports `gethostuuid` on macOS but not `tzset` (tests declare it themselves).

**Spec text that did not hold or was inconsistent, and how it was settled.**
1. §9.2 named the argument type of `src/path.rs` `RemoteArg`; §9.3 defines `Arg`. → `Arg` (§9.2 edited).
2. §7.2 lists "2 = usage error (clap)" while the `exit_code` comment of §9.3 sent every unlisted error, `SyncError::Usage` included, to 1. → `SyncError::Usage` maps to **2**; the precedence gained the two codes §7.2 did not rank: 3 > 4 > 75 > 5 > 6 > 130 > 2 > 1 (§7.2 and §9.3 edited).
3. §9.3 lets most enums wrap others with `#[from]` and wants one function to "walk the whole chain". With plain `#[from]` either every message is printed twice (`Display` + `source`) or — with `#[error(transparent)]`, which was chosen — `source()` skips the wrapped enum, and a typed value attached through anyhow's `.context(err)` cannot be downcast from the chain at all. → wrapping variants are transparent, and `error.rs` descends through them explicitly: `exit_code` and the new **`error::find::<T>(&anyhow::Error) -> Option<&T>`** see the anyhow chain, context values and every nested enum. Callers must use `find` instead of walking `source()` (§9.3 edited).
4. §9.10 promises "one file per command" but §9.2 lists neither `cli/sync.rs` nor `cli/tree.rs`. → `copy.rs` hosts `run` and `run_sync`, `ls.rs` hosts `run` and `run_tree` (§9.10 edited).
5. §6.1 gives the constants without types. → fixed and listed in §6.1 (`u64` sizes, `Duration` time spans with `*_MS` / `*_NS` companions).
6. §9.5 / §9.2: trait methods shown as `async fn` are declared `fn … -> impl Future<Output = …> + Send` in `backend/mod.rs` (as the general API rules of §9.2 already demand); implementations write `async fn`. Compiles as is on 1.89+.

**Additions and precisions in WP0's own API** (all additive; §9.3 edited where a signature or a behaviour is concerned):
- `types`: `DeviceId` / `BlobId` have a hex `Debug` and implement `Display`; `from_hex` accepts lowercase only; `StatSig::is_exec` is the owner-execute bit; `Entry::empty_file` sets `hash = BLAKE3("")`; `Entry::dir` has `mtime_ns = 0`.
- `error`: `find` (above); `PathError` is `Clone + Copy + PartialEq + Eq`; `QuotaKind` and `GuardKind` implement `Debug` and `Display`; a leading `/` is `PathError::Absolute`, a trailing `/` is `EmptyComponent`.
- `util`: `unhex` is strict (lowercase only; `--vault-id` input must be lower-cased by the CLI first); `unb64url` rejects padding and non-canonical trailing bits; `crockford_encode` pads a trailing partial group with zero bits (debug-asserts the multiple of 5); `human_age` returns one unit without "ago"; `hostname` is the short name; new `group_thousands`; `write_atomic` names its temp file `.<name>.tmp-<16 hex>` and removes it on failure; `parse_rfc3339_ms` also accepts lowercase `t`/`z`, a leap second `:60`, any number of fraction digits (truncated to ms) and returns `None` before 1970.
- `path`: `parse_arg` drops trailing slashes of a remote argument and rejects `:/…`; `local_conflict_name(.., attempt)` — 0 or 1 is the plain name, n ≥ 2 appends `-n`; conflict names are clamped by cutting the stem first and, only if `infix + ext` alone exceeds 255 bytes, the extension.
- `ui`: `UiOpts: Default`; `Ui::with_writers` (`#[doc(hidden)]`, output capture for tests), `Ui::quiet()`, `Ui::verbose()`; `Progress::{bytes, files, blobs}`; `Event::Plan` omits `None` fields in JSON; `Event::Summary` has **no** human rendering (commands print their own ▸ line with `out`); under `--json`, `warn()` is a `warn` event on stdout and `error()` stays on stderr.
- `consts`: types and companion names as listed in §6.1.
- `tests/support/prng.rs`: `Prng::{new, from_env, next_u64, next_u32, below, range, index, bool, chance, fill, bytes, array, pick, shuffle, name, fork}`, `for_each_seed(name, cases, |rng| …)` (prints `GCLONE_TEST_SEED=<seed>` for a failing case), `base_seed`, `parse_seed`, `SEED_ENV`, `DEFAULT_SEED`. xorshift64* seeded through splitmix64; the first outputs for seed 1 are frozen by a test. The file has no `#[cfg(test)]` module of its own (it is compiled into every integration-test binary); its self-tests run once in the library's unit-test build.

**Stubs (every other file of §9.2).** Each contains the public items of §9.4–§9.10 with `todo!("WPn")` bodies and a file-level `#![allow(unused_variables, dead_code)]` that the owner removes. Decisions the spec left open — owners may rearrange inside their own files as long as the public paths keep resolving:
- Re-exports: `crypto`, `format`, `transfer` re-export everything from their sub-modules; `backend` re-exports `AnyBackend`, `DirBackend`, `Flaky`, `OpKind`, `MemBackend`, `Counters`, `MemCheckpoint` (`backend::conformance::run` and `backend::drive::*` stay under their module path); `backend::drive` re-exports the pacer, error and probe items and adds `pub const FIELDS`; `auth` re-exports `login::*` and `TokenProvider`; `index` re-exports `apply::{HeadStore, MemIndex, ApplyStats, apply_segment, causal_order}`; `sync` re-exports `scan::*`, `plan::*`, `gc::*`, `check::*` and `exec::execute` (so `sync::plan`, `sync::scan`, `sync::gc` name both a module and a function), `remote_ops` stays a module path; `cli` re-exports `context::*`.
- Placement: the constants, `AuthEndpoints`, `validate_auth_url`, `resolve_auth_url` and `http_client` are in `auth/mod.rs`, the rest of §9.6's first block in `auth/login.rs`; all `Vault` method stubs are in `index/mod.rs` (`refresh.rs`, `commit.rs`, `resolve.rs`, `repair.rs`, `query.rs`, `state/schema.rs`, `state/tables.rs`, `backend/drive/api.rs`, `backend/drive/upload.rs` are empty files for their owners).
- Small real bodies where the value is fully determined by this spec: `Handle::top` / `is_top`, `KdfParams::default`, `DriveEndpoints::default`, `DriveConfig::default`, `PacerConfig::default`, `impl Clone for TransferCtx`, the `Vault` getters `backend` / `db` / `keys` / `handles`, the constants of `format::descriptor` (`README_TEXT` ends with a newline), and `crypto::stream::{HEADER_LEN, TAG_LEN}` (aliases of the `consts` values).
- Derives the spec did not state, on types without secrets: `Header`, `ChunkSpan`, `KdfPreamble`, `SealedObject` (`Clone, Debug, PartialEq, Eq`); the index types of §4.6 (`Clone, Debug, PartialEq, Eq, Serialize, Deserialize`). Secret-bearing types have exactly the derives of §9.4–§9.10.
- `cli/mod.rs` contains the clap definitions of §7.1 (`Cli`, `Command`, one `<Cmd>Args` per command file) and a plain dispatcher in `run()` — clap parse (usage errors exit 2), `ui::init_logging`, dispatch, `error::exit_code` — so that the binary builds and `gclone --help` works. WP7 completes it (Ctrl-C handler, the texts of §2.8) and may change any argument definition; `check` currently takes `--download` plus 0..=2 positional arguments. Three unit tests there check the clap definition against the invocations of §7.1.
- **Skeleton contract**: `util::tests::api_contract` (compile-only) asserts the §9.2 rule for the shared surface — `Backend` is implemented by `MemBackend`, `DirBackend`, `Flaky<MemBackend>`, `AnyBackend`, `DriveBackend`; `Keyring`, `MasterKey`, `PurposeKey`, `Sealer`, `Passphrase`, `PackBuilder` are `Send + 'static`; `Vault<B>`, `TransferCtx<B>`, `Db`, `TokenProvider`, `Ui`, `Filter`, `PlanInput`, `Opener` are `Send + Sync`; `cli::Ctx` is `Send`; and the futures of the public async functions of §9.5–§9.10 are `Send`. If a package makes one of these non-`Send` (for example by holding a `MutexGuard` or a `rusqlite` statement across an `.await`), the library's test build stops compiling with an error pointing at this module. A deliberate signature change to one of the listed functions needs the matching line there changed by WP0.

### 17.2 Integration wave 1 — WP1, WP2, WP8 (2026-11-11)

State after this wave: WP0, WP1, WP2, WP8 are implemented; WP3–WP7 are still the WP0 stubs. In the project root `cargo build --all-targets`, `cargo test` (lib 94 passed + 1 ignored generator, `backend_conformance` 36, `crypto_format` 38), `cargo clippy --all-targets -- -D warnings`, and in `worker/` `npm run typecheck` and `npm test` (138 tests) pass. No test is ignored for lack of a package: the one `#[ignore]` is the vector generator `gen_vectors` of §4.7.

**Dependencies (§9.1; requested by WP1, applied by the integrator).** `chacha20poly1305` gains the feature `zeroize` (the cipher object wipes its copy of the stream key, and the one-time MAC key, on drop) and `argon2` gains `zeroize` (wipes the initial hash and the final block hash). `Cargo.lock` gains three dependency edges onto the already present `zeroize` 1.9.1 — no new package. **Not covered:** `Argon2::hash_password_into` allocates the working memory itself and argon2 0.6.0 does not wipe it on free, feature or not; wiping it would need `hash_password_into_with_memory` over a caller-owned buffer in `crypto/kdf.rs` (open hardening item, not required by this spec).

**WP1 — spec text settled (sections edited in place).**
1. §2.6: `m_kib`, `t`, `p` of the `KdfPreamble` are `u32` big-endian (frozen in `tests/vectors/stream_v1.json`).
2. §4.2 step 3: `EpochTooOld` is checked before `UnknownEpoch`.
3. §4.7: "append one byte → `TrailingData`" holds only after a full final chunk; otherwise `Corrupt` is also correct.
4. §3.1: the data-folder counter `<n:04>` is decimal.

**WP1 — additions and precisions in its own API** (public signatures of §9.4 unchanged):
- `KdfPreamble::decode`: fewer than 36 bytes or a foreign magic → `KeyfileDamaged`; magic `GCK<digit ≠ 1>` → `KeyfileVersion(digit)`; wrong alg / Argon2 version, non-zero reserved bytes, out-of-bounds parameters → `KdfParams`.
- Index acceptance (§4.6) error variants: name of the wrong kind → `BadName`; rule 1 (h8) and rule 4 (inner vault / device / seq / lamport) → `IdentityMismatch`; rule 2 → `Crypto(..)`; unknown codec → `Codec(n)`; trailing bytes, empty plaintext, postcard errors, unknown body version → `Decode(..)`; rule 5 → `Path(..)`; rules 6–7 → `BadEntry(..)`. Keyfile: authenticated JSON that is not a payload → `KeyfileDamaged`; `v` is read first, so a future payload shape reports `KeyfileVersion`.
- Stricter than stated: `Keyring::new` rejects a repeated epoch (`Misuse`); `seal_segment` / `seal_snapshot` refuse a body whose `vault_id` differs from the keyring's (`IdentityMismatch`); `seal_keyfile` refuses out-of-bounds params (`KdfParams`), `v != 1` (`KeyfileVersion`), unusable keys (`KeyfileDamaged`) and a result above `KEYFILE_MAX` (`BadEntry`) before any derivation; `derive_pass_key` re-checks the bounds (`CryptoError::Kdf`); `VaultDescriptor::parse` requires 32 lowercase hex digits (`Decode`) and leaves `min_reader` to the caller (§3.3); `Opener::open_chunk` returns `Corrupt` for chunk lengths no stream can contain before touching the AEAD; `ciphertext_len` saturates at `u64::MAX`.
- **Panics instead of errors where the signature is infallible** (deviation from the "no `expect` on crypto results" rule of §9.2, accepted): `Sealer::new` and `seal_all` assert `chunk_log2 ∈ 12..=24` — production code passes only `CHUNK_LOG2`; a test of another package that passes something else panics. The length functions (`chunk_count`, `ciphertext_len`, `plaintext_len`, `chunk_range`, `chunk_cipher_len`) assume a validated `chunk_log2`.
- The salt-taking constructor is the private `Sealer::with_salt` (called by `Sealer::new` with a fresh random salt); the `#[cfg(test)]` wrapper `with_salt_for_tests` serves the KATs. No public or crate-visible constructor takes a salt.
- `Passphrase` has no equality helper: the "same passphrase as an earlier attempt" check of ATTACH (§2.6, WP7) compares `display()` values.
- `tests/vectors/stream_v1.json` also freezes the two purpose keys, one `K_pass` vector, and one keyfile, segment and snapshot. The last two pin the field order of `src/types.rs` and of the index types: a reordered field fails `format::index::tests::frozen_*_still_opens`. Regenerate only for a deliberate format change.
- Not exercised: a real derivation at the upper bounds (`m_kib = 524288, t = 4` is tested at the bounds level only).

**WP2 — behaviour of the fakes where §9.5 was silent** (public signatures unchanged; §9.5 and §12.1 edited where another package depends on it):
- `PutBody` contract is enforced by `MemBackend` and `DirBackend`: a `Small` body above `MULTIPART_MAX`, a non-final `Stream` part that is not exactly `PART_SIZE`, or more bytes than `total` → `Fatal{400, "badRequest"}`; a channel that closes before `total` bytes → `Io(UnexpectedEof)`.
- Missing parent: `put` / `create_folder` → `Fatal{404, "notFound"}`; `list` of an unknown parent → empty; `create_folder` with an id that names a file → `AlreadyExists`.
- `stat(Handle::top())` → a folder meta (name `""`, parent top, not trashed) — the §3.3 `stat(root)` check works when the vault root is the top level; `get` of top or of a folder → `Fatal{403, "fileNotDownloadable"}`; `trash` / `delete` of top → `Fatal{400}`.
- Trashed folders: descendants report `trashed = true`, are hidden from `list` / `find_by_name`, stay readable by id; deleting a folder deletes its content.
- `DirBackend`: one name per folder (`Fatal{409, "nameConflict"}`, §9.5 — consequence for vault creation: §2.6 "Two first devices", item 1, and §12.1 WP4); `open` requires an existing directory; the id map is a journal with cached size / mtime / md5 per file, compacted on `open`; names starting with `.`, empty names and names with `/` or NUL are refused (`Fatal{400}`), ids starting with `p:` are refused as new ids; trash layout `<root>/.trash/<slot>/<name>` with the origin in the journal (`untrash`: `Fatal{409}` if the name was taken meanwhile, `Fatal{404}` if the origin folder is gone); changes take an advisory lock on the root so several processes can share a directory; `DirBackend: Clone`; `about()` reports `limit: None`, `account: None`; a put costs two fsyncs (measured ≈ 8 ms). On a case-insensitive file system names differing only in case are one path (gclone's own object names are lowercase).
- `MemBackend`: the clock starts at wall-clock time and moves only through `set_now_ms` / `advance_ms`; `MemCheckpoint` covers objects only (ids are never reissued after `restore`); `tamper` panics on a handle that is not a stored file; `put` counts every call, `put_bytes` only newly stored bytes, `get_bytes` the bytes actually yielded; `impl Default`.
- `Flaky`: `times == u32::MAX` = until `clear()`; `clear()` drops planned faults and the list lag, keeps call counts; injected failures count in `calls()` and never reach the inner backend; `cut_next_stream_put` and `on_put_progress` wait for the next **Stream** put (Small puts pass and leave them armed); `cut_next_get` ends with `Err(Transient)` even when the object is shorter than `after_bytes`; with both `lose_ack` and `corrupt_md5` armed the lost ack fires first; `Flaky<B>: Clone` when `B: Clone` (clones share plan and counts).
- `backend/mod.rs` has crate-private helpers for the fakes (`PartReader`, `check_small`, `bad_request`, `not_downloadable`, `md5_of`, `ObjMeta::top`).

**WP8 — deviations** (§2.3, §16.1, §16.5 edited): the `typecheck` script also checks `test/`; `.gitignore` re-includes `.dev.vars.example`; `500 internal_error` for unexpected exceptions; `/login` refuses a non-canonical 43-character challenge; `405` on GET routes is HTML with `Allow: GET`, `404` is always JSON; a Google `/token` answer without `scope` → `403 scope_missing` (a `/refresh` answer without `scope` passes on `""`); JSON answers also carry `X-Content-Type-Options: nosniff`; `check-config.mjs` also refuses `logpush`, `tail_consumers` and every storage binding, anywhere in the file; no per-isolate `CryptoKey` cache; `typescript ^7.0`; resolved tools: wrangler 4.160.1, vitest 4.1.12, `@cloudflare/vitest-plugin` 1.8.0 (the Workers-runtime integration resolved — the Node fallback of §16.5 was not used; the `ratelimits` key was accepted as written). `contract.json`: 34 cases and the reading rules now in §16.5.

**Open after this wave** (for the packages named):
- WP3: `DriveBackend::find_by_name` must filter by exact name client-side; `FakeDrive` must hold the ≈ 48 MiB conformance object; `tests/auth.rs` must run all 34 contract cases under the reading rules of §16.5.
- WP4: the orphan-vault acceptance test runs on `MemBackend`.
- WP7: create the `--vault-dir` directory before `DirBackend::open`; report the directory backend's `409 nameConflict` from `Vault::create` with the text of §2.6; compare passphrase attempts through `display()`.
- Unverified by any automated test, as before: real Google and real Cloudflare behaviour (§2.9, §16.5), and the cross-process path of `DirBackend` (tested with two instances in one process).

### 17.3 Integration wave 2 — WP3, WP4, WP5 (2026-11-11)

State after this wave: WP0–WP5 and WP8 are implemented; WP6 (`src/sync/*`) and WP7 (`src/config.rs`, `src/cli/*`) are still the WP0 stubs. In the project root `cargo build --all-targets --locked`, `cargo build --release --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check` and `cargo test --locked` pass: lib 143 passed + 1 ignored generator, `auth` 30, `backend_conformance` 36, `cross_package` 8, `crypto_format` 38, `drive_http` 39, `index_adversary` 10, `index_props` 56, `transfer` 36. No test is ignored for lack of a package: the one `#[ignore]` is still the vector generator `gen_vectors` of §4.7. `worker/` was not touched (byte-identical to the tree verified in §17.2); its tests were not re-run.

**Shared files.** None of the three packages requested a change: `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/types.rs`, `src/error.rs`, `src/consts.rs`, `src/util.rs`, `src/ui.rs` and every WP6 / WP7 stub are as they were after wave 1. No public signature of §9.6–§9.8 changed; everything below is behaviour where the spec was silent or inconsistent, or an additive item.

**Cross-package check (integrator).** Each package tested against `MemBackend` / `Flaky` (WP4, WP5) or against its own fake (WP3) only, so the integrator added `tests/cross_package.rs` — owned by no work package (§12) — and ran `Vault` and the transfer layer together on `DriveBackend` over `FakeDrive` (also with a page cap of 3), `DirBackend`, `MemBackend` and both through `AnyBackend`: create with a real keyfile → `upload_batch` (empty file, a pack of 40, a 1 MiB + single-member blob, a two-part resumable blob) → `drafts_for` → `stage` → `commit` → `finish_mutation`; a second device `discover`s, opens the keyfile, `verify_visible`, `open`, `refresh`, downloads everything (`locate_blob`, `verify_remote`, `read_range`, `download_group`, `materialize_empty`) byte-equal; edit + delete flow back; `write_snapshot`, `cleanup_index`, `replace_keyfile`, `repair(false)`; a third device joins; equal head fingerprints throughout; ops staged by a run that died before its commit survive a re-open, pass `verify_pending_blobs` on that backend and are published without a dropped op. Further: the recovery drill of §12.1 (WP7) at library level — the outer directory copied without `.gclone-dir-ids.json` (readable **and** writable afterwards) and the inner vault folder alone (root = `Handle::top()`); and Drive faults seen through `Vault` + transfer — `503` / `500` / `429` on creates, a `401` on a folder create, a lost answer on a session PUT, list lag, a `503` on a download, `403 appNotAuthorizedToFile` on `stat` → `IndexError::VaultNotVisible` (exit 4), a revoked login → `IndexError::Backend(Auth(Expired))` (exit 4). **All of it passed without a change to any package** — no cross-package mismatch was found. Measured for WP7: the generic scenario on `FakeDrive` takes ≈ 26 s with the production pacer (`PacerConfig::default()`) against ≈ 13 s with the fake's fast pacer.

**WP3 — deviations and precisions** (§2.4, §6.2, §9.6 edited in place where another package depends on it):
1. Browser flow (§2.4): the URL and the check code are printed only after `open` returned true; a failed `open` prints nothing of that flow and falls back to the headless flow, which prints its own URL.
2. Conflict rule (§6.2 "retry the stat up to 3 times" vs §12.1 "after 3 stats"): 3 `stat`s in total.
3. Top-level parents (§6.4.1 says only "parents missing → `Handle::top()`"): My Drive's root id is learnt or looked up once (`files/root?fields=id`); if that lookup is refused under `drive.file` — **unverified** — top-level parents are reported by their raw id (§6.2).
4. Any `429` from the Worker URL is the rate-limit row (wait `Retry-After` capped at 60 s, 5 s without the header, retry once), also when the body is not the JSON error object — a zone rate-limiting rule in front of the Worker (§16.6) answers that way. The end result is `Network(..)` either way. `/refresh` retry pauses: 0.25 s, 0.5 s, 1 s, 2 s.
5. Write breaker: tripped = the run of write throttles without a success spans at least the breaker time (first to latest throttle); two throttles further apart than the breaker time start a new run; time passing without a new throttle does not trip it. Throttled part PUTs and status queries count as write throttles and lower the write rate.
6. `TokenProvider` checks the cache file's **directory** as well as the file (§8.1 "same check"): a `token.json` in a directory with group/other bits is ignored (and still rewritten after a refresh). WP7: the state root must be 0700 for a cached token to be used — the same rule as for `secrets.json`.
7. `classify()`: only `500` / `502` / `503` / `504` are `Transient` (the literal row), other `5xx` are `Fatal`; an unparseable `2xx` body is `Transient`.
8. `DriveBackend` extras (§6.2 "where the protocol text is silent"), `DriveBackend: Clone`, `Pacer::set_backoff_unit` (test hook), `auth::login::describe` (`pub(crate)`).
9. Headless flow: each item of the paste channel is one attempt with all ASCII whitespace (embedded line breaks included) removed; blank lines are skipped without using up an attempt; a closed channel ends the flow with `LoginFailed`.
10. `FakeDrive` (§9.6 edited): `Clone`; the additions listed there; revoking invalidates access tokens too; the `/auth/refresh` length rule spares the fake's own short tokens (§2.3 demands 20..=512 characters, §9.6 names the tokens `rt-ok` / `rt-1`; the contract case `refresh_malformed_token` still gets `400 invalid_request`).
11. Contract fixture: `location` patterns are matched by a small regex subset written in `tests/auth.rs` (literals, backslash escapes, `.`, `[...]` with ranges, `+ * ?`) — no regex crate is a direct dependency; any other syntax fails the test. All 34 cases run, and the 23 `/token` and `/refresh` answers are replayed through `auth::redeem` / `auth::refresh` against a separately written mapping table.
12. Probe rows: outcomes are `Pass` / `Info` / `Fail` as judged by the probe; a failed clean-up adds one extra line with id 0.

**WP4 — deviations and precisions** (§5.2.2, §5.3, §5.6, §5.8, §5.10, §8.4, §9.7 edited in place):
1. Snapshot lamport = local lamport + 1, advancing the local clock; examining another device's snapshot raises the local lamport as well (§5.6, §5.3).
2. `causal_order` is a priority topological order; `refresh` applies the whole order in one transaction (§5.3).
3. Fork tie rules for `removed_ms` and for colliding `(path, stamp, entry.hash)` (§5.2.2).
4. Extra `meta` keys `vault_id`, `base_snapshot_id`, `last_snapshot_md5` (§8.4).
5. `Vault::repair(false)` returns `Ok` with `still_missing` when loss remains — **WP7's `cli/repair.rs` must exit 3 on a non-empty `still_missing`**; gap handling in `repair` honours `GAP_GRACE` (§5.10, §9.7).
6. Renamed objects are missing for whatever references them: the by-ID fetch and presence check (c) require the expected name (§5.3).
7. "Accepted listed snapshot" needs a listed object known to hold the accepted bytes; the base is also on offer when `stat(base_snapshot_id)` shows it un-trashed (§5.3).
8. Machine-fingerprint rotation is checked in `Vault::open` and at the start of `commit` too (§5.3).
9. `commit()` prepends `Op::Device` when the replica does not list this device id (§5.6).
10. `verify_pending_blobs`: "earlier process" = rows that existed when the `Vault` was opened (id watermark; the `pid` column is still written); the age rule only for blobs whose `Blob` record is unpublished (§5.8).
11. `resolve_conflicts`: leftover staged ops are committed first and the resolutions go into a following segment (two segments instead of one when leftovers exist); a conflict copy whose identical content already stands at the conflict path is not put again; fork twins (two heads with equal stamps) are resolved by a successor `Put` of the winner's entry instead of a `Del` (a `Del` on the shared stamp would remove the winner too); resolutions that would put two `Put`s for one path into one segment are deferred to a further round (at most 8 rounds per call).
12. `dead_blobs(now)` / `VaultStats.dead_blob_bytes` = "what gc would trash now"; `blobs()` returns every row (§9.7). **WP6's `gc` must not apply `GC_GRACE` a second time on a different clock.**
13. `IndexError::Gap.names` = the missing objects (§5.3).
14. Local `removed` rows older than `HISTORY_KEEP` are pruned when this device writes a snapshot (§5.6).
15. Conditions without a dedicated `IndexError` variant use `IndexError::Io(io::Error::other(text))` (exit 1): two or no folders named `index` / `data` in `discover`, a stored index / data folder that is not inside the vault folder in `verify_visible`. A keyfile or object that is not stored intact (size / md5) fails with `BackendError::Transient` after trashing it.
16. `refresh` with an empty listing and a non-empty replica stats the index folder as well (§5.3).
17. Additive: `index::testing` (`#[doc(hidden)]`), `MemIndex::{blobs, devices, vault}`; the data-folder counter starts at 1 (§9.7).
18. Known limit, kept as specified: `seen` carries one tip per other device (greatest `(seq, hash)`), so after a fork with branches of different length not every branch is a causal dependency of later segments. Both branches are still applied on every device (tested), but strict order-independence is property-tested for fork-free histories only.
19. For WP6 / WP7: `outbox_stuck()` is `Some` as soon as an outbox row exists; `vault_name()` is empty until `VaultInit` was applied; `list()` reports a file that also has children as `is_dir = true` with its head; `stage` validates drafts (`IndexError::Format`) and a debug build panics on two `Put`s for one path in one segment; library warnings go through `tracing::warn!` (§5.3, §5.6, §9.7).

**WP5 — deviations and precisions** (§5.7, §6.2, §6.3, §9.8, §12.1 edited in place):
1. Download retries count consecutive failures without progress; private pause 250 ms → 4 s; an early end of the body triggers one `stat`, and a truncated blob reports `TransferError::Verify`, not a crypto error (§6.3).
2. Directory `fsync` once per directory per coalesced request, before any result is returned (§5.7 step 3; on macOS every `fsync` is `F_FULLFSYNC` — this halved the time for 500 small files). *Superseded by §17.15: both the files and the directories are now flushed per batch.*
3. The transfer layer creates missing parent directories and a missing root, each level `lstat`-checked; an unexpected directory at the target is `UnsafeTarget` before any request; unsafe targets and invalid paths never cause a request (§5.7 step 1).
4. Pack close rule: also at `PACK_TARGET` + 1 MiB of sealed bytes (§6.2).
5. `PackBuilder::add` refuses size 0 and ≥ `PACK_MEMBER_MAX` with `Io(InvalidInput)` (§9.8).
6. Retry classification and stop behaviour of `upload_batch`; zero-length files after a stop (§6.2).
7. Cancellation: puts in flight get 5 s (private `CANCEL_GRACE` in `transfer/upload.rs`, not in `consts.rs`); a dropped receiver aborts at once (§5.7). (§17.13: the same deadline now covers every backend call of the batch.)
8. Memory: measured peak ≈ 81.25 MiB against the nominal 81 MiB at `transfers = 2`; the bound test is a unit test in `src/transfer/upload.rs` (§12.1).
9. Precisions: `lstat_sig` returns `None` for `ENOTDIR` as well as `ENOENT`; `observed_ns` is taken just before its `fstat` / `lstat`; `Progress` counts plaintext bytes; `move_aside` uses hard-link + unlink so it can never replace an existing name (fallback: `lstat` + `rename` where hard links are unsupported); items sharing a `Loc` are fetched once; `download_group` materializes zero-length entries itself and returns results in input order.
10. `transfer/mod.rs` gained the crate-private helpers `blocking` (a `spawn_blocking` wrapper) and `replicate` (a second error value of the same variant — one failed blob fails N files and the error enums are not `Clone`).
11. For WP6: `Failed(_, SourceChanged)` is the run-time `ChangedDuringUpload` skip (§17.13: it now includes a source that is gone or no longer a regular file); `Err(UnsafeTarget)` / `Err(TargetCollision)` are the download skips; a pump-level failure fails every unfinished item of the group with the same variant.

**Open after this wave** (for the packages named):
- WP6: use `dead_blobs` / `blobs` as described in WP4 item 12; never stage two `Put`s for one path into one segment (debug builds panic); treat the events of WP5 item 11 as skips, not failures.
- WP7: exit 3 on `RepairReport.still_missing`; `AuthEndpoints::new(url)` always carries Google's real revoke URL — the Drive-mode e2e test must route `logout --revoke` to the fake (`GCLONE_TEST_REVOKE_URL`, §12.1), or it would call Google; a CLI subprocess gets the production pacer (writes start at 4/s, `BACKOFF` from 1 s), so Drive-mode e2e runs with injected faults are slow; `FakeDrive::browse` panics unless `/login` answers the `200` confirmation page with exactly one link, and a login's `open` closure has to spawn it (`FakeDrive` is `Clone`; `tests/auth.rs` shows the pattern); `token.json` is only used from a 0700 directory.
- Not exercised by any automated test: real Google and real Cloudflare (§2.9, §16.5), as before — the Drive wire behaviour rests on `FakeDrive` following §6.4.1; the HTTP/2 path of the API client (the fake speaks HTTP/1.1); whether `files/root` is readable under `drive.file`; a resumable session whose part PUTs answer `401` forever (the fake cannot fail parts and status queries separately); the index-cache pruning rule (30 days + covered by the base — it uses file mtimes against the wall clock); the "unsatisfied rollback mark" verdict (damaged `state.db`) and `NeedsNewerGclone` during a rebuild at `Vault` level; the 5 s cancel grace with a put that really hangs; the hard-link fallback of `move_aside`; a failing directory `fsync` (a real one — since §17.15 a refused barrier is exercised through a test hook); which branch of the `TargetCollision` test ran (it depends on whether the temp directory's file system folds case).
- Accepted costs and risks, recorded for later hardening: index-cache writes are `util::write_atomic` (two fsyncs per object, up to eight in parallel during a pull) — on macOS this is the slow part of `Vault`-level tests; `refresh` re-downloads listed objects that fail acceptance on every run (they are never cached), which lets an adversary cost bandwidth but not correctness; after `repair --accept-loss`, a skipped segment that reappears later can leave a spurious extra head when a newer segment had named one of its versions as base — it is then settled by the normal conflict resolution.

### 17.4 Integration wave 3 — WP6 (2026-11-11)

State after this wave: every Rust package except WP7 is implemented — WP0–WP6 and WP8; `src/config.rs` and `src/cli/*` are still the WP0 stubs (the binary builds, `gclone --help` works, commands are not functional). In the project root `cargo build --all-targets --locked`, `cargo build --release --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check` and `cargo test --locked` pass: lib 193 passed + 1 ignored generator (`sync::plan` 37, `sync::scan` 13 among them), `auth` 30, `backend_conformance` 36, `cross_package` 14, `crypto_format` 38, `drive_http` 39, `index_adversary` 10, `index_props` 56, `sync_e2e` 43, `sync_faults` 12, `transfer` 36. No test is ignored for lack of a package: the one `#[ignore]` is still the vector generator `gen_vectors` of §4.7. `worker/` was not touched; its tests were not re-run. Nothing was run on Linux (the non-macOS branches of `sync/scan.rs` — the fold probe without `pathconf`, `statx` birth times, non-UTF-8 names, which APFS refuses — are compiled and tested on macOS only as far as the file system allows).

**Shared files.** WP6 requested no change: `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/types.rs`, `src/error.rs`, `src/consts.rs`, `src/util.rs`, `src/ui.rs` and every WP7 stub are as they were after wave 2. No public signature of §9.9 changed. `README.md` (status paragraph only) was brought up to date by the integrator.

**Cross-package check (integrator).** WP6's own tests run on `MemBackend` / `Flaky` with in-memory databases. `tests/cross_package.rs` gained a sync scenario — the command flow of §10 (`refresh → commit → resolve_conflicts → sync::run → finish_mutation`) between two devices with `state.db` files — run on `MemBackend`, `DirBackend`, `AnyBackend::Dir`, `DriveBackend` over `FakeDrive` with injected faults (`503` ×2 on multipart creates, a `429` on a resumable init, a lost answer on a session PUT, all during one upload run) and `AnyBackend::Drive` with a page cap of 3: first push (empty file, a pack of 40, a blob of its own, a two-part resumable blob, an executable, an empty directory) → no-change push → pull into a root that does not exist → no-change pull hashing 0 files → edit / delete / directory rename (`Reuse`: 1, uploads: 2) / add on the second device → pull and `copy` up on the first → `remote_ops::{mkdir, mv, rm}` → the delete guard refusing the following pull (40 of 47 entries) and `--yes` carrying it out → `copy` of a prefix into a new root → `restore_candidates` / `restore` of an overwritten version → `check_blobs`, `check_download`, `check_local`, `gc(orphans, purge)` (nothing collected, nothing damaged) → equal trees and head fingerprints → a re-opened `Vault` on the same `state.db` (same device id; a no-change push and pull transfer and hash nothing). **All of it passed without a change to WP2–WP5.** One defect was found and fixed in WP6 (next paragraph).

**Fixed by the integrator in `src/sync/mod.rs`.** `sync::run` accepted a remote prefix that is a file (or lies under one): `copy DIR :notes.txt` uploaded `notes.txt/x` and reported a clean run — the index's rule 2 (§5.2.3) would then move `notes.txt` to a conflict name — and `copy :notes.txt DIR` downloaded nothing and exited 0. Now refused with `SyncError::Usage` before any work (§5.5.1 "The remote prefix is a directory"; test `a_prefix_that_is_a_file_is_refused` in `tests/cross_package.rs`). `remote_ops` already refused the corresponding cases.

**WP6 — deviations and precisions** (§5.5.1, §5.5.2, §5.5.3, §5.5.4, §5.7, §5.9, §9.9, §10 edited in place):
1. `copy` does not report destination-only entries (rows 4-DOWN, 5-UP): planned as skips, not counted in `Summary.skipped`, no skip event, exit code unaffected. `sync` reports them and exits 6 (§5.5.1).
2. G2 and G3 apply to uploads only; a missing root on a download is created before the pair is opened; a missing root on an upload is `EmptySource` unless `--force` (§5.5.2).
3. Empty-directory marker facing a directory with content: `RecordBase` of kind `Dir` once, then nothing (§5.5.1).
4. `Filter::excluded` also hides `.gclone-partial-*` / `.gclone-probe-*` components on all three inputs (§5.5.3).
5. Type-change groups that cannot remove the old type completely are settled at plan time (`Skip(UnsafeTarget)`, no group); no separate `RmdirLocal` action for a directory that becomes a file on download (§5.5.1).
6. Row 7 DOWN with a remote directory and an unsynced local file: the file is moved aside, then the directory is created (§5.5.1).
7. G4 counts every delete, directory markers and deletes of reused content included: a rename of most of a tree needs `--yes` or `--max-delete` (§5.5.2). Kept as specified; a rename-aware count is a possible later refinement. (Since §17.14 `--max-delete N` is a hard limit rather than a second way to confirm.)
8. `remote_ops` refuses the cases §5.5.4 was silent on (`Usage`), reports a missing source as `Io(NotFound)`; `restore_candidates` checks presence only (§5.5.4).
9. `gc --purge`, `check_blobs` and `restore` accept a backend without md5 (size only); an object `stat` no longer finds is dropped from the blob table without counting as purged (§5.9).
10. How a run ends: quota / rate limit → `Err(Backend(..))` after committing what completed (a `RateLimited` upload with the ledger ≥ `LEDGER_WARN` → `QuotaExceeded(DailyUpload)`); cancellation → `Err(Interrupted)` after the commit; neither carries a `Summary` (§5.7).
11. Additive public items: `Filter: Clone + Debug`, `sync::filter_base`, `Action::key()`, `Action::is_delete()`, `impl Display for SkipReason` (§9.9).
12. Each run that downloads or meta-sets files waits about 2 s at its end (re-observation, §5.7 step 5) — tests and the CLI e2e pay it per such run.

**Known limits** (accepted, recorded for later hardening):
- Exclude patterns match case-sensitively and by exact Unicode form (§5.5.3). *(Since §17.12 the exclusion is decided per comparison key, so a differently spelled twin no longer escapes — or is deleted because of — a pattern.)*
- The transfer layer's collision check compares only the final path component; a differently spelled *parent* directory on a folding file system is handled by the planner's spelling rule, not at run time.
- Files uploaded right after being written get a base row inside the racy window, so the next sync hashes them once more (only downloads are re-observed, §5.7 step 5); a base row refreshed within 2 s of the file's ctime stays untrusted for one more run.
- An upload-side type-change group whose uploads are all skipped at run time leaves its `Del`s unstaged and unreported; the next sync plans them again (§5.5.1).
- A dry run of an existing root creates the pair row in `state.db` (nothing else is written).

**Test coverage gaps of WP6** (none blocks WP7): "a changed `st_dev` alone changes nothing" is covered structurally only (the identity function returns `(st_ino, birth time)`; a device-number change cannot be simulated); the non-UTF-8 count is not exercised on APFS (the test asserts 0 or 1 depending on whether the file could be created); tests that depend on case folding or on NFC/NFD preservation branch on what the file system does — on this machine the folding branch ran, the case-sensitive one did not.

**Open after this wave** (for WP7):
- `sync::run` returns `Err` — without a `Summary` — for guards (exit 5), quota / rate limit (exit 75) and Ctrl-C (exit 130); `execute` has already committed what completed, so `cli/copy.rs` maps the error through `error::exit_code` and still calls nothing else. `Summary::exit_code()` is 0 or 6.
- Without a TTY, G6 needs `--reset-pair` / `--keep-pair` and G4 needs `--yes`; `sync::run` asks through `ui.choose` / `ui.confirm` itself and returns `Usage` when both pair flags are given.
- `restore_candidates(vault, path, now_ms)` takes server time: pass `backend.now_ms()`.
- `copy` / `sync` with a remote argument that names a file is a usage error from `sync::run` (exit 2); `check --download :FILE` works (`check_download` walks the prefix itself too).
- `gc` reports; it does not refuse on an incomplete index — that check stays in `cli/gc.rs` (§10). `check_*` return a `CheckReport`; exit 3 on `!report.ok()` is the CLI's.
- The futures of `run`, `gc`, `check_*` and `remote_ops::*` are `Send` (`util::tests::api_contract`, and a compile-time test in `tests/sync_faults.rs`).
- Still open from §17.3 for WP7: exit 3 on `RepairReport.still_missing`; the Drive-mode e2e test must route `logout --revoke` to the fake; the production pacer makes fault-injected Drive-mode CLI runs slow; `token.json` is only used from a 0700 directory.
- Not exercised by any automated test, as before: real Google and real Cloudflare (§2.9, §16.5); anything on Linux.

### 17.5 Integration wave 4 — WP7 (2026-11-11)

State after this wave: **every package is implemented** — WP0–WP8; no `todo!()` is left in `src/`. In the project root `cargo build --all-targets --locked`, `cargo build --release --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check` and `cargo test --locked` pass: lib 218 passed + 1 ignored generator (37 of them in `src/config.rs` and `src/cli/*`), `auth` 30, `backend_conformance` 36, `cli_e2e` 17, `cross_package` 14, `crypto_format` 38, `drive_http` 39, `index_adversary` 10, `index_props` 56, `live` 0 run + 2 ignored, `sync_e2e` 43, `sync_faults` 12, `transfer` 36, doc-tests 0. Ignored tests: the vector generator `gen_vectors` (§4.7) and the two opt-in tests of `tests/live.rs` (§13 item 10) — none for lack of a package; a bare `cargo test --locked -- --ignored` passes too (all three return at once without their environment switch), and `GCLONE_LIVE=mem cargo test --locked --test live -- --ignored` passes (2). `worker/` was not touched (byte-identical to the tree WP8 delivered and §17.2 verified); its tests were not re-run. Nothing was run on Linux, and nothing against real Google or Cloudflare.

**Shared files.** WP7 requested no change: `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/types.rs`, `src/error.rs`, `src/consts.rs`, `src/util.rs`, `src/ui.rs` are as they were after wave 3, and so are all files of WP1–WP6 and `tests/cross_package.rs`. No public signature of §9.10 changed. `README.md` (status, the test notes with the live-run command, the day-0 checklist, the layout list) was brought up to date by the integrator.

**Cross-package check (integrator).** WP7's own e2e tests drive the debug binary. The integrator additionally ran the **release** binary (LTO, `panic = "abort"`) over a directory vault: `login` (create) → `copy` up → second device `login` (attach) → `copy` down (equal trees) → `status` on both (equal `Head`) → `ls -l`, `tree`, `about`, `check`, `check --download`, `check LOCAL :REMOTE`, `gc -n`, `cat`, `sync -n`, `sync`, `restore --list`, `restore`, `--json copy` (valid NDJSON ending in `summary`) → `passwd` → `logout` → `ls` (exit 4, the `--vault-dir` hint) → `login` with the old passphrase (exit 4) and the new one → `repair` → `logout --forget` → unconfigured `ls` (4), `login` without a URL (4), `login http://example.com` (4, `BadAuthUrl`); file modes 0600 / 0700. **All of it behaved as specified**, and three things no automated test covered were checked:
- **Release builds ignore the test switches**: with `GCLONE_TEST_FAST_KDF=1` in the environment the release binary wrote a keyfile with `m_kib = 262144, t = 3, p = 1` (read from the preamble). All `GCLONE_TEST_*` reads go through `cli::context::test_env` (`cfg!(debug_assertions)`).
- **Graceful Ctrl-C during `copy`** (3,060 files, 720 MB, SIGINT after 0.4 s): the message, exit 130, 24 files committed and visible to `ls`, `Pending none`; the next `copy` uploaded the remaining 3,036, `check` found 61 good blobs, a second device pulled an equal tree.
- **The lost-creation-race path** of §2.6 end to end — now an automated test, `a_lost_creation_race_switches_to_the_winner` in `tests/cli_e2e.rs` (§12.1): the loser's passphrase comes through a FIFO, which lets the test create the winning vault between the loser's discovery and its creation.

**Fixed by the integrator** (`src/cli/login.rs`, `src/cli/status.rs`): the day arithmetic on `refresh_expires_in` / `refresh_expires_at_ms` — numbers taken from the Worker's answer and from `secrets.json` — used plain `+`; a value near `u64::MAX` panicked a debug build and wrapped in release. Both are saturating now (unit test extended). No other defect was found, and no cross-package mismatch: WP7 runs on WP1–WP6 without a change to any of them.

**WP7 — deviations and precisions** (§2.6, §7.1, §7.2, §9.10, §10, §12.1 edited in place):
1. `--vault-id HEX` that matches nothing is a usage error also when no vault at all was found: a vault asked for by id is never created (§2.6 step B.2 lists `--vault-id` before "found is empty" now).
2. On an attached device `--new-vault`, or a `--vault-id` other than the attached vault, is a usage error (exit 2) naming `gclone logout --forget`; B.2 would have ignored both silently (§2.6).
3. When a device becomes connected, `config.json` is written **before** `secrets.json` (§2.6 CREATE / ATTACH, §10): a cached key never exists without the config it belongs to. A kill in between leaves `Locked` (Drive: the keyless secrets of step A.4) or `NotLoggedIn` (directory), which `gclone login` repairs through ATTACH.
4. `RefreshPolicy::Tolerant` does not tolerate a login failure (exit 4: `VaultNotVisible`, `BackendError::Auth(_)`, `AppNotAuthorized`): read-only commands and `gc` fail with it instead of continuing on the replica — required by "after revoke, `ls` exits 4" (§12.1); integrity verdicts and network errors are tolerated as before (§9.10, §10). *Narrowed by §17.9, item 1:* `AuthError::Network` and `AuthError::Io` are network errors in this sense, not login failures.
5. `copy` / `sync -n` open with `settle = false` and skip `finish_mutation`: a dry run publishes nothing, leftover staged ops included. After a **download**, an `OutboxStuck` from `finish_mutation` is a warning, not a failure (§10).
6. Exit codes the spec left open (§7.2): no terminal and no `--passphrase-file` → 2; too short / empty passphrase from a file → 1; `logout --forget` refused over unpublished changes → 5; `logout --revoke` without `--yes` off a terminal → 2, declined → 1; `gc` refuses with 3 for any refresh failure it does not pass on (a network error included).
7. Message wording (§2.8 — the texts are owned by `cli/`): `NotAllowed` shows the Worker's own message (the address is inside it, not available separately); `BadAuthUrl` reads "The auth Worker URL must be https://… — <reason> (given: <url>)."; `NotConfigured` also names `gclone login --vault-dir DIR`; the expiring-login text ends with "(Nothing was stored; --allow-expiring-login accepts such a login.)"; `logout` on a directory vault says "The cached vault key was removed from this device." instead of the Google-token sentence.
8. `status`: "Login expires in N days" rounds to the nearest day (604799 s → 7); `status -q` prints warnings only (§7.1).
9. `tests/live.rs` accepts `GCLONE_LIVE=mem` besides `GCLONE_LIVE=1`: a rehearsal of the same code on an in-memory backend that already holds foreign objects. With `1` everything happens inside one throwaway top-level folder `gclone-live-test-<hex>` through a scoping wrapper (the user's vault is neither listed nor touched), and the folder is trashed at the end, also after a failure (§12.1). The documented command is `GCLONE_LIVE=1 cargo test --test live -- --ignored --test-threads 1`.
10. Ctrl-C (§7.1): graceful only in `copy` / `sync`; every other command exits 130 at once after restoring the terminal settings.
11. `FileSecretStore::save` refuses to write into an existing state root that is not private, and `login` checks the state root before signing in (§9.10) — the spec defined the strict check for `load` only.
12. clap definitions tightened (§7.1): `--transfers` 1..=64; `--vault-dir` conflicts with `AUTH_URL`; `--new-vault` conflicts with `--vault-id`; `restore --list` conflicts with `--version`; `--version` ≥ 1.
13. Additive public items (§9.10): `Secrets::empty`, `Secrets::set_keys`, `Config::vault_id_bytes`, `Config::handles`, `OpenOpts::read_only` / `mutating`, `Ctx::report_refresh`, `LoginArgs: Default`.
14. `ls -l` shows no time for directories (the §7.3 example shows one): directories carry no mtime in the index.
15. The directory backend adopts an **empty** folder of the vault's name, so the "exists but holds no complete vault" text of §2.6 appears only for a non-empty orphan — which is what an interrupted creation leaves.

**Things that must not be "cleaned up".** Two acceptance items are observable only through debug log lines, and `tests/cli_e2e.rs` reads them under `-vv`: `reading keyfile candidate <name>` (`cli/login.rs`; "at most `KEYFILE_TRY_MAX` keyfiles are read") and `drive backend: transfers=N …` (`cli/context.rs`; "`--transfers 2` reaches the backend config"). Removing either `tracing::debug!` breaks a test.

**Open decisions and known limits** (none blocks first use over a directory vault; the Drive path additionally waits for the live run below):
- `--json` with any command other than `copy` / `sync` prints nothing on stdout (`Ui::out` is silent under `--json`, §7.1): `gclone ls --json` exits 0 with empty output. Either define listing events or make those commands ignore the flag. **Settled in §17.14**: they refuse the flag (exit 2).
- A dry run of an existing root still creates the pair row in `state.db` (§17.4), now reachable from the CLI.
- Two devices get the same default name when their host names are equal (`--device-name` sets it); `status` then lists the name twice, told apart only by the id on the "This device" line.

**Not exercised by any automated test** (in addition to the lists of §17.3 and §17.4): real Google and real Cloudflare — `tests/live.rs` with `GCLONE_LIVE=1` and `gclone probe` were never run, so the wire shapes of §6.4.1, the day-0 probes of §2.9 and the conformance suite against the real service are all still open, and **this is the gate before first real use**; the browser (loopback) flow started from the binary (the library flow is covered in `tests/auth.rs`); the "Run `gclone login` now?" offer after an expired login; the terminal passphrase prompts (generated passphrase, too short / short with warning / mismatch, three wrong attempts — checked by hand under a pseudo-terminal by WP7 only); a graceful Ctrl-C during `copy` / `sync` (checked by hand by the integrator, above); that a release build ignores `GCLONE_TEST_DRIVE_API` / `_UPLOAD` / `GCLONE_TEST_REVOKE_URL` (the same `test_env` gate as the checked `GCLONE_TEST_FAST_KDF`); anything on Linux.

### 17.6 Final pass (2026-11-11)

This copy (`docs/SPEC.md`) is the spec as it stood after wave 4 plus this section and the mention of it in the title line; nothing else was edited.

State: in the project root `cargo build --release --locked`, `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` (no warning) and `cargo test --locked` pass: lib 218 passed + 1 ignored generator, `auth` 30, `backend_conformance` 36, `cli_e2e` 19, `cross_package` 14, `crypto_format` 38, `drive_http` 39, `index_adversary` 10, `index_props` 56, `live` 0 run + 2 ignored, `sync_e2e` 43, `sync_faults` 12, `transfer` 36 — 551 passed, 3 ignored (the vector generator and the two opt-in live tests; none for lack of code). `GCLONE_LIVE=mem cargo test --locked --test live -- --ignored --test-threads 1` passes (2). No `todo!()` / `unimplemented!()` is left in `src/`. In `worker/`: `npm ci`, `npm run typecheck` and `npm test` pass (configuration check + 138 tests in 5 files; the run prints one expected "Network connection lost" line from a test that simulates it). Nothing was deployed, nothing was run on Linux, and nothing against real Google or Cloudflare.

**Smoke test of the release binary over a directory vault** (three simulated devices = three `GCLONE_CONFIG_DIR` / `GCLONE_STATE_DIR` pairs). Covered: vault creation; a tree with an empty file, 1-byte and small files, files at every chunk / pack / multipart boundary (65,535 … 16,777,217 bytes), a 21 MiB and a 200 MiB and a 1.4 GiB file, Unicode / NFD / emoji / space / quote / newline / control-character names, a 244-byte name, nested and empty directories, 10,000 small files; `sync` up, attach of a second device, `sync` down, `diff -r` clean, mtimes and the exec bit equal; modify / append / delete / rename of files and directories / type change file ↔ directory, re-sync, `diff -r` clean; two-device conflicts (conflict copies both ways, skips, exit 6); `mkdir`, `mv`, `rm`, `restore`, `cat` with ranges, `--json`, `--exclude`, `.gcloneignore`, the delete guard (with and without a terminal), `passwd` + a third device, `logout`, `logout --forget`, `gc`, `gc --orphans`, `gc --purge`, `repair`, `about`, `status`; SIGINT and SIGKILL in the middle of an upload followed by a resumed run; a source file that grows while it is uploaded; a copied state directory (clone detection); lock contention; a flipped byte, a truncation and a removal of a blob (`check`, `check --download`, `cat`, `copy` all report it, exit 3 / 6); a removed and a damaged index segment (rollback warning on a device that had seen it; a fresh device warns about the damaged object); the terminal passphrase prompts under a pseudo-terminal. A randomized soak (3 devices, random create / modify / delete / rename / rmtree operations with `sync` up and down in random order, 9 seeds, 60–100 rounds each) converged to equal trees and equal heads every time, with clean `check`, `check --download` and `check LOCAL :REMOTE`. **Everything behaved as specified.**

**Fixed** (`src/ui.rs`, `init_logging`): log lines were coloured with ANSI escape codes although stderr was a pipe or a file. Colour is now used only when stderr is a terminal and `NO_COLOR` is unset. Regression test: `log_lines_in_a_pipe_carry_no_escape_codes` in `tests/cli_e2e.rs`; the harness's `Out::sane` now also refuses escape codes in any captured output.

**Added test** (`tests/cli_e2e.rs`, `drive_mode_varied_tree_round_trip`): the binary against `FakeDrive` over HTTP with the smoke test's tree — empty file, packed files, a file above 20 MiB (asserted to go up as a resumable upload of several parts), Unicode names, nested and empty directories — two devices, modify / delete / rename (3 uploads, 4 reuses), equal trees and heads, `check`, `check --download`, `check LOCAL :REMOTE`, a ranged `cat`.

**Observed, by design, now stated in `README.md` ("Limitations")**: two new files with identical content in one run are both uploaded (reuse looks only at live index entries, §5.5.1); a `chmod` that does not change the exec bit is not propagated (§5.7); a case-only rename is not propagated (§14 item 7); `copy` / `sync` refuse a single file as source or destination; the per-file `fsync` of §5.7 step 2 limits restores of many small files to a few hundred files per second on macOS (10,000 files: 43 s — *no longer: §17.15 flushes per batch*), and the re-observation pass of §5.7 step 5 adds up to 2 s to every run that downloads (unchanged); a pre-created state directory with mode 0755 is refused (§8.1 strict loading — let gclone create it); `ls` / `tree` print control characters in names unescaped; a killed process can leave spool files in a directory vault's `.gclone-tmp/` until the next `open` after they went stale.

**Still open** — unchanged from §17.5: the real services. `gclone probe`, `tests/live.rs` with `GCLONE_LIVE=1`, the manual rows of §2.9, a deployed Worker and the browser (loopback) login started from the binary have never been run; Linux is untested.

### 17.7 Review round 4 — worker security (2026-11-12)

Five findings of a security review of `worker/`, all confirmed in the code and fixed. Nothing was deployed and nothing ran against real Google or Cloudflare; what stays unverified is listed at the end. Sections edited: title line, §0, §1.3, §2 (diagram), §2.2, §2.3, §2.3.1, §2.3.2, §2.4 (mapping table, check code), §2.9 (probe 5), §9.6 (the fake), §12.1 (WP3, WP8), §15, §16.1–§16.7.

1. **`/token` did not pin the granted scope** (§2.3 said "`scope` contains `SCOPE_DRIVE_FILE`", and the code did exactly that). The authorization URL is not under the Worker's control once it has left `/login`, so a link with a rewritten `scope` — or with `include_granted_scopes=true` — produced, through the Worker's client secret, a refresh token for whatever Google granted, e.g. the owner's whole Drive in plaintext. **Now**: `ALLOWED_SCOPES` (§2.2); `/token` answers `403 scope_not_allowed` and discards the tokens when any reported scope is outside the set, and `/refresh` does the same for a refresh token whose grant is wider (§2.3). No revoke in either case. New error code `scope_not_allowed`; the device maps it to `AuthError::Denied(message)` (`src/auth/login.rs`, §2.4). `FakeDrive` had the same "contains" rule and now applies the same check. Contract fixture: `token_scope_not_allowed`, `refresh_scope_not_allowed`, `given` keywords `grant_wide_scope`, `refresh_wide_scope` (36 cases). The device-side check of §2.4 is unchanged (a device cannot verify a Worker it has to trust anyway).
2. **The check-code confirmation was bypassable.** `/callback` answered Google's redirect with the grant at once (302 to the loopback address, or the paste page), for any unexpired state, whoever had fetched it — so a phisher who sent the `accounts.google.com` link instead of the `/login` link took the "only pre-consent control" of §2.3.2 out of the flow; in loopback mode one consent then delivered the grant to whatever listened on the chosen port. **Now** `/callback` is visited twice (§2.3): Google's redirect is answered with a `200` confirmation page (check code, warning, one link) and nothing else; the link carries a new sealed blob kind, *pending* (§2.3.1, kind `0x03`, key `K_pending`), and only the request with that blob is answered with the grant. The grant's expiry is the pending blob's, so `GRANT_TTL` keeps bounding the age of Google's code. The stateless, cookie-free design is kept (the alternative — a `__Host-` cookie binding `state` to the browser, §14 item 8 — would have needed cookies and still stays possible on top). The `/login` page is unchanged and is now described as what it is: a courtesy to the honest flow, not a control. A login is 4 requests instead of 3. `FakeDrive` follows: `/auth/continue` answers the second confirmation page and `/auth/callback?confirmed=<n>` releases the grant; `FakeDrive::browse` and both contract harnesses refuse a redirect or a paste code before that page. The device code and its texts are unchanged ("The page must show the check code …" now holds for two pages).
3. **Request URLs with query strings could still reach stored logs.** `invocation_logs: false` suppresses only the separate invocation event; Cloudflare attaches the triggering request to every stored log event and to traces. **Now** `wrangler.jsonc` also sets `observability.redact_query_string: true` and `observability.traces.enabled: false`; `check-config.mjs` requires both and forbids `destinations` and `streaming_tail_consumers` (§16.2); the wrangler floor is `^4.160.1`, the locked version in which the key was checked (`package.json` and `package-lock.json`). The statement that `wrangler tail` shows only the Worker's own lines was **wrong** — it prints the full URL of every live request — and is corrected in §2.3, §16.2, §16.6 and `worker/README.md`. The checker has its own tests now (`scripts/check-config.selftest.mjs`, `node --test`).
4. **The rate-limit key was the full client address**, so one IPv6 host (2^64 addresses in its /64) was not limited at all. **Now** the key is the /64 prefix for IPv6 (`rateLimitKey`, §2.3). A second, global budget was considered and **not** added: it would let any stranger lock the owner out at a trivial request rate. A sender with many networks is still not stopped; the texts that claimed otherwise (§1.3, §2.3, §2.3.2, §16.6, README) now say so and point to the zone rule.
5. **Custom domain.** `setup.sh` printed the Worker's host name as Google's "Authorized domain" for a host outside `workers.dev`; Google takes the registrable domain only. It now prints the last two labels with a note (`./setup.sh --authorized-domain <host>` exposes the value to `scripts/setup.selftest.mjs`). The README and §16.6 name the registrable domain, document the custom domain as a `routes` entry in `wrangler.jsonc` (restored by every deploy) instead of a dashboard setting, and say that "If the Worker is lost" includes the domain. `preview_urls: false` is pinned in the shipped file and asserted. The reviewer's claim that an omitted `preview_urls` leaves preview hosts enabled after `workers_dev: false` was **not** confirmed — wrangler 4.160.1's own warning text says the default follows `workers_dev` — the key is pinned anyway, so the shipped state does not depend on it.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass with the counts of §17.6 (551 passed, 3 ignored; no Rust test was added as a function — `redeem_maps_the_workers_refusals`, the contract fixture test and the mapping-table tests grew). In `worker/`: `npm run typecheck` and `npm test` pass — configuration check, 12 `node --test` tests in 2 files, 162 Vitest tests in 5 files (138 before); `npx wrangler deploy --dry-run` builds with the new configuration. The new tests were also run against the sources as they were before this section: 76 of the Vitest tests and 8 of the `node --test` tests fail there.

**Still unverified, and now part of probe 5 (§2.9)**: that Google's `scope` answer for an unmodified login consists of members of `ALLOWED_SCOPES` only (if not, every login fails closed with `scope_not_allowed` naming the entry); that a Google authorization code is still redeemable after up to `GRANT_TTL` on the confirmation page (unchanged bound, but the time is now spent by a person reading a page); that a stored Workers Logs event carries no query string with the settings of §16.2; that `cf-connecting-ip` is a plain IPv4 or IPv6 address. Not addressed here (reported by the same review as unproven against real Google): `/refresh` revokes grant-wide when a refresh ID token lacks `email` or `email_verified`; `emailAllowed` requires a boolean `email_verified` while one Google example shows the string `"true"`.

### 17.8 Review round 4 — crypto and formats (2026-11-12)

Two findings of a review of the crypto/format layer, both confirmed by reading the code and fixed. Sections edited: §2.8, §3.3, §4.6, §4.7, §5.3, §6.1, §7.2, §9.3, §9.4, §9.5, §9.7, §11, §12.1, §13, §15.

1. **An index object in a newer format was reported as a failed authentication and skipped.** `Vault::accept` turned every error of `open_segment` / `open_snapshot` into "corrupt index object … counts as missing" — including the errors that exist to say "written by a newer gclone": `CryptoError::Unsupported` (suite, chunk size, type, flags), `CryptoError::UnknownEpoch`, `FormatError::Codec`, and the body-version case, which was only a `Decode` string. The device then planned and wrote against an index without that object and exited 0. §3.3 ("unknown version anywhere → fail closed") and §4.6 ("fails acceptance → counts as missing") contradicted each other; the code followed §4.6. **Now** (§4.6 "Unreadable is not corrupt"): `FormatError::BodyVersion(u8)` is its own variant, `FormatError::newer_format()` names the four version refusals, and for bytes that came from the store `accept` returns `IndexError::UnsupportedObject { name, what }` — the refresh, and with it `repair`, stops with exit 3 and a text that names the object (§2.8). A cached copy that does not open is still only dropped. `BadMagic` and `EpochTooOld` stay "corrupt". Decision recorded in §4.6 and §15: the header fields are read before any key is derived, so the stop can be provoked by anyone who can write to the `index` folder; stopping only on the two authenticated signals (codec, body version) was considered and rejected, because a new suite, flag or key epoch — the changes a later format is most likely to make — would then still be skipped silently, and the parties who can plant an object can already stop every device by trashing the journal. The CLI line for objects that really failed acceptance no longer says "failed authentication" (it now also covers oversized objects): "N index object(s) failed verification (damaged, oversized, or not written with this vault's key) and were ignored".
2. **Index objects and the descriptor were buffered without a size bound before any authentication.** `fetch_object` and `fetch_references` used `get_all(…, None)` and never looked at a size; `Vault::discover` trusted the *listed* size of the plaintext descriptor and then read without a range. A multi-gigabyte object under a valid index name, or a store that lists a small size and serves a large body, ended the process in the allocator on every run, with no diagnostic. **Now**: `INDEX_OBJECT_MAX` = 1 GiB is a format rule (§4.6 rule 1) — `seal_segment` / `seal_snapshot` refuse to write more, `open_*` refuse to accept more; every download of an index object goes through `backend::get_bounded` (§9.5), which asks for one byte more than allowed and drops the stream once more than the bound has arrived, also when the range is ignored; an object listed above the bound is not requested at all; objects listed above `INDEX_PARALLEL_MAX` (16 MiB) are fetched one at a time instead of eight side by side. `discover` reads the descriptor through the same helper with `DESCRIPTOR_MAX` (now in `consts.rs`). Rejected objects are logged as `corrupt index object <name>: larger than …`, appear in `RefreshReport.corrupt_objects` and count as missing. The fakes had the same blind spot — a listed size was always the true size — so `MemBackend::claim_size` was added. What is **not** bounded is spelled out in §15 (a lying store can still cost 8 × 1 GiB). The keyfile path (§2.6) already read with a range and is unchanged.

Tests added: `src/backend/mod.rs` (`collect_bounded_stops_reading_a_body_that_is_too_long`, `get_bounded_asks_for_one_byte_more_than_allowed`), `src/format/index.rs` (`an_index_object_above_the_cap_is_refused_unread`, `newer_format_classifies_version_errors_only`; `decode_fails_closed` now expects `BodyVersion(1)`), `src/error.rs` (exit code 3 for `UnsupportedObject`), `tests/index_adversary.rs` (`an_index_object_of_a_newer_format_stops_the_refresh`, `damage_is_still_reported_as_damage_not_as_a_newer_format`, `an_oversized_index_object_is_never_buffered`, `an_oversized_descriptor_is_never_buffered`), `tests/cli_e2e.rs` (`an_index_object_of_a_newer_format_is_not_ignored`). With the two behaviours switched back in the sources (the version refusal ignored, the bounds set to `u64::MAX`), the three behavioural tests of `tests/index_adversary.rs` fail.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 560 passed, 3 ignored (lib 222, `auth` 30, `backend_conformance` 36, `cli_e2e` 20, `cross_package` 14, `crypto_format` 38, `drive_http` 39, `index_adversary` 14, `index_props` 56, `sync_e2e` 43, `sync_faults` 12, `transfer` 36). `worker/` was not touched.

**Still unverified** (no real Drive was contacted): that Drive honours `Range: bytes=0-N` on `alt=media` downloads with a `206` (if it answers `200` with the whole body, `DriveBackend::get` cuts the stream and `get_bounded` stops reading it, so the bound holds either way); that the `size` Drive lists for an index object is its exact byte length — the fix deliberately uses the listed size only to *skip* objects and to decide what is fetched alone, never as the read bound, so a wrong listed size cannot make a genuine object unreadable unless it is listed above 1 GiB.

### 17.9 Review round 4 — auth client (2026-11-12)

Five findings of a review of the device side of the login (`src/auth/`, `src/cli/{context,login,logout}.rs`), all confirmed in the code and fixed. Four of them were the spec's own letter, faithfully implemented; the sections that said so are changed. Sections edited: title line, §2.4 (browser flow step 3), §2.6 (A.4, B.2), §2.7 (`logout`), §2.8, §7.2, §8.1, §9.3 (`util`), §9.10, §10, §12.1, §15, §17.5 item 4; README ("Adding a device", "Limitations", "Local files").

1. **Read-only commands failed with exit 4 when the auth Worker was unreachable and no access token was cached.** `RefreshPolicy::Tolerant` treated every `BackendError::Auth(_)` as "this login no longer works" (§17.5 item 4), `AuthError::Network` included — so `ls` / `tree` / `status` / `about` answered from the replica while Drive was unreachable, but only for the hour a cached access token lasts; after that, a laptop without network, a Worker outage or an exhausted `workers.dev` quota (§15) made them fail although nothing was wrong with the login. **Now** `login_failure` (`cli/context.rs`) counts `VaultNotVisible`, `AppNotAuthorized` and every `AuthError` *except* `Network` and `Io`; those two take the tolerant path like `BackendError::Transient`: a warning ("could not reach the auth Worker: … Showing the last state this device has seen.") and the replica. Unchanged: mutating commands (`RefreshPolicy::Required`) exit 4 with the §2.8 text; `cat` / `check` fail with exit 4 at their first download; `gc` refuses with 3 as for any other incomplete refresh; a revoked or expired login (`Expired`), `NotAllowed`, `Denied`, `ScopeMissing` and `WorkerMisconfigured` stay exit 4 for every command.
2. **A sign-in with the wrong Google account on a re-attaching device was kept, and `gclone login` could never replace it.** Step A.4 saved the new refresh token whenever no key was cached, before B.2 knew whether that login sees the vault of `config.json`. After `VaultNotVisible` the wrong login stayed on file; every later `gclone login` found it working (A.2), printed "Already signed in", and failed on the vault again without asking — while the message said "Sign in with the account that owns the vault". **Now** (§2.6 A.4): on a device with `config.json` the token of a fresh sign-in is saved only once the attached vault was seen with it — after B.1, as before, or as soon as B.2 found `config.vault_id` in the discovery (before the passphrase prompt, so a wrong passphrase still does not cost a second sign-in). A device without `config.json` saves at once, as before. Accepted cost: on an attached device a failure between the sign-in and the discovery (a network error) costs one more sign-in. In addition, `VaultNotVisible` from `login` while A.2 **kept** the login on file — the state older builds left behind, or a vault that really is out of the app's reach — now ends with "This device is signed in as <email>, and `gclone login` keeps a login that still works: to sign in with another account run `gclone logout` first, then `gclone login`." (B.1 and B.2).
3. **`logout --revoke --forget` revoked before it asked the question that could still stop it.** The grant-wide, irreversible revoke ran first; the unpublished-changes confirmation of `--forget` came after it, and declining returned exit 5 with "nothing was removed" — every device signed out, `secrets.json` kept with a dead token, the revoke unreported, and the hint "run any gclone command to publish them" false. **Now** the order is: load the login and the endpoints → the `--revoke` confirmation → the `--forget` check and confirmation → only then `auth::revoke` → the deletions. Declining the second question: "nothing was revoked and nothing was removed (pass --yes to forget anyway)", exit 5.
4. **`logout` could leave a live access token or a temp copy of `secrets.json` behind.** "Signed in" is decided by the presence of `secrets.json`; without it the command returned "nothing to do" and left a `token.json` alone, and because `secrets.json` was deleted first, a logout that failed or was killed between its two deletions produced exactly that state. Nothing removed `.secrets.json.tmp-<hex>` files — full copies with refresh token and cached key that `util::write_atomic` leaves when the process is killed between creating the temp file and the rename (Ctrl-C exits at once outside `copy` / `sync`, §7.1). **Now** every `logout` removes `token.json` and the temp files of `token.json` and `secrets.json` (`util::remove_atomic_leftovers`), signed in or not, and does so **before** `secrets.json`; `SecretStore::delete` removes the temp copies of its own file (which also covers the lost creation race of §2.6). Not signed in but something was removed → "Not signed in on this device; leftover files of an earlier login (cached access token, unfinished writes) were removed." Temp files are not swept at any other time: `token.json` is written without the state lock, and taking away a concurrent writer's temp file would make its rename fail. **Not closed**: a command that runs without the state lock (a read-only command that found the lock busy, §8.3; any command on a device whose state directory does not exist yet) and loaded the secrets before the `logout` can still refresh afterwards and write `token.json` again; that token lives at most an hour and the next `logout` removes it.
5. **The loopback listener dropped a request whose head exceeded 16 KiB**, without an answer. It buffered the whole head although only the request line is used, and a browser sends every cookie stored for host `127.0.0.1` — cookies are not separated by port — with the redirect; with more than about 15 KiB of them (local dev servers, notebooks) the redirect that carried the valid grant was discarded, the browser showed an empty-response error, and the device waited out `AUTH_TIMEOUT` with the grant long dead. **Now** (§2.4 step 3) the request line is acted upon as soon as it has arrived; the headers are only drained (up to the empty line, 4 MiB or 5 s) so that closing the connection does not reset it under the answer page; a request line over 8 KiB is answered `414` and the login keeps waiting.

Tests added (each fails with its fix reverted — checked in a scratch copy): `src/cli/context.rs` `login_failure_is_a_dead_login_not_an_unreachable_worker`; `src/util.rs` `remove_atomic_leftovers_takes_only_the_temp_files_of_that_path`; `src/config.rs` `delete_removes_temp_copies_of_an_interrupted_save`; `tests/auth.rs` `loopback_answer_with_huge_headers_still_signs_in`; `tests/cli_e2e.rs` `drive_mode_read_only_commands_survive_an_unreachable_auth_worker`, `drive_mode_wrong_account_after_logout_and_revoke_forget_order` (its `logout` part runs the binary on a pseudo-terminal — `libc::openpty` — because the prompts exist only on a TTY), `logout_removes_leftover_login_files` (§12.1). `FakeDrive` was not changed: it still models one Drive for every account, so "another account sees no vault" is injected (`fail_next(Route::Media, 1, 404, …)` on the descriptor download, `fail_next(Route::Stat, 1, 403, …)`), not derived from the signed-in address.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 567 passed, 3 ignored (lib 225, `auth` 31, `backend_conformance` 36, `cli_e2e` 23, `cross_package` 14, `crypto_format` 38, `drive_http` 39, `index_adversary` 14, `index_props` 56, `sync_e2e` 43, `sync_faults` 12, `transfer` 36). `worker/` was not touched.

**Observed and left as they are** (reported with finding 5, not defects of their own): `force_refresh` re-reads the rejected token from the cache instead of taking it from the caller, so a late `401` can cost one redundant `/refresh`; `AUTH_TIMEOUT` can cancel a `/token` call that is in flight; a failed bind of `127.0.0.1:0` is an error instead of a fall-back to the paste flow; an `AUTH_URL` with a path is accepted although the Worker only routes at its root.

**Still unverified** (no real browser, Google account or Worker was used): what a real browser shows when the loopback answer arrives after several hundred KiB of request headers were drained; that a second allow-listed account's discovery under `drive.file` really comes back empty (rather than with an error) for a vault it does not own — either way the login is not kept, since `VaultNotVisible` and every other failure precede the save.

### 17.10 Review round 4 — Drive API (2026-11-12)

Three findings of a review of the upload side of `DriveBackend` (`src/backend/drive/{mod,api,upload}.rs`), all confirmed in the code and fixed. None could show against `FakeDrive`: it receives every request body at loopback speed and never cut, dropped or delayed a part more than once. Sections edited: title line, §6.1 (constants, types), §6.2 (Small, steps 2 and 7, "where the protocol text is silent"), §6.4, §6.5 (transient row), §9.6 (`DriveConfig`, `DriveBackend`, `FakeDrive`), §12.1 (WP3), §15; README ("Limitations").

1. **`HTTP_READ_TIMEOUT` was a 60 s deadline for every upload request.** §6.4 gave the transfer client `read_timeout` and "no total timeout", taking reqwest's read timeout for a per-read stall detector. In reqwest 0.13 that holds for the response body only: until the response headers arrive, one `sleep(read_timeout)` is armed per request and nothing pushes it back while the request body is written. So connect + the whole body + the response headers had to fit into 60 s — a 4 MiB multipart body needed 560 kbit/s per stream and could never succeed below that (ten re-sends from byte 0, then `Transient`, three attempts, file failed); a 16 MiB part needed 2.2 Mbit/s per stream (9 Mbit/s of uplink at the default four transfers) and otherwise advanced only through cut-off, status query and resend. **Now** (§6.4) uploads have a client of their own without `read_timeout`: every request on it has a total timeout (`HTTP_READ_TIMEOUT`, raised to `HTTP_READ_TIMEOUT + len / UPLOAD_MIN_RATE` for a request with an upload body), and upload bodies go out as a stream of `UPLOAD_SLICE` pieces under a stall watch that gives the request up when the HTTP stack took no piece for `HTTP_READ_TIMEOUT`. `Inner::upload_request` builds such a request (`api::Outgoing` = request + watch; `Inner::call` takes either that or a plain `RequestBuilder`); the multipart POST, part PUTs and the probes' uploads (§2.9) use it, the initiation and status queries run under the client's default total timeout. Downloads and metadata calls keep `read_timeout`, which is correct for requests without a body worth mentioning. New constants `UPLOAD_MIN_RATE` (8 KiB/s) and `UPLOAD_SLICE` (16 KiB); `DriveConfig.read_timeout` (additive) so that tests need not wait a minute. Accepted: a multipart or part body is now always sent with an explicit `Content-Length` over a stream (before, only parts made of several slices were); below 8 KiB/s per stream uploads fail by design (§15).
2. **A resumable session that was advancing was abandoned after `MAX_ATTEMPTS` cut parts.** The round counter (`stalled`) was reset only when a part PUT itself was answered `308` with a higher `Range`. After a part that failed (network error, `5xx`, throttle, `401`), progress is learned from the status query — which reset nothing. Ten cut parts in a row therefore ended the put with `Transient` although each had moved the session forward, the transfer layer restarted the whole file under a new salt and ID, and the waits between those rounds grew to 64 s. **Now** (§6.2 step 7) progress is "a `308` — the part's or the status query's — that reports more than the server ever held", and it resets the counter, the backoff exponent and the write breaker's run. The high-water mark (rather than "more than the last answer") keeps a session that forgets bytes and takes them again from running forever.
3. **Rounds without progress were repeated at once.** A part answered `308` with the old `Range` (or none) was sent again immediately — up to ten times 16 MiB back to back — and a session that held every byte without being complete was asked ten times within milliseconds; every other retry in that loop backed off. **Now** such a round is followed by `BACKOFF(n)` like a transient failure (§6.2 step 7); it still counts towards `MAX_ATTEMPTS` and still ends in `Transient("the upload session makes no progress")`.

`FakeDrive` (it encoded none of the three misconceptions, but could not provoke them): `ack_only_times`, `drop_parts`, `hold_completion` (§9.6); a status query on a session that holds every byte now completes it (before, such a session — reachable only through `ack_only` on a last part of whole granules — answered `308` forever). `hold_completion` is injected behaviour: whether real Drive answers `308` with the full `Range` while it finalises is unverified.

Tests added (each fails with its fix reverted — checked in a scratch copy): `tests/drive_http.rs` `an_upload_that_flows_steadily_may_take_longer_than_the_read_timeout`, `an_upload_that_stops_moving_is_given_up_after_the_read_timeout` (both against `SlowUpload`, a raw TCP endpoint in that file that reads bodies at a set pace), `a_session_that_advances_through_cut_parts_is_not_given_up`, `rounds_without_progress_wait_before_the_next_one`; `src/backend/drive/upload.rs` `body_slices_are_small_and_the_last_one_ends_the_watch`, `the_watch_fires_when_nothing_moved_for_the_limit`. `neither_client_follows_redirects` became `no_client_follows_redirects` and covers the upload client (§12.1).

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 573 passed, 3 ignored (lib 227, `auth` 31, `backend_conformance` 36, `cli_e2e` 23, `cross_package` 14, `crypto_format` 38, `drive_http` 43, `index_adversary` 14, `index_props` 56, `sync_e2e` 43, `sync_faults` 12, `transfer` 36). `worker/` was not touched.

**Still unverified** (nothing here ran against real Drive or over a real slow link): the stall watch's tolerance was measured on loopback only (with the limit shortened to 2 s, streams of 160 KiB/s and more passed and 80 KiB/s tripped it — 5.3 and 2.7 KiB/s at the real limit, in line with hyper's 256 KiB queue); how much of a body the kernel's send buffer holds on a real slow uplink once the last piece is handed over, which decides how late a connection that dies at that point is noticed (§15); that Drive keeps the bytes of a part PUT that is cut off (documented for resumable uploads, and what finding 2 relies on to matter).

### 17.11 Review round 4 — index and local state (2026-11-12)

Nine findings of a review of the journal (`src/index/`), the local state (`src/state/`) and their callers (`src/sync/gc.rs`, `src/cli/{context,login}.rs`, `src/path.rs`). Eight were confirmed in the code and fixed; one had been fixed by §17.8 already. In most of them the code followed the letter of this spec, and the spec is what changed. Sections edited: title line, §2.6 (ATTACH), §5.1, §5.2.3, §5.3 (presence check, "as implemented"), §5.6 (commit, cleanup), §5.8, §5.9, §8.3, §8.4, §9.3 (`path`), §9.7, §9.10, §10, §12.1 (WP4, WP6, WP7), §13, §15.

1. **A stale outbox segment was published without looking at its blobs** (medium). `recover_outbox` re-put the sealed segment and applied it with its base effects; `verify_pending_blobs` covered `pending` rows only. A segment that was sealed in time and then waited — full Drive, device off — named blobs that were unknown objects to every other device; `gc --orphans` elsewhere trashed them after 14 days, and the returning device then published heads on trashed blobs and base rows saying "in sync", so the files were never uploaded again and the only remote copy went with Drive's trash purge. §5.9 claimed the 7-day rule protected such work; it never reached the outbox. **Now** (§5.8): `recover_outbox` stats the blobs the segment names, un-trashes, and withdraws the segment (outbox row and `own` row deleted, surviving ops staged again with their effects, the others dropped with a warning) when a blob is missing, damaged or, unpublished, older than `ORPHAN_GRACE / 2` — unless the segment itself is already in the store, which is then finished as sealed. `CommitReport.dropped_ops` includes what a withdrawal dropped. New: `tables::own_delete`; `commit.rs` `settle_outbox`, `withdraw_stale`, `check_blobs` (shared with `verify_pending_blobs`), `segment_stored`, `draft_from_op`. The tests had the same blind spot: three crash-safety tests published stuck segments whose `Put`s named blobs that had never been uploaded; they now upload them (`put_uploaded`).
2. **`gc` judged dead blobs by heads alone** (medium). `dead_blobs` / `purge_candidates` ignored this device's own `pending` and outbox, which only the orphan step consulted. With a `restore` stuck in the outbox on a full Drive — when `gc --purge` is run — the restored version's blob was trashed and deleted for good on day 30 and the outbox then published a head for it. **Now** (§5.9) both queries, `VaultStats.dead_blob_bytes` and therefore `sync::gc` treat blobs named by unpublished ops as referenced (`Vault::staged_blob_ids`, which `pending_blob_names` is now a view of). `sync/gc.rs` is unchanged. Across devices the publisher's check of item 1 is the backstop (§15).
3. **A device that had logged out could not log in again while its replica had a Gap/Rollback verdict, and without a login could not run `repair`** (medium). ATTACH called `refresh()` before saving the key, as §2.6 prescribed, and gave up on the verdict; `repair` needs the key. The remaining exit, `logout --forget`, deletes the index cache `repair` republishes from. **Now** (§2.6): a Gap/Rollback verdict does not stop ATTACH — nothing is published, the key is saved, the verdict is printed as a warning with the `gclone repair` advice in place of the head line, exit 0. Every other refresh error still fails the login with nothing saved.
4. **A cached segment re-applied while not listed lost its file id** (low). After a rebuild, `gather` looked the place of a cached, unlisted candidate up among the old `applied` rows only; a segment known through `base_covered`, `hw` or `own` got an empty id and the writer's clock. Presence rule (c) could then not be evaluated and list lag ended the refresh in `Rollback` (the empty `applied` id also hid the id the mark still had); the empty id went into `seen` references and snapshot tips. **Now** (§5.3 "as implemented"): the id comes from the remembered `applied` rows, the old base tips and marks (kept in `meta.remembered` across a crash), or `own` / `hw` / `base_covers`, with one `stat` for the creation time; the presence check prefers a non-empty id; an `applied` row without id adopts the listed object's.
5. **The conflict copy's path could exceed `PATH_MAX`** (low). Only the final component was clamped. For a path within about 30 bytes of 4096, `stage` refused the copy with `TooLong`; `resolve_conflicts` failed identically on every call and device, and with it `settle`, `finish_mutation` and `repair` — no mutating command could run, including the `rm` that would have removed the conflict. **Now** (§5.1): `path::conflict_name` cuts the name to fit the path limit and, where the bare infix does not fit, places the copy in the nearest ancestor with room. Deterministic as before; unchanged for every path that already produced a valid copy.
6. **Whole snapshots were re-read and decoded on every refresh and on every mutating command** (low, cost). (a) The presence check proved a mark whose segment a cleanup had trashed by loading the newest snapshot — every refresh, every device, read-only commands included — although the base's coverage is in `base_covered`. (b) `cleanup_index` had no memory: once the device's snapshot was a week old, every `finish_mutation` did a `stat`, a listing and a decode of every listed snapshot to find nothing. **Now**: §5.3 "as implemented" (rule (b) from `base_covered` when the base is listed with the recorded size and md5; new meta `base_snapshot_md5`) and §5.6 (`meta.cleanup_done`; `finish_mutation` compares with the listing its command's refresh saw and makes no call).
7. **Conflict queries scanned `heads` several times per command** (low, cost). No index covered `winner = 0`; rule 2 probed below every file. **Now** (§5.2.3, §8.4): partial index `heads_losers`; table `touched` fed by `SqlStore::insert_head` / `supersede`, bounded by `touched_bound` in `apply_and_record`, replaced by `meta.resolve_all` after `load_snapshot`; in debug builds — every test — `blocking_files` asserts that the touched paths name exactly the clashes a full scan finds. Both additions are created in an existing version-1 `state.db` at the next `Db::open`.
8. **Index objects downloaded without a size bound** — already fixed by §17.8 item 2 (`INDEX_OBJECT_MAX`, `get_bounded`, `INDEX_PARALLEL_MAX`; tests `an_oversized_index_object_is_never_buffered`, `an_oversized_descriptor_is_never_buffered`); re-checked in the code, nothing changed. The finding's further suggestion, a persistent record of rejected objects so that they are not downloaded again on every refresh, is **deferred** (§15): it must never turn a rejection caused by a damaged transfer into a permanent `Gap`, and a planted object costs the same parties less effort than trashing the journal.
9. **A read-only command that found the lock busy still opened a write transaction** (low). `open_ctx` called `Db::open` and `Vault::open` whatever `try_lock` said; `Vault::open` always ran `BEGIN IMMEDIATE` (device name; possibly the machine fingerprint or a device-id rotation — by a process without the lock). While the lock holder was inside a long transaction the command waited 5 s and failed with "database is locked"; two first opens could race on creating the schema. **Now** (§8.3): `Db::open_shared` and `Vault::open_unlocked`.

Tests added — with the nine behaviours switched back in a scratch copy of the sources, the twelve marked ▸ fail and every other test passes: `src/path.rs` ▸`conflict_name_stays_within_the_path_limit`; `src/index/resolve.rs` ▸`conflict_queries_do_not_scan_the_heads`, `rule_2_looks_at_the_touched_paths_and_their_ancestors`, `rule_2_scans_everything_after_a_rebuild_or_a_flood`; `src/state/mod.rs` `an_older_database_gets_the_later_additions`; `tests/index_props.rs` ▸`a_stale_outbox_segment_is_not_published_over_swept_blobs`, ▸`recover_outbox_checks_the_blobs_of_a_waiting_segment`, ▸`gc_spares_blobs_that_unpublished_ops_name`, ▸`a_conflict_at_a_path_near_the_length_limit_is_resolved`, ▸`snapshots_are_not_reloaded_command_after_command`, `a_reader_without_the_lock_is_not_blocked_by_a_writer`; `tests/index_adversary.rs` ▸`a_cached_segment_reapplied_while_unlisted_keeps_its_file_id`; `tests/sync_faults.rs` ▸`a_segment_that_waited_too_long_is_withdrawn_and_the_file_uploaded_again`, ▸`gc_purge_spares_the_blob_of_a_restore_that_is_stuck_in_the_outbox`; `tests/cli_e2e.rs` ▸`login_after_logout_works_while_the_index_needs_repair`, and ▸`concurrent_commands` gained the write-transaction case.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 588 passed, 3 ignored (lib 232, `auth` 31, `backend_conformance` 36, `cli_e2e` 24, `cross_package` 14, `crypto_format` 38, `drive_http` 43, `index_adversary` 15, `index_props` 62, `sync_e2e` 43, `sync_faults` 14, `transfer` 36). `worker/` was not touched.

**Observed and left as they are**: a lock-less read-only command can still wait for a writer at a later single-statement write (download ledger, `check`'s `trashed_ms` mark; §8.3); `repair --accept-loss` also applies blocked segments younger than `GAP_GRACE`; the machine fingerprint contains the inode of the index-cache directory, so recreating that directory rotates the device id; `is_missing` treats every `BackendError::Fatal` as "object absent" in presence rule (c). The last three were named by the review without evidence and were not examined here.

**Still unverified** (nothing ran against real Drive): that `files.get` on a pre-generated id that was never used answers `404` — `recover_outbox` relies on it to tell "the segment was never stored" from "it is in the store" (a wrong `present` only keeps the old behaviour for that segment; a wrong `absent` would withdraw a segment that other devices have applied, which the next refresh then meets as a foreign segment under its own id and answers with a device-id rotation, both branches applied); how long after a `files.update(trashed=true)` by another client a `files.get` of the same object still reports it un-trashed, which bounds the race named in §15.

### 17.12 Review round 4 — sync engine (2026-11-12)

Seven findings of a review of the sync engine (`src/sync/`, the download side of `src/transfer/`, `src/cli/copy.rs`), each reproduced by two verifiers against the unmodified tree; all seven were confirmed in the code and fixed. In five of them the code followed the letter of this spec and the spec is what changed. None could show in the existing tests: every exclude test used non-negated patterns and identical spellings on all sides, no test put gclone's directories under a sync root, set `--reset-pair` on an unchanged root, looked at file modes after an update, or let two devices upload the same content. `FakeDrive` and the other fakes are not involved (the engine sits above the `Backend` trait); the planner's own invariant test encoded the same blind spot as the code — it modelled the local side with `Filter::excluded` per path instead of with the walker's pruning — and now runs with negation patterns over a function that *is* the walker's rule. Sections edited: title line, §5.1, §5.4, §5.5 (pair identity), §5.5.1 (row 1, precisions), §5.5.3 (rewritten), §5.7 (order, download step 2), §7.1, §8.1, §9.9, §12.1 (WP6), §14 item 10, §15, §17.4 (known limit); README ("How `copy` and `sync` behave", "Security model", "Limitations").

1. **A sync root that contains gclone's own directories uploaded the secrets and swapped the live `state.db` on download** (medium). Nothing excluded `<config>`, `<state root>` or a directory vault's directory. With the defaults (§8.1) `copy ~ :home` uploaded `config.json`, `secrets.json`, `token.json`, `state.db` + `-wal` + `-shm`, `lock` and the index cache, exit 0, and never converged because each run rewrites `state.db`; `copy :home ~` on another device classified its live state files as "both changed" (row 7), moved the **open** database aside and renamed the other device's copy into place at 0644 — everything the run wrote afterwards went to the moved-aside inode, and the next command opened a foreign database (clone detection then rotated the device id; the base rows were gone). **Now** (§5.5.3): `SyncRequest.own_dirs`; a root at or inside one of them is `Usage` (exit 2) before anything is created; under the root they are excluded by key on all three inputs, with a note. Verified by the reviewers for a directory vault; the Drive-vault variant (another device's `secrets.json` arriving at 0644, strict loading then refusing to start) was inferred, not run — it is closed by the same exclusion.
2. **A `!` re-include under an excluded directory was hidden locally but visible remotely** (medium). `Filter::excluded` was `matched_path_or_any_parents`, which in `ignore` 0.4 tests the path first and returns a whitelist match without consulting the parents; the walker prunes the directory and never sees the child. With `build/` + `!build/keep.txt`: `sync` up → `DelRemote build/keep.txt` (row 8) while the file exists locally, never uploaded again; `sync` / `copy` down → the local file moved aside and downloaded again on every run. **Now** (§5.5.3): `excluded_at` asks the ancestors top-down, then the path — the walker's rule on every input; the re-include is without effect, as in git.
3. **Exclusion was decided per spelling while the planner joins by key** (medium). A pattern matching only the remote spelling hid the remote row and left the local twin with its base row: row 9, `DelLocal` on `sync` down (reproduced on APFS: `Cache/` against a local `cache/`), below the delete guard's thresholds without a question. **Now** (§5.5.3 "one answer per key"): `hide_excluded` removes a key from all three inputs when any of its spellings — local, remote or base, with their ancestor directories — is excluded. `sync::run` no longer uses `remote_rows(.., filter, ..)` / `filter_base`; both remain public with their per-spelling meaning. The upward half of the finding (`Skip(RemoteDeleted)`, exit 6, on every `sync` up) was not reproduced by the verifiers; it follows from the same rows and is closed by the same step.
4. **Every download recreated the file as 0644 / 0755** (low; §5.7 step 2 prescribed it). An existing 0600 file was widened to the umask default by the download of a newer version — on the device that had created it, too — while `SetLocalMeta` kept the bits. **Now**: the new file takes over the permission bits of the regular file found at the target (replaced or moved aside), x bits by `exec` as `SetLocalMeta` sets them; a new path gets 0644 / 0755 under the umask as before. The suggestion to create *new* files 0600 was not taken: the umask is the user's statement about new files, every comparable tool honours it, and a file private on one device and umask-default on another is the documented consequence of not transporting permission bits (§14 item 10, §15).
5. **`--reset-pair` was ignored when the root's identity had not changed** (low). The flag was read only inside the `RootChanged` branch; after a restore into the same directory the run deleted and overwrote per the table although the help promised that it would not. **Now** (§5.5): honoured unconditionally; `--keep-pair` with an unchanged identity stays a silent no-op. Help texts in `cli/copy.rs` reworded.
6. **A local directory that still had a remote marker was pruned with its last file** (low). `delete_locals` pruned every emptied ancestor except the directories of this run's `MkdirLocal`; a marker facing a directory with content plans nothing, so its directory was unprotected, and the next upload turned the missing directory into `DelRemote` of the marker — the empty directory then disappeared on every device although no user removed it. **Now**: `Plan.keep_dirs` (§5.5.1, §5.7 step 3).
7. **Two devices uploading equal content with different mtimes rewrote each other's metadata forever** (low; rows 1 and 3 as specified). `RecordBase` for equal content, then `SetRemoteMeta` on the next run because `L` and `R` differed, then the other device the same — one index `Put` per file per device every second run. **Now** (§5.5.1 row 1): upward only metadata that changed since the base row is pushed. Downward nothing changed (a download still aligns the local file with the remote entry). The suggested change for DOWN — act only when the remote metadata differs from what the base row recorded — was not taken: the base row does not record remote metadata, and in row 1 the remote stamp is unchanged by definition, so the rule would have ended the existing behaviour that `sync` down undoes a local `touch`.

Tests added — with the seven behaviours switched back in a scratch copy of the sources, the twelve tests marked ▸ fail and every other test passes: `src/sync/scan.rs` ▸`a_negation_under_an_ignored_directory_brings_nothing_back_on_any_side`, ▸`a_key_excluded_under_any_spelling_is_hidden_on_all_three_inputs`, `own_directories_are_excluded_by_key_on_every_side`; `src/sync/plan.rs` ▸`row_1_pushes_only_metadata_that_changed_here`, ▸`invariant_excluded_keys_yield_no_actions` (negation patterns added), `an_empty_directory_marker_faces_a_directory_with_content` (`keep_dirs`); `tests/sync_e2e.rs` ▸`a_negation_under_an_excluded_directory_deletes_and_duplicates_nothing`, ▸`an_exclude_that_matches_one_spelling_hides_the_key_on_both_sides` (acts where the file system folds case; returns early elsewhere), ▸`equal_content_with_different_mtimes_settles_between_two_uploaders`, ▸`a_download_never_widens_the_mode_of_an_existing_file`, ▸`reset_pair_is_honoured_when_the_root_is_the_same_directory`, ▸`a_directory_with_a_remote_marker_survives_the_delete_of_its_last_file`; `tests/transfer.rs` ▸`a_download_keeps_the_permission_bits_of_the_file_it_replaces`; `tests/cli_e2e.rs` ▸`gclones_own_directories_under_the_sync_root_are_not_synced`.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 600 passed, 3 ignored (lib 236, `auth` 31, `backend_conformance` 36, `cli_e2e` 25, `cross_package` 14, `crypto_format` 38, `drive_http` 43, `index_adversary` 15, `index_props` 62, `sync_e2e` 49, `sync_faults` 14, `transfer` 37). `worker/` was not touched.

**Behaviour changes a user can meet**: `--exclude 'dir/' --exclude '!dir/file'` no longer treats `dir/file` as included on the remote side (write `dir/*` + `!dir/file`); an exclude now also hides a twin that is spelled differently on the other side; `copy` / `sync` print a note and skip gclone's own directories, and refuse a root inside them; downloads keep the mode of the file they replace; `--reset-pair` always resets; an emptied directory that the remote still lists stays; a device whose file has the same content as the remote entry but another mtime no longer pushes that mtime unless it changed since the last sync.

**Still unverified / not exercised**: nothing here ran against real Drive (none of the seven depends on it) or on Linux — the case-sensitive branch of the spelling test returns early on a non-folding file system, where the NFC/NFD variant of finding 3 is covered by the unit test only. Own directories are recognised by canonical path on the local side and by key on the remote side; a file system whose folding differs from Unicode full case folding could spell a remote twin of `~/.config/gclone` in a way neither catches (the download-time backstop of §5.7 step 3 then reports a collision).

### 17.13 Review round 4 — transfer (2026-11-12)

Six findings of a review of the transfer path (`src/transfer/`, the transfer side of `src/sync/exec.rs`, the upload clients of `src/backend/drive/`), each confirmed by two verifiers against the unmodified tree. All six are real. Two were already closed when this pass started — by §17.10 (finding 1) and §17.12 (finding 4), which had reached the same defects from the Drive and the sync side — and were re-confirmed in the code and by their tests, not changed again. Four were fixed here. In two of those (5, 6) and in the already-closed 4 the code followed the letter of this spec and the spec is what changed. Why no test showed them: the fakes answer every call, at once (no call ever hung, so a wait that ignores the cancellation looked the same as one that honours it; no put ever outlasted a timeout); no test gave more than three paths the same content, removed a source between scan and upload, or answered a `get` with `RateLimited`; and the one test that opened missing and non-regular sources asserted the old classification. `Flaky` — the transfer and sync tests' fault injector — gained the missing fault (`hang`, §9.5). Sections edited: title line, §5.7 (failed vs skipped, how a run ends, download step 2, Ctrl-C), §6.2 (attempts), §6.3, §9.5, §9.8, §12.1 (WP2, WP5, WP6), §15, §17.3 (WP5 items 7 and 11, back references); README ("How `copy` and `sync` behave", "Limitations").

1. **`HTTP_READ_TIMEOUT` capped every upload request at 60 s** (reported high, both verifiers medium). This is §17.10 item 1, found a second time from the transfer side; the fix described there is in place: uploads have a client of their own without `read_timeout`, every request on it has a total timeout that grows with its body (`HTTP_READ_TIMEOUT + len / UPLOAD_MIN_RATE`), bodies leave in `UPLOAD_SLICE` pieces under a stall watch, and progress learned from a status query resets the round counter (§17.10 item 2 — the "reset `stalled`" half of the suggested fix). Re-confirmed by reading `Inner::upload_request`, `Outgoing::send` and `put_stream`, and by the tests of §17.10 (`an_upload_that_flows_steadily_may_take_longer_than_the_read_timeout` and three more), which pass. **Not taken** from the suggestion: sending each part PUT as "a few MiB" of the retained part. With the total timeout by length a 16 MiB request no longer depends on the uplink speed down to `UPLOAD_MIN_RATE`, a cut part still advances by what Drive kept, and smaller requests would add a round trip per few MiB on every link.
2. **Every target sharing one `Loc` was opened at once** (medium). `FileSink::data` created the partial file of every target of a member with the first verified chunk and kept all of them open until the member ended: N paths with one content — the planner's `Reuse` produces exactly that — needed N descriptors. With the macOS default soft limit of 256 a tree with a few hundred identical files failed in part with `EMFILE` on every run (reproduced by both verifiers: 247 of 600 succeeded), and other streams of the process could fail to open files or sockets meanwhile. **Now** (§5.7 step 2): targets are written one after another — a member up to `PACK_MEMBER_MAX` from memory once it is verified, a larger one through the partial file of one target and verified local copies of it — at most two descriptors per member. No partial file is created any more for a small member that fails verification. Accepted: a write error on the file that takes a large member's stream fails every target of that member (§15); a larger member's further targets cost a local read-and-hash of the first file instead of a second decryption pass. **Not taken**: raising the soft `RLIMIT_NOFILE` at start-up — with the bound above (2 × `transfers` groups × 2 descriptors) nothing needs it.
3. **A `RateLimited` download was an ordinary failure** (medium). `Exec::downloaded` had stop arms for `Cancelled` and `QuotaExceeded` only; a `get` that came back `RateLimited` — the pacer's ten attempts spent — marked its files failed, and the executor went on to launch every remaining blob group, each spending the same budget against an API that had said "stop", and ended `Ok(Summary)` with exit 6 (reproduced by a verifier: five further groups launched). §5.7 and §6.5 required the stop for every transfer; only the upload side had it. **Now**: `Backend(RateLimited)` from a download sets `Stop::RateLimited` — no further group is launched, what completed is committed, `Err(Backend(RateLimited))`, exit 75. Groups already running finish on their own (at most 2 × `transfers` − 1 further answers). There is no ledger rule on this side: Drive names its download quota (`downloadQuota` → `QuotaExceeded(DailyDownload)`, §6.5), unlike the 750 GB/day upload cap.
4. **A download reset the mode of the file it replaced to 0644 / 0755** (low). This is §17.12 item 4 and is fixed there (§5.7 step 2, `file_mode`); re-confirmed in `Target::commit` and by `a_download_keeps_the_permission_bits_of_the_file_it_replaces` / `a_download_never_widens_the_mode_of_an_existing_file`.
5. **A source that vanished between scan and upload was `SourceUnreadable`** (low; §17.3 item 11 as specified). Every failed open — `ENOENT`, `ELOOP`, "not a regular file" — became a failed transfer: `Summary.failed`, exit 6 and, above all, **no deletes in that run**. In a tree with temporary-file churn (an editor, a build) that is most runs. The rest of the engine already treats the same event as a change (`MkdirRemote` of a vanished directory is `Skip(ChangedDuringUpload)`, a vanished `DelLocal` target is "already gone", the scan's own hashing sets `changed_during_scan`). **Now** (§6.2): `open_failed` in `transfer/source.rs` maps "gone" (`NotFound`, `NotADirectory`), "a symlink now" (`ELOOP`) and "opened, but no regular file" (a private marker inside the `InvalidInput` error of `open_source`, whose message is unchanged) to `SourceChanged`, at classification, in `PackBuilder::add` and when `upload_single` opens a large file again; everything else stays `SourceUnreadable`. The executor needed no change. `hash_file` (scan side) keeps reporting `SourceUnreadable` — its caller treats every error alike.
6. **The first Ctrl-C was honoured by the put only** (low). `Batch::in_flight` wrapped the put; the id request before it, the `stat` of an acceptance without md5, the `stat` after a lost answer and the `trash` of a rejected object were awaited bare, and each of them can sit in the pacer's ten attempts (backoff up to 64 s) on a dead network. A verifier measured 13.75 s with a slow `new_ids` — and the put was then **started after** the cancellation and reported as uploaded. On the download side the by-name lookup and the `stat` after a short body were outside `unless_cancelled`, and zero-length files were created and `fsync`ed to the last one after the cancellation (in `download_group` and in the executor's `fetch_empties`). **Now** (§5.7): every backend wait of `upload_batch` goes through `in_flight`, whose deadline is one per batch (`CANCEL_GRACE` after the cancellation was first noticed by a call in flight — a transfer cancelled during its put does not get another five seconds for the `stat` behind it); `new_id` refuses to hand out an id once the batch has stopped, so no put starts after a cancellation or a quota answer; `Pump` wraps both remaining calls; `materialize_empties(items, cancel)` (new, additive; the executor's `fetch_empties` is gone) and `download_group` look at the token between files, and the sink looks at it between the targets of one member and between the pieces of a local copy. Accepted: an upload whose acceptance `stat` or `trash` is dropped at the deadline leaves an unreferenced object for `gc --orphans`.

Tests added — with the four fixes switched back in a scratch copy (finding 2 by keeping every target's partial file open until all were written), the eleven marked ▸ fail and every other test passes: `tests/transfer.rs` ▸`many_paths_with_one_content_do_not_exhaust_the_descriptors` (384 descriptors open against 66 before the download; with the fix the count stays flat), ▸`fifos_symlinks_and_directories_are_refused_without_blocking` (expectation changed to `SourceChanged`; a mode-000 file and a removed large file added), ▸`a_large_source_that_vanishes_before_a_new_attempt_has_changed`, ▸`a_cancelled_upload_waits_five_seconds_for_no_backend_call` (`new_ids`, the put, the `stat` after a lost answer; the `new_ids` and the `stat` case each fail without their fix), ▸`a_cancelled_download_waits_for_no_backend_call` (`find_by_name`, `stat`; each fails without its fix), ▸`zero_length_files_are_not_written_after_a_cancellation`; `tests/sync_faults.rs` ▸`a_rate_limited_download_stops_the_run_and_keeps_finished_files`, ▸`a_source_that_vanished_after_the_scan_is_skipped_and_deletes_go_ahead`; `src/transfer/source.rs` ▸`a_source_that_is_gone_or_replaced_has_changed_and_one_that_is_locked_is_unreadable`; `src/transfer/pack.rs` ▸`failures_leave_the_builder_unchanged` (expectation changed); `src/transfer/upload.rs` ▸`an_id_that_arrives_after_the_cancellation_starts_no_put`. Not part of the switch-back: `src/transfer/download.rs` `a_small_member_opens_no_file_before_it_is_verified_and_then_one_at_a_time`, `a_large_member_streams_into_one_file_and_is_copied_from_it`, `a_copy_is_verified_and_a_failed_write_fails_the_member`, `a_cancellation_is_seen_between_the_targets_of_one_member` — they count the sink's open partial files after every chunk and so pin the new structure rather than detect the old one; and `tests/backend_conformance.rs` `flaky_hang_never_answers_until_cleared`. The cancel tests run under paused time: the five seconds are exact and cost nothing.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 614 passed, 3 ignored (lib 242, `auth` 31, `backend_conformance` 37, `cli_e2e` 25, `cross_package` 14, `crypto_format` 38, `drive_http` 43, `index_adversary` 15, `index_props` 62, `sync_e2e` 49, `sync_faults` 16, `transfer` 42). `worker/` was not touched.

**Behaviour changes a user can meet**: a tree with hundreds of identical files downloads completely; a restore that Drive throttles beyond gclone's own retries stops with exit 75 instead of grinding through every remaining file and ending with 6; a file that disappears (or turns into a directory, symlink or FIFO) while a run is in progress is reported as `changed while it was uploaded` and no longer holds back the deletes of that run; the first Ctrl-C ends an upload batch within five seconds also when the network is gone, and stops creating empty files.

**Still unverified / not done**: nothing here ran against real Drive (findings 2, 5 and 6 do not depend on it; for 3 the classification of a throttled `alt=media` request as `RateLimited` rests on §6.5 and `FakeDrive`). Not run on Linux: `ELOOP` for `O_NOFOLLOW` and `/dev/fd` are the same there, FreeBSD's `EMLINK` is not mapped. The cancellation rule covers the transfer layer only: `Vault::data_folder()` before an upload slice, the commits after a cancellation and every other index-level call still run through the pacer's attempts on a dead network — the second Ctrl-C (§5.7) remains the way out, and staged ops stay durable. The batch deadline is set when a call in flight notices the cancellation; a call that starts in the instant between two calls of one transfer gets up to five seconds from its own start. The descriptor test detects the old behaviour by sampling `/dev/fd` from a second thread (the soft limit of the test machine was 1,048,576, so `EMFILE` itself could not occur); it allows 200 descriptors of noise from the tests running beside it.

### 17.14 Review round 4 — command line and setup (2026-11-12)

Ten findings of a review of what a user meets at the terminal (`src/cli/`, the messages of `src/sync/`, `worker/setup.sh`, both READMEs), each checked by two verifiers against the tree as it was before round 4. All ten are real. One was closed when this pass started and one half-closed — by §17.12 (finding 1) and §17.7 item 5 (the Authorized-domain half of finding 6) — and were re-confirmed in the code and by their tests, not changed again. In six of them the code followed the letter of this spec, and the spec is what changed: several were not bugs against a rule but rules that did not survive contact with a user (a "limit" that a flag lifts, a "restorable" that cannot be used, a success for a path that does not exist). None could show in the existing tests: no test combined `--max-delete` with `--yes`, restored a directory, moved onto something that exists except to assert the replacement, downloaded from a path that is not there, or read an error message for the flag it should name. The fakes are not involved (everything here sits above the `Backend` trait and outside the Worker's request path). Sections edited: title line, §2.1, §2.8, §5.5.1 (precisions), §5.5.2 (G2, G4, the texts), §5.5.4 (rewritten), §5.9, §7.1, §7.2, §9.3, §9.7, §9.9, §10, §12.1 (WP6, WP7, WP8), §14 item 7, §16.1, §16.6, §17.4 item 7, §17.5 (the `--json` decision); README ("Install", "One-time setup", "Everyday commands", "Limitations", "Exit codes"); `worker/README.md` ("One-time setup", "Operating it", "Custom domain and rate-limiting rule").

1. **A sync root that contains gclone's own directories** (reported high, both verifiers medium). This is §17.12 item 1: `SyncRequest.own_dirs`, excluded by key on all three inputs with a note, a root inside one of them refused. Re-confirmed in `sync::run` / `Filter::with_own_dirs` and by `gclones_own_directories_under_the_sync_root_are_not_synced`, which passes.
2. **"Restorable for 25 days" could not be used for a directory** (medium). `restore` took one exact file path; nothing listed removed paths; after `rm -r :md` — which printed "restorable … gclone restore" — `restore --list :md` answered "No restorable version of :md" and `restore :md` failed. The same after a `sync` that deleted many files. **Now** (§5.5.4): `Vault::removed_under`, `remote_ops::restorable_under` / `restore_many`; `restore --list :DIR` lists the restorable files under a directory (`:` = the vault), `restore -r :DIR` brings back every deleted file under it in one segment, several paths are accepted, and `rm` / `sync` print the command. A directory without `-r` is a usage error that names `-r`. Not taken: `restore :DIR` restoring without `-r` (the flag mirrors `rm -r`, and a mistyped file path must not restore a tree), and a directory restore "as of" a time (§14).
3. **`--max-delete N` was not a limit** (reported medium, both verifiers low — §5.5.2 specified it as a second way to answer the guard). `--yes` lifted it and a terminal merely asked, so in the one place a cap matters — an unattended `sync --yes --max-delete N`, local unlinks included — it had no effect, under a help text that read "Refuse to delete more than N entries". **Now**: `GuardKind::MaxDelete`, never confirmable; the default thresholds keep `DeleteLimit`, the question and `--yes`. The dry-run warning names the right flag for each.
4. **`mv` merged into an existing directory and replaced files silently** (reported medium, both verifiers low — §5.5.4 specified `b‖suffix` with the target's winner as base). `mv :Photos/old :Archive` mixed `old`'s files into `:Archive`; a same-named file there, or a file moved onto a file, was superseded without a word; a file moved onto an empty directory replaced the directory. **Now** (§5.5.4): the shell's rule for the destination (into an existing directory), nothing existing replaced or merged into without `--force`, a count of what `--force` replaced, file ↔ directory never. `remote_ops::mv` gained `force` and returns `Moved`.
5. **A download or a check from a remote path that does not exist succeeded** (reported medium, both verifiers low — §5.5.1 called a missing prefix "fine" for both directions). `copy :Documnets ~/restore` created an empty directory and exited 0; `check --download :no/such` printed "Checked 0 files: all good." **Now** (§5.5.1, §5.9): `Io(NotFound)`, exit 1, before anything is created — except for a pair with base rows, where the removal is carried out. The verifier's correction stands: `check LOCAL :P` already failed whenever the local tree was not empty; it now fails with the right reason in every case.
6. **Custom-domain setup** (reported medium, both verifiers low). The Authorized-domain line was fixed in §17.7 item 5 (re-confirmed: `setup.sh` prints the registrable domain with a note; `scripts/setup.selftest.mjs`). The other half — `setup.sh` could only set up the `workers.dev` host, so a user whose goal is a custom domain configured Google twice and signed in on every device twice, and the examples baked the `workers.dev` URL in — was judged an enhancement by both verifiers and is done here because it is cheap and removes exactly that double work: `setup.sh` asks first, `scripts/custom-domain.mjs` writes the `routes` entry before the first deploy, and both READMEs describe "custom domain from the start" and use the custom URL in the `GCLONE_DEFAULT_AUTH_URL` example (§2.1, §16.1).
7. **`sync` exits 6 forever on destination-only entries, and nothing said why or what to do** (reported medium, both verifiers low; the behaviour is rows 4-DOWN / 5-UP as specified and stays). **Now** the texts carry it: the two skip reasons name the remedy, one `hint:` line gives the count and the exact `gclone copy` command and says that `--force` does not delete such entries, the help of `sync` and of `--force` says in user terms what each does and does not do (the old `--force` help cited "§5.5.1" and "G2/G3"), and the README has a paragraph for the two-device case. Not taken: an opt-in `--delete-unseen` — deleting what this device never saw is the one thing the planner promises never to do.
8. **Guard errors off a terminal did not say how to proceed** (low). `explain_guard` (§5.5.2); the lock message says that nothing was changed and how to find the other process; `--keep-pair` / `--reset-pair` are in the README.
9. **The documented rate-limiting rule did not stop the flood it was documented for** (low). It matched four paths while every other path of the host invokes the Worker too, and its example threshold admitted more requests a day from one address than the quota holds. **Now** (§16.6, `worker/README.md` step 5): all paths of the host, 5 per 10 s, the plan-dependent expression, and the plain statement that a per-address rule bounds each sender and not the total. The suggested `Cache-Control` on `/` and `/privacy` was **not** taken: a Worker on a custom domain runs in front of the cache and is invoked regardless (the verifier's objection).
10. **Output modes** (low). (a) `--json` with a command that does not implement it printed nothing and exited 0 → refused, exit 2, and the flag's help says "copy and sync only" (§7.1; the open decision of §17.5). (b) `-q` hid the skip lines of a run that exits 6 because of them → the first ten reasons go to stderr. (c) "Run `gclone login <AUTH_URL>`" in a build or environment that needs no argument → "Run `gclone login`". (d) A dry run that only creates directories printed `+ mkdir` and then "Nothing to do" → `Summary.dirs_created`. (e) A file as the source said only "is not a directory" → the explanation and `gclone cat`; `copy --help` / `sync --help` now state the directory and contents-into-DST semantics. Of the three smaller items the reviewer listed without numbering: an empty string as the local argument is a usage error; `mkdir` of an existing directory says "exists already". **Not done**: `gclone login` on a signed-in device starting a full browser sign-in when the Worker is only temporarily unreachable — it belongs to the login flow of §2.6 step A and was not verified by the reviewers.

Tests added — see §12.1 for what each asserts. `tests/sync_e2e.rs`: `mv_moves_into_an_existing_directory_and_replaces_nothing_unasked`, `a_removed_directory_is_listed_and_restored_in_one_segment`, `reading_from_a_remote_path_that_does_not_exist_is_an_error`; changed: `the_delete_guard_needs_yes_without_a_terminal` (the hard limit, the dry run), `mkdir_rm_mv_are_index_only` (file onto file needs `force`; refusals commit nothing). `tests/cli_e2e.rs`: `restore_mv_and_missing_paths_at_the_command_line`, `guards_and_skips_name_the_way_out`. `src/sync/plan.rs`: `g4_delete_guard` (expects `MaxDelete`). `src/cli/copy.rs`: `every_guard_names_the_way_out`, `summary_lines_follow_the_examples` (directories). `src/cli/mod.rs`: `not_connected_names_a_command_that_works`, `json_is_offered_where_it_is_implemented`. `worker/scripts/custom-domain.selftest.mjs` (6 tests), `worker/scripts/setup.selftest.mjs` (1 added). Call sites of the changed `remote_ops::mv` signature were adapted in `tests/cross_package.rs`, `tests/sync_faults.rs` and `src/util.rs`.

Switch-back check, in scratch copies: with every source file of this pass put back to its earlier state, the two new `tests/cli_e2e.rs` tests fail and the other 25 pass; with three behaviours switched back by hand under the new signatures (`check_guards` returning `DeleteLimit` for an explicit limit, the missing-remote checks of `sync::run` and `sync::check` removed, `mv` always renaming and always replacing), `g4_delete_guard`, `the_delete_guard_needs_yes_without_a_terminal`, `mkdir_rm_mv_are_index_only`, `mv_moves_into_an_existing_directory_and_replaces_nothing_unasked` and `reading_from_a_remote_path_that_does_not_exist_is_an_error` fail and the other 48 tests of `tests/sync_e2e.rs` pass. `a_removed_directory_is_listed_and_restored_in_one_segment` exercises functions that did not exist before and cannot be switched back.

State: `cargo fmt`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` pass — 622 passed, 3 ignored (lib 245, `auth` 31, `backend_conformance` 37, `cli_e2e` 27, `cross_package` 14, `crypto_format` 38, `drive_http` 43, `index_adversary` 15, `index_props` 62, `sync_e2e` 52, `sync_faults` 16, `transfer` 42). In `worker/`: `npm run typecheck` and `npm test` pass — configuration check, 19 `node --test` tests in 3 files, 162 Vitest tests in 5 files; `npx wrangler deploy --dry-run` builds a copy of the directory after `node scripts/custom-domain.mjs gclone.example.org`. No file under `worker/src` or `worker/test` was touched, and the shipped `wrangler.jsonc` is unchanged.

**Behaviour changes a user can meet**: `sync … --max-delete N --yes` now refuses above N; `gclone mv :a :dir` puts `a` *into* an existing `:dir` and no longer merges, and `mv` onto an existing file needs `--force`; `copy` / `sync` from, and `check` of, a remote path that does not exist exit 1; `--json` with any command but `copy` / `sync` exits 2 instead of printing nothing; `restore` takes several paths and `-r`; the wording of the two destination-only skip reasons, of every guard refusal, of the `rm` result line and of the lock message changed (scripts that match on them: `refusing to delete d of n files`, `not the directory last synced with`, `another gclone is running on this vault` are still substrings); `sync` prints a `hint:` / `note:` line on stderr in the cases above.

**Still unverified / not exercised**: nothing here ran against real Drive, Google's console or Cloudflare. In particular: that `wrangler deploy` with the `routes` entry written by `custom-domain.mjs` creates the DNS record and certificate for a zone in the account (`npx wrangler deploy --dry-run` accepts the file; the real deploy was not run), how long a new custom host takes to answer (`setup.sh` waits five minutes), and the plan table of Cloudflare's rate-limiting rules, which is taken from its documentation and changes. `restorable_under` asks the backend once per blob; on a vault with very many large removed files a `restore --list :` is as many `stat` calls.

### 17.15 Download durability in batches (2026-11-12)

*Reviewed in §17.16, which corrects items 3 and 4 below, replaces the reopening content barrier by a sync through the writing descriptors, and extends invariant I2 to every writer of base state. The text below is kept as written, with pointers where it was wrong.*

**Why.** Every downloaded file was flushed on its own before its rename (`File::sync_all`, which is `F_FULLFSYNC` on macOS — a flush of the drive's write cache, ≈ 4 ms whatever the file's size), and each zero-length file twice. 10,000 small files took 43 s to restore against 0.7 s to upload; 2,000 empty files 18 s.

**What changed** (§5.7 steps 2, 3 and the new 3a, §6.1, §9.2, §9.8, §12.1 edited in place). A written file is *staged* — verified, mtime and mode set, closed — and finished with its **batch**: content barrier → renames (re-stat rules unchanged) → rename barrier → outcomes released → base rows. A batch closes at `DOWNLOAD_BATCH_FILES` = 512 files, `DOWNLOAD_BATCH_BYTES` = 16 MiB, when a file arrives `DOWNLOAD_BATCH_AGE` = 1 s after its first one, and at the end of its blob group. New module `src/transfer/durable.rs` (crate-private): `make_durable(paths)`. `download_group` carries one batch across the coalesced requests of its blob; zero-length files go through the same code (`materialize_empties`; `materialize_empty` is that function for one item — both signatures unchanged), and the executor hands them over in slices of `DOWNLOAD_BATCH_FILES`, one slice at a time beside the blob groups (the blob groups keep `2 × transfers` streams to themselves). `Exec::downloaded` is unchanged: it was and is the only writer of download base rows, and an `Ok` reaches it only out of those two functions.

**The durability claim and its evidence.**
1. *What one `F_FULLFSYNC` covers.* `fcntl(2)` of the macOS SDK on the development machine (macOS 27.2, `MacOSX.sdk/usr/share/man/man2/fcntl.2`): "F_FULLFSYNC Does the same thing as fsync(2) then asks the drive to flush all buffered data to the permanent storage device (arg is ignored). As this drains the entire queue of the device and acts as a barrier, data that had been fsync'd on the same device before is guaranteed to be persisted when this call returns." `fsync(2)`, same SDK: "fsync() will flush all data from the host to the drive (i.e. the 'permanent storage device'), the drive itself may not physically write the data to the platters for quite some time and it may be written in an out-of-order sequence." So one `F_FULLFSYNC` makes durable what **was `fsync`ed** on that device — it promises nothing for other files' dirty pages that never left the page cache. Hence: plain `fsync(2)` on every file (and every directory), then one `F_FULLFSYNC` per `st_dev`. The same reading is given by an Apple DTS engineer in the developer forums ("`fsync()` → tell the filesystem to flush its own buffer out to disk; `F_FULLFSYNC` → tell the underlying device to flush its own cache", thread 849633). Measured here: `fsync(2)` ≈ 6 µs per small file, `F_FULLFSYNC` ≈ 4 ms.
2. *Why two barriers and not one.* The design first proposed — write and rename without any flush, one barrier before the base rows — keeps invariant I2 but gives up I1, which the per-file flush used to provide: between a rename and that barrier a power loss could leave an empty or partial file at a target. With no base row (a new file) or the previous version's row (a replaced file) the next upload plans it as a local change — row 2 or row 7 of §5.5.1 — and publishes it, the good remote version surviving at best as a conflict copy. The content barrier before the renames closes that; it costs one more flush per batch, not per file.
3. *Why the ancestors.* The transfer layer creates missing directories. Before, only the directory of the rename was flushed; a base row whose file sits in a directory that is itself not durable would be read as a local delete after a power loss (row 8). Journaled and copy-on-write file systems commit such changes in order in practice; the rename barrier now names the chain up to the sync root instead of relying on that. Not covered, as before: the entry of the sync root in *its* parent when this run created the root (the `RootChanged` / `EmptySource` guards of §5.5.2 stand behind that case), and `MkdirLocal` directories, which hold no content. *(Wrong for a directory that stays empty — §17.16 finding 4: `MkdirLocal` rows now wait for a barrier. The root's own entry stays uncovered.)*
4. *Linux.* Every path still gets its own `fsync(2)`: the guarantee is exactly the old one. The `syncfs(2)` in front is an accelerator whose result is ignored (no write-error reporting before Linux 5.8; not forwarded by FUSE), so no claim rests on it. *(Not the old guarantee — §17.16 finding 2: that `fsync` went through a descriptor opened after the writes, and the answers of `close` and `syncfs` were dropped. Fixed there.)*
5. *`state.db`.* SQLite's `synchronous=FULL` issues plain `fsync` on macOS (no `PRAGMA fullfsync`), so a base row can become durable *later* than its file — the harmless direction (rows 5 and 6). It cannot become durable earlier: `base_put` is called after the rename barrier returned. *(True of the rows of downloads only; the other writers of base rows: §17.16 findings 1, 3 and 4.)*

**Measured** (release build, this Mac's internal APFS SSD, `--vault-dir` vault, upload on device 1, download into a fresh directory on device 2 with its own `GCLONE_CONFIG_DIR` / `GCLONE_STATE_DIR`, `diff -r` identical and no partial file left in every run; the download time includes the re-observation wait of step 5, ≈ 2.0 s, which is unchanged):

| tree | upload | download before | download after |
|---|---|---|---|
| 10,000 files of 200–4,000 bytes in 100 directories (20 MiB) | 0.7 s | 42.7 s, 44.4 s (two runs) | 3.3 s, 3.2 s |
| 400 files of 200–400 KiB (114 MiB, packed) | 0.4 s | 3.4 s | 2.2 s |
| 24 files of 3–6 MiB (104 MiB, one blob each) | 0.3 s | 2.3 s | 2.3 s |
| 2,000 zero-length files | 0.15 s | 17.9 s | 2.3 s |

A sample of the 10,000-file download shows where the remaining 1.3 s go: `rename` and `open` (the file system's own work per file), ≈ 0.1 s in `F_FULLFSYNC` (some 40 flushes instead of 20,000), next to nothing in `fsync(2)`. On Linux nothing was measured on real hardware; in a container on this machine (Linux 7.2, btrfs on a virtual disk — indicative only) 2,000 small files took 1.2–1.7 s with a flush per file, 0.8–0.9 s with `fsync`-only batches and 0.07–0.08 s with `syncfs` + `fsync` batches.

**Decisions.**
- *The re-observation wait stays* (§5.7 step 5; it is now most of a small download). Two ways to remove it were looked at and neither is taken here. (a) Record downloaded rows as "fresh" and let the *next* run re-observe them (signature unchanged and ≥ `RACY_WINDOW` old → refresh the row without hashing). This is exactly as sound as the end-of-run pass — both conclude "unchanged" from an equal signature seen at least `RACY_WINDOW` after the file's ctime — but it needs a column in `base`, planner and scan changes, and it gives up the acceptance property that a sync run *immediately* after a download hashes nothing (§12.1); it is a change of its own. (b) A shorter window where timestamps are fine-grained (APFS): the window is a property of the file system's timestamp granularity, which gclone has no reliable way to establish per mount; not clearly sound.
- *`syncfs` alone as the Linux barrier* was rejected for the reasons in item 4.
- *Outcomes still reach the executor per blob group*, not per batch: a group's base rows are written when `download_group` returns. The batch bounds what a barrier covers and what sits in partial files; what a crash costs is the re-hashing of the groups in flight (their finished files are in place and are recorded by content, row 6), as before.
- *The barrier follows symlinks* when it opens a path (a root may be handed to the transfer layer through one, as before); the lstat walk of step 1 is what keeps targets inside the root.
- *Mode of a replaced file*: the permission bits of the file at the target are read when the partial file is staged, a batch (not one flush) before the rename. A `chmod` on the target in between changes its ctime, so the re-stat finds a file the plan did not expect and moves it aside — as it did in the shorter window before.

**Tests.** New: `src/transfer/durable.rs` (3), `src/transfer/download.rs` (6: `nothing_is_reported_before_the_content_and_the_renames_are_durable`, `the_content_barrier_sees_the_finished_partial_files`, `a_file_that_takes_over_an_unreadable_mode_is_flushed_on_its_own`, `a_failed_barrier_fails_every_file_behind_it`, `a_batch_is_closed_by_count_and_by_bytes`, `empty_files_wait_for_their_barriers_too`), `src/sync/exec.rs` (2: `base_rows_are_written_only_behind_the_barriers`, `a_failed_barrier_leaves_no_base_row`) — what each asserts: §12.1. The four sink tests of §17.13 are unchanged except that they end with `batch.finish()` where they called `sync_dirs()`. Switch-back check in scratch copies: without the content barrier 6 of the new tests fail; with outcomes released regardless of the rename barrier 3 fail; without the count bound 1 fails; the unmodified copy passes. The Linux branch was compiled and its tests run in a container (rustc 1.99.1, Linux 7.2 aarch64): the unit tests of `transfer` and `sync::exec` and the suites `transfer`, `sync_faults` and `cross_package` pass there. (Two tests outside this change fail in that container and were left alone: `cli_e2e::an_interrupted_attach_leaves_the_device_unconnected` relies on `chmod 555` stopping the process, which it does not for root; `sync_e2e::a_new_file_takes_the_remote_directory_spelling_on_a_folding_file_system` expects two uploads in its branch for a case-sensitive file system, where the second file is a `Reuse`.)

A download killed with `kill -9` after 0.45 s of the 10,000-file restore left 4,563 files in place and 326 partial files; the next `copy` fetched the 5,437 missing files, recorded the others by content, reported no conflict, and an upload dry run from that directory planned nothing.

**Behaviour changes a user can meet**: restores of many small or empty files are an order of magnitude faster on macOS; while a download runs, finished files appear in bursts (a batch at a time) instead of one by one, and up to 16 MiB per download stream wait in `.gclone-partial-*` files; a process killed hard loses the files of its open batches (they are fetched again; partial files are swept after a day, §5.4), where it used to lose at most the file being written; after Ctrl-C the files already written are still finished. The directories from a downloaded file up to the sync root must be readable by the user, or the batch behind them fails (before: only the directory of the rename) — the scan already skips everything below a directory it cannot read (§5.4), so no download is planned into one.

**Still unverified / not exercised**: no power was cut — the ordering is asserted through the hook, the guarantees themselves are the documented ones of `fsync(2)` / `F_FULLFSYNC` / `fsync` on Linux; drives that ignore a flush request ("certain FireWire drives", `fcntl(2)`) defeat this design as they defeated the old one; the speed on Linux ext4 / XFS on real hardware (each `fsync` after the `syncfs` still issues a cache flush there); a batch that spans two devices (`st_dev`) is handled by construction and not tested; a real failing `fsync`.

### 17.16 Review of §17.15: a barrier for every writer of base state, and the sync through the writing descriptor (2026-11-12)

A review of §17.15 reported six issues. Each was checked against the code: four are defects (two of them older than §17.15, which only made them visible by stating I2 as an invariant), one is a regression of §17.15, one concerns its report only. §5.4, §5.7 steps 2, 3a, the new 3b and 4, §6.1, §9.2 and §12.1 are edited in place; §17.15 keeps its text, with a pointer here where it was wrong.

**Findings and fixes.**
1. **`RecordBase` rows were written with no barrier** (medium; older than §17.15). `Exec::run` wrote them straight from the plan. `RecordBase` is how a file gets its row that an earlier run renamed into place and could not report — after a failed rename barrier, or when the process was killed between the rename and the barrier (up to a batch per stream) — so exactly the files whose rename is *not* known to be durable were recorded without one. A second fault then leaves a row for the new version over the old file (the next upload publishes the old content over the newer remote version, row 2) or over no file (`sync` deletes it in the vault, row 8). *Fix*: `Exec::record_bases` — §5.7 step 3b: the file and its directories up to the root are made durable first, in slices of `RECORD_SLICE`; a row that only refreshes its predecessor is exempt (decision below).
2. **On Linux the content barrier was weaker than the per-file flush it replaced** (medium; introduced by §17.15, whose item 4 claimed "exactly the old one"). The partial file was closed without `fsync` and the result of `close` dropped; `syncfs` then forced the write-back while no descriptor was open on the files, and its result was dropped too; only then each file was opened again read-only and `fsync`ed. `fsync(2)` promises a write-back error to the descriptors that wrote the data or were open when it happened — not to one opened afterwards — so an `EIO` (or `ENOSPC` / `EDQUOT` on NFS) could go unseen: the file renamed, reported, recorded and later trusted. (In practice kernels from 4.13 on hand an unreported error to the next opener; the exposure was older kernels, NFS clients that track errors per open file, and inodes evicted in between. No failing `fsync` was produced; this rests on the man pages and the code.) *Fix*: a written file is never opened again. `durable::hand_over` syncs it through the descriptor it was written with and closes that descriptor with `close(2)` checked; on Linux up to `DOWNLOAD_OPEN_FILES` files stay open for one `syncfs` in front of their `fsync`s, and an error of `syncfs` is the error of the group. That is the old guarantee, and literally so: `fsync` through the writing descriptor before the rename.
3. **`SetLocalMeta` rows were written with no barrier** (low; older). If the row survives a power loss and the `utimes` / `chmod` does not — `state.db` on another file system, or a file system whose `fsync` logs only the synced inode — the next upload takes the old mtime or exec bit for a change made here and pushes it (`SetRemoteMeta`, row 1), undoing the other device's change. *Fix*: the files are made durable before their rows (step 3b).
4. **`MkdirLocal` rows, and the forgetting of rows after `DelLocal`, had no barrier** (low; older; §17.15 item 3 named only the first and called it harmless — it is not: for a directory that stays empty no later rename barrier covers it, and its row then reads as a local delete, row 8). A forgotten row over an `unlink` that is undone leaves a file without a row, which the next upload publishes although it was deleted in the vault (row 4). *Fix*: both wait for a barrier (step 3b) — the created directory's chain up to the root; the directory of the removal.
5. **The report of §17.15 miscounted its tests** (low; no code): it said 12 new tests, 7 of them in `download.rs`. There were 11, 6 in `download.rs` — as §17.15 itself lists them (comparison of the test names with the copy from before that change).
6. **The stale-partial sweep judged age by mtime, and the content barrier was all-or-nothing** (low; the sweep is older, §17.15 widened what it costs). A staged file carries the mtime of the file it will be, so a scan by another gclone identity over the same tree (a second vault or configuration directory; the same vault is excluded by the state lock) removed staged files at once, and the content barrier, which opened the partial files by name, then failed the whole batch — up to 512 files, each with `No such file or directory`. *Fix*: (a) `scan`: a partial file is stale `PARTIAL_STALE` after the **newer of mtime and ctime** (§5.4) — the ctime of a file a download works on is always "now"; (b) the content barrier no longer opens anything (finding 2), so a partial file that vanishes fails its own rename and nothing else; (c) errors are attributed: `make_durable` returns the paths that failed alone, and a directory that cannot be synced fails the files in and below it instead of the batch.

**What changed in the code.** `src/transfer/durable.rs`: `hand_over(files, &mut Drives) -> io::Result<Vec<(usize, io::Error)>>` and `Drives::flush(written)` for files this process wrote; `make_durable(paths) -> io::Result<Vec<(usize, io::Error)>>` for directories and files that were already there (`Err` = the barrier, the list = single paths); `syncfs` only where more than one path is synced, its error returned (only `ENOSYS` ignored); `close(2)` checked (`EINTR`: the descriptor is gone all the same and is never closed twice; what there was to say about the data `fsync` had said); a second test hook, `hook::observe_files`. `src/transfer/download.rs`: `Target::stage` returns the staged name **and** the open file; `Batch` hands files over (`max_open`, process-wide `HELD` ≤ `DOWNLOAD_OPEN_TOTAL`), keeps one descriptor per device in `durable::Drives` for the flush, fails single files; the exception for files without owner-read is gone with the second open. `src/sync/exec.rs`: `settle(needs)` — the barrier in front of rows, each path synced once — with `chain` (what a row rests on) and `removed_from`; `record_bases`; `mkdir_locals`, `set_local_metas` and `remove_locals` call `settle` before their rows are written or forgotten. `src/sync/scan.rs`: `partial_is_stale`, `sweep_partial`. `src/consts.rs`: `DOWNLOAD_OPEN_FILES`, `DOWNLOAD_OPEN_TOTAL`. No public signature changed.

**Decisions.**
- *A refreshing row needs no barrier.* A `RecordBase` row with the key, kind, content hash and remote stamp of the row it replaces differs from it in the signature and the observation time only. Whatever a power loss does to the file, the new row leads the next run to nothing the old row would not have led to — except that a file whose signature survived and whose content did not is trusted instead of uploaded, which is the safer side. So `touch`-ing a tree, or re-hashing the untrusted rows of an interrupted download, costs no flush per file. `Exec::record_bases` reads the pair's rows once to tell the two apart; the plan's action type is unchanged.
- *Linux: descriptors are held, not files synced one by one.* Syncing each file as it is staged would also be the old guarantee, at the old price — a journal commit per file. Holding up to 32 writing descriptors per batch keeps one `syncfs` (one commit) per 32 files and still syncs every file through its writer. The bound is per batch and per process (`DOWNLOAD_OPEN_TOTAL` = 256; a batch that finds the process at its bound hands over at once): with `--transfers 64` there are 129 batches, and the soft descriptor limit is 1024 on most Linux systems. On macOS nothing is held (`DOWNLOAD_OPEN_FILES` = 1): plain `fsync` costs microseconds whenever it is called, and one descriptor per batch and device stays open for the `F_FULLFSYNC`.
- *An error of `syncfs` fails its group although it may be another file's.* Since Linux 5.8 it reports any inode of the file system that could not be written back. A restore next to a failing writer then fails files it wrote correctly; they are fetched again by the next run. The other way round — ignoring it — is finding 2.
- *A failed barrier is a failure, not a skip*: `Summary.failed`, exit 6, deletes suppressed. Nothing is undone — the file stays in place, the directory stays created, the entry stays removed — only the row is not written (or not forgotten), and the next run decides from what it finds: a file in place is recorded by content, a created directory gets its row, a row whose entry is gone is forgotten.
- *What a removal rests on* is the directory it happened in; if a later step of the same phase removed that directory too, the nearest one above it that is left (down to the root) — the removal of the directory is then the change that carries it.
- *Not covered*, now stated in §5.7 step 3b and in `README.md`: rows of the **upload** side (a source file is the user's; gclone does not sync it, and a file that a power loss takes back after its upload reads as deleted here), `ForgetBase`, the root's own entry in its parent, and — for files gclone did not write — whatever the kernel no longer reports to a descriptor opened for the `fsync`. *Mixed versions*: a gclone built before this section that scans the tree still sweeps by mtime; a restore by this version then loses the swept files one by one, not by the batch (measured below).

**Measured** (release build, this Mac's internal APFS SSD, `--vault-dir` vault, the trees and the method of §17.15; `diff -r` identical and no partial file left in every run; download times include the ≈ 2.0 s re-observation wait):

| what | before §17.15 | §17.15 | now |
|---|---|---|---|
| 10,000 files of 200–4,000 bytes in 100 directories: download | 42.7 s, 44.4 s (§17.15); 47.0 s (again today) | 3.42 s, 3.36 s (again today) | 3.22 s, 3.32 s, 3.29 s, 3.36 s, 3.36 s |
| the same tree already in place on device 2, first run (10,000 rows recorded by content) | — | 0.17 s, 0.17 s | 0.30 s, 0.30 s |
| that restore while a second identity scans the destination in a loop (files with mtime 2020) | 8,334 of 10,300 arrive (review) | 0 of 10,000 arrive | 10,000 of 10,000 arrive; with a scanner of the §17.15 build: 432 arrive, 9,568 fail one by one |

The download is as fast as it was (the differences are within the noise of the runs): no partial file is opened a second time, which pays for the `fstat` each file now gets. The barrier of the recorded rows costs ≈ 13 µs per file (open, `fsync`, close) plus one `F_FULLFSYNC` per 4,096 rows. A restore killed with `kill -9` after 0.45 s and after 0.7 s (4,563 and 6,611 files in place, 14 and 506 partial files): the next `copy` fetched exactly the missing files, recorded the others by content behind their barrier, reported no conflict and no failure, and an upload dry run from the directory planned nothing.

**Linux** (a container on this machine: rustc 1.99.1, Linux 7.2 aarch64, overlayfs on a virtual disk — indicative only; a flush is cheap there). The crate builds without a warning. All 269 unit tests pass — the new ones included, with `DOWNLOAD_OPEN_FILES` = 32 and the `syncfs` in front of each group — and so do the suites `transfer` (42), `sync_faults` (16), `cross_package` (14) and the rest, except four tests that fail there for reasons outside this change: the two named in §17.15, and two `auth` contract tests that read `worker/test/contract.json`, which was not copied into the container. A restore of 10,000 small files took 3.35–3.39 s there (a build from before §17.15: 6.5 s), one of 2,000 files 2.3 s (3.5 s), the 2.0 s wait included: holding the descriptors keeps what §17.15 gained on Linux.

**Tests.** 12 new, 3 renamed with their assertion changed; 647 pass in all (was 635), 3 ignored as before. `src/transfer/durable.rs` (5; new: `written_files_are_synced_through_their_own_descriptors_and_closed`, `a_refused_content_barrier_is_an_error_and_closes_what_was_kept`; `a_path_that_cannot_be_synced_fails_the_barrier` became `…_fails_alone`). `src/transfer/download.rs` (new: `every_file_is_synced_through_the_descriptor_it_was_written_with`, `a_staged_file_is_not_swept_and_a_vanished_one_fails_alone`, `a_directory_that_cannot_be_synced_fails_the_files_below_it`; `a_file_that_takes_over_an_unreadable_mode_is_flushed_on_its_own` became `…_like_any_other`; `a_batch_is_closed_by_count_and_by_bytes` also bounds the open descriptors). `src/sync/exec.rs` (new: `a_row_rests_on_the_entry_and_on_the_directories_above_it`, `a_row_recorded_by_content_waits_for_its_barrier`, `a_refreshed_row_needs_no_barrier`, `a_row_over_a_new_mtime_waits_for_its_barrier`, `a_row_for_a_created_directory_waits_for_its_barrier`, `a_row_is_forgotten_behind_the_barrier_of_the_removal`). `src/sync/scan.rs` (new: `a_partial_file_is_stale_a_day_after_the_last_thing_done_to_it`; `reserved_names_are_invisible_and_stale_partials_are_removed` became `…_and_a_partial_file_in_use_is_left_alone`). What each asserts: §12.1.
Switch-back check in a scratch copy, the unit tests of `sync::exec`, `sync::scan` and `transfer` (51): staleness by mtime alone → 3 fail (both scan tests, the staged-file test); `RecordBase` without its barrier → 1 fails; the three other writers without theirs → their 3 tests fail; the content synced through a descriptor opened after the writes → 3 fail (the two descriptor tests, and the mode-000 file, which cannot be opened); every error the barrier's error (all-or-nothing) → 7 fail; the unmodified copy passes.

**Behaviour changes a user can meet**: a download run that finds files already in place flushes them before it records them (≈ 13 µs per file on this Mac); a disk that refuses a flush now shows as failed files for metadata updates, created directories, local deletes and recorded files as well, where it showed only for downloads; one bad file or directory no longer fails a batch of 512; `.gclone-partial-*` files left by a killed run are swept a day after they were last touched, whatever their mtime — and never while a download still works on them. On Linux a download holds up to 32 files open per stream (256 in the process).

**Still unverified / not exercised**: no power was cut and no real `fsync`, `close` or `syncfs` error was produced — the ordering and the attribution of errors are asserted through the hooks, the guarantees are the documented ones; the Linux path ran in a container only (above); NFS, FUSE and file systems that report write errors at `close` were not tried; a batch that spans two devices is handled by construction and not tested; whether Darwin reports a failed write-back to a descriptor at all is not documented in `fsync(2)` / `fcntl(2)` — syncing through the writing descriptor is the most that can be done there, and it is what the code before §17.15 did.

### 17.17 Linux builds, releases and the installer (2026-11-12)

Until here gclone had been built and run on macOS (arm64) alone, and §17.15 had run one module in a container. This round built and tested it on Linux and added what distributes it; no format, no algorithm and nothing under `worker/` changed.

**What ran.** In containers (OrbStack on the Mac, `rust:1-bookworm`, rustc 1.99.1, as an unprivileged user — root would walk through the permission tests): `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` on aarch64 natively for the glibc target and for `aarch64-unknown-linux-musl`, and the tests on x86_64 (glibc) under Rosetta: 648 pass, 3 ignored, each time, as on macOS. The release binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` are static (`musl-gcc` from `musl-tools` compiles the bundled SQLite and aws-lc; no cross toolchain — each is built on its own architecture) and ran a two-device `--vault-dir` scenario on Alpine, Debian and Ubuntu: sync up and down, `diff -r`, modify / delete / rename / move a directory of 300 files, remote `mv` / `rm` / `mkdir`, `restore`, the three `check` forms, case twins as two files, a name that is not UTF-8, the default directories with and without `XDG_CONFIG_HOME` / `XDG_STATE_HOME`, `ls -l` in the zone of `TZ`, the headless sign-in fallback without `xdg-open`, and a TLS handshake against a public host with the system's CA certificates.

**What was wrong.**
1. `tests/sync_e2e.rs`, `a_new_file_takes_the_remote_directory_spelling_on_a_folding_file_system`: the branch for a case-sensitive file system had never run and expected 2 uploads. `Foo/a` has the content of `foo/a`, which the vault holds: it is reused, 1 file is uploaded, and the one-way sync reports `foo/a` as destination-only. The test now asserts that, and the download that follows.
2. `src/transfer/download.rs`, `umask()` and its test: `u32::from(mode_t)` is a conversion on macOS (16 bits) and none on Linux, where clippy refuses it under `-D warnings`. Allowed at the two places, with the reason.
3. `src/util.rs`, `format_local_minute`: naming `libc::time_t` is a deprecation warning on musl targets. The type is now taken from `localtime_r`'s signature. Both release targets are 64-bit, where the width is the same either way.
4. `src/auth/mod.rs`, `http_client`: a system without CA certificates (a minimal container) failed with "builder error". The message carries the source chain now ("No CA certificates were loaded from the system"), as the Drive client's already did.

**Added.**
- `gclone --version` (§7): `gclone <version> (<target triple>, auth URL <url>)`, or `…, no auth URL built in)`. The triple comes from the new `build.rs` (`GCLONE_TARGET`); an empty `GCLONE_DEFAULT_AUTH_URL` counts as none, as in §2.2. Unit test `cli::tests::version_names_the_target_and_the_built_in_auth_url`.
- `.github/workflows/ci.yml` (fmt, clippy, tests on Linux and macOS; the Worker's typecheck and tests; `install.sh`) and `release.yml` (on a tag `v<version>`: tests and release builds for the two musl targets and the two macOS targets, `gclone-<target>.tar.gz` + `SHA256SUMS`, published with `gh`; the auth URL from the repository variable `GCLONE_DEFAULT_AUTH_URL`).
- `install.sh` and `tests/install/` (45 cases against a local directory and a fake GitHub: token, `gh` login and anonymous downloads, a storage host that refuses a forwarded `Authorization` header, checksum and target refusals; run with bash-as-sh, dash and BusyBox ash).

**Still unverified.** No Linux machine of its own was used — the kernel was OrbStack's, the file systems the containers' (no ext4 / btrfs / NFS on real disks, no power cut); x86_64 ran under emulation only. No GitHub workflow has run: the action versions exist and `actionlint` accepts the files, nothing more. `install.sh` has not met the real GitHub API. A real sign-in on Linux (a browser started through `xdg-open`, the loopback redirect) was not made. WSL2 was not tried. As the repository stands the Worker's `npm test` fails in three self-tests of `scripts/custom-domain.selftest.mjs`, which expect `wrangler.jsonc` in its `workers.dev` shape while the file carries the custom domain; the Worker's 162 vitest tests pass on Linux.

### 17.18 gclone 0.2.0 — the login is Google's device authorization grant (2026-11-12)

**Decision** (the owner: "can we do polling oauth instead of the localhost thing?"). `gclone login` no longer goes through a browser redirect to the Worker and a loopback listener or paste code on the device. It is Google's device authorization grant (RFC 8628) and nothing else: the device asks the Worker for a code (`POST /device/start`), shows the address and the user code, and polls (`POST /device/poll`) until the user has entered the code at `https://www.google.com/device`. The Worker proxies both steps so that the client secret never reaches a device, and it stays stateless — more so than before: Google holds the pending login, the device carries the device code, and the Worker seals nothing. A second OAuth client of type *TVs and Limited Input devices* was created in the same Cloud project; Google's device-code endpoint accepts it with `openid email https://www.googleapis.com/auth/drive.file` and answers `{device_code, user_code, expires_in: 1800, interval: 5, verification_url: "https://www.google.com/device"}` (checked against the real endpoint on 2026-11-12 — the only part of this change that met the real Google).

Edited in place: the title line, §0 (Auth bullet, new §0.6), §1.1, §1.3 (the Worker, strangers, network and phisher rows), §2 (roles and diagram), §2.1–§2.4 (rewritten; §2.3.1 is now "Statelessness"), §2.5, §2.6 (steps A.2–A.4, B), §2.8, §2.9 (probes 1, 4, 5), §4 (a note), §7.3, §8.2, §9.2, §9.3, §9.6, §9.10, §10, §11, §12 (WP3, WP7, WP8 lists), §13–§15, §16. §0.4, §0.5 and the earlier errata describe the redirect flow as it was; they are history.

**Removed.** Worker: `GET /login`, `GET /callback` (both visits), `POST /token`, the confirmation, finish, code and error pages, `src/seal.ts` (state / pending / grant blobs, HKDF, AES-GCM, check code, nonce), the secret `SEAL_KEY`, the OIDC nonce binding, the clock in `Deps`, HTML error answers (every error is JSON now, on the two pages' paths too). Device: the loopback listener and its HTTP parsing, the paste flow and its stdin reader, `Pkce`, `login_url`, `parse_loopback`, `parse_pasted`, `redeem`, `PASTE_PREFIX`, `AuthError::StateMismatch`, `STATE_TTL`, `GRANT_TTL`. Tests: `worker/test/{seal,login,token}.test.ts`; the browser and headless sections of `tests/auth.rs`; `FakeDrive::browse` and its pages. `worker/test/contract.json` is version 2.

**Added.**
- Worker (§2.3, §16): `POST /device/start`, `POST /device/poll`; the device-code states as stable error codes (`400 authorization_pending`, `400 slow_down`, `400 expired_token`; `403 access_denied` and `400 invalid_grant` as before), decided by Google's `error` field, not by its status (Google uses `428` and `403`); after a successful poll the checks `/token` had — an ID token of this client, a verified e-mail in `ALLOWED_EMAILS` (else revoke and refuse), granted scope ⊆ `ALLOWED_SCOPES` and ∋ `drive.file`, a refresh token — minus the nonce, for which the grant has no place; `/refresh` takes `"client": "device"`.
- Device (§2.4, §9.6): `auth::device_start`, `auth::device_wait`, `DeviceCode`, `AuthClient`; the three lines of §2.4; `slow_down` adds 5 s; failed polls are followed by the next one, with one note per streak; the code's lifetime ends the wait (`AuthError::Timeout`, which now means that); the answer of `/device/start` is checked before it is printed or opened. `--no-browser` means "do not open a browser"; `want_headless` decides the same without the flag.
- `Secrets.client` (§8.2) and the status warning for a login that still belongs to the legacy client.

**The transition** (one device holds a refresh token of the old *Web application* client; Google refreshes a token only for the client that issued it):
1. Worker secrets: `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` now mean the **device** client. The old client's values move to the optional `GOOGLE_LEGACY_CLIENT_ID` / `GOOGLE_LEGACY_CLIENT_SECRET` (used only when both are set; one without the other takes only the legacy client away — §17.19, which corrects the first wording "one without the other is `server_misconfigured`" on every route). `SEAL_KEY` is deleted. Order that keeps the signed-in device working throughout: put the two legacy secrets → `wrangler deploy` the new Worker → put the device client's ID and secret → delete `SEAL_KEY` (`worker/README.md`, "Moving from the browser sign-in").
2. `/refresh` picks the client by the request: `"client": "device"` → the device client; no `client` field → the legacy client. No field and no legacy secrets → `400 invalid_grant` with a message that says to run `gclone login` again, **without asking Google**. *Deviation from the first wording of the decision* ("absent ⇒ legacy when the legacy secrets are configured, else device"): asking Google with the device client's credentials for a token of another client could only fail, and what Google answers then is unverified (`unauthorized_client` would have surfaced as `client_invalid` — "the Worker is misconfigured" — instead of "log in again"). Every login that carries no marker was made before 0.2.0, so "absent" always means "legacy"; the direct refusal gives the old binary (`Expired` → "run `gclone login`") and the new one the same, correct, message.
3. The device stores the marker with every login it makes (`"client": "device"` in `secrets.json`) and sends it with every `/refresh`. A `secrets.json` without it — every file written before 0.2.0 — is a legacy login and is written back unchanged.
4. `gclone login` on a device whose login on file is a legacy one **always** signs in again, although that login may work (§2.6 A.2): otherwise a device could only move by `logout`, which discards the cached key. The new token replaces the old one **only once the attached vault was seen with it** (B.1 / B.2, as for every re-login); until then nothing on the device changes.
5. When every device has run `gclone login`: delete the two legacy secrets and the old client. A device that was forgotten gets "run `gclone login`" (exit 4) at its next command and is fine after it. A gclone older than 0.2.0 keeps refreshing through the legacy client but cannot log in any more (`/login` is `404`); a 0.2.0 device against a Worker from before answers "the auth Worker at this URL is an older version without the code sign-in".

**Not verified, and what happens if it is not so** (probe 4, §2.9): that files created through the *Web application* client are visible, under `drive.file`, to the device client of the same Cloud project. If they are not, the new login of step 4 finds no vault: `login` ends with `VaultNotVisible` and the fresh-login text of §2.8 — what was (not) changed, that the legacy secrets keep the device working, and where the ways out are described — exit 4, `secrets.json` byte-identical, `config.json` and the state directory untouched (`drive_mode_a_login_of_the_legacy_client_is_replaced_by_gclone_login`). A device with a `config.json` never creates a vault in that situation; a **new** device without one would find no vault and offer to create one, which is the ordinary first-device path and cannot be told apart from it.

**New accepted risk: device-code phishing** (§1.3, §2.3.2, §15) — `/device/start` is unauthenticated, so someone can start a login and try to get the owner to enter *their* user code at Google; the allowlist does not help, the consenting account being the allowed one. Implemented against it: the terminal's "(enter only a code shown in this terminal; waiting…)" with every code and the same warning on the Worker's home page; the rate limit on both routes; nothing of a request reaches Google but a pre-filtered device code; no device code, user code or token in any log line; every answer `no-store`. Residual: a phished grant reaches ciphertext only, but could trash it (recoverable for 30 days). The hand-over phishing of the redirect flow, and its two confirmation pages, are gone with that flow.

**Other consequences.** A poll answer that carries the tokens and is lost loses that login (§2.3.1): nothing stores them. The Worker's logs show one `authorization_pending` line per poll of a waiting login. `AUTH_TIMEOUT` is 1800 s. The contract fixture has no test vector any more (there is no cryptography on either side of the boundary). `Cargo.toml` is 0.2.0 (the release workflow compares the tag with it).

**Tests** (as of this section; the numbers after the review are in §17.19). Rust: `cargo test --locked` — 642 passed, 3 ignored (the two live tests and one unit test, as before); `tests/auth.rs` 24, of which the contract test runs the fixture's 45 cases against `FakeDrive` and replays the 41 on the three routes through the client; `tests/cli_e2e.rs` 28 (new: the legacy-client move; `ctrl_c_exits_130` now interrupts a polling login). Worker: `npm test` — the configuration check, 20 script self-tests, 119 Vitest tests in the Workers runtime (`device.test.ts`, `refresh.test.ts`, `contract.test.ts`); `npm run typecheck`; `npx wrangler deploy --dry-run`.

**Still unverified** (no consent was given at the real Google, nothing was deployed): that the device grant's token answer carries an ID token with `email` / `email_verified` when `openid email` is requested (Google's "Sign-In on TVs" guide shows one; its device-flow page does not mention it) — without it every login ends in `403 grant_unusable` (§17.19; first written here as `502 upstream_error`), fail closed, and the Worker would have to ask the userinfo endpoint instead; the exact `scope` text of that answer; the error code and status Google uses for a device code that ran out (`expired_token` is RFC 8628's; the device also stops at its own deadline); what Google answers to a refresh token presented with another client's credentials (the Worker never does that); the visibility question above; that a `user_code` always fits the checks of §2.3 / §2.4 (2..=64 printable ASCII characters); the legacy path against the real old client.

### 17.19 Review of 0.2.0 — fourteen issues, and the Intel Mac build (2026-11-12)

Reviewers of §17.18 filed sixteen reports; two issues were reported twice, which leaves fourteen. Each was re-checked in the code; all are real, and each is fixed at its cause, with a test that fails without the fix (the two document corrections excepted). Nothing was deployed and no real Google was involved. Edited in place: the title line, §1.3, §2.2–§2.4, §2.6 (A.4, B.2), §2.8, §2.9 (probe 5), §4, §9.6, §9.10, §12.1, §16.1–§16.5, three sentences of §17.18; `worker/README.md`, `README.md`, `docs/AUTH.md`.

**Worker.**
1. *A half-set legacy pair took the whole Worker down.* `configuredClients` returned null when exactly one of `GOOGLE_LEGACY_CLIENT_ID` / `_SECRET` was set, so `/device/start`, `/device/poll` and device-client refreshes answered `500 server_misconfigured` — a state every Worker passes through, because the pair is put and deleted with two `wrangler secret` commands that are each deployed at once. Now `Clients { device, legacy: null, legacyIncomplete: true }`: only a `/refresh` without `client` answers `500 server_misconfigured` (a message naming both secrets; not `invalid_grant`, which would say "log in again" to a login that may be fine), and the home page says `Status: ready` plus a warning. The fake Worker of `FakeDrive` did not model the state at all; it does now (`set_legacy_client_half_set`), and two contract cases hold both sides to it.
2. *The allowlist compared with Unicode lower-casing.* `"\u212A".toLowerCase()` is `"k"`: an ID token for `ma<KELVIN SIGN>@example.com` passed for the entry `mak@example.com`. The comparison folds the 26 ASCII letters only; a claim or an entry that is not 3..=254 printable ASCII characters matches nothing.
3. *`scripts/check-config.mjs` was a list of forbidden key names*, and looked at `ratelimits` at the top level only: `unsafe.bindings` (any binding type), `env.<name>` without or with a weaker limiter, and binding keys the list did not know (`ai`, `browser`, `send_email`, …) all passed. It is an allowlist now (§16.2); `env` and `unsafe` are refused as a whole. `logpush: false`, which the old check let through, is refused with the rest.
4. *`/device/poll` told an anonymous caller the full address of whoever entered its user code.* The `403 email_not_allowed` message shows the address masked (`s***@example.net`), on `/refresh` as well; a claim that is not printable ASCII is not shown at all. The contract fixture matches that message literally.
5. *A grant that Google had issued and the Worker could not use was answered `502 upstream_error`* — a code the device polls again on. The next poll could only get `invalid_grant`, so the user saw "the code is no longer valid … Run `gclone login` again" instead of the cause; and this is the path of the still unverified question whether the device grant's answer carries an ID token. New code **`403 grant_unusable`** for everything after Google's `200` that is not one of the three existing refusals: no refresh token, no usable access token, no ID token, an ID token that cannot be read or is not Google's for this client. The message says which. `403` rather than a 5xx so that no client — also not a future one — mistakes it for "try again"; `upstream_error` is kept for the cases where Google gave no usable answer and nothing was consumed. A `200` answer that carries an `error` field is treated as that error, so a pending login can never be ended as an "unusable grant". The fake Worker injected its `502` before it looked at the code and therefore never consumed one on that answer; it has `omit_id_token()` now, answers `403 grant_unusable` and marks the code used. *Not changed*: a permanent error of Google that the Worker does not know (`invalid_request` on a poll) is still `502` and is polled until the code ends — with the back-off of item 8 that is at most a poll a minute, and the first failure is printed.
6. *A device-code answer without `interval` was refused*, although RFC 8628 §3.2 makes the field optional and §3.5 names 5 as the default. Worker and device both take an absent `interval` as 5 s (`DEFAULT_POLL_INTERVAL_S`, `AUTH_POLL_INTERVAL_DEFAULT`); a value that is present and not a positive number is still refused.

**Device.**
7. *The sign-in address was opened whatever it was.* The device opens it only when it is an `https` page of `google.com` or a host below it (`is_google_page`); otherwise it prints `NOT_GOOGLE_NOTE` after the code, opens nothing, and goes on — so a moved Google page does not break the login. A URL with a user name or password is refused like any malformed answer. The Worker passes on whatever `https` address Google names, on purpose (§2.3): the reviewers' optional host check there was **not** added — it protects against nobody (the Worker's upstream is Google) and would turn a moved page into a failed login for every device.
8. *Failed polls were repeated at the unchanged interval* (RFC 8628 §3.5 requires a client to reduce its polling frequency). `device_wait` waits `interval · 2ⁿ` after the n-th network or 5xx failure in a row, capped at `AUTH_RETRY_AFTER_MAX`, never below `interval`, and back to `interval` with the first poll that is answered (§2.4 step 3; `poll_pause`). `/device/start` keeps its five tries in about four seconds: they are bounded.
9. *The `email` of a `/device/poll` answer was printed and stored unchecked* — the same Worker that cannot inject control sequences through `/device/start` could through "Signed in as …". It is held to printable ASCII without a space, at most 254 bytes, with an `@`.
10. *A legacy login whose Worker has no legacy secrets was told that Google had ended it.* `Hints.legacy_login` (set from `Secrets.client`) selects the text of §2.8 that names the cause.
11. *A device with a legacy login and no vault could create a second vault and lose the old login on the way.* Step A.4 saved the new grant at once when there was no `config.json`, and B.2 went on to CREATE when the new login saw nothing — which is also what "the new client cannot see the old client's vault" looks like. On such a device the new token is now saved only once a vault was found, and "nothing found" is `VaultNotVisible` with a text that names `--new-vault` (§2.6, §2.8). A **new** device (no `secrets.json` at all) still cannot be told from a first device; `worker/README.md` and `README.md` now say to let an attached device go first, and not to run `gclone logout` on a device from before 0.2.0 before its `gclone login` has worked.

**Fake auth Worker (`tests/support/fake_drive.rs`).**
12. *It did not keep Google's two timing rules*: `slow_down` came only from a counter a test set, and a code expired only on `expire_codes()`. Each login now records when it started and when it was last polled: a poll that comes sooner than `interval` after the previous one is `400 slow_down` (also for an approved code, which it does not redeem), and a code is `expired_token` once `expires_in` has passed. `Seen.at` is the arrival time of every request; `early_polls()` counts the `slow_down` answers given for timing. `set_poll_interval`, which no test had called, is used by three.

**Documents.**
13. `docs/AUTH.md`: "(step 16)" → "(step 14)"; the client of the browser sign-in was not "a second" client.
14. §4: "SHA-256 (PKCE, login check code)" removed; `sha2` is used for HKDF only.

**Releases.** `.github/workflows/release.yml` no longer builds `x86_64-apple-darwin`. `README.md` said "macOS (Apple silicon and Intel)" in two places; it now says that Intel Macs build from source. `install.sh` refuses an Intel Mac before it downloads anything — *"no prebuilt gclone for Intel Macs"*, with the pointer to "Building from source" — instead of failing on a download that cannot exist (a shell under Rosetta on Apple silicon is still recognised and gets the arm64 build; `--target x86_64-apple-darwin` is still honoured for a release of one's own). `tests/install/test.sh`: the fake release holds the three targets a real one has; cases for the refusal (from a directory and from GitHub) and for the explicit target.

**Tests.** Rust: `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` — 651 passed, 3 ignored (lib 273, `tests/auth.rs` 29, `tests/cli_e2e.rs` 29; the contract test runs the fixture's 48 cases against `FakeDrive` and replays the 44 on the three routes through the client), `cargo build --release --locked`. Worker: `npm run typecheck`; `npm test` — the configuration check, 23 script self-tests, 127 Vitest tests; `npx wrangler deploy --dry-run` (one binding: `RATE_LIMIT`). `sh tests/install/test.sh`: 59 cases, with sh, bash and dash.

**Still unverified.** Everything §17.18 lists. In addition: what a real device sees when Google's device grant carries no ID token is now a clear, final message — but whether it does is as open as before (probe 5); that Google never names a sign-in address outside `google.com` (if it does, the login works and prints the warning); Google's own status and wording for a poll that comes too early beyond the documented `slow_down`.

### 17.20 gclone 0.3.0 — `gclone web`, the vault in a browser; the orphan note of `check` (2026-11-12)

**Decision** (the owner: "can you offer a web viewer for the files? like a local gdrive UI basically that shows the encrypted content?"). A new command, `gclone web [--port N] [--no-browser]`, serves a Google-Drive-like file browser for the **decrypted** vault from the gclone binary, on loopback, read-only. The whole of it is §7.4. Edited in place: the title line, §1.3 (three rows), §5.9 (the last sentence of "no arguments"), §7.1, **§7.4 (new)**, §8.3, §9.1, §9.2, §9.7, §9.9, §9.10, §10, §13, §14, §15; `README.md` ("Browse the vault in your browser", the security bullet, a limitation, the layout); the `--help` text of the command. `Cargo.toml` is 0.3.0.

**Added.**
- `src/web/mod.rs` — `bind`, `serve`, `App` (session, checks, routes, the file stream), `Options`, `RefreshState`, `Refresher`, the constants of §7.4 (`LIST_PAGE`, `LIST_PAGE_MAX`, `SEARCH_HITS`, `SEARCH_HITS_MAX`, `STREAMS_MAX`, `PAGE_CSP`); `src/web/http.rs` — the response body (`Body`: a buffer, or a channel of verified frames that fails instead of ending when the download failed), `parse_query` (strict), `parse_range`, `etag`, `none_match`, `content_disposition`, `natural_cmp`; `src/web/mime.rs` — `of_name`, `Served::{inline, csp}`, `Kind`; `src/web/assets/` — the page. `src/cli/web.rs` — the command.
- `Vault::search` and `SearchHit` (§9.7); `cli::context::open_vault` (the second half of `open_ctx`, now shared) and the texts of `report_refresh` as functions; `cli::SERVING`.
- Dependencies: `hyper` (`http1`, `server`) and `hyper-util` (`tokio`) as **direct** dependencies. Both were in the tree through `reqwest`; `Cargo.lock` changes by the version line and two names in gclone's own list. No framework, no `http-body-util` (the body type is thirty lines), no TLS (loopback), nothing that needs a C library. The release binary (aarch64-apple-darwin) went from 9,763,632 to 10,094,512 bytes (+330,880, 3.4 %), the page's ~50 KiB of text included.

**Decisions inside the design.**
1. *A query parameter, exchanged by a redirect, not a fragment.* A fragment never reaches the server, so the page itself would have had to be served without the secret; the requirement is that every route needs it. The key is one-time (the browser does record the link's address, §17.21 — what it records is spent); `Referrer-Policy: no-referrer` and `Cache-Control: no-store` are on every response.
2. *The link works once*, and the cookie's value is a different secret. A link that leaked afterwards — a shell scrollback, a screenshot — is worthless (the launcher's argument list no longer holds one, §17.21). A new link costs one press of Enter in the terminal, and since §17.21 ends the sessions before it; without a terminal on stdin the viewer has to be started again (it says which of the two applies).
3. *A link followed from another site is answered with a page instead of a redirect* (§7.4, "Session"): otherwise a link clicked in a browser-based terminal would use the key up and then show "403", because `SameSite=Strict` cookies do not travel with a cross-site navigation or its redirects.
4. *`POST /api/refresh` is the one route that is not `GET`/`HEAD`* — it takes the state lock and talks to the store; the first wording of the design said "everything is GET". The cross-origin checks cover it like every other route.
5. *Several ranges are answered `200` with the whole file*, not `416` and not `multipart/byteranges`; a `Range` that is not understood likewise.
6. *PDF responses are not sandboxed.* `CSP: sandbox` on the response keeps Chrome's viewer from loading. They carry `default-src 'none'; frame-ancestors 'self'`, their type is fixed and `nosniff`.
7. *`502` for a file the store does not deliver* (missing, damaged, unreachable, login ended) with the command line's text, while nothing was sent; after the first bytes the connection is cut. `404` is kept for paths the index does not have.
8. *No lock between requests.* The first idea — one vault opened under the lock, the lock released — would have kept a `Vault::open` handle alive while other processes write the replica (its in-memory device id, pending high-water mark and listed-snapshots fingerprint go stale). Instead the server lives on the lock-less handle that §8.3 defines for exactly that, and each refresh is a short-lived locked vault, as if `gclone ls` were run.
9. *Order and paging are the server's*, so that a directory of any size is ordered once and the contract is testable; the page loads 2000 entries per request and draws a window of rows. Search results (at most 1000) were ordered in the page; since §17.21 the server orders them too.
10. *The download ledger is kept* (as `cat`): what the viewer streams counts against the day's download figure in `about`. Written through a connection of its own, errors ignored.
11. *`[::1]` as well as `127.0.0.1`* when the port is free there, so that `ssh -L 8377:localhost:8377` works whichever address the far end tries first; the printed link names `127.0.0.1`.
12. *Ctrl-C exits 0* (not 130): it is the documented way to end the command.

**`gclone check` during another device's upload** (reported from a live run the same day). A device puts its blobs before it publishes the index segment that names them (§5.7), so while an upload runs elsewhere, `check` on any other device sees objects that are in no blob table — and printed "note: N object(s) in the data folders belong to no known blob (gclone gc --orphans)", which reads like an instruction to delete them. `CheckReport.orphans_recent` now counts the unknown objects that are younger than `ORPHAN_GRACE` (the very rule by which `gc --orphans` leaves them alone); the note for those says "not in the index yet — probably another device's upload in progress; nothing to do (`gclone gc --orphans` only collects such objects once they are older than 14 days)", and only older objects get the note that names `gc --orphans` as the remedy. The number comes from the constant.

**Accepted risk** at the time (§1.3, §15): the session cookie was not bound to the port. Closed by §17.21 (the cookie's path).

**Tests.** `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` — 678 passed, 3 ignored (lib 287, `tests/web.rs` 13, `tests/cli_e2e.rs` 29, `tests/index_props.rs` 62, `tests/sync_e2e.rs` 53; the others unchanged), `cargo build --release --locked`. New: `tests/web.rs` (§13 item 8a) — every case speaks HTTP to the built binary; unit tests in `src/web/` (type table, ranges, entity tags, `Content-Disposition` for hostile names, strict query decoding, natural order, listing order, the page's references) and `src/cli/{web,check}.rs`; `search` in `tests/index_props.rs`; the two orphan notes in `tests/cli_e2e.rs` and `tests/sync_e2e.rs`.

**Run by hand** (macOS, the debug and the release binary, a directory vault with nested directories, 2,000 and 10,000 files in one directory, a 22 MiB file, PNG / SVG / PDF / WAV / text / HTML files, a broken MP4, names with Unicode, quotes, a line break, 200 characters): the API with `curl`; the page in headless Chrome 157 at 1280×800 and 400×800, light and dark, driven over the DevTools protocol — the link exchange (the address loses the key and keeps the folder), listing, 10,000 entries (24 rows in the DOM, 40–60 ms per page of 2000 in a debug build, no frame over 22 ms while scrolling end to end), sort, search, every kind of preview (the PDF in Chrome's viewer inside the frame; the HTML file as text and the SVG's script not run), keyboard navigation, back/forward/reload, the refresh action; Enter for a new link and Ctrl-C on a pseudo-terminal.

**Not verified.** Any browser but Chrome (in particular whether Firefox's and Safari's PDF viewers accept `default-src 'none'` on the PDF response, and how Safari treats the `Sec-Fetch-*` headers the checks read when present); the viewer against the real Google Drive (only `FakeDrive`: token renewal after a `401`, a login that ended); a run on Linux (the code has no platform-specific part beyond `want_headless`); the path that opens the browser (`open::that_detached` — no test may open one) and an actual `ssh -L` session; a client that disconnects while the stream task waits for a **stalled** store (covered by construction — `Sender::closed` — but the test stalls the client, not the store); video seeking in a real player (ranges are tested over HTTP, a playable video was not at hand); screen readers.

### 17.21 Review of 0.3.0 — `gclone web`: twenty-two issues (2026-11-13)

Three reviewers of §17.20 — security, correctness, the page — filed twenty-three reports; a running viewer that ignores `gclone logout` was reported twice, which leaves twenty-two issues. Each was re-checked against the code and, where it is about behaviour, reproduced; all are real, and each is fixed at its cause — the server-side ones with a test that fails without the fix. Edited in place: the title line, §1.3 (the local-user row), §7.1 (the secrets rule, the test switches), **§7.4** (rewritten from "Process" to "The page"), §8.3, §9.7, §9.10, §10, §13 (8a), §14 (9a), §15, four sentences of §17.20; `README.md`; the `--help` text of the command. No dependency was added (`chacha20poly1305` and `blake3`, already direct dependencies, seal the file ids); `Cargo.lock` is unchanged.

**The session.**
1. *The link's key was in the argument list of the browser launcher* (`open -- http://127.0.0.1:PORT/?k=…`; on Linux in the browser's own arguments for as long as it runs) — readable by every account of the machine, and whoever redeems a key first owns the session. The launcher now gets the **path of a `0600` page** in the `0700` state directory that leads to the link (§7.4, "The link, and the browser"); the page is removed when the link is used or replaced and when the viewer ends. And a theft is actionable: a used link answers that somebody else opened it and what to do, and **a new link is a new session** — Enter ends every cookie, path and download from before. Before, a new link revoked nothing.
2. *The cookie was `Path=/` on a host whose cookies ignore ports*, so the browser handed the session secret to every other server on `127.0.0.1` it talked to — also on the sub-requests of a page that another site had navigated it to — and with the cookie any local process reads the vault. Everything but the link now lives under a per-session random prefix, and the cookie is scoped to it (§7.4, "Session"). §15's accepted risk is gone; what is left of it is the case of a prefix that leaked.
3. *One foreign cookie with a non-ASCII value locked the user out* (`HeaderValue::to_str` failed on the whole `Cookie` header — browsers put such values on the wire as UTF-8, and send the cookies of all loopback ports together): the link was used up and every page said "open the link". Cookies are parsed as bytes. The same pattern made `Origin` and `Sec-Fetch-Site` fail **open** — an unreadable value, or a second header after an acceptable one, counted as absent; they are refused now, as `Host` always was.
4. *The names of the folders and files the user opened went into the browser's history* — the address (`#/folder/file`), the tab title, and `/file?path=…` for "open in a new tab": on disk, restored with sessions, and with history sync on, uploaded to the browser's vendor — the party the vault's names are encrypted against. The address and the title no longer change (`history.state`), and files are fetched by opaque ids (§7.4, "Nothing of the vault's names where the browser keeps it"). Checked in a throwaway Chrome profile after browsing: `History` holds the link's address and the prefix, both titled "gclone", and nothing else; the names are still in `Sessions/Session_*` (the saved `history.state`) — §15.
5. *A link was not used up when the browser that opened it already had a session*, so a second link stayed valid after it had been through the browser, its address in the history file. There is no such shortcut any more: the cookie is not sent to `/`, and every key that reaches the server is spent or refused. §7.4 no longer claims that the key is in no history entry.
6. *A running viewer ignored `gclone logout` and undid `gclone logout --forget`* (reported by two reviewers): it kept serving decrypted files after "Signed out on this device", and one click on Refresh after `--forget` re-created the state directory with a full plaintext index — which its own open connection, still on the unlinked old database, then never showed. `DeviceGuard` (§7.4): asked per request, per refresh — before and under the lock, which is taken without creating anything (`state::try_lock_existing`) — and once a second by the command, which ends with the text and exit 4. `logout` itself is unchanged: it neither waits for nor signals a viewer.

**The server.**
7. *`gclone web &` froze* — also Ctrl-Z and `bg`, and `nohup gclone web &` on macOS: the thread that waits for Enter read the terminal from a background process group, and the default action of `SIGTTIN` stops the whole process; the link had been printed and never answered. `SIGTTIN` is ignored (§7.4); the texts offer Enter only to a foreground process.
8. *`HEAD /file` honoured `Range`* (206 / 416). `Range` and `If-Range` are looked at for `GET` only.
9. *The 64 KiB limit for the request head was not what was enforced* — hyper's buffer accepted heads of 100,000 bytes. The handler counts the head and answers `431` above `HEADER_BYTES_MAX`; the number in §7.4 is true now.

**The page** (each looked at in headless Chrome 157 at 1440×900 and 390×844, light and dark, driven over the DevTools protocol against a directory vault with deep paths, hostile names, 5,020 entries in one folder, media, PDFs and text in several encodings).
10. *Breadcrumbs shrank instead of scrolling* — at depth 5 on a phone every crumb was an ellipsis. A crumb no longer shrinks (`flex: none`); the path scrolls, starts at its end, and fades where its beginning is out of view.
11. *Image, PDF, audio and video previews were an empty panel while the bytes were on their way* — the normal first impression against Drive. Every preview shows "Loading <name> (<size>)…" with a spinner until its element reports that it has something (`load`, `loadedmetadata`; for the PDF frame also a four-second limit, so that a viewer that never reports does not stay hidden).
12. *The preview claimed to be a modal dialog and was not*: Tab left it for controls behind it, and typing there closed it. Everything behind the open preview is `inert`.
13. *A download that the store could not deliver failed silently* — the browser started and cancelled a download named `file.txt`, the page said nothing. Both download controls ask the store for the first byte and show the server's message in place of the file; a file that cannot be read has no download and no "open" control next to the error.
14. *The vault summary went stale*: "just now" for hours, and an old file count after a `copy` on the same device. It is redrawn every minute, when the page becomes visible and when the popover opens, and fetched again with every listing.
15. *A file reached from another folder's listing took size, date and kind from a same-named row of the folder shown before.* Rows know the folder they belong to, and opening a file always asks `/api/stat` (which also carries the id).
16. *A transparent image with dark content was invisible in the dark theme.* Images have a light checkerboard of their own in both themes.
17. *Search results were ordered by the browser's collator, folders by the server* — the same entries in two orders, depending on the browser's language. `/api/search` takes `sort` and `order` and uses the listing's function.
18. *Names were not shown faithfully* (`white-space: nowrap`): runs of spaces collapsed, leading spaces vanished, a line break or a tab looked like a space. `white-space: pre`, and control characters as their pictures; paths, links and tooltips keep the real name.
19. *Keyboard and screen readers*: a focused list without a selected row had no focus indicator; the scroll container was a tab stop of its own; nothing said "Folder". A focus ring around the rows, `tabindex="-1"` on the container, the kind of each entry as hidden text.
20. *The text preview assumed UTF-8 and cut characters in half.* A byte-order mark selects UTF-16; otherwise UTF-8 when the bytes are valid UTF-8, else Windows-1252; a sequence split by the 512 KiB cut is dropped.
21. *In search results the folder of a match was cut at its end* — the part next to the match, which tells two matches apart. It is cut at its beginning; the tooltip has all of it.
22. *Messages showed Markdown backticks.* Commands in messages are `<code>` elements, built from text nodes.

**Decisions.** The place in the vault is kept in `history.state`, in the clear: reload and back/forward need it to survive, and the alternative — a state sealed by the server — would make every navigation a request; the cost is §15's first item. A redirect (`303`) answers the link only when the browser states that no other site began the navigation; everything else gets the page that navigates by itself, which also covers browsers without fetch metadata now that the launch page makes the first navigation a cross-site one. File ids come with `/api/stat` only (the page asks for the one file it opens), not with every row of a listing. The head limit is enforced rather than documented as "between 64 and 128 KiB". `logout` does not look for viewers.

**Tests.** `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` — 695 passed, 3 ignored (lib 294, `tests/web.rs` 23; the others unchanged), `cargo build --release --locked` (aarch64-apple-darwin: 10,144,288 bytes, +49,776). New in `tests/web.rs`: the cookie's path and the session among foreign cookies; repeated and unreadable `Origin` / `Sec-Fetch-Site`; the head limit at 60 KiB and above 64 KiB; `HEAD` with `Range`; search order against listing order for every key and direction; files by id (sealed, authenticated, per viewer); `logout` and `logout --forget` under a running viewer (no route serves, exit 4, nothing written back); on a pseudo-terminal that is the viewer's controlling terminal, Enter (new link, the old cookie and path dead on every route, its download cut) and the viewer as a background job (fails without the `SIGTTIN` line: "the viewer is stopped"); what the launcher is handed (`GCLONE_TEST_BROWSER`: a path, mode `0600`, gone once the link is used and when the viewer ends). Unit tests: `DeviceGuard`, `state::try_lock_existing`, the launch page, file ids, the logged route, search order, and — in the page's self-check — that the script never touches `document.title` or `location.hash`, pushes state without a URL, and builds no `file?path` address.

**Run by hand.** The launch page followed by Chrome from its `file:` address (ends at the listing; cookie `Path=/s-…/; HttpOnly; SameSite=Strict`; the page file gone); reload, back and forward through folders, a preview and a search with real clicks; the checks named under "The page", each with a screenshot that was looked at.

**Not verified.** Everything §17.20 lists. In addition: the two pseudo-terminal tests and the launch page on Linux (in particular a snap or flatpak browser, which cannot read gclone's state directory — §15); `open` handing the launch page to the real default browser (no test may open one; Chrome was pointed at the file by hand); Safari and Firefox with the path-scoped cookie and the `file:` → `http://127.0.0.1` navigation; that a Drive viewer's token renewal in the second after a `logout` leaves a `token.json` behind (§15; inferred from the code); the race in which a `logout` lands between a refresh's second look at the guard and its open (closed by construction: `logout` needs the lock the refresh holds).
