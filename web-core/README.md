# gclone-web-core

The read path of gclone for the hosted viewer, compiled to WebAssembly: keyfile, index objects,
the merge rule, the viewer's listing and search rules, per-file tickets and ranged chunk
decryption. It does no I/O, reads no clock and draws no randomness: JavaScript lists and
fetches (Drive), and hands the bytes in.

Nothing of the formats or the cryptography is implemented here. `src/lib.rs` compiles the main
crate's own files a second time, by path (`consts`, `crypto`, `error`, `format`, `path`,
`types`, `util`, `index/apply.rs`, `web/mime.rs`, `web/rules.rs`). What this crate adds:

| File | What |
|---|---|
| `src/reader.rs` | A stateless replica: newest accepted snapshot ⊕ the segments it does not cover, in the in-memory index; `list`, `stat`, `search`, `info` through `web/rules.rs`; tickets. |
| `src/file.rs` | `FileReader`: streaming, ranged decryption of one file from its ticket. |
| `src/ops.rs` | The calls that need no index: descriptor, keyfile candidates and cost, `unlock`, the key bundle, `served`, `parse_range`. |
| `src/api.rs` | The wasm-bindgen surface over the three (compiled for wasm only). |

The crate has its own empty `[workspace]` and its own `Cargo.lock`, so that the CLI's
`Cargo.toml`, `Cargo.lock` and release build never see it. Every dependency is one of the CLI's
at the CLI's version; `build.sh` fails if the two lockfiles disagree.

## Build

```sh
sh web-core/build.sh            # → web-core/pkg/{core.js, core.wasm, build.json}
```

Needs cargo and rustc with the `wasm32-unknown-unknown` target, a wasm linker (a rustup
toolchain brings `rust-lld`), and the `wasm-bindgen` command at exactly the version of the
`wasm-bindgen` crate in `Cargo.lock` (`cargo install wasm-bindgen-cli --version <it> --locked`).
With nix, as a development build: `nix-shell -p cargo rustc lld wasm-bindgen-cli nodejs --run
'sh web-core/build.sh'`. The script checks the tools, compiles with path remapping (no local
path ends up in the module), runs `wasm-bindgen --target no-modules`, and then checks what came
out: the module imports nothing but wasm-bindgen's own intrinsics, it is at most 800 KB, and the
glue has no `eval`. `build.json` records the compiler that built it.

`core.js` is a classic script that defines the global `wasm_bindgen`. A worker loads it like
this (the location of the `.wasm` is always passed: the file is not called `core_bg.wasm`):

```js
importScripts(policy.createScriptURL('/a/<build>/core.js'));
await wasm_bindgen({ module_or_path: '/a/<build>/core.wasm' });
wasm_bindgen.core_version();
```

It needs `script-src 'self' 'wasm-unsafe-eval'` and `connect-src 'self'` (the glue fetches the
`.wasm`); under Trusted Types the script URL goes through the context's policy.

The command in the lockfile's version is installed by `sh .github/scripts/install-wasm-bindgen.sh`
(what CI and the release workflow run). After a version bump or a dependency change in the root
crate, bring `Cargo.toml`'s version and `Cargo.lock` here along (`cargo check` in this directory,
without `--locked`): `build.sh` fails with the list of differences otherwise, and the release workflow
refuses a tag whose version is not also this crate's.

## Test

```sh
cargo test --locked                       # in web-core/: tests/parity.rs, natively
sh web-core/test/run.sh                   # the wasm in Node against the native implementation
GCLONE_WEB_CORE_SMOKE="chrome webkit firefox" sh web-core/test/run.sh    # + three browsers
```

- `tests/parity.rs` builds vaults with the main library (two devices, a snapshot and segments
  after it, renames, deletes, conflicts, a file where another device has a folder, names outside
  ASCII) and asserts that the reader and a freshly attached SQL replica agree — as JSON, byte
  for byte, the native side through `gclone::web::rules` — on every listing in every order,
  every search, `stat`, `info` and the head fingerprint. Also: the three format gates, the
  refresh cost, keyfiles, the key bundle, tickets, ranged decryption and tampering.
- `test/run.sh` runs that test once more with `GCLONE_WEB_CORE_EXPORT` set, which writes the
  vault and the native answers to a directory, and then `test/e2e.mjs`: the wasm module, loaded
  from `pkg/` the way a worker loads it, must give the same bytes; it then reads directory
  vaults that the native `gclone` binary writes during the test (`ls -R`, `ls -l`, `tree`,
  `cat`, `status`, `passwd`, concurrent writers, planted keyfiles, damaged objects).
- `test/smoke/run.mjs` loads the module with `importScripts()` in two dedicated workers and a
  Service Worker under the viewer's Content-Security-Policy and Trusted Types policy.

For lints: `cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings` (the API) and
`cargo clippy --locked --lib --tests -- -D warnings` (natively). `--all-targets` does not work:
it would build the unit tests of the included files, which belong to the main crate.

## The API

Structured values cross as JSON strings, bytes as `Uint8Array`, sizes and offsets as numbers
(whole and below 2^53, or refused). A failure is thrown as an `Error` whose message is
`"<code>: <sentence>"`:

| Code | Meaning |
|---|---|
| `wrong-passphrase` | `unlock`: the keyfile is intact, the passphrase is not its passphrase. |
| `damaged` | A keyfile or descriptor that cannot be read. |
| `other-vault` | `unlock`: the keyfile opened and belongs to another vault. |
| `needs-newer` | A format version this build does not know — anywhere. Stop; do not guess. |
| `not-found` | No such folder or file (the sentence is the local viewer's). |
| `not-a-file` | A ticket was asked for a folder. |
| `corrupt` | Ciphertext that does not verify, or an index entry that contradicts itself. |
| `bad-input` | A malformed argument, or a call out of order. |

Anything else that is thrown (a `RuntimeError`, a `RangeError`) is the instance itself failing —
out of memory, most likely. That instance must not be used again.

```
// any context
core_version() -> string
parse_rfc3339_ms(s) -> number | undefined

// vault worker, before unlock
parse_descriptor(bytes) -> JSON {vault_id, min_reader, created_ms, readable}
keyfile_candidates(names_json) -> JSON [name]        highest generation first, at most 4
keyfile_cost(name, bytes) -> JSON {gen, m_kib, t, p}

// KDF worker
unlock(keyfile_name, keyfile_bytes, passphrase, vault_id) -> Uint8Array    the key bundle

// vault worker
class Vault
  static from_keys(bundle: Uint8Array) -> Vault      zero-fills `bundle`
  vault_id() -> string
  reset()
  snapshot_candidates(names_json) -> JSON [name]     newest first
  load_snapshot(name, bytes) -> boolean              false: damaged, try the next
  needed_segments(names_json) -> JSON [name]
  add_segment(name, bytes, created_ms?) -> boolean   false: damaged (recorded)
  finish() -> JSON {snapshot, applied, blocked, missing: [[device, seq, hash, file_id]],
                    corrupt: ["<name>: <why>"], files, dirs, bytes, conflicts, head, vault_name}
  info(refresh_json) -> JSON InfoJson + "head"
  list(path, sort?, order?, offset?, limit?) -> JSON ListJson
  stat(path) -> JSON EntryJson (with path)
  search(q, limit?, sort?, order?) -> JSON SearchJson
  ticket(path) -> JSON {v: 1, name, size, file_id, blob_name, off, clen, chunk_log2, key, header}
  free()

// Service Worker
served(name, download) -> JSON {kind, mime, csp, disposition}   disposition: a bare "inline" for what is shown;
                                                                 "attachment; filename=…" (the name) for a download
parse_range(header | undefined, size) -> JSON {kind: "whole" | "range" | "unsatisfiable", start, end}
class FileReader
  constructor(ticket_json, start, end)               plaintext [start, end), end clamped to the size
  cipher_start() -> number   cipher_end() -> number  bytes of the blob object to request
  push(bytes) -> Uint8Array                          verified plaintext that became ready
  resume_at() -> number                              drops the partial chunk; continue from here
  remaining() -> number                              plaintext still owed; 0 = complete
  free()
```

The comments in `src/api.rs` say what each call throws.
