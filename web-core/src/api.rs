//! The wasm-bindgen surface (design §5). One module, loaded by three contexts: the KDF worker
//! (`unlock`), the vault worker (`Vault`) and the Service Worker (`served`, `parse_range`,
//! `FileReader`). The page never loads it.
//!
//! Structured values cross as JSON strings, bytes as `Uint8Array`, sizes and offsets as
//! numbers (whole, below 2^53 — anything else is refused). A failure is thrown as an `Error`
//! whose message is `"<code>: <sentence>"`, the code one of `wrong-passphrase`, `damaged`,
//! `other-vault`, `needs-newer`, `not-found`, `not-a-file`, `corrupt`, `bad-input`. Anything
//! else that is thrown — a `RuntimeError`, a `RangeError` — is the module itself failing
//! (out of memory, most likely): that instance must not be used again.
//!
//! Nothing here does I/O, reads a clock or draws randomness; the module's only imports are
//! wasm-bindgen's own intrinsics. Everything is a thin wrapper: the logic is in `ops`,
//! `reader` and `file`, which run natively in `tests/parity.rs`.

use wasm_bindgen::prelude::*;
use zeroize::{Zeroize as _, Zeroizing};

use crate::reader::Reader;
use crate::web::rules::RefreshState;
use crate::{Code, Error, file, integer, number, ops};

fn throw(e: Error) -> JsError {
    JsError::new(&e.to_string())
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|e| {
        throw(Error::new(
            Code::BadInput,
            format!("cannot encode the answer: {e}"),
        ))
    })
}

/// A JSON array of names (a listing).
fn names(json: &str) -> Result<Vec<String>, JsError> {
    serde_json::from_str(json).map_err(|_| {
        throw(Error::new(
            Code::BadInput,
            "names: not a JSON array of strings",
        ))
    })
}

fn whole(value: f64, what: &str) -> Result<u64, JsError> {
    integer(value, what).map_err(throw)
}

// ---------------------------------------------------------------------------------------------
// Any context
// ---------------------------------------------------------------------------------------------

/// The version of this module (the crate's, which is gclone's).
#[wasm_bindgen]
pub fn core_version() -> String {
    ops::core_version().to_owned()
}

/// Drive's `createdTime` (RFC 3339) in milliseconds, as the CLI parses it; `undefined` for
/// text that is not such a time.
#[wasm_bindgen]
pub fn parse_rfc3339_ms(s: &str) -> Option<f64> {
    ops::parse_rfc3339_ms(s).map(|ms| ms as f64)
}

// ---------------------------------------------------------------------------------------------
// Vault worker, before unlock
// ---------------------------------------------------------------------------------------------

/// `{"vault_id", "min_reader", "created_ms", "readable"}` of a `gclone-vault.json` — an
/// unauthenticated hint. `readable: false`: the vault needs a newer viewer. Throws `damaged`
/// for bytes that are no descriptor.
#[wasm_bindgen]
pub fn parse_descriptor(bytes: &[u8]) -> Result<String, JsError> {
    json(&ops::parse_descriptor(bytes).map_err(throw)?)
}

/// The keyfiles to try among the names of the vault root (a JSON array): a JSON array, highest
/// generation first, at most four.
#[wasm_bindgen]
pub fn keyfile_candidates(names_json: &str) -> Result<String, JsError> {
    json(&ops::keyfile_candidates(&names(names_json)?))
}

/// `{"gen", "m_kib", "t", "p"}`: what unlocking with this keyfile costs, read before any work.
/// Throws `damaged` (not a usable keyfile, or parameters outside the format's bounds),
/// `needs-newer` (a keyfile version this build does not read), `bad-input` (not a keyfile name).
#[wasm_bindgen]
pub fn keyfile_cost(name: &str, bytes: &[u8]) -> Result<String, JsError> {
    json(&ops::keyfile_cost(name, bytes).map_err(throw)?)
}

// ---------------------------------------------------------------------------------------------
// KDF worker
// ---------------------------------------------------------------------------------------------

/// Argon2id and the keyfile: the key bundle for [`Vault::from_keys`]. `vault_id`: the chosen
/// descriptor's (32 hex digits). Blocking, and it grows this instance's memory by the
/// keyfile's `m_kib` for good — call it in a worker of its own and terminate that worker.
/// Throws `wrong-passphrase`, `damaged`, `needs-newer`, `other-vault`.
#[wasm_bindgen]
pub fn unlock(
    keyfile_name: &str,
    keyfile_bytes: &[u8],
    passphrase: String,
    vault_id: &str,
) -> Result<Vec<u8>, JsError> {
    // Taken by value: this module's copy of the passphrase is wiped when the call ends.
    let passphrase = Zeroizing::new(passphrase);
    let bundle = ops::unlock(keyfile_name, keyfile_bytes, &passphrase, vault_id).map_err(throw)?;
    Ok(bundle.to_vec())
}

// ---------------------------------------------------------------------------------------------
// Vault worker
// ---------------------------------------------------------------------------------------------

/// The keys of one vault and its index. No call hands out a master key.
#[wasm_bindgen]
pub struct Vault {
    reader: Reader,
}

#[wasm_bindgen]
impl Vault {
    /// From the bundle `unlock` returned. **The bundle is wiped**: this module's copy and the
    /// caller's array are zero-filled before the call returns, whether it succeeds or not.
    pub fn from_keys(bundle: &mut [u8]) -> Result<Vault, JsError> {
        let keys = ops::keys_of(bundle);
        bundle.zeroize();
        Ok(Vault {
            reader: Reader::new(keys.map_err(throw)?),
        })
    }

    /// 32 hex digits.
    pub fn vault_id(&self) -> String {
        crate::util::hex(&self.reader.keys().vault_id())
    }

    /// Forgets the index and keeps the keys.
    pub fn reset(&mut self) {
        self.reader.reset();
    }

    /// Every snapshot of the index listing (a JSON array of names), newest first: a JSON array.
    pub fn snapshot_candidates(&self, names_json: &str) -> Result<String, JsError> {
        json(&Reader::snapshot_candidates(&names(names_json)?))
    }

    /// `true`: accepted, it is the base now. `false`: damaged — try the next candidate.
    /// Throws `needs-newer` (the object's format, or the vault format it holds, is newer) and
    /// `bad-input` (called twice, or after a segment: `reset()` first).
    pub fn load_snapshot(&mut self, name: &str, bytes: &[u8]) -> Result<bool, JsError> {
        self.reader.load_snapshot(name, bytes).map_err(throw)
    }

    /// The listed segments to fetch (JSON array in, JSON array out): not covered by the
    /// snapshot, not in hand, not applied.
    pub fn needed_segments(&self, names_json: &str) -> Result<String, JsError> {
        json(&self.reader.needed_segments(&names(names_json)?))
    }

    /// `created_ms`: the store's creation time of the object (`parse_rfc3339_ms(createdTime)`);
    /// `undefined` when it is not known. `true`: taken. `false`: damaged (recorded in the
    /// report). Throws `needs-newer`.
    pub fn add_segment(
        &mut self,
        name: &str,
        bytes: &[u8],
        created_ms: Option<f64>,
    ) -> Result<bool, JsError> {
        let created_ms = created_ms.map(|ms| whole(ms, "created_ms")).transpose()?;
        self.reader
            .add_segment(name, bytes, created_ms)
            .map_err(throw)
    }

    /// Applies what is applicable and returns the report: `{"snapshot", "applied", "blocked",
    /// "missing": [[device, seq, hash, file_id]], "corrupt", "files", "dirs", "bytes",
    /// "conflicts", "head", "vault_name"}`. Throws `needs-newer` (a segment declares a vault
    /// format this build does not read).
    pub fn finish(&mut self) -> Result<String, JsError> {
        json(&self.reader.finish().map_err(throw)?)
    }

    /// The viewer's `info` answer (the local viewer's shape, plus `"head"`). `refresh_json`:
    /// `{"at_ms", "ok", "applied", "note"}`, the outcome of the last refresh, as the caller
    /// tracks it.
    pub fn info(&self, refresh_json: &str) -> Result<String, JsError> {
        let refresh: RefreshState = serde_json::from_str(refresh_json).map_err(|_| {
            throw(Error::new(
                Code::BadInput,
                "refresh: not {at_ms, ok, applied, note}",
            ))
        })?;
        json(&self.reader.info(refresh))
    }

    /// The viewer's `list` answer. `path`: `""` for the root. `sort` (`name`, `size`, `mtime`),
    /// `order` (`asc`, `desc`), `offset` and `limit` may be `undefined`: the local viewer's
    /// defaults. With `at` (a moment in milliseconds since 1970; `now` is then required, the
    /// caller's clock): the folder as it was at that moment, with `"at"` — moved into the
    /// window — and, for a folder that did not exist then, `"absent"` and `"nearest"`. Throws
    /// `not-found` (no such folder, without `at`) and `bad-input`.
    #[allow(clippy::too_many_arguments)]
    pub fn list(
        &mut self,
        path: &str,
        sort: Option<String>,
        order: Option<String>,
        offset: Option<f64>,
        limit: Option<f64>,
        at: Option<f64>,
        now: Option<f64>,
    ) -> Result<String, JsError> {
        let (sort, order) = (sort.as_deref(), order.as_deref());
        let listed = match at {
            Some(at) => self
                .reader
                .list_at(path, sort, order, offset, limit, at, now),
            None => self.reader.list(path, sort, order, offset, limit),
        };
        json(&listed.map_err(throw)?)
    }

    /// The viewer's `stat` answer: the entry at `path`, with its path. With `at` (and `now`):
    /// the entry of that moment; with `v` (and `now`): the version of the file that the id
    /// names — both with `"v"`, the id of the version shown, and `"since"`. Not both. Throws
    /// `not-found`, `bad-input`.
    pub fn stat(
        &mut self,
        path: &str,
        at: Option<f64>,
        v: Option<String>,
        now: Option<f64>,
    ) -> Result<String, JsError> {
        json(
            &self
                .reader
                .stat_at(path, at, v.as_deref(), now)
                .map_err(throw)?,
        )
    }

    /// The viewer's `search` answer. `limit`, `sort` and `order` may be `undefined`. With `at`
    /// (and `now`): what was there at that moment.
    pub fn search(
        &mut self,
        q: &str,
        limit: Option<f64>,
        sort: Option<String>,
        order: Option<String>,
        at: Option<f64>,
        now: Option<f64>,
    ) -> Result<String, JsError> {
        let (sort, order) = (sort.as_deref(), order.as_deref());
        let found = match at {
            Some(at) => self.reader.search_at(q, limit, sort, order, at, now),
            None => self.reader.search(q, limit, sort, order),
        };
        json(&found.map_err(throw)?)
    }

    /// The viewer's `versions` answer: `{"path", "now_ms", "from_ms", "deleted", "more",
    /// "versions": [{"v", "current"?, "shown"?, "size", "mtime_ms", "written_ms"?,
    /// "written_approx"?, "written_by", "until_ms"?, "by"?, "why"?, "restore"?}]}` — the file
    /// as it is and its removed versions that are kept, newest first. `at`: the moment whose
    /// version is marked `"shown"`. `now`: the caller's clock (this module reads none).
    pub fn versions(&mut self, path: &str, at: Option<f64>, now: f64) -> Result<String, JsError> {
        json(&self.reader.versions(path, at, Some(now)).map_err(throw)?)
    }

    /// The viewer's `deleted` answer: `{"path", "gone", "sort", "order", "total", "offset",
    /// "entries", "restore"?, "as_it_was_ms"?}` — what was deleted from the folder `path` and
    /// is kept, in pages like `list`. Throws `not-found` (no folder, and nothing kept under
    /// the name).
    pub fn deleted(
        &self,
        path: &str,
        sort: Option<String>,
        order: Option<String>,
        offset: Option<f64>,
        limit: Option<f64>,
        now: f64,
    ) -> Result<String, JsError> {
        let found = self.reader.deleted(
            path,
            sort.as_deref(),
            order.as_deref(),
            offset,
            limit,
            Some(now),
        );
        json(&found.map_err(throw)?)
    }

    /// The viewer's `timeline` answer: `{"now_ms", "from_ms", "devices", "moments": [[ms,
    /// files, device, approx]]}`.
    pub fn timeline(&mut self, now: f64) -> Result<String, JsError> {
        json(&self.reader.timeline(Some(now)).map_err(throw)?)
    }

    /// The ticket of one file: `{"v": 1, "name", "size", "file_id", "blob_name", "off", "clen",
    /// "chunk_log2", "key", "header"}` — the key of that one file's stream and where its
    /// ciphertext is. For the Service Worker, over the ticket port; never for the page. With
    /// `v` (a version id, and `now`): the ticket of that version of the file, while it is
    /// kept. Throws `not-found`, `not-a-file`, `corrupt` (the index entry contradicts itself),
    /// `needs-newer`.
    pub fn ticket(
        &self,
        path: &str,
        v: Option<String>,
        now: Option<f64>,
    ) -> Result<String, JsError> {
        json(
            &self
                .reader
                .ticket_of(path, v.as_deref(), now)
                .map_err(throw)?,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Service Worker
// ---------------------------------------------------------------------------------------------

/// `{"kind", "mime", "csp", "disposition"}`: the headers of an answer that carries the bytes
/// of a file called `name`. `download`: `application/octet-stream` and `attachment`, whatever
/// the kind.
#[wasm_bindgen]
pub fn served(name: &str, download: bool) -> Result<String, JsError> {
    json(&ops::served(name, download))
}

/// `{"kind": "whole" | "range" | "unsatisfiable", "start", "end"}` for a `Range` header
/// (`undefined`: none) against a file of `size` bytes: the plaintext bytes `start..end`.
#[wasm_bindgen]
pub fn parse_range(header: Option<String>, size: f64) -> Result<String, JsError> {
    json(&ops::parse_range(header.as_deref(), whole(size, "size")?))
}

/// Decrypts the plaintext bytes `start..end` of one file from its ticket, as the ciphertext
/// arrives.
#[wasm_bindgen]
pub struct FileReader {
    inner: file::FileReader,
}

#[wasm_bindgen]
impl FileReader {
    /// `end` is clamped to the file's size. Throws `bad-input` for a ticket that is not one,
    /// and for a `start` beyond the end.
    #[wasm_bindgen(constructor)]
    pub fn new(ticket_json: &str, start: f64, end: f64) -> Result<FileReader, JsError> {
        let (start, end) = (whole(start, "start")?, whole(end, "end")?);
        Ok(FileReader {
            inner: file::FileReader::from_json(ticket_json, start, end).map_err(throw)?,
        })
    }

    /// The bytes of the blob object to request are `cipher_start()..cipher_end()` (end
    /// exclusive). Equal: nothing to request.
    pub fn cipher_start(&self) -> Result<f64, JsError> {
        number(self.inner.cipher_start(), "the blob offset").map_err(throw)
    }

    pub fn cipher_end(&self) -> Result<f64, JsError> {
        number(self.inner.cipher_end(), "the blob offset").map_err(throw)
    }

    /// The next bytes of that range, in pieces of any size → the verified plaintext that
    /// became ready, cut to `start..end`. Throws `corrupt`; after that, every call does.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.push(bytes).map_err(throw)
    }

    /// Where a request that broke off continues: the blob offset of the first chunk that has
    /// not verified. Bytes of that chunk that were pushed already are dropped: the next
    /// `push` must start at this offset.
    pub fn resume_at(&mut self) -> Result<f64, JsError> {
        number(self.inner.resume_at(), "the blob offset").map_err(throw)
    }

    /// Plaintext bytes still owed; `0`: complete.
    pub fn remaining(&self) -> Result<f64, JsError> {
        number(self.inner.remaining(), "the length").map_err(throw)
    }
}

/// One Argon2id derivation with the given cost and a fixed salt — for measuring a device
/// (`bench` feature only; the caller takes the time).
#[cfg(feature = "bench")]
#[wasm_bindgen]
pub fn kdf_bench(m_kib: u32, t: u32) -> Result<(), JsError> {
    ops::kdf_bench(m_kib, t).map_err(throw)
}
