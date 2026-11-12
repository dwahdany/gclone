//! Shared constants: SPEC §6.1 (transfer pipeline, pacing, grace periods) and the
//! device-side constants of §2.2. None is part of the on-disk format unless marked **F**.
//!
//! Type conventions (so that every package casts the same way):
//! - sizes of files, objects and byte offsets are `u64`;
//! - fixed format lengths that index into buffers (`HEADER_LEN`, `TAG_LEN`) are `usize`;
//! - time spans are `std::time::Duration` under the spec's name, with a `*_MS` (`u64`) or
//!   `*_NS` (`i64`) companion where the span is compared against stored timestamps.

use std::time::Duration;

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * KIB;
pub const GIB: u64 = 1024 * MIB;

const DAY: Duration = Duration::from_secs(86_400);
const DAY_MS: u64 = 86_400_000;

// ---------------------------------------------------------------------------------------------
// §4.2 / §6.1 — stream container (F)
// ---------------------------------------------------------------------------------------------

/// **F** — `chunk_log2` written in every stream header (64 KiB chunks).
pub const CHUNK_LOG2: u8 = 16;
/// Accepted `chunk_log2` range on read (§4.2).
pub const CHUNK_LOG2_MIN: u8 = 12;
pub const CHUNK_LOG2_MAX: u8 = 24;
/// **F** — length of the stream header.
pub const HEADER_LEN: usize = 60;
/// **F** — Poly1305 tag length.
pub const TAG_LEN: usize = 16;

// ---------------------------------------------------------------------------------------------
// §6.1 — packing and transfers
// ---------------------------------------------------------------------------------------------

/// Files with `0 < size < PACK_MEMBER_MAX` are packed.
pub const PACK_MEMBER_MAX: u64 = MIB;
/// A pack is closed when the next member would push its plaintext past this.
pub const PACK_TARGET: u64 = 16 * MIB;
/// Objects `≤` this go up as one `uploadType=multipart` request.
pub const MULTIPART_MAX: u64 = 4 * MIB;
/// Resumable upload granule (Drive requires multiples of 256 KiB for non-final parts).
pub const UPLOAD_GRANULE: u64 = 256 * KIB;
/// Resumable upload part (`64 × UPLOAD_GRANULE`).
pub const PART_SIZE: u64 = 64 * UPLOAD_GRANULE;
/// Concurrent blob uploads; download streams = `2 × transfers`.
pub const TRANSFERS_DEFAULT: usize = 4;
/// Sources handed to one `upload_batch` call.
pub const UPLOAD_BATCH_FILES: usize = 10_000;
/// Members whose gap is `≤` this are fetched with one ranged GET.
pub const RANGE_COALESCE_GAP: u64 = 256 * KIB;
/// Large sources are re-`fstat`ed this often while uploading.
pub const SOURCE_RECHECK_BYTES: u64 = 64 * MIB;
/// Per file, each attempt with a new salt + blob id + Drive ID.
pub const UPLOAD_ATTEMPTS: u32 = 3;
pub const DOWNLOAD_RETRIES: u32 = 5;
/// Downloaded files are made durable in batches (§5.7 step 3): a batch is closed — its content
/// flushed, its files renamed, the renames flushed, its outcomes reported — after this many
/// files …
pub const DOWNLOAD_BATCH_FILES: usize = 512;
/// … or this many bytes, whichever comes first. A batch is also what a download may hold in
/// partial files beside the files it is about to replace.
pub const DOWNLOAD_BATCH_BYTES: u64 = 16 * MIB;
/// A batch that has been open this long is closed by the next file that arrives: on a slow
/// link finished files do not wait for a full batch.
pub const DOWNLOAD_BATCH_AGE: Duration = Duration::from_secs(1);
/// Written files of a batch that are still open: a file is synced through the descriptor it
/// was written with (§5.7 step 3a), and where a `syncfs` in front of a group of `fsync`s pays
/// (Linux) that many descriptors wait for it. Elsewhere each file is synced and closed as soon
/// as it is complete.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const DOWNLOAD_OPEN_FILES: usize = 32;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const DOWNLOAD_OPEN_FILES: usize = 1;
/// … and no more than this many in all batches of the process together (there is a batch per
/// download stream, up to 129 of them; the soft descriptor limit is 1024 on most Linux systems).
pub const DOWNLOAD_OPEN_TOTAL: usize = 256;

// ---------------------------------------------------------------------------------------------
// §6.1 — journal, compaction, garbage collection
// ---------------------------------------------------------------------------------------------

pub const COMMIT_INTERVAL: Duration = Duration::from_secs(120);
pub const COMMIT_MAX_OPS: usize = 4096;
pub const COMPACT_MIN_SEGMENTS: u64 = 64;
/// Compaction also triggers when the applied segments' bytes exceed
/// `max(COMPACT_MIN_BYTES, 25 % of the base snapshot's size)` (§5.6).
pub const COMPACT_MIN_BYTES: u64 = MIB;
pub const SNAPSHOT_KEEP: usize = 2;
/// **F** — the largest index object (segment or snapshot, sealed bytes) that is written or
/// read (§4.6 rule 1). An index object is buffered whole **before** anything in it is
/// authenticated, so the bound has to come from the format, not from the store.
pub const INDEX_OBJECT_MAX: u64 = GIB;
/// Index objects listed larger than this are fetched one at a time instead of eight side by
/// side (§5.3), so that unauthenticated bytes in flight stay near [`INDEX_OBJECT_MAX`].
pub const INDEX_PARALLEL_MAX: u64 = 16 * MIB;
/// The vault descriptor is one short line of JSON (§3.3); nothing longer is read.
pub const DESCRIPTOR_MAX: u64 = 64 * KIB;

pub const INDEX_TRASH_DELAY: Duration = Duration::from_secs(7 * 86_400);
pub const INDEX_TRASH_DELAY_MS: u64 = 7 * DAY_MS;
pub const GC_GRACE: Duration = Duration::from_secs(30 * 86_400);
pub const GC_GRACE_MS: u64 = 30 * DAY_MS;
pub const RESTORE_WINDOW: Duration = Duration::from_secs(25 * 86_400);
pub const RESTORE_WINDOW_MS: u64 = 25 * DAY_MS;
pub const HISTORY_KEEP: Duration = Duration::from_secs(35 * 86_400);
pub const HISTORY_KEEP_MS: u64 = 35 * DAY_MS;
pub const ORPHAN_GRACE: Duration = Duration::from_secs(14 * 86_400);
pub const ORPHAN_GRACE_MS: u64 = 14 * DAY_MS;
/// The local index cache keeps an object until the base covers it **and** it is this old (§5.6).
pub const INDEX_CACHE_KEEP_MS: u64 = 30 * DAY_MS;
/// Google keeps trashed objects this long (§3.2, §5.9).
pub const DRIVE_TRASH_KEEP_MS: u64 = 30 * DAY_MS;
/// Stale `.gclone-partial-*` files older than this are removed by the scan (§5.4).
pub const PARTIAL_STALE: Duration = DAY;

/// Blocked segments younger than this are list lag (local clock, §5.3).
pub const GAP_GRACE: Duration = Duration::from_secs(600);
pub const GAP_GRACE_MS: u64 = 600_000;
/// Racy-timestamp window (§5.4).
pub const RACY_WINDOW: Duration = Duration::from_secs(2);
pub const RACY_WINDOW_NS: i64 = 2_000_000_000;
/// Objects per data folder before a new one is started (§3.1).
pub const DATA_FOLDER_MAX: u64 = 100_000;
/// Delete guard G4 (§5.5.2).
pub const MAX_DELETE_ABS: u64 = 100;
/// `files.generateIds` batch; on `400` the pool falls back to [`ID_POOL_BATCH_FALLBACK`].
pub const ID_POOL_BATCH: usize = 100;
pub const ID_POOL_BATCH_FALLBACK: usize = 10;
/// Waiting time of mutating commands for the process lock (§8.3).
pub const LOCK_WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------------------------
// §6.1 — HTTP and pacer
// ---------------------------------------------------------------------------------------------

pub const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for the answer's headers and for each read of its body. For a request that
/// carries an upload body it is the stall limit instead: the longest time in which the HTTP
/// stack takes no further slice of the body (§6.4).
pub const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Bytes per second. A request with an upload body of `len` bytes may take
/// `HTTP_READ_TIMEOUT + len / UPLOAD_MIN_RATE` in all (§6.4); a slower stream counts as dead.
pub const UPLOAD_MIN_RATE: u64 = 8 * KIB;
/// Upload bodies are handed to the HTTP stack in slices of this size, so that "a slice was
/// taken" is a fine-grained sign of bytes leaving (§6.4). 16 slices — what the HTTP/1 stack
/// queues before it flushes — must go out well inside `HTTP_READ_TIMEOUT` at `UPLOAD_MIN_RATE`.
pub const UPLOAD_SLICE: usize = 16 * 1024;
/// Read timeout of the client that talks to the auth Worker (§9.6 `auth::http_client`).
pub const AUTH_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests per second: WRITE {start 4, min 0.5, max 20}; READ {start 10, min 1, max 25}.
pub const PACER_WRITE_START: f64 = 4.0;
pub const PACER_WRITE_MIN: f64 = 0.5;
pub const PACER_WRITE_MAX: f64 = 20.0;
pub const PACER_READ_START: f64 = 10.0;
pub const PACER_READ_MIN: f64 = 1.0;
pub const PACER_READ_MAX: f64 = 25.0;
/// `+0.5/s` per [`PACER_INCREASE_EVERY`] without throttling.
pub const PACER_INCREASE: f64 = 0.5;
pub const PACER_INCREASE_EVERY: Duration = Duration::from_secs(10);
/// Multiplicative decrease on a throttling answer.
pub const PACER_DECREASE: f64 = 0.5;
/// `BACKOFF(n) = min(2^n s + rand(0..PACER_BACKOFF_JITTER_MS), PACER_BACKOFF_MAX)`.
pub const PACER_BACKOFF_MAX: Duration = Duration::from_secs(64);
pub const PACER_BACKOFF_JITTER_MS: u64 = 1000;
pub const PACER_MAX_ATTEMPTS: u32 = 10;
/// Sliding 60 s window of quota units.
pub const UNITS_PER_MIN_CAP: u32 = 250_000;
pub const UNITS_LIST: u32 = 100;
pub const UNITS_DOWNLOAD: u32 = 200;
/// create / update / trash / delete.
pub const UNITS_WRITE: u32 = 50;
/// get / about / generateIds.
pub const UNITS_GET: u32 = 5;
pub const UNITS_UPLOAD_PART: u32 = 0;
/// Continuous write throttling without one success for this long trips the breaker.
pub const WRITE_BREAKER: Duration = Duration::from_secs(600);

/// Uploaded in the trailing 24 h (Google's cap: 750 GB/day).
pub const LEDGER_WARN: u64 = 700 * GIB;
/// Downloaded in the trailing 24 h (documented egress allowance: 1 TB/project/day).
pub const LEDGER_DL_WARN: u64 = 900 * GIB;
pub const LEDGER_WINDOW_MS: u64 = DAY_MS;

// ---------------------------------------------------------------------------------------------
// §2.2 — device-side auth and keyfile constants
// ---------------------------------------------------------------------------------------------

/// `/login → /callback`: time the user may spend on Google's consent screen (Worker side).
pub const STATE_TTL: Duration = Duration::from_secs(600);
/// `/callback → /token`: lifetime of a grant.
pub const GRANT_TTL: Duration = Duration::from_secs(120);
/// The device waits this long for the loopback request (= `STATE_TTL`).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(600);
/// Refresh the access token when less than this is left.
pub const ACCESS_TOKEN_SKEW: Duration = Duration::from_secs(60);
pub const ACCESS_TOKEN_SKEW_MS: u64 = 60_000;
/// `status` warns when the newest refresh is older than this many days.
pub const IDLE_WARN_DAYS: u64 = 150;
/// Largest request body the Worker reads.
pub const AUTH_BODY_MAX: usize = 8 * 1024;
/// After `429 rate_limited` the device waits `Retry-After`, capped at this, and retries once (§2.4).
pub const AUTH_RETRY_AFTER_MAX: Duration = Duration::from_secs(60);
/// `/refresh` is tried this often on 5xx / network errors (§2.4).
pub const AUTH_REFRESH_ATTEMPTS: u32 = 5;
/// Attempts at pasting a sign-in code / typing the passphrase (§2.4, §2.6).
pub const PROMPT_ATTEMPTS: u32 = 3;

/// Unicode scalar values, for a typed passphrase.
pub const PASSPHRASE_MIN_CHARS: usize = 12;
/// A generated passphrase has this many Crockford symbols (100 bits).
pub const PASSPHRASE_GENERATED_SYMBOLS: usize = 20;
/// Below this many characters a typed passphrase gets a warning (§2.6).
pub const PASSPHRASE_WARN_CHARS: usize = 20;
pub const KEYFILE_MAX: u64 = 64 * KIB;
/// A new device looks at the keyfiles with the highest generation only.
pub const KEYFILE_TRY_MAX: usize = 4;
/// Written keyfile KDF parameters: Argon2id v1.3, 256 MiB, t = 3, p = 1, 16-byte salt.
pub const KDF_M_KIB: u32 = 262_144;
pub const KDF_T: u32 = 3;
pub const KDF_P: u32 = 1;
pub const KDF_SALT_LEN: usize = 16;
/// Accepted on decode (§2.6): `8192 ≤ m_kib ≤ 524288`, `1 ≤ t ≤ 4`, `p = 1`.
pub const KDF_M_KIB_MIN: u32 = 8_192;
pub const KDF_M_KIB_MAX: u32 = 524_288;
pub const KDF_T_MIN: u32 = 1;
pub const KDF_T_MAX: u32 = 4;

// ---------------------------------------------------------------------------------------------
// §5.1 — path limits
// ---------------------------------------------------------------------------------------------

pub const PATH_COMPONENT_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;
pub const PARTIAL_PREFIX: &str = ".gclone-partial-";
pub const PROBE_PREFIX: &str = ".gclone-probe-";
pub const IGNORE_FILE: &str = ".gcloneignore";

// Relations the code relies on, checked at compile time.
const _: () = {
    assert!(PART_SIZE == 16 * MIB);
    assert!(PART_SIZE.is_multiple_of(UPLOAD_GRANULE));
    assert!(MULTIPART_MAX.is_multiple_of(UPLOAD_GRANULE));
    assert!(PACK_MEMBER_MAX < PACK_TARGET);
    assert!(CHUNK_LOG2_MIN <= CHUNK_LOG2 && CHUNK_LOG2 <= CHUNK_LOG2_MAX);
    assert!(KDF_M_KIB_MIN <= KDF_M_KIB && KDF_M_KIB <= KDF_M_KIB_MAX);
    assert!(KDF_T_MIN <= KDF_T && KDF_T <= KDF_T_MAX);
    assert!(INDEX_PARALLEL_MAX <= INDEX_OBJECT_MAX);
    // restore window < gc grace < history keep (§5.9)
    assert!(RESTORE_WINDOW_MS < GC_GRACE_MS && GC_GRACE_MS < HISTORY_KEEP_MS);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_and_integer_forms_agree() {
        assert_eq!(AUTH_TIMEOUT, STATE_TTL);
        for (d, ms) in [
            (INDEX_TRASH_DELAY, INDEX_TRASH_DELAY_MS),
            (GC_GRACE, GC_GRACE_MS),
            (RESTORE_WINDOW, RESTORE_WINDOW_MS),
            (HISTORY_KEEP, HISTORY_KEEP_MS),
            (ORPHAN_GRACE, ORPHAN_GRACE_MS),
            (GAP_GRACE, GAP_GRACE_MS),
            (ACCESS_TOKEN_SKEW, ACCESS_TOKEN_SKEW_MS),
        ] {
            assert_eq!(d.as_millis() as u64, ms);
        }
        assert_eq!(RACY_WINDOW.as_nanos() as i64, RACY_WINDOW_NS);
        assert_eq!(PARTIAL_STALE.as_secs(), 86_400);
        assert_eq!(LEDGER_WINDOW_MS, 86_400_000);
        assert_eq!(DRIVE_TRASH_KEEP_MS, INDEX_CACHE_KEEP_MS);
    }
}
